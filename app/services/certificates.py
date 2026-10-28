# app/services/certificates.py
"""Delegate certificate issuance to Learning; render and notify in Academy."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from uuid import UUID

from dotmac_learning import (
    CertificateCommand,
    CertificateFact,
    CertificateIssue,
    CertificateNotEligible,
)
from dotmac_learning import (
    issue_certificate as learning_issue_certificate,
)
from fpdf import FPDF
from sqlalchemy.orm import Session

from app.services.exceptions import ConflictError

# Ornamental certificate frame (generated). app/services/ -> repo root.
_FRAME = Path(__file__).resolve().parents[2] / "static" / "img" / "cert-frame.png"

logger = logging.getLogger(__name__)


def issue_certificate(
    db: Session,
    *,
    tenant_id: UUID,
    person_id: UUID,
    course_id: UUID,
    now: datetime | None = None,
) -> CertificateFact:
    """Return a detached certificate, preserving the product eligibility error."""
    try:
        result = learning_issue_certificate(
            db,
            CertificateCommand(tenant_id=tenant_id, person_id=person_id, course_id=course_id, now=now),
        )
    except CertificateNotEligible as exc:
        raise ConflictError(str(exc)) from exc
    deliver_certificate_notification(db, result)
    return result.certificate


def deliver_certificate_notification(db: Session, result: CertificateIssue) -> None:
    """Notify only for new issuance, including issuance by completion commands."""
    if not result.created:
        return
    cert = result.certificate
    try:
        from app.services.notifications import notify as _notify

        with db.begin_nested():
            _notify(
                db,
                tenant_id=cert.tenant_id,
                person_id=cert.person_id,
                kind="certificate",
                title="Your certificate is ready",
                body="Congratulations on completing the course!",
            )
    except Exception as exc:
        logger.warning("in-app notify (certificate) failed: %s", exc)


def render_certificate_pdf(*, recipient_name: str, course_title: str, serial: str, issued_at: datetime) -> bytes:
    """Render a single-page landscape A4 certificate PDF and return its bytes."""
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()

    if _FRAME.exists():
        pdf.image(str(_FRAME), 0, 0, 297, 210)
    else:
        pdf.set_draw_color(47, 122, 82)
        pdf.set_line_width(2)
        pdf.rect(10, 10, 277, 190)

    pdf.set_text_color(47, 122, 82)
    pdf.set_font("Helvetica", "B", 36)
    pdf.set_y(45)
    pdf.cell(0, 20, "Certificate of Completion", align="C")

    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "", 16)
    pdf.set_y(85)
    pdf.cell(0, 10, "This certifies that", align="C")

    pdf.set_font("Helvetica", "B", 28)
    pdf.set_y(98)
    pdf.cell(0, 14, recipient_name, align="C")

    pdf.set_font("Helvetica", "", 16)
    pdf.set_y(120)
    pdf.cell(0, 10, "has successfully completed", align="C")

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_y(132)
    pdf.cell(0, 12, course_title, align="C")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(90, 90, 90)
    pdf.set_y(170)
    pdf.cell(0, 8, f"Issued {issued_at:%d %B %Y}    -    Serial {serial}", align="C")

    out = pdf.output()  # fpdf2 >= 2.7 returns a bytearray
    return bytes(out)
