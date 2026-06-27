# app/services/certificates.py
"""Issue and render course-completion certificates.

A certificate may be issued only once the learner's ``CourseCompletion`` is
``completed``. Issuance is idempotent (one per person/course). The PDF is
rendered on demand with fpdf2 — no system dependencies.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from fpdf import FPDF
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.certificate import Certificate
from app.models.completion import CourseCompletion
from app.services.exceptions import ConflictError


def _serial() -> str:
    return f"CERT-{uuid4().hex[:12].upper()}"


def issue_certificate(
    db: Session, *, tenant_id: UUID, person_id: UUID, course_id: UUID,
    now: datetime | None = None,
) -> Certificate:
    """Return the certificate for a completed course, creating it if needed.

    Raises ConflictError if the course is not yet completed.
    """
    existing = db.scalars(
        select(Certificate)
        .where(Certificate.tenant_id == tenant_id)
        .where(Certificate.person_id == person_id)
        .where(Certificate.course_id == course_id)
    ).first()
    if existing is not None:
        return existing

    completion = db.scalars(
        select(CourseCompletion)
        .where(CourseCompletion.tenant_id == tenant_id)
        .where(CourseCompletion.person_id == person_id)
        .where(CourseCompletion.course_id == course_id)
    ).first()
    if completion is None or completion.status != "completed":
        raise ConflictError("course not completed; certificate cannot be issued")

    cert = Certificate(tenant_id=tenant_id, person_id=person_id, course_id=course_id,
                       serial=_serial(), issued_at=now or datetime.now(UTC))
    db.add(cert)
    db.flush()
    return cert


def render_certificate_pdf(
    *, recipient_name: str, course_title: str, serial: str, issued_at: datetime
) -> bytes:
    """Render a single-page landscape A4 certificate PDF and return its bytes."""
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()

    pdf.set_draw_color(40, 70, 120)
    pdf.set_line_width(2)
    pdf.rect(10, 10, 277, 190)

    pdf.set_text_color(40, 70, 120)
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
