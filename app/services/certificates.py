# app/services/certificates.py
"""Issue and render course-completion certificates.

A certificate may be issued only once the learner's ``CourseCompletion`` is
``completed``. Issuance is idempotent (one per person/course). The PDF is
rendered on demand with fpdf2 — no system dependencies.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from fpdf import FPDF
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.certificate import Certificate
from app.models.completion import CourseCompletion
from app.services.exceptions import ConflictError

# Certificate background (built by content/management/figures-src/
# generate_cert_frame.py -- a guilloche/banknote-style border generated via
# Gemini plus a code-composited watermark and ribbon seal carrying the real
# brand mark; see that script's docstring). app/services/ -> repo root.
_FRAME = Path(__file__).resolve().parents[2] / "static" / "img" / "cert-frame.jpg"

# Content sits centered on the full page, inside the background's guilloche
# border -- unlike an earlier brand-panel design, this layout has no side
# panel offsetting the center. Bounds are the border's inner (orange-rule)
# content field, sampled from the generated background, with an 8mm inset;
# keep in sync with generate_cert_frame.py if the border proportions change.
_CONTENT_X0 = 39.0
_CONTENT_X1 = 258.0
_CONTENT_CX = 148.5  # page center; the design is symmetric, unlike the panel layout
_CONTENT_W = _CONTENT_X1 - _CONTENT_X0

# Certificate-only typefaces (OFL-licensed, static instances baked from the
# Google Fonts variable sources -- see static/fonts/certificate/OFL-*.txt for
# the license text of each). Fraunces/Manrope match the academy's own web
# type scale (static/fonts/fraunces-*.woff2, manrope-*.woff2); Pacifico is a
# certificate-only script accent used solely for the title, matching the
# reference certificate's flowing cursive treatment.
_FONTS = Path(__file__).resolve().parents[2] / "static" / "fonts" / "certificate"
_FRAUNCES = _FONTS / "Fraunces-SemiBold.ttf"
_MANROPE = _FONTS / "Manrope-Regular.ttf"
_MANROPE_SEMIBOLD = _FONTS / "Manrope-SemiBold.ttf"
_PACIFICO = _FONTS / "Pacifico-Regular.ttf"

_EMERALD = (47, 122, 82)
_CHARCOAL = (35, 35, 35)
_MUTED = (114, 106, 96)

logger = logging.getLogger(__name__)


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
    from app.services import learning_events

    learning_events.emit(
        db, tenant_id=tenant_id, person_id=person_id, kind="certificate_earned",
        course_id=course_id, subject_id=course_id,
        detail={"serial": cert.serial},
    )
    try:
        from app.services.notifications import notify as _notify
        _notify(
            db,
            tenant_id=tenant_id,
            person_id=person_id,
            kind="certificate",
            title="Your certificate is ready",
            body="Congratulations on completing the course!",
        )
    except Exception as exc:
        logger.warning("in-app notify (certificate) failed: %s", exc)
    return cert


def _tracked(pdf: FPDF, *, y: float, text: str, size: float, spacing: float,
             color: tuple[int, int, int], font: str) -> None:
    """One line of letter-spaced small caps, centered in the content area --
    the supporting-text treatment used throughout the certificate (labels,
    dividers' captions)."""
    pdf.set_font(font, "", size)
    pdf.set_text_color(*color)
    pdf.set_char_spacing(spacing)
    pdf.set_xy(_CONTENT_X0, y)
    pdf.cell(_CONTENT_W, 6, text.upper(), align="C")
    pdf.set_char_spacing(0)


def render_certificate_pdf(
    *, recipient_name: str, course_title: str, serial: str, issued_at: datetime
) -> bytes:
    """Render a single-page landscape A4 certificate PDF and return its bytes."""
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=False)
    pdf.add_page()

    if _FRAME.exists():
        pdf.image(str(_FRAME), 0, 0, 297, 210)
    else:
        pdf.set_draw_color(*_EMERALD)
        pdf.set_line_width(2)
        pdf.rect(10, 10, 277, 190)

    # All four or none: a partial set (e.g. Fraunces present but Manrope
    # missing) previously still hardcoded "Manrope" for every label below,
    # which fpdf2 raises on ("Undefined font") since add_font was never
    # called for it -- that's not the graceful degrade the comment promised.
    if all(p.exists() for p in (_FRAUNCES, _MANROPE, _MANROPE_SEMIBOLD, _PACIFICO)):
        pdf.add_font("Fraunces", "", str(_FRAUNCES))
        pdf.add_font("Manrope", "", str(_MANROPE))
        pdf.add_font("Manrope", "B", str(_MANROPE_SEMIBOLD))
        pdf.add_font("Pacifico", "", str(_PACIFICO))
        display_font, script_font, label_font = "Fraunces", "Pacifico", "Manrope"
    else:  # fonts not vendored (e.g. a stripped checkout) -- degrade gracefully
        display_font = script_font = label_font = "Helvetica"

    # Title in the script face, natural mixed case with no letter-spacing --
    # a connected cursive font reads as broken with tracking applied.
    pdf.set_font(script_font, "", 40 if script_font == "Pacifico" else 26)
    pdf.set_text_color(*_CHARCOAL)
    pdf.set_xy(_CONTENT_X0, 34)
    pdf.cell(_CONTENT_W, 18, "Certificate of Completion", align="C")

    _tracked(pdf, y=58, text="This is to certify that", size=10.5, spacing=0.8,
             color=_MUTED, font=label_font)

    # Recipient name -- bold serif, sitting over the background's faint
    # "Dotmac Academy" watermark, with a plain rule underneath.
    pdf.set_font(display_font, "", 30)
    pdf.set_text_color(*_CHARCOAL)
    pdf.set_xy(_CONTENT_X0, 68)
    pdf.cell(_CONTENT_W, 16, recipient_name, align="C")

    pdf.set_draw_color(*_MUTED)
    pdf.set_line_width(0.2)
    pdf.line(_CONTENT_CX - 45, 90, _CONTENT_CX + 45, 90)

    _tracked(pdf, y=98, text="has successfully completed the course",
             size=10.5, spacing=0.8, color=_MUTED, font=label_font)

    pdf.set_font(label_font, "B", 15)
    pdf.set_text_color(*_CHARCOAL)
    pdf.set_xy(_CONTENT_X0, 108)
    pdf.cell(_CONTENT_W, 10, course_title, align="C")

    # Signature / seal / date footer -- the background's ribbon seal is
    # centered between these two columns (see generate_cert_frame.py), so
    # they stop well short of the middle rather than spanning full width.
    # The rule's y (140) is matched by hand to the seal's baked-in vertical
    # position there -- keep the two in sync if either moves.
    col_w = 62.0
    left_x = _CONTENT_X0 + 8
    right_x = _CONTENT_X1 - 8 - col_w

    pdf.set_font(label_font, "B", 11)
    pdf.set_text_color(*_CHARCOAL)
    pdf.set_xy(right_x, 128)
    pdf.cell(col_w, 7, f"{issued_at:%d %B %Y}", align="C")

    pdf.set_draw_color(*_EMERALD)
    pdf.set_line_width(0.25)
    pdf.line(left_x, 140, left_x + col_w, 140)
    pdf.line(right_x, 140, right_x + col_w, 140)

    for x, label in ((left_x, "Academy Director"), (right_x, "Date")):
        pdf.set_font(label_font, "", 9)
        pdf.set_text_color(*_MUTED)
        pdf.set_xy(x, 142.5)
        pdf.cell(col_w, 5, label, align="C")

    _tracked(pdf, y=165, text=f"Certificate Serial  ·  {serial}", size=8,
             spacing=0.4, color=_MUTED, font=label_font)

    out = pdf.output()  # fpdf2 >= 2.7 returns a bytearray
    return bytes(out)
