"""Applicant-facing emails — acknowledgement and the entrance-exam invitation.

The exam link used to be rendered ONCE on the /apply response page. If the
candidate closed the tab, the token was gone forever and there was no way back
in — which is how 180 applicants produced zero sittings. The invitation email is
the durable copy of that link.

Sends are best-effort: ``send_email`` never raises and returns False when SMTP
is unconfigured, so a mail failure can never block an application.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.admissions import Applicant
from app.services.email import send_email

_WRAP = """\
<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#0D1F16;
            max-width:560px;margin:0 auto;padding:24px;">
  <p style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;
            color:#0B4F31;font-weight:600;margin:0 0 4px;">Fibre Academy</p>
  <h1 style="font-size:22px;margin:0 0 16px;">{title}</h1>
  {body}
  <p style="margin-top:28px;font-size:12px;color:#5B6B62;">
    Dotmac Fibre Academy — please do not reply to this address.
  </p>
</div>"""

_BTN = """\
<p style="margin:24px 0;">
  <a href="{url}" style="background:#F4621A;color:#fff;text-decoration:none;
     padding:12px 22px;border-radius:6px;font-weight:600;display:inline-block;">
    Start the assessment
  </a>
</p>
<p style="font-size:13px;color:#5B6B62;">
  If the button doesn't work, paste this into your browser:<br>
  <span style="word-break:break-all;">{url}</span>
</p>"""


def send_application_received(db: Session, *, applicant: Applicant) -> bool:
    """Acknowledge the application. Sent immediately on submit."""
    name = html.escape((applicant.first_name or "there").strip())
    body = (
        f"<p>Hi {name},</p>"
        "<p>We've received your application to the Fibre Academy. Thank you.</p>"
        "<p>The next step is a short online entrance assessment. We've sent it to you "
        "in a separate email — check your inbox (and your spam folder).</p>"
    )
    return send_email(
        applicant.email,
        "We've received your Fibre Academy application",
        _WRAP.format(title="Application received", body=body),
        text_body=(
            f"Hi {name},\n\nWe've received your application to the Fibre Academy.\n\n"
            "The next step is a short online entrance assessment — we've sent it in a "
            "separate email. Check your inbox and spam folder.\n"
        ),
        db=db,
    )


def send_exam_invite(db: Session, *, applicant: Applicant, url: str, minutes: int | None) -> bool:
    """The entrance-exam invitation: instructions, the link, and the deadline.

    This is the durable copy of the token — the whole point of the email.
    """
    name = html.escape((applicant.first_name or "there").strip())
    deadline = applicant.assessment_deadline
    by = deadline.strftime("%A %d %B %Y") if deadline else None

    timing = (
        f"<li>It is <strong>timed: {minutes} minutes</strong> once you begin, and submits "
        "automatically when the time is up.</li>"
        if minutes
        else "<li>Take your time — there is no time limit.</li>"
    )
    rules = (
        "<ul style='line-height:1.7;'>"
        "<li>30 multiple-choice questions. Choose the single best answer.</li>"
        f"{timing}"
        "<li>You get <strong>one attempt</strong>, so start when you can finish uninterrupted.</li>"
        "<li>Your answers save as you go — if your connection drops, reopen the link and "
        "carry on where you left off.</li>"
        "<li>It tests general aptitude — numeracy, reading, reasoning, safety sense and basic "
        "technical understanding. <strong>You are not expected to know fibre already.</strong></li>"
        "</ul>"
    )
    body = (
        f"<p>Hi {name},</p>"
        "<p>Here is your Fibre Academy entrance assessment.</p>"
        + rules
        + (f"<p><strong>Complete it by {by}.</strong></p>" if by else "")
        + _BTN.format(url=html.escape(url, quote=True))
        + "<p style='font-size:13px;color:#5B6B62;'>Trouble with the link, or cut off part-way? "
        "Reply to the team and we can reopen your sitting.</p>"
    )
    text = (
        f"Hi {name},\n\nYour Fibre Academy entrance assessment:\n{url}\n\n"
        "- 30 multiple-choice questions, one best answer each\n"
        + (f"- Timed: {minutes} minutes once you begin; it submits automatically at zero\n" if minutes else "")
        + "- One attempt — start when you can finish uninterrupted\n"
        "- Answers save as you go; if your connection drops, reopen the link and continue\n"
        "- It tests general aptitude, not fibre knowledge\n" + (f"\nComplete it by {by}.\n" if by else "")
    )
    ok = send_email(
        applicant.email,
        "Your Fibre Academy entrance assessment",
        _WRAP.format(title="Your entrance assessment", body=body),
        text_body=text,
        db=db,
    )
    if ok:
        applicant.invite_sent_at = datetime.now(UTC)
    return ok
