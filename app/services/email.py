"""Email subsystem — inert-by-default SMTP sender + notification helpers.

Design rules (see project memory / Inc1):

* Uses ONLY the Python stdlib (``smtplib`` + ``email.message.EmailMessage``);
  no new third-party dependency.
* INERT WHEN UNCONFIGURED: if ``settings.smtp_host`` is empty/None,
  :func:`send_email` logs and returns ``False``. It NEVER raises and NEVER
  blocks, so an unconfigured VM behaves as "email disabled". The operator
  enables email purely by setting SMTP_* env vars.
* NON-FATAL: every public entry point swallows exceptions and returns a bool.
  Sending an email must never break grading or a web request.

These helpers ``flush`` only when they read via the passed-in session; they
never ``commit`` (the caller owns the transaction boundary).
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.assessment import Score, Submission

logger = logging.getLogger(__name__)


def send_email(to: str, subject: str, html_body: str, text_body: str | None = None) -> bool:
    """Send an HTML email (with optional plain-text alternative).

    Returns ``True`` only if the message was handed to the SMTP server. Returns
    ``False`` (and logs) when SMTP is unconfigured or on ANY exception — it never
    raises, so callers can treat email as best-effort.
    """
    if not settings.smtp_host:
        logger.info("SMTP not configured (SMTP_HOST empty); skipping email to %s: %s", to, subject)
        return False
    if not to:
        logger.info("No recipient address; skipping email: %s", subject)
        return False
    try:
        msg = EmailMessage()
        msg["From"] = settings.smtp_from
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(text_body or "This message requires an HTML-capable email client.")
        msg.add_alternative(html_body, subtype="html")

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
        logger.info("sent email to %s: %s", to, subject)
        return True
    except Exception as exc:  # never let an email failure propagate
        logger.warning("failed to send email to %s (%s): %s", to, subject, exc)
        return False


def notify_score_if_first_pass(db: Session, *, score, activity, person) -> bool:
    """Email the student a congratulations IFF this is their FIRST passing score.

    Fires only when ``score.passed`` is true AND there is no other passing
    :class:`Score` for the same (tenant, activity, person). Returns whether an
    email was actually sent. Wrapped in try/except — any failure (DB or SMTP) is
    swallowed and returns ``False`` so grading always succeeds.
    """
    try:
        if not getattr(score, "passed", False):
            return False
        if person is None or not getattr(person, "email", None):
            return False

        prior_passes = db.scalar(
            select(func.count())
            .select_from(Score)
            .join(
                Submission,
                (Submission.id == Score.submission_id)
                & (Submission.tenant_id == Score.tenant_id),
            )
            .where(Score.tenant_id == score.tenant_id)
            .where(Submission.activity_id == activity.id)
            .where(Submission.person_id == person.id)
            .where(Score.passed.is_(True))
            .where(Score.id != score.id)
        )
        if int(prior_passes or 0) > 0:
            return False

        subject = f"You passed {activity.title}"
        name = (getattr(person, "first_name", "") or "there").strip()
        pct = f"{score.fraction * 100:.0f}%"
        html = (
            f"<p>Hi {name},</p>"
            f"<p>Congratulations — you passed <strong>{activity.title}</strong> "
            f"with a score of {pct}.</p>"
            f"<p>Keep up the great work!</p>"
            f"<p>— Dotmac Academy</p>"
        )
        text = (
            f"Hi {name},\n\n"
            f"Congratulations — you passed {activity.title} with a score of {pct}.\n\n"
            f"Keep up the great work!\n\n— Dotmac Academy\n"
        )
        return send_email(person.email, subject, html, text_body=text)
    except Exception as exc:  # non-fatal: grading must still succeed
        logger.warning("notify_score_if_first_pass failed: %s", exc)
        return False


def render_transcript_html(transcript: dict) -> str:
    """Render a student transcript (from ``reports.student_transcript``) to HTML."""
    person = transcript["person"]
    rows = transcript["rows"]
    name = f"{person.first_name} {person.last_name}".strip()
    parts = [
        f"<h2>Transcript — {name}</h2>",
        f"<p>{person.email}</p>",
        '<table border="1" cellpadding="6" cellspacing="0">',
        "<tr><th>Activity</th><th>Type</th><th>Score</th><th>Result</th></tr>",
    ]
    if not rows:
        parts.append('<tr><td colspan="4">No graded activities yet.</td></tr>')
    for row in rows:
        act = row["activity"]
        result = "Pass" if row["passed"] else "Fail"
        parts.append(
            f"<tr><td>{act.title}</td><td>{act.type}</td>"
            f"<td>{row['fraction'] * 100:.0f}%</td><td>{result}</td></tr>"
        )
    parts.append("</table>")
    return "\n".join(parts)


def render_cohort_html(matrix: dict) -> str:
    """Render a cohort progress matrix (from ``reports.cohort_matrix``) to HTML."""
    cohort = matrix["cohort"]
    rows = matrix["rows"]
    parts = [
        f"<h2>Cohort progress — {cohort.name}</h2>",
        '<table border="1" cellpadding="6" cellspacing="0">',
        "<tr><th>Student</th><th>Email</th><th>Completion</th></tr>",
    ]
    if not rows:
        parts.append('<tr><td colspan="3">No enrolled students.</td></tr>')
    for row in rows:
        parts.append(
            f"<tr><td>{row['name']}</td><td>{row['email']}</td>"
            f"<td>{row['completion'] * 100:.0f}%</td></tr>"
        )
    parts.append("</table>")
    return "\n".join(parts)
