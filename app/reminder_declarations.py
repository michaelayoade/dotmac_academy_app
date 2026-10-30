"""Actual product reminder audit vocabulary, composed into both entrypoints."""
from dotmac_kernel.features import FeatureManifest

REMINDER_RESEND_ACTION = "reminder.resend"
REMINDER_AUDIT_DECLARATION = FeatureManifest(name="academy_reminders", audit_actions=(REMINDER_RESEND_ACTION,))
