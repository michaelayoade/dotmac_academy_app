"""Single-Academy settings store — DB-over-env effective configuration.

Reads/writes the ``platform_settings`` key/value table and merges stored values
over the env/config defaults from :data:`app.config.settings`. Everything is
best-effort and safe: if the table is missing or empty (fresh DB, pre-migration),
:func:`effective` simply returns the env defaults so nothing breaks.

Writes require the restricted settings-writer session (the historical database
role is named ``platform_api``); ``app_user`` may only SELECT. The caller owns
the transaction boundary — these helpers ``flush`` only.
"""

from __future__ import annotations

import logging

from sqlalchemy import select, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session, aliased

from app.config import (
    ADMISSION_ENROLLMENT_POLICY_KEYS,
    AUTHENTICATION_POLICY_SHAPES,
    BOOTSTRAP_POLICY_KEYS,
    ENROLLMENT_INITIAL_STATE_POLICY_KEYS,
    ENTRANCE_INVITATION_POLICY_KEYS,
    ICAL_FEED_POLICY_KEYS,
    INITIAL_IDENTITY_POLICY_KEYS,
    INVITATION_PURPOSE_POLICY_SHAPES,
    LAB_CAPACITY_KEYS,
    LAB_EXECUTION_OVERRIDE_KEY,
    LAB_EXECUTION_POLICY_SHAPES,
    LEARNING_POLICY_SHAPES,
    ONBOARDING_POLICY_KEYS,
    PASSWORD_CHANGE_POLICY_SHAPES,
    PROFILE_POLICY_SHAPES,
    InvitationMemberRole,
    LabExecutionPolicy,
    settings,
    validate_admin_home_access_roles,
    validate_admission_enrollment_policy_value,
    validate_authentication_policy_value,
    validate_bank_author_roles,
    validate_bank_export_roles,
    validate_bank_publish_roles,
    validate_bank_repoint_roles,
    validate_bank_retire_roles,
    validate_bootstrap_policy_value,
    validate_catalog_staff_roles,
    validate_enrollment_initial_state_policy_value,
    validate_entrance_invitation_deadline_days,
    validate_gradebook_access_roles,
    validate_ical_feed_policy,
    validate_initial_identity_policy_value,
    validate_invitation_default_member_role,
    validate_invitation_member_role_map,
    validate_invitation_purpose_policy_value,
    validate_lab_admin_access_roles,
    validate_lab_execution_overrides,
    validate_lab_execution_relations,
    validate_lab_execution_value,
    validate_lab_policy_integer,
    validate_learning_policy_relations,
    validate_learning_policy_value,
    validate_notifications_recent_limit,
    validate_onboarding_policy_value,
    validate_password_change_policy_value,
    validate_password_reset_min_length,
    validate_profile_policy_value,
    validate_reminders_admin_access_roles,
    validate_reports_access_roles,
    validate_settings_access_roles,
    validate_teaching_access_roles,
    validate_web_account_creation_password_min_length,
    validate_web_account_creation_role_admission,
    validate_web_account_creation_role_provisioning,
)
from app.models.platform_settings import PlatformSetting

logger = logging.getLogger(__name__)

# Keys whose stored string value is coerced to a non-str type on read.
_INT_KEYS = frozenset(
    {
        "smtp_port",
        "max_concurrent_labs",
        "max_concurrent_labs_per_tenant",
        "password_reset_min_length",
        "lab_idle_minutes",
        "reminder_inactivity_days",
        "reminder_digest_hour",
        "reminder_digest_weekday",
        "success_inactive_days",
        "success_min_grade_pct",
        "success_certificate_grace_hours",
        "reminder_inactivity_max_nudges",
    }
)
_BOOL_KEYS = frozenset(
    {"smtp_starttls", "email_auto_on_pass", "email_digest_enabled", "reminders_enabled", "learner_digest_enabled"}
)
_INT_MINIMUMS = {
    "password_reset_min_length": 1,
    "max_concurrent_labs": 1,
    "max_concurrent_labs_per_tenant": 0,
    "lab_idle_minutes": 1,
}

# The full set of known keys, with their default sourced live from `settings`
# (or a literal) so monkeypatching `settings.*` in tests is reflected here.
_INVITATION_KEYS = frozenset({"invitation_member_role_map", "invitation_default_member_role"})

_WEB_ACCOUNT_CREATION_KEYS = frozenset(
    {
        "web_account_creation_role_admission",
        "web_account_creation_password_min_length",
        "web_account_creation_role_provisioning",
    }
)

_BANK_ROLE_VALIDATORS = {
    "bank_author_roles": validate_bank_author_roles,
    "bank_publish_roles": validate_bank_publish_roles,
    "bank_repoint_roles": validate_bank_repoint_roles,
    "bank_export_roles": validate_bank_export_roles,
    "bank_retire_roles": validate_bank_retire_roles,
}

KNOWN_KEYS: tuple[str, ...] = (
    *_BANK_ROLE_VALIDATORS,
    "admin_home_access_roles",
    "lab_admin_access_roles",
    "reminders_admin_access_roles",
    "teaching_access_roles",
    "catalog_staff_roles",
    "gradebook_access_roles",
    "settings_access_roles",
    "reports_access_roles",
    "notifications_recent_limit",
    *ICAL_FEED_POLICY_KEYS,
    *BOOTSTRAP_POLICY_KEYS,
    *ENTRANCE_INVITATION_POLICY_KEYS,
    *ADMISSION_ENROLLMENT_POLICY_KEYS,
    *ENROLLMENT_INITIAL_STATE_POLICY_KEYS,
    *INITIAL_IDENTITY_POLICY_KEYS,
    *ONBOARDING_POLICY_KEYS,
    *AUTHENTICATION_POLICY_SHAPES,
    *INVITATION_PURPOSE_POLICY_SHAPES,
    *PROFILE_POLICY_SHAPES,
    *PASSWORD_CHANGE_POLICY_SHAPES,
    *LEARNING_POLICY_SHAPES,
    "web_account_creation_role_admission",
    "web_account_creation_password_min_length",
    "web_account_creation_role_provisioning",
    "invitation_member_role_map",
    "invitation_default_member_role",
    "password_reset_min_length",
    "smtp_host",
    "smtp_port",
    "smtp_user",
    "smtp_password",
    "smtp_from",
    "smtp_starttls",
    "email_auto_on_pass",
    "email_digest_enabled",
    "branding_name",
    "management_inquiry_recipient",
    "max_concurrent_labs",
    "max_concurrent_labs_per_tenant",
    "lab_idle_minutes",
    LAB_EXECUTION_OVERRIDE_KEY,
    "reminders_enabled",
    "reminder_inactivity_days",
    "reminder_digest_hour",
    "reminder_digest_weekday",
    "reminder_inactivity_max_nudges",
    "learner_digest_enabled",
    "entrance_questions_per_category",
)


def _defaults() -> dict[str, object]:
    """Env/config defaults for every known key (read live so tests can patch)."""
    return {
        **{key: validate_lab_execution_value(key, getattr(settings, key)) for key in LAB_EXECUTION_POLICY_SHAPES},
        LAB_EXECUTION_OVERRIDE_KEY: {},
        "settings_access_roles": validate_settings_access_roles(settings.settings_access_roles),
        **{key: fn(getattr(settings, key)) for key, fn in _BANK_ROLE_VALIDATORS.items()},
        "admin_home_access_roles": validate_admin_home_access_roles(settings.admin_home_access_roles),
        "lab_admin_access_roles": validate_lab_admin_access_roles(settings.lab_admin_access_roles),
        "reminders_admin_access_roles": validate_reminders_admin_access_roles(settings.reminders_admin_access_roles),
        "teaching_access_roles": validate_teaching_access_roles(settings.teaching_access_roles),
        "catalog_staff_roles": validate_catalog_staff_roles(settings.catalog_staff_roles),
        "gradebook_access_roles": validate_gradebook_access_roles(settings.gradebook_access_roles),
        "reports_access_roles": validate_reports_access_roles(settings.reports_access_roles),
        **{key: validate_ical_feed_policy(key, getattr(settings, key)) for key in ICAL_FEED_POLICY_KEYS},
        "notifications_recent_limit": validate_notifications_recent_limit(settings.notifications_recent_limit),
        **{key: validate_bootstrap_policy_value(key, getattr(settings, key)) for key in BOOTSTRAP_POLICY_KEYS},
        **{key: getattr(settings, key) for key in ENTRANCE_INVITATION_POLICY_KEYS},
        **{key: getattr(settings, key) for key in ADMISSION_ENROLLMENT_POLICY_KEYS},
        **{key: getattr(settings, key) for key in ENROLLMENT_INITIAL_STATE_POLICY_KEYS},
        **{key: validate_onboarding_policy_value(key, getattr(settings, key)) for key in ONBOARDING_POLICY_KEYS},
        **{
            key: validate_initial_identity_policy_value(key, getattr(settings, key))
            for key in INITIAL_IDENTITY_POLICY_KEYS
        },
        **{
            key: validate_invitation_purpose_policy_value(key, getattr(settings, key))
            for key in INVITATION_PURPOSE_POLICY_SHAPES
        },
        **{
            key: validate_password_change_policy_value(key, getattr(settings, key))
            for key in PASSWORD_CHANGE_POLICY_SHAPES
        },
        **{key: validate_profile_policy_value(key, getattr(settings, key)) for key in PROFILE_POLICY_SHAPES},
        **{
            key: validate_authentication_policy_value(key, getattr(settings, key))
            for key in AUTHENTICATION_POLICY_SHAPES
        },
        **{key: validate_learning_policy_value(key, getattr(settings, key)) for key in LEARNING_POLICY_SHAPES},
        "web_account_creation_role_provisioning": validate_web_account_creation_role_provisioning(
            settings.web_account_creation_role_provisioning
        ),
        "web_account_creation_role_admission": validate_web_account_creation_role_admission(
            settings.web_account_creation_role_admission
        ),
        "web_account_creation_password_min_length": validate_web_account_creation_password_min_length(
            settings.web_account_creation_password_min_length
        ),
        "invitation_member_role_map": validate_invitation_member_role_map(settings.invitation_member_role_map),
        "invitation_default_member_role": validate_invitation_default_member_role(
            settings.invitation_default_member_role
        ),
        "password_reset_min_length": validate_password_reset_min_length(settings.password_reset_min_length),
        "smtp_host": settings.smtp_host,
        "smtp_port": settings.smtp_port,
        "smtp_user": settings.smtp_user,
        "smtp_password": settings.smtp_password,
        "smtp_from": settings.smtp_from,
        "smtp_starttls": settings.smtp_starttls,
        "email_auto_on_pass": True,
        "email_digest_enabled": True,
        "branding_name": "Dotmac Academy",
        "management_inquiry_recipient": settings.management_inquiry_recipient,
        "max_concurrent_labs": settings.max_concurrent_labs,
        "max_concurrent_labs_per_tenant": settings.max_concurrent_labs_per_tenant,
        "lab_idle_minutes": settings.lab_idle_minutes,
        "reminders_enabled": True,
        "reminder_inactivity_days": 7,
        "reminder_digest_hour": 7,
        "reminder_digest_weekday": 0,
        "reminder_inactivity_max_nudges": 4,
        # Off by default: turning this on mails every active learner, so it
        # must be a deliberate act rather than a consequence of deploying.
        "learner_digest_enabled": False,
        # 0 = serve the whole entrance bank, which is the behaviour that existed
        # before sampling. Set it once the bank is large enough that drawing N
        # per category still covers every competency.
        "entrance_questions_per_category": 0,
    }


def _coerce_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _coerce(key: str, value: str | None, default: object) -> object:
    """Coerce a stored string to the key's native type, falling back on error."""
    if key == LAB_EXECUTION_OVERRIDE_KEY:
        return validate_lab_execution_overrides(value)
    if key in LAB_CAPACITY_KEYS:
        return validate_lab_policy_integer(key, value)
    if key in _BANK_ROLE_VALIDATORS:
        return _BANK_ROLE_VALIDATORS[key](value)
    if key == "admin_home_access_roles":
        return validate_admin_home_access_roles(value)
    if key == "lab_admin_access_roles":
        return validate_lab_admin_access_roles(value)
    if key == "reminders_admin_access_roles":
        return validate_reminders_admin_access_roles(value)
    if key == "teaching_access_roles":
        return validate_teaching_access_roles(value)
    if key == "catalog_staff_roles":
        return validate_catalog_staff_roles(value)
    if key == "gradebook_access_roles":
        return validate_gradebook_access_roles(value)
    if key == "reports_access_roles":
        return validate_reports_access_roles(value)
    if key == "settings_access_roles":
        return validate_settings_access_roles(value)
    if key in ICAL_FEED_POLICY_KEYS:
        return validate_ical_feed_policy(key, value)
    if key == "notifications_recent_limit":
        return validate_notifications_recent_limit(value)
    if key in BOOTSTRAP_POLICY_KEYS:
        return validate_bootstrap_policy_value(key, value)
    if key in ENTRANCE_INVITATION_POLICY_KEYS:
        return validate_entrance_invitation_deadline_days(value)
    if key in ENROLLMENT_INITIAL_STATE_POLICY_KEYS:
        return validate_enrollment_initial_state_policy_value(key, value)
    if key in ADMISSION_ENROLLMENT_POLICY_KEYS:
        return validate_admission_enrollment_policy_value(key, value)
    if key in ONBOARDING_POLICY_KEYS:
        return validate_onboarding_policy_value(key, value)
    if key in INITIAL_IDENTITY_POLICY_KEYS:
        return validate_initial_identity_policy_value(key, value)
    if key in INVITATION_PURPOSE_POLICY_SHAPES:
        return validate_invitation_purpose_policy_value(key, value)
    if key in PASSWORD_CHANGE_POLICY_SHAPES:
        return validate_password_change_policy_value(key, value)
    if key in PROFILE_POLICY_SHAPES:
        return validate_profile_policy_value(key, value)
    if key in AUTHENTICATION_POLICY_SHAPES:
        return validate_authentication_policy_value(key, value)
    if key in LEARNING_POLICY_SHAPES:
        return validate_learning_policy_value(key, value)
    if key == "web_account_creation_role_provisioning":
        return validate_web_account_creation_role_provisioning(value)
    if key == "web_account_creation_role_admission":
        return validate_web_account_creation_role_admission(value)
    if key == "web_account_creation_password_min_length":
        return validate_web_account_creation_password_min_length(value)
    if key == "invitation_member_role_map":
        return validate_invitation_member_role_map(value)
    if key == "invitation_default_member_role":
        return validate_invitation_default_member_role(value)
    if value is None:
        return default
    if key == "password_reset_min_length":
        return validate_password_reset_min_length(value)
    if key in _BOOL_KEYS:
        return _coerce_bool(value)
    if key in _INT_KEYS:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        minimum = _INT_MINIMUMS.get(key)
        return default if minimum is not None and parsed < minimum else parsed
    return value


def get_all(db: Session | Connection) -> dict[str, str | None]:
    """Return every stored row as a ``{key: value}`` dict (values are strings)."""
    # ORM attributes retain Session autoflush and scalar freshness. The fixed
    # textual source cannot be redirected by search_path or schema_translate_map;
    # the same statement also executes through Core while Session is PREPARED.
    source = (
        text("SELECT key,value FROM public.platform_settings")
        .columns(
            PlatformSetting.__table__.c.key,
            PlatformSetting.__table__.c.value,
        )
        .subquery("canonical_platform_settings")
    )
    canonical = aliased(PlatformSetting, source, adapt_on_names=True)
    rows = db.execute(select(canonical.key, canonical.value)).all()
    # A stored NULL policy is malformed, never an absent override. Other keys
    # retain their historical omission and fallback semantics.
    return {
        r.key: r.value
        for r in rows
        if r.key in _BANK_ROLE_VALIDATORS
        or r.key in {"admin_home_access_roles", "lab_admin_access_roles", "reminders_admin_access_roles"}
        or r.key == "teaching_access_roles"
        or r.key == "catalog_staff_roles"
        or r.key == "gradebook_access_roles"
        or r.key == "settings_access_roles"
        or r.key == "reports_access_roles"
        or r.key in ICAL_FEED_POLICY_KEYS
        or r.key == "notifications_recent_limit"
        or r.value is not None
        or r.key in ENTRANCE_INVITATION_POLICY_KEYS
        or r.key in ENROLLMENT_INITIAL_STATE_POLICY_KEYS
        or r.key in ADMISSION_ENROLLMENT_POLICY_KEYS
        or r.key in INITIAL_IDENTITY_POLICY_KEYS
        or r.key in INVITATION_PURPOSE_POLICY_SHAPES
        or r.key in PASSWORD_CHANGE_POLICY_SHAPES
        or r.key in PROFILE_POLICY_SHAPES
        or r.key in AUTHENTICATION_POLICY_SHAPES
        or r.key in _INVITATION_KEYS
        or r.key in _WEB_ACCOUNT_CREATION_KEYS
        or r.key in BOOTSTRAP_POLICY_KEYS
        or r.key in LEARNING_POLICY_SHAPES
        or r.key in LAB_CAPACITY_KEYS
        or r.key in LAB_EXECUTION_POLICY_SHAPES
        or r.key == LAB_EXECUTION_OVERRIDE_KEY
    }


def _validate_learning_proposal(db: Session, updates: dict[str, str | None], *, removed: str | None) -> None:
    """Validate final policy after replacements, so malformed rows are repairable."""
    proposed = {key: getattr(settings, key) for key in LEARNING_POLICY_SHAPES}
    stored = get_all(db)
    for key, value in stored.items():
        if key in LEARNING_POLICY_SHAPES and key != removed:
            proposed[key] = value
    for key, value in updates.items():
        if key in LEARNING_POLICY_SHAPES:
            proposed[key] = value
    validated = {key: validate_learning_policy_value(key, value) for key, value in proposed.items()}
    validate_learning_policy_relations(validated)


class LabExecutionPolicyConflict(ValueError):
    """The observed override object changed; caller may retry a fresh request."""


def _lab_values(stored: dict[str, object]) -> dict[str, object]:
    if any(key in stored for key in LAB_EXECUTION_POLICY_SHAPES):
        raise ValueError("split lab execution settings are unsupported")
    values = {key: validate_lab_execution_value(key, getattr(settings, key)) for key in LAB_EXECUTION_POLICY_SHAPES}
    if LAB_EXECUTION_OVERRIDE_KEY in stored:
        values.update(validate_lab_execution_overrides(stored[LAB_EXECUTION_OVERRIDE_KEY]))
    for key in LAB_CAPACITY_KEYS:
        values[key] = validate_lab_policy_integer(key, stored[key] if key in stored else getattr(settings, key))
    validate_lab_execution_relations(values)
    return values


def _lab_proposal(db: Session, updates: dict[str, str | None], *, removed: str | None = None):
    observed = get_all(db)
    proposed = {key: value for key, value in observed.items() if key != removed}
    proposed.update(updates)
    _lab_values(proposed)
    return observed


def _cas_lab_override(db: Session, observed: dict[str, object], *, value: str | None = None, remove: bool = False):
    key = LAB_EXECUTION_OVERRIDE_KEY
    if key in observed:
        statement = (
            "DELETE FROM public.platform_settings "
            "WHERE key=:key AND value IS NOT DISTINCT FROM :observed RETURNING key"
            if remove
            else "UPDATE public.platform_settings SET value=:value "
            "WHERE key=:key AND value IS NOT DISTINCT FROM :observed RETURNING key"
        )
        changed = db.execute(text(statement), {"key": key, "observed": observed[key], "value": value}).first()
    else:
        # A speculative insert serializes an observed absence. For an absent
        # delete, remove our placeholder in the same caller-owned transaction.
        changed = db.execute(
            text(
                "INSERT INTO public.platform_settings (key,value) VALUES (:key,:value) "
                "ON CONFLICT (key) DO NOTHING RETURNING key"
            ),
            {"key": key, "value": "{}" if remove else value},
        ).first()
        if changed is not None and remove:
            db.execute(text("DELETE FROM public.platform_settings WHERE key=:key"), {"key": key})
    if changed is None:
        raise LabExecutionPolicyConflict("lab execution policy changed; retry with fresh settings")
    # SQL CAS bypasses the identity map. Touch only the owned settings object.
    existing = db.identity_map.get(db.identity_key(PlatformSetting, key))
    if existing is not None:
        if remove:
            db.expunge(existing)
        else:
            db.expire(existing)


def execution_policy(db: Session) -> LabExecutionPolicy:
    """Read exactly one strict store snapshot through the actual worker Session."""
    return LabExecutionPolicy.from_settings(effective(db, require_store=True))


def set_many(db: Session, values: dict[str, str | None]) -> None:
    """Upsert each ``key -> value`` (string). Flushes; never commits."""
    observed = (
        _lab_proposal(db, values)
        if any(key in (*LAB_CAPACITY_KEYS, *LAB_EXECUTION_POLICY_SHAPES, LAB_EXECUTION_OVERRIDE_KEY) for key in values)
        else None
    )
    if any(key in LEARNING_POLICY_SHAPES for key in values):
        _validate_learning_proposal(db, values, removed=None)
    for key, value in values.items():
        if key in _BANK_ROLE_VALIDATORS:
            _BANK_ROLE_VALIDATORS[key](value)
            continue
        if key == "admin_home_access_roles":
            validate_admin_home_access_roles(value)
            continue
        if key == "lab_admin_access_roles":
            validate_lab_admin_access_roles(value)
            continue
        if key == "reminders_admin_access_roles":
            validate_reminders_admin_access_roles(value)
            continue
        if key == "teaching_access_roles":
            validate_teaching_access_roles(value)
            continue
        if key == "catalog_staff_roles":
            validate_catalog_staff_roles(value)
            continue
        if key == "gradebook_access_roles":
            validate_gradebook_access_roles(value)
            continue
        if key == "reports_access_roles":
            validate_reports_access_roles(value)
            continue
        if key == "settings_access_roles":
            validate_settings_access_roles(value)
            continue
        if key in ICAL_FEED_POLICY_KEYS:
            validate_ical_feed_policy(key, value)
            continue
        if key == "notifications_recent_limit":
            validate_notifications_recent_limit(value)
            continue
        if key in BOOTSTRAP_POLICY_KEYS:
            validate_bootstrap_policy_value(key, value)
            continue
        if key in ENTRANCE_INVITATION_POLICY_KEYS:
            validate_entrance_invitation_deadline_days(value)
            continue
        if key in ENROLLMENT_INITIAL_STATE_POLICY_KEYS:
            validate_enrollment_initial_state_policy_value(key, value)
            continue
        if key in ADMISSION_ENROLLMENT_POLICY_KEYS:
            validate_admission_enrollment_policy_value(key, value)
            continue
        if key in ONBOARDING_POLICY_KEYS:
            validate_onboarding_policy_value(key, value)
            continue
        if key in INITIAL_IDENTITY_POLICY_KEYS:
            validate_initial_identity_policy_value(key, value)
            continue
        if key in INVITATION_PURPOSE_POLICY_SHAPES:
            validate_invitation_purpose_policy_value(key, value)
            continue
        if key in PASSWORD_CHANGE_POLICY_SHAPES:
            validate_password_change_policy_value(key, value)
            continue
        if key in PROFILE_POLICY_SHAPES:
            validate_profile_policy_value(key, value)
            continue
        if key in AUTHENTICATION_POLICY_SHAPES:
            validate_authentication_policy_value(key, value)
            continue
        if key in LEARNING_POLICY_SHAPES:
            continue
        if key in _WEB_ACCOUNT_CREATION_KEYS:
            _coerce(key, value, None)
            continue
        if key in _INVITATION_KEYS:
            _coerce(key, value, None)
            continue
        if key == "password_reset_min_length" and value is not None:
            validate_password_reset_min_length(value)
            continue
        if key not in _INT_MINIMUMS or value is None or not value.strip():
            continue
        try:
            parsed = int(value)
        except ValueError as exc:
            raise ValueError(f"{key} must be an integer") from exc
        minimum = _INT_MINIMUMS[key]
        if parsed < minimum:
            raise ValueError(f"{key} must be at least {minimum}")
    if LAB_EXECUTION_OVERRIDE_KEY in values:
        _cas_lab_override(db, observed, value=values[LAB_EXECUTION_OVERRIDE_KEY])
    for key, value in values.items():
        if key == LAB_EXECUTION_OVERRIDE_KEY:
            continue
        existing = db.get(PlatformSetting, key)
        if existing is None:
            db.add(PlatformSetting(key=key, value=value))
        else:
            existing.value = value
    db.flush()


def delete(db: Session, key: str) -> None:
    """Delete a stored key if present. Flushes; never commits."""
    if key in (*LAB_CAPACITY_KEYS, *LAB_EXECUTION_POLICY_SHAPES, LAB_EXECUTION_OVERRIDE_KEY):
        observed = _lab_proposal(db, {}, removed=key)
        if key == LAB_EXECUTION_OVERRIDE_KEY:
            _cas_lab_override(db, observed, remove=True)
            db.flush()
            return
    if key in LEARNING_POLICY_SHAPES:
        _validate_learning_proposal(db, {}, removed=key)
    existing = db.get(PlatformSetting, key)
    if existing is not None:
        db.delete(existing)
        db.flush()


class EffectiveSettings:
    """Attribute-access view of the merged (DB-over-env) known settings.

    Attributes are populated dynamically from KNOWN_KEYS; the declarations below
    document the shape and let static checkers resolve attribute access.
    """

    bank_author_roles: tuple[str, ...]
    bank_publish_roles: tuple[str, ...]
    bank_repoint_roles: tuple[str, ...]
    bank_export_roles: tuple[str, ...]
    bank_retire_roles: tuple[str, ...]
    admin_home_access_roles: tuple[str, ...]
    lab_admin_access_roles: tuple[str, ...]
    reminders_admin_access_roles: tuple[str, ...]
    teaching_access_roles: tuple[str, ...]
    catalog_staff_roles: tuple[str, ...]
    gradebook_access_roles: tuple[str, ...]
    settings_access_roles: tuple[str, ...]
    reports_access_roles: tuple[str, ...]
    ical_feed_token_ttl_days: int
    ical_feed_uid_domain: str
    ical_feed_filename: str
    notifications_recent_limit: int
    bootstrap_allowed_database_role_pairs: tuple[tuple[str, str], ...]
    bootstrap_role_provisioning: dict[str, str]
    bootstrap_initial_role_slug: str
    bootstrap_tenant_is_active: bool
    bootstrap_password_min_length: int
    bootstrap_owner_first_name: str
    bootstrap_owner_last_name_template: str
    learning_search_staff_roles: tuple[str, ...]
    entrance_invitation_deadline_days: int
    bulk_enrollment_initial_role: str
    bulk_enrollment_initial_status: str
    invitation_enrollment_initial_status: str
    admission_enrollment_initial_role: str
    admission_enrollment_initial_status: str
    onboarding_enrollment_global_role: str
    onboarding_task_catalog: tuple[tuple[str, str], ...]
    invitation_onboarding_replace_outstanding: bool
    account_initial_is_active: bool
    account_initial_profile_status: str
    invitation_token_hours: float
    invitation_password_min_length: int
    invitation_human_replace_outstanding: bool
    invitation_stranded_replace_outstanding: bool
    password_change_min_length: int
    account_avatar_max_bytes: int
    account_email_results_default: bool
    account_email_digest_default: bool
    authentication_max_failed_logins: int
    authentication_lockout_minutes: float
    web_account_creation_role_provisioning: dict[str, str]
    web_account_creation_role_admission: dict[str, tuple[str, ...]]
    web_account_creation_password_min_length: int
    invitation_member_role_map: dict[str, InvitationMemberRole]
    invitation_default_member_role: InvitationMemberRole
    smtp_host: str
    password_reset_min_length: int
    password_reset_token_minutes: float
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    smtp_starttls: bool
    email_auto_on_pass: bool
    email_digest_enabled: bool
    branding_name: str
    management_inquiry_recipient: str
    max_concurrent_labs: int
    max_concurrent_labs_per_tenant: int
    lab_idle_minutes: int
    lab_command_timeout_seconds_by_action: dict[str, int]
    lab_operation_lease_seconds_by_kind: dict[str, int]
    lab_operation_max_attempts_by_kind: dict[str, int]
    lab_operation_retry_delay_seconds: int
    lab_worker_poll_interval_seconds: int
    lab_restart_reclaim_lock_timeout_seconds: int
    lab_operation_unknown_lease_seconds: int
    lab_operation_unknown_max_attempts: int
    lab_process_termination_grace_seconds: int

    def __init__(self, values: dict[str, object]) -> None:
        self.__dict__.update(values)

    def __getitem__(self, key: str) -> object:  # dict-like convenience
        return self.__dict__[key]

    def get(self, key: str, default: object = None) -> object:
        return self.__dict__.get(key, default)


def effective(db: Session | Connection | None = None, *, require_store: bool = False) -> EffectiveSettings:
    """Return known settings with DB values overriding env defaults.

    Cheap + safe: if ``db`` is None, or the table is missing/empty, or the query
    fails for any reason, the env/config defaults are returned unchanged.
    Security policy composition uses ``require_store=True`` to refuse missing
    sessions and propagate read failures rather than authorize from fallback.
    Malformed reset/invitation-policy values always refuse instead of falling back.
    """
    if require_store and db is None:
        raise ValueError("a settings database session is required")
    merged = _defaults()
    stored = {}
    if db is not None:
        try:
            stored = get_all(db)
        except Exception as exc:  # table missing/pre-migration/permission — fall back
            if require_store:
                raise
            logger.debug("settings_store.effective falling back to env defaults: %s", exc)
            stored = {}
        for key, raw in stored.items():
            if key in merged:
                merged[key] = _coerce(key, raw, merged[key])
    for key in ENTRANCE_INVITATION_POLICY_KEYS:
        merged[key] = validate_entrance_invitation_deadline_days(merged[key])
    for key in ENROLLMENT_INITIAL_STATE_POLICY_KEYS:
        merged[key] = validate_enrollment_initial_state_policy_value(key, merged[key])
    for key in ADMISSION_ENROLLMENT_POLICY_KEYS:
        merged[key] = validate_admission_enrollment_policy_value(key, merged[key])
    validate_learning_policy_relations(merged)
    merged.update(_lab_values(stored))
    return EffectiveSettings(merged)
