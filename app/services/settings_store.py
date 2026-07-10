"""Platform settings store — DB-over-env effective configuration.

Reads/writes the ``platform_settings`` key/value table and merges stored values
over the env/config defaults from :data:`app.config.settings`. Everything is
best-effort and safe: if the table is missing or empty (fresh DB, pre-migration),
:func:`effective` simply returns the env defaults so nothing breaks.

Writes require a platform/admin session (``platform_api``); ``app_user`` may only
SELECT. The caller owns the transaction boundary — these helpers ``flush`` only.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.config import settings
from app.models.platform_settings import PlatformSetting

logger = logging.getLogger(__name__)

# Keys whose stored string value is coerced to a non-str type on read.
_INT_KEYS = frozenset({"smtp_port", "max_concurrent_labs", "lab_idle_minutes"})
_BOOL_KEYS = frozenset({"smtp_starttls", "email_auto_on_pass", "email_digest_enabled"})

# The full set of known keys, with their default sourced live from `settings`
# (or a literal) so monkeypatching `settings.*` in tests is reflected here.
KNOWN_KEYS: tuple[str, ...] = (
    "smtp_host",
    "smtp_port",
    "smtp_user",
    "smtp_password",
    "smtp_from",
    "smtp_starttls",
    "email_auto_on_pass",
    "email_digest_enabled",
    "branding_name",
    "max_concurrent_labs",
    "lab_idle_minutes",
)


def _defaults() -> dict[str, object]:
    """Env/config defaults for every known key (read live so tests can patch)."""
    return {
        "smtp_host": settings.smtp_host,
        "smtp_port": settings.smtp_port,
        "smtp_user": settings.smtp_user,
        "smtp_password": settings.smtp_password,
        "smtp_from": settings.smtp_from,
        "smtp_starttls": settings.smtp_starttls,
        "email_auto_on_pass": True,
        "email_digest_enabled": True,
        "branding_name": "Dotmac Academy",
        "max_concurrent_labs": settings.max_concurrent_labs,
        "lab_idle_minutes": settings.lab_idle_minutes,
    }


def _coerce_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _coerce(key: str, value: str | None, default: object) -> object:
    """Coerce a stored string to the key's native type, falling back on error."""
    if value is None:
        return default
    if key in _BOOL_KEYS:
        return _coerce_bool(value)
    if key in _INT_KEYS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    return value


def get_all(db: Session) -> dict[str, str]:
    """Return every stored row as a ``{key: value}`` dict (values are strings)."""
    rows = db.query(PlatformSetting).all()
    return {r.key: r.value for r in rows if r.value is not None}


def set_many(db: Session, values: dict[str, str | None]) -> None:
    """Upsert each ``key -> value`` (string). Flushes; never commits."""
    for key, value in values.items():
        existing = db.get(PlatformSetting, key)
        if existing is None:
            db.add(PlatformSetting(key=key, value=value))
        else:
            existing.value = value
    db.flush()


def delete(db: Session, key: str) -> None:
    """Delete a stored key if present. Flushes; never commits."""
    existing = db.get(PlatformSetting, key)
    if existing is not None:
        db.delete(existing)
        db.flush()


class EffectiveSettings:
    """Attribute-access view of the merged (DB-over-env) known settings.

    Attributes are populated dynamically from KNOWN_KEYS; the declarations below
    document the shape and let static checkers resolve attribute access.
    """

    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    smtp_starttls: bool
    email_auto_on_pass: bool
    email_digest_enabled: bool
    branding_name: str
    max_concurrent_labs: int
    lab_idle_minutes: int

    def __init__(self, values: dict[str, object]) -> None:
        self.__dict__.update(values)

    def __getitem__(self, key: str) -> object:  # dict-like convenience
        return self.__dict__[key]

    def get(self, key: str, default: object = None) -> object:
        return self.__dict__.get(key, default)


def effective(db: Session | None = None) -> EffectiveSettings:
    """Return known settings with DB values overriding env defaults.

    Cheap + safe: if ``db`` is None, or the table is missing/empty, or the query
    fails for any reason, the env/config defaults are returned unchanged.
    """
    merged = _defaults()
    if db is not None:
        try:
            stored = get_all(db)
        except Exception as exc:  # table missing/pre-migration/permission — fall back
            logger.debug("settings_store.effective falling back to env defaults: %s", exc)
            stored = {}
        for key, raw in stored.items():
            if key in merged:
                merged[key] = _coerce(key, raw, merged[key])
    return EffectiveSettings(merged)
