"""Platform-wide settings — a simple key/value store.

Like :class:`app.models.tenant.Tenant`, this is a PLATFORM-level table: it has
NO ``tenant_id`` column and is NOT under RLS. Rows are read by ``app_user`` and
``platform_api`` (SELECT) and written only by ``platform_api`` (and the offline
``app_admin`` owner). Values are stored as text and coerced on read by
:mod:`app.services.settings_store`.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class PlatformSetting(Base):
    __tablename__ = "platform_settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
