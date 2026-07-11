"""Push course completions to dotmac_erp HR (best-effort, signed, deduped)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from app.config import settings
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.person import Person
from app.services import erp_sync


class _FakeResp:
    def __init__(self, status_code):
        self.status_code = status_code


def _seed(admin_session, tenant, *, status="completed"):
    course = Course(
        tenant_id=tenant.id,
        slug=f"c-{uuid.uuid4().hex[:6]}",
        title="Fiber Splicing",
        discipline="fiber",
        source_ref="x",
        version=1,
    )
    person = Person(
        tenant_id=tenant.id,
        email=f"e{uuid.uuid4().hex[:6]}@dotmac.ng",
        first_name="E",
        last_name="M",
    )
    admin_session.add_all([course, person])
    admin_session.flush()
    comp = CourseCompletion(
        tenant_id=tenant.id,
        person_id=person.id,
        course_id=course.id,
        status=status,
        pct=1.0,
        completed_at=datetime(2026, 7, 11, tzinfo=UTC),
    )
    admin_session.add(comp)
    admin_session.flush()
    return comp, person, course


def _configure(monkeypatch, url="https://erp.example/dotmac-academy/webhook"):
    monkeypatch.setattr(settings, "erp_webhook_url", url, raising=False)
    monkeypatch.setattr(settings, "erp_webhook_secret", "shh", raising=False)


def test_push_marks_synced_and_signs(admin_session, tenant_a, monkeypatch):
    _configure(monkeypatch)
    captured = {}

    def fake_post(url, content=None, headers=None, timeout=None):
        captured.update(url=url, content=content, headers=headers)
        return _FakeResp(200)

    monkeypatch.setattr(erp_sync.httpx, "post", fake_post)

    comp, person, _ = _seed(admin_session, tenant_a)
    ok = erp_sync.push_completion(admin_session, tenant_id=tenant_a.id, completion=comp)
    assert ok is True
    assert comp.erp_synced_at is not None
    body = json.loads(captured["content"])
    assert body["event"] == "course_completed"
    assert body["email"] == person.email
    assert body["course_title"] == "Fiber Splicing"
    assert body["passed"] is True
    assert body["certificate_ref"] == str(comp.id)
    assert captured["headers"]["X-Webhook-Signature-256"].startswith("sha256=")
    admin_session.rollback()


def test_inert_when_unconfigured(admin_session, tenant_a, monkeypatch):
    monkeypatch.setattr(settings, "erp_webhook_url", "", raising=False)
    comp, _, _ = _seed(admin_session, tenant_a)
    assert erp_sync.sync_pending(admin_session, tenant_id=tenant_a.id) == 0
    assert comp.erp_synced_at is None
    admin_session.rollback()


def test_sync_pending_dedups(admin_session, tenant_a, monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(erp_sync.httpx, "post", lambda *a, **k: _FakeResp(200))
    _seed(admin_session, tenant_a)
    assert erp_sync.sync_pending(admin_session, tenant_id=tenant_a.id) == 1
    # already synced → nothing to push
    assert erp_sync.sync_pending(admin_session, tenant_id=tenant_a.id) == 0
    admin_session.rollback()


def test_failure_leaves_unsynced(admin_session, tenant_a, monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(erp_sync.httpx, "post", lambda *a, **k: _FakeResp(503))
    comp, _, _ = _seed(admin_session, tenant_a)
    ok = erp_sync.push_completion(admin_session, tenant_id=tenant_a.id, completion=comp)
    assert ok is False
    assert comp.erp_synced_at is None
    admin_session.rollback()
