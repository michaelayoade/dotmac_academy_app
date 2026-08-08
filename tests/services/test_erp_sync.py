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
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        # ERP always answers with a status body; "recorded" is the happy path.
        self._body = {"status": "recorded"} if body is None else body

    def json(self):
        if self._body is _UNREADABLE:
            raise ValueError("not json")
        return self._body


_UNREADABLE = object()


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
    outcome = erp_sync.push_completion(admin_session, tenant_id=tenant_a.id, completion=comp)
    assert outcome == erp_sync.SYNCED
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
    assert erp_sync.sync_pending(admin_session, tenant_id=tenant_a.id) == {
        erp_sync.SYNCED: 0, erp_sync.UNMATCHED: 0, erp_sync.FAILED: 0
    }
    assert comp.erp_synced_at is None
    admin_session.rollback()


def test_sync_pending_dedups(admin_session, tenant_a, monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(erp_sync.httpx, "post", lambda *a, **k: _FakeResp(200))
    _seed(admin_session, tenant_a)
    assert erp_sync.sync_pending(admin_session, tenant_id=tenant_a.id)[erp_sync.SYNCED] == 1
    # already synced → nothing to push
    assert erp_sync.sync_pending(admin_session, tenant_id=tenant_a.id)[erp_sync.SYNCED] == 0
    admin_session.rollback()


def test_failure_leaves_unsynced(admin_session, tenant_a, monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(erp_sync.httpx, "post", lambda *a, **k: _FakeResp(503))
    comp, _, _ = _seed(admin_session, tenant_a)
    outcome = erp_sync.push_completion(admin_session, tenant_id=tenant_a.id, completion=comp)
    assert outcome == erp_sync.FAILED
    assert comp.erp_synced_at is None
    admin_session.rollback()


# ---------------------------------------------------------------------------
# A 2xx is not delivery
# ---------------------------------------------------------------------------


def test_ignored_reply_is_not_recorded_as_delivered(admin_session, tenant_a, monkeypatch):
    """The defect: ERP answers an unmatched employee with HTTP 200 and
    {"status": "ignored"}, and the old code stamped erp_synced_at on any 2xx —
    recording as delivered a completion HR never received, and never retrying
    it. Never fired in production only because there were no completions."""
    _configure(monkeypatch)
    monkeypatch.setattr(
        erp_sync.httpx, "post",
        lambda *a, **k: _FakeResp(200, {"status": "ignored", "reason": "no matching employee"}),
    )
    comp, _, _ = _seed(admin_session, tenant_a)

    outcome = erp_sync.push_completion(admin_session, tenant_id=tenant_a.id, completion=comp)
    assert outcome == erp_sync.UNMATCHED
    assert comp.erp_synced_at is None  # stays in the backlog, visible

    admin_session.rollback()


def test_unmatched_is_counted_separately_from_failure(admin_session, tenant_a, monkeypatch):
    """A silent zero and a silent hundred-unmatched used to look identical."""
    _configure(monkeypatch)
    monkeypatch.setattr(
        erp_sync.httpx, "post", lambda *a, **k: _FakeResp(200, {"status": "ignored"})
    )
    _seed(admin_session, tenant_a)

    counts = erp_sync.sync_pending(admin_session, tenant_id=tenant_a.id)
    assert counts[erp_sync.UNMATCHED] == 1
    assert counts[erp_sync.SYNCED] == 0
    assert counts[erp_sync.FAILED] == 0
    admin_session.rollback()


def test_unreadable_2xx_body_is_retried_not_assumed(admin_session, tenant_a, monkeypatch):
    """A 2xx we cannot parse is not evidence of anything."""
    _configure(monkeypatch)
    monkeypatch.setattr(
        erp_sync.httpx, "post", lambda *a, **k: _FakeResp(200, _UNREADABLE)
    )
    comp, _, _ = _seed(admin_session, tenant_a)

    outcome = erp_sync.push_completion(admin_session, tenant_id=tenant_a.id, completion=comp)
    assert outcome == erp_sync.FAILED
    assert comp.erp_synced_at is None
    admin_session.rollback()


def test_recorded_updated_and_duplicate_replies_count_as_delivered(admin_session, tenant_a, monkeypatch):
    """ERP answers "updated" when re-delivering the same certificate ref."""
    _configure(monkeypatch)
    for status in ("recorded", "updated", "duplicate"):
        monkeypatch.setattr(
            erp_sync.httpx, "post", lambda *a, s=status, **k: _FakeResp(200, {"status": s})
        )
        comp, _, _ = _seed(admin_session, tenant_a)
        assert erp_sync.push_completion(
            admin_session, tenant_id=tenant_a.id, completion=comp
        ) == erp_sync.SYNCED
    admin_session.rollback()


def test_payload_carries_a_contract_version(admin_session, tenant_a, monkeypatch):
    """ERP dispatches on it, so a breaking change ships as version 2 beside the
    old handler rather than as a silent reshape."""
    _configure(monkeypatch)
    captured = {}

    def fake_post(url, content=None, headers=None, timeout=None):
        captured.update(content=content)
        return _FakeResp(200)

    monkeypatch.setattr(erp_sync.httpx, "post", fake_post)
    comp, _, _ = _seed(admin_session, tenant_a)
    erp_sync.push_completion(admin_session, tenant_id=tenant_a.id, completion=comp)

    assert json.loads(captured["content"])["version"] == erp_sync.CONTRACT_VERSION
    admin_session.rollback()


def test_422_with_ignored_detail_is_unmatched_not_retryable_failure(
    admin_session, tenant_a, monkeypatch
):
    """ERP now refuses an unmatched employee with 422 and the status under
    `detail`. Reading the body before the status line keeps both the old 200 and
    the new 422 shape classified as UNMATCHED — otherwise the 422 would look
    like a transient failure and retry forever."""
    _configure(monkeypatch)
    monkeypatch.setattr(
        erp_sync.httpx, "post",
        lambda *a, **k: _FakeResp(
            422, {"detail": {"status": "ignored", "reason": "no matching employee"}}
        ),
    )
    comp, _, _ = _seed(admin_session, tenant_a)

    outcome = erp_sync.push_completion(admin_session, tenant_id=tenant_a.id, completion=comp)
    assert outcome == erp_sync.UNMATCHED
    assert comp.erp_synced_at is None
    admin_session.rollback()


def test_unsupported_event_is_unmatched_not_delivered(admin_session, tenant_a, monkeypatch):
    """A version ERP cannot route is not delivery either."""
    _configure(monkeypatch)
    monkeypatch.setattr(
        erp_sync.httpx, "post",
        lambda *a, **k: _FakeResp(422, {"detail": {"status": "unsupported"}}),
    )
    comp, _, _ = _seed(admin_session, tenant_a)

    assert erp_sync.push_completion(
        admin_session, tenant_id=tenant_a.id, completion=comp
    ) == erp_sync.UNMATCHED
    assert comp.erp_synced_at is None
    admin_session.rollback()


def test_genuine_server_error_is_still_a_retryable_failure(admin_session, tenant_a, monkeypatch):
    """A 503 with no status body must stay FAILED — it is worth retrying."""
    _configure(monkeypatch)
    monkeypatch.setattr(
        erp_sync.httpx, "post", lambda *a, **k: _FakeResp(503, {"detail": "boom"})
    )
    comp, _, _ = _seed(admin_session, tenant_a)

    assert erp_sync.push_completion(
        admin_session, tenant_id=tenant_a.id, completion=comp
    ) == erp_sync.FAILED
    assert comp.erp_synced_at is None
    admin_session.rollback()
