"""Hosted canonical recipient reads; authored here, never run locally."""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from dotmac_kernel.models import Party, PartyPerson
from sqlalchemy import delete, text, update

from app.models.identity_extensions import AcademyAccountProfile
from app.services import assessment, completion, email, lab_lifecycle
from app.services.exceptions import ConflictError
from tests.services.test_canonical_current_user import current_account

assert current_account


def test_recipient_joins_current_fields_and_preferences_without_identity_map_staleness(current_account):
    a = current_account
    cached = (a.db.get(Party, a.pid), a.db.get(PartyPerson, a.pid), a.db.get(AcademyAccountProfile, a.pid))
    changed_email = f"recipient-{uuid4().hex}@a.edu"
    a.admin.execute(update(Party).where(Party.id == a.pid).values(email=changed_email))
    a.admin.execute(update(PartyPerson).where(PartyPerson.party_id == a.pid).values(first_name="Current"))
    a.admin.execute(
        update(AcademyAccountProfile)
        .where(AcademyAccountProfile.party_id == a.pid)
        .values(prefs={"email_results": False})
    )
    a.admin.commit()
    root = a.db.get_transaction()
    recipient = completion._notification_recipient(a.db, tenant_id=a.tid, person_id=a.pid)
    assert recipient.id == a.pid and recipient.email == changed_email and recipient.first_name == "Current"
    assert recipient.prefs == {"email_results": False}
    assert not email.recipient_allows(recipient, "email_results")
    assert cached[0].email == a.email and cached[1].first_name == "Sign"
    assert a.db.get_transaction() is root


def test_wrong_tenant_and_unknown_party_refuse_recipient(current_account, tenant_b):
    a = current_account
    assert completion._notification_recipient(a.db, tenant_id=tenant_b.id, person_id=a.pid) is None
    assert completion._notification_recipient(a.db, tenant_id=a.tid, person_id=uuid4()) is None


@pytest.mark.parametrize("missing", ["profile", "subtype"])
def test_missing_canonical_recipient_part_refuses(current_account, missing):
    a = current_account
    # Deleting the Academy profile first satisfies its canonical subtype FK.
    a.admin.execute(delete(AcademyAccountProfile).where(AcademyAccountProfile.party_id == a.pid))
    if missing == "subtype":
        a.admin.execute(delete(PartyPerson).where(PartyPerson.party_id == a.pid))
    a.admin.commit()
    assert completion._notification_recipient(a.db, tenant_id=a.tid, person_id=a.pid) is None


@pytest.mark.parametrize("status,active", [("active", True), ("suspended", True), ("active", False)])
def test_delivery_read_preserves_status_behavior_without_authorizing_accounts(current_account, status, active):
    a = current_account
    a.admin.execute(update(Party).where(Party.id == a.pid).values(is_active=active))
    a.admin.execute(update(AcademyAccountProfile).where(AcademyAccountProfile.party_id == a.pid).values(status=status))
    a.admin.commit()
    assert completion._notification_recipient(a.db, tenant_id=a.tid, person_id=a.pid).id == a.pid


def test_certificate_recipient_uses_live_email_name_preferences_and_original_attribution(current_account, monkeypatch):
    a = current_account
    queued = []
    monkeypatch.setattr("app.services.email_outbox.enqueue_email", lambda db, **kw: queued.append(kw) or True)
    certificate = SimpleNamespace(id=uuid4(), serial="CANONICAL-1")
    course_id = uuid4()
    kwargs = dict(tenant_id=a.tid, person_id=a.pid, course_id=course_id, course_title="A & B", certificate=certificate)
    assert completion._email_certificate(a.db, **kwargs)
    assert queued[0]["recipient"] == a.email
    assert "Sign" in queued[0]["html_body"] and "A &amp; B" in queued[0]["html_body"]
    assert queued[0]["payload"] == {"person_id": str(a.pid), "course_id": str(course_id)}
    assert queued[0]["idempotency_key"] == f"certificate:{certificate.id}"
    a.admin.execute(
        update(AcademyAccountProfile)
        .where(AcademyAccountProfile.party_id == a.pid)
        .values(prefs={"email_results": False})
    )
    a.admin.commit()
    assert not completion._email_certificate(a.db, **kwargs)
    assert len(queued) == 1


def test_assessment_optional_intent_keeps_learning_person_and_tenant(current_account, monkeypatch):
    a = current_account
    activity = SimpleNamespace(id=uuid4(), type="mcq_test")
    score = SimpleNamespace(id=uuid4(), tenant_id=a.tid, person_id=a.pid)
    commands, deliveries = [], []
    monkeypatch.setattr(
        assessment.settings_store, "effective", lambda *args, **kw: {"learning_missing_question_weight": 1}
    )
    monkeypatch.setattr(
        assessment,
        "submit_mcq_activity",
        lambda db, command: commands.append(command) or SimpleNamespace(score=score, completion=None),
    )
    monkeypatch.setattr(email, "notify_score_if_first_pass", lambda db, **kw: deliveries.append(kw))
    assert assessment.submit_activity(a.db, tenant_id=a.tid, person_id=a.pid, activity=activity, answers={}) is score
    assert commands[0].tenant_id == a.tid and commands[0].person_id == a.pid
    assert deliveries[0]["person"].id == a.pid and deliveries[0]["person"].email == a.email
    assert deliveries[0]["score"] is score and deliveries[0]["activity"] is activity


def test_lab_optional_intent_keeps_instance_person_and_required_effect_order(current_account, monkeypatch):
    a = current_account
    instance = SimpleNamespace(
        id=uuid4(),
        tenant_id=a.tid,
        person_id=a.pid,
        activity_id=uuid4(),
        status="active",
        error=None,
        seed={},
    )
    activity = SimpleNamespace(pass_threshold=0.5)
    score = SimpleNamespace(id=uuid4())
    commands, order, deliveries = [], [], []
    monkeypatch.setattr(lab_lifecycle, "run_checks", lambda *args, **kw: {"score": 1, "max_score": 1, "per_check": []})
    monkeypatch.setattr(lab_lifecycle, "get_activity", lambda *args, **kw: activity)
    monkeypatch.setattr(
        lab_lifecycle,
        "record_lab_result",
        lambda db, command: commands.append(command) or SimpleNamespace(score=score, completion=object()),
    )
    monkeypatch.setattr(completion, "deliver_completion_notifications", lambda *args: order.append("completion"))
    monkeypatch.setattr(
        email, "notify_score_if_first_pass", lambda db, **kw: (order.append("optional"), deliveries.append(kw))
    )
    assert lab_lifecycle.grade(a.db, instance, object(), SimpleNamespace(checks=[], limits={}), object()) is score
    assert commands[0].tenant_id == a.tid and commands[0].person_id == a.pid
    assert commands[0].instance_id == instance.id and commands[0].activity_id == instance.activity_id
    assert deliveries[0]["person"].id == a.pid and deliveries[0]["person"].email == a.email
    assert deliveries[0]["score"] is score and order == ["completion", "optional"]


def test_restricted_app_role_recipient_read_needs_no_identity_update_grant(current_account):
    a = current_account
    assert a.db.scalar(text("SELECT current_user")) == "app_user"
    assert not a.db.scalar(text("SELECT has_table_privilege(current_user, 'public.parties', 'UPDATE')"))
    assert not a.db.scalar(text("SELECT has_table_privilege(current_user, 'public.party_persons', 'UPDATE')"))
    assert completion._notification_recipient(a.db, tenant_id=a.tid, person_id=a.pid).id == a.pid


def test_assessment_admission_refusal_precedes_optional_identity_read(current_account, monkeypatch):
    a = current_account
    monkeypatch.setattr(
        assessment.settings_store, "effective", lambda *args, **kw: {"learning_missing_question_weight": 1}
    )

    def refuse(db, command):
        raise assessment.AdmissionRefused("refused")

    def unexpected_read(*args, **kwargs):
        pytest.fail("refused submission must not read notification identity")

    monkeypatch.setattr(assessment, "submit_mcq_activity", refuse)
    monkeypatch.setattr(completion, "_notification_recipient", unexpected_read)
    with pytest.raises(ConflictError, match="refused"):
        assessment.submit_activity(
            a.db,
            tenant_id=a.tid,
            person_id=a.pid,
            activity=SimpleNamespace(id=uuid4(), type="mcq_test"),
            answers={},
        )
