"""Certificate issuance + PDF rendering (Slice 2d)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest
from sqlalchemy.orm import sessionmaker

from app.models.certificate import Certificate
from app.models.completion import CourseCompletion
from app.models.course import Course
from app.models.learning_event import LearningEvent
from app.models.person import Person
from app.services import certificates
from app.services.certificates import issue_certificate, render_certificate_pdf
from app.services.exceptions import ConflictError


def _person_course(db, tid):
    p = Person(tenant_id=tid, email="cert@a.edu", first_name="Cert", last_name="Holder")
    c = Course(tenant_id=tid, slug="net", title="Networking", discipline="networking",
               source_ref="x", version=1)
    db.add_all([p, c])
    db.flush()
    return p, c


def _complete(db, tid, p, c):
    db.add(CourseCompletion(tenant_id=tid, person_id=p.id, course_id=c.id,
                            status="completed", pct=1.0, completed_at=datetime.now(UTC)))
    db.flush()


def test_issue_requires_completion(admin_session, tenant_a):
    p, c = _person_course(admin_session, tenant_a.id)
    # No completion record → cannot issue.
    with pytest.raises(ConflictError):
        issue_certificate(admin_session, tenant_id=tenant_a.id, person_id=p.id, course_id=c.id)
    assert admin_session.query(CourseCompletion).filter_by(
        tenant_id=tenant_a.id, person_id=p.id, course_id=c.id
    ).count() == 0
    admin_session.rollback()


def test_issue_is_idempotent(admin_session, tenant_a):
    p, c = _person_course(admin_session, tenant_a.id)
    _complete(admin_session, tenant_a.id, p, c)
    now = datetime(2026, 6, 27, tzinfo=UTC)
    cert1 = issue_certificate(admin_session, tenant_id=tenant_a.id, person_id=p.id,
                              course_id=c.id, now=now)
    cert2 = issue_certificate(admin_session, tenant_id=tenant_a.id, person_id=p.id,
                              course_id=c.id, now=datetime(2026, 7, 1, tzinfo=UTC))
    assert cert1.serial == cert2.serial
    assert cert1.issued_at == now
    n = admin_session.query(Certificate).filter(
        Certificate.tenant_id == tenant_a.id, Certificate.person_id == p.id,
        Certificate.course_id == c.id).count()
    assert n == 1
    admin_session.rollback()


def test_render_pdf_bytes(admin_session, tenant_a):
    pdf = render_certificate_pdf(recipient_name="Ada Lovelace", course_title="Networking 101",
                                 serial="CERT-ABC123", issued_at=datetime(2026, 6, 27, tzinfo=UTC))
    assert isinstance(pdf, bytes | bytearray)
    assert bytes(pdf[:5]) == b"%PDF-"
    assert len(pdf) > 500


def test_concurrent_issuers_recheck_certificate_after_completion_lock(
    admin_engine, admin_session, tenant_a, monkeypatch
):
    person, course = _person_course(admin_session, tenant_a.id)
    _complete(admin_session, tenant_a.id, person, course)
    tid, person_id, course_id = tenant_a.id, person.id, course.id
    admin_session.commit()
    start = Barrier(2)
    real_lock = certificates.lock_existing_completion

    def synchronized_lock(db, **kwargs):
        # Both issuers have already observed no certificate. Retain the real
        # PostgreSQL aggregate lock, so the waiter must requery after acquiring it.
        start.wait(timeout=5)
        return real_lock(db, **kwargs)

    monkeypatch.setattr(certificates, "lock_existing_completion", synchronized_lock)
    factory = sessionmaker(bind=admin_engine, autoflush=False)

    def issue(_):
        with factory() as db:
            cert = issue_certificate(db, tenant_id=tid, person_id=person_id, course_id=course_id)
            identity = cert.id, cert.serial, cert.issued_at
            db.commit()
            return identity

    with ThreadPoolExecutor(max_workers=2) as pool:
        identities = list(pool.map(issue, (1, 2)))
    assert identities[0] == identities[1]
    assert admin_session.query(Certificate).filter_by(
        tenant_id=tid, person_id=person_id, course_id=course_id
    ).count() == 1
    assert admin_session.query(LearningEvent).filter_by(
        tenant_id=tid, person_id=person_id, course_id=course_id, kind="certificate_earned"
    ).count() == 1
