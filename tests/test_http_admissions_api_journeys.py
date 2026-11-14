"""Maintained full-assembly admissions API journeys; execute in hosted CI only.

Public intake, API sign-in, authorization and writes use the ordinary app. Only
reference/account fixtures and independent persisted-state inspection use admin.
No worker or mail transport runs; pending outbox rows prove queued intent only.
"""

from uuid import uuid4

from dotmac_learning.participation_models import Cohort, CohortTrack, Track

from tests.issue2_wave2_support import _bank_with_questions
from tests.issue2_wave3_support import current_account, grant_std, make_person_credential, make_person_party
from tests.test_http_journeys import _run

assert current_account  # Imported pytest fixture.


_API_INTAKE = r"""
# Keep the API's request/response EmailStr validation active with a valid example domain.
email = "api-intake@example.com"
page = csrf_get("/apply")
assert os.environ["JOURNEY_CHOICE"] in page.text
submitted = post("/apply", {
    "first_name": "API", "last_name": "Applicant", "email": email,
    "track_choice": os.environ["JOURNEY_CHOICE"], "has_device": "yes",
})
assert submitted.status_code == 200 and "Application received" in submitted.text
applicants = rows(Applicant, email=email)
assert len(applicants) == 1
applicant = applicants[0]
assert applicant.status == "applied" and applicant.source == "website" and applicant.person_id is None
path = f"/admissions/{applicant.id}"
cohort = os.environ["JOURNEY_COHORT"]

def api_post(connection, url, payload, auth=None):
    return connection.post(url, json=payload, headers={
        "Origin": str(connection.base_url).rstrip("/"),
        "x-csrf-token": connection.cookies.get("csrf_token", ""),
        **(auth or {}),
    })

def api_login(connection, email):
    assert connection.get("/login").status_code == 200
    response = api_post(connection, "/auth/login", {"email": email, "password": "chosen-password9"})
    assert response.status_code == 200, (response.status_code, response.text)
    assert response.json()["token_type"] == "bearer"
    auth = {"Authorization": "Bearer " + response.json()["access_token"]}
    assert connection.get("/auth/me", headers=auth).status_code == 200
    return auth

def product_state(tenant=tid):
    # Each call uses a fresh committed-state connection, never the request identity map.
    with inspect_db() as db:
        db.execute(text("SELECT set_config('app.current_tenant', :tenant, true)"), {"tenant": str(tenant)})
        state = {}
        for model in (Applicant, OnboardingTask, EmailOutbox, Party, PartyRoleGrant, Enrollment, AccountToken):
            state[model.__name__] = [dict(row) for row in db.execute(
                select(model.__table__).where(model.tenant_id == tenant).order_by(model.id)
            ).mappings()]
        state["applicant_audits"] = [dict(row) for row in db.execute(
            select(AuditEvent.__table__).where(
                AuditEvent.tenant_id == tenant, AuditEvent.entity_type == "applicant",
                AuditEvent.entity_id == str(applicant.id),
            ).order_by(AuditEvent.id)
        ).mappings()]
        return state
"""


_API_ENROLLMENT = (
    _API_INTAKE
    + r"""
auth = api_login(client, os.environ["JOURNEY_EMAIL"])
read = client.get(path, headers=auth)
assert read.status_code == 200 and read.json()["email"] == email
for status in ("screened", "accepted", "onboarding"):
    response = api_post(client, path + "/transition", {"to_status": status, "notes": "API review"}, auth)
    assert response.status_code == 200, (status, response.status_code, response.text)
    assert response.json()["status"] == rows(Applicant, id=applicant.id)[0].status == status

tasks_response = client.get(path + "/onboarding", headers=auth)
assert tasks_response.status_code == 200
tasks = tasks_response.json()
assert {task["key"] for task in tasks} == {"entrance_assessment", "confirm_details", "orientation"}
assert all(task["status"] == "pending" for task in tasks)
emailed_link("onboarding_invite", "/onboarding", email)
before = product_state()
premature = api_post(client, path + "/enroll", {"cohort_id": cohort}, auth)
assert premature.status_code == 400, (premature.status_code, premature.text)
assert product_state() == before
assert rows(Party, email=email) == []
assert rows(Enrollment, cohort_id=UUID(cohort)) == []
# The same authenticated client recovers through real task writes, then enrolls.
for task in tasks:
    completed = api_post(client, f"/admissions/onboarding-tasks/{task['id']}", {"status": "done"}, auth)
    assert completed.status_code == 200, (completed.status_code, completed.text)
    assert completed.json()["status"] == "done" and completed.json()["completed_at"] is not None
assert all(task.status == "done" for task in rows(OnboardingTask, applicant_id=applicant.id))
response = api_post(client, path + "/enroll", {"cohort_id": cohort}, auth)
assert response.status_code == 200, (response.status_code, response.text)
enrolled = rows(Applicant, id=applicant.id)[0]
assert response.json()["status"] == enrolled.status == "enrolled"
assert response.json()["person_id"] == str(enrolled.person_id)
people = rows(Party, email=email)
assert len(people) == 1 and people[0].id == enrolled.person_id
memberships = rows(Enrollment, person_id=enrolled.person_id)
assert len(memberships) == 1
assert (str(memberships[0].cohort_id), str(memberships[0].track_id), memberships[0].status,
        memberships[0].role_in_cohort) == (cohort, os.environ["JOURNEY_TRACK"], "active", "student")
# API enrollment preserves global grants; self-service onboarding owns its global student grant.
assert rows(PartyRoleGrant, party_id=enrolled.person_id) == []
transitions = rows(AuditEvent, entity_id=str(applicant.id), action="applicant.transition")
assert {event.details["to_status"] for event in transitions} == {"screened", "accepted", "onboarding", "enrolled"}
assert len(transitions) == 4
assert all(event.details["source"] == "admin_api" for event in transitions)
assert all(str(event.actor_party_id) == os.environ["JOURNEY_PERSON"] for event in transitions)
# A repeated enrollment is refused without duplicating identity, grants, audit or mail.
before = product_state()
assert api_post(client, path + "/enroll", {"cohort_id": cohort}, auth).status_code == 400
assert product_state() == before
mail = rows(EmailOutbox, recipient=email)
assert mail and {"application_received", "onboarding_invite"}.issubset({row.kind for row in mail})
assert all(row.status == "pending" and row.attempts == 0 and row.sent_at is None for row in mail)
assert rows(LabInstance) == [] and rows(LabOperation) == [] and rows(ERPCompletionCheckpoint) == []
"""
)


_API_ISOLATION = (
    _API_INTAKE
    + r"""
# Reuse the outer application lifespan; a second client must not rerun startup.
other = TestClient(app, base_url=os.environ["JOURNEY_OTHER_ORIGIN"], follow_redirects=False)
try:
    foreign_auth = api_login(other, os.environ["JOURNEY_OTHER_EMAIL"])
    before = product_state()
    other_tenant = UUID(os.environ["JOURNEY_OTHER_TENANT"])
    before_other = product_state(other_tenant)
    hidden = other.get(path, headers=foreign_auth)
    assert hidden.status_code == 404 and email not in hidden.text
    listing = other.get("/admissions", headers=foreign_auth)
    assert listing.status_code == 200 and email not in listing.text
    assert str(applicant.id) not in {row["id"] for row in listing.json()}
    for suffix, payload in (("/transition", {"to_status": "screened"}), ("/enroll", {"cohort_id": cohort})):
        denied = api_post(other, path + suffix, payload, foreign_auth)
        assert denied.status_code == 404, (denied.status_code, denied.text)
        assert email not in denied.text
        assert product_state() == before
        assert product_state(other_tenant) == before_other
finally:
    other.close()

student_auth = api_login(client, os.environ["JOURNEY_STUDENT_EMAIL"])
before = product_state()
assert client.get(path, headers=student_auth).status_code == 403
for suffix, payload in (("/transition", {"to_status": "screened"}), ("/enroll", {"cohort_id": cohort})):
    denied = api_post(client, path + suffix, payload, student_auth)
    assert denied.status_code == 403, (denied.status_code, denied.text)
    assert email not in denied.text
    assert product_state() == before
# A genuine tenant-A admin can still read and write after both isolation refusals.
auth = api_login(client, os.environ["JOURNEY_EMAIL"])
assert client.get(path, headers=auth).json()["email"] == email
recovered = api_post(client, path + "/transition", {"to_status": "screened"}, auth)
assert recovered.status_code == 200 and recovered.json()["status"] == "screened"
assert rows(Applicant, id=applicant.id)[0].status == "screened"
assert rows(Party, email=email) == [] and rows(Enrollment, cohort_id=UUID(cohort)) == []
events = rows(AuditEvent, entity_id=str(applicant.id), action="applicant.transition")
assert len(events) == 1 and events[0].details["source"] == "admin_api"
assert str(events[0].actor_party_id) == os.environ["JOURNEY_PERSON"]
"""
)


def _intake(a):
    grant_std(a.admin, tenant_id=a.tid, party_id=a.pid, role="admin")
    bank = _bank_with_questions(a.admin, a.tenant)
    cohort = Cohort(tenant_id=a.tid, name="API intake", discipline="fiber", status="active", entrance_bank_id=bank.id)
    track = Track(tenant_id=a.tid, slug=uuid4().hex, name="API training track", status="active")
    a.admin.add_all([cohort, track])
    a.admin.flush()
    a.admin.add(CohortTrack(tenant_id=a.tid, cohort_id=cohort.id, track_id=track.id, status="active"))
    a.admin.commit()
    return {
        "JOURNEY_CHOICE": f"{cohort.id}:{track.id}",
        "JOURNEY_COHORT": cohort.id,
        "JOURNEY_TRACK": track.id,
        "JOURNEY_PERSON": a.pid,
    }


def test_public_application_api_review_tasks_and_enrollment_recover_after_refusal(current_account):
    _run(current_account, _API_ENROLLMENT, **_intake(current_account))


def test_public_applicant_api_rejects_foreign_admin_and_local_student_writes(current_account):
    from app.services.security import hash_password

    a = current_account
    extra = _intake(a)
    for tenant, role, key in ((a.tenant_b, "admin", "OTHER"), (a.tenant, "student", "STUDENT")):
        email = f"api-{key.lower()}@example.com"
        person = make_person_party(a.admin, tenant_id=tenant.id, email=email, first_name="API", last_name=key)
        make_person_credential(
            a.admin,
            tenant_id=tenant.id,
            party_id=person.id,
            email=email,
            password_hash=hash_password("chosen-password9"),
        )
        grant_std(a.admin, tenant_id=tenant.id, party_id=person.id, role=role)
        extra[f"JOURNEY_{key}_EMAIL"] = email
    a.admin.commit()
    _run(
        a,
        _API_ISOLATION,
        JOURNEY_OTHER_ORIGIN=f"http://{a.tenant_b.slug}.localhost",
        JOURNEY_OTHER_TENANT=a.tenant_b.id,
        **extra,
    )
