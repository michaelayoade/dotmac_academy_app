from __future__ import annotations

import os
from datetime import UTC, datetime

from dotmac_kernel.models import Party, PartyPerson, PartyRoleGrant, PartyType
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models.assessment import Activity, Question, QuestionBank
from app.models.auth import UserCredential
from app.models.cohort import Cohort, Enrollment
from app.models.course import Chapter, Course
from app.models.identity_extensions import AcademyAccountProfile, AcademyCredentialPolicy
from app.models.lab import LabTemplate
from app.models.offering import CourseOffering
from app.models.tenant import Tenant
from app.services.bootstrap import bootstrap_tenant, ensure_roles
from app.services.security import hash_password

ADMIN_EMAIL = "admin@dotmac.io"
TENANT_SLUG = "dotmac"
DISCIPLINE = "networking"

# Weak sentinels that must never seed a real environment. A committed default is
# exactly how a public-repo credential leak happened before — so the password is
# resolved at runtime from the environment and refuses to fall back.
_FORBIDDEN_PASSWORDS = {"", "changeme-dev-only", "changeme", "password", "admin"}
_MIN_PASSWORD_LEN = 12


def resolve_admin_password() -> str:
    """The seed admin password, from SEED_ADMIN_PASSWORD. No default on purpose."""
    pw = os.environ.get("SEED_ADMIN_PASSWORD", "")
    if pw in _FORBIDDEN_PASSWORDS or len(pw) < _MIN_PASSWORD_LEN:
        raise SystemExit(
            "Refusing to seed: set SEED_ADMIN_PASSWORD to a strong secret "
            f"(>= {_MIN_PASSWORD_LEN} chars, not a placeholder) before running this script. "
            "e.g. SEED_ADMIN_PASSWORD=$(openssl rand -base64 24)"
        )
    return pw


def one(db, stmt):
    return db.scalars(stmt).first()


def main() -> None:
    admin_password = resolve_admin_password()  # fail fast before touching the DB
    engine = create_engine(settings.migration_database_url, future=True)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = Session()
    try:
        tenant = one(db, select(Tenant).where(Tenant.slug == TENANT_SLUG))
        bootstrapped_owner_id = None
        if tenant is None:
            # Fresh environment: the canonical bootstrap creates the tenant
            # and its owner admin in one act (never a hand-rolled tenant).
            result = bootstrap_tenant(
                db,
                slug=TENANT_SLUG,
                name="Dotmac Academy",
                admin_email=ADMIN_EMAIL,
                admin_password=admin_password,
            )
            bootstrapped_owner_id = result.owner_party_id
            tenant = one(db, select(Tenant).where(Tenant.id == result.id))

        roles = ensure_roles(db, tenant.id)
        admin = one(
            db,
            select(Party)
            .where(Party.tenant_id == tenant.id)
            .where(Party.email == ADMIN_EMAIL)
            .where(Party.party_type == PartyType.person),
        )
        now = datetime.now(UTC)
        if admin is None:
            admin = Party(
                tenant_id=tenant.id,
                party_type=PartyType.person,
                display_name="Dotmac Admin",
                email=ADMIN_EMAIL,
                is_active=True,
            )
            db.add(admin)
            db.flush()
            db.add(PartyPerson(party_id=admin.id, first_name="Dotmac", last_name="Admin"))
            db.add(
                AcademyAccountProfile(
                    tenant_id=tenant.id, party_id=admin.id, status="active",
                    prefs={}, created_at=now, updated_at=now,
                )
            )
            db.flush()
        person_row = one(db, select(PartyPerson).where(PartyPerson.party_id == admin.id))
        if person_row is not None:
            person_row.first_name = "Dotmac"
            person_row.last_name = "Admin"
        profile = one(
            db,
            select(AcademyAccountProfile).where(
                AcademyAccountProfile.tenant_id == tenant.id,
                AcademyAccountProfile.party_id == admin.id,
            ),
        )
        if profile is not None:
            profile.status = "active"
            profile.updated_at = now
        if bootstrapped_owner_id != admin.id:
            cred = one(
                db,
                select(UserCredential)
                .where(UserCredential.tenant_id == tenant.id)
                .where(UserCredential.party_id == admin.id),
            )
            if cred is None:
                cred = UserCredential(
                    tenant_id=tenant.id,
                    party_id=admin.id,
                    password_hash=hash_password(admin_password),
                )
                db.add(cred)
                db.flush()
                db.add(
                    AcademyCredentialPolicy(
                        tenant_id=tenant.id, credential_id=cred.id, email=ADMIN_EMAIL,
                        failed_login_attempts=0, locked_until=None, lifecycle_version=0,
                        reset_required=False, created_at=now, updated_at=now,
                    )
                )
            else:
                cred.password_hash = hash_password(admin_password)

        for role_slug in ("admin", "instructor"):
            role = roles[role_slug]
            grant = one(
                db,
                select(PartyRoleGrant)
                .where(PartyRoleGrant.tenant_id == tenant.id)
                .where(PartyRoleGrant.party_id == admin.id)
                .where(PartyRoleGrant.role_id == role.id),
            )
            if grant is None:
                db.add(PartyRoleGrant(tenant_id=tenant.id, party_id=admin.id, role_id=role.id))

        cohort = one(
            db,
            select(Cohort)
            .where(Cohort.tenant_id == tenant.id)
            .where(Cohort.name == "Dotmac Academy Demo Cohort"),
        )
        if cohort is None:
            cohort = Cohort(
                tenant_id=tenant.id,
                name="Dotmac Academy Demo Cohort",
                discipline=DISCIPLINE,
                status="active",
            )
            db.add(cohort)
            db.flush()
        else:
            cohort.discipline = DISCIPLINE
            cohort.status = "active"

        enrollment = one(
            db,
            select(Enrollment)
            .where(Enrollment.tenant_id == tenant.id)
            .where(Enrollment.cohort_id == cohort.id)
            .where(Enrollment.person_id == admin.id),
        )
        if enrollment is None:
            db.add(
                Enrollment(
                    tenant_id=tenant.id,
                    cohort_id=cohort.id,
                    person_id=admin.id,
                    role_in_cohort="instructor",
                    status="active",
                )
            )
        else:
            enrollment.role_in_cohort = "instructor"
            enrollment.status = "active"

        course = one(
            db,
            select(Course)
            .where(Course.tenant_id == tenant.id)
            .where(Course.slug == "networking-foundations-demo"),
        )
        if course is None:
            course = Course(
                tenant_id=tenant.id,
                slug="networking-foundations-demo",
                title="Networking Foundations Demo",
                discipline=DISCIPLINE,
                source_ref="seed:academy-demo",
                version=1,
                status="published",
            )
            db.add(course)
            db.flush()
        else:
            course.title = "Networking Foundations Demo"
            course.discipline = DISCIPLINE
            course.status = "published"

        chapter = one(
            db,
            select(Chapter)
            .where(Chapter.tenant_id == tenant.id)
            .where(Chapter.course_id == course.id)
            .where(Chapter.number == 1),
        )
        if chapter is None:
            chapter = Chapter(
                tenant_id=tenant.id,
                course_id=course.id,
                number=1,
                title="IP Addressing, Routing, and Operations",
                part="Foundation",
                body_md=(
                    "# IP Addressing, Routing, and Operations\n\n"
                    "This demo chapter introduces subnetting, default gateways, "
                    "routing checks, and operational troubleshooting workflows."
                ),
                body_html=(
                    "<h1>IP Addressing, Routing, and Operations</h1>"
                    "<p>This demo chapter introduces subnetting, default gateways, "
                    "routing checks, and operational troubleshooting workflows.</p>"
                ),
                source_hash="seed-academy-demo",
                order_index=1,
            )
            db.add(chapter)
        else:
            chapter.title = "IP Addressing, Routing, and Operations"
            chapter.part = "Foundation"
            chapter.body_html = (
                "<h1>IP Addressing, Routing, and Operations</h1>"
                "<p>This demo chapter introduces subnetting, default gateways, "
                "routing checks, and operational troubleshooting workflows.</p>"
            )
            chapter.body_md = (
                "# IP Addressing, Routing, and Operations\n\n"
                "This demo chapter introduces subnetting, default gateways, "
                "routing checks, and operational troubleshooting workflows."
            )

        offering = one(
            db,
            select(CourseOffering)
            .where(CourseOffering.tenant_id == tenant.id)
            .where(CourseOffering.cohort_id == cohort.id)
            .where(CourseOffering.course_id == course.id),
        )
        if offering is None:
            db.add(
                CourseOffering(
                    tenant_id=tenant.id,
                    cohort_id=cohort.id,
                    course_id=course.id,
                    status="active",
                )
            )
        else:
            offering.status = "active"

        bank = one(
            db,
            select(QuestionBank)
            .where(QuestionBank.tenant_id == tenant.id)
            .where(QuestionBank.course_id == course.id)
            .where(QuestionBank.chapter_number == 1)
            .where(QuestionBank.kind == "chapter"),
        )
        if bank is None:
            bank = QuestionBank(
                tenant_id=tenant.id,
                course_id=course.id,
                chapter_number=1,
                kind="chapter",
                version=1,
            )
            db.add(bank)
            db.flush()

        questions = [
            {
                "ext_id": "single_gateway",
                "stem": "Which device is normally used as the default gateway for hosts on a LAN?",
                "type": "single",
                "options": ["Access switch", "Router interface", "DNS resolver", "Patch panel"],
                "correct": ["Router interface"],
                "rubric_category": "recall",
                "explanation": "The default gateway is the routed interface used to leave the local subnet.",
                "weight": 1,
            },
            {
                "ext_id": "multi_private_ranges",
                "stem": "Select all RFC1918 private IPv4 ranges.",
                "type": "multi",
                "options": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "198.51.100.0/24"],
                "correct": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                "rubric_category": "application",
                "explanation": "198.51.100.0/24 is reserved for documentation, not private addressing.",
                "weight": 2,
            },
            {
                "ext_id": "tf_same_subnet",
                "stem": "Two hosts in the same IPv4 subnet can usually communicate without a router.",
                "type": "truefalse",
                "options": ["true", "false"],
                "correct": ["true"],
                "rubric_category": "recall",
                "explanation": "Same-subnet traffic is delivered at layer 2 after address resolution.",
                "weight": 1,
            },
            {
                "ext_id": "numeric_hosts",
                "stem": "How many usable host addresses are in a /30 IPv4 subnet?",
                "type": "numeric",
                "options": {"tolerance": 0},
                "correct": [2],
                "rubric_category": "application",
                "explanation": "A /30 has four addresses: network, two usable hosts, and broadcast.",
                "weight": 1,
            },
            {
                "ext_id": "fill_gap_protocol",
                "stem": "Fill in the gap: The protocol used to map an IPv4 address to a MAC address is ____.",
                "type": "short_text",
                "options": {},
                "correct": ["ARP", "Address Resolution Protocol"],
                "rubric_category": "analysis",
                "explanation": "ARP resolves IPv4 addresses to link-layer addresses on the local network.",
                "weight": 1,
            },
        ]
        for item in questions:
            q = one(
                db,
                select(Question)
                .where(Question.tenant_id == tenant.id)
                .where(Question.bank_id == bank.id)
                .where(Question.ext_id == item["ext_id"]),
            )
            if q is None:
                q = Question(tenant_id=tenant.id, bank_id=bank.id, **item)
                db.add(q)
            else:
                for key, value in item.items():
                    setattr(q, key, value)

        assessment = one(
            db,
            select(Activity)
            .where(Activity.tenant_id == tenant.id)
            .where(Activity.course_id == course.id)
            .where(Activity.title == "Chapter 1 Mixed Form Assessment"),
        )
        if assessment is None:
            assessment = Activity(
                tenant_id=tenant.id,
                course_id=course.id,
                chapter_number=1,
                type="mcq_test",
                bank_id=bank.id,
                title="Chapter 1 Mixed Form Assessment",
                pass_threshold=0.7,
                max_attempts=3,
                grading="auto",
                weight=1.0,
                question_count=None,
            )
            db.add(assessment)
        else:
            assessment.bank_id = bank.id
            assessment.type = "mcq_test"
            assessment.pass_threshold = 0.7
            assessment.max_attempts = 3
            assessment.grading = "auto"
            assessment.weight = 1.0

        lab_activity = one(
            db,
            select(Activity)
            .where(Activity.tenant_id == tenant.id)
            .where(Activity.course_id == course.id)
            .where(Activity.title == "Lab: Verify Gateway Reachability"),
        )
        if lab_activity is None:
            lab_activity = Activity(
                tenant_id=tenant.id,
                course_id=course.id,
                chapter_number=1,
                type="lab",
                bank_id=None,
                title="Lab: Verify Gateway Reachability",
                pass_threshold=0.8,
                max_attempts=None,
                grading="manual",
                weight=1.0,
                question_count=None,
            )
            db.add(lab_activity)
            db.flush()
        else:
            lab_activity.type = "lab"
            lab_activity.chapter_number = 1
            lab_activity.pass_threshold = 0.8
            lab_activity.grading = "manual"

        lab = one(
            db,
            select(LabTemplate)
            .where(LabTemplate.tenant_id == tenant.id)
            .where(LabTemplate.activity_id == lab_activity.id),
        )
        topology = """name: ${instance_name}
topology:
  nodes:
    host1:
      kind: linux
      image: alpine:latest
    router1:
      kind: linux
      image: alpine:latest
  links:
    - endpoints: [host1:eth1, router1:eth1]
"""
        checks = [
            {
                "id": "ping_gateway",
                "label": "Host can reach the gateway",
                "node": "host1",
                "command": "ping -c 1 192.0.2.1",
                "expect": "0% packet loss",
                "weight": 1,
            }
        ]
        if lab is None:
            lab = LabTemplate(
                tenant_id=tenant.id,
                course_id=course.id,
                chapter_number=1,
                activity_id=lab_activity.id,
                slug="verify-gateway-reachability",
                title="Verify Gateway Reachability",
                topology=topology,
                instructions_html=(
                    "<p>Launch the lab, inspect the host addressing, and verify "
                    "that the host can reach its default gateway.</p>"
                ),
                instructions_md=(
                    "Launch the lab, inspect the host addressing, and verify "
                    "that the host can reach its default gateway."
                ),
                checks=checks,
                seed_spec={"gateway": {"type": "choice", "values": ["192.0.2.1"]}},
                limits={"minutes": 45, "memory_mb": 256},
                engine="containerlab",
                source_hash="seed-academy-demo",
                version=1,
            )
            db.add(lab)
        else:
            lab.course_id = course.id
            lab.chapter_number = 1
            lab.slug = "verify-gateway-reachability"
            lab.title = "Verify Gateway Reachability"
            lab.topology = topology
            lab.instructions_html = (
                "<p>Launch the lab, inspect the host addressing, and verify "
                "that the host can reach its default gateway.</p>"
            )
            lab.instructions_md = (
                "Launch the lab, inspect the host addressing, and verify "
                "that the host can reach its default gateway."
            )
            lab.checks = checks
            lab.seed_spec = {"gateway": {"type": "choice", "values": ["192.0.2.1"]}}
            lab.limits = {"minutes": 45, "memory_mb": 256}
            lab.engine = "containerlab"
            lab.source_hash = "seed-academy-demo"

        db.commit()
        print(f"Seeded tenant: {tenant.slug} ({tenant.id})")
        print(f"Admin: {ADMIN_EMAIL}")
        print(f"Cohort: {cohort.name} ({cohort.id})")
        print(f"Course: {course.title} / {course.slug} ({course.id})")
        print("Assessment: Chapter 1 Mixed Form Assessment")
        print("Lab: Verify Gateway Reachability")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
        engine.dispose()


if __name__ == "__main__":
    main()
