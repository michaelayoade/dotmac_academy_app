"""Command-line interface for platform-level management operations.

Usage
-----
    python -m app.cli <subcommand> [options]

IMPORTANT — database role for bootstrap-tenant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Creating a tenant is a platform-level operation.  The application role
(``app_user``) is RLS-restricted and cannot INSERT into the ``tenants``
table.  Before running ``bootstrap-tenant``, set ``DATABASE_URL`` (or
``PLATFORM_DATABASE_URL``) to a role that has the required privileges,
such as the migration/superuser URL, e.g.::

    DATABASE_URL=postgresql+psycopg://postgres:secret@host/db \\
        python -m app.cli bootstrap-tenant ...
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

_DEFAULT_CHAPTERS_DIR = Path("/home/dotmac/projects/dotmac-academy/manuals/00-foundation/chapters")
_DEFAULT_FIGURES_DIR = Path("/home/dotmac/projects/dotmac-academy/figures/final")
_DEFAULT_BANKS_DIR = Path("/home/dotmac/projects/dotmac-academy/manuals/00-foundation/assessments/banks")
_DEFAULT_LABS_DIR = Path("/home/dotmac/projects/dotmac-academy/manuals/00-foundation/labs")


def _bootstrap(args: argparse.Namespace) -> None:
    from app.db import SessionLocal
    from app.services.bootstrap import bootstrap_tenant

    db = SessionLocal()
    try:
        t = bootstrap_tenant(
            db,
            slug=args.slug,
            name=args.name,
            admin_email=args.admin_email,
            admin_password=args.admin_password,
        )
        db.commit()
        print(f"tenant {t.slug} ({t.id}) created")
    finally:
        db.close()


def _import_foundation(args: argparse.Namespace) -> None:
    from app.db import SessionLocal
    from app.models.tenant import Tenant
    from app.services.content_import import import_foundation, sync_figures

    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == args.tenant_slug).first()
        if tenant is None:
            raise SystemExit(f"Tenant with slug '{args.tenant_slug}' not found.")
        course = import_foundation(
            db,
            tenant_id=tenant.id,
            chapters_dir=args.chapters_dir,
            figures_dir=args.figures_dir,
            strict_figures=not args.allow_missing_figures,
        )
        db.commit()
        # Copy produced figures into the served static tree so chapter <img> tags resolve.
        static_figures = Path(__file__).resolve().parent.parent / "static" / "figures"
        copied = sync_figures(args.figures_dir, static_figures)
        print(
            f"foundation course '{course.slug}' ({course.id}) v{course.version} imported; "
            f"{copied} figure(s) synced to static/figures/"
        )
    finally:
        db.close()


def _import_manual(args: argparse.Namespace) -> None:
    from app.db import SessionLocal
    from app.models.tenant import Tenant
    from app.services.content_import import import_manual, sync_figures

    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == args.tenant_slug).first()
        if tenant is None:
            raise SystemExit(f"Tenant with slug '{args.tenant_slug}' not found.")
        course = import_manual(
            db,
            tenant_id=tenant.id,
            slug=args.slug,
            title=args.title,
            discipline=args.discipline,
            source_ref=args.source_ref or f"{args.slug}@0.1.0",
            chapters_dir=args.chapters_dir,
            figures_dir=args.figures_dir,
            strict_figures=not args.allow_missing_figures,
        )
        db.commit()
        static_figures = Path(__file__).resolve().parent.parent / "static" / "figures"
        copied = sync_figures(args.figures_dir, static_figures)
        print(
            f"course '{course.slug}' ({course.id}) v{course.version} imported; "
            f"{copied} figure(s) synced to static/figures/"
        )
    finally:
        db.close()


def _load_banks(args: argparse.Namespace) -> None:
    from app.db import SessionLocal
    from app.models.assessment import Activity
    from app.models.course import Course
    from app.models.tenant import Tenant
    from app.services.bank_loader import lint_bank, load_bank, parse_bank

    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == args.tenant_slug).first()
        if tenant is None:
            raise SystemExit(f"Tenant with slug '{args.tenant_slug}' not found.")

        banks_dir = Path(args.banks_dir)
        if not banks_dir.is_dir():
            raise SystemExit(f"Banks directory not found: {banks_dir}")

        yaml_files = sorted(banks_dir.glob("*.yaml"))
        if not yaml_files:
            print(f"No *.yaml files found in {banks_dir}")
            return

        loaded = 0
        for yaml_path in yaml_files:
            doc = parse_bank(yaml_path)
            violations = lint_bank(doc)
            if violations:
                print(f"SKIP {yaml_path.name}: rubric lint violations:")
                for v in violations:
                    print(f"  - {v}")
                continue

            # Resolve the course by slug within this tenant
            course = db.query(Course).filter(Course.tenant_id == tenant.id, Course.slug == doc.course).first()
            if course is None:
                print(f"SKIP {yaml_path.name}: course '{doc.course}' not found for tenant '{args.tenant_slug}'")
                continue

            bank = load_bank(db, tenant_id=tenant.id, course_id=course.id, doc=doc)

            # Upsert Activity for this chapter bank
            pass_threshold = {
                "chapter": 0.0,
                "mid": 0.60,
                "final": 0.70,
            }.get(doc.kind, 0.0)
            title = f"Chapter {doc.chapter} test" if doc.kind == "chapter" else f"{doc.kind.title()} assessment"
            activity = (
                db.query(Activity)
                .filter(
                    Activity.tenant_id == tenant.id,
                    Activity.course_id == course.id,
                    Activity.bank_id == bank.id,
                )
                .first()
            )
            if activity is None:
                activity = Activity(
                    tenant_id=tenant.id,
                    course_id=course.id,
                    chapter_number=doc.chapter,
                    type="mcq_test",
                    bank_id=bank.id,
                    title=title,
                    pass_threshold=pass_threshold,
                )
                db.add(activity)
            else:
                activity.title = title
                activity.pass_threshold = pass_threshold

            db.commit()
            print(f"Loaded {yaml_path.name}: bank {bank.id}, activity '{title}'")
            loaded += 1

        print(f"Done — {loaded}/{len(yaml_files)} bank(s) loaded.")
    finally:
        db.close()


def _import_labs(args: argparse.Namespace) -> None:
    from app.db import SessionLocal
    from app.models.course import Course
    from app.models.tenant import Tenant
    from app.services.lab_content import import_labs

    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.slug == args.tenant_slug).first()
        if tenant is None:
            raise SystemExit(f"Tenant with slug '{args.tenant_slug}' not found.")

        course = db.query(Course).filter(Course.tenant_id == tenant.id, Course.slug == args.course_slug).first()
        if course is None:
            raise SystemExit(
                f"Course '{args.course_slug}' not found for tenant '{args.tenant_slug}'. "
                "Import the course chapters before importing its labs."
            )

        labs_dir = Path(args.labs_dir)
        if not labs_dir.is_dir():
            raise SystemExit(f"Labs directory not found: {labs_dir}")

        templates = import_labs(
            db,
            tenant_id=tenant.id,
            course_id=course.id,
            labs_dir=labs_dir,
            chapters_dir=args.chapters_dir,
        )
        db.commit()
        for t in templates:
            print(f"lab '{t.slug}' -> activity {t.activity_id} v{t.version}")
        print(f"Done — {len(templates)} lab(s) imported for course '{course.slug}' and tenant '{args.tenant_slug}'.")
    finally:
        db.close()


def _email_digest(args: argparse.Namespace) -> None:
    """Cross-tenant weekly digest: email each cohort's instructor(s) a summary.

    Uses a BYPASSRLS admin session (like the lab jobs) so it can sweep every
    tenant. Email failures are non-fatal (send_email returns False), so one bad
    address never aborts the run.
    """
    from sqlalchemy import select

    from app.models.cohort import Cohort, Enrollment
    from app.models.person import Person
    from app.models.tenant import Tenant
    from app.services import lab_jobs
    from app.services.email import recipient_allows, render_cohort_html, send_email
    from app.services.reports import cohort_matrix
    from app.services.settings_store import effective

    sent = 0
    with lab_jobs.admin_session() as db:
        if not effective(db).email_digest_enabled:
            print("email-digest: disabled via platform settings; skipping")
            return
        tenants = db.scalars(select(Tenant)).all()
        for tenant in tenants:
            cohorts = db.scalars(select(Cohort).where(Cohort.tenant_id == tenant.id)).all()
            for cohort in cohorts:
                matrix = cohort_matrix(db, tenant_id=tenant.id, cohort_id=cohort.id)
                instructors = db.scalars(
                    select(Person)
                    .join(
                        Enrollment,
                        (Enrollment.person_id == Person.id) & (Enrollment.tenant_id == Person.tenant_id),
                    )
                    .where(Enrollment.tenant_id == tenant.id)
                    .where(Enrollment.cohort_id == cohort.id)
                    .where(Enrollment.role_in_cohort == "instructor")
                    .where(Enrollment.status == "active")
                ).all()
                for instructor in instructors:
                    if not recipient_allows(instructor, "email_digest"):
                        continue
                    if send_email(
                        instructor.email,
                        f"Weekly progress digest — {cohort.name}",
                        render_cohort_html(matrix),
                    ):
                        sent += 1
    print(f"email-digest: sent {sent} message(s)")


def _at_risk_sweep(args: argparse.Namespace) -> None:
    """Cross-tenant: nudge students who are behind/overdue (in-app notification).

    BYPASSRLS admin session like the digest; deduped so re-runs don't spam.
    """
    from sqlalchemy import select

    from app.models.cohort import Enrollment
    from app.models.tenant import Tenant
    from app.services import at_risk, lab_jobs

    sent = 0
    with lab_jobs.admin_session() as db:
        for tenant in db.scalars(select(Tenant)).all():
            student_ids = set(
                db.scalars(
                    select(Enrollment.person_id)
                    .where(Enrollment.tenant_id == tenant.id)
                    .where(Enrollment.role_in_cohort == "student")
                    .where(Enrollment.status == "active")
                ).all()
            )
            for pid in student_ids:
                sent += at_risk.notify_person_if_at_risk(db, tenant_id=tenant.id, person_id=pid)
        db.commit()
    print(f"at-risk-sweep: sent {sent} nudge(s)")


def _erp_training_sync(args: argparse.Namespace) -> None:
    """Cross-tenant: push completed courses to dotmac_erp HR (training reports).

    BYPASSRLS admin session; idempotent — only unsynced completions are pushed
    and ERP dedups on the certificate ref, so re-runs are safe. Inert unless
    ERP_WEBHOOK_URL is configured.
    """
    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import erp_sync, lab_jobs

    pushed = 0
    with lab_jobs.admin_session() as db:
        for tenant in db.scalars(select(Tenant)).all():
            pushed += erp_sync.sync_pending(db, tenant_id=tenant.id)
        db.commit()
    print(f"erp-training-sync: pushed {pushed} completion(s)")


def _set_entrance_bank(args: argparse.Namespace) -> None:
    """Designate a cohort's entrance-assessment question bank (opens it for intake)."""
    import uuid

    from app.models.cohort import Cohort
    from app.services import lab_jobs

    with lab_jobs.admin_session() as db:
        cohort = db.get(Cohort, uuid.UUID(args.cohort_id))
        if cohort is None:
            raise SystemExit(f"Cohort {args.cohort_id} not found.")
        cohort.entrance_bank_id = uuid.UUID(args.bank_id)
        if args.time_limit_minutes is not None:
            cohort.entrance_time_limit_minutes = args.time_limit_minutes or None
        db.commit()
        limit = cohort.entrance_time_limit_minutes
        print(
            f"cohort '{cohort.name}' entrance bank set to {args.bank_id}"
            + (f" (time limit {limit} min)" if limit else " (untimed)")
        )


def _set_default_entrance_bank(args: argparse.Namespace) -> None:
    """Set the academy-wide default entrance bank — every applicant sits it."""
    import uuid

    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import lab_jobs

    with lab_jobs.admin_session() as db:
        tenant = db.scalars(select(Tenant).where(Tenant.slug == args.tenant_slug)).first()
        if tenant is None:
            raise SystemExit(f"Tenant '{args.tenant_slug}' not found.")
        tenant.default_entrance_bank_id = uuid.UUID(args.bank_id)
        if args.time_limit_minutes is not None:
            tenant.default_entrance_time_limit_minutes = args.time_limit_minutes or None
        db.commit()
        limit = tenant.default_entrance_time_limit_minutes
        print(
            f"academy '{tenant.slug}' default entrance bank set to {args.bank_id}"
            + (f" (time limit {limit} min)" if limit else " (untimed)")
        )


def _invite_applicants(args: argparse.Namespace) -> None:
    """Email the entrance-assessment invitation to applicants who haven't sat it.

    This is the backfill for every applicant who applied before the invitation
    email existed — they were shown the link once on-screen (or never), so they
    have no way to reach the exam. Also the recovery path for a bounced email.

    Idempotent-ish: re-inviting mints a fresh token and a fresh deadline, which
    invalidates any older link for that applicant.
    """
    from sqlalchemy import select

    from app.models.admissions import Applicant
    from app.models.tenant import Tenant
    from app.services import entrance_exam, lab_jobs

    with lab_jobs.admin_session() as db:
        tenant = db.scalars(select(Tenant).where(Tenant.slug == args.tenant_slug)).first()
        if tenant is None:
            raise SystemExit(f"Tenant '{args.tenant_slug}' not found.")

        stmt = (
            select(Applicant)
            .where(Applicant.tenant_id == tenant.id)
            .where(Applicant.assessment_taken_at.is_(None))  # never sat it
        )
        if args.cohort_id:
            import uuid

            stmt = stmt.where(Applicant.cohort_id == uuid.UUID(args.cohort_id))
        if not args.resend:
            stmt = stmt.where(Applicant.invite_sent_at.is_(None))  # not already invited
        if args.email:
            stmt = stmt.where(Applicant.email == args.email)
        targets = list(db.scalars(stmt).all())

        print(f"{len(targets)} applicant(s) to invite (deadline {args.deadline_days} days, base {args.base_url})")
        if args.dry_run:
            for a in targets[:20]:
                print(f"  DRY-RUN would email {a.email}")
            if len(targets) > 20:
                print(f"  ... and {len(targets) - 20} more")
            print("\nDRY RUN — no tokens minted, no email sent.")
            return

        sent = failed = skipped = 0
        for a in targets:
            if not entrance_exam.has_entrance_exam(db, applicant=a):
                skipped += 1
                continue
            res = entrance_exam.invite(db, applicant=a, base_url=args.base_url, deadline_days=args.deadline_days)
            if res["emailed"]:
                sent += 1
            else:
                failed += 1
                print(f"  !! email FAILED for {a.email} (token minted; link still valid)")
        db.commit()
        print(f"\ninvited: {sent}   email failed: {failed}   no exam configured: {skipped}")
        if failed:
            print(
                "NOTE: failures mean SMTP rejected/was unconfigured. The tokens ARE valid — "
                "re-run once mail is working, or hand the link out another way."
            )


def _reset_entrance_exam(args: argparse.Namespace) -> None:
    """Reopen an applicant's entrance sitting and mint a fresh exam link.

    The recovery path when a candidate loses their one attempt to a dropped
    connection, a dead battery, or a clock that ran down while they were offline.
    Without this, a network blip permanently locks a good candidate out.
    """
    from sqlalchemy import select

    from app.models.admissions import Applicant
    from app.models.tenant import Tenant
    from app.services import entrance_exam, lab_jobs

    with lab_jobs.admin_session() as db:
        tenant = db.scalars(select(Tenant).where(Tenant.slug == args.tenant_slug)).first()
        if tenant is None:
            raise SystemExit(f"Tenant '{args.tenant_slug}' not found.")
        applicant = db.scalars(
            select(Applicant).where(Applicant.tenant_id == tenant.id).where(Applicant.email == args.email)
        ).first()
        if applicant is None:
            raise SystemExit(f"No applicant with email '{args.email}' in '{args.tenant_slug}'.")

        had = applicant.assessment_taken_at is not None
        raw = entrance_exam.reset_exam(db, applicant=applicant)
        db.commit()
        print(f"reset entrance sitting for {applicant.email} (reset #{applicant.assessment_reset_count})")
        if had:
            print("  note: a completed result was discarded — they now re-sit from scratch.")
        print(f"  new exam link: /apply/assessment?token={raw}")


def _recompute_entrance_levels(args: argparse.Namespace) -> None:
    """Re-derive level bands from a cohort's ACTUAL score distribution.

    The built-in floors (beginner/intermediate/advanced) are a *prediction* of item
    difficulty, not a measurement of it. If the real cohort clusters differently,
    absolute cut-offs mis-stream everyone — e.g. an empty "advanced" band.

    Percentile banding is self-calibrating: bottom 25% -> beginner, top 25% ->
    advanced. Computed over VALID sittings only (a near-chance or click-through
    result is an absence of data and must not drag the distribution).
    """
    import uuid

    from sqlalchemy import select

    from app.models.admissions import Applicant
    from app.models.tenant import Tenant
    from app.services import lab_jobs

    with lab_jobs.admin_session() as db:
        tenant = db.scalars(select(Tenant).where(Tenant.slug == args.tenant_slug)).first()
        if tenant is None:
            raise SystemExit(f"Tenant '{args.tenant_slug}' not found.")

        stmt = (
            select(Applicant)
            .where(Applicant.tenant_id == tenant.id)
            .where(Applicant.assessment_score.is_not(None))
            .where(Applicant.assessment_valid.is_not(False))
        )
        if args.cohort_id:
            stmt = stmt.where(Applicant.cohort_id == uuid.UUID(args.cohort_id))
        rows = list(db.scalars(stmt).all())

        if len(rows) < args.min_cohort:
            raise SystemExit(
                f"only {len(rows)} valid sitting(s) — below --min-cohort {args.min_cohort}. "
                "Percentiles on a handful of scores are noise; leaving bands as they are."
            )

        scores = sorted(a.assessment_score for a in rows)
        n = len(scores)
        p25 = scores[int(0.25 * (n - 1))]
        p75 = scores[int(0.75 * (n - 1))]
        print(f"valid sittings: {n}   p25={p25:.3f}  p75={p75:.3f}")

        if args.dry_run:
            print("DRY RUN — no levels written.")
            return

        changed = 0
        for a in rows:
            band = (
                "beginner" if a.assessment_score <= p25 else "advanced" if a.assessment_score >= p75 else "intermediate"
            )
            if a.assessment_level != band:
                a.assessment_level = band
                changed += 1
        db.commit()
        print(f"re-banded {changed} applicant(s) by percentile (bottom 25% / middle / top 25%).")


def _lab_worker(args: argparse.Namespace) -> None:
    from app.config import settings
    from app.services import lab_jobs
    from app.services.labengine.containerlab import ContainerlabEngine

    engine = ContainerlabEngine(settings.lab_workdir)
    print("lab-worker started; draining pending labs every 5s")
    while True:
        with lab_jobs.admin_session() as db:
            n = lab_jobs.drain_once(db, engine)
        if n:
            print(f"provisioned {n} lab(s)")
        time.sleep(5)


def _reap_labs(args: argparse.Namespace) -> None:
    from app.config import settings
    from app.services import lab_jobs
    from app.services.labengine.containerlab import ContainerlabEngine

    engine = ContainerlabEngine(settings.lab_workdir)
    with lab_jobs.admin_session() as db:
        reaped = lab_jobs.reap_idle(db, engine)
        provisioned = lab_jobs.drain_once(db, engine)
    print(f"reaped {reaped} idle lab(s); provisioned {provisioned} pending lab(s)")


def main() -> None:
    p = argparse.ArgumentParser(
        prog="app.cli",
        description="Platform management CLI for dotmac_academy_app.",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    b = sub.add_parser(
        "bootstrap-tenant",
        help="Create a tenant with standard roles and an initial admin user.",
        description=(
            "Create a tenant, the three standard roles (student/instructor/admin), "
            "an admin Person + UserCredential, and grant that person the admin role. "
            "NOTE: this is a platform-level operation — run with DATABASE_URL pointing "
            "at a role allowed to INSERT into tenants (superuser/migration URL), "
            "since app_user is RLS-restricted."
        ),
    )
    b.add_argument("--slug", required=True, help="URL-safe tenant identifier")
    b.add_argument("--name", required=True, help="Human-readable tenant name")
    b.add_argument("--admin-email", required=True, help="Email for the initial admin user")
    b.add_argument("--admin-password", required=True, help="Password for the initial admin user")
    b.set_defaults(func=_bootstrap)

    imp = sub.add_parser(
        "import-foundation",
        help="Import the Foundation manual markdown files as rendered HTML chapters.",
        description=(
            "Parse chapter-*.md files from the Foundation manual directory and upsert "
            "them into the database as Course/Chapter records for the given tenant. "
            "Idempotent — re-running skips unchanged chapters and only bumps Course.version "
            "when content changed."
        ),
    )
    imp.add_argument("--tenant-slug", required=True, help="Slug of the target tenant")
    imp.add_argument(
        "--chapters-dir",
        type=Path,
        default=_DEFAULT_CHAPTERS_DIR,
        help="Directory containing chapter-*.md files (default: Foundation manual)",
    )
    imp.add_argument(
        "--figures-dir",
        type=Path,
        default=_DEFAULT_FIGURES_DIR,
        help="Directory containing produced figure PNG files (default: figures/final)",
    )
    imp.add_argument(
        "--allow-missing-figures",
        action="store_true",
        help="Import chapters with placeholder blocks for missing figures.",
    )
    imp.set_defaults(func=_import_foundation)

    im = sub.add_parser(
        "import-manual",
        help="Import any manual's chapters as a course (generic over Foundation/Fiber/etc.).",
        description=(
            "Parse chapter-*.md from --chapters-dir and upsert them as a Course "
            "(identified by --slug) plus its Chapters for the tenant. Idempotent. "
            "Use this for any manual, e.g. fiber-engineering."
        ),
    )
    im.add_argument("--tenant-slug", required=True, help="Slug of the target tenant")
    im.add_argument("--slug", required=True, help="Course slug, e.g. fiber-engineering")
    im.add_argument("--title", required=True, help="Course title, e.g. 'Fiber Engineering'")
    im.add_argument("--discipline", default="networking", help="Discipline tag (default: networking)")
    im.add_argument("--source-ref", default=None, help="Provenance string (default: <slug>@0.1.0)")
    im.add_argument(
        "--chapters-dir",
        type=Path,
        required=True,
        help="Directory containing chapter-*.md files",
    )
    im.add_argument(
        "--figures-dir",
        type=Path,
        default=_DEFAULT_FIGURES_DIR,
        help="Directory containing produced figure PNG files",
    )
    im.add_argument(
        "--allow-missing-figures",
        action="store_true",
        help="Import chapters with placeholder blocks for missing figures.",
    )
    im.set_defaults(func=_import_manual)

    lb = sub.add_parser(
        "load-banks",
        help="Load YAML MCQ question banks into the database for a tenant.",
        description=(
            "For each *.yaml file in --banks-dir: parse the bank, lint it against the "
            "20/50/30 rubric-mix rule (skip and print violations on failure), load it into "
            "QuestionBank/Question tables, and create an Activity for each chapter bank."
        ),
    )
    lb.add_argument("--tenant-slug", required=True, help="Slug of the target tenant")
    lb.add_argument(
        "--banks-dir",
        type=Path,
        default=_DEFAULT_BANKS_DIR,
        help="Directory containing *.yaml bank files (default: Foundation assessments/banks)",
    )
    lb.set_defaults(func=_load_banks)

    il = sub.add_parser(
        "import-labs",
        help="Load labs-as-code (lab.yaml dirs) as Activity(type='lab')+LabTemplate.",
        description=(
            "For each <labs-dir>/*/lab.yaml: parse the lab definition (topology + "
            "instructions + checks + seed_spec + limits), render instructions to HTML "
            "(resolving $include directives against --chapters-dir), and upsert a paired "
            "Activity(type='lab') and LabTemplate keyed by (course, slug). Idempotent — "
            "unchanged labs are skipped and version only bumps when content changes."
        ),
    )
    il.add_argument("--tenant-slug", required=True, help="Slug of the target tenant")
    il.add_argument(
        "--course-slug",
        default="foundation",
        help="Course slug to attach labs to (default: foundation)",
    )
    il.add_argument(
        "--labs-dir",
        type=Path,
        default=_DEFAULT_LABS_DIR,
        help="Directory containing <slug>/lab.yaml lab dirs (default: Foundation labs)",
    )
    il.add_argument(
        "--chapters-dir",
        type=Path,
        default=_DEFAULT_CHAPTERS_DIR,
        help="Directory of chapter-*.md files for $include resolution (default: Foundation chapters)",
    )
    il.set_defaults(func=_import_labs)

    lw = sub.add_parser(
        "lab-worker",
        help="Run the cross-tenant provisioning worker loop (deploys pending labs).",
        description=(
            "Long-running background worker: every ~5s, opens an app_admin "
            "(BYPASSRLS) session and deploys the oldest queued/provisioning lab "
            "instances across all tenants, up to MAX_CONCURRENT_LABS. Intended to "
            "run under systemd (academy-lab-worker.service, Restart=always)."
        ),
    )
    lw.set_defaults(func=_lab_worker)

    rl = sub.add_parser(
        "reap-labs",
        help="One-shot: destroy idle lab instances, then drain pending ones.",
        description=(
            "Reap active lab instances idle longer than LAB_IDLE_MINUTES (marking "
            "them 'reaped'), then drain any pending instances. Intended to run on a "
            "timer (academy-reap-labs.timer → academy-reap-labs.service oneshot)."
        ),
    )
    rl.set_defaults(func=_reap_labs)

    ed = sub.add_parser(
        "email-digest",
        help="One-shot: email each cohort's instructor(s) a progress digest.",
        description=(
            "Cross-tenant: open an app_admin (BYPASSRLS) session, build the "
            "cohort progress matrix for every cohort in every tenant, and email "
            "each cohort's enrolled instructor(s) a summary. Email failures are "
            "non-fatal. Intended to run on a timer "
            "(academy-email-digest.timer -> academy-email-digest.service oneshot)."
        ),
    )
    ed.set_defaults(func=_email_digest)

    ar = sub.add_parser("at-risk-sweep", help="Nudge students who are behind/overdue")
    ar.set_defaults(func=_at_risk_sweep)

    ets = sub.add_parser("erp-training-sync", help="Push completed courses to dotmac_erp HR")
    ets.set_defaults(func=_erp_training_sync)

    seb = sub.add_parser("set-entrance-bank", help="Designate a cohort's entrance-assessment bank")
    seb.add_argument("--cohort-id", required=True)
    seb.add_argument("--bank-id", required=True)
    seb.add_argument(
        "--time-limit-minutes", type=int, default=None, help="Per-sitting time limit (0 or omit = untimed)"
    )
    seb.set_defaults(func=_set_entrance_bank)

    sdb = sub.add_parser("set-default-entrance-bank", help="Academy-wide default entrance bank (all applicants sit it)")
    sdb.add_argument("--tenant-slug", required=True)
    sdb.add_argument("--bank-id", required=True)
    sdb.add_argument(
        "--time-limit-minutes", type=int, default=None, help="Per-sitting time limit (0 or omit = untimed)"
    )
    sdb.set_defaults(func=_set_default_entrance_bank)

    inv = sub.add_parser(
        "invite-applicants",
        help="Email the entrance-assessment invitation to applicants who haven't sat it",
    )
    inv.add_argument("--tenant-slug", required=True)
    inv.add_argument(
        "--base-url", default="https://academy.dotmac.io", help="Public base URL used to build the exam link"
    )
    inv.add_argument("--deadline-days", type=int, default=7, help="Days the link stays valid (default 7)")
    inv.add_argument("--cohort-id", default=None, help="Limit to one intake")
    inv.add_argument("--email", default=None, help="Just this one applicant (use to test first)")
    inv.add_argument(
        "--resend",
        action="store_true",
        help="Also re-invite applicants already emailed (mints a NEW token, killing the old link)",
    )
    inv.add_argument("--dry-run", action="store_true")
    inv.set_defaults(func=_invite_applicants)

    rex = sub.add_parser(
        "reset-entrance-exam",
        help="Reopen an applicant's entrance sitting (dropped connection / lost attempt)",
    )
    rex.add_argument("--tenant-slug", required=True)
    rex.add_argument("--email", required=True, help="Applicant's email")
    rex.set_defaults(func=_reset_entrance_exam)

    rel = sub.add_parser(
        "recompute-entrance-levels",
        help="Re-derive level bands from the cohort's real score distribution (percentiles)",
    )
    rel.add_argument("--tenant-slug", required=True)
    rel.add_argument("--cohort-id", default=None, help="Limit to one intake (default: all)")
    rel.add_argument(
        "--min-cohort",
        type=int,
        default=20,
        help="Refuse below this many valid sittings — percentiles on few scores are noise",
    )
    rel.add_argument("--dry-run", action="store_true")
    rel.set_defaults(func=_recompute_entrance_levels)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
