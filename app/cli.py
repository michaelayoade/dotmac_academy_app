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

_DEFAULT_CHAPTERS_DIR = Path(
    "/home/dotmac/projects/dotmac-academy/manuals/00-foundation/chapters"
)
_DEFAULT_FIGURES_DIR = Path(
    "/home/dotmac/projects/dotmac-academy/figures/final"
)
_DEFAULT_BANKS_DIR = Path(
    "/home/dotmac/projects/dotmac-academy/manuals/00-foundation/assessments/banks"
)
_DEFAULT_LABS_DIR = Path(
    "/home/dotmac/projects/dotmac-academy/manuals/00-foundation/labs"
)


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
            course = (
                db.query(Course)
                .filter(Course.tenant_id == tenant.id, Course.slug == doc.course)
                .first()
            )
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

        course = (
            db.query(Course)
            .filter(Course.tenant_id == tenant.id, Course.slug == "foundation")
            .first()
        )
        if course is None:
            raise SystemExit(
                f"Foundation course not found for tenant '{args.tenant_slug}'. "
                "Run import-foundation first."
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
        print(f"Done — {len(templates)} lab(s) imported for tenant '{args.tenant_slug}'.")
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
    from app.services.email import render_cohort_html, send_email
    from app.services.reports import cohort_matrix
    from app.services.settings_store import effective

    sent = 0
    with lab_jobs.admin_session() as db:
        if not effective(db).email_digest_enabled:
            print("email-digest: disabled via platform settings; skipping")
            return
        tenants = db.scalars(select(Tenant)).all()
        for tenant in tenants:
            cohorts = db.scalars(
                select(Cohort).where(Cohort.tenant_id == tenant.id)
            ).all()
            for cohort in cohorts:
                matrix = cohort_matrix(db, tenant_id=tenant.id, cohort_id=cohort.id)
                instructors = db.scalars(
                    select(Person)
                    .join(
                        Enrollment,
                        (Enrollment.person_id == Person.id)
                        & (Enrollment.tenant_id == Person.tenant_id),
                    )
                    .where(Enrollment.tenant_id == tenant.id)
                    .where(Enrollment.cohort_id == cohort.id)
                    .where(Enrollment.role_in_cohort == "instructor")
                    .where(Enrollment.status == "active")
                ).all()
                for instructor in instructors:
                    if send_email(
                        instructor.email,
                        f"Weekly progress digest — {cohort.name}",
                        render_cohort_html(matrix),
                    ):
                        sent += 1
    print(f"email-digest: sent {sent} message(s)")


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
        "--chapters-dir", type=Path, required=True,
        help="Directory containing chapter-*.md files",
    )
    im.add_argument(
        "--figures-dir", type=Path, default=_DEFAULT_FIGURES_DIR,
        help="Directory containing produced figure PNG files",
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

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
