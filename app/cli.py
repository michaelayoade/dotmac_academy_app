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
    from app.services.content_import import import_foundation

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
        print(f"foundation course '{course.slug}' ({course.id}) v{course.version} imported")
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

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
