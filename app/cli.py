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

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
