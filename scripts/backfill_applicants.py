"""Backfill ERP job applicants into academy admissions (one-time).

The "Fiber Academy" job opening (code ``FA1``) in the ERP ATS was doubling as
the academy's admissions system. This imports those applicants as academy
``Applicant`` rows (``source=erp_backfill``, ``external_ref`` = the ERP applicant
id) so they enter the academy's own pipeline. Idempotent on email — safe to
re-run.

They come in as ``applied`` regardless of ERP disposition: an applicant rejected
as a *job candidate* may still be a valid *training student*, so they re-enter
the academy's own screening.

Export the data from the ERP database first:

    SELECT json_agg(json_build_object(
        'external_ref', ja.job_applicant_id,
        'email',        ja.email,
        'first_name',   ja.first_name,
        'last_name',    ja.last_name,
        'phone',        ja.phone,
        'applied_on',   ja.applied_on))
    FROM recruit.job_applicant ja
    JOIN recruit.job_opening jo ON jo.job_opening_id = ja.job_opening_id
    WHERE jo.job_code = 'FA1';

Then run (with the app DATABASE_URL pointing at the academy DB):

    python -m scripts.backfill_applicants --tenant-slug dotmac --input fa1.json
    python -m scripts.backfill_applicants --tenant-slug dotmac --input fa1.json --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.tenant import Tenant  # noqa: F401  (register Tenant so applicants.tenant_id FK resolves)
from app.services import admissions as admissions_service


def _to_date(value: Any) -> date | None:
    if not value:
        return None
    return date.fromisoformat(str(value)[:10])


def backfill(db: Session, *, tenant_id: UUID, rows: list[dict[str, Any]]) -> dict[str, int]:
    """Upsert ERP applicant rows into academy admissions. Returns a summary.

    Skips rows without an email. Idempotent on (tenant, email) via the service.
    Does not commit — the caller owns the transaction.
    """
    imported = 0
    skipped = 0
    for row in rows:
        email = (row.get("email") or "").strip()
        if not email:
            skipped += 1
            continue
        ext = row.get("external_ref")
        admissions_service.submit_application(
            db,
            tenant_id=tenant_id,
            email=email,
            first_name=(row.get("first_name") or "?").strip() or "?",
            last_name=(row.get("last_name") or "?").strip() or "?",
            phone=row.get("phone"),
            program="Fiber Academy",
            source="erp_backfill",
            external_ref=str(ext) if ext else None,
            applied_on=_to_date(row.get("applied_on")),
        )
        imported += 1
    return {"imported": imported, "skipped": skipped, "total": len(rows)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill ERP applicants into academy admissions.")
    parser.add_argument("--tenant-slug", required=True)
    parser.add_argument("--input", required=True, help="JSON array of ERP applicant rows")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        rows = json.load(fh)
    if not isinstance(rows, list):
        sys.exit("input must be a JSON array")

    from app.db import SessionLocal

    db = SessionLocal()
    try:
        tenant_id = db.execute(
            text("SELECT id FROM tenants WHERE slug = :s"), {"s": args.tenant_slug}
        ).scalar()
        if tenant_id is None:
            sys.exit(f"tenant '{args.tenant_slug}' not found")
        # Prime RLS for this transaction (matches get_db). We commit once at the
        # end so the SET LOCAL context survives the whole backfill.
        db.execute(
            text("SELECT set_config('app.current_tenant', :t, true)"),
            {"t": str(tenant_id)},
        )
        summary = backfill(db, tenant_id=tenant_id, rows=rows)
        if args.dry_run:
            db.rollback()
            print(f"DRY RUN — would import {summary}")
        else:
            db.commit()
            print(f"backfilled {summary}")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
