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
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from dotmac_kernel.db import platform_session, tenant_session_by_slug
from dotmac_kernel.exceptions import NotFoundError
from dotmac_kernel.models import Tenant as KernelTenant
from sqlalchemy.orm import Session

_DEFAULT_CHAPTERS_DIR = Path("/home/dotmac/projects/dotmac-academy/manuals/00-foundation/chapters")
_DEFAULT_FIGURES_DIR = Path("/home/dotmac/projects/dotmac-academy/figures/final")
_DEFAULT_BANKS_DIR = Path("/home/dotmac/projects/dotmac-academy/manuals/00-foundation/assessments/banks")
_DEFAULT_LABS_DIR = Path("/home/dotmac/projects/dotmac-academy/manuals/00-foundation/labs")


@contextmanager
def _tenant_session(slug: str) -> Iterator[tuple[Session, KernelTenant]]:
    """`tenant_session_by_slug` with the CLI's error convention.

    Yields the KERNEL's `Tenant`, not `app.models.tenant.Tenant`: the kernel
    resolves the slug against its own model. Both map the `tenants` table, and
    the CLI only reads `.id`/`.slug`, so this works — but two mapped classes for
    one table is exactly the duplication that adopting the kernel's `Tenant`
    outright would remove. Annotated honestly rather than cast to ours.

    The kernel raises `NotFoundError`; a command-line tool should exit with a
    message, not a traceback. Wrapping it here keeps that translation in one
    place instead of six.
    """
    try:
        with tenant_session_by_slug(slug) as (db, tenant):
            yield db, tenant
    except NotFoundError as exc:
        raise SystemExit(str(exc)) from exc


def _bootstrap(args: argparse.Namespace) -> None:
    from app.services.bootstrap import bootstrap_tenant

    # The one command that cannot be tenant-scoped: it is CREATING the tenant,
    # so there is nothing to scope to yet. Creating a tenant is a platform
    # operation, which is what `platform_session` is for. Its small pool is
    # irrelevant here — this is a one-shot command, not a request path.
    with platform_session() as db:
        t = bootstrap_tenant(
            db,
            slug=args.slug,
            name=args.name,
            admin_email=args.admin_email,
            admin_password=args.admin_password,
        )
        print(f"tenant {t.slug} ({t.id}) created")


def _email_outbox(args: argparse.Namespace) -> None:
    """Deliver/reconcile committed email intents without exposing payloads."""
    from app.services.email_outbox import deliver_pending, requeue_failed
    from app.services.lab_jobs import admin_session

    with admin_session() as db:
        requeued = requeue_failed(db) if args.requeue_failed else 0
        counts = deliver_pending(db, limit=args.limit)
        db.commit()
    print(
        "email-outbox: "
        f"sent={counts['sent']} retried={counts['retried']} "
        f"failed={counts['failed']} requeued={requeued}"
    )


def _import_foundation(args: argparse.Namespace) -> None:
    from app.services.content_import import import_foundation, sync_figures

    with _tenant_session(args.tenant_slug) as (db, tenant):
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


def _import_manual(args: argparse.Namespace) -> None:
    from app.services.content_import import import_manual, sync_figures

    with _tenant_session(args.tenant_slug) as (db, tenant):
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


def _audit_banks(args: argparse.Namespace) -> None:
    """Check every bank already live in the database against lint_bank.

    load-banks enforces the rules on the way in, which leaves a gap: a bank
    loaded before a rule existed stays live and non-compliant, and nothing
    says so. This closes it — the same linter, pointed at the projection.
    """
    from app.models.assessment import QuestionBank
    from app.models.course import Course
    from app.services.bank_loader import doc_from_db, lint_bank

    with _tenant_session(args.tenant_slug) as (db, tenant):

        q = (
            db.query(QuestionBank, Course)
            .join(Course, Course.id == QuestionBank.course_id)
            .filter(QuestionBank.tenant_id == tenant.id)
        )
        if args.discipline:
            q = q.filter(Course.discipline == args.discipline)
        if args.course:
            q = q.filter(Course.slug == args.course)
        rows = q.order_by(Course.discipline, Course.slug, QuestionBank.chapter_number).all()

        banks = failing = 0
        per_discipline: dict[str, list[int]] = {}
        for bank, course in rows:
            banks += 1
            doc = doc_from_db(db, bank=bank, course_slug=course.slug)
            violations = lint_bank(doc)
            tally = per_discipline.setdefault(course.discipline, [0, 0])
            tally[0] += 1
            if violations:
                failing += 1
                tally[1] += 1
                label = f"ch{bank.chapter_number}" if bank.chapter_number else bank.kind
                print(f"{course.slug} [{label}] {len(doc.questions)}q")
                for v in violations:
                    print(f"    {v}")

        print()
        print(f"{'discipline':32} {'banks':>6} {'failing':>8}")
        for discipline, (total, bad) in sorted(per_discipline.items()):
            print(f"{discipline:32} {total:>6} {bad:>8}")
        print(f"{'TOTAL':32} {banks:>6} {failing:>8}")

        if failing and args.fail_on_violations:
            raise SystemExit(1)


def _load_banks(args: argparse.Namespace) -> None:
    from app.models.assessment import Activity
    from app.models.course import Course
    from app.services.bank_loader import lint_bank, load_bank, parse_bank

    with _tenant_session(args.tenant_slug) as (db, tenant):

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
            # The bank may set its own pass mark; the per-kind values are the
            # default for banks that do not. Activity.pass_threshold is a real
            # column, and hardcoding it here silently reverted anything set
            # elsewhere on every import.
            pass_threshold = doc.policy.get(
                "pass_threshold",
                {"chapter": 0.0, "mid": 0.60, "final": 0.70}.get(doc.kind, 0.0),
            )
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

            # Assessment policy declared in the bank. Only keys the author
            # actually set are applied, so a bank without a policy block leaves
            # the activity exactly as it was.
            policy_applied = []
            if "pool" in doc.policy:
                activity.question_count = doc.policy["pool"]
                policy_applied.append(f"pool={doc.policy['pool']}")
            if "max_attempts" in doc.policy:
                activity.max_attempts = doc.policy["max_attempts"]
                policy_applied.append(f"max_attempts={doc.policy['max_attempts']}")
            if "mode" in doc.policy:
                activity.assessment_mode = doc.policy["mode"]
                policy_applied.append(f"mode={doc.policy['mode']}")

            db.commit()
            suffix = f", policy: {' '.join(policy_applied)}" if policy_applied else ""
            print(f"Loaded {yaml_path.name}: bank {bank.id}, activity '{title}'{suffix}")
            loaded += 1

        print(f"Done — {loaded}/{len(yaml_files)} bank(s) loaded.")


def _import_labs(args: argparse.Namespace) -> None:
    from app.models.course import Course
    from app.services.lab_content import import_labs

    with _tenant_session(args.tenant_slug) as (db, tenant):

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


def _reminders_sweep(args: argparse.Namespace) -> None:
    """Run one reminder policy sweep per tenant (timer entrypoint).

    Uses an offline BYPASSRLS session because scheduled jobs have no request
    tenant context. Decisions are owned by services.reminders.sweep; email
    delivery stays with the outbox worker.
    """
    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import lab_jobs
    from app.services.reminders import sweep
    from app.services.success_queue import sweep as queue_sweep

    with lab_jobs.admin_session() as db:
        tenants = db.scalars(select(Tenant)).all()
        for tenant in tenants:
            counts = sweep(db, tenant_id=tenant.id)
            db.commit()
            print(f"reminders-sweep[{tenant.slug}]: {counts}")
            qcounts = queue_sweep(db, tenant_id=tenant.id)
            db.commit()
            print(f"success-queue[{tenant.slug}]: {qcounts}")


def _learner_digest(args: argparse.Namespace) -> None:
    """Queue each learner's weekly progress email.

    Distinct from ``email-digest``, which is the *instructor* cohort matrix.
    Gated by its own ``learner_digest_enabled`` Academy setting, off by default:
    this mails every active learner, so it must be switched on deliberately
    rather than start sending the moment it deploys.
    """
    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import lab_jobs, learner_digest
    from app.services.settings_store import effective

    with lab_jobs.admin_session() as db:
        cfg = effective(db)
        if not bool(cfg.get("learner_digest_enabled", False)) and not args.force:
            print("learner-digest: disabled via Academy settings; skipping (use --force to override)")
            return
        base_url = str(cfg.get("academy_base_url", args.base_url)).rstrip("/")
        branding = str(cfg.get("branding_name", "Dotmac Academy"))
        totals = {"queued": 0, "skipped_optout": 0, "skipped_no_courses": 0}
        for tenant in db.scalars(select(Tenant)).all():
            counts = learner_digest.send_weekly_digests(
                db, tenant_id=tenant.id, base_url=base_url, branding=branding
            )
            for key, n in counts.items():
                totals[key] += n
        if args.dry_run:
            db.rollback()
            print(f"DRY RUN — nothing queued. Would be: {totals}")
            return
        db.commit()
    print(
        f"learner-digest: queued={totals['queued']} "
        f"opted-out={totals['skipped_optout']} no-live-course={totals['skipped_no_courses']}"
    )
def _classify_audience(args: argparse.Namespace) -> None:
    """Mark enrolments staff/external from an ERP roster export (ADR 0004).

    The roster is CSV ``work_email,employee_ref`` — ERP's answer, not a guess.
    Anything absent stays unclassified unless --assume-roster-complete says the
    export covers every employee, which is a claim only an operator can make.
    """
    import csv

    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import audience, lab_jobs

    roster: dict[str, str] = {}
    with open(args.roster_file, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) >= 2 and row[0].strip() and not row[0].lstrip().startswith("#"):
                roster[row[0].strip()] = row[1].strip()
    if not roster:
        raise SystemExit(f"No usable rows in {args.roster_file} (expected: work_email,employee_ref)")

    with lab_jobs.admin_session() as db:
        tenant = db.scalars(select(Tenant).where(Tenant.slug == args.tenant_slug)).first()
        if tenant is None:
            raise SystemExit(f"Tenant '{args.tenant_slug}' not found.")
        counts = audience.classify_from_roster(
            db, tenant_id=tenant.id, roster=roster,
            mark_rest_external=args.assume_roster_complete,
        )
        split = audience.counts_by_audience(db, tenant_id=tenant.id)
        pending = audience.unclassified(db, tenant_id=tenant.id)
        if args.dry_run:
            db.rollback()
            print(f"DRY RUN — nothing written. Would be: {counts}")
        else:
            db.commit()
            print(f"classify-audience: {counts}")
        print(f"roster now: {split}")
        if pending:
            print(f"\n{len(pending)} learner(s) still unclassified — review rather than guess:")
            for email, name in pending[:20]:
                print(f"  {email}  {name}")
            if len(pending) > 20:
                print(f"  ... and {len(pending) - 20} more")


def _hr_report(args: argparse.Namespace) -> None:
    """Email HR the staff-only training roll-up."""
    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import hr_digest, lab_jobs
    from app.services.settings_store import effective

    recipients = [r for r in (args.to or "").split(",") if r.strip()]
    if not recipients:
        raise SystemExit("No recipients: pass --to hr@dotmac.ng")

    queued = 0
    with lab_jobs.admin_session() as db:
        branding = str(effective(db).get("branding_name", "Dotmac Academy"))
        for tenant in db.scalars(select(Tenant)).all():
            if args.dry_run:
                from datetime import UTC, datetime, timedelta

                snap = hr_digest.snapshot(
                    db, tenant_id=tenant.id, since=datetime.now(UTC) - timedelta(days=args.days)
                )
                print(f"DRY RUN [{tenant.slug}] {hr_digest.render(snap, branding=branding)[1]}")
                continue
            queued += hr_digest.send_hr_report(
                db, tenant_id=tenant.id, recipients=recipients, days=args.days, branding=branding
            )
        if args.dry_run:
            db.rollback()
            return
        db.commit()
    print(f"hr-report: queued {queued} message(s) to {', '.join(recipients)}")


def _email_digest(args: argparse.Namespace) -> None:
    """Queue each cohort instructor's weekly Academy summary.

    Uses an offline BYPASSRLS session because scheduled jobs do not have request
    tenant context. Delivery is owned by the outbox worker.
    """
    from datetime import UTC, datetime

    from sqlalchemy import select

    from app.models.cohort import Cohort, Enrollment
    from app.models.person import Person
    from app.models.tenant import Tenant
    from app.services import lab_jobs
    from app.services.email import recipient_allows, render_cohort_html
    from app.services.email_outbox import enqueue_email
    from app.services.reports import cohort_matrix
    from app.services.settings_store import effective

    queued = 0
    period = datetime.now(UTC).strftime("%G-W%V")
    with lab_jobs.admin_session() as db:
        if not effective(db).email_digest_enabled:
            print("email-digest: disabled via Academy settings; skipping")
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
                    if enqueue_email(
                        db,
                        tenant_id=tenant.id,
                        idempotency_key=(
                            f"weekly-digest:{period}:{cohort.id}:{instructor.id}"
                        ),
                        kind="weekly_digest",
                        recipient=instructor.email,
                        subject=f"Weekly progress digest — {cohort.name}",
                        html_body=render_cohort_html(matrix),
                        payload={"cohort_id": str(cohort.id)},
                    ):
                        queued += 1
        db.commit()
    print(f"email-digest: queued {queued} message(s)")


def _at_risk_sweep(args: argparse.Namespace) -> None:
    """Cross-tenant: nudge students who are behind/overdue (in-app notification).

    BYPASSRLS admin session like the digest; deduped so re-runs don't spam.
    """
    from sqlalchemy import select

    from app.models.cohort import Enrollment
    from app.models.tenant import Tenant
    from app.services import at_risk, lab_jobs

    print("at-risk-sweep: DEPRECATED — the Success Queue (reminders-sweep) is the intervention owner")
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
    """Cross-tenant: project changed staff course progress to dotmac_erp HR.

    BYPASSRLS admin session; idempotent — only unsynced completions are pushed
    and ERP dedups on the certificate ref, so re-runs are safe. Inert unless
    ERP_WEBHOOK_URL is configured.
    """
    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import erp_sync, lab_jobs

    totals = {erp_sync.SYNCED: 0, erp_sync.UNMATCHED: 0, erp_sync.FAILED: 0}
    with lab_jobs.admin_session() as db:
        for tenant in db.scalars(select(Tenant)).all():
            for outcome, n in erp_sync.sync_pending(db, tenant_id=tenant.id).items():
                totals[outcome] += n
        db.commit()
    print(
        f"erp-training-sync: synced={totals[erp_sync.SYNCED]} "
        f"unmatched={totals[erp_sync.UNMATCHED]} failed={totals[erp_sync.FAILED]}"
    )
    if totals[erp_sync.UNMATCHED]:
        # Unmatched will not clear by retrying — the learner's Academy email
        # matches no ERP employee. Say so where an operator will see it.
        print(
            f"NOTE: {totals[erp_sync.UNMATCHED]} completion(s) reached ERP but were not recorded "
            "(no matching employee). These stay unsynced until the identity link is fixed."
        )


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


def _admin_report(args: argparse.Namespace) -> None:
    """Cross-tenant: email each tenant's admins the activity report."""
    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import admin_reports, lab_jobs

    print("at-risk-sweep: DEPRECATED — the Success Queue (reminders-sweep) is the intervention owner")
    sent = 0
    with lab_jobs.admin_session() as db:
        for tenant in db.scalars(select(Tenant)).all():
            sent += admin_reports.send_activity_report(db, tenant_id=tenant.id, hours=args.hours)
        db.commit()
    print(f"admin-report: sent {sent} email(s)")


def _reinvite_stranded(args: argparse.Namespace) -> None:
    """Re-issue activation links to enrolled learners who never set a password.

    These learners cannot act on any other message we send them, so this is the
    one wave that has to precede a re-engagement campaign, not follow it.
    """
    import uuid

    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import lab_jobs, reengagement

    cohort_id = uuid.UUID(args.cohort_id) if args.cohort_id else None
    with lab_jobs.admin_session() as db:
        tenant = db.scalars(select(Tenant).where(Tenant.slug == args.tenant_slug)).first()
        if tenant is None:
            raise SystemExit(f"Tenant '{args.tenant_slug}' not found.")

        targets = reengagement.stranded_learners(db, tenant_id=tenant.id, cohort_id=cohort_id)
        print(f"{len(targets)} stranded learner(s) — enrolled, no password, never signed in (base {args.base_url})")
        if args.dry_run:
            for p in targets[:20]:
                print(f"  DRY-RUN would email {p.email}")
            if len(targets) > 20:
                print(f"  ... and {len(targets) - 20} more")
            print("\nDRY RUN — no tokens minted and no email queued.")
            return

        res = reengagement.reinvite_stranded(
            db, tenant_id=tenant.id, base_url=args.base_url, cohort_id=cohort_id
        )
        db.commit()
        print(f"\nqueued: {res['queued']}   queue failures: {res['failed']}")
        if res["failed"]:
            print("NOTE: queue failures did not expose or print activation tokens.")


def _set_auto_accept(args: argparse.Namespace) -> None:
    """Set (or clear) a cohort's auto-accept threshold for entrance sittings."""
    import uuid

    from app.models.cohort import Cohort
    from app.services import lab_jobs

    with lab_jobs.admin_session() as db:
        cohort = db.get(Cohort, uuid.UUID(args.cohort_id))
        if cohort is None:
            raise SystemExit(f"Cohort {args.cohort_id} not found.")
        if args.threshold is not None and not 0.0 <= args.threshold <= 1.0:
            raise SystemExit("--threshold must be a fraction between 0 and 1 (e.g. 0.6)")
        cohort.auto_accept_threshold = args.threshold
        db.commit()
        if args.threshold is None:
            print(f"cohort '{cohort.name}': auto-accept OFF (human decisions only)")
        else:
            print(f"cohort '{cohort.name}': valid sittings scoring >= {args.threshold:.0%} auto-accept")


def _set_default_entrance_bank(args: argparse.Namespace) -> None:
    """Set the academy-wide default entrance bank — every applicant sits it."""
    import uuid

    from sqlalchemy import select

    from app.models.tenant import Tenant
    from app.services import lab_jobs
    from app.services.entrance_exam import set_academy_defaults

    with lab_jobs.admin_session() as db:
        tenant = db.scalars(select(Tenant).where(Tenant.slug == args.tenant_slug)).first()
        if tenant is None:
            raise SystemExit(f"Tenant '{args.tenant_slug}' not found.")
        row = set_academy_defaults(
            db,
            tenant_id=tenant.id,
            bank_id=uuid.UUID(args.bank_id),
            time_limit_minutes=(args.time_limit_minutes or None),
        )
        db.commit()
        limit = row.default_time_limit_minutes
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
            print("\nDRY RUN — no tokens minted and no email queued.")
            return

        queued = failed = skipped = 0
        for a in targets:
            if not entrance_exam.has_entrance_exam(db, applicant=a):
                skipped += 1
                continue
            res = entrance_exam.invite(db, applicant=a, base_url=args.base_url, deadline_days=args.deadline_days)
            if res["emailed"]:
                queued += 1
            else:
                failed += 1
                print(f"  !! invitation could not be queued for {a.email}")
        db.commit()
        print(f"\nqueued: {queued}   queue failures: {failed}   no exam configured: {skipped}")
        if failed:
            print("NOTE: queue failures did not expose or print invitation tokens.")


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
        queued = entrance_exam.reset_and_invite(
            db,
            applicant=applicant,
            base_url=args.base_url,
        )
        db.commit()
        print(f"reset entrance sitting for {applicant.email} (reset #{applicant.assessment_reset_count})")
        if had:
            print("  note: a completed result was discarded — they now re-sit from scratch.")
        print(f"  replacement invitation queued={queued}")


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
        # The query already excludes NULL scores; pair each applicant with its score
        # so the band comparisons below are over plain floats.
        rows = [(a, a.assessment_score) for a in db.scalars(stmt).all() if a.assessment_score is not None]

        if len(rows) < args.min_cohort:
            raise SystemExit(
                f"only {len(rows)} valid sitting(s) — below --min-cohort {args.min_cohort}. "
                "Percentiles on a handful of scores are noise; leaving bands as they are."
            )

        scores = sorted(score for _, score in rows)
        n = len(scores)
        p25 = scores[int(0.25 * (n - 1))]
        p75 = scores[int(0.75 * (n - 1))]
        print(f"valid sittings: {n}   p25={p25:.3f}  p75={p75:.3f}")

        if args.dry_run:
            print("DRY RUN — no levels written.")
            return

        changed = 0
        for a, score in rows:
            band = "beginner" if score <= p25 else "advanced" if score >= p75 else "intermediate"
            if a.assessment_level != band:
                a.assessment_level = band
                a.assessment_result_version = (a.assessment_result_version or 0) + 1
                a.assessment_erp_synced_at = None
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
        # After reaping, so a console this run just tore down is already gone and
        # only genuine leftovers remain.
        orphans = lab_jobs.sweep_orphan_consoles(db)
        provisioned = lab_jobs.drain_once(db, engine)
    print(
        f"reaped {reaped} idle lab(s); killed {orphans} orphan console(s); "
        f"provisioned {provisioned} pending lab(s)"
    )


def _load_curriculum(args: argparse.Namespace) -> None:
    """Apply a CURRICULUM.yaml's prerequisite graph. The canonical writer.

    ``CoursePrerequisite`` is read by ``entitlements`` in two places and was
    written in none, so prerequisites were enforceable and uncreatable. The file
    is authoritative and the table is a projection of it: rows for the
    discipline that the file no longer declares are removed, so re-running after
    deleting an edge actually deletes it.
    """
    import yaml

    from app.models.course import Course
    from app.models.prerequisite import CoursePrerequisite

    doc = yaml.safe_load(args.file.read_text())["curriculum"]
    declared = doc.get("prerequisites") or []

    with _tenant_session(args.tenant_slug) as (db, tenant):

        courses = {
            c.slug: c
            for c in db.query(Course).filter(Course.tenant_id == tenant.id).all()
        }

        wanted: set[tuple] = set()
        missing: list[str] = []
        for entry in declared:
            slug = entry["course"]
            for req in entry.get("requires") or []:
                for name in (slug, req):
                    if name not in courses:
                        missing.append(name)
                if slug in courses and req in courses:
                    if slug == req:
                        raise SystemExit(f"{slug} cannot require itself")
                    wanted.add((courses[slug].id, courses[req].id))

        if missing:
            # Fail rather than silently skip: a typo'd slug would otherwise look
            # exactly like a successful run that enforced nothing.
            raise SystemExit(
                "These courses are declared in the file but not imported: "
                + ", ".join(sorted(set(missing)))
            )

        # A cycle would lock every course in it permanently unreachable.
        edges: dict = {}
        for course_id, requires_id in wanted:
            edges.setdefault(course_id, set()).add(requires_id)
        state: dict = {}

        def _walk(node) -> None:
            state[node] = 1
            for nxt in edges.get(node, ()):
                if state.get(nxt) == 1:
                    raise SystemExit("prerequisite cycle detected; refusing to write")
                if not state.get(nxt):
                    _walk(nxt)
            state[node] = 2

        for node in list(edges):
            if not state.get(node):
                _walk(node)

        existing_rows = (
            db.query(CoursePrerequisite)
            .filter(CoursePrerequisite.tenant_id == tenant.id)
            .all()
        )
        scoped = {c.id for c in courses.values() if c.discipline == doc.get("discipline")}
        existing = {(r.course_id, r.requires_course_id): r for r in existing_rows}

        added = removed = 0
        for pair in wanted - set(existing):
            db.add(
                CoursePrerequisite(
                    tenant_id=tenant.id, course_id=pair[0], requires_course_id=pair[1]
                )
            )
            added += 1
        for pair, row in existing.items():
            if pair not in wanted and pair[0] in scoped:
                db.delete(row)
                removed += 1

        if args.dry_run:
            db.rollback()
            print(f"[dry-run] would add {added}, remove {removed}")
            return
        db.commit()
        print(f"prerequisites: {added} added, {removed} removed, {len(wanted)} declared")


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

    lc = sub.add_parser(
        "load-curriculum",
        help="Apply a CURRICULUM.yaml prerequisite graph for a tenant.",
        description=(
            "The canonical writer for CoursePrerequisite, which entitlements enforces "
            "but nothing previously created. The file is authoritative: declared edges "
            "are added, and edges no longer declared are removed, so the table stays a "
            "projection of the file. Refuses to write on an unknown slug or a cycle."
        ),
    )
    lc.add_argument("--tenant-slug", required=True, help="Slug of the target tenant")
    lc.add_argument("--file", type=Path, required=True, help="Path to CURRICULUM.yaml")
    lc.add_argument("--dry-run", action="store_true", help="Report changes without writing")
    lc.set_defaults(func=_load_curriculum)

    ab = sub.add_parser(
        "audit-banks",
        help="Lint every question bank already live in the database.",
        description=(
            "load-banks enforces the bank rules on the way in. That leaves banks "
            "loaded before a rule existed live and non-compliant with nothing to "
            "say so. This runs the same lint_bank over the database, so the state "
            "of the estate is a question anyone can answer rather than a query "
            "someone has to write."
        ),
    )
    ab.add_argument("--tenant-slug", required=True, help="Slug of the target tenant")
    ab.add_argument("--discipline", default=None, help="Restrict to one discipline")
    ab.add_argument("--course", default=None, help="Restrict to one course slug")
    ab.add_argument(
        "--fail-on-violations",
        action="store_true",
        help="Exit 1 if any bank fails, for use as a scheduled check.",
    )
    ab.set_defaults(func=_audit_banks)

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
        help="One-shot: destroy idle lab instances, sweep orphan consoles, drain pending.",
        description=(
            "Reap active lab instances idle longer than LAB_IDLE_MINUTES (marking "
            "them 'reaped'), kill any ttyd console whose instance is no longer live, "
            "then drain any pending instances. Intended to run on a timer "
            "(academy-reap-labs.timer → academy-reap-labs.service oneshot). The "
            "console sweep is why this timer must be ENABLED on every host that "
            "spawns consoles, not only the one running the lab worker."
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

    ld = sub.add_parser(
        "learner-digest",
        help="One-shot: email each learner their weekly progress summary.",
        description=(
            "Cross-tenant: open an app_admin (BYPASSRLS) session and queue one "
            "weekly progress email per active student learner — what they did, "
            "where they are, what is next. Distinct from email-digest, which is "
            "the instructor cohort matrix. Idempotent per ISO week. Gated by the "
            "learner_digest_enabled Academy setting, which is OFF by default."
        ),
    )
    ld.add_argument(
        "--base-url",
        default="https://academy.dotmac.io",
        help="Fallback public base URL when academy_base_url is unset",
    )
    ld.add_argument("--dry-run", action="store_true", help="Count recipients without queueing")
    ld.add_argument(
        "--force",
        action="store_true",
        help="Run even when learner_digest_enabled is off (use with --dry-run to preview)",
    )
    ld.set_defaults(func=_learner_digest)
    ca = sub.add_parser(
        "classify-audience",
        help="Mark enrolments staff/external from an ERP roster export (ADR 0004)",
        description=(
            "Reads CSV 'work_email,employee_ref' — ERP's answer, not a guess. "
            "Matches are marked staff and carry their employee reference; "
            "anything absent stays unclassified and is listed for review, "
            "because audience is never inferred from an email domain."
        ),
    )
    ca.add_argument("--tenant-slug", required=True)
    ca.add_argument("--roster-file", required=True, help="CSV: work_email,employee_ref")
    ca.add_argument(
        "--assume-roster-complete",
        action="store_true",
        help="Mark every non-match as external (only if the export covers ALL employees)",
    )
    ca.add_argument("--dry-run", action="store_true")
    ca.set_defaults(func=_classify_audience)

    hr = sub.add_parser(
        "hr-report",
        help="Email HR the staff-only training roll-up",
        description=(
            "Counts only enrolments explicitly marked staff. Unclassified "
            "learners are excluded and the count of them is stated in the mail, "
            "so a partial roster cannot be mistaken for a complete picture."
        ),
    )
    hr.add_argument("--to", required=True, help="Comma-separated recipients, e.g. hr@dotmac.ng")
    hr.add_argument("--days", type=int, default=7, help="Reporting window (default 7)")
    hr.add_argument("--dry-run", action="store_true", help="Print the report without queueing")
    hr.set_defaults(func=_hr_report)

    eo = sub.add_parser(
        "email-outbox",
        help="Deliver committed email intents with durable retries.",
    )
    eo.add_argument("--limit", type=int, default=100, help="Maximum due messages to process")
    eo.add_argument(
        "--requeue-failed",
        action="store_true",
        help="Requeue terminal failures before attempting delivery",
    )
    eo.set_defaults(func=_email_outbox)

    rsw = sub.add_parser("reminders-sweep", help="Detect due student reminders and queue delivery")
    rsw.set_defaults(func=_reminders_sweep)

    ar = sub.add_parser(
        "at-risk-sweep",
        help="DEPRECATED: superseded by the Success Queue (runs inside "
             "reminders-sweep); now only sends legacy in-app nudges",
    )
    ar.set_defaults(func=_at_risk_sweep)

    ets = sub.add_parser("erp-training-sync", help="Project staff training progress to dotmac_erp HR")
    ets.set_defaults(func=_erp_training_sync)

    seb = sub.add_parser("set-entrance-bank", help="Designate a cohort's entrance-assessment bank")
    seb.add_argument("--cohort-id", required=True)
    seb.add_argument("--bank-id", required=True)
    seb.add_argument(
        "--time-limit-minutes", type=int, default=None, help="Per-sitting time limit (0 or omit = untimed)"
    )
    seb.set_defaults(func=_set_entrance_bank)

    arp = sub.add_parser("admin-report", help="Email tenant admins the admissions/learning activity report")
    arp.add_argument("--hours", type=int, default=24, help="Reporting window in hours (default 24)")
    arp.set_defaults(func=_admin_report)

    saa = sub.add_parser("set-auto-accept", help="Auto-accept valid entrance sittings at/above a score threshold")
    saa.add_argument("--cohort-id", required=True)
    saa.add_argument(
        "--threshold", type=float, default=None, help="Fraction 0..1 (e.g. 0.6); omit to turn auto-accept off"
    )
    saa.set_defaults(func=_set_auto_accept)

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

    ris = sub.add_parser(
        "reinvite-stranded",
        help="Re-issue activation links to enrolled learners who never set a password",
    )
    ris.add_argument("--tenant-slug", required=True)
    ris.add_argument(
        "--base-url", default="https://academy.dotmac.io", help="Public base URL used to build the activation link"
    )
    ris.add_argument("--cohort-id", default=None, help="Limit to one cohort")
    ris.add_argument("--dry-run", action="store_true")
    ris.set_defaults(func=_reinvite_stranded)

    rex = sub.add_parser(
        "reset-entrance-exam",
        help="Reopen an applicant's entrance sitting (dropped connection / lost attempt)",
    )
    rex.add_argument("--tenant-slug", required=True)
    rex.add_argument("--email", required=True, help="Applicant's email")
    rex.add_argument("--base-url", default="https://academy.dotmac.io")
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
