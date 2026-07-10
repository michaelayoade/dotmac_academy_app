"""Backfill semantics for the 0008_course_offerings migration.

The migration links every cohort to each course sharing its discipline, so the
cutover from discipline-string matching preserves existing access. This test
mirrors the migration's backfill statement and asserts it (a) creates the links
and (b) is idempotent via the ON CONFLICT guard.
"""

from __future__ import annotations

from sqlalchemy import select, text

from app.models.cohort import Cohort
from app.models.course import Course
from app.models.offering import CourseOffering

# Mirror of alembic/versions/0008_course_offerings.py upgrade() backfill.
_BACKFILL = text("""
    INSERT INTO course_offerings
        (id, tenant_id, cohort_id, course_id, status, created_at, updated_at)
    SELECT gen_random_uuid(), c.tenant_id, c.id, co.id, 'active', now(), now()
    FROM cohorts c
    JOIN courses co
      ON co.tenant_id = c.tenant_id AND co.discipline = c.discipline
    ON CONFLICT (tenant_id, cohort_id, course_id) DO NOTHING;
""")


def test_backfill_links_same_discipline_and_is_idempotent(admin_session, tenant_a):
    tid = tenant_a.id
    # Cohort + a matching-discipline course (linked) and a non-matching one (not linked).
    coh = Cohort(tenant_id=tid, name="Net Cohort", discipline="networking", status="active")
    match = Course(tenant_id=tid, slug="net", title="Net", discipline="networking",
                   source_ref="x", version=1)
    other = Course(tenant_id=tid, slug="fiber", title="Fiber", discipline="fiber",
                   source_ref="x", version=1)
    admin_session.add_all([coh, match, other])
    admin_session.flush()

    admin_session.execute(_BACKFILL)

    links = admin_session.scalars(
        select(CourseOffering.course_id).where(CourseOffering.tenant_id == tid)
        .where(CourseOffering.cohort_id == coh.id)
    ).all()
    assert match.id in links
    assert other.id not in links

    # Idempotent: a second run adds nothing (ON CONFLICT DO NOTHING).
    admin_session.execute(_BACKFILL)
    links2 = admin_session.scalars(
        select(CourseOffering.course_id).where(CourseOffering.tenant_id == tid)
        .where(CourseOffering.cohort_id == coh.id)
    ).all()
    assert len(links2) == len(links)
    admin_session.rollback()
