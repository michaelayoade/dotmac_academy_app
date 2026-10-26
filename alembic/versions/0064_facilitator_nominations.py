"""Add scoped facilitator nominations without overloading learner enrollment.

Revision ID: 0064_facilitator_nominations
Revises: 0063_lab_console_activity
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0064_facilitator_nominations"
down_revision = "0063_lab_console_activity"
branch_labels = None
depends_on = None

NOMINATIONS = "facilitator_nominations"
REQUIREMENTS = "facilitator_requirements"
ACTIVATION_CAPABILITY = "public.activate_eligible_facilitator_nominations"


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def _tenant_table(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
    op.execute(
        f"CREATE POLICY {table}_tenant_isolation ON {table} "
        f"USING (tenant_id = app_current_tenant_id()) "
        f"WITH CHECK (tenant_id = app_current_tenant_id());"
    )
    op.execute(f"REVOKE ALL PRIVILEGES ON {table} FROM PUBLIC;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO app_user, platform_api;")


def upgrade() -> None:
    op.create_table(
        NOMINATIONS,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("person_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("nominated_by_person_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.Column("cohort_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("offering_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activation_reason", sa.String(40), nullable=True),
        *_timestamps(),
        sa.UniqueConstraint("tenant_id", "id", name="uq_facilitator_nominations_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["people.tenant_id", "people.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_person",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "nominated_by_person_id"],
            ["people.tenant_id", "people.id"],
            name="fk_facilitator_nominations_nominator",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "cohort_id"],
            ["cohorts.tenant_id", "cohorts.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_cohort",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "offering_id"],
            ["course_offerings.tenant_id", "course_offerings.id"],
            ondelete="CASCADE",
            name="fk_facilitator_nominations_offering",
        ),
        sa.CheckConstraint("scope_type IN ('course', 'cohort')", name="ck_facilitator_nominations_scope"),
        sa.CheckConstraint("status IN ('pending', 'active', 'revoked')", name="ck_facilitator_nominations_status"),
        sa.CheckConstraint(
            "(scope_type = 'cohort' AND cohort_id IS NOT NULL AND offering_id IS NULL) OR "
            "(scope_type = 'course' AND cohort_id IS NULL AND offering_id IS NOT NULL)",
            name="ck_facilitator_nominations_target",
        ),
    )
    op.create_index("ix_facilitator_nominations_tenant_id", NOMINATIONS, ["tenant_id"])
    op.create_index("ix_facilitator_nominations_person_id", NOMINATIONS, ["person_id"])
    op.create_index("ix_facilitator_nominations_cohort_id", NOMINATIONS, ["cohort_id"])
    op.create_index("ix_facilitator_nominations_offering_id", NOMINATIONS, ["offering_id"])
    op.create_index("ix_facilitator_nominations_status", NOMINATIONS, ["status"])
    op.create_index(
        "uq_facilitator_nominations_cohort_scope",
        NOMINATIONS,
        ["tenant_id", "person_id", "cohort_id"],
        unique=True,
        postgresql_where=sa.text("scope_type = 'cohort'"),
    )
    op.create_index(
        "uq_facilitator_nominations_course_scope",
        NOMINATIONS,
        ["tenant_id", "person_id", "offering_id"],
        unique=True,
        postgresql_where=sa.text("scope_type = 'course'"),
    )

    op.create_table(
        REQUIREMENTS,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("nomination_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("course_id", postgresql.UUID(as_uuid=True), nullable=False),
        *_timestamps(),
        sa.UniqueConstraint("tenant_id", "id", name="uq_facilitator_requirements_tenant_id_id"),
        sa.UniqueConstraint(
            "tenant_id", "nomination_id", "course_id", name="uq_facilitator_requirements_nomination_course"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "nomination_id"],
            ["facilitator_nominations.tenant_id", "facilitator_nominations.id"],
            ondelete="CASCADE",
            name="fk_facilitator_requirements_nomination",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "course_id"],
            ["courses.tenant_id", "courses.id"],
            name="fk_facilitator_requirements_course",
        ),
    )
    op.create_index("ix_facilitator_requirements_tenant_id", REQUIREMENTS, ["tenant_id"])
    op.create_index("ix_facilitator_requirements_nomination_id", REQUIREMENTS, ["nomination_id"])
    op.create_index("ix_facilitator_requirements_course_id", REQUIREMENTS, ["course_id"])
    _tenant_table(NOMINATIONS)
    _tenant_table(REQUIREMENTS)

    # Activation is the sole privileged persistence path shared by the web tier,
    # repair sweep, and restricted lab worker. The definer function re-derives
    # eligibility from canonical facts and emits fixed consequences atomically;
    # callers cannot choose arbitrary nomination, notification, or audit writes.
    op.execute(
        """
        CREATE FUNCTION public.activate_eligible_facilitator_nominations(
            p_tenant_id uuid,
            p_nomination_id uuid DEFAULT NULL,
            p_person_id uuid DEFAULT NULL,
            p_course_id uuid DEFAULT NULL,
            p_limit integer DEFAULT NULL,
            p_actor_person_id uuid DEFAULT NULL
        )
        RETURNS TABLE (candidate_nomination_id uuid, activated_now boolean)
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $$
        DECLARE
            v_nomination record;
            v_candidate_ids uuid[];
        BEGIN
            IF p_tenant_id IS DISTINCT FROM public.app_current_tenant_id() THEN
                RAISE EXCEPTION 'facilitator activation tenant mismatch'
                    USING ERRCODE = '42501';
            END IF;
            IF p_actor_person_id IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1
                     FROM public.people AS actor
                    WHERE actor.tenant_id = p_tenant_id
                      AND actor.id = p_actor_person_id
               )
            THEN
                RAISE EXCEPTION 'facilitator activation actor tenant mismatch'
                    USING ERRCODE = '22023';
            END IF;
            IF p_actor_person_id IS NOT NULL AND p_nomination_id IS NULL THEN
                RAISE EXCEPTION 'automated facilitator activation cannot name an actor'
                    USING ERRCODE = '22023';
            END IF;
            IF p_nomination_id IS NOT NULL THEN
                IF p_person_id IS NOT NULL OR p_course_id IS NOT NULL OR p_limit IS NOT NULL THEN
                    RAISE EXCEPTION 'invalid facilitator activation selector'
                        USING ERRCODE = '22023';
                END IF;
            ELSIF p_person_id IS NOT NULL OR p_course_id IS NOT NULL THEN
                IF p_person_id IS NULL OR p_course_id IS NULL OR p_limit IS NOT NULL THEN
                    RAISE EXCEPTION 'invalid facilitator activation selector'
                        USING ERRCODE = '22023';
                END IF;
            ELSIF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000 THEN
                RAISE EXCEPTION 'invalid facilitator activation selector'
                    USING ERRCODE = '22023';
            END IF;

            IF p_limit IS NOT NULL THEN
                SELECT pg_catalog.array_agg(candidate.id ORDER BY candidate.created_at, candidate.id)
                  INTO v_candidate_ids
                  FROM (
                      SELECT n.id, n.created_at
                        FROM public.facilitator_nominations AS n
                       WHERE n.tenant_id = p_tenant_id
                         AND n.status = 'pending'
                         AND EXISTS (
                             SELECT 1
                               FROM public.people AS person
                              WHERE person.tenant_id = n.tenant_id
                                AND person.id = n.person_id
                                AND person.status = 'active'
                         )
                         AND EXISTS (
                             SELECT 1
                               FROM public.facilitator_requirements AS required
                              WHERE required.tenant_id = n.tenant_id
                                AND required.nomination_id = n.id
                         )
                         AND NOT EXISTS (
                             SELECT 1
                               FROM public.facilitator_requirements AS required
                              WHERE required.tenant_id = n.tenant_id
                                AND required.nomination_id = n.id
                                AND NOT EXISTS (
                                    SELECT 1
                                      FROM public.course_completions AS completed
                                     WHERE completed.tenant_id = required.tenant_id
                                       AND completed.person_id = n.person_id
                                       AND completed.course_id = required.course_id
                                       AND completed.status = 'completed'
                                )
                         )
                       ORDER BY n.created_at, n.id
                       LIMIT p_limit
                         FOR UPDATE OF n SKIP LOCKED
                  ) AS candidate;
            ELSE
                SELECT pg_catalog.array_agg(candidate.id ORDER BY candidate.created_at, candidate.id)
                  INTO v_candidate_ids
                  FROM (
                      SELECT n.id, n.created_at
                        FROM public.facilitator_nominations AS n
                       WHERE n.tenant_id = p_tenant_id
                         AND (
                             n.id = p_nomination_id
                             OR (
                                 p_person_id IS NOT NULL
                                 AND n.person_id = p_person_id
                                 AND n.status = 'pending'
                                 AND EXISTS (
                                     SELECT 1
                                       FROM public.facilitator_requirements AS affected
                                      WHERE affected.tenant_id = n.tenant_id
                                        AND affected.nomination_id = n.id
                                        AND affected.course_id = p_course_id
                                 )
                             )
                         )
                       ORDER BY n.created_at, n.id
                         FOR UPDATE OF n
                  ) AS candidate;
            END IF;

            FOR v_nomination IN
                SELECT n.*
                  FROM public.facilitator_nominations AS n
                 WHERE n.id = ANY(COALESCE(v_candidate_ids, ARRAY[]::uuid[]))
                 ORDER BY n.created_at, n.id
            LOOP
                candidate_nomination_id := v_nomination.id;
                activated_now := false;

                IF p_actor_person_id IS NOT NULL
                   AND v_nomination.nominated_by_person_id IS DISTINCT FROM p_actor_person_id
                THEN
                    RAISE EXCEPTION 'facilitator activation actor does not own nomination provenance'
                        USING ERRCODE = '22023';
                END IF;

                IF v_nomination.status = 'pending'
                   AND EXISTS (
                       SELECT 1
                         FROM public.people AS candidate
                        WHERE candidate.tenant_id = v_nomination.tenant_id
                          AND candidate.id = v_nomination.person_id
                          AND candidate.status = 'active'
                   )
                   AND EXISTS (
                       SELECT 1
                         FROM public.facilitator_requirements AS required
                        WHERE required.tenant_id = v_nomination.tenant_id
                          AND required.nomination_id = v_nomination.id
                   )
                   AND NOT EXISTS (
                       SELECT 1
                         FROM public.facilitator_requirements AS required
                        WHERE required.tenant_id = v_nomination.tenant_id
                          AND required.nomination_id = v_nomination.id
                          AND NOT EXISTS (
                              SELECT 1
                                FROM public.course_completions AS completed
                               WHERE completed.tenant_id = required.tenant_id
                                 AND completed.person_id = v_nomination.person_id
                                 AND completed.course_id = required.course_id
                                 AND completed.status = 'completed'
                          )
                   )
                THEN
                    UPDATE public.facilitator_nominations
                       SET status = 'active',
                           activated_at = pg_catalog.clock_timestamp(),
                           revoked_at = NULL,
                           activation_reason = 'requirements_completed',
                           updated_at = pg_catalog.clock_timestamp()
                     WHERE tenant_id = v_nomination.tenant_id
                       AND id = v_nomination.id
                       AND status = 'pending';

                    IF FOUND THEN
                        activated_now := true;
                        INSERT INTO public.notifications (
                            id, tenant_id, person_id, kind, title, body, link
                        ) VALUES (
                            pg_catalog.gen_random_uuid(),
                            v_nomination.tenant_id,
                            v_nomination.person_id,
                            'facilitator_activated',
                            'Your facilitator assignment is active',
                            'You completed the required course work and can now facilitate the assigned learning scope.',
                            '/learn'
                        );
                        INSERT INTO public.audit_events (
                            id, tenant_id, actor_person_id, action,
                            entity_type, entity_id, details
                        ) VALUES (
                            pg_catalog.gen_random_uuid(),
                            v_nomination.tenant_id,
                            p_actor_person_id,
                            'facilitator_nomination.activate',
                            'facilitator_nomination',
                            v_nomination.id::text,
                            pg_catalog.jsonb_build_object(
                                'scope', v_nomination.scope_type,
                                'person_id', v_nomination.person_id::text
                            )
                        );
                    END IF;
                END IF;
                RETURN NEXT;
            END LOOP;
        END;
        $$;
        """
    )
    op.execute(f"REVOKE ALL ON FUNCTION {ACTIVATION_CAPABILITY}(uuid, uuid, uuid, uuid, integer, uuid) FROM PUBLIC;")
    op.execute(
        f"GRANT EXECUTE ON FUNCTION {ACTIVATION_CAPABILITY}(uuid, uuid, uuid, uuid, integer, uuid) "
        "TO app_user, platform_api, academy_lab_worker;"
    )

    op.execute(
        """
        INSERT INTO facilitator_nominations (
            id, tenant_id, person_id, scope_type, cohort_id, status,
            activated_at, activation_reason, created_at, updated_at
        )
        SELECT gen_random_uuid(), e.tenant_id, e.person_id, 'cohort', e.cohort_id,
               'active', now(), 'legacy_grandfathered', now(), now()
          FROM enrollments e
          JOIN person_roles pr
            ON pr.tenant_id = e.tenant_id AND pr.person_id = e.person_id
          JOIN roles r
            ON r.tenant_id = pr.tenant_id AND r.id = pr.role_id
           AND r.slug = 'instructor'
         WHERE e.role_in_cohort = 'instructor' AND e.status = 'active'
        ON CONFLICT DO NOTHING
        """
    )


def downgrade() -> None:
    op.execute(f"DROP FUNCTION {ACTIVATION_CAPABILITY}(uuid, uuid, uuid, uuid, integer, uuid);")
    op.drop_table(REQUIREMENTS)
    op.drop_table(NOMINATIONS)
