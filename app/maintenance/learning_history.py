"""Private fixed-a5 Learning source capture; source-only adoption prerequisite.

No canonical writes, DDL, root commit or rollback. The external coordinator must
fence/drain writers and pre-lock its COMPLETE source/identity/retained lockset in
one deterministic order before composing relocation/import/migrations. This
reader locks its fixed subset; locks alone are not an operational fence.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

import dotmac_learning as learning
import sqlalchemy as sa
from dotmac_learning.transfer_contracts import validate_tenant_extent
from sqlalchemy.engine import Connection

from app.maintenance.account_token_identity import _issued as _identity_issued
from app.maintenance.identity_history import _connection_preflight


class LearningHistoryRefused(RuntimeError):
    """Fixed material-free refusal; caller must roll back the adoption root."""


def _require(condition):
    if not condition:
        raise LearningHistoryRefused("Academy Learning history refused; root rollback required")


@dataclass(frozen=True, slots=True, repr=False)
class _TableSpec:
    name: str
    row_type: type
    columns: tuple = field(repr=False)
    foreign_keys: tuple = field(repr=False)
    unique_keys: tuple = field(repr=False)
    indexes: tuple = field(repr=False)


# Storage declarations derived from all31 actual a5 model Git blobs, NOT the
# unmerged ERP worktree. 261 source fields = 260 V5 fields + one product ACK.
_TABLES = (
    _TableSpec(
        "announcements",
        learning.AnnouncementRowV5,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("cohort_id", "uuid", True),
            ("author_person_id", "uuid", False),
            ("title", "character varying(200)", False),
            ("body_md", "text", False),
            ("body_html", "text", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "cohort_id"), "cohorts", ("tenant_id", "id"), "c"),
            (("tenant_id", "author_person_id"), "people", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (("uq_announcements_tenant_id_id", ("tenant_id", "id")),),
        (
            ("announcements_pkey", ("id",), True),
            ("uq_announcements_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_announcements_tenant_id", ("tenant_id",), False),
            ("ix_announcements_cohort_id", ("cohort_id",), False),
        ),
    ),
    _TableSpec(
        "question_banks",
        learning.QuestionBankRowV2,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("course_id", "uuid", False),
            ("chapter_number", "integer", True),
            ("kind", "character varying(10)", False),
            ("version", "integer", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id",), "tenants", ("id",), "c"),),
        (("uq_question_banks_tenant_id_id", ("tenant_id", "id")),),
        (
            ("question_banks_pkey", ("id",), True),
            ("uq_question_banks_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_question_banks_tenant_id", ("tenant_id",), False),
            ("ix_question_banks_course_id", ("course_id",), False),
        ),
    ),
    _TableSpec(
        "questions",
        learning.QuestionRowV2,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("bank_id", "uuid", False),
            ("ext_id", "character varying(60)", False),
            ("stem", "text", False),
            ("type", "character varying(12)", False),
            ("options", "jsonb", False),
            ("correct", "jsonb", False),
            ("rubric_category", "character varying(12)", False),
            ("category", "character varying(40)", True),
            ("explanation", "text", False),
            ("weight", "integer", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "bank_id"), "question_banks", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (("uq_questions_bank_ext", ("tenant_id", "bank_id", "ext_id")),),
        (
            ("questions_pkey", ("id",), True),
            ("uq_questions_bank_ext", ("tenant_id", "bank_id", "ext_id"), True),
            ("ix_questions_tenant_id", ("tenant_id",), False),
            ("ix_questions_bank_id", ("bank_id",), False),
        ),
    ),
    _TableSpec(
        "activities",
        learning.ActivityRowV1,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("course_id", "uuid", False),
            ("chapter_number", "integer", True),
            ("type", "character varying(16)", False),
            ("bank_id", "uuid", True),
            ("title", "character varying(200)", False),
            ("pass_threshold", "double precision", False),
            ("max_attempts", "integer", True),
            ("assessment_mode", "character varying(10)", False),
            ("grading", "character varying(10)", False),
            ("weight", "double precision", False),
            ("question_count", "integer", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id",), "tenants", ("id",), "c"),),
        (("uq_activities_tenant_id_id", ("tenant_id", "id")),),
        (
            ("activities_pkey", ("id",), True),
            ("uq_activities_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_activities_tenant_id", ("tenant_id",), False),
            ("ix_activities_course_id", ("course_id",), False),
            ("ix_activities_bank_id", ("bank_id",), False),
        ),
    ),
    _TableSpec(
        "submissions",
        learning.SubmissionRowV1,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("activity_id", "uuid", False),
            ("person_id", "uuid", False),
            ("answers", "jsonb", False),
            ("attempt_no", "integer", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "activity_id"), "activities", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (
            ("uq_submissions_tenant_id_id", ("tenant_id", "id")),
            ("uq_submissions_person_activity_attempt", ("tenant_id", "activity_id", "person_id", "attempt_no")),
        ),
        (
            ("submissions_pkey", ("id",), True),
            ("uq_submissions_tenant_id_id", ("tenant_id", "id"), True),
            ("uq_submissions_person_activity_attempt", ("tenant_id", "activity_id", "person_id", "attempt_no"), True),
            ("ix_submissions_tenant_id", ("tenant_id",), False),
            ("ix_submissions_activity_id", ("activity_id",), False),
            ("ix_submissions_person_id", ("person_id",), False),
        ),
    ),
    _TableSpec(
        "scores",
        learning.ScoreRowV1,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("submission_id", "uuid", False),
            ("score", "double precision", False),
            ("max_score", "double precision", False),
            ("fraction", "double precision", False),
            ("passed", "boolean", False),
            ("per_item", "jsonb", False),
            ("source", "character varying(10)", False),
            ("override_reason", "text", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "submission_id"), "submissions", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (),
        (
            ("scores_pkey", ("id",), True),
            ("ix_scores_tenant_id", ("tenant_id",), False),
            ("ix_scores_submission_id", ("submission_id",), False),
        ),
    ),
    _TableSpec(
        "activity_attempts",
        learning.ActivityAttemptRowV4,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("activity_id", "uuid", False),
            ("person_id", "uuid", False),
            ("question_ext_ids", "jsonb", False),
            ("started_at", "timestamp with time zone", False),
            ("submitted_at", "timestamp with time zone", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "activity_id"), "activities", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (("uq_activity_attempts_tenant_id_id", ("tenant_id", "id")),),
        (
            ("activity_attempts_pkey", ("id",), True),
            ("uq_activity_attempts_tenant_id_id", ("tenant_id", "id"), True),
            ("uq_activity_attempts_open", ("tenant_id", "activity_id", "person_id"), True),
            ("ix_activity_attempts_tenant_id", ("tenant_id",), False),
            ("ix_activity_attempts_activity_id", ("activity_id",), False),
            ("ix_activity_attempts_person_id", ("person_id",), False),
        ),
    ),
    _TableSpec(
        "attempt_grants",
        learning.AttemptGrantRowV4,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("activity_id", "uuid", False),
            ("person_id", "uuid", False),
            ("extra_attempts", "integer", False),
            ("reason", "text", False),
            ("granted_by", "uuid", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "activity_id"), "activities", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (("uq_attempt_grants_tenant_id_id", ("tenant_id", "id")),),
        (
            ("attempt_grants_pkey", ("id",), True),
            ("uq_attempt_grants_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_attempt_grants_lookup", ("tenant_id", "activity_id", "person_id"), False),
            ("ix_attempt_grants_tenant_id", ("tenant_id",), False),
            ("ix_attempt_grants_activity_id", ("activity_id",), False),
            ("ix_attempt_grants_person_id", ("person_id",), False),
        ),
    ),
    _TableSpec(
        "chapter_bookmarks",
        learning.ChapterBookmarkRowV2,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("person_id", "uuid", False),
            ("course_id", "uuid", False),
            ("chapter_id", "uuid", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id",), "tenants", ("id",), "c"),
            (("course_id",), "courses", ("id",), "c"),
            (("chapter_id",), "chapters", ("id",), "c"),
        ),
        (("uq_chapter_bookmarks_person_chapter", ("tenant_id", "person_id", "chapter_id")),),
        (
            ("chapter_bookmarks_pkey", ("id",), True),
            ("uq_chapter_bookmarks_person_chapter", ("tenant_id", "person_id", "chapter_id"), True),
            ("ix_chapter_bookmarks_tenant_id", ("tenant_id",), False),
            ("ix_chapter_bookmarks_person_id", ("person_id",), False),
            ("ix_chapter_bookmarks_course_id", ("course_id",), False),
            ("ix_chapter_bookmarks_chapter_id", ("chapter_id",), False),
        ),
    ),
    _TableSpec(
        "chapter_notes",
        learning.ChapterNoteRowV2,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("person_id", "uuid", False),
            ("course_id", "uuid", False),
            ("chapter_id", "uuid", False),
            ("body", "text", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id",), "tenants", ("id",), "c"),
            (("course_id",), "courses", ("id",), "c"),
            (("chapter_id",), "chapters", ("id",), "c"),
        ),
        (("uq_chapter_notes_person_chapter", ("tenant_id", "person_id", "chapter_id")),),
        (
            ("chapter_notes_pkey", ("id",), True),
            ("uq_chapter_notes_person_chapter", ("tenant_id", "person_id", "chapter_id"), True),
            ("ix_chapter_notes_tenant_id", ("tenant_id",), False),
            ("ix_chapter_notes_person_id", ("person_id",), False),
            ("ix_chapter_notes_course_id", ("course_id",), False),
            ("ix_chapter_notes_chapter_id", ("chapter_id",), False),
        ),
    ),
    _TableSpec(
        "certificates",
        learning.CertificateRowV1,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("person_id", "uuid", False),
            ("course_id", "uuid", False),
            ("serial", "character varying(32)", False),
            ("issued_at", "timestamp with time zone", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id", "course_id"), "courses", ("tenant_id", "id"), "c"), (("tenant_id",), "tenants", ("id",), "c")),
        (
            ("uq_certificates_tenant_id_id", ("tenant_id", "id")),
            ("uq_certificates_person_course", ("tenant_id", "person_id", "course_id")),
            ("uq_certificates_tenant_serial", ("tenant_id", "serial")),
        ),
        (
            ("certificates_pkey", ("id",), True),
            ("uq_certificates_tenant_id_id", ("tenant_id", "id"), True),
            ("uq_certificates_person_course", ("tenant_id", "person_id", "course_id"), True),
            ("uq_certificates_tenant_serial", ("tenant_id", "serial"), True),
            ("ix_certificates_tenant_id", ("tenant_id",), False),
            ("ix_certificates_person_id", ("person_id",), False),
            ("ix_certificates_course_id", ("course_id",), False),
        ),
    ),
    _TableSpec(
        "class_sessions",
        learning.ClassSessionRowV5,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("cohort_id", "uuid", False),
            ("offering_id", "uuid", True),
            ("session_type", "character varying(20)", False),
            ("title", "character varying(200)", False),
            ("starts_at", "timestamp with time zone", False),
            ("ends_at", "timestamp with time zone", True),
            ("instructor_person_id", "uuid", True),
            ("location", "character varying(160)", True),
            ("join_url", "character varying(500)", True),
            ("notes", "text", True),
            ("status", "character varying(20)", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id", "cohort_id"), "cohorts", ("tenant_id", "id"), "c"), (("tenant_id",), "tenants", ("id",), "c")),
        (("uq_class_sessions_tenant_id_id", ("tenant_id", "id")),),
        (
            ("class_sessions_pkey", ("id",), True),
            ("uq_class_sessions_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_class_sessions_cohort_start", ("tenant_id", "cohort_id", "starts_at"), False),
            ("ix_class_sessions_instructor", ("tenant_id", "instructor_person_id"), False),
            ("ix_class_sessions_tenant_id", ("tenant_id",), False),
        ),
    ),
    _TableSpec(
        "cohorts",
        learning.CohortRowV3,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("name", "character varying(120)", False),
            ("discipline", "character varying(40)", False),
            ("status", "character varying(20)", False),
            ("delivery_mode", "character varying(20)", False),
            ("entrance_bank_id", "uuid", True),
            ("entrance_time_limit_minutes", "integer", True),
            ("auto_accept_threshold", "double precision", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id",), "tenants", ("id",), "c"),),
        (("uq_cohorts_tenant_id_id", ("tenant_id", "id")),),
        (
            ("cohorts_pkey", ("id",), True),
            ("uq_cohorts_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_cohorts_tenant_id", ("tenant_id",), False),
        ),
    ),
    _TableSpec(
        "enrollments",
        learning.EnrollmentRowV3,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("cohort_id", "uuid", False),
            ("person_id", "uuid", False),
            ("track_id", "uuid", True),
            ("role_in_cohort", "character varying(20)", False),
            ("status", "character varying(20)", False),
            ("audience", "character varying(20)", True),
            ("employee_ref", "character varying(64)", True),
            ("access_ends_at", "timestamp with time zone", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "cohort_id", "track_id"), "cohort_tracks", ("tenant_id", "cohort_id", "track_id"), "a"),
            (("tenant_id", "cohort_id"), "cohorts", ("tenant_id", "id"), "c"),
            (("tenant_id", "person_id"), "people", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (("uq_enrollments_member", ("tenant_id", "cohort_id", "person_id")),),
        (
            ("enrollments_pkey", ("id",), True),
            ("uq_enrollments_member", ("tenant_id", "cohort_id", "person_id"), True),
            ("ix_enrollments_tenant_id", ("tenant_id",), False),
            ("ix_enrollments_cohort_id", ("cohort_id",), False),
            ("ix_enrollments_person_id", ("person_id",), False),
            ("ix_enrollments_track_id", ("track_id",), False),
            ("ix_enrollments_audience", ("audience",), False),
            ("ix_enrollments_access_ends_at", ("tenant_id", "access_ends_at"), False),
        ),
    ),
    _TableSpec(
        "course_completions",
        learning.CourseCompletionRowV1,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("person_id", "uuid", False),
            ("course_id", "uuid", False),
            ("status", "character varying(20)", False),
            ("pct", "double precision", False),
            ("completed_at", "timestamp with time zone", True),
            ("erp_synced_at", "timestamp with time zone", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id", "course_id"), "courses", ("tenant_id", "id"), "c"), (("tenant_id",), "tenants", ("id",), "c")),
        (
            ("uq_course_completions_tenant_id_id", ("tenant_id", "id")),
            ("uq_course_completions_person_course", ("tenant_id", "person_id", "course_id")),
        ),
        (
            ("course_completions_pkey", ("id",), True),
            ("uq_course_completions_tenant_id_id", ("tenant_id", "id"), True),
            ("uq_course_completions_person_course", ("tenant_id", "person_id", "course_id"), True),
            ("ix_course_completions_tenant_id", ("tenant_id",), False),
            ("ix_course_completions_person_id", ("person_id",), False),
            ("ix_course_completions_course_id", ("course_id",), False),
        ),
    ),
    _TableSpec(
        "courses",
        learning.CourseRowV1,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("slug", "character varying(63)", False),
            ("title", "character varying(200)", False),
            ("discipline", "character varying(40)", False),
            ("source_ref", "character varying(120)", False),
            ("version", "integer", False),
            ("status", "character varying(20)", False),
            ("listed", "boolean", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id",), "tenants", ("id",), "c"),),
        (("uq_courses_tenant_slug", ("tenant_id", "slug")), ("uq_courses_tenant_id_id", ("tenant_id", "id"))),
        (
            ("courses_pkey", ("id",), True),
            ("uq_courses_tenant_slug", ("tenant_id", "slug"), True),
            ("uq_courses_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_courses_tenant_id", ("tenant_id",), False),
        ),
    ),
    _TableSpec(
        "chapters",
        learning.ChapterRowV2,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("course_id", "uuid", False),
            ("number", "integer", False),
            ("title", "character varying(200)", False),
            ("part", "character varying(20)", False),
            ("body_html", "text", False),
            ("body_md", "text", False),
            ("source_hash", "character varying(64)", False),
            ("order_index", "integer", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id", "course_id"), "courses", ("tenant_id", "id"), "c"), (("tenant_id",), "tenants", ("id",), "c")),
        (("uq_chapters_tenant_course_number", ("tenant_id", "course_id", "number")),),
        (
            ("chapters_pkey", ("id",), True),
            ("uq_chapters_tenant_course_number", ("tenant_id", "course_id", "number"), True),
            ("ix_chapters_tenant_id", ("tenant_id",), False),
            ("ix_chapters_course_id", ("course_id",), False),
        ),
    ),
    _TableSpec(
        "learning_events",
        learning.LearningEventRowV1,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("person_id", "uuid", False),
            ("course_id", "uuid", True),
            ("kind", "character varying(30)", False),
            ("subject_id", "uuid", True),
            ("detail", "jsonb", False),
            ("occurred_at", "timestamp with time zone", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id", "person_id"), "people", ("tenant_id", "id"), "c"), (("tenant_id",), "tenants", ("id",), "c")),
        (),
        (
            ("learning_events_pkey", ("id",), True),
            ("ix_learning_events_person_time", ("tenant_id", "person_id", "occurred_at"), False),
            ("ix_learning_events_course_kind", ("tenant_id", "course_id", "kind"), False),
            ("ix_learning_events_kind_time", ("tenant_id", "kind", "occurred_at"), False),
            ("ix_learning_events_tenant_id", ("tenant_id",), False),
            ("ix_learning_events_person_id", ("person_id",), False),
            ("uq_learning_events_once_per_subject", ("tenant_id", "person_id", "kind", "subject_id"), True),
        ),
    ),
    _TableSpec(
        "course_offerings",
        learning.CourseOfferingRowV3,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("cohort_id", "uuid", False),
            ("course_id", "uuid", False),
            ("status", "character varying(20)", False),
            ("starts_at", "timestamp with time zone", True),
            ("ends_at", "timestamp with time zone", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "cohort_id"), "cohorts", ("tenant_id", "id"), "c"),
            (("tenant_id", "course_id"), "courses", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (
            ("uq_course_offerings_tenant_id_id", ("tenant_id", "id")),
            ("uq_course_offerings_cohort_course", ("tenant_id", "cohort_id", "course_id")),
        ),
        (
            ("course_offerings_pkey", ("id",), True),
            ("uq_course_offerings_tenant_id_id", ("tenant_id", "id"), True),
            ("uq_course_offerings_cohort_course", ("tenant_id", "cohort_id", "course_id"), True),
            ("ix_course_offerings_tenant_id", ("tenant_id",), False),
            ("ix_course_offerings_cohort_id", ("cohort_id",), False),
            ("ix_course_offerings_course_id", ("course_id",), False),
        ),
    ),
    _TableSpec(
        "offering_activities",
        learning.OfferingActivityRowV5,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("offering_id", "uuid", False),
            ("activity_id", "uuid", False),
            ("release_at", "timestamp with time zone", True),
            ("due_at", "timestamp with time zone", True),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "offering_id"), "course_offerings", ("tenant_id", "id"), "c"),
            (("tenant_id", "activity_id"), "activities", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (
            ("uq_offering_activities_tenant_id_id", ("tenant_id", "id")),
            ("uq_offering_activities_offering_activity", ("tenant_id", "offering_id", "activity_id")),
        ),
        (
            ("offering_activities_pkey", ("id",), True),
            ("uq_offering_activities_tenant_id_id", ("tenant_id", "id"), True),
            ("uq_offering_activities_offering_activity", ("tenant_id", "offering_id", "activity_id"), True),
            ("ix_offering_activities_tenant_id", ("tenant_id",), False),
            ("ix_offering_activities_offering_id", ("offering_id",), False),
            ("ix_offering_activities_activity_id", ("activity_id",), False),
        ),
    ),
    _TableSpec(
        "course_prerequisites",
        learning.CoursePrerequisiteRowV3,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("course_id", "uuid", False),
            ("requires_course_id", "uuid", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "course_id"), "courses", ("tenant_id", "id"), "c"),
            (("tenant_id", "requires_course_id"), "courses", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (
            ("uq_course_prerequisites_tenant_id_id", ("tenant_id", "id")),
            ("uq_course_prerequisites_pair", ("tenant_id", "course_id", "requires_course_id")),
        ),
        (
            ("course_prerequisites_pkey", ("id",), True),
            ("uq_course_prerequisites_tenant_id_id", ("tenant_id", "id"), True),
            ("uq_course_prerequisites_pair", ("tenant_id", "course_id", "requires_course_id"), True),
            ("ix_course_prerequisites_tenant_id", ("tenant_id",), False),
            ("ix_course_prerequisites_course_id", ("course_id",), False),
            ("ix_course_prerequisites_requires_course_id", ("requires_course_id",), False),
        ),
    ),
    _TableSpec(
        "chapter_reads",
        learning.ChapterReadRowV2,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("person_id", "uuid", False),
            ("chapter_id", "uuid", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id",), "tenants", ("id",), "c"), (("chapter_id",), "chapters", ("id",), "c")),
        (("uq_chapter_reads_person_chapter", ("tenant_id", "person_id", "chapter_id")),),
        (
            ("chapter_reads_pkey", ("id",), True),
            ("uq_chapter_reads_person_chapter", ("tenant_id", "person_id", "chapter_id"), True),
            ("ix_chapter_reads_tenant_id", ("tenant_id",), False),
            ("ix_chapter_reads_person_id", ("person_id",), False),
            ("ix_chapter_reads_chapter_id", ("chapter_id",), False),
        ),
    ),
    _TableSpec(
        "subtopic_reads",
        learning.SubtopicReadRowV2,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("person_id", "uuid", False),
            ("chapter_id", "uuid", False),
            ("subtopic_slug", "character varying(64)", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id",), "tenants", ("id",), "c"), (("chapter_id",), "chapters", ("id",), "c")),
        (("uq_subtopic_reads_person_subtopic", ("tenant_id", "person_id", "chapter_id", "subtopic_slug")),),
        (
            ("subtopic_reads_pkey", ("id",), True),
            ("uq_subtopic_reads_person_subtopic", ("tenant_id", "person_id", "chapter_id", "subtopic_slug"), True),
            ("ix_subtopic_reads_tenant_id", ("tenant_id",), False),
            ("ix_subtopic_reads_person_id", ("person_id",), False),
            ("ix_subtopic_reads_chapter_id", ("chapter_id",), False),
        ),
    ),
    _TableSpec(
        "success_queue_entries",
        learning.SuccessQueueEntryRowV5,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("person_id", "uuid", False),
            ("cohort_id", "uuid", True),
            ("reason_kind", "character varying(30)", False),
            ("supporting_facts", "jsonb", False),
            ("severity", "character varying(10)", False),
            ("detected_at", "timestamp with time zone", False),
            ("assigned_to", "uuid", True),
            ("recommended_action", "text", False),
            ("status", "character varying(15)", False),
            ("resolved_at", "timestamp with time zone", True),
            ("resolved_by", "uuid", True),
            ("score_hint", "double precision", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id", "person_id"), "people", ("tenant_id", "id"), "c"), (("tenant_id",), "tenants", ("id",), "c")),
        (("uq_success_queue_tenant_id_id", ("tenant_id", "id")),),
        (
            ("success_queue_entries_pkey", ("id",), True),
            ("uq_success_queue_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_success_queue_tenant_id", ("tenant_id",), False),
            ("ix_success_queue_person_id", ("person_id",), False),
            ("ix_success_queue_cohort_id", ("cohort_id",), False),
            ("ix_success_queue_status", ("tenant_id", "status", "severity"), False),
            ("uq_success_queue_open_person_reason", ("tenant_id", "person_id", "reason_kind"), True),
        ),
    ),
    _TableSpec(
        "tracks",
        learning.TrackRowV3,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("slug", "character varying(80)", False),
            ("name", "character varying(160)", False),
            ("status", "character varying(20)", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        ((("tenant_id",), "tenants", ("id",), "c"),),
        (("uq_tracks_tenant_slug", ("tenant_id", "slug")), ("uq_tracks_tenant_id_id", ("tenant_id", "id"))),
        (
            ("tracks_pkey", ("id",), True),
            ("uq_tracks_tenant_slug", ("tenant_id", "slug"), True),
            ("uq_tracks_tenant_id_id", ("tenant_id", "id"), True),
            ("ix_tracks_tenant_id", ("tenant_id",), False),
        ),
    ),
    _TableSpec(
        "track_courses",
        learning.TrackCourseRowV3,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("track_id", "uuid", False),
            ("course_id", "uuid", False),
            ("order_index", "integer", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "track_id"), "tracks", ("tenant_id", "id"), "c"),
            (("tenant_id", "course_id"), "courses", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (("uq_track_courses_track_course", ("tenant_id", "track_id", "course_id")),),
        (
            ("track_courses_pkey", ("id",), True),
            ("uq_track_courses_track_course", ("tenant_id", "track_id", "course_id"), True),
            ("ix_track_courses_tenant_id", ("tenant_id",), False),
            ("ix_track_courses_track_id", ("track_id",), False),
            ("ix_track_courses_course_id", ("course_id",), False),
        ),
    ),
    _TableSpec(
        "cohort_tracks",
        learning.CohortTrackRowV3,
        (
            ("id", "uuid", False),
            ("tenant_id", "uuid", False),
            ("cohort_id", "uuid", False),
            ("track_id", "uuid", False),
            ("status", "character varying(20)", False),
            ("created_at", "timestamp with time zone", False),
            ("updated_at", "timestamp with time zone", False),
        ),
        (
            (("tenant_id", "cohort_id"), "cohorts", ("tenant_id", "id"), "c"),
            (("tenant_id", "track_id"), "tracks", ("tenant_id", "id"), "c"),
            (("tenant_id",), "tenants", ("id",), "c"),
        ),
        (
            ("uq_cohort_tracks_tenant_id_id", ("tenant_id", "id")),
            ("uq_cohort_tracks_cohort_track", ("tenant_id", "cohort_id", "track_id")),
        ),
        (
            ("cohort_tracks_pkey", ("id",), True),
            ("uq_cohort_tracks_tenant_id_id", ("tenant_id", "id"), True),
            ("uq_cohort_tracks_cohort_track", ("tenant_id", "cohort_id", "track_id"), True),
            ("ix_cohort_tracks_tenant_id", ("tenant_id",), False),
            ("ix_cohort_tracks_cohort_id", ("cohort_id",), False),
            ("ix_cohort_tracks_track_id", ("track_id",), False),
        ),
    ),
)

_FOREIGN_KEY_NAMES = {
    "announcements": (
        "fk_announcements_tenant_cohort",
        "fk_announcements_tenant_author",
        "announcements_tenant_id_fkey",
    ),
    "question_banks": ("question_banks_tenant_id_fkey",),
    "questions": ("fk_questions_tenant_bank", "questions_tenant_id_fkey"),
    "activities": ("activities_tenant_id_fkey",),
    "submissions": ("fk_submissions_tenant_activity", "submissions_tenant_id_fkey"),
    "scores": ("fk_scores_tenant_submission", "scores_tenant_id_fkey"),
    "activity_attempts": ("fk_activity_attempts_tenant_activity", "activity_attempts_tenant_id_fkey"),
    "attempt_grants": ("fk_attempt_grants_tenant_activity", "attempt_grants_tenant_id_fkey"),
    "chapter_bookmarks": (
        "chapter_bookmarks_tenant_id_fkey",
        "chapter_bookmarks_course_id_fkey",
        "chapter_bookmarks_chapter_id_fkey",
    ),
    "chapter_notes": ("chapter_notes_tenant_id_fkey", "chapter_notes_course_id_fkey", "chapter_notes_chapter_id_fkey"),
    "certificates": ("fk_certificates_tenant_course", "certificates_tenant_id_fkey"),
    "class_sessions": ("fk_class_sessions_tenant_cohort", "class_sessions_tenant_id_fkey"),
    "cohorts": ("cohorts_tenant_id_fkey",),
    "enrollments": (
        "fk_enrollments_tenant_cohort_track",
        "fk_enrollments_tenant_cohort",
        "fk_enrollments_tenant_person",
        "enrollments_tenant_id_fkey",
    ),
    "course_completions": ("fk_course_completions_tenant_course", "course_completions_tenant_id_fkey"),
    "courses": ("courses_tenant_id_fkey",),
    "chapters": ("fk_chapters_tenant_course", "chapters_tenant_id_fkey"),
    "learning_events": ("fk_learning_events_tenant_person", "learning_events_tenant_id_fkey"),
    "course_offerings": (
        "fk_course_offerings_tenant_cohort",
        "fk_course_offerings_tenant_course",
        "course_offerings_tenant_id_fkey",
    ),
    "offering_activities": (
        "fk_offering_activities_tenant_offering",
        "fk_offering_activities_tenant_activity",
        "offering_activities_tenant_id_fkey",
    ),
    "course_prerequisites": (
        "fk_course_prerequisites_tenant_course",
        "fk_course_prerequisites_tenant_requires",
        "course_prerequisites_tenant_id_fkey",
    ),
    "chapter_reads": ("chapter_reads_tenant_id_fkey", "chapter_reads_chapter_id_fkey"),
    "subtopic_reads": ("subtopic_reads_tenant_id_fkey", "subtopic_reads_chapter_id_fkey"),
    "success_queue_entries": ("fk_success_queue_tenant_person", "success_queue_entries_tenant_id_fkey"),
    "tracks": ("tracks_tenant_id_fkey",),
    "track_courses": (
        "fk_track_courses_tenant_track",
        "fk_track_courses_tenant_course",
        "track_courses_tenant_id_fkey",
    ),
    "cohort_tracks": (
        "fk_cohort_tracks_tenant_cohort",
        "fk_cohort_tracks_tenant_track",
        "cohort_tracks_tenant_id_fkey",
    ),
}

_SOURCE_NAMES = tuple(sorted(spec.name for spec in _TABLES))
_LOCK_NAMES = tuple(sorted((*_SOURCE_NAMES, "tenants", "people", "alembic_version")))
# Fixed source-derived PG16 renderings; never normalize quoted literals.
# Hosted confirmation is still required; another rendering must refuse.
_INDEX_PREDICATES = {
    ("activity_attempts", "uq_activity_attempts_open"): "(submitted_at IS NULL)",
    ("learning_events", "uq_learning_events_once_per_subject"): (
        "((kind)::text = ANY ((ARRAY['chapter_completed'::character varying, "
        "'certificate_earned'::character varying])::text[]))"
    ),
    ("success_queue_entries", "uq_success_queue_open_person_reason"): "((status)::text = 'open'::text)",
}
_ENROLLMENT_CHECKS = {
    "ck_enrollments_audience": (
        "((audience IS NULL) OR ((audience)::text = ANY ((ARRAY['staff'::character varying, "
        "'external'::character varying])::text[])))"
    ),
    "ck_enrollments_staff_has_employee_ref": (
        "(((audience)::text IS DISTINCT FROM 'staff'::text) OR (employee_ref IS NOT NULL))"
    ),
}
_INDEX_OPCLASSES = {
    "uuid": "pg_catalog.uuid_ops",
    "integer": "pg_catalog.int4_ops",
    "timestamp with time zone": "pg_catalog.timestamptz_ops",
    "character varying": "pg_catalog.text_ops",
}
_STATE_KEY = object()
_RELOCATION_KEY = object()
# Fixed historical0056 + 0061 worker grants, never canonical Learning policy.
_WORKER_TABLE_PRIVILEGES = {
    "activities": {"SELECT"},
    "courses": {"SELECT"},
    "course_completions": {"SELECT"},
    "submissions": {"SELECT", "INSERT"},
    "scores": {"SELECT", "INSERT"},
    "learning_events": {"SELECT", "INSERT"},
    "certificates": {"SELECT", "INSERT"},
}
_WORKER_COMPLETION_COLUMNS = {
    "INSERT": {"id", "tenant_id", "person_id", "course_id", "status", "pct"},
    "UPDATE": {"status", "pct", "completed_at", "updated_at"},
}


@dataclass(frozen=True, slots=True, repr=False)
class _Catalog:
    relation: tuple = field(repr=False)
    columns: tuple = field(repr=False)
    constraints: tuple = field(repr=False)
    incoming: tuple = field(repr=False)
    indexes: tuple = field(repr=False)
    policies: tuple = field(repr=False)
    dependencies: tuple = field(repr=False)
    acl: tuple = field(repr=False)
    column_acl: tuple = field(repr=False)
    rules: tuple = field(repr=False)
    triggers: tuple = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _CompletionAck:
    tenant_id: UUID
    id: UUID
    erp_synced_at: datetime | None = field(repr=False)


class _Capture:
    __slots__ = ()

    def __new__(cls):
        raise LearningHistoryRefused("Learning history capture is privately issued")

    def __repr__(self):
        return "<AcademyLearningHistory private capture>"


@dataclass(frozen=True, slots=True, repr=False)
class _Captured:
    handle: _Capture
    connection: Connection = field(repr=False)
    root: object = field(repr=False)
    physical_xid: str = field(repr=False)
    oids: tuple = field(repr=False)
    catalogs: tuple = field(repr=False)
    roles: tuple = field(repr=False)
    function: tuple = field(repr=False)
    tenants: tuple = field(repr=False)
    people: tuple = field(repr=False)
    raw_rows: tuple = field(repr=False)
    snapshot: learning.LearningSnapshotV5 = field(repr=False)
    completion_acks: tuple[_CompletionAck, ...] = field(repr=False)


def _freeze(value):
    return tuple(_freeze(v) for v in value) if isinstance(value, (list, tuple)) else value


def _query(connection, sql, **params):
    return tuple(_freeze(tuple(row)) for row in connection.execute(sa.text(sql), params))


def _oid(connection, name, schema="public"):
    # Names/schemas originate only in this module's fixed declaration/phase.
    return connection.scalar(
        sa.text("SELECT pg_catalog.to_regclass(:relation)::oid"), {"relation": schema + "." + name}
    )


def _catalog(connection, oid):
    q = lambda sql: _query(connection, sql, oid=oid)  # noqa: E731
    relation = q(
        "SELECT oid,relkind,pg_catalog.pg_get_userbyid(relowner),relrowsecurity,relforcerowsecurity,"
        "relhassubclass,relispartition,relpersistence,reloptions,relreplident,reltablespace "
        "FROM pg_catalog.pg_class WHERE oid=:oid"
    )
    _require(len(relation) == 1)
    return _Catalog(
        relation[0],
        q(
            "SELECT a.attnum,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,"
            "a.attisdropped,d.adbin::text,a.attidentity,a.attgenerated,a.attcollation "
            "FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef d ON "
            "d.adrelid=a.attrelid AND d.adnum=a.attnum "
            "WHERE a.attrelid=:oid AND a.attnum>0 ORDER BY a.attnum"
        ),
        q(
            "SELECT conname,contype,conkey,confrelid,confkey,confdeltype,confupdtype,confmatchtype,"
            "convalidated,condeferrable,condeferred,conbin::text FROM pg_catalog.pg_constraint "
            "WHERE conrelid=:oid ORDER BY conname"
        ),
        q(
            "SELECT oid,conname,conrelid,conkey,confkey,confdeltype,confupdtype,confmatchtype,"
            "convalidated,condeferrable,condeferred FROM pg_catalog.pg_constraint WHERE confrelid=:oid ORDER BY oid"
        ),
        q(
            "SELECT c.oid,c.relname,i.indisunique,i.indisprimary,i.indisvalid,i.indisready,i.indislive,"
            "i.indkey::text,i.indclass::text,i.indcollation::text,i.indoption::text,i.indexprs::text,"
            "i.indpred::text,i.indnkeyatts,i.indnatts,c.reloptions,c.reltablespace,c.relowner,c.relacl::text,am.amname,"
            "i.indnullsnotdistinct,i.indimmediate,i.indisexclusion,"
            "COALESCE((SELECT jsonb_agg(jsonb_build_array(CAST(k.oid AS bigint),CAST(k.conrelid AS bigint),"
            "CAST(k.conindid AS bigint),k.conname,k.contype,"
            "k.conkey,k.convalidated,k.condeferrable,k.condeferred) ORDER BY k.oid) "
            "FROM pg_catalog.pg_constraint k WHERE k.conindid=i.indexrelid AND k.contype IN ('p','u')),'[]'::jsonb) "
            "FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON "
            "c.oid=i.indexrelid JOIN pg_catalog.pg_am am ON am.oid=c.relam "
            "WHERE i.indrelid=:oid ORDER BY c.relname"
        ),
        q(
            "SELECT oid,polname,polcmd,polpermissive,polroles,polqual::text,polwithcheck::text "
            "FROM pg_catalog.pg_policy WHERE polrelid=:oid ORDER BY polname"
        ),
        q(
            "SELECT d.classid,d.objid,d.objsubid,d.refclassid,d.refobjid,d.refobjsubid,d.deptype "
            "FROM pg_catalog.pg_depend d WHERE (d.classid='pg_catalog.pg_policy'::regclass AND d.objid IN "
            "(SELECT oid FROM pg_catalog.pg_policy WHERE polrelid=:oid)) ORDER BY 1,2,3,4,5,6,7"
        ),
        q(
            "SELECT a.grantor,a.grantee,a.privilege_type,a.is_grantable FROM pg_catalog.pg_class c,"
            "LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a "
            "WHERE c.oid=:oid ORDER BY 1,2,3,4"
        ),
        q(
            "SELECT attnum,attacl::text FROM pg_catalog.pg_attribute WHERE "
            "attrelid=:oid AND attacl IS NOT NULL ORDER BY attnum"
        ),
        q(
            "SELECT oid,rulename,ev_type,ev_enabled,is_instead,ev_qual::text,ev_action::text "
            "FROM pg_catalog.pg_rewrite WHERE ev_class=:oid ORDER BY oid"
        ),
        q(
            "SELECT oid,tgname,tgfoid,tgtype,tgenabled,tgisinternal,tgconstraint,tgconstrrelid,"
            "tgdeferrable,tginitdeferred,tgargs,tgqual::text FROM pg_catalog.pg_trigger WHERE tgrelid=:oid ORDER BY oid"
        ),
    )


def _roles(connection):
    rows = _query(
        connection,
        "SELECT oid,rolname,rolsuper,rolbypassrls,rolinherit,rolcreaterole,rolcreatedb,"
        "rolcanlogin,rolreplication,rolconnlimit,rolvaliduntil,rolconfig FROM pg_catalog.pg_roles "
        "WHERE rolname IN ('app_admin','app_user','platform_api','academy_lab_worker') ORDER BY rolname",
    )
    _require(len(rows) == 4)
    by_name = {row[1]: row for row in rows}
    for name, row in by_name.items():
        _require(row[2] is False and row[3] is (name in {"app_admin", "academy_lab_worker"}))
        _require(row[4] is (name != "academy_lab_worker"))
        _require(row[5:9] == (False, False, True, False) and row[11] is None)
    memberships = _query(
        connection,
        "SELECT roleid,member,grantor,pg_catalog.to_jsonb(m)::text FROM pg_catalog.pg_auth_members m "
        "WHERE roleid IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN "
        "('app_admin','app_user','platform_api','academy_lab_worker')) "
        "OR member IN (SELECT oid FROM pg_catalog.pg_roles WHERE rolname IN "
        "('app_admin','app_user','platform_api','academy_lab_worker')) "
        "ORDER BY roleid,member,grantor",
    )
    _require(not memberships)
    return rows, memberships


def _tenant_function(connection):
    return _query(
        connection,
        "SELECT p.oid,p.proowner,p.prolang,p.prosecdef,p.proleakproof,p.provolatile,p.proparallel,"
        "p.prosrc,p.probin,p.proconfig,p.proacl::text FROM pg_catalog.pg_proc p "
        "WHERE p.oid='public.app_current_tenant_id()'::regprocedure",
    )


def _column_names(connection, oid, numbers):
    return tuple(
        connection.scalar(
            sa.text(
                "SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid=:oid AND "
                "attnum=:number AND NOT attisdropped"
            ),
            {"oid": oid, "number": number},
        )
        for number in numbers
    )


def _shape(connection, spec, catalog, oids, roles):
    oid = oids[spec.name]
    _require(catalog.relation == (oid, "r", "app_admin", True, True, False, False, "p", None, "d", 0))
    _require(all(not row[4] and row[6:8] == ("", "") for row in catalog.columns))
    _require(
        {row[1]: (row[2], not row[3]) for row in catalog.columns}
        == {name: (typ, nullable) for name, typ, nullable in spec.columns}
    )
    keys = []
    fks = []
    checks = []
    for row in catalog.constraints:
        name, kind, source, parent_oid, parent, delete, update, match, valid, deferrable, deferred, expression = row
        _require(valid is True and not deferrable and not deferred)
        if kind in {"p", "u"}:
            keys.append((name, kind, _column_names(connection, oid, source)))
        elif kind == "f":
            parent_name = next((name for name, value in oids.items() if value == parent_oid), None)
            _require(parent_name is not None and update == "a" and match == "s")
            fks.append(
                (
                    _column_names(connection, oid, source),
                    parent_name,
                    _column_names(connection, parent_oid, parent),
                    delete,
                )
            )
        elif kind == "c":
            checks.append(name)
        else:
            _require(False)
    _require(
        set(keys) == {(spec.name + "_pkey", "p", ("id",)), *((name, "u", cols) for name, cols in spec.unique_keys)}
    )
    _require(sorted(fks) == sorted(spec.foreign_keys))
    _require({row[0] for row in catalog.constraints if row[1] == "f"} == set(_FOREIGN_KEY_NAMES[spec.name]))
    expected_checks = _ENROLLMENT_CHECKS if spec.name == "enrollments" else {}
    _require(set(checks) == set(expected_checks))
    _require(
        _query(
            connection,
            "SELECT conname,pg_catalog.pg_get_expr(conbin,conrelid,false) FROM "
            "pg_catalog.pg_constraint WHERE conrelid=:oid AND contype='c' ORDER BY conname",
            oid=oid,
        )
        == tuple(sorted(expected_checks.items()))
    )
    expected_indexes = {name: (cols, unique) for name, cols, unique in spec.indexes}
    if spec.name == "enrollments":
        expected_indexes["ix_enrollments_audience"] = (("tenant_id", "audience"), False)
    _require({row[1] for row in catalog.indexes} == set(expected_indexes))
    constraint_indexes = {spec.name + "_pkey": ("p", ("id",))}
    constraint_indexes.update({name: ("u", columns) for name, columns in spec.unique_keys})
    declared_types = {name: typ for name, typ, _ in spec.columns}
    attribute_numbers = {row[1]: row[0] for row in catalog.columns}
    for row in catalog.indexes:
        (
            index_oid,
            name,
            unique,
            primary,
            valid,
            ready,
            live,
            numbers,
            classes,
            collations,
            ordering,
            expression,
            predicate,
            nkeys,
            natts,
            options,
            tablespace,
            owner,
            acl,
            method,
            nulls_not_distinct,
            immediate,
            exclusion,
            constraint_links,
        ) = row
        columns, expected_unique = expected_indexes[name]
        _require((unique, primary) == (expected_unique, name == spec.name + "_pkey"))
        _require(
            valid is True
            and ready is True
            and live is True
            and expression is None
            and nkeys == natts == len(columns)
            and options is None
            and tablespace == 0
            and acl is None
            and nulls_not_distinct is False
            and immediate is True
            and exclusion is False
        )
        numbers = tuple(map(int, numbers.split()))
        classes = tuple(map(int, classes.split()))
        collations = tuple(map(int, collations.split()))
        _require(len(numbers) == len(classes) == len(collations) == len(columns))
        _require(tuple(map(int, ordering.split())) == (0,) * len(columns))
        _require(numbers == tuple(attribute_numbers[column] for column in columns))
        _require(owner == roles["app_admin"] and method == "btree")
        types = tuple(
            "character varying" if declared_types[column].startswith("character varying(") else declared_types[column]
            for column in columns
        )
        _require(all(typ in _INDEX_OPCLASSES for typ in types))
        _require(
            _query(
                connection,
                "SELECT CASE WHEN opam.amname='btree' THEN ns.nspname||'.'||oc.opcname END,"
                "CASE WHEN v.collation_oid=0 THEN 'none' "
                "ELSE COALESCE(cns.nspname||'.'||co.collname,'unknown') END "
                "FROM unnest(CAST(:classes AS oid[]),CAST(:collations AS oid[])) "
                "WITH ORDINALITY v(opclass_oid,collation_oid,ordinal_position) "
                "LEFT JOIN pg_catalog.pg_opclass oc ON oc.oid=v.opclass_oid "
                "LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=oc.opcnamespace "
                "LEFT JOIN pg_catalog.pg_am opam ON opam.oid=oc.opcmethod "
                "LEFT JOIN pg_catalog.pg_collation co ON co.oid=v.collation_oid "
                "LEFT JOIN pg_catalog.pg_namespace cns ON cns.oid=co.collnamespace ORDER BY v.ordinal_position",
                classes=list(classes),
                collations=list(collations),
            )
            == tuple(
                (_INDEX_OPCLASSES[typ], "pg_catalog.default" if typ == "character varying" else "none") for typ in types
            )
        )
        expected_predicate = _INDEX_PREDICATES.get((spec.name, name))
        _require((predicate is not None) is (expected_predicate is not None))
        _require(
            connection.scalar(
                sa.text(
                    "SELECT pg_catalog.pg_get_expr(indpred,indrelid,false) "
                    "FROM pg_catalog.pg_index WHERE indexrelid=:oid"
                ),
                {"oid": index_oid},
            )
            == expected_predicate
        )
        if name in constraint_indexes:
            kind, key_columns = constraint_indexes[name]
            _require(len(constraint_links) == 1 and len(constraint_links[0]) == 9)
            link = constraint_links[0]
            _require(type(link[0]) is int and link[0] > 0)
            _require(
                link[1:]
                == (
                    oid,
                    index_oid,
                    name,
                    kind,
                    tuple(attribute_numbers[column] for column in key_columns),
                    True,
                    False,
                    False,
                )
            )
        else:
            _require(constraint_links == ())
    _require(not catalog.rules)
    _require(all(row[4] == "O" and row[5] is True for row in catalog.triggers))
    _require(len(catalog.policies) == 1)
    policy = catalog.policies[0]
    _require(policy[1:5] == (spec.name + "_tenant_isolation", "*", True, (0,)))
    expressions = _query(
        connection,
        "SELECT pg_catalog.pg_get_expr(polqual,polrelid),pg_catalog.pg_get_expr(polwithcheck,polrelid) "
        "FROM pg_catalog.pg_policy WHERE polrelid=:oid",
        oid=oid,
    )[0]
    allowed = {"(tenant_id = app_current_tenant_id())", "(tenant_id = public.app_current_tenant_id())"}
    _require(all(value in allowed for value in expressions))
    function_oid = connection.scalar(sa.text("SELECT 'public.app_current_tenant_id()'::regprocedure::oid"))
    policy_class = connection.scalar(sa.text("SELECT 'pg_catalog.pg_policy'::regclass::oid"))
    relation_class = connection.scalar(sa.text("SELECT 'pg_catalog.pg_class'::regclass::oid"))
    function_class = connection.scalar(sa.text("SELECT 'pg_catalog.pg_proc'::regclass::oid"))
    tenant_number = next(row[0] for row in catalog.columns if row[1] == "tenant_id")
    _require(
        set(catalog.dependencies)
        == {
            (policy_class, policy[0], 0, relation_class, oid, 0, "a"),
            (policy_class, policy[0], 0, relation_class, oid, tenant_number, "n"),
            (policy_class, policy[0], 0, function_class, function_oid, 0, "n"),
        }
    )
    owner_privileges = {
        row[0]
        for row in _query(
            connection,
            "SELECT privilege_type FROM pg_catalog.aclexplode(pg_catalog.acldefault('r',CAST(:owner AS oid)))",
            owner=roles["app_admin"],
        )
    }
    _require(
        {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
        <= owner_privileges
        <= {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"}
    )
    online = (
        {"SELECT", "INSERT"}
        if spec.name in {"learning_events", "subtopic_reads"}
        else {"SELECT", "INSERT", "UPDATE", "DELETE"}
    )
    expected_privileges = {
        "app_admin": owner_privileges,
        "app_user": online,
        "platform_api": online,
        "academy_lab_worker": _WORKER_TABLE_PRIVILEGES.get(spec.name, set()),
    }
    _require(
        set(catalog.acl)
        == {
            (roles["app_admin"], roles[role], p, False)
            for role, privileges in expected_privileges.items()
            for p in privileges
        }
    )
    column_grants = _WORKER_COMPLETION_COLUMNS if spec.name == "course_completions" else {}
    column_numbers = {row[1]: row[0] for row in catalog.columns}
    expected_column_acl = tuple(
        sorted(
            (column_numbers[column], column, roles["app_admin"], roles["academy_lab_worker"], privilege, False)
            for privilege, columns in column_grants.items()
            for column in columns
        )
    )
    _require(
        _query(
            connection,
            "SELECT t.attnum,t.attname,a.grantor,a.grantee,a.privilege_type,a.is_grantable "
            "FROM pg_catalog.pg_attribute t CROSS JOIN LATERAL pg_catalog.aclexplode(t.attacl) a "
            "WHERE t.attrelid=:oid ORDER BY 1,2,3,4,5,6",
            oid=oid,
        )
        == expected_column_acl
    )
    _require(tuple(row[0] for row in catalog.column_acl) == tuple(sorted({row[0] for row in expected_column_acl})))
    # Batch both complete effective matrices, including the owner and worker.
    # BYPASSRLS does not bypass SQL privileges; column rights also include table rights.
    _require(
        _query(
            connection,
            "SELECT r,p,pg_catalog.has_table_privilege(r,:oid,p) "
            "FROM unnest(CAST(:roles AS text[])) r,unnest(CAST(:privileges AS text[])) p ORDER BY r,p",
            oid=oid,
            roles=list(expected_privileges),
            privileges=sorted(owner_privileges),
        )
        == tuple(
            sorted(
                (role, privilege, privilege in privileges)
                for role, privileges in expected_privileges.items()
                for privilege in owner_privileges
            )
        )
    )
    column_privileges = ("SELECT", "INSERT", "UPDATE", "REFERENCES")
    _require(
        _query(
            connection,
            "SELECT r,a.attname,p,pg_catalog.has_column_privilege(r,:oid,a.attnum,p) "
            "FROM pg_catalog.pg_attribute a,unnest(CAST(:roles AS text[])) r,"
            "unnest(CAST(:privileges AS text[])) p WHERE a.attrelid=:oid AND a.attnum>0 ORDER BY r,a.attname,p",
            oid=oid,
            roles=list(expected_privileges),
            privileges=list(column_privileges),
        )
        == tuple(
            sorted(
                (
                    role,
                    column,
                    privilege,
                    privilege in privileges
                    or (role == "academy_lab_worker" and column in column_grants.get(privilege, set())),
                )
                for role, privileges in expected_privileges.items()
                for column in column_numbers
                for privilege in column_privileges
            )
        )
    )
    _require(
        connection.scalar(
            sa.text(
                "SELECT pg_catalog.has_table_privilege(current_user,:oid,'SELECT') "
                "AND NOT pg_catalog.row_security_active(:oid)"
            ),
            {"oid": oid},
        )
        is True
    )


def _raw_projection(connection, spec):
    # Independent direct SQL projection. Identifiers are fixed declarations;
    # every source column participates, including the product-only ACK.
    expressions = []
    for name, typ, _ in sorted(spec.columns):
        quoted = '"' + name + '"'
        if typ == "double precision":
            expression = f"encode(pg_catalog.float8send({quoted}),'hex')"
        elif typ == "timestamp with time zone":
            expression = f"encode(pg_catalog.timestamptz_send({quoted}),'hex')"
        elif typ == "jsonb":
            expression = quoted + "::text"
        else:
            expression = quoted
        expressions.append(expression)
    _require(any(spec is item for item in _TABLES))
    statement = (
        sa.select(*(sa.literal_column(expression) for expression in expressions))
        .select_from(sa.table(spec.name, schema="public"))
        .order_by(sa.literal_column('"id"'))
    )
    return tuple(_freeze(tuple(row)) for row in connection.execute(statement))


def _timestamp(value):
    if value is None:
        return None
    try:
        _require(type(value) is str and len(value) == 16)
        return datetime(2000, 1, 1, tzinfo=UTC) + timedelta(microseconds=struct.unpack("!q", bytes.fromhex(value))[0])
    except (ValueError, OverflowError, struct.error):
        raise LearningHistoryRefused("unsupported historical timestamp; root rollback required") from None


def _decode(connection, spec):
    relation = sa.table(spec.name, *(sa.column(name) for name, _, _ in spec.columns), schema="public")
    projection = []
    for name, typ, _ in spec.columns:
        value = relation.c[name]
        if typ == "jsonb":
            value = sa.cast(value, sa.Text)
        elif typ == "double precision":
            value = sa.func.pg_catalog.encode(sa.func.pg_catalog.float8send(value), "hex")
        elif typ == "timestamp with time zone":
            value = sa.func.pg_catalog.encode(sa.func.pg_catalog.timestamptz_send(value), "hex")
        projection.append(value.label(name))
    rows, acks = [], []
    for record in connection.execute(sa.select(*projection).order_by(relation.c.id)).mappings():
        values = dict(record)
        for name, typ, _ in spec.columns:
            if typ == "jsonb" and values[name] is not None:
                values[name] = learning.JsonbText(values[name])
            elif typ == "double precision" and values[name] is not None:
                values[name] = learning.Float8Bits(values[name])
            elif typ == "timestamp with time zone":
                values[name] = _timestamp(values[name])
        if spec.name == "course_completions":
            acks.append(_CompletionAck(values["tenant_id"], values["id"], values.pop("erp_synced_at")))
        _require(set(values) == {f.name for f in fields(spec.row_type)})
        rows.append(spec.row_type(**values))
    return tuple(rows), tuple(acks)


def _check(connection, handle):
    _require(isinstance(connection, Connection))
    root = _connection_preflight(connection)
    state = connection.info.get(_STATE_KEY)
    _require(
        type(state) is _Captured and state.handle is handle and state.connection is connection and state.root is root
    )
    _require(type(handle) is _Capture)
    _require(connection.scalar(sa.text("SELECT pg_catalog.txid_current()::text")) == state.physical_xid)
    return state


@dataclass(frozen=True, slots=True, repr=False)
class _IdentityContinuity:
    capture: _Capture
    connection: Connection = field(repr=False)
    root: object = field(repr=False)
    expected: object = field(repr=False)
    receipt: object = field(repr=False)


def _check_relocation(connection, state, expected):
    oids = dict(state.oids)
    _require(expected.relations.tenants == oids["tenants"] and expected.relations.people == oids["people"])
    _require(set(expected.cohort.tenants) == set(state.tenants))
    _require(set(expected.cohort.people) == {person for _, person in state.people})
    _require(
        all(
            _oid(connection, name, "academy_identity_compat") == oids[name]
            for name in ("tenants", "people", "alembic_version")
        )
    )


def _observe_identity_relocation(connection: Connection, capture: _Capture) -> None:
    """Observe real private importer association BEFORE a003 receipt pops it.

    Call after actual identity import, before immediate post-a003 token receipt
    consumption. No receipt/namespace/verified flag is accepted from a caller.
    The observation survives that owner's documented disposal on this root.
    """
    try:
        state = _check(connection, capture)
        _require(connection.info.get(_RELOCATION_KEY) is None)
        issued = _identity_issued(connection)
        _require(issued is not None and issued.entry.connection is connection and issued.entry.root is state.root)
        _require(issued.entry.historical and issued.imported is not None)
        expected, receipt = issued.imported
        _require(receipt is not None)
        _check_relocation(connection, state, expected)
        connection.info[_RELOCATION_KEY] = _IdentityContinuity(capture, connection, state.root, expected, receipt)
        _verify_source(connection, capture)
    except Exception:
        raise LearningHistoryRefused(
            "Academy identity relocation observation refused; root rollback required"
        ) from None


def _identity_phase(connection, state):
    oids = dict(state.oids)
    names = ("tenants", "people", "alembic_version")
    continuity = connection.info.get(_RELOCATION_KEY)
    if all(_oid(connection, name) == oids[name] for name in names):
        _require(continuity is None)
        _require(all(_oid(connection, name, "academy_identity_compat") is None for name in names))
        return "public"
    _require(type(continuity) is _IdentityContinuity and continuity.capture is state.handle)
    _require(continuity.connection is connection and continuity.root is state.root)
    _check_relocation(connection, state, continuity.expected)
    issued = _identity_issued(connection)
    if issued is not None:
        _require(issued.entry.connection is connection and issued.entry.root is state.root)
        _require(
            issued.imported is not None
            and issued.imported[0] is continuity.expected
            and issued.imported[1] is continuity.receipt
        )
    return "academy_identity_compat"


def _verify_source(connection, handle):
    state = _check(connection, handle)
    _require(type(state.snapshot) is learning.LearningSnapshotV5)
    state.snapshot.__post_init__()
    _require(state.snapshot.tenant_ids == state.tenants)
    _require(_encoded_rows(state.snapshot, state.completion_acks) == state.raw_rows)
    phase = _identity_phase(connection, state)
    oids = dict(state.oids)
    _require(_roles(connection) == state.roles and _tenant_function(connection) == state.function)
    for name in _SOURCE_NAMES:
        _require(_oid(connection, name) == oids[name])
    _require(tuple((name, _captured_catalog(connection, name, oid)) for name, oid in state.oids) == state.catalogs)
    queries = {
        "public": (
            "SELECT id FROM public.tenants ORDER BY id",
            "SELECT tenant_id,id FROM public.people ORDER BY id",
            "SELECT version_num FROM public.alembic_version ORDER BY version_num",
        ),
        "academy_identity_compat": (
            "SELECT id FROM academy_identity_compat.tenants ORDER BY id",
            "SELECT tenant_id,id FROM academy_identity_compat.people ORDER BY id",
            "SELECT version_num FROM academy_identity_compat.alembic_version ORDER BY version_num",
        ),
    }[phase]
    _require(_query(connection, queries[0]) == tuple((tenant,) for tenant in state.tenants))
    _require(_query(connection, queries[1]) == state.people)
    _require(_query(connection, queries[2]) == (("0061_lab_completion_grants",),))
    _require(tuple((spec.name, _raw_projection(connection, spec)) for spec in _TABLES) == state.raw_rows)
    _check(connection, handle)
    return state


def _capture_learning_history(connection: Connection) -> _Capture:
    """Private coordinator boundary: fixed historical public source, never fresh.

    Precondition: external fence/drain + coordinator's full deterministic lock
    set. This subset LOCK is not permission to obtain later locks out of order.
    Capture BEFORE identity relocation; verify may follow the same held OIDs
    only when the existing actual private identity-import record proves it.
    """
    try:
        root = _connection_preflight(connection)
        physical_xid = connection.scalar(sa.text("SELECT pg_catalog.txid_current()::text"))
        previous = connection.info.get(_STATE_KEY)
        if previous is not None and previous.root is not root and not previous.root.is_active:
            del connection.info[_STATE_KEY]
            connection.info.pop(_RELOCATION_KEY, None)
        _require(connection.info.get(_STATE_KEY) is None)
        _require(all(_oid(connection, name) is not None for name in _LOCK_NAMES))
        _require(
            all(
                _oid(connection, name, "academy_identity_compat") is None
                for name in ("tenants", "people", "alembic_version")
            )
        )
        connection.execute(
            sa.text(
                "LOCK TABLE " + ",".join('public."' + name + '"' for name in _LOCK_NAMES) + " IN ACCESS EXCLUSIVE MODE"
            )
        )
        _require(
            _query(connection, "SELECT version_num FROM public.alembic_version ORDER BY version_num")
            == (("0061_lab_completion_grants",),)
        )
        roles = _roles(connection)
        role_ids = {row[1]: row[0] for row in roles[0]}
        oids = tuple((name, _oid(connection, name)) for name in _LOCK_NAMES)
        catalogs = tuple((name, _captured_catalog(connection, name, oid)) for name, oid in oids)
        by_name = dict(catalogs)
        for spec in _TABLES:
            _shape(connection, spec, by_name[spec.name], dict(oids), role_ids)
        _incoming_shape(connection, by_name, dict(oids))
        for name in ("tenants", "people"):
            catalog = by_name[name]
            _require(catalog.relation[1:3] == ("r", "app_admin"))
            columns = {r[1]: (r[2], r[3]) for r in catalog.columns}
            _require(columns.get("id") == ("uuid", True))
            if name == "people":
                _require(columns.get("tenant_id") == ("uuid", True))
            _require(
                connection.scalar(
                    sa.text(
                        "SELECT pg_catalog.has_table_privilege(current_user,:oid,'SELECT') AND "
                        "NOT pg_catalog.row_security_active(:oid)"
                    ),
                    {"oid": dict(oids)[name]},
                )
                is True
            )
        tenants = tuple(row[0] for row in _query(connection, "SELECT id FROM public.tenants ORDER BY id"))
        validate_tenant_extent(tenants)
        people = _query(connection, "SELECT tenant_id,id FROM public.people ORDER BY id")
        _require(all(t in tenants and type(p) is UUID for t, p in people))
        decoded, acks = {}, ()
        for spec in _TABLES:
            decoded[spec.name], extra = _decode(connection, spec)
            if spec.name == "course_completions":
                acks = extra
        snapshot = learning.LearningSnapshotV5(version=5, tenant_ids=tenants, **decoded)
        raw_rows = tuple((spec.name, _raw_projection(connection, spec)) for spec in _TABLES)
        _require(raw_rows == _encoded_rows(snapshot, acks))
        handle = object.__new__(_Capture)
        state = _Captured(
            handle,
            connection,
            root,
            physical_xid,
            oids,
            catalogs,
            roles,
            _tenant_function(connection),
            tenants,
            people,
            raw_rows,
            snapshot,
            acks,
        )
        connection.info[_STATE_KEY] = state
        _verify_source(connection, handle)
        return handle
    except Exception:
        raise LearningHistoryRefused("Academy Learning capture refused; root rollback required") from None


def _export_learning_history(connection: Connection, capture: _Capture) -> learning.LearningSnapshotV5:
    """Released V5 observation from privately captured full source; no DDL grant."""
    try:
        return _verify_source(connection, capture).snapshot
    except Exception:
        raise LearningHistoryRefused("Academy Learning export refused; root rollback required") from None


def _completion_ack_history(connection: Connection, capture: _Capture) -> tuple[_CompletionAck, ...]:
    """Every completion's product ACK, including NULL; not a checkpoint receipt."""
    try:
        return _verify_source(connection, capture).completion_acks
    except Exception:
        raise LearningHistoryRefused("Academy completion ACK observation refused; root rollback required") from None


def _verify_canonical_learning_history(connection: Connection, capture: _Capture) -> learning.VerificationObservationV5:
    """Observe independent released-owner canonical equality, not import/cutover."""
    try:
        state = _verify_source(connection, capture)
        observation = learning.verify_snapshot_v5(connection, state.snapshot)
        _verify_source(connection, capture)
        return observation
    except Exception:
        raise LearningHistoryRefused(
            "Academy canonical Learning verification refused; root rollback required"
        ) from None


def _release_learning_history(connection: Connection, capture: _Capture) -> None:
    """Drop private source/material references; never touch caller transaction."""
    state = connection.info.get(_STATE_KEY)
    _require(type(state) is _Captured and state.handle is capture and state.connection is connection)
    del connection.info[_STATE_KEY]
    connection.info.pop(_RELOCATION_KEY, None)


def _encoded_rows(snapshot, acks):
    """Compare DTO values against independent raw SQL, including separate ACKs."""
    ack_values = {(row.tenant_id, row.id): row.erp_synced_at for row in acks}
    _require(len(ack_values) == len(acks) == len(snapshot.course_completions))
    result = []
    epoch = datetime(2000, 1, 1, tzinfo=UTC)
    for spec in _TABLES:
        rows = []
        for row in getattr(snapshot, spec.name):
            values = []
            for name, typ, _ in sorted(spec.columns):
                value = ack_values[(row.tenant_id, row.id)] if name == "erp_synced_at" else getattr(row, name)
                if value is not None:
                    if typ == "jsonb":
                        value = str(value)
                    elif typ == "double precision":
                        value = value.hex
                    elif typ == "timestamp with time zone":
                        delta = value - epoch
                        value = struct.pack(
                            "!q", (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
                        ).hex()
                values.append(value)
            rows.append(tuple(values))
        result.append((spec.name, tuple(rows)))
    return tuple(result)


def _incoming_shape(connection, catalogs, oids):
    expected: dict[str, list[tuple[object, ...]]] = {name: [] for name in _SOURCE_NAMES}
    for spec in _TABLES:
        for (source, parent, target, delete), constraint_name in zip(
            spec.foreign_keys, _FOREIGN_KEY_NAMES[spec.name], strict=True
        ):
            if parent in expected:
                expected[parent].append(
                    (spec.name, constraint_name, source, target, delete, "a", "s", True, False, False)
                )
    # Actual retained applicants references at frozen0041/0052; no new FK facts.
    expected["cohort_tracks"].append(
        (
            "applicants",
            "fk_applicants_tenant_cohort_track",
            ("tenant_id", "cohort_id", "track_id"),
            ("tenant_id", "cohort_id", "track_id"),
            "a",
            "a",
            "s",
            True,
            False,
            False,
        )
    )
    expected["question_banks"].append(
        (
            "applicants",
            "fk_applicants_tenant_assessment_bank",
            ("tenant_id", "assessment_bank_id"),
            ("tenant_id", "id"),
            "a",
            "a",
            "s",
            True,
            False,
            False,
        )
    )
    for name in _SOURCE_NAMES:
        actual = []
        for (
            _,
            constraint_name,
            child_oid,
            source,
            target,
            delete,
            update,
            match,
            valid,
            deferrable,
            deferred,
        ) in catalogs[name].incoming:
            child = _query(
                connection,
                "SELECT n.nspname,c.relname FROM pg_catalog.pg_class c "
                "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=:oid",
                oid=child_oid,
            )
            _require(len(child) == 1 and child[0][0] == "public")
            actual.append(
                (
                    child[0][1],
                    constraint_name,
                    _column_names(connection, child_oid, source),
                    _column_names(connection, oids[name], target),
                    delete,
                    update,
                    match,
                    valid,
                    deferrable,
                    deferred,
                )
            )
        _require(sorted(actual) == sorted(expected[name]))


def _captured_catalog(connection, name, oid):
    catalog = _catalog(connection, oid)
    if name not in {"tenants", "people"}:
        return catalog
    # Reference parents are owned by identity, not Learning. Their incoming
    # token/retained FKs and associated internal RI triggers change in a003/a004;
    # the actual private identity/token/whole-product coordinator owns them.
    # Every Learning source table retains its FULL incoming catalog above.
    own_constraints = {
        row[0] for row in _query(connection, "SELECT oid FROM pg_catalog.pg_constraint WHERE conrelid=:oid", oid=oid)
    }
    return replace(
        catalog, incoming=(), triggers=tuple(row for row in catalog.triggers if not row[5] or row[6] in own_constraints)
    )
