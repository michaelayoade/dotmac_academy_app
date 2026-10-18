"""Private historical retained-schema contract; no DDL or adoption authority.

Pins derive from the genuine a5/096 frozen 62-file chain through 0061.
PostgreSQL16 rendering pins remain candidate; full qualification is unsupported;
this source slice never issues a successful admission proof or product receipt.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.engine import Connection


class RetainedSchemaRefused(RuntimeError):
    """Fixed historical semantics or actual security authority did not match."""


class RetainedSchemaUnsupported(RetainedSchemaRefused):
    """Source matches inspected structure; hosted expression qualification owed."""


def _require(condition):
    if not condition:
        raise RetainedSchemaRefused("Historical retained schema refused; root rollback required")


# Fixed schema defaults below are frozen DDL, never new application configuration.
# Tuples: name, PostgreSQL type, nullable, PostgreSQL default expression.
_COLUMNS = (
    (
        "applicants",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("email", "character varying(254)", False, None),
            ("first_name", "character varying(80)", False, None),
            ("last_name", "character varying(80)", False, None),
            ("phone", "character varying(40)", True, None),
            ("program", "character varying(120)", True, None),
            ("status", "character varying(20)", False, "'applied'::character varying"),
            ("source", "character varying(30)", False, "'website'::character varying"),
            ("external_ref", "character varying(64)", True, None),
            ("notes", "character varying(1000)", True, None),
            ("applied_on", "date", False, "CURRENT_DATE"),
            ("person_id", "uuid", True, None),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
            ("cohort_id", "uuid", True, None),
            ("assessment_score", "double precision", True, None),
            ("assessment_level", "character varying(20)", True, None),
            ("assessment_profile", "jsonb", True, None),
            ("assessment_taken_at", "timestamp with time zone", True, None),
            ("assessment_token_hash", "character varying(128)", True, None),
            ("assessment_started_at", "timestamp with time zone", True, None),
            ("assessment_time_exceeded", "boolean", False, "false"),
            ("assessment_answers", "jsonb", True, None),
            ("assessment_valid", "boolean", True, None),
            ("assessment_invalid_reason", "character varying(40)", True, None),
            ("assessment_reset_count", "integer", False, "0"),
            ("date_of_birth", "date", True, None),
            ("state", "character varying(60)", True, None),
            ("city", "character varying(60)", True, None),
            ("highest_qualification", "character varying(60)", True, None),
            ("field_of_study", "character varying(120)", True, None),
            ("years_experience", "integer", True, None),
            ("current_role", "character varying(120)", True, None),
            ("has_device", "boolean", True, None),
            ("has_internet", "boolean", True, None),
            ("can_work_at_height", "boolean", True, None),
            ("available_from", "date", True, None),
            ("heard_from", "character varying(60)", True, None),
            ("cv_url", "character varying(500)", True, None),
            ("assessment_deadline", "timestamp with time zone", True, None),
            ("invite_sent_at", "timestamp with time zone", True, None),
            ("assessment_elapsed_seconds", "integer", False, "0"),
            ("onboarding_token_hash", "character varying(128)", True, None),
            ("track_id", "uuid", True, None),
            ("assessment_bank_id", "uuid", True, None),
            ("assessment_return_url", "character varying(2048)", True, None),
            ("assessment_erp_synced_at", "timestamp with time zone", True, None),
            ("assessment_result_version", "integer", False, "0"),
        ),
    ),
    (
        "email_outbox",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("idempotency_key", "character varying(200)", False, None),
            ("kind", "character varying(60)", False, "'generic'::character varying"),
            ("recipient", "character varying(254)", False, None),
            ("subject", "character varying(300)", False, None),
            ("html_body", "text", False, None),
            ("text_body", "text", True, None),
            ("payload", "jsonb", False, "'{}'::jsonb"),
            ("status", "character varying(20)", False, "'pending'::character varying"),
            ("attempts", "integer", False, "0"),
            ("available_at", "timestamp with time zone", False, "now()"),
            ("sent_at", "timestamp with time zone", True, None),
            ("last_error", "character varying(120)", True, None),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
        ),
    ),
    (
        "lab_instances",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("activity_id", "uuid", False, None),
            ("person_id", "uuid", False, None),
            ("instance_name", "character varying(120)", False, None),
            ("seed", "jsonb", False, "'{}'::jsonb"),
            ("status", "character varying(16)", False, "'queued'::character varying"),
            ("consoles", "jsonb", False, "'{}'::jsonb"),
            ("error", "text", True, None),
            ("started_at", "timestamp with time zone", True, None),
            ("last_active_at", "timestamp with time zone", True, None),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
            ("runtime_presence", "character varying(16)", False, "'absent'::character varying"),
        ),
    ),
    (
        "lab_operations",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("instance_id", "uuid", False, None),
            ("kind", "character varying(16)", False, None),
            ("state", "character varying(16)", False, "'queued'::character varying"),
            ("requested_by", "uuid", True, None),
            ("requested_at", "timestamp with time zone", False, "now()"),
            ("not_before", "timestamp with time zone", False, "now()"),
            ("claimed_by", "character varying(200)", True, None),
            ("claimed_at", "timestamp with time zone", True, None),
            ("heartbeat_at", "timestamp with time zone", True, None),
            ("attempts", "integer", False, "0"),
            ("finished_at", "timestamp with time zone", True, None),
            ("last_error", "text", True, None),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
            ("claimed_host", "character varying(255)", True, None),
            ("claimed_epoch", "character varying(64)", True, None),
            ("origin", "character varying(32)", True, None),
            ("runtime_precondition", "character varying(16)", True, None),
        ),
    ),
    (
        "lab_templates",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("course_id", "uuid", False, None),
            ("chapter_number", "integer", True, None),
            ("activity_id", "uuid", False, None),
            ("slug", "character varying(63)", False, None),
            ("title", "character varying(200)", False, None),
            ("topology", "text", False, "''::text"),
            ("instructions_html", "text", False, "''::text"),
            ("checks", "jsonb", False, "'[]'::jsonb"),
            ("seed_spec", "jsonb", False, "'{}'::jsonb"),
            ("limits", "jsonb", False, "'{}'::jsonb"),
            ("engine", "character varying(20)", False, "'containerlab'::character varying"),
            ("source_hash", "character varying(64)", False, "''::character varying"),
            ("version", "integer", False, "1"),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
            ("instructions_md", "text", True, None),
        ),
    ),
    (
        "notifications",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("person_id", "uuid", False, None),
            ("kind", "character varying(40)", False, None),
            ("title", "character varying(200)", False, None),
            ("body", "text", False, "''::text"),
            ("link", "character varying(255)", True, None),
            ("read_at", "timestamp with time zone", True, None),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
        ),
    ),
    (
        "onboarding_tasks",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("applicant_id", "uuid", False, None),
            ("key", "character varying(40)", False, None),
            ("label", "character varying(200)", False, None),
            ("order_index", "integer", False, "0"),
            ("status", "character varying(10)", False, "'pending'::character varying"),
            ("completed_at", "timestamp with time zone", True, None),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
        ),
    ),
    ("platform_settings", (("key", "character varying(80)", False, None), ("value", "text", True, None))),
    (
        "reminder_log",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("person_id", "uuid", False, None),
            ("event_kind", "character varying(30)", False, None),
            ("occurrence_key", "character varying(160)", False, None),
            ("title", "character varying(240)", False, "''::character varying"),
            ("link", "character varying(300)", True, None),
            ("channel", "character varying(20)", False, "'email'::character varying"),
            ("status", "character varying(20)", False, "'queued'::character varying"),
            ("outbox_key", "character varying(200)", True, None),
            ("sent_at", "timestamp with time zone", True, None),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
        ),
    ),
    (
        "reminder_preferences",
        (
            ("id", "uuid", False, None),
            ("tenant_id", "uuid", False, None),
            ("person_id", "uuid", False, None),
            ("frequency", "character varying(20)", False, "'immediate'::character varying"),
            ("quiet_start_hour", "integer", True, None),
            ("quiet_end_hour", "integer", True, None),
            ("optouts", "jsonb", False, "'[]'::jsonb"),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
        ),
    ),
    (
        "tenant_entrance_defaults",
        (
            ("tenant_id", "uuid", False, None),
            ("default_bank_id", "uuid", True, None),
            ("default_time_limit_minutes", "integer", True, None),
            ("created_at", "timestamp with time zone", False, "now()"),
            ("updated_at", "timestamp with time zone", False, "now()"),
        ),
    ),
)
_NAMES = tuple(name for name, _ in _COLUMNS)
_COLUMN_MAP = dict(_COLUMNS)

_FROZEN62 = (
    ("0005_labs.py", 3933, "1febeebbae42ab1aa66f6e0a3648fc5b84b53d53644ef7e19a7779b0bb2e8404"),
    ("0006_platform_settings.py", 1136, "638f6cbf8e210aee9e56f95740fec16c32d5bea4d5280beac8ca32c7f73d10d9"),
    ("0007_person_profile.py", 984, "5ba2d46aa152ce4531289fcdfe500a1de5195d606fab6d480bb258e1efd2b40a"),
    ("0008_course_offerings.py", 3270, "e818b9f05c60067b25999a9a3494aa4d7d26ea3a8cebcc598c0851aaaeedd548"),
    ("0009_offering_window.py", 770, "4376d5c7b121e84ef671829a0293de3e95d6ea6772dbbdb9f7303bf39f632772"),
    ("0010_course_completions.py", 2420, "71a5685aaee0de29b84b10c4b915cae9a28b81d896b2514c6d53232b9c5d497b"),
    ("0011_certificates.py", 2268, "971d76b1e8ba215153639992f0e4f065ef39205bfeae84137786d631d256921f"),
    ("0012_offering_activities.py", 2561, "b3980420b3b5bdbedf497f4725f3081c551decf3437ea224e52031fab90610d0"),
    ("0013_course_prerequisites.py", 2430, "76150f830515a1e75f3e355364fd9f5c49e33d08218b0be14a349d775c611af8"),
    ("0014_account_tokens.py", 2267, "bbe1d5ab93f59424b8183b997ad1541eaaeb161f776f1ca8b6ec2e4559536996"),
    ("0015_person_status.py", 502, "f3157118ce9e4dfbe85fa6141f9dc3d9e900552a90d81af168e11ee48d6479c8"),
    ("0016_activity_max_attempts.py", 464, "7c26ff37a40b81f662a49c6788bfbdf1889e4cd2b8de7f86eff57e457c44f2bd"),
    ("0017_activity_grading.py", 504, "7623567feb5649b0655977ff9bcab51f5386f453839989110a1d079d928aca03"),
    ("0018_course_status.py", 556, "c0e34afcfd3498b9a54db72386d6ca0d08fc91266218bc0612c64291452dc911"),
    ("0019_chapter_body_md.py", 467, "269908422fbe6e9c520ec3f3593b911065dc0912a4c831266d4a189bc1a0d152"),
    ("0020_activity_attempts.py", 2498, "81adde48bcd94469ecb02300d714c11b778a51cf4fdb3988b4336ced9824325f"),
    ("0020_notifications.py", 2287, "f3bf479ae08977b1b38286fa5b0b143dd394d13f298c39494a031a5a25c40f33"),
    ("0021_announcements.py", 2475, "0b77f7ebb01d2eba8fb10ad25c94a40d280b6b07ad210594cba49fe697528c7e"),
    ("0022_activity_weight.py", 423, "9abfce03c6dbbc9ba2f0206a560ba864be0bfc8da1c6e04259a737fcdc9c47dc"),
    ("0023_merge_gaps_attempts_heads.py", 597, "47e10f287a34d7e2af369deaf8863f3468ac8e8875c19e03faad7eefa470932b"),
    ("0024_chapter_reads.py", 1970, "0d187a865509021e2152e1c06ff5ef6e9a47e4c1400874718870de542d9a7bee"),
    ("0025_admissions.py", 2988, "e8e5ab8015b353f67b6d4e9324cfb054d4c6498f8b58ef8f1c633e2da55c63a7"),
    ("0026_class_sessions.py", 3201, "5a41c425aa7c3064432d43db5ce1bea9fc39874816af60fcc01715e18357e82b"),
    ("0027_assessment_mode.py", 721, "7981defee43ef9398d36d64e02f69b675aa3657e73a2b7d5ae22e61d31082726"),
    ("0028_onboarding_tasks.py", 2812, "8f07415391080426dd6f645cbcb9d1a7f3dc89d683f7cd432257860017823a78"),
    ("0029_completion_erp_synced.py", 517, "b81a71ef6378ae84a7135f4c0d21f532230b3546d3dc9f3b5b9df2a16bb9c436"),
    ("0030_entrance_assessment.py", 1715, "a4eb78a5115b18711506cb6db722c31e9c60b0875dd776e76e5ed7c367c1b580"),
    ("0031_applicant_assessment_token.py", 502, "300e85d6eee504a76afd4aa1a321b4fb732766c69a7c4219b0a2c6627e60d38c"),
    ("0032_entrance_timer.py", 887, "54e3794198ff270344a858d8a0a012038e841768765f9ce8105a85a5981e879b"),
    ("0033_tenant_default_entrance.py", 733, "e00d7d823b9c4843b1b3e7e3ec6174b1785e88bcd3ae4b0f6ef63a9bd97c875e"),
    ("0036_tracks.py", 7418, "1c8297a03559f09f8ddda42b21255587276a36f933f13d0bff2913ced053be2a"),
    ("0037_pause_entrance_timer.py", 585, "f44ee8eb3b5e1fa408acc21a120a3c71d6b24391b136f9019cf4f52b59973bec"),
    ("0038_onboarding_token.py", 497, "def53e06c77a7e64d06a0b2d9d7dfde9a802104edab3142b6482f2de586a9424"),
    ("0039_auto_accept_threshold.py", 487, "3729acc0356709216c2f92983ea350a45b356b13970a172eef308dce430446da"),
    ("0040_merge_tracks_admissions.py", 561, "bf2090ebe86706087c17a3a2bdc903c284b97545aa751fcbbe8d6b63e9eb9182"),
    ("0041_review_remediation.py", 7663, "04f1566ea2ab508eea96207652917a3b6ce5d278f7cefc4f99f94224a0b93060"),
    ("0042_course_listed.py", 1196, "3def18d99d255ab0cd13adb66c5eb6023e1ae061ad0fedc47c74ed46199eb68e"),
    ("0043_bookmarks_notes.py", 2324, "07515bb75f3d652b0b3029c560b2edcfc5fc72c3ce42bb825cc74084db3cc546"),
    ("0044_reminders.py", 3898, "04d7532c390e95c4d88d0ebf69fe92d681450b643d94d131e4f55768bf3153e3"),
    ("0045_learning_events.py", 2761, "870e0345e74481a4451d487afdcf7e40abc2b10ba3e114a68089448b3ef5d570"),
    ("0046_success_queue.py", 3611, "25d94ccc54d14ff95861345d0b15a20e6823b03b1899b40d2a57d14490809199"),
    ("0047_learning_event_dedup.py", 1208, "4f06d99be151b6a97d47951e85e06176c6dc4ab54df4c69c8e9aece8a2751dd8"),
    ("0048_subtopic_reads.py", 2181, "218a2e066370724baca846429f3ce89d7723f9d0cba9e0b3883bac25ce5721d5"),
    ("0049_enrollment_audience.py", 1856, "211b36f1b8055304c2aa84f2c3c37856011a0447211754ca3eb555c5d30456f7"),
    ("0050_enrollment_access_extension.py", 729, "589c23d4078e5ee08476614987eb2a82fa1b23ef66954712ad07b723388ca577"),
    ("0051_attempt_grants.py", 2952, "bb787257721d4521d71b8823e2ffcdf142035c6269a2550f0e8e9865c8482338"),
    ("0052_erp_applicant_assessments.py", 2627, "e7c67dbcc7ff2dc6eb59d2334f3a3c73eda89478bc7733cdb1bcfa46a1da1d9a"),
    ("0053_entrance_defaults_table.py", 3923, "d9a77e4084e5fbf68d74b61b278738396b3b1156ec8720cbe3976bdb4242f71d"),
    ("0054_lab_instructions_md.py", 2031, "ce94d46eab8f7a0b5ce8e109291a66ca964fa9fe71418080e6721ffd92276bf5"),
    ("0055_lab_operations.py", 6946, "5f1befb9f90c0db8fe3944c545e5802dd8eeb21eea9b55868311a835833905c5"),
    ("0056_lab_instance_worker_grants.py", 6243, "fd75319dd804b8f0a388d0fde8f164421503d8e26b695c1c4459bed519e52aa7"),
    ("0057_lab_instance_name_unique.py", 4118, "a62e6765da087bff95c0f23431ef3e6b11a6eca9bde45c357b2ac644175bc849"),
    ("0058_lab_runtime_presence.py", 10723, "90b055ad7a308bb2a4f4413e54d1d73e4ab97fe8da41c07f59c1bd0d76fe6e49"),
    ("0059_lab_claim_owner.py", 6926, "a1d08823ab75bc8049dc86e1738fb52ae25b71e43f5f3d48b4134bdfa9810f1e"),
    ("0060_lab_conditional_ops.py", 12881, "a9d670de50e1c9d8d0048edcf6c98524372fe6b562e27278a3bf37612daa5937"),
    ("0061_lab_completion_grants.py", 1588, "e2da178268685378e46239391f0455cfb3937f1ee632254d9baf0600d31b3f65"),
    (
        "20260504_0001_initial_tenant_schema.py",
        15464,
        "33f9569bccc1562a2973df75e597332bb13b3003bab4d1815943e6cbee3eba3e",
    ),
    ("20260626_0002_courses.py", 3080, "89eae42c361a70b81bd2416b9c1338072b4be67788e6dfe76137e12f31fb53ca"),
    ("20260626_0003_cohorts.py", 2851, "eb479ff244a1d5b65f395a6c1f188c079a0f0e9db3f72e4d6dc253cb82cd06bb"),
    ("20260626_0004_assessment.py", 6540, "a118b1658abced245f04994afc0989ead3c203dc93c71a48d99bfd5c2008b5eb"),
    ("20260711_0034_entrance_resilience.py", 1860, "0b14733170a5c9cb84edb6be6e1c57e703851537f6447aa173bd2046e80b2554"),
    ("20260711_0035_applicant_profile.py", 2280, "d6bcfc0f7932cdb1aa8df3f2608e3a4911e32673512da3e3ea2533ed7d82fdc0"),
)

_DDL_LINEAGE = (
    "0005_labs.py",
    "0006_platform_settings.py",
    "0020_notifications.py",
    "0025_admissions.py",
    "0028_onboarding_tasks.py",
    "0030_entrance_assessment.py",
    "0031_applicant_assessment_token.py",
    "0032_entrance_timer.py",
    "0037_pause_entrance_timer.py",
    "0038_onboarding_token.py",
    "0041_review_remediation.py",
    "0044_reminders.py",
    "0052_erp_applicant_assessments.py",
    "0053_entrance_defaults_table.py",
    "0054_lab_instructions_md.py",
    "0055_lab_operations.py",
    "0056_lab_instance_worker_grants.py",
    "0057_lab_instance_name_unique.py",
    "0058_lab_runtime_presence.py",
    "0059_lab_claim_owner.py",
    "0060_lab_conditional_ops.py",
    "20260711_0034_entrance_resilience.py",
    "20260711_0035_applicant_profile.py",
)

# name, constraint kind, ordered columns; all nondeferrable and validated.
_KEYS = (
    ("applicants", (("applicants_pkey", "p", ("id",)), ("uq_applicants_tenant_id_id", "u", ("tenant_id", "id")))),
    (
        "email_outbox",
        (
            ("email_outbox_pkey", "p", ("id",)),
            ("uq_email_outbox_idempotency", "u", ("tenant_id", "idempotency_key")),
            ("uq_email_outbox_tenant_id_id", "u", ("tenant_id", "id")),
        ),
    ),
    (
        "lab_instances",
        (("lab_instances_pkey", "p", ("id",)), ("uq_lab_instances_tenant_id_id", "u", ("tenant_id", "id"))),
    ),
    ("lab_operations", (("lab_operations_pkey", "p", ("id",)),)),
    (
        "lab_templates",
        (
            ("lab_templates_pkey", "p", ("id",)),
            ("uq_lab_templates_activity_id", "u", ("activity_id",)),
            ("uq_lab_templates_tenant_id_id", "u", ("tenant_id", "id")),
        ),
    ),
    (
        "notifications",
        (("notifications_pkey", "p", ("id",)), ("uq_notifications_tenant_id_id", "u", ("tenant_id", "id"))),
    ),
    (
        "onboarding_tasks",
        (
            ("onboarding_tasks_pkey", "p", ("id",)),
            ("uq_onboarding_tasks_applicant_key", "u", ("tenant_id", "applicant_id", "key")),
        ),
    ),
    ("platform_settings", (("platform_settings_pkey", "p", ("key",)),)),
    (
        "reminder_log",
        (
            ("reminder_log_pkey", "p", ("id",)),
            ("uq_reminder_log_occurrence", "u", ("tenant_id", "person_id", "occurrence_key")),
        ),
    ),
    (
        "reminder_preferences",
        (
            ("reminder_preferences_pkey", "p", ("id",)),
            ("uq_reminder_preferences_person", "u", ("tenant_id", "person_id")),
        ),
    ),
    ("tenant_entrance_defaults", (("tenant_entrance_defaults_pkey", "p", ("tenant_id",)),)),
)

# name, source columns, historical public target, target columns, delete action.
_FOREIGN_KEYS = (
    (
        "applicants",
        (
            ("applicants_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),
            (
                "fk_applicants_tenant_assessment_bank",
                ("tenant_id", "assessment_bank_id"),
                "question_banks",
                ("tenant_id", "id"),
                "NO ACTION",
            ),
            (
                "fk_applicants_tenant_cohort_track",
                ("tenant_id", "cohort_id", "track_id"),
                "cohort_tracks",
                ("tenant_id", "cohort_id", "track_id"),
                "NO ACTION",
            ),
        ),
    ),
    ("email_outbox", (("email_outbox_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),)),
    ("lab_instances", (("lab_instances_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),)),
    (
        "lab_operations",
        (
            (
                "fk_lab_operations_tenant_instance",
                ("tenant_id", "instance_id"),
                "lab_instances",
                ("tenant_id", "id"),
                "CASCADE",
            ),
            ("lab_operations_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),
        ),
    ),
    ("lab_templates", (("lab_templates_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),)),
    (
        "notifications",
        (
            ("fk_notifications_tenant_person", ("tenant_id", "person_id"), "people", ("tenant_id", "id"), "CASCADE"),
            ("notifications_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),
        ),
    ),
    (
        "onboarding_tasks",
        (
            (
                "fk_onboarding_tasks_tenant_applicant",
                ("tenant_id", "applicant_id"),
                "applicants",
                ("tenant_id", "id"),
                "CASCADE",
            ),
            ("onboarding_tasks_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),
        ),
    ),
    ("platform_settings", ()),
    (
        "reminder_log",
        (
            ("fk_reminder_log_tenant_person", ("tenant_id", "person_id"), "people", ("tenant_id", "id"), "CASCADE"),
            ("reminder_log_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),
        ),
    ),
    (
        "reminder_preferences",
        (
            (
                "fk_reminder_preferences_tenant_person",
                ("tenant_id", "person_id"),
                "people",
                ("tenant_id", "id"),
                "CASCADE",
            ),
            ("reminder_preferences_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),
        ),
    ),
    (
        "tenant_entrance_defaults",
        (("tenant_entrance_defaults_tenant_id_fkey", ("tenant_id",), "tenants", ("id",), "CASCADE"),),
    ),
)

# name, ordered keys, unique, primary, source predicate (not a rendered PG pin).
_INDEXES = (
    (
        "applicants",
        (
            ("applicants_pkey", ("id",), True, True, None),
            ("ix_applicants_assessment_bank_id", ("assessment_bank_id",), False, False, None),
            ("ix_applicants_status", ("tenant_id", "status"), False, False, None),
            ("ix_applicants_tenant_id", ("tenant_id",), False, False, None),
            ("ix_applicants_track_id", ("track_id",), False, False, None),
            (
                "uq_applicants_tenant_external_ref",
                ("tenant_id", "external_ref"),
                True,
                False,
                "external_ref IS NOT NULL",
            ),
            ("uq_applicants_tenant_id_id", ("tenant_id", "id"), True, False, None),
            ("uq_applicants_tenant_local_email", ("tenant_id", "email"), True, False, "external_ref IS NULL"),
        ),
    ),
    (
        "email_outbox",
        (
            ("email_outbox_pkey", ("id",), True, True, None),
            ("ix_email_outbox_status", ("status",), False, False, None),
            ("ix_email_outbox_tenant_id", ("tenant_id",), False, False, None),
            ("uq_email_outbox_idempotency", ("tenant_id", "idempotency_key"), True, False, None),
            ("uq_email_outbox_tenant_id_id", ("tenant_id", "id"), True, False, None),
        ),
    ),
    (
        "lab_instances",
        (
            ("ix_lab_instances_activity_id", ("activity_id",), False, False, None),
            ("ix_lab_instances_person_id", ("person_id",), False, False, None),
            ("ix_lab_instances_tenant_id", ("tenant_id",), False, False, None),
            ("lab_instances_pkey", ("id",), True, True, None),
            ("uq_lab_instances_instance_name", ("instance_name",), True, False, None),
            ("uq_lab_instances_tenant_id_id", ("tenant_id", "id"), True, False, None),
        ),
    ),
    (
        "lab_operations",
        (
            ("ix_lab_operations_claim", ("state", "not_before", "requested_at"), False, False, None),
            ("ix_lab_operations_tenant_id", ("tenant_id",), False, False, None),
            ("lab_operations_pkey", ("id",), True, True, None),
            ("uq_lab_operations_open_per_instance", ("instance_id",), True, False, "state IN ('queued', 'claimed')"),
        ),
    ),
    (
        "lab_templates",
        (
            ("ix_lab_templates_activity_id", ("activity_id",), False, False, None),
            ("ix_lab_templates_course_id", ("course_id",), False, False, None),
            ("ix_lab_templates_tenant_id", ("tenant_id",), False, False, None),
            ("lab_templates_pkey", ("id",), True, True, None),
            ("uq_lab_templates_activity_id", ("activity_id",), True, False, None),
            ("uq_lab_templates_tenant_id_id", ("tenant_id", "id"), True, False, None),
        ),
    ),
    (
        "notifications",
        (
            ("ix_notifications_person_id", ("person_id",), False, False, None),
            ("ix_notifications_tenant_id", ("tenant_id",), False, False, None),
            ("notifications_pkey", ("id",), True, True, None),
            ("uq_notifications_tenant_id_id", ("tenant_id", "id"), True, False, None),
        ),
    ),
    (
        "onboarding_tasks",
        (
            ("ix_onboarding_tasks_applicant", ("tenant_id", "applicant_id"), False, False, None),
            ("ix_onboarding_tasks_tenant_id", ("tenant_id",), False, False, None),
            ("onboarding_tasks_pkey", ("id",), True, True, None),
            ("uq_onboarding_tasks_applicant_key", ("tenant_id", "applicant_id", "key"), True, False, None),
        ),
    ),
    ("platform_settings", (("platform_settings_pkey", ("key",), True, True, None),)),
    (
        "reminder_log",
        (
            ("ix_reminder_log_event_kind", ("event_kind",), False, False, None),
            ("ix_reminder_log_person_id", ("person_id",), False, False, None),
            ("ix_reminder_log_status", ("status",), False, False, None),
            ("ix_reminder_log_tenant_id", ("tenant_id",), False, False, None),
            ("reminder_log_pkey", ("id",), True, True, None),
            ("uq_reminder_log_occurrence", ("tenant_id", "person_id", "occurrence_key"), True, False, None),
        ),
    ),
    (
        "reminder_preferences",
        (
            ("ix_reminder_preferences_person_id", ("person_id",), False, False, None),
            ("ix_reminder_preferences_tenant_id", ("tenant_id",), False, False, None),
            ("reminder_preferences_pkey", ("id",), True, True, None),
            ("uq_reminder_preferences_person", ("tenant_id", "person_id"), True, False, None),
        ),
    ),
    ("tenant_entrance_defaults", (("tenant_entrance_defaults_pkey", ("tenant_id",), True, True, None),)),
)

# Source expressions deliberately retained as source, not guessed PG renderings.
_CHECKS = (
    ("lab_instances", "ck_lab_instances_runtime_presence", "runtime_presence IN ('absent', 'present', 'unknown')"),
    ("lab_operations", "ck_lab_operations_kind", "kind IN ('deploy', 'destroy', 'check')"),
    ("lab_operations", "ck_lab_operations_state", "state IN ('queued', 'claimed', 'succeeded', 'failed', 'cancelled')"),
    (
        "lab_operations",
        "ck_lab_operations_conditional_runtime",
        "(origin IS NULL AND runtime_precondition IS NULL) "
        "OR (kind = 'deploy' AND origin IS NOT NULL AND origin = 'runtime_repair' "
        "AND runtime_precondition IS NOT NULL AND runtime_precondition = 'absent') "
        "OR (kind = 'destroy' AND origin IS NOT NULL AND origin = 'runtime_cleanup' "
        "AND runtime_precondition IS NOT NULL AND runtime_precondition = 'present')",
    ),
)
_ROLES = ("app_admin", "app_user", "platform_api", "academy_lab_worker")
_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
_COLUMN_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "REFERENCES")
_REQUEST_COLUMNS = (
    ("lab_instances", ("id", "tenant_id", "activity_id", "person_id", "instance_name", "seed")),
    ("lab_operations", ("id", "tenant_id", "instance_id", "kind", "requested_by")),
)
_RENDERING_GATE = (
    "frozen62_pg16_rendering_pins_and_context_hosted_qualification",
    "frozen62_pg_policy_function_dependencies",
    "frozen62_effective_cluster_authority_qualification",
)


# Candidate PostgreSQL16 deparser pins, derived from frozen DDL plus the
# independently source-bound full62 Genesis replay. Not a target/live baseline.
# Casts, parentheses, enum order and NULL guards are intentionally exact.
_CHECK_RENDERINGS = (
    (
        "lab_instances",
        "ck_lab_instances_runtime_presence",
        "((runtime_presence)::text = ANY ((ARRAY['absent'::character varying, 'present'::character varying, "
        "'unknown'::character varying])::text[]))",
    ),
    (
        "lab_operations",
        "ck_lab_operations_conditional_runtime",
        "(((origin IS NULL) AND (runtime_precondition IS NULL)) OR (((kind)::text = 'deploy'::text) AND (origin IS NOT "
        "NULL) AND ((origin)::text = 'runtime_repair'::text) AND (runtime_precondition IS NOT NULL) AND "
        "((runtime_precondition)::text = 'absent'::text)) OR (((kind)::text = 'destroy'::text) "
        "AND (origin IS NOT NULL) "
        "AND ((origin)::text = 'runtime_cleanup'::text) AND (runtime_precondition IS NOT NULL) AND "
        "((runtime_precondition)::text = 'present'::text)))",
    ),
    (
        "lab_operations",
        "ck_lab_operations_kind",
        "((kind)::text = ANY ((ARRAY['deploy'::character varying, 'destroy'::character varying, 'check'::character "
        "varying])::text[]))",
    ),
    (
        "lab_operations",
        "ck_lab_operations_state",
        "((state)::text = ANY ((ARRAY['queued'::character varying, 'claimed'::character varying, "
        "'succeeded'::character "
        "varying, 'failed'::character varying, 'cancelled'::character varying])::text[]))",
    ),
)
_PARTIAL_PREDICATE_RENDERINGS = (
    ("applicants", "uq_applicants_tenant_external_ref", "(external_ref IS NOT NULL)"),
    ("applicants", "uq_applicants_tenant_local_email", "(external_ref IS NULL)"),
    (
        "lab_operations",
        "uq_lab_operations_open_per_instance",
        "((state)::text = ANY ((ARRAY['queued'::character varying, 'claimed'::character varying])::text[]))",
    ),
)
# Default opclasses are type-derived from PG16 builtin definitions. No OID pins.
_BTREE_TYPE_OPCLASSES = (
    ("uuid", "pg_catalog.uuid_ops"),
    ("timestamp with time zone", "pg_catalog.timestamptz_ops"),
    ("text", "pg_catalog.text_ops"),
    ("character varying", "pg_catalog.text_ops"),
)


def _check_rendering_context(packet):
    """Candidate deparser context only; never deployment/security approval."""
    context = packet.get("rendering_context", ())
    if len(context) != 1:
        raise RetainedSchemaUnsupported("Historical retained rendering context unsupported")
    row = context[0]
    if not (
        len(row) == 6
        and type(row[0]) is int
        and 160000 <= row[0] < 170000
        and row[2:] == ('"$user", public', ("pg_catalog", "public"), "off", "on")
    ):
        raise RetainedSchemaUnsupported("Historical retained rendering context unsupported")


def _column_collation(sql_type):
    return (
        ("pg_catalog", "default") if sql_type == "text" or sql_type.startswith("character varying(") else (None, None)
    )


def _expected_index_semantics(table, columns):
    types = {name: sql_type for name, sql_type, _, _ in _COLUMN_MAP[table]}
    classes = dict(_BTREE_TYPE_OPCLASSES)
    opclasses: list[str] = []
    collations: list[str | None] = []
    for column in columns:
        sql_type = types[column]
        base_type = "character varying" if sql_type.startswith("character varying(") else sql_type
        opclass = classes.get(base_type)
        if opclass is None:
            raise RetainedSchemaUnsupported("Historical retained index type unsupported")
        opclasses.append(opclass)
        namespace, name = _column_collation(sql_type)
        collations.append(None if namespace is None else namespace + "." + name)
    return tuple(opclasses), tuple(collations)


def _rows(connection, sql, **params):
    return tuple(
        tuple(tuple(v) if isinstance(v, list) else v for v in row)
        for row in connection.execute(sa.text(sql), params).tuples()
    )


def _preflight(connection):
    _require(isinstance(connection, Connection))
    _require(not connection.closed and not connection.invalidated)
    root = connection.get_transaction()
    _require(root is not None and root.is_active and not connection.in_nested_transaction())
    _require(connection.dialect.name == "postgresql" and connection.dialect.driver == "psycopg")
    _require(connection.connection.driver_connection.autocommit is False)
    _require(connection.engine.hide_parameters is True and connection.engine.echo is False)
    _require(not connection.engine.logger.isEnabledFor(logging.DEBUG))
    _require(connection.get_execution_options().get("isolation_level") != "AUTOCOMMIT")
    _require(connection.scalar(sa.text("SELECT current_user")) == "app_admin")
    if connection.scalar(sa.text("SELECT current_setting('search_path')")) != '"$user", public':
        raise RetainedSchemaUnsupported("Historical retained rendering context unsupported")
    return root


def _verify_frozen_source(directory: Path):
    """Closed full62 byte inventory; fixture path is provenance, never authority."""
    _require(isinstance(directory, Path) and directory.is_dir())
    actual = tuple(
        sorted(
            (p.name, len(p.read_bytes()), hashlib.sha256(p.read_bytes()).hexdigest())
            for p in directory.iterdir()
            if p.is_file()
        )
    )
    _require(actual == _FROZEN62)


def _observe_historical_catalog(connection):
    """Private read-only catalog packet for hosted source review, never a proof.

    No row reads, row counts, row digests, credential material or logging. The
    packet is freely constructible and is therefore explicitly NOT consumed
    by the verifier as admission evidence. The verifier always reads its own
    live connection. OIDs are observations, never caller namespace overrides.
    """
    _preflight(connection)
    params = {"names": list(_NAMES), "roles": list(_ROLES)}
    queries = {
        "rendering_context": """
            SELECT current_setting('server_version_num')::integer,current_setting('server_version'),
                   current_setting('search_path'),pg_catalog.current_schemas(true),
                   current_setting('quote_all_identifiers'),current_setting('standard_conforming_strings')
        """,
        "relations": """
            SELECT c.relname,c.oid,c.relkind,pg_catalog.pg_get_userbyid(c.relowner),
                   c.relrowsecurity,c.relforcerowsecurity,c.relpersistence,c.relispartition,
                   c.relhassubclass,c.reloptions,c.relreplident,c.reltablespace
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY c.relname
        """,
        "columns": """
            SELECT c.relname,a.attnum,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),
                   NOT a.attnotnull,pg_catalog.pg_get_expr(d.adbin,d.adrelid,false),a.attisdropped,
                   a.attidentity,a.attgenerated,cn.nspname,co.collname,a.attinhcount,a.attislocal
            FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
            LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
            LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
            WHERE n.nspname='public' AND c.relname=ANY(:names) AND a.attnum>0
            ORDER BY c.relname,a.attnum
        """,
        "constraints": """
            SELECT c.relname,k.conname,k.contype,
                   ARRAY(SELECT a.attname FROM unnest(k.conkey) WITH ORDINALITY x(num,ord)
                         JOIN pg_catalog.pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=x.num ORDER BY x.ord),
                   pn.nspname,p.relname,
                   ARRAY(SELECT a.attname FROM unnest(k.confkey) WITH ORDINALITY x(num,ord)
                         JOIN pg_catalog.pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=x.num ORDER BY x.ord),
                   k.confdeltype,k.confupdtype,k.confmatchtype,k.convalidated,k.condeferrable,k.condeferred,
                   k.connoinherit,pg_catalog.pg_get_expr(k.conbin,k.conrelid,false),k.confrelid
            FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            LEFT JOIN pg_catalog.pg_class p ON p.oid=k.confrelid
            LEFT JOIN pg_catalog.pg_namespace pn ON pn.oid=p.relnamespace
            WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY c.relname,k.conname
        """,
        "indexes": """
            SELECT c.relname,ic.relname,i.indisunique,i.indisprimary,i.indisvalid,i.indisready,i.indislive,
                   ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY x(num,ord)
                         LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=x.num
                         ORDER BY x.ord),
                   i.indnkeyatts,i.indnatts,pg_catalog.pg_get_expr(i.indexprs,i.indrelid,false),
                   pg_catalog.pg_get_expr(i.indpred,i.indrelid,false),i.indoption::text,
                   ARRAY(SELECT ns.nspname||'.'||op.opcname FROM unnest(i.indclass) WITH ORDINALITY x(id,ord)
                         JOIN pg_catalog.pg_opclass op ON op.oid=x.id JOIN pg_catalog.pg_namespace ns
                         ON ns.oid=op.opcnamespace ORDER BY x.ord),
                   ARRAY(SELECT CASE WHEN x.id=0 THEN NULL ELSE ns.nspname||'.'||co.collname END
                         FROM unnest(i.indcollation) WITH ORDINALITY x(id,ord)
                         LEFT JOIN pg_catalog.pg_collation co ON co.oid=x.id
                         LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=co.collnamespace ORDER BY x.ord),
                   am.amname,ic.reloptions,ic.reltablespace,
                   pg_catalog.pg_get_userbyid(ic.relowner),i.indisexclusion,i.indimmediate
            FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid
            JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid JOIN pg_catalog.pg_am am ON am.oid=ic.relam
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY c.relname,ic.relname
        """,
        "policies": """
            SELECT c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles,
                   pg_catalog.pg_get_expr(p.polqual,p.polrelid,false),pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid,false)
            FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY c.relname,p.polname
        """,
        "table_acl": """
            SELECT c.relname,pg_catalog.pg_get_userbyid(a.grantor),
                   CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,
                   a.privilege_type,a.is_grantable
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace,
                 LATERAL pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
            WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY 1,2,3,4,5
        """,
        "column_acl": """
            SELECT c.relname,t.attname,pg_catalog.pg_get_userbyid(a.grantor),
                   CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END,
                   a.privilege_type,a.is_grantable
            FROM pg_catalog.pg_attribute t JOIN pg_catalog.pg_class c ON c.oid=t.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace,LATERAL pg_catalog.aclexplode(t.attacl) a
            WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY 1,2,3,4,5,6
        """,
        "roles": """
            SELECT rolname,oid,rolsuper,rolbypassrls,rolinherit,rolcreaterole,rolcreatedb,
                   rolreplication,rolconfig IS NULL
            FROM pg_catalog.pg_roles WHERE rolname=ANY(:roles) ORDER BY rolname
        """,
        "memberships": """
            SELECT pg_catalog.pg_get_userbyid(m.roleid),pg_catalog.pg_get_userbyid(m.member),m.admin_option
            FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member
            JOIN pg_catalog.pg_roles p ON p.oid=m.roleid
            WHERE r.rolname=ANY(:roles) OR p.rolname=ANY(:roles) ORDER BY 1,2,3
        """,
        "effective_tables": """
            SELECT c.relname,r,p,pg_catalog.has_table_privilege(r,c.oid,p)
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace,
                 unnest(CAST(:roles AS text[])) r,
                 unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
            WHERE n.nspname='public' AND c.relname=ANY(:names) ORDER BY 1,2,3
        """,
        "effective_columns": """
            SELECT c.relname,a.attname,r,p,pg_catalog.has_column_privilege(r,c.oid,a.attnum,p)
            FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace,unnest(CAST(:roles AS text[])) r,
                 unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) p
            WHERE n.nspname='public' AND c.relname=ANY(:names) AND a.attnum>0 AND NOT a.attisdropped
            ORDER BY 1,2,3,4
        """,
        "unexpected_rules_triggers": """
            SELECT c.relname,'rule',r.rulename FROM pg_catalog.pg_rewrite r
            JOIN pg_catalog.pg_class c ON c.oid=r.ev_class JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=ANY(:names)
            UNION ALL
            SELECT c.relname,'trigger',t.tgname FROM pg_catalog.pg_trigger t
            JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=ANY(:names) AND NOT t.tgisinternal ORDER BY 1,2,3
        """,
        "policy_dependencies": """
            SELECT c.relname,p.polname,d.classid::regclass::text,d.objsubid,
                   d.refclassid::regclass::text,d.refobjid,d.refobjsubid,d.deptype
            FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_policy p ON p.oid=d.objid
            JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE d.classid='pg_catalog.pg_policy'::regclass AND n.nspname='public'
                  AND c.relname=ANY(:names) ORDER BY 1,2,3,4,5,6,7,8
        """,
        "tenant_function": """
            SELECT p.oid,pg_catalog.pg_get_userbyid(p.proowner),l.lanname,p.provolatile,p.prosecdef,
                   p.proleakproof,p.proparallel,p.proconfig IS NULL,md5(p.prosrc),p.prorettype::regtype::text
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
            WHERE p.oid=pg_catalog.to_regprocedure('public.app_current_tenant_id()')
        """,
    }
    return {name: _rows(connection, sql, **params) for name, sql in queries.items()}


def _table_privileges(table, role):
    if role == "app_admin":
        return _PRIVILEGES
    if role == "academy_lab_worker":
        return {
            "lab_instances": ("SELECT", "UPDATE"),
            "lab_operations": ("SELECT", "INSERT", "UPDATE"),
            "lab_templates": ("SELECT",),
            "platform_settings": ("SELECT",),
            "notifications": ("SELECT", "INSERT"),
            "email_outbox": ("SELECT", "INSERT"),
        }.get(table, ())
    if table in ("lab_instances", "lab_operations"):
        return ("SELECT",)
    if table == "platform_settings":
        return ("SELECT",) if role == "app_user" else ("SELECT", "INSERT", "UPDATE", "DELETE")
    return ("SELECT", "INSERT", "UPDATE", "DELETE")


def _check_security(packet):
    roles = {row[0]: row for row in packet["roles"]}
    _require(set(roles) == set(_ROLES))
    for name, row in roles.items():
        _require(row[2] is False and row[3] is (name in ("app_admin", "academy_lab_worker")))
        _require(not any(row[5:8]) and row[8] is True)
    _require(roles["academy_lab_worker"][4] is False)
    # No implicit inherited grant, SET ROLE escalation or worker role membership.
    _require(not packet["memberships"])
    table_acl: list[tuple[str, str, str, str, bool]] = []
    for table in _NAMES:
        for role in _ROLES:
            table_acl.extend((table, "app_admin", role, p, False) for p in _table_privileges(table, role))
    _require(packet["table_acl"] == tuple(sorted(table_acl)))
    column_acl = tuple(
        sorted((t, c, "app_admin", "app_user", "INSERT", False) for t, columns in _REQUEST_COLUMNS for c in columns)
    )
    _require(packet["column_acl"] == column_acl)
    expected_tables = tuple(
        sorted((t, r, p, p in _table_privileges(t, r)) for t in _NAMES for r in _ROLES for p in _PRIVILEGES)
    )
    _require(packet["effective_tables"] == expected_tables)
    request = dict(_REQUEST_COLUMNS)
    expected_columns = tuple(
        sorted(
            (
                t,
                c[0],
                r,
                p,
                p in _table_privileges(t, r) or (r == "app_user" and p == "INSERT" and c[0] in request.get(t, ())),
            )
            for t, columns in _COLUMNS
            for c in columns
            for r in _ROLES
            for p in _COLUMN_PRIVILEGES
        )
    )
    _require(packet["effective_columns"] == expected_columns)


def _check_structure(packet):
    _check_rendering_context(packet)
    _require(tuple(r[0] for r in packet["relations"]) == _NAMES)
    for row in packet["relations"]:
        _require(row[2:4] == ("r", "app_admin"))
        tenant = row[0] != "platform_settings"
        _require(row[4:6] == (tenant, tenant))
        _require(row[6:] == ("p", False, False, None, "d", 0))
    expected_columns = tuple((t, i, *c) for t, columns in _COLUMNS for i, c in enumerate(columns, 1))
    _require(tuple(row[:6] for row in packet["columns"]) == expected_columns)
    _require(all(row[6:9] == (False, "", "") and row[11:] == (0, True) for row in packet["columns"]))
    # Every default (including absence) is an exact frozen-source _COLUMNS pin.
    expected_column_collations = tuple(_column_collation(c[1]) for _, columns in _COLUMNS for c in columns)
    _require(tuple(row[9:11] for row in packet["columns"]) == expected_column_collations)
    # Fixed PK/unique/FK set, never initial-capture-equals-current authority.
    expected_constraints: list[tuple[str, str, str, tuple[str, ...]]] = []
    for table, primary_unique_keys in _KEYS:
        expected_constraints.extend((table, name, kind, columns) for name, kind, columns in primary_unique_keys)
    for table, foreign_keys in _FOREIGN_KEYS:
        expected_constraints.extend((table, name, "f", columns) for name, columns, _, _, _ in foreign_keys)
    checks = {(t, n): expression for t, n, expression in _CHECK_RENDERINGS}
    actual_constraints: list[tuple[str, str, str, tuple[str, ...]]] = []
    fk_map = {(t, f[0]): f for t, foreign_keys in _FOREIGN_KEYS for f in foreign_keys}
    for row in packet["constraints"]:
        table, name, kind, columns = row[:4]
        # Ordinary-table PK/UNIQUE/FK constraints do not inherit; CHECK does.
        # Frozen DDL declares no NO INHERIT check or partitioned relation.
        # PostgreSQL index_constraint_create/addFkConstraint set these flags;
        # this is kind-specific source semantics, never an observed override.
        _require(kind in ("p", "u", "f", "c"))
        _require(row[10:14] == (True, False, False, kind != "c"))
        if kind == "c":
            _require((table, name) in checks and row[14] == checks[(table, name)])
        else:
            actual_constraints.append((table, name, kind, columns))
            _require(row[14] is None)
        if kind == "f":
            foreign_key_spec = fk_map.get((table, name))
            if foreign_key_spec is None:
                raise RetainedSchemaRefused("Historical retained schema refused; root rollback required")
            _require(
                row[4:10]
                == (
                    "public",
                    foreign_key_spec[2],
                    foreign_key_spec[3],
                    "c" if foreign_key_spec[4] == "CASCADE" else "a",
                    "a",
                    "s",
                )
            )
    _require(tuple(sorted(actual_constraints)) == tuple(sorted(expected_constraints)))
    _require({(r[0], r[1]) for r in packet["constraints"] if r[2] == "c"} == set(checks))
    expected_indexes = {(t, s[0]): s for t, indexes in _INDEXES for s in indexes}
    partial_predicates = {(t, n): expression for t, n, expression in _PARTIAL_PREDICATE_RENDERINGS}
    _require({(r[0], r[1]) for r in packet["indexes"]} == set(expected_indexes))
    for row in packet["indexes"]:
        index_spec = expected_indexes[(row[0], row[1])]
        _require(row[2:7] == (index_spec[2], index_spec[3], True, True, True))
        _require(row[7:11] == (index_spec[1], len(index_spec[1]), len(index_spec[1]), None))
        _require(row[12] == " ".join("0" for _ in index_spec[1]))
        _require(row[15:] == ("btree", None, 0, "app_admin", False, True))
        expected_opclasses, expected_collations = _expected_index_semantics(row[0], index_spec[1])
        _require(row[13:15] == (expected_opclasses, expected_collations))
        _require(row[11] == partial_predicates.get((row[0], row[1])))
    expected_policies = tuple(
        (
            t,
            t + "_tenant_isolation",
            "*",
            True,
            (0,),
            "(tenant_id = app_current_tenant_id())",
            "(tenant_id = app_current_tenant_id())",
        )
        for t in _NAMES
        if t != "platform_settings"
    )
    _require(packet["policies"] == expected_policies)
    _require(not packet["unexpected_rules_triggers"])


def _verify_historical_retained_schema(connection):
    """Strict historical public-only structural verifier, currently unsupported.

    NO successful proof, caller packet, expected override, namespace selector,
    baseline blessing or mutation. All structural and effective-right checks
    run before the unconditional hosted qualification gate. No caller can use
    equality with a previous live observation to bypass fixed semantics.
    """
    root = _preflight(connection)
    packet = _observe_historical_catalog(connection)
    _check_structure(packet)
    _check_security(packet)
    _require(connection.get_transaction() is root and root.is_active)
    raise RetainedSchemaUnsupported("Historical retained PG rendering/security qualification pending")
