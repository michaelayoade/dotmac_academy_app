"""Academy product configuration layered on the kernel settings contract."""

from __future__ import annotations

import json
import math
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import Annotated, ClassVar, Literal, cast

from dotmac_kernel.config import Settings as KernelSettings
from dotmac_kernel.config import validate_settings as validate_kernel_settings
from pydantic import Field, field_validator, model_validator
from pydantic_settings import NoDecode, SettingsConfigDict
from sqlalchemy.engine import make_url

# Academy currently contains inline scripts and WebSocket lab consoles. This
# product default is declared by app.assembly's ProductSecurityPolicy;
# CONTENT_SECURITY_POLICY can still override it at deployment time.
ACADEMY_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
    "form-action 'self'; object-src 'none'; img-src 'self' data:; "
    "font-src 'self'; style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:"
)


LAB_EXECUTION_POLICY_SHAPES = {
    "lab_command_timeout_seconds_by_action": ("inspect", "deploy", "destroy", "check"),
    "lab_operation_lease_seconds_by_kind": ("deploy", "destroy", "check"),
    "lab_operation_max_attempts_by_kind": ("deploy", "destroy", "check"),
    "lab_operation_retry_delay_seconds": (),
    "lab_worker_poll_interval_seconds": (),
    "lab_restart_reclaim_lock_timeout_seconds": (),
    "lab_operation_unknown_lease_seconds": (),
    "lab_operation_unknown_max_attempts": (),
    "lab_process_termination_grace_seconds": (),
}
LAB_CAPACITY_KEYS = ("max_concurrent_labs", "max_concurrent_labs_per_tenant", "lab_idle_minutes")
LAB_EXECUTION_OVERRIDE_KEY = "lab_execution_policy_overrides"


def _lab_json(value: object) -> object:
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate lab policy key")
            result[key] = item
        return result

    if isinstance(value, str):
        try:
            return json.loads(value, object_pairs_hook=pairs)
        except (ValueError, TypeError):
            raise ValueError("invalid lab policy JSON") from None
    return value


def validate_lab_policy_integer(key: str, value: object, *, text: bool = True) -> int:
    if text and isinstance(value, str) and value.isascii() and value.isdecimal():
        value = int(value)
    minimum = 0 if key == "max_concurrent_labs_per_tenant" else 1
    if type(value) is not int or value < minimum or value > 2147483647:
        raise ValueError(f"{key} must be an integer between {minimum} and 2147483647")
    return value


def validate_lab_execution_value(key: str, value: object) -> object:
    shape = LAB_EXECUTION_POLICY_SHAPES[key]
    if not shape:
        return validate_lab_policy_integer(key, value)
    value = _lab_json(value)
    if type(value) is not dict or set(value) != set(shape):
        raise ValueError(f"{key} must contain the exact action/kind keys")
    return {name: validate_lab_policy_integer(key, value[name], text=False) for name in shape}


def validate_lab_execution_overrides(value: object) -> dict[str, object]:
    value = _lab_json(value)
    if type(value) is not dict or set(value) - LAB_EXECUTION_POLICY_SHAPES.keys():
        raise ValueError("lab execution overrides must be an object of known fields")
    # JSON members use numbers, not numeric strings. Absent members inherit env.
    for key, item in value.items():
        if not LAB_EXECUTION_POLICY_SHAPES[key]:
            validate_lab_policy_integer(key, item, text=False)
    return {key: validate_lab_execution_value(key, item) for key, item in value.items()}


def validate_lab_execution_relations(values: Mapping[str, object]) -> None:
    waits = validate_lab_execution_value(
        "lab_command_timeout_seconds_by_action", values["lab_command_timeout_seconds_by_action"]
    )
    leases = validate_lab_execution_value(
        "lab_operation_lease_seconds_by_kind", values["lab_operation_lease_seconds_by_kind"]
    )
    grace = validate_lab_policy_integer(
        "lab_process_termination_grace_seconds", values["lab_process_termination_grace_seconds"]
    )
    inspect, deploy, destroy, check = (waits[key] for key in ("inspect", "deploy", "destroy", "check"))
    bounds = {
        "deploy": max(inspect + destroy, inspect + deploy, 2 * inspect) + 2 * grace,
        "destroy": 2 * inspect + destroy + 2 * grace,
        "check": check + 2 * grace,
    }
    if any(leases[kind] <= bound for kind, bound in bounds.items()):
        raise ValueError("lab lease must exceed configured command and cleanup waits")
    if values["lab_operation_unknown_lease_seconds"] <= inspect + 2 * grace:
        raise ValueError("unknown lab lease must exceed inspect and cleanup waits")


@dataclass(frozen=True)
class LabExecutionPolicy:
    """Immutable policy for one startup phase or worker pass.

    Lease relations bound configured command/cleanup waits, not total wall time.
    """

    lab_command_timeout_seconds_by_action: Mapping[str, int]
    lab_operation_lease_seconds_by_kind: Mapping[str, int]
    lab_operation_max_attempts_by_kind: Mapping[str, int]
    lab_operation_retry_delay_seconds: int
    lab_worker_poll_interval_seconds: int
    lab_restart_reclaim_lock_timeout_seconds: int
    lab_operation_unknown_lease_seconds: int
    lab_operation_unknown_max_attempts: int
    lab_process_termination_grace_seconds: int
    max_concurrent_labs: int
    max_concurrent_labs_per_tenant: int
    lab_idle_minutes: int

    def __post_init__(self):
        values = {}
        for key, shape in LAB_EXECUTION_POLICY_SHAPES.items():
            raw = getattr(self, key)
            # Copy immutable projections too, so callers cannot retain a backing dict.
            values[key] = validate_lab_execution_value(key, dict(raw) if shape and isinstance(raw, Mapping) else raw)
        for key in LAB_CAPACITY_KEYS:
            values[key] = validate_lab_policy_integer(key, getattr(self, key))
        validate_lab_execution_relations(values)
        for key, value in values.items():
            object.__setattr__(self, key, MappingProxyType(value) if isinstance(value, dict) else value)

    @classmethod
    def from_settings(cls, value):
        return cls(**{key: getattr(value, key) for key in (*LAB_EXECUTION_POLICY_SHAPES, *LAB_CAPACITY_KEYS)})

    def lease_seconds(self, kind: str) -> int:
        return self.lab_operation_lease_seconds_by_kind.get(kind, self.lab_operation_unknown_lease_seconds)

    def max_attempts(self, kind: str) -> int:
        return self.lab_operation_max_attempts_by_kind.get(kind, self.lab_operation_unknown_max_attempts)


def validate_password_reset_min_length(value: object) -> int:
    """Parse the reset setting without bool/float coercion or unsafe fallback."""
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        value = int(value.strip())
    if type(value) is not int or value < 1:
        raise ValueError("password_reset_min_length must be a positive integer")
    return value


def validate_lab_check_output_limit(value: object) -> int:
    """Strict positive output length; empty/bool/float values never fall back."""
    message = "lab check output limit must be a positive integer"
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        try:
            value = int(value.strip())
        except ValueError:
            raise ValueError(message) from None
    if type(value) is not int or value < 1:
        raise ValueError(message)
    return value


def validate_notifications_recent_limit(value: object) -> int:
    """Strict positive integer policy shared by environment and stored overrides."""
    message = "notifications_recent_limit must be a positive integer"
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        try:
            value = int(value.strip())
        except ValueError:
            raise ValueError(message) from None
    if type(value) is not int or value < 1:
        raise ValueError(message)
    return value


ICAL_FEED_POLICY_KEYS = ("ical_feed_token_ttl_days", "ical_feed_uid_domain", "ical_feed_filename")


def validate_ical_feed_policy(key: str, value: object) -> int | str:
    """Validate environment/store values before rendering headers or minting."""
    if key == "ical_feed_token_ttl_days":
        if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
            value = int(value.strip())
        if type(value) is not int or value < 1:
            raise ValueError("ical_feed_token_ttl_days must be a positive integer")
        return value
    if type(value) is not str or not value.strip() or "\r" in value or "\n" in value:
        raise ValueError(f"{key} must be nonempty and contain no CR/LF")
    if key == "ical_feed_filename" and any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in value
    ):
        raise ValueError("ical_feed_filename must be a safe ASCII filename")
    return value


ENTRANCE_INVITATION_POLICY_KEYS = ("entrance_invitation_deadline_days",)


def validate_entrance_invitation_deadline_days(value: object) -> int:
    """Parse Settings/store integers without bool/float or malformed fallback."""
    message = "entrance_invitation_deadline_days must be a positive integer"
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        try:
            value = int(value.strip())
        except ValueError:
            raise ValueError(message) from None
    if type(value) is not int or value < 1:
        raise ValueError(message)
    return value


PASSWORD_CHANGE_POLICY_SHAPES = {"password_change_min_length": "nonnegative_int"}


def validate_password_change_policy_value(key: str, value: object) -> int:
    """Strict purpose minimum; zero is configurable and bool/float are refused."""
    if key not in PASSWORD_CHANGE_POLICY_SHAPES:
        raise ValueError("unknown password-change policy setting")
    message = f"{key} must be a nonnegative integer"
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        try:
            value = int(value.strip())
        except ValueError:
            raise ValueError(message) from None
    if type(value) is not int or value < 0:
        raise ValueError(message)
    return value


INVITATION_PURPOSE_POLICY_SHAPES = {
    "invitation_token_hours": "signed_hours",
    "invitation_password_min_length": "positive_int",
    "invitation_human_replace_outstanding": "bool",
    "invitation_stranded_replace_outstanding": "bool",
    "invitation_onboarding_replace_outstanding": "bool",
}


def validate_invitation_purpose_policy_value(key: str, value: object) -> int | float | bool:
    """Strict invitation purpose policy; no clamping or malformed fallback."""
    shape = INVITATION_PURPOSE_POLICY_SHAPES[key]
    message = f"{key} has an invalid policy value"
    if shape == "bool":
        if isinstance(value, str):
            text = value.strip().lower()
            if text in {"true", "1", "yes", "on"}:
                return True
            if text in {"false", "0", "no", "off"}:
                return False
        if type(value) is not bool:
            raise ValueError(message)
        return value
    if shape == "positive_int":
        if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
            try:
                value = int(value.strip())
            except ValueError:
                raise ValueError(message) from None
        if type(value) is not int or value < 1:
            raise ValueError(message)
        return value
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except (ValueError, OverflowError):
            raise ValueError(message) from None
    if type(value) not in (int, float):
        raise ValueError(message)
    try:
        normalized = float(value)
        if not math.isfinite(normalized):
            raise ValueError(message)
        timedelta(hours=normalized)
    except (ValueError, OverflowError):
        raise ValueError(message) from None
    return normalized


ADMISSION_ENROLLMENT_POLICY_KEYS = (
    "admission_enrollment_initial_role",
    "admission_enrollment_initial_status",
)


def validate_admission_enrollment_policy_value(key: str, value: object) -> str:
    """Match Learning's unconstrained String(20), without normalization."""
    if key not in ADMISSION_ENROLLMENT_POLICY_KEYS or type(value) is not str or len(value) > 20:
        raise ValueError(f"{key} must be a string of at most 20 characters")
    return value


BULK_ENROLLMENT_POLICY_KEYS = (
    "bulk_enrollment_initial_role",
    "bulk_enrollment_initial_status",
)
INVITATION_ENROLLMENT_POLICY_KEYS = ("invitation_enrollment_initial_status",)
ENROLLMENT_INITIAL_STATE_POLICY_KEYS = (*BULK_ENROLLMENT_POLICY_KEYS, *INVITATION_ENROLLMENT_POLICY_KEYS)


def validate_enrollment_initial_state_policy_value(key: str, value: object) -> str:
    """Preserve Learning String(20) facts exactly, including blank strings."""
    if key not in ENROLLMENT_INITIAL_STATE_POLICY_KEYS or type(value) is not str or len(value) > 20:
        raise ValueError(f"{key} must be a string of at most 20 characters")
    return value


ONBOARDING_POLICY_KEYS = ("onboarding_enrollment_global_role", "onboarding_task_catalog")
ONBOARDING_PROCEDURES = frozenset({"entrance_assessment", "confirm_details", "orientation"})


def validate_onboarding_policy_value(key: str, value: object) -> object:
    message = f"{key} has an invalid policy value"
    if key == "onboarding_enrollment_global_role":
        if type(value) is not str or not value.strip() or value != value.strip() or len(value) > 63:
            raise ValueError(message)
        return value
    if key != "onboarding_task_catalog":
        raise ValueError(message)
    if type(value) is str:
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple) or len(value) != len(ONBOARDING_PROCEDURES):
        raise ValueError(message)
    result = []
    for item in value:
        if type(item) not in (list, tuple) or len(item) != 2:
            raise ValueError(message)
        key_name, label = item
        if type(key_name) is not str or key_name not in ONBOARDING_PROCEDURES:
            raise ValueError(message)
        if type(label) is not str or not label.strip() or len(label) > 200:
            raise ValueError(message)
        result.append((key_name, label))
    if {item[0] for item in result} != ONBOARDING_PROCEDURES:
        raise ValueError(message)
    return tuple(result)


INITIAL_IDENTITY_POLICY_KEYS = ("account_initial_is_active", "account_initial_profile_status")


def validate_initial_identity_policy_value(key: str, value: object) -> bool | str:
    """Parse exact creation settings without inventing account status policy."""
    message = f"{key} has an invalid policy value"
    if key == "account_initial_is_active":
        if type(value) is str:
            text = value.strip().lower()
            if text in {"true", "1", "yes", "on"}:
                return True
            if text in {"false", "0", "no", "off"}:
                return False
        if type(value) is not bool:
            raise ValueError(message)
        return value
    if key != "account_initial_profile_status" or type(value) is not str or len(value) > 20:
        raise ValueError(message)
    return value


PROFILE_POLICY_SHAPES = {
    "account_avatar_max_bytes": "positive_int",
    "account_email_results_default": "bool",
    "account_email_digest_default": "bool",
}


def validate_profile_policy_value(key: str, value: object) -> int | bool:
    """Strict stored/env profile policy; no malformed-value fallback."""
    message = f"{key} has an invalid policy value"
    if PROFILE_POLICY_SHAPES[key] == "positive_int":
        if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
            value = int(value.strip())
        # BinaryIO.read(limit + 1) accepts a Py_ssize_t count. Reserve the
        # extra overflow-detection byte; this is a platform representation
        # boundary, not an additional product/business upload limit.
        if type(value) is not int or not 0 < value < sys.maxsize:
            raise ValueError(message)
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"true", "1", "yes", "on"}:
            return True
        if text in {"false", "0", "no", "off"}:
            return False
    if type(value) is not bool:
        raise ValueError(message)
    return value


AUTHENTICATION_POLICY_SHAPES = {
    "authentication_max_failed_logins": "positive_int",
    "authentication_lockout_minutes": "nonnegative_duration",
    "password_reset_token_minutes": "nonnegative_duration",
}


def validate_authentication_policy_value(key: str, value: object) -> int | float:
    """Strict product policy parsing; never clamp or echo the supplied value."""
    shape = AUTHENTICATION_POLICY_SHAPES[key]
    message = f"{key} has an invalid policy value"
    if isinstance(value, str):
        try:
            value = int(value.strip()) if shape == "positive_int" else float(value.strip())
        except (ValueError, OverflowError):
            raise ValueError(message) from None
    if shape == "positive_int":
        if type(value) is not int or value <= 0:
            raise ValueError(message)
        return value
    if type(value) not in (int, float) or value < 0:
        raise ValueError(message)
    try:
        normalized = float(value)
        if not math.isfinite(normalized):
            raise ValueError(message)
        # Preserve native fractional-minute rounding. The representational
        # limit comes from timedelta itself, never a product business cap.
        timedelta(minutes=normalized)
    except (OverflowError, ValueError):
        raise ValueError(message) from None
    return normalized


InvitationMemberRole = Literal["student", "instructor"]


def validate_invitation_default_member_role(value: object) -> InvitationMemberRole:
    """Accept only the owner's closed role contract, without coercion."""
    if type(value) is not str or value not in ("student", "instructor"):
        raise ValueError("invitation_default_member_role must be student or instructor")
    return cast(InvitationMemberRole, value)


def validate_invitation_member_role_map(value: object) -> dict[str, InvitationMemberRole]:
    """Parse a strict JSON object or mapping; never include input in errors."""
    message = "invitation_member_role_map must map nonempty role names to student or instructor"

    def unique_object(pairs):
        result = {}
        for key, role in pairs:
            if key in result:
                raise ValueError(message)
            result[key] = role
        return result

    if isinstance(value, str):
        try:
            value = json.loads(value, object_pairs_hook=unique_object)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) is not dict:
        raise ValueError(message)
    result: dict[str, InvitationMemberRole] = {}
    for key, role in value.items():
        if type(key) is not str or not key or key != key.strip():
            raise ValueError(message)
        try:
            result[key] = validate_invitation_default_member_role(role)
        except ValueError:
            raise ValueError(message) from None
    return result


def validate_web_account_creation_password_min_length(value: object) -> int:
    """Parse this entrypoint's nonnegative minimum without bool/float coercion."""
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        value = int(value.strip())
    if type(value) is not int or value < 0:
        raise ValueError("web_account_creation_password_min_length must be a nonnegative integer")
    return value


def validate_web_account_creation_role_admission(value: object) -> dict[str, tuple[str, ...]]:
    """Validate configured role names and ordered, nonempty unique actor lists."""
    message = "web_account_creation_role_admission must map role names to nonempty unique actor-role lists"

    def unique_object(pairs):
        result = {}
        for key, actors in pairs:
            if key in result:
                raise ValueError(message)
            result[key] = actors
        return result

    if isinstance(value, str):
        try:
            value = json.loads(value, object_pairs_hook=unique_object)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) is not dict:
        raise ValueError(message)
    result: dict[str, tuple[str, ...]] = {}
    for target, actors in value.items():
        if type(target) is not str or not target or target != target.strip():
            raise ValueError(message)
        if type(actors) not in (list, tuple) or not actors:
            raise ValueError(message)
        if any(type(actor) is not str or not actor or actor != actor.strip() for actor in actors):
            raise ValueError(message)
        if len(set(actors)) != len(actors):
            raise ValueError(message)
        result[target] = tuple(actors)
    return result


def validate_web_account_creation_role_provisioning(value: object) -> dict[str, str]:
    """Validate role catalog creation names without inventing role defaults."""
    message = "web_account_creation_role_provisioning must map role names to nonempty display names"

    def unique_object(pairs):
        result = {}
        for key, name in pairs:
            if key in result:
                raise ValueError(message)
            result[key] = name
        return result

    if isinstance(value, str):
        try:
            value = json.loads(value, object_pairs_hook=unique_object)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) is not dict:
        raise ValueError(message)
    for role, name in value.items():
        if type(role) is not str or not role or role != role.strip():
            raise ValueError(message)
        if type(name) is not str or not name or name != name.strip():
            raise ValueError(message)
    return dict(value)


# Validation shapes contain no business defaults; those live in Settings.
LEARNING_POLICY_SHAPES: dict[str, tuple[str, str]] = {
    "learning_reading_words_per_minute": ("int", "positive"),
    "learning_reading_minimum_minutes": ("int", "nonnegative"),
    "learning_join_lead_minutes": ("int", "nonnegative"),
    "learning_todo_graded_lookback_days": ("int", "nonnegative"),
    "learning_todo_graded_limit": ("int", "nonnegative"),
    "learning_todo_window_horizon_days": ("int", "nonnegative"),
    "learning_todo_near_deadline_days": ("int", "nonnegative"),
    "learning_todo_far_deadline_days": ("int", "nonnegative"),
    "learning_agenda_limit": ("int", "nonnegative"),
    "learning_person_announcements_limit": ("int", "nonnegative"),
    "learning_tenant_announcements_limit": ("int", "nonnegative"),
    "learning_dashboard_at_risk_fraction": ("float", "fraction"),
    "learning_dashboard_stale_days": ("int", "nonnegative"),
    "learning_behind_pace_fraction": ("float", "fraction"),
    "learning_search_limit": ("int", "nonnegative"),
    "learning_search_staff_roles": ("tuple[str, ...]", "role_slugs"),
    "learning_top_movers_limit": ("int", "nonnegative"),
    "learning_attention_limit": ("int", "nonnegative"),
    "learning_activity_report_hours": ("int", "nonnegative"),
    "learning_lab_pass_threshold": ("float", "fraction"),
    "learning_instructor_at_risk_fraction": ("float", "fraction"),
    "learning_instructor_stale_days": ("int", "nonnegative"),
    "learning_instructor_workspace_limit": ("int", "nonnegative"),
    "learning_trend_sample_limit": ("int", "at_least_two"),
    "learning_trend_min_samples": ("int", "at_least_two"),
    "learning_trend_min_delta_fraction": ("float", "fraction"),
    "learning_activity_chart_weeks": ("int", "nonnegative"),
    "learning_velocity_weeks": ("int", "nonnegative"),
    "learning_resume_after_days": ("int", "nonnegative"),
    "learning_active_window_days": ("int", "nonnegative"),
    "learning_comparison_prior_weeks": ("int", "positive"),
    "success_inactive_days": ("int", "signed"),
    "success_min_grade_pct": ("int", "signed"),
    "success_certificate_grace_hours": ("int", "signed"),
    "success_inactivity_high_factor": ("float", "at_least_one"),
    "success_overdue_high_count": ("int", "nonnegative"),
    "success_overdue_high_days": ("int", "nonnegative"),
    "success_overdue_title_limit": ("int", "nonnegative"),
    "success_below_passing_min_graded": ("int", "nonnegative"),
    "success_below_passing_min_weight_fraction": ("float", "fraction"),
    "success_below_passing_high_grade_factor": ("float", "fraction"),
    "success_almost_complete_fraction": ("float", "fraction"),
    "learning_default_activity_type": ("str", "text"),
    "learning_default_activity_pass_threshold": ("float", "fraction"),
    "learning_default_activity_assessment_mode": ("str", "text"),
    "learning_default_activity_grading": ("str", "text"),
    "learning_default_activity_weight": ("float", "positive"),
    "learning_default_course_status": ("str", "text"),
    "learning_default_course_listed": ("bool", "bool"),
    "learning_default_session_type": ("str", "session_type"),
    "learning_default_extra_attempts": ("int", "positive"),
    "learning_bank_pass_threshold_by_kind": ("dict[str, float]", "fraction_map"),
    "learning_bank_fallback_pass_threshold": ("float", "fraction"),
    "learning_bank_new_activity_assessment_mode": ("str", "text"),
    "learning_bank_new_activity_grading": ("str", "text"),
    "learning_bank_new_activity_weight": ("float", "positive"),
    "learning_exam_seconds_per_question": ("float", "nonnegative"),
    "learning_exam_near_chance_margin": ("float", "positive"),
    "learning_exam_fallback_score_floor": ("float", "fraction"),
    "learning_exam_fallback_duration_seconds": ("float", "nonnegative"),
    "learning_missing_question_weight": ("int", "positive"),
    # Composable Learning policies (A1): creation defaults and Terms inputs.
    # Defaults in Settings reproduce the historical hardcoded behaviour.
    "learning_prerequisite_default_kind": ("str", "prerequisite_kind"),
    "learning_prerequisite_default_composition": ("str", "prerequisite_composition"),
    "learning_track_default_gating_mode": ("str", "track_gating_mode"),
    "learning_default_completion_fraction": ("float", "positive_fraction"),
    "learning_default_certificate_auto_issue": ("bool", "bool"),
    "learning_default_certificate_validity_days": ("int", "nonnegative"),
    "learning_feedback_reveal_by_mode": ("dict[str, str]", "reveal_map"),
    "learning_default_activity_scoring_policy": ("str", "scoring_policy"),
    "learning_progress_trend_sample_limit": ("int", "at_least_two"),
    "learning_progress_trend_min_samples": ("int", "at_least_two"),
    "learning_progress_trend_min_delta_fraction": ("float", "fraction"),
    "learning_cohort_half_fraction": ("float", "fraction"),
    "success_enabled_rules": ("tuple[str, ...]", "success_rules"),
    "success_severity_by_rule": ("dict[str, str]", "severity_map"),
    "learning_session_promotes_delivery_mode": ("bool", "bool"),
    "learning_default_attempt_cooldown_seconds": ("int", "cooldown_seconds"),
    "learning_pacing_default_open": ("bool", "bool"),
}

# Closed catalogs mirrored from Learning code (validated again there).
LEARNING_PREREQUISITE_COMPOSITIONS = ("all", "any")
LEARNING_TRACK_GATING_MODES = ("none", "previous", "all_previous")
LEARNING_SCORING_POLICIES = ("best", "latest", "first")
LEARNING_FEEDBACK_REVEAL_POLICIES = ("immediate", "on_pass_or_exhausted", "never")
LEARNING_SUCCESS_SEVERITIES = ("high", "medium", "low")
LEARNING_ATTEMPT_COOLDOWN_MAX_SECONDS = 2592000


def certificate_validity_days_or_none(value: int) -> int | None:
    """Map the stored sentinel to Learning validity: 0 means never expires."""
    if type(value) is not int or value < 0:
        raise ValueError("learning_default_certificate_validity_days has an invalid policy value")
    return None if value == 0 else value


def validate_admin_home_access_roles(value: object) -> tuple[str, ...]:
    """Custom roles allowed, empty denies, malformed policy refuses."""
    message = "admin_home_access_roles has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def validate_lab_admin_access_roles(value: object) -> tuple[str, ...]:
    """Custom roles allowed, empty denies, malformed policy refuses."""
    message = "lab_admin_access_roles has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def validate_reminders_admin_access_roles(value: object) -> tuple[str, ...]:
    """Custom roles allowed, empty denies, malformed policy refuses."""
    message = "reminders_admin_access_roles has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def validate_teaching_access_roles(value: object) -> tuple[str, ...]:
    """Explicit role policy: custom slugs allowed, empty denies, malformed refuses."""
    message = "teaching_access_roles has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def validate_catalog_staff_roles(value: object) -> tuple[str, ...]:
    """Explicit role policy: custom slugs allowed, empty denies, malformed refuses."""
    message = "catalog_staff_roles has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def validate_gradebook_access_roles(value: object) -> tuple[str, ...]:
    """Explicit role policy: custom slugs allowed, empty denies, malformed refuses."""
    message = "gradebook_access_roles has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def validate_settings_access_roles(value: object) -> tuple[str, ...]:
    """Explicit role policy: custom slugs allowed, empty denies, malformed refuses."""
    message = "settings_access_roles has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def validate_reports_access_roles(value: object) -> tuple[str, ...]:
    """Explicit role policy: custom slugs allowed, empty denies, malformed refuses."""
    message = "reports_access_roles has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def _validate_bank_role_list(key: str, value: object) -> tuple[str, ...]:
    """Explicit role policy: custom slugs allowed, empty denies, malformed refuses."""
    message = f"{key} has an invalid policy value"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if type(value) not in (list, tuple):
        raise ValueError(message)
    if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
        raise ValueError(message)
    if len(set(value)) != len(value):
        raise ValueError(message)
    return tuple(value)


def validate_bank_author_roles(value: object) -> tuple[str, ...]:
    return _validate_bank_role_list("bank_author_roles", value)


def validate_bank_publish_roles(value: object) -> tuple[str, ...]:
    return _validate_bank_role_list("bank_publish_roles", value)


def validate_bank_repoint_roles(value: object) -> tuple[str, ...]:
    return _validate_bank_role_list("bank_repoint_roles", value)


def validate_bank_export_roles(value: object) -> tuple[str, ...]:
    return _validate_bank_role_list("bank_export_roles", value)


def validate_bank_retire_roles(value: object) -> tuple[str, ...]:
    return _validate_bank_role_list("bank_retire_roles", value)


def validate_learning_policy_value(key: str, value: object) -> object:
    """Reject malformed explicit policy rather than select a silent fallback."""
    kind, shape = LEARNING_POLICY_SHAPES[key]
    message = f"{key} has an invalid policy value"
    if kind == "tuple[str, ...]":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (TypeError, ValueError):
                raise ValueError(message) from None
        if type(value) not in (list, tuple):
            raise ValueError(message)
        if any(type(slug) is not str or not slug or slug != slug.strip() for slug in value):
            raise ValueError(message)
        if len(set(value)) != len(value):
            raise ValueError(message)
        if shape == "success_rules":
            from dotmac_learning.delivery_models import REASON_KINDS

            if not set(value) <= set(REASON_KINDS):
                raise ValueError(message)
        return tuple(value)
    if kind == "dict[str, str]":
        if isinstance(value, str):

            def unique_str_object(pairs):
                result = {}
                for name, item in pairs:
                    if name in result:
                        raise ValueError(message)
                    result[name] = item
                return result

            try:
                value = json.loads(value, object_pairs_hook=unique_str_object)
            except (TypeError, ValueError):
                raise ValueError(message) from None
        if type(value) is not dict:
            raise ValueError(message)
        result_str: dict[str, str] = {}
        for name, item in value.items():
            if type(name) is not str or not name or name != name.strip():
                raise ValueError(message)
            if type(item) is not str or not item or item != item.strip():
                raise ValueError(message)
            result_str[name] = item
        if shape == "reveal_map":
            from dotmac_learning import ASSESSMENT_MODES

            if set(result_str) != set(ASSESSMENT_MODES):
                raise ValueError(message)
            if any(item not in LEARNING_FEEDBACK_REVEAL_POLICIES for item in result_str.values()):
                raise ValueError(message)
            if result_str.get("exam") == "immediate":
                raise ValueError(message)
        elif shape == "severity_map":
            from dotmac_learning.delivery_models import REASON_KINDS

            if not set(result_str) <= set(REASON_KINDS):
                raise ValueError(message)
            if any(item not in LEARNING_SUCCESS_SEVERITIES for item in result_str.values()):
                raise ValueError(message)
        return result_str
    if kind == "dict[str, float]":
        if isinstance(value, str):

            def unique_object(pairs):
                result = {}
                for name, threshold in pairs:
                    if name in result:
                        raise ValueError(message)
                    result[name] = threshold
                return result

            try:
                value = json.loads(value, object_pairs_hook=unique_object)
            except (TypeError, ValueError):
                raise ValueError(message) from None
        if type(value) is not dict:
            raise ValueError(message)
        result = {}
        for name, threshold in value.items():
            if type(name) is not str or not name or name != name.strip():
                raise ValueError(message)
            if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
                raise ValueError(message)
            result[name] = float(threshold)
        return result
    if kind == "str":
        if type(value) is not str or not value or value != value.strip():
            raise ValueError(message)
        if shape == "session_type":
            from dotmac_learning import SESSION_TYPES

            if value not in SESSION_TYPES:
                raise ValueError(message)
        elif shape == "prerequisite_kind":
            from dotmac_learning import PREREQUISITE_CONDITION_KINDS

            if value not in PREREQUISITE_CONDITION_KINDS:
                raise ValueError(message)
        elif shape == "prerequisite_composition":
            if value not in LEARNING_PREREQUISITE_COMPOSITIONS:
                raise ValueError(message)
        elif shape == "track_gating_mode":
            if value not in LEARNING_TRACK_GATING_MODES:
                raise ValueError(message)
        elif shape == "scoring_policy":
            if value not in LEARNING_SCORING_POLICIES:
                raise ValueError(message)
        return value
    if kind == "bool":
        if isinstance(value, str):
            parsed = value.strip().lower()
            if parsed in ("true", "1", "yes", "on"):
                return True
            if parsed in ("false", "0", "no", "off"):
                return False
        if type(value) is not bool:
            raise ValueError(message)
        return value
    if isinstance(value, str):
        try:
            value = int(value.strip()) if kind == "int" else float(value.strip())
        except (ValueError, OverflowError):
            raise ValueError(message) from None
    if kind == "int":
        if type(value) is not int:
            raise ValueError(message)
    elif type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(message)
    if shape == "nonnegative" and value < 0:
        raise ValueError(message)
    if shape == "positive" and value <= 0:
        raise ValueError(message)
    if shape == "at_least_two" and value < 2:
        raise ValueError(message)
    if shape == "at_least_one" and value < 1:
        raise ValueError(message)
    if shape == "fraction" and not 0 <= value <= 1:
        raise ValueError(message)
    if shape == "positive_fraction" and not 0 < value <= 1:
        raise ValueError(message)
    if shape == "cooldown_seconds" and not 0 <= value <= LEARNING_ATTEMPT_COOLDOWN_MAX_SECONDS:
        raise ValueError(message)
    return value if kind == "int" else float(value)


def validate_learning_policy_relations(values: dict[str, object]) -> None:
    """Reject contradictory composed policy without clamping the input."""
    if cast(int, values["learning_todo_near_deadline_days"]) > cast(int, values["learning_todo_far_deadline_days"]):
        raise ValueError("near deadline days must not exceed far deadline days")
    if cast(int, values["learning_trend_sample_limit"]) < cast(int, values["learning_trend_min_samples"]):
        raise ValueError("trend sample limit must cover minimum samples")
    if cast(int, values["learning_progress_trend_sample_limit"]) < cast(
        int, values["learning_progress_trend_min_samples"]
    ):
        raise ValueError("progress trend sample limit must cover minimum samples")


BOOTSTRAP_POLICY_KEYS = (
    "bootstrap_allowed_database_role_pairs",
    "bootstrap_role_provisioning",
    "bootstrap_initial_role_slug",
    "bootstrap_tenant_is_active",
    "bootstrap_password_min_length",
    "bootstrap_owner_first_name",
    "bootstrap_owner_last_name_template",
)


def validate_bootstrap_policy_value(key: str, value: object) -> object:
    """Closed product composition; empty role pairs explicitly deny admission."""
    message = f"{key} has an invalid policy value"
    if key == "bootstrap_allowed_database_role_pairs":
        if type(value) is str:
            try:
                value = json.loads(value)
            except (ValueError, TypeError):
                raise ValueError(message) from None
        if not isinstance(value, (list, tuple)):
            raise ValueError(message)
        result = []
        for pair in value:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise ValueError(message)
            if any(type(role) is not str or not role or role != role.strip() or len(role) > 63 for role in pair):
                raise ValueError(message)
            result.append(tuple(pair))
        if len(set(result)) != len(result):
            raise ValueError(message)
        return tuple(result)
    if key == "bootstrap_role_provisioning":
        return validate_web_account_creation_role_provisioning(value)
    if key == "bootstrap_tenant_is_active":
        return validate_initial_identity_policy_value("account_initial_is_active", value)
    if key == "bootstrap_password_min_length":
        return validate_web_account_creation_password_min_length(value)
    if key == "bootstrap_owner_last_name_template":
        if type(value) is not str or value.count("{tenant_name}") != 1:
            raise ValueError(message)
        rest = value.replace("{tenant_name}", "")
        if "{" in rest or "}" in rest:
            raise ValueError(message)
        return value
    if key not in BOOTSTRAP_POLICY_KEYS or type(value) is not str or value != value.strip() or not value:
        raise ValueError(message)
    return value


class Settings(KernelSettings):
    """Kernel settings plus values owned only by the Academy product."""

    model_config: ClassVar[SettingsConfigDict] = {**KernelSettings.model_config, "hide_input_in_errors": True}

    # Learning policy compatibility values are product-owned and overrideable.
    learning_reading_words_per_minute: int = 200
    learning_reading_minimum_minutes: int = 1
    learning_join_lead_minutes: int = 60
    learning_todo_graded_lookback_days: int = 14
    learning_todo_graded_limit: int = 10
    learning_todo_window_horizon_days: int = 30
    learning_todo_near_deadline_days: int = 7
    learning_todo_far_deadline_days: int = 30
    learning_agenda_limit: int = 50
    learning_person_announcements_limit: int = 20
    learning_tenant_announcements_limit: int = 50
    learning_dashboard_at_risk_fraction: float = 0.5
    learning_dashboard_stale_days: int = 14
    learning_behind_pace_fraction: float = 0.2
    ical_feed_token_ttl_days: int = 365
    ical_feed_uid_domain: str = "academy.dotmac.io"
    ical_feed_filename: str = "dotmac-academy.ics"

    @field_validator(*ICAL_FEED_POLICY_KEYS, mode="before")
    @classmethod
    def _ical_feed_policy(cls, value: object, info):
        return validate_ical_feed_policy(info.field_name, value)

    notifications_recent_limit: int = 30

    @field_validator("notifications_recent_limit", mode="before")
    @classmethod
    def _notifications_recent_limit(cls, value: object) -> int:
        return validate_notifications_recent_limit(value)

    learning_search_limit: int = 20
    admin_home_access_roles: tuple[str, ...] = ("admin",)

    @field_validator("admin_home_access_roles", mode="before")
    @classmethod
    def _admin_home_access_roles(cls, value: object) -> tuple[str, ...]:
        return validate_admin_home_access_roles(value)

    lab_admin_access_roles: tuple[str, ...] = ("instructor", "admin")

    @field_validator("lab_admin_access_roles", mode="before")
    @classmethod
    def _lab_admin_access_roles(cls, value: object) -> tuple[str, ...]:
        return validate_lab_admin_access_roles(value)

    reminders_admin_access_roles: tuple[str, ...] = ("admin",)

    @field_validator("reminders_admin_access_roles", mode="before")
    @classmethod
    def _reminders_admin_access_roles(cls, value: object) -> tuple[str, ...]:
        return validate_reminders_admin_access_roles(value)

    teaching_access_roles: tuple[str, ...] = ("instructor", "admin")

    @field_validator("teaching_access_roles", mode="before")
    @classmethod
    def _teaching_access_roles(cls, value: object) -> tuple[str, ...]:
        return validate_teaching_access_roles(value)

    catalog_staff_roles: tuple[str, ...] = ("instructor", "admin")

    @field_validator("catalog_staff_roles", mode="before")
    @classmethod
    def _catalog_staff_roles(cls, value: object) -> tuple[str, ...]:
        return validate_catalog_staff_roles(value)

    gradebook_access_roles: tuple[str, ...] = ("instructor", "admin")

    @field_validator("gradebook_access_roles", mode="before")
    @classmethod
    def _gradebook_access_roles(cls, value: object) -> tuple[str, ...]:
        return validate_gradebook_access_roles(value)

    settings_access_roles: tuple[str, ...] = ("admin",)

    @field_validator("settings_access_roles", mode="before")
    @classmethod
    def _settings_access_roles(cls, value: object) -> tuple[str, ...]:
        return validate_settings_access_roles(value)

    reports_access_roles: tuple[str, ...] = ("instructor", "admin")

    @field_validator("reports_access_roles", mode="before")
    @classmethod
    def _reports_access_roles(cls, value: object) -> tuple[str, ...]:
        return validate_reports_access_roles(value)

    # Question-bank lifecycle authority (adopted matrix): assigned
    # instructors may author drafts; publish/repoint/export/retire are
    # admin-only unless an operator widens a list through settings.
    bank_author_roles: tuple[str, ...] = ("instructor", "admin")

    @field_validator("bank_author_roles", mode="before")
    @classmethod
    def _bank_author_roles(cls, value: object) -> tuple[str, ...]:
        return validate_bank_author_roles(value)

    bank_publish_roles: tuple[str, ...] = ("admin",)

    @field_validator("bank_publish_roles", mode="before")
    @classmethod
    def _bank_publish_roles(cls, value: object) -> tuple[str, ...]:
        return validate_bank_publish_roles(value)

    bank_repoint_roles: tuple[str, ...] = ("admin",)

    @field_validator("bank_repoint_roles", mode="before")
    @classmethod
    def _bank_repoint_roles(cls, value: object) -> tuple[str, ...]:
        return validate_bank_repoint_roles(value)

    bank_export_roles: tuple[str, ...] = ("admin",)

    @field_validator("bank_export_roles", mode="before")
    @classmethod
    def _bank_export_roles(cls, value: object) -> tuple[str, ...]:
        return validate_bank_export_roles(value)

    bank_retire_roles: tuple[str, ...] = ("admin",)

    @field_validator("bank_retire_roles", mode="before")
    @classmethod
    def _bank_retire_roles(cls, value: object) -> tuple[str, ...]:
        return validate_bank_retire_roles(value)

    learning_search_staff_roles: tuple[str, ...] = ("instructor", "admin")
    learning_top_movers_limit: int = 5
    learning_attention_limit: int = 8
    learning_activity_report_hours: int = 24
    learning_lab_pass_threshold: float = 0.7
    learning_instructor_at_risk_fraction: float = 0.5
    learning_instructor_stale_days: int = 14
    learning_instructor_workspace_limit: int = 12
    learning_trend_sample_limit: int = 10
    learning_trend_min_samples: int = 4
    learning_trend_min_delta_fraction: float = 0.05
    learning_activity_chart_weeks: int = 8
    learning_velocity_weeks: int = 4
    learning_resume_after_days: int = 7
    learning_active_window_days: int = 7
    learning_comparison_prior_weeks: int = 4
    success_inactive_days: int = 7
    success_min_grade_pct: int = 60
    success_certificate_grace_hours: int = 6
    success_inactivity_high_factor: float = 2.0
    success_overdue_high_count: int = 3
    success_overdue_high_days: int = 7
    success_overdue_title_limit: int = 5
    success_below_passing_min_graded: int = 2
    success_below_passing_min_weight_fraction: float = 0.2
    success_below_passing_high_grade_factor: float = 0.5
    success_almost_complete_fraction: float = 0.8
    learning_default_activity_type: str = "mcq_test"
    learning_default_activity_pass_threshold: float = 0.0
    learning_default_activity_assessment_mode: str = "graded"
    learning_default_activity_grading: str = "auto"
    learning_default_activity_weight: float = 1.0
    learning_default_course_status: str = "published"
    learning_default_course_listed: bool = False
    learning_default_session_type: str = "live_class"
    learning_default_extra_attempts: int = 1
    learning_bank_pass_threshold_by_kind: dict[str, float] = Field(
        default_factory=lambda: {"chapter": 0.0, "mid": 0.6, "final": 0.7}
    )
    learning_bank_fallback_pass_threshold: float = 0.0
    learning_bank_new_activity_assessment_mode: str = "graded"
    learning_bank_new_activity_grading: str = "auto"
    learning_bank_new_activity_weight: float = 1.0
    learning_exam_seconds_per_question: float = 12.0
    learning_exam_near_chance_margin: float = 1.33
    learning_exam_fallback_score_floor: float = 0.3333333333333333
    learning_exam_fallback_duration_seconds: float = 360.0
    learning_missing_question_weight: int = 1
    # Composable Learning policies (A1). Every default reproduces the
    # historical hardcoded behaviour; non-default values are opt-in data.
    learning_prerequisite_default_kind: str = "course_completed"
    learning_prerequisite_default_composition: str = "all"
    learning_track_default_gating_mode: str = "previous"
    learning_default_completion_fraction: float = 1.0
    learning_default_certificate_auto_issue: bool = True
    # Sentinel: 0 means certificates never expire (mapped to None).
    learning_default_certificate_validity_days: int = 0
    learning_feedback_reveal_by_mode: dict[str, str] = Field(
        default_factory=lambda: {
            "practice": "immediate",
            "graded": "on_pass_or_exhausted",
            "exam": "never",
        }
    )
    learning_default_activity_scoring_policy: str = "best"
    learning_progress_trend_sample_limit: int = 8
    learning_progress_trend_min_samples: int = 3
    learning_progress_trend_min_delta_fraction: float = 0.03
    learning_cohort_half_fraction: float = 0.5
    success_enabled_rules: tuple[str, ...] = (
        "inactivity",
        "overdue_work",
        "below_passing",
        "failed_final",
        "certificate_blocked",
    )
    success_severity_by_rule: dict[str, str] = Field(
        default_factory=lambda: {"failed_final": "high", "certificate_blocked": "medium"}
    )
    learning_session_promotes_delivery_mode: bool = True
    learning_default_attempt_cooldown_seconds: int = 0
    learning_pacing_default_open: bool = True

    @field_validator(*LEARNING_POLICY_SHAPES, mode="before")
    @classmethod
    def _learning_policy_value(cls, value: object, info) -> object:
        return validate_learning_policy_value(info.field_name, value)

    @model_validator(mode="after")
    def _learning_policy_relations(self):
        validate_learning_policy_relations({key: getattr(self, key) for key in LEARNING_POLICY_SHAPES})
        return self

    # User preference defaults are separate from global mail delivery switches.
    # Offline authority is deliberately unconfigured until deployment supplies
    # actual login/effective PAIRS. Product role and name defaults preserve CLI behavior.
    bootstrap_allowed_database_role_pairs: tuple[tuple[str, str], ...] = ()
    bootstrap_role_provisioning: dict[str, str] = Field(
        default_factory=lambda: {"student": "Student", "instructor": "Instructor", "admin": "Administrator"}
    )
    bootstrap_initial_role_slug: str = "admin"
    bootstrap_tenant_is_active: bool = True
    bootstrap_password_min_length: int = 0
    bootstrap_owner_first_name: str = "Admin"
    bootstrap_owner_last_name_template: str = "{tenant_name}"

    @field_validator(*BOOTSTRAP_POLICY_KEYS, mode="before")
    @classmethod
    def _bootstrap_policy_value(cls, value: object, info):
        return validate_bootstrap_policy_value(info.field_name, value)

    account_initial_is_active: bool = True
    account_initial_profile_status: str = "active"

    @field_validator(*INITIAL_IDENTITY_POLICY_KEYS, mode="before")
    @classmethod
    def _initial_identity_policy_value(cls, value: object, info) -> bool | str:
        return validate_initial_identity_policy_value(info.field_name, value)

    account_avatar_max_bytes: int = 1048576
    account_email_results_default: bool = True
    account_email_digest_default: bool = True

    @field_validator(*PROFILE_POLICY_SHAPES, mode="before")
    @classmethod
    def _profile_policy_value(cls, value: object, info) -> int | bool:
        return validate_profile_policy_value(info.field_name, value)

    # IANA zone for instructor-entered wall-clock times (sessions/timetables).
    academy_timezone: str = "Africa/Lagos"
    # Compatibility defaults live only in the product Settings/env layer.
    authentication_max_failed_logins: int = 5
    authentication_lockout_minutes: float = 15

    @field_validator(*AUTHENTICATION_POLICY_SHAPES, mode="before")
    @classmethod
    def _authentication_policy_value(cls, value: object, info) -> int | float:
        return validate_authentication_policy_value(info.field_name, value)

    # Self-service password CHANGE only; separate from reset and creation.
    password_change_min_length: int = 8

    @field_validator(*PASSWORD_CHANGE_POLICY_SHAPES, mode="before")
    @classmethod
    def _password_change_policy_value(cls, value: object, info) -> int:
        return validate_password_change_policy_value(info.field_name, value)

    # Account reset only; preserve the historical reset minimum by default.
    password_reset_min_length: int = 8
    password_reset_token_minutes: float = 120.0

    @field_validator("password_reset_min_length", mode="before")
    @classmethod
    def _password_reset_minimum(cls, value: object) -> int:
        return validate_password_reset_min_length(value)

    # Invitation issuance/acceptance purposes. Compatibility defaults live here.
    # Compatibility default lives only in product Settings/environment.
    entrance_invitation_deadline_days: int = 7

    @field_validator(*ENTRANCE_INVITATION_POLICY_KEYS, mode="before")
    @classmethod
    def _entrance_invitation_policy_value(cls, value: object) -> int:
        return validate_entrance_invitation_deadline_days(value)

    invitation_token_hours: float = 168.0
    invitation_password_min_length: int = 8
    invitation_human_replace_outstanding: bool = True
    invitation_stranded_replace_outstanding: bool = False
    invitation_onboarding_replace_outstanding: bool = True
    admission_enrollment_initial_role: str = "student"
    admission_enrollment_initial_status: str = "active"

    @field_validator(*ADMISSION_ENROLLMENT_POLICY_KEYS, mode="before")
    @classmethod
    def _admission_enrollment_policy_value(cls, value: object, info) -> str:
        return validate_admission_enrollment_policy_value(info.field_name, value)

    bulk_enrollment_initial_role: str = "student"
    bulk_enrollment_initial_status: str = "active"
    invitation_enrollment_initial_status: str = "active"

    @field_validator(*ENROLLMENT_INITIAL_STATE_POLICY_KEYS, mode="before")
    @classmethod
    def _enrollment_initial_state_policy_value(cls, value: object, info) -> str:
        return validate_enrollment_initial_state_policy_value(info.field_name, value)

    onboarding_enrollment_global_role: str = "student"
    onboarding_task_catalog: tuple[tuple[str, str], ...] = (
        ("entrance_assessment", "Complete the entrance assessment"),
        ("confirm_details", "Confirm your enrolment details"),
        ("orientation", "Review the programme orientation"),
    )

    @field_validator(*ONBOARDING_POLICY_KEYS, mode="before")
    @classmethod
    def _onboarding_policy_value(cls, value: object, info) -> object:
        return validate_onboarding_policy_value(info.field_name, value)

    @field_validator(*INVITATION_PURPOSE_POLICY_SHAPES, mode="before")
    @classmethod
    def _invitation_purpose_policy_value(cls, value: object, info) -> int | float | bool:
        return validate_invitation_purpose_policy_value(info.field_name, value)

    # Product-owned role mapping; preserve historical invitation behavior by default.
    invitation_member_role_map: dict[str, InvitationMemberRole] = Field(
        default_factory=lambda: {"admin": "instructor", "instructor": "instructor"}
    )
    invitation_default_member_role: InvitationMemberRole = "student"

    @field_validator("invitation_member_role_map", mode="before")
    @classmethod
    def _invitation_role_mapping(cls, value: object) -> dict[str, InvitationMemberRole]:
        return validate_invitation_member_role_map(value)

    @field_validator("invitation_default_member_role", mode="before")
    @classmethod
    def _invitation_role_default(cls, value: object) -> InvitationMemberRole:
        return validate_invitation_default_member_role(value)

    # Web chosen-password creation only; compatibility defaults are product settings.
    web_account_creation_role_admission: dict[str, tuple[str, ...]] = Field(
        default_factory=lambda: {
            "student": ("instructor", "admin"),
            "instructor": ("admin",),
            "admin": ("admin",),
        }
    )
    # Zero preserves the existing web entrypoint's absence of a strength minimum.
    web_account_creation_password_min_length: int = 0

    @field_validator("web_account_creation_role_admission", mode="before")
    @classmethod
    def _web_account_role_admission(cls, value: object) -> dict[str, tuple[str, ...]]:
        return validate_web_account_creation_role_admission(value)

    @field_validator("web_account_creation_password_min_length", mode="before")
    @classmethod
    def _web_account_password_minimum(cls, value: object) -> int:
        return validate_web_account_creation_password_min_length(value)

    # Complete role catalog provisioning, distinct from which actors may assign roles.
    web_account_creation_role_provisioning: dict[str, str] = Field(
        default_factory=lambda: {
            "student": "Student",
            "instructor": "Instructor",
            "admin": "Administrator",
        }
    )

    @field_validator("web_account_creation_role_provisioning", mode="before")
    @classmethod
    def _web_account_role_provisioning(cls, value: object) -> dict[str, str]:
        return validate_web_account_creation_role_provisioning(value)

    lab_command_timeout_seconds_by_action: Annotated[dict[str, int], NoDecode] = Field(
        default_factory=lambda: {"inspect": 60, "deploy": 900, "destroy": 420, "check": 480}
    )
    lab_operation_lease_seconds_by_kind: Annotated[dict[str, int], NoDecode] = Field(
        default_factory=lambda: {"deploy": 1200, "destroy": 600, "check": 600}
    )
    lab_operation_max_attempts_by_kind: Annotated[dict[str, int], NoDecode] = Field(
        default_factory=lambda: {"deploy": 3, "destroy": 5, "check": 3}
    )
    lab_operation_retry_delay_seconds: int = 5
    lab_worker_poll_interval_seconds: int = 5
    lab_restart_reclaim_lock_timeout_seconds: int = 5
    lab_operation_unknown_lease_seconds: int = 600
    lab_operation_unknown_max_attempts: int = 3
    lab_process_termination_grace_seconds: int = 5

    @field_validator(*LAB_EXECUTION_POLICY_SHAPES, mode="before")
    @classmethod
    def _lab_execution_value(cls, value: object, info):
        return validate_lab_execution_value(info.field_name, value)

    @field_validator(*LAB_CAPACITY_KEYS, mode="before")
    @classmethod
    def _lab_capacity_value(cls, value: object, info):
        return validate_lab_policy_integer(info.field_name, value)

    @model_validator(mode="after")
    def _lab_execution_relations(self):
        LabExecutionPolicy.from_settings(self)
        return self

    # Lab orchestration (Increment 2).
    max_concurrent_labs: int = 20
    # 0 inherits the global limit. A distinct positive value is an explicit
    # fairness policy for any future multi-tenant deployment.
    max_concurrent_labs_per_tenant: int = 0
    lab_workdir: str = "/home/dotmac/labs"
    # Containerlab and Docker execution is permitted only on the lab host.
    lab_host_role: str = "web"
    # Dedicated continuous-worker identity. Never reuse the migration/superuser
    # DSN for the long-running worker or reconciler.
    lab_worker_database_url: str = ""
    lab_idle_minutes: int = 60
    # Learner-facing command evidence and DNS actual excerpts (historical sizes).
    lab_check_evidence_chars: int = 160
    lab_check_dns_actual_chars: int = 120

    @field_validator("lab_check_evidence_chars", "lab_check_dns_actual_chars", mode="before")
    @classmethod
    def _lab_check_output_limit(cls, value: object) -> int:
        return validate_lab_check_output_limit(value)

    # Address the app DIALS to reach a lab console. Same-host deployments keep the
    # loopback default; when the lab worker runs on a separate KVM host, set this
    # to that host's private/tunnel address (e.g. its WireGuard IP).
    lab_console_host: str = "127.0.0.1"
    # Address ttyd BINDS when this process spawns a console. Deliberately a
    # SEPARATE knob from ``lab_console_host``: on the app host the dial address is
    # REMOTE, and ttyd cannot bind an address the local host does not own — it
    # retries the bind forever at 100% CPU and never listens. Empty means "same as
    # ``lab_console_host``", which is correct on a single-host deployment and on
    # the lab host itself, where the tunnel address IS local.
    lab_console_bind_host: str = ""
    # Port probed on the lab host for the academy_lab_host_up health gauge.
    lab_host_probe_port: int = 22

    # GlitchTip (Sentry protocol) error tracking — inert unless BOTH are set.
    glitchtip_dsn: str = ""
    glitchtip_enabled: bool = False
    glitchtip_traces_sample_rate: float = 0.1

    # dotmac_erp training-report push (inert by default — empty URL disables it).
    # On course completion, a signed webhook records the result on the employee's
    # HR record; ERP matches by work email and ignores non-employees.
    erp_webhook_url: str = ""
    erp_webhook_secret: str = ""

    # ERP -> Academy applicant-assessment registration. Inbound and outbound
    # secrets are deliberately different trust directions. The public base URL
    # is used to mint links without trusting the request Host header; allowed
    # return origins are a comma-separated exact-origin allowlist.
    erp_inbound_hmac_secret: str = ""
    erp_assessment_token_secret: str = ""
    erp_inbound_hmac_max_skew_seconds: int = 300
    erp_allowed_return_origins: str = ""
    academy_public_base_url: str = ""

    # Email / SMTP (inert by default — empty smtp_host disables sending).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "Dotmac Academy <academy@localhost>"
    smtp_starttls: bool = True
    management_inquiry_recipient: str = "fiberacademy@dotmac.ng"

    # Prometheus /metrics bearer token. Empty (default) = endpoint disabled.
    metrics_token: str = ""
    metrics_lab_probe_ttl_seconds: float = 30.0
    metrics_lab_probe_timeout_seconds: float = 2.0
    metrics_pipeline_ttl_seconds: float = 60.0

    @field_validator(
        "metrics_lab_probe_ttl_seconds",
        "metrics_lab_probe_timeout_seconds",
        "metrics_pipeline_ttl_seconds",
        mode="before",
    )
    @classmethod
    def _metrics_positive_duration(cls, value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise ValueError("metrics durations must be finite positive numbers")
        try:
            duration = float(value)
        except (ValueError, OverflowError):
            raise ValueError("metrics durations must be finite positive numbers") from None
        if not math.isfinite(duration) or duration <= 0:
            raise ValueError("metrics durations must be finite positive numbers")
        return duration

    # Migration-only authority policy: empty values deny migration entry.
    migration_login_role: str = ""
    migration_effective_role: str = ""

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()


def validate_settings(s: Settings) -> list[str]:
    """Return list of fatal errors (empty if OK). Caller raises if non-empty in prod."""
    errors = validate_kernel_settings(s)
    try:
        LabExecutionPolicy.from_settings(s)
    except ValueError:
        errors.append("Lab execution policy is invalid")
    # Single-tenancy is the kernel's control now (TENANCY=single, which makes it
    # assert at startup that exactly one tenant row exists and bind to it). This
    # repo used to name the slug itself in ACADEMY_TENANT_SLUG; that duplicated
    # an identity the database already holds. Production must still declare the
    # posture, so the requirement moves rather than disappearing.
    if s.is_production and s.tenancy != "single":
        errors.append(
            "TENANCY must be 'single' in production — this is a single-tenant "
            "deployment and the kernel's startup assertion is what enforces it"
        )
    if s.is_production and not s.csrf_enabled:
        errors.append("CSRF_ENABLED must be true in production")
    if s.is_production and not s.rate_limit_enabled:
        errors.append("RATE_LIMIT_ENABLED must be true in production")
    if s.rate_limit_requests <= 0 or s.rate_limit_window_seconds <= 0:
        errors.append("rate-limit request and window values must be positive")
    if s.max_concurrent_labs <= 0:
        errors.append("MAX_CONCURRENT_LABS must be positive")
    if s.max_concurrent_labs_per_tenant < 0:
        errors.append("MAX_CONCURRENT_LABS_PER_TENANT must be zero or positive")
    lab_role = s.lab_host_role.lower()
    if lab_role not in {"web", "lab"}:
        errors.append("LAB_HOST_ROLE must be 'web' or 'lab'")
    elif lab_role == "lab":
        if not s.lab_worker_database_url:
            errors.append("LAB_WORKER_DATABASE_URL is required when LAB_HOST_ROLE=lab")
        else:
            try:
                worker_role = make_url(s.lab_worker_database_url).username
            except Exception:
                worker_role = None
            if worker_role != "academy_lab_worker":
                errors.append("LAB_WORKER_DATABASE_URL must authenticate as academy_lab_worker")
    if s.is_production and s.smtp_host and not s.smtp_starttls:
        errors.append("SMTP_STARTTLS must be true when SMTP is configured in production")
    if s.erp_inbound_hmac_max_skew_seconds <= 0:
        errors.append("ERP_INBOUND_HMAC_MAX_SKEW_SECONDS must be positive")
    if s.erp_inbound_hmac_secret:
        if not s.erp_assessment_token_secret:
            errors.append("ERP_ASSESSMENT_TOKEN_SECRET is required when ERP inbound integration is enabled")
        if not s.erp_allowed_return_origins:
            errors.append("ERP_ALLOWED_RETURN_ORIGINS is required when ERP inbound integration is enabled")
        if not s.academy_public_base_url:
            errors.append("ACADEMY_PUBLIC_BASE_URL is required when ERP inbound integration is enabled")
        if s.erp_webhook_secret and s.erp_inbound_hmac_secret == s.erp_webhook_secret:
            errors.append("ERP inbound and outbound HMAC secrets must be distinct")
    if s.is_production and s.academy_public_base_url and not s.academy_public_base_url.startswith("https://"):
        errors.append("ACADEMY_PUBLIC_BASE_URL must use HTTPS in production")
    return errors
