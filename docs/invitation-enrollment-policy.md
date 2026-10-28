# Invitation enrollment policy

Academy configures the global-role to cohort-role mapping through
`Settings.invitation_member_role_map` (`INVITATION_MEMBER_ROLE_MAP`, a JSON
object) and `Settings.invitation_default_member_role`
(`INVITATION_DEFAULT_MEMBER_ROLE`). Both accept only `student` or `instructor`
as member-role values. The documented Settings defaults map global `admin`
and `instructor` to cohort `instructor`; every other global role maps to cohort
`student`. These are configurable product defaults, not shared Learning rules.
An empty map is valid and routes all roles through the configured default.

The same two keys in `platform_settings` override environment configuration.
Missing rows use Settings values; malformed JSON, invalid roles, NULL policy
values, missing sessions and unreadable stores refuse. Stored JSON mappings also
reject duplicate keys. Environment complex-value JSON decoding is performed by
the installed Pydantic Settings source before field validation; duplicate-key
normalization there follows that dependency's JSON decoder. A policy
factory uses `effective(db, require_store=True)` and snapshots both validated
inputs into an immutable policy. Errors do not interpolate configuration values.
Deleting a stored key restores the configured environment value. Invalid writes
are rejected before settings writes. Existing unrelated settings and the strict
password-reset policy retain their prior behavior.

For nonempty assignments, `invite_and_enroll` resolves this policy once after
required-email validation and before Person, global-role, credential or
invitation effects. Account-only invitations with no assignments do not read
the unused enrollment policy. Its public signature and callers stay unchanged. The
private assignment adapter passes the same session, tenant/person/cohort UUIDs,
optional track, ordered course UUIDs including duplicates, and unchanged global
role to public `ensure_invitation_enrollment`, with required `role_policy`.
Learning owns enrollment, unconditional instructor preservation, activation,
track offering effects and course offering effects. Academy retains identity,
role eligibility/grants, credential/invite lifecycle and description strings.

Roster authority still comes from the existing product boundaries:
`accounts.users_invite` checks the authenticated admin role before passing true;
`instructor.invite_to_cohort` resolves `_is_admin` for the authenticated person;
`lifecycle.invite_user` supplies no assignments, so its explicit authority value
is inert. A boolean is not independent authorization proof. Mapping a role does
not authorize a caller or grant a global role. No new route or login policy is
introduced. Existing route authentication/authorization remains required.

The caller owns the transaction and rollback on any failure. The adapter does
not begin, commit, roll back or open a session. Learning retains caller autoflush,
the existing track-owner flush/order and a pending role change before a refused
non-student reactivation. Translated domain refusals preserve message and cause;
unexpected and transaction-change errors propagate. Product descriptions retain
reactivation notes, instructor-preservation text and course order/duplicates.

This source capsule is not installed adoption, publication or local-module
retirement. Hosted CI must exercise the actual composed release and canonical
Kernel Party/PartyPerson fixtures. Existing database canaries still refer to
legacy mapped Academy classes; their identity-map assertions do not prove parity
after canonical identity adoption. Genuine authenticated authority/grant locks,
whole-account savepoint integration, canonical identity/FK migration, and full
credential API adoption remain the identity lane's gates. Legacy auth remains
frozen here. No runtime tests were run locally.
