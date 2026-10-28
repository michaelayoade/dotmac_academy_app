# Prepared canonical human invitation boundaries

This source capsule prepares human issuance and resend. It does not install an
assembly, audit registry, package, migration, or runtime adapter. Hosted tests
are authored and have not run.

`invite_web_account` requires a fresh current admin cookie and retains the UI's
student/instructor/admin selection. `invite_web_cohort_account` requires a fresh
instructor/admin cookie and assigns student. `resend_web_account_invitation`
requires admin. The strict generic `invite_and_enroll` and `invite_user` wrappers
require real admin authority and preserve existing custom global roles; the
latter conflicts atomically when any credential exists. No caller boolean, actor
UUID, ORM Person, or DB access alone establishes human authority.

The operation locks all existing actor/target Parties in deduplicated UUID order
before subtypes, product profiles, role catalog/grants, exact HMAC-cookie session,
complete target credentials/policies, and invitations. It refreshes target
resolution after waits and refuses a changed target without taking a late Party
lock. Actual post-wait clocks and current actor status/grants/session prove each
write boundary. Targets may remain suspended or inactive. Returned account views
are immutable and retain their genuine UUID, names, status, and activation state.

Existing credentials still permit invite-and-enroll role/enrollment updates but
produce no activation token. Admin resend with existing credentials is read-only.
Issuance never hashes or creates credentials. Global role provisioning reuses
`web_account_creation_role_provisioning`; UI admission also consumes the existing
`web_account_creation_role_admission`. Provisioning is additive and never renames
custom roles. Generic existing-custom-role admission remains distinct from UI
standard-role closure. Learning owns cohort/course/track facts and enrollment
commands; the product retains selection errors and description/email formatting.

The explicit context manager keeps identity, roles, Learning, invitation tokens,
actual material-free user audit, and durable email enqueue in one public
`conflict_savepoint`. Enqueue exceptions roll back every family; enqueue `False`
remains an ordinary response. The existing email body, activation URL, and
`account-invite:{person_id}:{hash_token(token)}` idempotency format remain product
owned. Raw tokens are repr-hidden delivery material and never enter audit or HTML
summaries. The prepared `FeatureManifest` in `app/invitation_declarations.py`
declares `account.invitation.completed`; future registry enrollment is required.
No registry is installed by these files.

Business defaults exist only in Settings and `.env.example`:

- `INVITATION_TOKEN_HOURS=168`: strict finite native timedelta hours. Explicit
  zero, negative, or fractional values are honored; datetime range overflow
  refuses. Helper `None` means the configured value, never a truthiness fallback.
- `INVITATION_HUMAN_REPLACE_OUTSTANDING=true`: consumes every previous unused
  invitation, including expired invitations, while preserving used history.
- `INVITATION_STRANDED_REPLACE_OUTSTANDING=false`: separately prepared policy for
  the unported stranded-account provenance; no human behavior is imposed on it.
- `INVITATION_PASSWORD_MIN_LENGTH=8`: strict positive acceptance-purpose minimum,
  distinct from creation, reset, and password change. The acceptance factory is
  prepared; claim route/template wiring belongs to a separate source capsule.

The fixed protocol uses 32 random bytes encoded as hex and the existing HMAC64
store format. Purpose identifiers, privilege predicates, and entropy are not
settings.

The original account-invitation tests retain all fifteen scenarios. Canonical
fixture ports replace legacy Person reads with genuine Party/subtype/profile
records and caller booleans with real cookie/grant setup. Necessary assertion
normalizations replace mutable-object identity with UUID/fields/immutability,
nonprotocol mock token text with deterministic 64-hex entropy, unproved custom-role
actor booleans with actual admin authority, and fake single-flush traces with
canonical staged persistence checks. These changes are itemized in the proof.

Unported lifecycle, CLI, admissions/onboarding, stranded reengagement, claim/reset,
status/role/create/password handlers, and their original test cohorts remain
explicit gates. Legacy boolean/ORM-only invitation calls fail closed; they are
not compatibility authority shims. In particular, old lifecycle invitation ports
must adopt the strict wrapper before any retirement claim. Canonical token a003
catalog/FK qualification, complete app_user fixture, installed Kernel/Learning
floors, action enrollment, and all participating principal-first writers remain
required. Presence in this source capsule is not installed retirement evidence.
