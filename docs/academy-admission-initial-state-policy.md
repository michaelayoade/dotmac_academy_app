# Admission enrollment initial state — source-only increment

This capsule targets the future Learning public contract
`AdmissionEnrollmentInitialState(role_in_cohort: str, status: str)` and the
required keyword `ensure_admission_enrollment(db, command, *, initial_state)`.
Released Learning a1 is immutable and does not contain this API. There is no
installed compatibility claim or fallback to the old signature.

Settings and environment contain the only admission compatibility defaults:
`admission_enrollment_initial_role=student` and
`admission_enrollment_initial_status=active` (uppercase environment names).
Both are registered known string settings. A stored row overrides the environment;
an absent row uses Settings. Stored null, malformed values, store read failure,
a missing required database session, or a missing effective key refuse admission.
The values must be built-in strings with at most 20 Unicode characters. Empty,
whitespace, and unrecognized strings remain exact: the existing String(20) schema
has no role/status enumeration or CHECK. No trimming or invented enum is applied.

The factory uses `effective(require_store=True)` and constructs one frozen public
Learning state. Shared `_enroll_locked` composes it once after the existing
status/tasks/cohort/intake guards and validation of an existing identity, before
new identity or enrollment writes. Automatic bearer completion and explicit
administrative enrollment use that path. No form, browser, or API argument can
choose this state; it supplies no human authority or global role grant.

An eligible admission now requires valid configuration even when Learning will
reuse an existing enrollment. This is an explicit new configuration refusal.
Learning ignores the configured role/status for existing rows and preserves all
fields except the established track update. No additional public enrollment
lookup or mutable callback was added. Newly inserted rows receive the snapshot's
actual role/status. A configured instructor/dropped row remains dropped; it does
not obtain an instructor global grant. The account cohort-name reader includes
all states; the course entitlement reader requires active enrollment.

The existing bearer/private-context proof, Party → Applicant → Task lock order,
task-before-eligibility behavior, savepoint including welcome enqueue, False
versus fatal enqueue handling, credentials, separately configured global role,
tokens, audits, root revalidation, and every-exit clearing remain intact. The
V2 automatic path composes its existing global-role and invitation policies
immediately after shared admission returns and before any global grant or token
effect. Each snapshot is composed once. This preserves intake and existing-target
guard priority even when admission settings are also malformed. Later global-role
or token policy refusal rolls back the preceding task, identity, enrollment, and
transition-audit effects inside the same savepoint. There is no hardcoded enrollment
role/status postcondition. Policy is local to `_enroll_locked`, never retained in
the private context. A failure after task completion rolls back the task and
any owned effects even when the caller catches the exception and commits.

Hosted tests are authored, not run. They cover Settings/environment boundaries,
actual store writes/reads/deletion and null refusal, immutable snapshots,
DB-over-env precedence, read failure, missing keys/session, configured new rows
and genuine readers, mid-operation settings mutation, existing enrollment
preservation, and caught-outer-commit rollback. Existing regression names and
assertions are retained, with owner-call wrappers ported to the required keyword.
V2 adds both-invalid automatic intake/target priority, pre-DML refusal with valid
guards, and later-policy failure after actual admission followed by caught outer
commit. Only local stdlib AST/hash checks and pinned Ruff source checks are authorized.

Still owed: independent source review; canonical whole fixture and complete
assembly; legacy admin/assessment audit bridges and the full unskipped zero-admin
regression; future Kernel33 and Learning release/install, migrations, RLS/ACL and
audit composition; full HTTP qualification. This increment does not remove
Enrollment ORM/server defaults or close bulk/invitation policy. A prospective
Learning migration, remaining writer policies, constructor census, and complete
hosted qualification remain necessary. No release, activation, deployment, or
full business-default retirement is claimed.
