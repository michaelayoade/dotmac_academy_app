# Enrollment initial-state Settings composition (source only)

Academy owns compatibility defaults in Settings/environment only:
`bulk_enrollment_initial_role=student`, `bulk_enrollment_initial_status=active`,
and `invitation_enrollment_initial_status=active`. Every field requires an exact
builtin string of at most 20 Unicode characters. Empty and whitespace strings
remain accepted storage facts; nothing trims, coerces, or restricts vocabulary.
Stored Settings override environment facts. Stored null/malformed facts, missing
effective keys, no Session, and store failures refuse. Missing stored rows use
valid Settings facts, never owner/ORM/server defaults. DB overrides are merged
before final validation so an unused invalid environment fact cannot mask a
valid DB override.

`roster_policy.bulk_enrollment_policy(db)` pins both facts with one
`effective(require_store=True)` call and returns the future Learning frozen
`BulkEnrollmentInitialState`. It is deliberately not wired in this capsule.
The separate real bulk consumer must establish genuine human context and actual
cohort existence before composing policy, then before track/enrollment writes
pass `initial_state=` to the public Learning bulk owner. Learning rechecks the
cohort, so that extra read is deliberate. The consumer also must pass the
required tenant-bound Academy-profile presence selection; inactive profiles
remain eligible. Policy is a fact supplier, never authority or presence proof.

`AcademyInvitationEnrollmentPolicy` requires the distinct future Learning
`InvitationEnrollmentInitialState`, freshly reconstructs it, and freezes it
alongside the role mapping and fallback. The factory pins all three inputs from
one effective snapshot. The existing private `_invite_locked` context resolves
that policy once before identity/role/token mutation, keeps strict/resend error
ordering, and passes its `initial_state` to every owner assignment. Account-only
invitations do not compose enrollment policy. New rows consume configured status;
existing explicit activation, instructor protection, role updates, descriptions,
track/course choices and transaction boundaries retain their prior semantics.
A repeated invitation may explicitly activate a configured non-active new row.

This source requires the prospective Learning required-policy owner source. The
released a1 distribution is not claimed to export these types or new keywords.
Learning owns exact-type and fresh validation before DB access. The bulk and
invitation types are distinct from each other and from admission state. No
release, installation, runtime, test execution or full retirement qualification
is claimed. The added tests are hosted-only canaries. Local evidence is limited
to stdlib AST/hash/source checks and the expressly pinned Ruff checker.

The partial base already supplied `.env.example`; its existing bytes are
preserved as a prefix and the three entries are appended. The base manifest is
`049e7cb8378db19f18137c9c50bb6e24cd59331dd23dba434e3b723b7e6137d3`.
