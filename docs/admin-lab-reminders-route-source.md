# Admin home, lab administration and reminder route source

This independent source candidate copies every file and mode from the closed
370-file paired recipient/audit/labs source, with independent inodes. It restores
admin_home, lab_admin and reminders_admin plus the Academy reminder policy owner.
No runtime, installed package, factory closure or physical migration is qualified.

## Ownership and behavior

Admin people counts use canonical tenant Party + PartyPerson without active or
Academy-profile predicates. Course and cohort counts reuse the public Learning
all_courses and instructor_cohort_choices reads (including drafts/inactive rows).
Live lab counts and the monitor remain Academy LabInstance facts. The monitor
uses bounded tenant/id-filtered canonical contact batches and preserves inactive
people without product profiles. Missing contacts retain the historical inner
join behavior. Its override POST calls the existing Academy assessment adapter;
no assessment engine or Learning storage is restored.

Six public Learning reminder fact reads replace the historical direct Learning
ORM queries in their existing occurrence order. The public
active_student_person_ids_select relation supplies the enrollment population;
Academy retains canonical account availability, reminder occurrence keys/copy,
preferences, quiet hours, digests, ReminderLog, notifications and outbox writes.
History preserves tenant, kind, status, search/count and paging semantics.
Historical inactivity/quiet-hour/config defaults are retained; no new Learning
policy, table, notification framework or migration is introduced.

Reminder resend requires a genuine Request and fresh cookie account, tenant,
purpose policy and canonical grants. Public Kernel identity_storage primitives
lock all participating Party rows in UUID order before subtype/profile/session,
roles/grants and the target ReminderLog. Authority/policy refresh follows blocking
stages and follows audit/outbox flush. A public Kernel conflict_savepoint encloses
the command, and the caller owns root commit. The historical resend key precision,
email payload and ledger semantics remain unchanged. Canonical public
write_audit_event records only the authenticated party and fixed event-kind detail;
reminder.resend is registered by an actual FeatureManifest composed into web and
migration owners. No caller actor UUID or generic legacy audit writer authorizes
the command. Existing generic app.services.audit retirement remains separate work.

## Access configuration

Settings alone declares the historical defaults for three independent validated
policies: admin_home_access_roles, lab_admin_access_roles and
reminders_admin_access_roles. DB-over-env access policy accepts custom slugs,
empty lists deny, malformed values including stored NULL refuse. These policies
are separate from Settings, teaching and search access. The .env.example labels
are the only presentation/config additions; no historical UI template, static
asset or original copied test bytes are changed. Existing literal status sets and
occurrence/audit names are fixed storage/protocol identities.

## Evidence and remaining qualification

The three historical templates, empty-labs image and three historical test files
are copied byte/mode exactly from the pinned 951-file historical snapshot. All
370 parent files are preserved except explicitly listed owned modifications;
all prior tests remain byte exact. New hosted canaries exercise actual routers,
canonical cookies/grants, public Learning facts, all-person counts, historical
contacts, reminder detection/idempotence/digests/root rollback, actual resend
outbox/audit receipts, post-write policy refusal and a real Party-lock wait with
grant withdrawal. Only the policy-change injection runs after the real audit
writer to prove command rollback; no owner or authorization read is mocked away.
All tests are AUTHORED, NOT RUN. Only stdlib AST/hash and pinned Ruff are run here.

Future Kernel identity storage and public Learning source dependencies remain
UNALLOCATED/UNRELEASED. Published package floors do not qualify those future APIs.
Canonical Party FKs on ReminderLog/ReminderPreference/notifications require future
a004 physical adoption. Installed owner registry, actual hosted fixtures, runtime,
full factory composition, source retirement, release and adoption remain pending.
No local imports, runtime, tests, SQL, type checks, builds, installs or Docker run.
