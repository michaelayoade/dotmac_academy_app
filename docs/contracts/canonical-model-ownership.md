# Canonical model ownership source contract

This unactivated source capsule restores declarations absent from the 165-file
baseline. It preserves every baseline byte and file mode, including the closed
account token and identity extensions. It does not change configuration, package
pins, settings, routes, services, migrations, fixture wiring or application startup.

Historical proof is the actual a5 Git tree
`a5ffe6316e97bf33e17ef9c1f00788796f5e5a5a`, tree
`3e5678114a65ad760fa85f3367719a087bbf3b07`. All 31 original model files in
`/private/tmp/learning-delivery-support-source-closure-096` match their captured
Git blob hashes. The 47 historical mappings partition into 27 Learning, eight
legacy Kernel/identity, and 12 retained Academy tables. This count describes the
historical tree, not the size of the future composed canonical Kernel catalog.
The full actual historical migration set has 62 files through 0061; there is no
historical 0062 checkpoint migration.

Learning facades re-export the exact owner class objects from its five installed
model groups. They declare no new ORM classes or constructors and copy no policy
defaults. All 27 Learning mapped class/field names retain their legacy names
except removal of `CourseCompletion.erp_synced_at` from Learning. The five
assessment tables already carried tenant scope; this source reconstructs none.
`app.models.base.Base` remains product-owned and is never rebound to KernelBase.

Canonical Kernel exports replace tenant, authentication, RBAC and audit mappings.
The old Person module contains only retirement documentation. There is no
`Person` alias, legacy people mapping, `PersonRole` shim, or fake canonical field.
Writers must port to Party + PartyPerson and canonical auth/RBAC contracts before
activation. The following current-capsule import sites are explicit remaining
caller gates (the full restored application collection requires an additional
whole-source audit):

- `app/cli.py:421`: `app.models.person` (Person)
- `app/services/admin_reports.py:41`: `app.models.person` (Person)
- `app/services/admin_reports.py:42`: `app.models.rbac` (AuditEvent, PersonRole, Role)
- `app/services/admissions.py:23`: `app.models.auth` (UserCredential)
- `app/services/admissions.py:25`: `app.models.person` (Person)
- `app/services/admissions.py:26`: `app.models.rbac` (PersonRole)
- `app/services/admissions.py:497`: `app.models.rbac` (AuditEvent)
- `app/services/assessment.py:51`: `app.models.person` (Person)
- `app/services/completion.py:107`: `app.models.person` (Person)
- `app/services/identity.py:18`: `app.models.auth` (UserCredential)
- `app/services/identity.py:19`: `app.models.person` (Person)
- `app/services/lab_lifecycle.py:803`: `app.models.person` (Person)
- `app/services/learner_digest.py:26`: `app.models.person` (Person)
- `app/services/roster.py:20`: `app.models.person` (Person)
- `app/services/success_queue.py:17`: `app.models.person` (Person)
- `app/web/account.py:23`: `app.models.person` (Person)
- `app/web/accounts.py:33`: `app.models.person` (Person)
- `app/web/accounts.py:34`: `app.models.rbac` (PersonRole)
- `app/web/instructor.py:40`: `app.models.person` (Person)
- `app/web/instructor.py:41`: `app.models.rbac` (PersonRole, Role)
- `app/web/learn.py:27`: `app.models.person` (Person)
- `app/web/timetable.py:20`: `app.models.person` (Person)

The 12 historical retained tables are account_tokens, applicants, email_outbox,
lab_templates, lab_instances, lab_operations, notifications, onboarding_tasks,
platform_settings, tenant_entrance_defaults, reminder_log and reminder_preferences.
Token adoption is closed and unchanged here. The other ten tenant FKs point to
canonical Tenant columns. Three retained person composites point to canonical
Party (tenant_id, id) with additional PartyPerson (party_id) subtype FKs. The two
Applicant references point to Learning CohortTrack and QuestionBank columns,
preserving default NO ACTION. All previously cascading references still cascade.
All non-FK AST metadata, defaults, columns, indexes, constraints and methods in
the eight retained declaration modules remain identical to historical source.
Internal onboarding -> applicant and lab operation -> instance relationships
remain. Logical lab UUIDs, default_bank_id, applicant.person_id and requested_by
remain without invented FKs.

NEW `academy_erp_completion_checkpoints` is product-owned and contains only
(tenant_id, completion_id) plus raw nullable erp_synced_at. Its tenant and
completion FKs point to canonical owner Column objects. The later genuine a005
must create the new table and copy EVERY legacy completion key and raw timestamp,
including NULL, before commit. No ACK copy, writer, DDL, migration claim or
activation is made here. The older local ERP draft is not historical proof.

The profile and credential-policy tables are additional product candidates already
in the baseline; their copied Kernel tables are references, never ownership.
Inspection composition must assign owners before copying, include every installed
stateful module even when disabled, normalize absent schema to public, copy each
owned physical table once, and reject duplicate owners and unresolved targets.
No inspection metadata is a create_all or DDL destination.

Tests are authored for hosted CI and were not run locally. Local validation is
limited to stdlib AST, hash and mode proofs and the explicitly pinned Ruff binary.
Full installed catalog, all caller ports, migration a004/a005, whole-application
collection and runtime activation are still future gates. Release freeze remains
OPEN and this capsule is neither published nor deployed.

Inspection source consumes the real `ModuleRegistry.startup_order()` manifests
and their `tables`, `platform_tables` and `db_schema` declarations. There is no
model-registration field or loader framework on ModuleManifest. Learning's
actual manifest imports its five groups. Explicit required `kernel_tables`
contains real canonical Kernel Table objects; the inspection entry checks they
belong to KernelBase.metadata in public. `kernel_owned_tables()` registers the
known supported Kernel declaration modules and derives ownership from actual
class defining modules (plus standalone Core Table declarations), never the
entire shared Base. A before-module registration snapshot is usable; when
manifests have already imported modules, defining-module provenance supplies the
partition instead. Unknown shared-Base tables are refused. Actual caller and
ordinary environment/startup wiring remain future gates.

The Kernel API evidence is the seven exact actual-f674 Git blobs captured at
`/private/tmp/kernel-registry-actual-f674-preimages-20261018`, verified by
`capture-verified-v2.json` (SHA256
`03a8424525b6bbb9af9476c8b910b94b36007d3f836a337b8ab2686145adde64`).
The actual reference alembic environment's registration imports and supported
public Kernel model-module declarations provide source evidence only; this
capsule does not import or run that environment.
