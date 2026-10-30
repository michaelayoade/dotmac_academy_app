# Reminder caller transaction V3 source candidate

This independent 393-file child preserves all 391 V2 paths and every existing
test byte/mode. Only reminder_resend.py and reminder_resend_unit.py are adapted;
this document and one hosted caller-transaction canary file are new. Root's
reviewed plan is /private/tmp/academy-reminder-caller-transaction-v3-plan-20261019.md,
SHA256 19ced9718a3472948091efbe74d9d8e054bb9ac09283108eea8751028fc31884.
Source review and authored tests do not qualify runtime behavior.

## Fixed command custody

The helper records the actual caller logical root/all nested ancestors, physical
root/all savepoint predecessors, original Connection and DBAPI identity before
entering the public Kernel conflict helper. Already-materialized associations
come from SQLAlchemy's actual SessionTransaction._connections records;
after_begin supplies subsequent exact associations. Pairs are never inferred
from matching names or the current savepoint. Caller-owned lazy nesting and
new post-return Session/Connection nesting remain native.

Exact registered logical/physical methods dispatch through bounded completion
frames naming operation, entry, target and descendants. No ambient owner flag
permits another operation. ACTIVE participant completion is refused before the
original method. Kernel release consumes its actual public claim once; helper
recovery permits only the genuine rollback/close cascade. Ordinary caller root
and nested release/abort entries, transaction context exits and conservative
single-statement driver SELECTs are supported after return. Raw transaction SQL,
comment/separator disguises and active participant driver SQL are refused.

## Fixed epochs and actual recovery

Each successful command has a sealed ordered receipt: exact fixed log/outbox/
audit expectations, authority closure, original caller ancestor identities and
pre-command values/absence for its fixed effects. Promotion follows successful
actual helper exit. Folding uses table/primary-key identities, so a later
command may supersede a log expectation while preserving independent earlier
outbox/audit receipts. Actual nested abort requires physical outcome and logical
cleanup, verifies restored scalar facts against sealed predecessors/absence,
then retires only contained epochs. Helper failure verifies the original fixed
inventories before restoring previous receipts. Observed current rows never
become replacement expectations. Missing/falsey email, exact actual outbox bool/
identity/defaults/provenance, all log fields, audit attribution/cardinality and
unrelated-row protections from V2 remain enforced.

## Final completion fence and authorized driver interception

Success validation checks dirty ORM state before no-autoflush fresh authority
reads. An SQL generation records later work; after_flush_postexec validates while
the Session is ACTIVE. Immediately before actual physical commit, fixed scalar
reads use the captured Connection (not Session.execute from PREPARED). Expired
fields use recorded dirty state plus scalar reads, without lazy loading. The
frame then seals; later callback SQL is refused before effect.

Root additionally authorized a narrow dialect.do_commit dispatch keyed by exact
registered physical DBAPI identity. This final pre-driver latch checks poison,
frame/binding identity, fixed dirty state and the last validated SQL generation
after all Connection commit listeners, including a listener that catches its own
denied SQL attempt. It delegates original dispatch for unrelated connections.
This is an implementation interception, not a new transaction authority/API.
Independent V3 review must specifically assess it. Failed/uncertain physical
completion is never accepted or automatically retried; actual caller abort or
Connection abandonment remains required.

Class/driver registry mutation uses a short process-local lock; no lock spans
original methods, database work or callbacks. Cleanup unregisters exact handler
identities and restores an instance attribute only if this unit's wrapper is
still current. Later caller wrappers are not clobbered; an ended chained guard
passes through to its captured original. Actual root acceptance/abort releases
receipts, Request closures, row and transaction references. Independent Sessions
share no permission frame. Concurrent use of the same Session is unsupported.

## Hosted verification and limits

The new file retains all four reviewer invocation scenarios and their original
assertions. Parameterized genuine command canaries cover root completion/abort
families, active participant completion surfaces, two pre-existing ancestors,
post-return nesting/native begin errors, predecessor restoration and failed
second commands, fake/failed physical recovery, dirty/Core/before-commit/flush/
late-caught-listener mutations, control SQL, rebinding and independent two-tenant
Sessions with actual committed admin readback and patch-safe cleanup. Existing
V1/V2 no-email, replay, owner receipt and transaction canaries remain byte exact.
All hosted canaries are AUTHORED NOT RUN. Only stdlib AST/hash and authorized
pinned Ruff execute locally; no imports, runtime/tests, SQL, type checks,
build/install, Docker, network shell or external mutation.

SQLAlchemy ancestry, transaction state and event order are pinned source
contracts from the plan and still require hosted installed verification. This
bounded boundary does not claim protection against arbitrary malicious Python
replacing internals, cached pre-patch methods, raw DBAPI access or arbitrary SQL
function effects. Future Kernel/Learning owner sources remain UNALLOCATED/
UNRELEASED. a004 physical FKs, canonical hosted fixtures, full factory/installed
execution, adoption, source retirement and release remain unqualified.
