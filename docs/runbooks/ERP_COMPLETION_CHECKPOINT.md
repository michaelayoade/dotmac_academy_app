# D1 ERP checkpoint custody

This is the candidate source contract, not permission to migrate production.
Hosted qualification, a reviewed canonical convergence pin and the separate
production gates must complete before runtime adoption or sender rollout.

Learning owns `mod_learning.course_completions`. Academy owns
`academy_erp_completion_checkpoints`, keyed by tenant and completion. Historical
a005 copies every raw acknowledgement, including NULL, after genuine capture;
its immutable bytes and inert privileges remain unchanged. Candidate a011 adds
a nullable progress marker without inventing an acknowledgement or zero marker.

The imported-completion membership table is independent of the checkpoint and
references the canonical completion. Its initial keyset comes only from the
genuine guarded transition, after exact original key/ACK conservation. Runtime
code never reconstructs it from surviving checkpoints. A missing checkpoint for
an imported key refuses before INSERT or HTTP, including after restart and for
original NULL acknowledgements. A genuine new nonmember completion can initialize
its checkpoint lazily. Real owner deletion may remove both product references;
resurrecting deleted identities is not an authorized recovery procedure.

All sender instances must be drained before adoption so the protected key/ACK
cut cannot move. The existing offline admin session remains the sole delivery
marker writer. No request, platform or lab-worker membership DML is granted;
the migration is the sole membership initializer. Services flush within their
caller's transaction and do not commit. Preserve accepted markers when recovering
from failures; do not reactivate a displaced Learning writer.

Main's legacy 0065 progress and 0066 checkpoint migrations are a different
populated predecessor. The current D1 entry refuses that lineage and the
pre-existing destination. Do not drop it, clear markers, change version rows or
copy table shape to force admission. A separately reviewed custody entry is
required. Main's 0066 downgrade is not a D1 rollback procedure.

Before qualification, rehearsals use disposable caller-owned roots and finish
with rollback. D1 assembly downgrades refuse; committed recovery needs a reviewed
forward-compatible plan preserving every accepted fact. Genuine migration
execution, full catalog/data checks, final callback verification and independent
hosted failure/restart/concurrency tests remain the evidence boundary.
