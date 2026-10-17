# Academy ERP completion checkpoint transfer

0062 is product preparation only. It moves delivery acknowledgements into
`academy_erp_completion_checkpoints`; learning completion fields and timestamps
stay unchanged. The sender alone lazily creates and locks checkpoints; its caller
owns commit. The legacy column is frozen in application code, not protected from
an administrative database role. Admissions assessment delivery is unchanged.

Before rollout, stop admission of every ERP completion sweep/manual sender and
drain their transactions. Apply 0062 online with a migration role able to inspect
all FORCE-RLS rows. It locks completions, copies every row (including unfinished
and NULL acknowledgements), verifies exact keys and NULL-safe timestamps, and
refuses RLS-filtered inspection. Deploy the checkpoint sender before resuming.
Mixed old/new senders are unsafe: old senders still write the legacy snapshot.
Qualify the full hosted PostgreSQL migration/service/RLS/concurrency suite before
any separately authorized production operation.

For application reversal, stop and drain senders again. Downgrade 0062 online
before starting old code. Both tables are locked; current checkpoint facts are
copied directly back to existing completion rows without changing `updated_at`.
Legacy NULL to checkpoint non-NULL is legitimate new delivery. A conflicting
legacy non-NULL acknowledgement, a missing checkpoint for such a row, or an
orphan checkpoint refuses reversal and leaves the table intact. New completions
without checkpoints and with legacy NULL remain unsynced. Investigate conflicts
against durable receiver evidence; never delete checkpoints or coalesce NULLs
to force a downgrade. Rehearse recovery before proceeding.

Later learning-module cutover must retain this product table and rebind its
completion foreign key after the module import; never cascade-delete delivery
facts during retirement. Restore **all** new module completions before reversing
checkpoint references or restoring the old learning tables.

The v1 email payload, raw-body HMAC and explicit recorded/updated/duplicate ACK
classification remain unchanged here. They do not satisfy ADR 0004's stable
`employee_ref` identity boundary. Mapping qualification, the ERP receiver fix and
v2 reconciliation remain separate unfinished work. This is neither module
adoption nor identity/runtime/production cutover evidence.
