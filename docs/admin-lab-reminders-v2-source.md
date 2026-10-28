# Reminder resend V2 source correction

This new independent snapshot preserves every original 388-file candidate path
and every original test byte/mode. Only reminder_resend.py is adapted; a private
fixed command custody helper and new hosted canaries are added. No historical
UI/static, route policy, Learning owner or generic audit framework changes.

The private helper binds the actual caller Session/root, Connection/physical
root and DBAPI identity, and the exact public Kernel conflict savepoint. It
intercepts completion on those actual objects before dispatch, latches swallowed
attempts, checks SQLAlchemy Connection events and rejects raw participant SQL.
Slotted SQLAlchemy physical transaction methods use private exact-object class
 dispatch: unregistered transactions always call original methods, and cleanup
 removes every registration/reference. This is needed to block completion before
 the transaction object itself deactivates; Connection events alone run later.
 The public helper lifecycle authorizes only its own release/recovery. Command
failure recovers its savepoint; damaged recovery holds the exact root for caller
rollback. Successful fixed receipts and fresh request policy remain pinned until
the original caller root ends, including before final commit. Root-end cleanup
restores methods, removes Connection listeners, and releases Request/row refs.
Repeated genuine resend commands in the same caller root retain earlier pins.

A missing/falsey historical contact email refuses before effects; no account
eligibility policy is added. The command verifies genuine enqueue bool against
actual row provenance, exact tenant/key/recipient/kind/message/payload, native
new-outbox defaults, unchanged pre-existing rows and exact audit delta. It
verifies every target ReminderLog column, allowing only status/outbox_key/sent_at
and its normal update timestamp. The timestamp uses the same sampled command
instant explicitly so no unrelated timestamp mutation can hide in that field.
Persisted scalar reads detect Core UPDATE changes; dirty ORM values are checked
before refresh. Only fixed outbox/audit inserts and the reminder update are
permitted during participant work; unrelated reminder rows are also preserved.

The independent review's three actual invocation canaries are integrated into a
new file, with additional Session/Connection/root/savepoint caught-completion,
after-return dirty target, genuine caller commit and same-root idempotent resend
canaries. All original assertions are retained. Tests are AUTHORED NOT RUN.
Only stdlib AST/hash and the pinned Ruff binary execute locally. No application
imports/runtime/tests/SQL/type/build/install/Docker/network-shell execution.

Future Kernel transaction/identity and Learning owner sources remain
UNALLOCATED/UNRELEASED. a004 physical FKs, hosted canonical fixture/runtime,
installed factory closure, adoption and retirement remain unqualified.
