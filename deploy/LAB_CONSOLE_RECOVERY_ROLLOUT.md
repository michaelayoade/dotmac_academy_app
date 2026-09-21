# Academy lab-worker rollout and console-recovery smoke

This runbook records the order and evidence required to move the Academy lab
control plane to a revision containing migrations 0055–0060 and worker console
recovery. It grants no production, SSH, database, secret, or deployment
authority. The operator must use explicitly named hosts and the approved
OpenBao-backed `academy_lab_worker` credential; never place its value in this
file, a command line, logs, or shell history.

## Preconditions

- The exact source revision is merged and its required hosted checks are green.
- The non-owning `academy_lab_worker` role exists with ADR-0008's attributes,
  no memberships or owned objects, and only migrations 0055–0060's grants.
- `LAB_WORKER_DATABASE_URL` is materialized from its approved OpenBao pointer.
- The web and lab hosts, rollback owner, maintenance window, and database
  backup/restore point are named in the change record.
- No old worker or reconciler may run while migration 0060 and its matching
  code are introduced.

## Read-only lab-host preflight

Before changing services, capture the exit status—not unrestricted output—of:

```text
sudo -n containerlab inspect --all --format json
```

Using a known Academy lab, verify the real output has the shapes consumed by
`ContainerlabEngine`: the lab name maps to node entries carrying `name`,
`ipv4_address`, and `kind`, and the reported topology path matches the configured
Academy lab work directory. A missing/mismatched path is a refusal, not an
invitation to weaken ownership checks. Stop if the host's JSON shape differs.

Also verify the accepted checkout revision, Poetry 2.4.1, `containerlab`,
`ttyd`, `/dev/kvm` when required, the local console bind address, database
backup, worker role posture, and current migration head. Do not print the DSN.

## Synchronized update

1. Stop and disable the reconcile timer for the maintenance window; stop any
   running reconciler service and the continuous worker.
2. Confirm no worker or reconciler process remains. Do not kill learner
   containerlab runtimes; they are the state this rollout must preserve.
3. Update the checkout to the accepted revision and run `deploy/install.sh`.
4. Apply migrations through 0060 with the migration/offline identity. Migration
   0055 deliberately refuses if the dedicated worker role is absent.
5. Install/refresh both worker and reconciler units from the same checkout and
   run the systemd daemon reload.
6. Start the continuous worker, then enable/start the reconcile timer. Never run
   an old worker beside a new reconciler or vice versa.

## Smoke evidence

- Before installation, record the checkout's immutable accepted commit SHA.
  After installing the units, verify systemd's effective `WorkingDirectory`
  and `ExecStart` for both point into that exact checkout, and verify the
  checkout still resolves to the recorded SHA. After the continuous worker
  starts, also verify its live `MainPID` resolves to that directory. The
  reconciler is a short-lived `Type=oneshot` unit, so require a successful
  post-verification invocation/result rather than a live PID. The services do
  not emit a source revision themselves. The role/host fail-closed checks must
  pass and no second worker may acquire the singleton lock.
- A queued test lab deploys, reaches `runtime_presence=present`, and exposes a
  working Linux-node console. Check, reset, and destroy settle their operations.
- Capacity deferral, same-host previous-epoch reclaim, attempt ceilings, and a
  conditional repair no-op behave as recorded in the operation ledger.
- For one active multi-node test lab, record the healthy ttyd node/port set,
  terminate one ttyd process, and wait one worker poll. The missing Linux node
  receives a new working port, healthy node ports remain unchanged, RouterOS
  nodes remain console-free, and the next poll makes no further change.
- Run one reconciler pass and verify no unrelated runtime, console, status, or
  error projection changes. Capture only redacted counts/statuses.

## Rollback

Before stopping the compatible worker, quiesce new lab-operation submissions
using the change record's named traffic-control procedure and let every open
conditional intent drain. Verify the following read-only count is zero:

```sql
SELECT count(*)
FROM lab_operations
WHERE state IN ('queued', 'claimed')
  AND runtime_precondition IS NOT NULL;
```

Then stop worker and reconciler and repeat that verification. Migration 0060's
downgrade deliberately refuses when this count is nonzero; do not improvise a
manual settlement. If a conditional intent appears after stop, restore the
compatible worker and investigate before retrying. Only then roll migrations
back to the revision understood by the code being restored, restore both units
from that same revision, and restart them together. If safe rollback cannot be
proved, leave services stopped and restore from the named database recovery
point rather than mixing versions.

## Retire web-host authority last

Only after the two-host smoke is accepted may the web host lose containerlab,
Docker/KVM lab access, lab-worker credentials, and related sudo authorization.
Verify the old reaper/worker units are disabled and absent there. The lab host's
worker remains the single runtime executor; SMTP/web/application processes do
not become fallback lab writers.
