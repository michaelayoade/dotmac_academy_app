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
docker ps --quiet | wc -l
```

Using a known Academy lab, verify the real output has the shapes consumed by
`ContainerlabEngine`: the lab name maps to node entries carrying `name`,
`ipv4_address`, and `kind`, and the reported topology path matches the configured
Academy lab work directory. A missing/mismatched path is a refusal, not an
invitation to weaken ownership checks. Stop if the host's JSON shape differs.

Also verify the accepted checkout revision, Poetry 2.4.1, `containerlab`,
`ttyd`, `/dev/kvm` when required, the local console bind address, database
backup, worker role posture, and current migration head. Do not print the DSN.

## Install the lab-host IPv6 ingress guard

Install and verify the host guard before stopping the old worker or changing
the application checkout. It is a separate root-operated boundary; do not add
it to `deploy/install.sh`, activate UFW, or let a root unit execute files from
the `dotmac`-writable checkout.

1. Verify the named host is exactly `academy-labs`, and record the exact
   `systemctl is-enabled`, `systemctl is-active`, and `systemctl show -p
   SubState` results for `ufw.service`, `nftables.service`, and
   `firewalld.service`. The accepted live baseline is UFW enabled and
   `active (exited)` while `ufw status` reports inactive, nftables
   disabled/inactive, and firewalld absent. The UFW service state only records
   that its oneshot boot loader ran; `ufw status` is the policy-state check.
   Any different state is a stop condition. Also require TCP listeners on
   ports 22 and 5437 to be the expected SSH and observed runtime processes. A
   changed listener owner is a stop condition.
2. After recording that baseline, run
   `sudo systemctl disable --now ufw.service`, require the unit to become
   disabled/inactive, and require `ufw status` to remain inactive. Then run
   `sudo systemctl mask ufw.service nftables.service firewalld.service` and
   require all three to report masked. Reconfirm IPv4 SSH before installing
   the guard. Repeat the bounded `containerlab inspect` command and running
   Docker-container count from preflight; require the command to succeed and
   the count to be unchanged. The masks prevent a later controller start from
   replacing the owned rules while the guard is authoritative; Docker remains
   an independent runtime rule writer.
3. Set `ACCEPTED_SHA` to the immutable revision approved for this rollout.
   Require `git rev-parse HEAD` to equal it, and require both
   `git diff --quiet` and `git diff --cached --quiet` for all three guard assets.
   Install the bytes from that Git object—not from the mutable worktree—as
   root-owned copies. Run the staging block in Bash with fail-fast pipeline
   handling so a missing blob can create at most an empty temporary file and
   can never replace an installed guard:

   ```text
   export ACCEPTED_SHA=<full-approved-commit-sha>
   bash -euo pipefail -c '
     test "$(git rev-parse HEAD)" = "${ACCEPTED_SHA}"
     git diff --quiet "${ACCEPTED_SHA}" -- deploy/academy-lab-ipv6-guard.nft deploy/academy-lab-ipv6-guard.service deploy/academy-lab-ipv6-guard-docker.conf
     git diff --cached --quiet "${ACCEPTED_SHA}" -- deploy/academy-lab-ipv6-guard.nft deploy/academy-lab-ipv6-guard.service deploy/academy-lab-ipv6-guard-docker.conf
     git cat-file -e "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard.nft"
     git cat-file -e "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard.service"
     git cat-file -e "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard-docker.conf"
     staging_dir="$(mktemp -d)"
     trap '\''rm -rf -- "${staging_dir}"'\'' EXIT
     git show "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard.nft" >"${staging_dir}/academy-lab-ipv6-guard.nft"
     git show "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard.service" >"${staging_dir}/academy-lab-ipv6-guard.service"
     git show "${ACCEPTED_SHA}:deploy/academy-lab-ipv6-guard-docker.conf" >"${staging_dir}/academy-lab-ipv6-guard-docker.conf"
     sudo install -d -o root -g root -m 0755 /etc/nftables.d
     sudo install -d -o root -g root -m 0755 /etc/systemd/system/docker.service.d
     sudo install -o root -g root -m 0644 "${staging_dir}/academy-lab-ipv6-guard.nft" /etc/nftables.d/academy-lab-ipv6-guard.nft
     sudo install -o root -g root -m 0644 "${staging_dir}/academy-lab-ipv6-guard.service" /etc/systemd/system/academy-lab-ipv6-guard.service
     sudo install -o root -g root -m 0644 "${staging_dir}/academy-lab-ipv6-guard-docker.conf" /etc/systemd/system/docker.service.d/academy-lab-ipv6-guard.conf
     read -r expected_nft_sha _ < <(sha256sum "${staging_dir}/academy-lab-ipv6-guard.nft")
     read -r installed_nft_sha _ < <(sudo sha256sum /etc/nftables.d/academy-lab-ipv6-guard.nft)
     read -r expected_unit_sha _ < <(sha256sum "${staging_dir}/academy-lab-ipv6-guard.service")
     read -r installed_unit_sha _ < <(sudo sha256sum /etc/systemd/system/academy-lab-ipv6-guard.service)
     read -r expected_dropin_sha _ < <(sha256sum "${staging_dir}/academy-lab-ipv6-guard-docker.conf")
     read -r installed_dropin_sha _ < <(sudo sha256sum /etc/systemd/system/docker.service.d/academy-lab-ipv6-guard.conf)
     test "${expected_nft_sha}" = "${installed_nft_sha}"
     test "${expected_unit_sha}" = "${installed_unit_sha}"
     test "${expected_dropin_sha}" = "${installed_dropin_sha}"
   '
   ```

4. Compare the SHA-256 of each installed artifact with `git show` of the same
   path at `ACCEPTED_SHA`; refuse on either mismatch. Then run
   `sudo nft --check --file /etc/nftables.d/academy-lab-ipv6-guard.nft`, then
   run `sudo systemctl daemon-reload`,
   `sudo systemctl enable academy-lab-ipv6-guard.service`, and then
   `sudo systemctl restart academy-lab-ipv6-guard.service`. The explicit
   restart reapplies an updated artifact even when the oneshot unit was already
   active. The unit first ensures its otherwise empty owned table exists (and
   ignores only that idempotent create command's status), so the same atomic
   destroy/recreate batch works on first boot and later restarts. Its lack of
   `ExecStop` keeps the old table present until nft's atomic owned-table
   replacement succeeds. The Docker drop-in is a start-only gate:
   it refuses a future Docker start unless the guard and both chains exist, but
   it does not make a later intentional guard stop propagate to running learner
   containers.
5. Require `systemctl is-active academy-lab-ipv6-guard.service` to report
   `active`; a host/path assertion failure is a refusal. Inspect only the owned
   table with `sudo nft list table inet academy_lab_ipv6_guard` and confirm
   both the prerouting and input rules are present. Repeat the bounded
   `containerlab inspect` command and Docker-container count once more; require
   success and the original count before treating the guard as applied.
6. Reconfirm IPv4 SSH and outbound IPv6, then prove both IPv6 ingress layers
   independently. Record read-only counter values before and after each test;
   do not reset counters or mutate either firewall. From an explicitly named,
   off-network IPv6-capable host, attempt new TCP connections to ports 22 and
   5437. Neither may connect, and both attempts must increase the exact,
   uniquely labeled Garki-core edge rule counter
   `SEC-IPv6-20260921 deny unsolicited new to Dotmac-Labs`. Because that
   upstream `/128` forward-drop consumes the packets, these attempts are not
   expected to increase either counter in the Dotmac Labs host guard. A local
   `no route` result is inconclusive and does not prove the edge layer.
7. Without disabling, deleting, flushing, replacing, or otherwise changing
   the Garki-core edge rule, exercise the Dotmac Labs host guard through an
   explicitly named safe directly connected or router-originated IPv6 path.
   The path must reach the lab host while leaving the edge rule enabled. New
   TCP attempts to port 22 must fail and increase the host `input` counter;
   new TCP attempts to port 5437 must fail and increase the host `prerouting`
   counter. For this recorded Dotmac Labs topology, absence of either expected
   layer is a stop condition; refuse any ambiguous result and never treat one
   layer's counter as proof of the other. A separately documented single-layer
   topology must name and prove its applicable direct counter. ICMPv6 and
   established return traffic remain permitted, and retain the existing IPv4
   and outbound-IPv6 checks.

The guard deliberately matches any local IPv6 destination instead of the
current SLAAC `/128`, so a VM address change cannot silently bypass the host
boundary. Garki-core's separate `/128` defense-in-depth rule must still be
reconciled when the VM address changes.

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

To remove only the host ingress guard, leave the rules active while detaching
it from boot, then delete its uniquely owned table explicitly:

```text
sudo systemctl disable academy-lab-ipv6-guard.service
sudo rm /etc/systemd/system/docker.service.d/academy-lab-ipv6-guard.conf
sudo systemctl daemon-reload
sudo systemctl stop academy-lab-ipv6-guard.service
sudo nft delete table inet academy_lab_ipv6_guard
sudo rm /etc/systemd/system/academy-lab-ipv6-guard.service
sudo rm /etc/nftables.d/academy-lab-ipv6-guard.nft
sudo systemctl daemon-reload
sudo systemctl unmask ufw.service nftables.service firewalld.service
sudo systemctl enable --now ufw.service
```

Verify the guard service is inactive, the named table is absent, and IPv4
management remains available. The final `enable --now` restores the
specifically recorded UFW unit state: enabled and `active (exited)`, while
`ufw status` must remain inactive. Also require nftables to be
disabled/inactive and firewalld to be absent after unmasking. If any recorded
state differed, stop rather than guessing how to restore it. Do not delete,
flush, or replace any other nftables, iptables, Docker, or UFW state.
Garki-core's edge rule remains in place during this rollback.

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
