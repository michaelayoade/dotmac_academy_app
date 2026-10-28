# Academy's direct external-connector surface

Academy adopts the Governance-owned schema-9 ratchet from accepted ADR 0011 at
the immutable canonical-main commit
`4f6fbf98c25f7cfbb3dacc4f3d2f5fd7e473f193`.

The rule inventories and freezes measured legacy connector surfaces while they
move behind Dotmac Integrator. It is defence in depth, not runtime isolation:
deployment policy must ultimately remove provider credentials and external
egress from Academy regardless of how connector code is written.

Academy does not declare measurement roots and does not copy the detector. The
Governance engine derives the universe from Git-tracked Python, proves
test-only reachability centrally, and reports every untracked Python file as an
error.

## Accepted baseline

Measured on 2026-08-16 with the accepted schema-9 engine: 156 tracked Python
sources measured, 207 proven test-only sources excluded, no syntax errors.
Measured-source digest:
`f73c638a4397ac8aa9d80f2be0237692030549bc9028b24d1137f9078cdc96dd`.

| Category | Baseline | Files behind it |
| --- | ---: | --- |
| `outbound_transport` | 3 | `app/services/email.py`, `app/services/erp_assessment_sync.py`, `app/services/erp_sync.py` |
| `webhook_surface` | 0 | — |
| `provider_credential` | 3 | `app/config.py`, `app/services/email.py`, `app/services/settings_store.py` |
| `connector_task` | 0 | — |
| `sync_checkpoint` | 2 | `app/models/erp_completion_checkpoint.py`, `app/services/erp_sync.py` |
| `delivery_retry` | 0 | — |

`outbound_transport` covers the HTTP deliveries to ERP and Academy's SMTP
delivery. `provider_credential` counts identifiers only; no secret value is
read or recorded by the detector.

### Transitional checkpoint amendment (2026-10-28)

PR #178 takes the explicitly documented narrow, human-approved transition path
for separating ERP acknowledgement facts from learning completion before the
learning-module extraction. The two measured sources above are the complete
schema-9 finding: the Academy-owned checkpoint model and its sole sender/writer.
This is a deliberate debt-register increase, not a rename, an exclusion, or a
claim that transport ownership has moved to Dotmac Integrator.

The checkpoint preserves every historical acknowledgement and gives reversal a
lossless source while completion storage moves. It remains transitional: the
Integrator handoff must replace the direct sender with versioned command and
receipt contracts, preserve these facts, and lower this baseline in the same
reviewed cutover. Production rollout remains separately authorized.

## Conserved exclusion

`app/web/labs.py::_proxy_http` holds a real `outbound_transport` finding. The
central reachability derivation currently removes that module through the
assembly chain, so schema 9 publishes and requires this exact conservation
record instead of silently subtracting it:

`7692b24602b10a7d4c006f251d41e48c34f1550b17651a691c7d3c9ebdbc6ec4`

Re-reviewed on 2026-09-19 for the lab-worker ownership cutover. The proxy
implementation itself is unchanged; the fingerprint moved because the module's
runtime imports changed when direct `ContainerlabEngine` execution was removed
from the web tier and replaced by durable operation enqueueing. The conserved
surface remains the same authenticated, tenant/instance-owner-gated console
reverse proxy, not a newly accepted connector or broader egress path.

This is not a claim that the proxy is test code or harmless. If reachability
changes, the fingerprint changes, or the surface is deleted, the conservation
ratchet fails until this record is reviewed in the same change.

## Review rule

A count rising fails. A count falling also fails until the profile and this
record are lowered in the same change. Every reduction must show either:

- deletion of the measured client, credential, callback, task, checkpoint or
  retry surface; or
- cutover to a named connector distribution behind Dotmac Integrator, with the
  versioned observation, command or receipt contract that replaced it.

Zero means only that the accepted detector saw zero measured spellings. It
does not prove that Academy lacks external connectivity. The ratchet reaches
its sunset only with ADR 0011's runtime package, secret, egress, ingress and
inbox/outbox conditions.
