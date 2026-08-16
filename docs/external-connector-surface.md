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
| `sync_checkpoint` | 0 | — |
| `delivery_retry` | 0 | — |

`outbound_transport` covers the HTTP deliveries to ERP and Academy's SMTP
delivery. `provider_credential` counts identifiers only; no secret value is
read or recorded by the detector.

## Conserved exclusion

`app/web/labs.py::_proxy_http` holds a real `outbound_transport` finding. The
central reachability derivation currently removes that module through the
assembly chain, so schema 9 publishes and requires this exact conservation
record instead of silently subtracting it:

`a3838b848c3a881e35d9cac84fd38e7b5c7924c9b564c59ce8f8ed34341a478d`

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
