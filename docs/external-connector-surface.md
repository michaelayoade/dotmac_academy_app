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

## Historical baseline

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

The initial measurement above is historical. Main PR #178 introduced the
explicit transitional two-file checkpoint baseline before Learning extraction.
That copied table describes main at that checkpoint; it does not describe the
subsequent D1 measurement. Immediately before this ERP change, the pinned
classifier measured `app/maintenance/checkpoint_transition.py::_CheckpointTransition`
and `app/models/erp_completion_checkpoint.py::ERPCompletionCheckpoint`, rather
than the model and sender paths shown in the historical table.

The independently reviewed D1 measurement on 2026-10-28 is **three**
`sync_checkpoint` source files: those same maintenance and model files, plus
`app/services/erp_sync.py::ERPCheckpointInvariantError`. The added exception has
only a docstring body; the pinned class-name rule counts it because its name
contains `Checkpoint`. It enforces refusal when an imported completion loses
its checkpoint. This explicit baseline reconciliation adds no durable store,
transport or credential. The maintenance source is unchanged. All other
category baselines remain as shown above.

### Current measured baseline — 2026-10-28

| Category | Baseline | Files behind it |
| --- | ---: | --- |
| `outbound_transport` | 3 | `app/services/email.py`, `app/services/erp_assessment_sync.py`, `app/services/erp_sync.py` |
| `webhook_surface` | 0 | — |
| `provider_credential` | 3 | `app/config.py`, `app/services/email.py`, `app/services/settings_store.py` |
| `connector_task` | 0 | — |
| `sync_checkpoint` | 3 | `app/maintenance/checkpoint_transition.py`, `app/models/erp_completion_checkpoint.py`, `app/services/erp_sync.py` |
| `delivery_retry` | 0 | — |

D1 retains the connector debt, with raw acknowledgement custody in a005 and candidate
progress/imported-key custody in a011. Learning owns completion state; Academy's
offline ERP sender owns only its delivery markers. Transport ownership has not
moved to Integrator. Its eventual handoff must preserve acknowledgements and
replace this sender through reviewed command/receipt contracts.

## Conserved exclusion

`app/web/labs.py::_proxy_http` holds a real `outbound_transport` finding. The
central reachability derivation currently removes that module through the
assembly chain, so schema 9 publishes and requires this exact conservation
record instead of silently subtracting it:

`2c328231a93ddd1bd861da9a32a325523d176432dca6b3706b87589717c4ad06`

Re-reviewed on 2026-09-19 for the lab-worker ownership cutover. The proxy
implementation itself is unchanged; the fingerprint moved because the module's
runtime imports changed when direct `ContainerlabEngine` execution was removed
from the web tier and replaced by durable operation enqueueing. The conserved
surface remains the same authenticated, tenant/instance-owner-gated console
reverse proxy, not a newly accepted connector or broader egress path.

This is not a claim that the proxy is test code or harmless. If reachability
changes, the fingerprint changes, or the surface is deleted, the conservation
ratchet fails until this record is reviewed in the same change.

Re-reviewed for D1's current-main integration on 2026-10-28. The bounded WebFig
POST bridge retains canonical tenant, owner and entitlement checks and Kernel
a107's signed, session-bound CSRF validation, including production Host cookies.
Origin proof uses the ASGI scheme, request bodies are capped, and device cookie
names/paths and redirects remain confined. Encoded-dot and malformed redirects
are refused. Text/JavaScript root-path rewriting streams with bounded overlap;
binary bodies remain unchanged. Response validators for rewritten bytes are
removed. Only response read timeout is unbounded for WebFig notification polls;
connect, write and pool acquisition remain bounded. Live browser/CSP proof and
the separately authorized Kernel a108 release/pin remain production gates.

Six exact conserved test findings in `tests/web/test_webfig_proxy.py` accompany
the runtime transport: `test_post_jsproxy_passes_through`,
`test_learner_credentials_not_forwarded_and_device_cookie_confined`,
`test_device_redirects_stay_inside_prefix`,
`test_javascript_root_redirect_stays_inside_console_prefix`,
`test_upstream_down_is_502`, and
`test_signed_proxy_rewrites_stream_and_drops_stale_validators`.
The pinned Governance engine derives them through their in-memory fake upstream
fixture. Independent review verified that derivation and the whole-module
fingerprint `2958fc7c69a21568e8583e400ba63730ccda9bd239ac56a53aecd6e436da3603`.
They add no production connector or baseline increase.

The pinned clean-candidate derivation also proves
`tests/services/test_erp_sync_contract.py` test-only. Its fake classes
`_AbsentCheckpoint` and `_LostImportedCheckpointSession` yield two conserved
`sync_checkpoint` findings through that same class-name rule. Both are declared
with the independently verified whole-module fingerprint
`104ecada6f5e6cbdf55461fff29413c587c4caef0c55c64dd45e93a311ce867a`.
They introduce no runtime checkpoint or connector.

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
