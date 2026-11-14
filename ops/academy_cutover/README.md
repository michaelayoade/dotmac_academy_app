# Academy cutover code

This directory holds the operational helper source that is copied byte for byte
into a reviewed, protected campaign packet. `SOURCE_FILES.sha256` records the
published source bytes. Campaign inputs must pin those same bytes; a successful
test run does not supply deployment authority or prove a complete live census.

Private manifests, approvals, observations, receipts, authentication profiles,
vendor fixtures and launch inputs are kept outside this repository. The isolated
hosted workflow uses only synthetic data and locked public test tools. It has no
application, database, SSH or private-fixture credentials.

Tests run only in hosted CI. Use static inspection and linting during local
preparation. The test configuration excludes the application's root fixtures and
plugins, and the default test boundary refuses network and process creation.

The stdin-delivery regression has one explicit exception: a closed adapter runs
a fixed, isolated Python child in hosted CI. It checks retained file input across
a deliberate wait timeout. Other process and network calls remain denied. Its
test subject contains stream functions without operational host configuration;
this qualification does not establish private campaign or live host readiness.

The discovery collector retains hash-only systemd relationship endpoints and
separate final installed/loaded inventories. Matching reads describe limited
observational stability; they do not establish sender classification, an
operational fence, or a complete activation graph. Unknown objects remain
unresolved. The process proof stays at v2, and the census reducers continue to
refuse completion while the remaining domain adapters are unfinished.

Relationship list parsing decodes one quoting layer emitted by systemctl for
string arrays. Native unit-name escapes remain literal bytes: `\x2d` is not
converted to `-`. The accepted list representation is an unquoted name without
backslashes, or a complete double-quoted name with each native backslash doubled.
Scalar `Id` and `Unit` properties remain unquoted native bytes. Malformed or
noncanonical representations remain unresolved. Endpoint order, duplicates and
original output projections are retained.

Graph facts v2 bind the explicit `AcademySystemdEndpointProfile.v1` and its hash.
The limits are 4,096 decoded attempts per field, 8,192 per unit/read, 65,536 in
each of the initial and repeated passes, and 131,072 overall. The passes have
separate allowances. Each unit listing and the retained graph records remain
capped at 8,192 rows; the union of observed listings can be larger. Malformed
and duplicate attempts consume the same endpoint limits; retained hashes are counted
separately. Exhaustion stops decoding and marks any unparsed tail without
asserting that the tail contains valid endpoints. An offending field remains
invalid and retains no endpoint hashes.

Historical graph facts v1 keep their original interpretation. These endpoint
limits do not establish complete acquisition, activation or authority coverage;
activation semantics and the other domain adapters still require implementation
and qualification. Other command, file and deadline
limits remain separate.

Report v2 adds an exact 256 MiB captured-payload budget across command stdout,
file and proc reads, and sized link reads, including rejected bytes and declared
overflow probes. This measures captured payload, not filesystem metadata I/O or
process memory. Retention admission bounds each record to 2 MiB and ordinary
record JSON to 46 MiB. A separate 16 MiB reserve belongs exclusively to template
definition evidence; metadata and framing have 1 MiB, for a 63 MiB normal report.
Derived listing-row projections retain their historical JSON encoding.

The complete report is sealed before delivery. Encoding or retention failures
can produce a distinct bounded failure envelope with no domain evidence;
delivery failures never append a second document. Historical v1 reports retain
their closed schema. Consumers must distinguish normal v2 reports from failure
envelopes; false authority flags alone do not establish successful collection.

Report v3 and resource profile v2 separate ordinary filesystem work (16,384),
definition work (262,144), and their cumulative ceiling (278,528). Reserved
definition cleanup work is reported separately. The ordinary counter retains the
earlier file-attempt accounting; definition work charges its filesystem operations,
iterator advances and descriptor cleanup. Payload and output byte limits
stay unchanged. Historical normal and failure envelopes retain their closed
schemas; campaign consumers must explicitly adopt the new contract.

Runtime graph facts v3 bind a v255 relation catalogue covering the manager's
exported unit-name relationships and raw scalar `Following`. The catalogue
distinguishes start, event, ordering, precondition, propagation and membership
relations, including symmetric namespace joins. Path-valued properties and
conditional activation defaults remain explicit unresolved requirements rather
than fabricated unit endpoints. Endpoint and report budgets stay unchanged.

Effective definitions use the manager's ordered search paths and an explicit root
profile. Targets include units actually seen in either installed/loaded inventory
pass and abstract templates in the lookup map, bounded to 1,024 targets before
any selected body reads. Other unobserved ordinary units and concrete instances
are not invented. Failed or changed membership boundaries remain incomplete.
These inventories precede source acquisition; they do not bracket every body read.
The legacy `systemd_template_definitions` domain key now carries versioned
effective-definition evidence. Historical template facts remain supported.

The collector resolves effective fragments, aliases, masks, drop-ins and
dependency directories, then reads only selected unit sources. Two passes compare
source identities, hashes and manager state. Referenced credentials, environment
files and executable bodies are not read; unprofiled linked targets remain
unresolved. Abstract instance-dependent relations remain symbolic.

Fully captured root inventories supply immediate candidate-directory absence
evidence. Present candidate directories are scanned once per pass; the cache is
discarded before the next pass. Alias work has a separate aggregate attempt limit
and checks cancellation and the deadline. Candidate selection charges its own
attempt limit before directory construction, duplicate checks and cached or absent
lookup returns. Definition limits include 1,536 selected
paths, 3,072 body-read records, 8,192 relations and the existing 16 MiB domain
reserve. A larger inventory or exhausted budget remains incomplete.

The definition domain separates complete selected-source acquisition from
activation semantics. It never supplies a sender classification or authority
reference. Its own work, file, body, relation and encoded-evidence limits remain
distinct from the collector's cumulative resource guards. Both must be integrated
and qualified in the campaign packet before host use.
