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
template definitions, remaining relations and the other domain adapters still
require implementation and qualification. Other command, file and deadline
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
