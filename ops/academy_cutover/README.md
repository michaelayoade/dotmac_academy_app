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
