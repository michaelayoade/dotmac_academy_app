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
