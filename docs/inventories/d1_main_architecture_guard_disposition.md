# D1 disposition of main's identity/autogenerate architecture guard

Source: `tests/architecture/test_kernel_identity_autogenerate_gate.py` at immutable
main commit `201cf4bfb701c1ee5deb98c9b77dd4b21b299905`. D1 base for this
reconciliation: `120f07a6c5ff477ae71dade0ca936b2a83c00cd7`.

The main guard protects the pre-cutover Academy identity schema. D1 adopts
installed Kernel a107 identity and Learning owners through the explicit
historical/fresh adoption programme. Retaining `people`, `person_roles`,
`user_credentials.person_id`, or a pre-facet Kernel pin would contradict that
programme. This reconciliation transfers the protective properties to actual
D1 ownership and ordinary migration entry. It does not relax a baseline or
authorize production adoption, schema changes, or Kernel a108.

## Assertion disposition

| Immutable main assertion or detector | D1 disposition and executable evidence |
| --- | --- |
| `test_academy_still_owns_its_declarative_base` | Already retained by `tests/test_canonical_model_ownership.py::test_legacy_identity_mappings_and_constructor_defaults_are_retired`: the retained product Base remains distinct from Kernel Base; identity/Learning facades introduce no local mapped classes. |
| `test_this_gate_watches_the_same_models_autogenerate_does` | Ordinary `alembic/env.py` deliberately has `target_metadata = None` and refuses autogeneration. The replacement guard executes that real environment for both CLI `cmd_opts` and programmatic `RevisionContext` signals, on engine and supplied-connection branches, with database-entry tripwires. Model-module import-name equality is retired because ordinary entry has no autogenerate target. |
| `test_the_autogenerate_target_holds_no_kernel_only_identity_table` | Kernel identity tables are now legitimate declared owners. `test_actual_installed_owner_graph_remains_closed_with_learning_disabled` in the replacement file proves the full installed graph equals declared physical owners, preserves FK targets/actions, and resolves every copied FK to the exact copied owner column. Existing `test_identity_reference_copies_are_excluded_from_product_ownership` excludes copied identity references from Academy ownership. |
| `test_the_shared_identity_tables_keep_their_academy_shape` | The pre-cutover `person_id` shape is intentionally retired. Existing `test_legacy_identity_mappings_and_constructor_defaults_are_retired`, `test_retained_cross_metadata_targets_and_actions`, and `test_checkpoint_owns_erp_markers_and_references_canonical_completion` in `tests/test_canonical_model_ownership.py` verify actual canonical objects, product extensions, and target identity. The replacement guard does not recreate legacy columns. |
| `test_no_migration_creates_a_kernel_only_identity_table` | Canonical Kernel migrations legitimately create their owned identity tables. `tests/test_ordinary_migration_graph.py::test_graph_commands_have_complete_config_and_bindings_before_env` verifies complete installed migration locations and excludes the legacy versions directory from ordinary entry. `test_all_62_frozen_history_bytes_are_conserved_in_complete_hosted_source`, `test_frozen_fixture_inventory_is_exactly_the_62_historical_files`, and `test_legacy_successors_are_only_pinned_custody` preserve exact historical/custody bytes. |
| `test_no_migration_drops_an_academy_owned_identity_column` | The old deny-list describes the fallback schema and is retired as a current-model invariant. The frozen-history checks above prevent changing those historical migrations. Protected adoption retains separate lossless-copy/rollback evidence in `tests/test_academy_identity_history.py`, including `test_same_root_lossless_policy_alias_and_json_null_copy` and `test_extension_fault_rolls_back_canonical_audit_and_every_policy_row`. Those PostgreSQL checks remain hosted qualification, not a claim made by this local source reconciliation. |
| `test_the_kernel_pin_stays_below_the_facet_wall` | The old upper-pin assertion is superseded by the implemented C1.1 facet. `tests/architecture/test_academy_web_facet.py::test_single_staff_admin_facet_at_root`, `test_authentication_profile_is_tenant_cookie_session`, `test_admission_permission_owned_by_academy_and_bound_to_standard_roles`, and `test_registry_yields_one_legacy_surface_with_exact_entry_routes` check actual declarations and admission. No synthetic facet-gap predicate or older pin assertion is retained. |
| `test_the_facet_gap_detector_fires_only_on_the_real_combination` and `test_the_assembly_declaration_is_actually_readable` | Their synthetic predicate/AST-reader machinery is retired. The actual facet/registry checks above inspect the constructed declarations. `tests/architecture/test_kernel_runtime_composition.py::test_ci_verifies_the_record_with_its_exact_contract_revision` retains the independently pinned composition verifier wiring; composition-record regeneration remains a separate coordinator responsibility. |
| `test_the_phantom_table_detector_fails_on_a_synthetic_cutover`, `test_the_shape_detector_fails_on_a_synthetic_party_id_swap`, and `test_the_two_forbidden_sets_cannot_be_erased_by_the_offence_they_detect` | The forbidden-set algorithms target the retired identity shape. Existing `test_normalized_duplicate_owners_are_refused_before_copy`, `test_unresolved_and_unowned_foreign_key_targets_are_refused`, `test_legacy_identity_learning_and_module_as_kernel_ownership_are_refused`, and `test_unclaimed_shared_base_tables_are_refused` in `tests/test_canonical_model_ownership.py` retain their negative-control purpose. The replacement file additionally removes and duplicates the actual installed Kernel tenant owner, proving rejection against the real graph. |
| `test_the_migration_scanner_is_not_defeated_by_line_wrapping` and `test_the_drop_column_scanner_sees_a_wrapped_destructive_drop` | The legacy scanner itself is retired; exact frozen-history hashes are insensitive to formatting changes, while real ordinary entry refuses autogeneration before producing directives. This does not claim a blanket static ban on future owner migration DDL. New migration changes still require their owner contracts and hosted qualification. |
| `test_the_comparison_tracks_the_installed_kernel_and_is_not_empty` | The replacement owner-graph test reads genuine installed Kernel declarations, Learning manifest tables/platform tables/schema/migration owner, and Academy declarations. It compares exact sets without a numeric baseline. It explicitly disables Learning while retaining its ownership. Existing `tests/test_ordinary_migration_graph.py::test_disabled_owner_still_contributes_exact_location` separately proves disabled owners retain their migration locations. |

## Ordinary-entry fix and validation limits

Programmatic `alembic.command.revision(..., autogenerate=True)` supplies a genuine
`RevisionContext` through `EnvironmentContext` options without CLI `cmd_opts`.
The prior D1 check reached migration authority validation before inspecting that
signal. Ordinary entry now uses public, dialect-only `context.configure()` and
`context.get_context().opts` before any engine, URL selection, or supplied
connection validation. Alembic supports repeated configuration; the existing
online path still configures the actual caller connection and retains its
authority/root-transaction checks. The later defensive check remains.

The new guard also proves non-autogenerate commands still reach the actual
supplied-connection validator and engine-construction boundary. Neither test
opens a connection. Existing real PostgreSQL supplied-root preservation and
authority-denial canaries in `tests/test_ordinary_migration_graph.py` remain
required hosted evidence; they are not replaced by the local boundary checks.

Local targeted validation: 29 passed, two real-PostgreSQL supplied-connection
tests deselected, using an inert nonsecret `DATABASE_URL` solely for lazy engine
construction. JUnit: `/private/tmp/d1-architecture-guard-tests.xml`. No local
Docker, database access, migration execution, or production operation occurred.
