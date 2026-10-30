"""No-DB contracts and refusal units; these do not qualify hosted convergence."""

import ast
import hashlib
import inspect
import json
import re
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from dotmac_kernel.migrations import versions_dir as kernel_versions

from alembic.runtime.migration import HeadMaintainer, MigrationContext
from alembic.script import ScriptDirectory
from app.maintenance import checkpoint_transition, lab_claim_lease_transition
from app.maintenance import fresh_product as fresh
from app.migration_graph import ordinary_migration_config

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_TRY_SHA256 = {
    "a004": "cac55181fa70150aa25ac569c796770f90e043791cc0ec39c947083e34926fce",
    "a005": "17b6dcce136dd0d7fbb24027b8c3e80f06669ee4b3fcec6922ab8edf08a90e89",
    "a006": "1df958ddd055f28e324674306bfd60b668274849dba4f11f15d7be16681eeb78",
}


def test_fixed_table_census_matches_actual_declared_owners():
    fresh._owner_contracts()


def test_dependency_cuts_match_alembic_maintained_version_rows():
    scripts = ScriptDirectory.from_config(ordinary_migration_config())
    graph = tuple((r.revision, r.down_revision, r.dependencies) for r in scripts.walk_revisions())
    context = MigrationContext.configure(dialect_name="postgresql", opts={"as_sql": True, "output_buffer": StringIO()})
    heads = ()
    for target in (fresh._A002, fresh._A003, "learning@head", *fresh._STAGES, "heads"):
        maintainer = HeadMaintainer(context, set(heads))
        for step in scripts._upgrade_revs(target, heads):
            maintainer.update_to_step(step)
        heads = tuple(sorted(maintainer.heads))
        if target == "learning@head":
            assert heads == fresh._cut(graph, fresh._STAGES[0], final=False)
            assert heads == (fresh._A003, "lr_0010_question_bank_versions")
        elif target in fresh._STAGES:
            assert heads == fresh._cut(graph, target, final=True)
        elif target == "heads":
            assert heads == fresh._terminal_versions(graph)
            assert set(heads) != set(scripts.get_heads())


@pytest.mark.parametrize("prefix", HISTORICAL_TRY_SHA256)
def test_historical_migration_branch_ast_is_unchanged(prefix):
    (path,) = (ROOT / "alembic/identity_assembly_versions").glob(prefix + "_*.py")
    tree = ast.parse(path.read_text())
    upgrade = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade")
    (historical,) = (n for n in upgrade.body if isinstance(n, ast.Try))
    assert (
        hashlib.sha256(ast.dump(historical, include_attributes=False).encode()).hexdigest()
        == HISTORICAL_TRY_SHA256[prefix]
    )
    dispatch = next(n for n in upgrade.body if isinstance(n, ast.If))
    assert upgrade.body.index(dispatch) < upgrade.body.index(historical)


def _historical_statements(function):
    tree = ast.parse(inspect.getsource(function))
    assignment = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "statements" for t in n.targets)
    )
    return ast.literal_eval(assignment.value)


def test_checkpoint_and_lease_ddl_match_historical_bytes_without_raw_ack_copy():
    historical = _historical_statements(checkpoint_transition._apply_checkpoint_transition)
    assert historical[-1].startswith("INSERT INTO public.academy_erp_completion_checkpoints")
    assert fresh._checkpoint_ddl() == historical[:-1]
    assert fresh._lease_ddl() == _historical_statements(lab_claim_lease_transition._apply_lab_claim_lease_transition)


def test_retained_renderer_builds_keys_before_canonical_foreign_keys_and_limits_insert_columns():
    statements = fresh._retained_ddl()
    tables = [s for s in statements if s.startswith("CREATE TABLE")]
    assert len(tables) == 11
    assert all('CREATE TABLE "public".' in s for s in tables)
    first_fk = next(i for i, s in enumerate(statements) if "FOREIGN KEY" in s)
    assert first_fk == 11
    assert sum("FOREIGN KEY" in s for s in statements) == 20
    assert not any("academy_identity_compat" in s or "IF NOT EXISTS" in s for s in statements)
    assert any('REFERENCES "public"."party_persons" ("party_id")' in s for s in statements)
    assert any('REFERENCES "mod_learning"."question_banks"' in s for s in statements)
    assert not any(s.startswith("INSERT INTO") for s in statements)
    lab_grants = [s for s in statements if s.startswith("GRANT") and '"lab_operations"' in s and '"app_user"' in s]
    assert len(lab_grants) == 2
    assert any('GRANT INSERT ("id", "tenant_id", "instance_id", "kind", "requested_by")' in s for s in lab_grants)
    assert all(not s.startswith("GRANT SELECT, INSERT") for s in lab_grants)


@pytest.mark.parametrize("pin", [None, "", "a" * 63, "A" * 64])
def test_unqualified_entry_refuses_before_creating_state_or_ddl(monkeypatch, pin):
    monkeypatch.setattr(fresh, "FRESH_CANONICAL_SHA256", pin)
    with pytest.raises(fresh.FreshProductUnqualified, match="pin unavailable"):
        fresh.run_fresh_composed_entry(object(), decision_ref="test-decision")
    with pytest.raises(fresh.FreshProductUnqualified):
        fresh.verify_fresh_composed_db(object())


@pytest.fixture
def continuation(monkeypatch):
    root = object()
    connection = SimpleNamespace(info={})
    entry = fresh._Entry(connection, root, ("physical-context",), token_catalog="actual-catalog")
    connection.info[fresh._STATE_KEY] = entry
    monkeypatch.setattr(fresh.identity, "_connection_preflight", lambda conn: root)
    monkeypatch.setattr(fresh.tokens, "_physical_context", lambda conn: ("physical-context",))
    monkeypatch.setattr(fresh.tokens, "_catalog", lambda conn: "actual-catalog")
    return connection, entry


def test_public_constructible_receipt_cannot_issue_continuation(continuation):
    connection, entry = continuation
    counterfeit = fresh.tokens.AccountTokenIdentityReceipt(None, 123, 0, fresh._A003, 3)
    with pytest.raises(fresh.FreshProductRefused):
        fresh.prepare_fresh_product(connection, decision_ref="review-ref", token_receipt=counterfeit)
    assert entry.poisoned


@pytest.mark.parametrize("drift", ["root", "connection", "xid", "catalog", "historical", "token"])
def test_continuity_drift_refuses_and_poison_is_sticky(continuation, monkeypatch, drift):
    connection, entry = continuation
    if drift == "root":
        monkeypatch.setattr(fresh.identity, "_connection_preflight", lambda conn: object())
    elif drift == "connection":
        entry.connection = object()
    elif drift == "xid":
        monkeypatch.setattr(fresh.tokens, "_physical_context", lambda conn: ("other-xid",))
    elif drift == "catalog":
        monkeypatch.setattr(fresh.tokens, "_catalog", lambda conn: "other-catalog")
    elif drift == "historical":
        connection.info[fresh.product._STATE_KEY] = object()
    else:
        connection.info[fresh.tokens._STATE_KEY] = object()
    with pytest.raises(fresh.FreshProductRefused):
        fresh._apply(connection, fresh._STAGES[0])
    assert entry.poisoned
    connection.info.pop(fresh.product._STATE_KEY, None)
    connection.info.pop(fresh.tokens._STATE_KEY, None)
    with pytest.raises(fresh.FreshProductRefused):
        fresh._check(connection, entry)


def test_duplicate_issue_poisons_existing_continuation(continuation):
    connection, entry = continuation
    with pytest.raises(fresh.FreshProductRefused):
        fresh._start(connection)
    assert entry.poisoned


def test_out_of_order_or_replayed_stage_never_executes_ddl(continuation):
    connection, entry = continuation
    entry.prepared = True
    with pytest.raises(fresh.FreshProductRefused):
        fresh._apply(connection, fresh._STAGES[1])
    assert entry.next_stage == 0 and entry.poisoned


def test_fresh_owner_never_commits_stamps_or_uses_orm_ddl():
    tree = ast.parse(inspect.getsource(fresh))
    forbidden = {"commit", "rollback", "create_all", "stamp"}
    assert not any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in forbidden
        for n in ast.walk(tree)
    )


@pytest.mark.parametrize("catalog", ["relation", "function", "schema"])
def test_initial_catalog_is_rejected_before_migrations(monkeypatch, catalog):
    def rows(connection, sql):
        marker = {"relation": "pg_class", "function": "pg_proc", "schema": "SELECT nspname"}[catalog]
        return (("unreviewed-existing-object",),) if marker in sql else ()

    monkeypatch.setattr(fresh.tokens, "_tuples", rows)
    with pytest.raises(fresh.FreshProductRefused):
        fresh._initial_empty(object())


@pytest.mark.parametrize("event", ["begin", "rollback", "savepoint", "rollback_savepoint", "release_savepoint"])
def test_repaired_transaction_drift_stays_poisoned(monkeypatch, event):
    connection = SimpleNamespace(info={})
    root = object()
    listeners = {}
    monkeypatch.setattr(fresh.identity, "_connection_preflight", lambda conn: root)
    monkeypatch.setattr(fresh.tokens, "_physical_context", lambda conn: ("same-context-after-repair",))
    monkeypatch.setattr(fresh, "_initial_empty", lambda conn: None)
    monkeypatch.setattr(fresh.sa.event, "listen", lambda conn, name, callback: listeners.update({name: callback}))
    entry = fresh._start(connection)
    listeners[event](connection, None, None)
    # Restoring the same wrapper/root/XID does not erase passive event evidence.
    with pytest.raises(fresh.FreshProductRefused):
        fresh._check(connection, entry)
    assert entry.poisoned


def test_extra_grantee_or_column_grant_is_rejected_independently_of_pin(monkeypatch):
    monkeypatch.setattr(
        fresh.tokens,
        "_tuples",
        lambda *args, **kwargs: (("academy_erp_completion_checkpoints", "app_admin", "app_user", "SELECT", False),),
    )
    with pytest.raises(fresh.FreshProductRefused):
        fresh._retained_security(object())


@pytest.mark.parametrize("acl", ["owner_contract", "missing_explicit", "unexpected_grantee"])
def test_helper_acl_matches_installed_kernel_grants_including_public_defaults(monkeypatch, acl):
    # Derive the explicit grants from the installed owner rather than repeating
    # the verifier's role list. A later grant/revoke must be reviewed here.
    statements = []
    for path in kernel_versions().glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                sql = " ".join(node.value.split())
                if sql.startswith(("GRANT ", "REVOKE ")) and "app_current_tenant_id()" in sql:
                    statements.append(sql)
    assert len(statements) == 1
    grant = re.fullmatch(
        r"GRANT EXECUTE ON FUNCTION (?:public\.)?app_current_tenant_id\(\) TO ([a-z_, ]+);",
        statements[0],
    )
    assert grant is not None
    explicit_roles = {role.strip() for role in grant[1].split(",")}
    assert explicit_roles == {"app_user", "platform_api"}
    helper_roles = {"PUBLIC", "app_admin", *explicit_roles}
    if acl == "missing_explicit":
        helper_roles -= explicit_roles
    elif acl == "unexpected_grantee":
        helper_roles.add("academy_lab_worker")

    def catalog_rows(connection, sql, *, signature):
        name = signature.split("(", 1)[0].removeprefix("public.")
        activation = name == "activate_eligible_facilitator_nominations"
        if "aclexplode" in sql:
            roles = (
                helper_roles
                if name == "app_current_tenant_id"
                else (
                    {"app_admin", "app_user", "platform_api", "academy_lab_worker"}
                    if activation
                    else {"PUBLIC", "app_admin"}
                )
            )
            return tuple(sorted(("app_admin", role, "EXECUTE", False) for role in roles))
        config = None if name == "app_current_tenant_id" else ("search_path=pg_catalog",)
        return (("app_admin", activation, config),)

    monkeypatch.setattr(fresh.tokens, "_tuples", catalog_rows)
    if acl == "owner_contract":
        fresh._function_security(object())
    else:
        with pytest.raises(fresh.FreshProductRefused):
            fresh._function_security(object())


@pytest.fixture
def synthetic_catalog(monkeypatch):
    # Exercise the real projection/digest code, not a prebuilt packet. The fake
    # returns a field only when the actual SQL requests it, so omission regresses
    # both the query contract and digest-sensitivity tests below.
    state = {
        "defaults": "NULL::uuid, NULL::uuid, NULL::uuid, NULL::integer, NULL::uuid",
        "argnames": ("p_tenant_id", "p_nomination_id", "p_person_id", "p_course_id", "p_limit", "p_actor_person_id"),
        "argmodes": ("i", "i", "i", "i", "i", "i", "t", "t"),
        "leakproof": False,
        "ri": [
            (
                "public",
                "tenants",
                "public",
                "applicants_tenant_id_fkey",
                "public",
                "applicants",
                "public",
                "tenants",
                9,
                "O",
                False,
                False,
                True,
                "pg_catalog",
                "RI_FKey_cascade_del",
                "",
                0,
                "",
                None,
                None,
                None,
            )
        ],
        "queries": [],
        "columns": [("mod_learning", "courses", "id", "uuid", True)],
        "table_acl": [("public", "academy_erp_completion_checkpoints", "app_admin", "app_admin", "SELECT", False)],
        "bodies": {},
        "undeclared": (),
        "function_acl": {},
        "dependencies": [("table:mod_learning.courses", "schema:mod_learning", "n")],
    }
    monkeypatch.setattr(fresh.identity, "_connection_preflight", lambda connection: object())
    monkeypatch.setattr(fresh, "_owner_contracts", lambda: None)
    monkeypatch.setattr(fresh, "_function_census", lambda connection, final: None)

    def rows(connection, sql, **params):
        state["queries"].append(sql)
        if "SELECT 'pg_collation' WHERE EXISTS" in sql:
            return tuple((category,) for category in state["undeclared"])
        if "c.relkind,pg_catalog.pg_get_userbyid(c.relowner)" in sql:
            return tuple(
                (namespace, name, "r", "app_admin", True, True, "p", False, None)
                for namespace, name in fresh._canonical_relations()
            )
        if "WITH tables AS" in sql:
            return tuple(state["dependencies"])
        if "format_type(a.atttypid" in sql:
            return tuple(state["columns"])
        if "aclexplode(COALESCE(c.relacl" in sql:
            return tuple(state["table_acl"])
        if "aclexplode" in sql and "signature" in params:
            return tuple(state["function_acl"].get(params["signature"], ()))
        if "FROM pg_catalog.pg_trigger t " in sql:
            return tuple(state["ri"])
        if "l.lanname," in sql and "FROM pg_catalog.pg_proc p" in sql:
            function = params["signature"].split("(", 1)[0]
            facts = (function, "", "trigger", False, None, "app_admin", "v", "u", False)
            if "p.proleakproof" in sql:
                facts += (state["leakproof"],)
            facts += ("plpgsql",)
            if "pg_catalog.pg_get_expr(p.proargdefaults,0)" in sql:
                facts += (state["defaults"],)
            if "p.proargnames" in sql:
                facts += (state["argnames"],)
            if "p.proargmodes" in sql:
                facts += (state["argmodes"],)
            return ((*facts, state["bodies"].get(function, "unchanged function source")),)
        return ()

    monkeypatch.setattr(fresh.tokens, "_tuples", rows)
    return state


def test_fingerprint_projects_qualified_child_and_parent_ri_semantics_without_generated_names(synthetic_catalog):
    fresh.catalog_fingerprint(object())
    (ri_sql,) = (sql for sql in synthetic_catalog["queries"] if "t.tgtype,t.tgenabled" in sql)
    projection = ri_sql.split(" FROM pg_catalog.pg_trigger", 1)[0]
    assert "k.oid=t.tgconstraint AND k.contype='f'" in ri_sql
    assert "(cn.nspname||'.'||ch.relname)=ANY(:qualified)" in ri_sql
    assert "(pn.nspname||'.'||pa.relname)=ANY(:qualified)" in ri_sql
    for field in (
        "tn.nspname",
        "tr.relname",
        "kn.nspname",
        "k.conname",
        "cn.nspname",
        "ch.relname",
        "pn.nspname",
        "pa.relname",
        "t.tgtype",
        "t.tgenabled",
        "t.tgdeferrable",
        "t.tginitdeferred",
        "t.tgisinternal",
        "fn.nspname",
        "f.proname",
        "pg_catalog.pg_get_function_identity_arguments(f.oid)",
    ):
        assert field in projection
    assert "t.tgname" not in ri_sql and "t.oid" not in ri_sql
    assert "pg_get_triggerdef" not in ri_sql


@pytest.mark.parametrize(
    "change",
    ["default", "argnames", "argmodes", "leakproof", "ri_missing", "ri_disabled", "ri_deferred", "ri_function"],
)
def test_fingerprint_changes_with_function_interface_or_ri_enforcement(synthetic_catalog, change):
    before = fresh.catalog_fingerprint(object())
    if change == "default":
        synthetic_catalog["defaults"] = "NULL::uuid, NULL::uuid, NULL::uuid, 1, NULL::uuid"
    elif change == "argnames":
        synthetic_catalog["argnames"] = (*synthetic_catalog["argnames"][:-1], "changed_actor_parameter")
    elif change == "argmodes":
        synthetic_catalog["argmodes"] = ("i", "i", "i", "i", "i", "i", "o", "o")
    elif change == "leakproof":
        synthetic_catalog["leakproof"] = True
    elif change == "ri_missing":
        synthetic_catalog["ri"] = []
    else:
        trigger = list(synthetic_catalog["ri"][0])
        position, value = {
            "ri_disabled": (9, "D"),
            "ri_deferred": (11, True),
            "ri_function": (14, "RI_FKey_noaction_del"),
        }[change]
        trigger[position] = value
        synthetic_catalog["ri"] = [tuple(trigger)]
    assert fresh.catalog_fingerprint(object()) != before


@pytest.mark.parametrize(
    "change", ["learning_column", "kernel_column", "kernel_outbox_body", "kernel_execute_acl", "academy_acl"]
)
def test_whole_owner_catalog_blindspots_change_fingerprint(synthetic_catalog, change):
    before = fresh.catalog_fingerprint(object())
    if change == "learning_column":
        synthetic_catalog["columns"].append(("mod_learning", "courses", "unreviewed", "text", False))
    elif change == "kernel_column":
        synthetic_catalog["columns"].append(("public", "tenants", "unreviewed", "text", False))
    elif change == "kernel_outbox_body":
        synthetic_catalog["bodies"]["public.claim_outbox_batch"] = "tampered body"
    elif change == "kernel_execute_acl":
        signature = "public.claim_outbox_batch(text,integer,integer)"
        synthetic_catalog["function_acl"][signature] = [("app_admin", "app_user", "EXECUTE", False)]
    else:
        synthetic_catalog["table_acl"].append(
            ("public", "academy_erp_completion_checkpoints", "app_admin", "app_user", "SELECT", False)
        )
    assert fresh.catalog_fingerprint(object()) != before


def test_catalog_serialization_version_and_all_function_signatures(synthetic_catalog):
    packet = fresh._catalog_packet(object())
    assert packet["serialization"] == (("academy-canonical-catalog-v2",),)
    assert {row[0] for row in packet["owner_sources"]} == {"Kernel", "Learning", "Academy"}
    assert len(packet["functions"]) == 7
    assert {row[:2] for row in packet["relations"]} == set(fresh._canonical_relations())
    assert any("pg_identify_object" in sql for sql in synthetic_catalog["queries"])
    assert len(fresh.catalog_object_digests(object())) > 7


def test_kernel_function_body_contracts_match_pinned_owner_sources(synthetic_catalog):
    actual = {}
    for filename in ("20260731_0011_outbox_relay_leasing.py", "20260731_0012_platform_outbox.py"):
        tree = ast.parse((Path(kernel_versions()) / filename).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            name = re.search(r"CREATE OR REPLACE FUNCTION public\.(\w+)", node.value)
            body = re.search(r"AS \$fn\$(.*?)\$fn\$", node.value, re.S)
            if name and body:
                actual["public." + name.group(1)] = hashlib.sha256(body.group(1).encode()).hexdigest()
    packet = fresh._catalog_packet(object())
    assert actual == dict(packet["kernel_function_sources"])


def test_catalog_column_permutation_preserves_fingerprint_and_object_digests(synthetic_catalog):
    synthetic_catalog["columns"].extend(
        [
            ("mod_learning", "courses", "title", "text", False),
            ("public", "tenants", "id", "uuid", True),
        ]
    )
    before = fresh.catalog_fingerprint(object())
    objects = fresh.catalog_object_digests(object())
    synthetic_catalog["columns"].reverse()
    synthetic_catalog["table_acl"].reverse()
    synthetic_catalog["ri"].reverse()
    assert fresh.catalog_fingerprint(object()) == before
    assert fresh.catalog_object_digests(object()) == objects


def test_every_category_orders_complete_rows_without_erasing_semantics(synthetic_catalog, monkeypatch):
    categories = tuple(fresh._catalog_packet(object()))
    rows = (
        ("public", "same_table", "z", ("second", "first"), "  literal  "),
        ("public", "same_table", "a", ("first", "second"), "literal"),
    )
    packet = {category: rows for category in categories}
    monkeypatch.setattr(fresh, "_catalog_packet", lambda connection: packet)
    before = fresh.catalog_fingerprint(object())
    objects = fresh.catalog_object_digests(object())
    diagnostic_bytes = json.dumps(objects).encode()
    packet = {category: tuple(reversed(rows)) for category in reversed(categories)}
    assert fresh.catalog_fingerprint(object()) == before
    assert fresh.catalog_object_digests(object()) == objects
    assert json.dumps(fresh.catalog_object_digests(object())).encode() == diagnostic_bytes
    # Multiplicity, input/output argument order and literal whitespace are facts.
    for changed in (
        (*rows, rows[0]),
        ((rows[0][0], rows[0][1], rows[0][2], tuple(reversed(rows[0][3])), rows[0][4]), rows[1]),
        ((*rows[0][:-1], rows[0][-1].strip()), rows[1]),
    ):
        packet = {category: changed for category in categories}
        assert fresh.catalog_fingerprint(object()) != before


@pytest.mark.parametrize(
    "category",
    [
        "pg_collation",
        "pg_operator",
        "pg_opclass",
        "pg_opfamily",
        "pg_conversion",
        "pg_ts_config",
        "pg_ts_dict",
        "pg_ts_parser",
        "pg_ts_template",
        "pg_statistic_ext",
        "pg_cast",
        "pg_am",
        "pg_transform",
        "pg_event_trigger",
        "pg_foreign_data_wrapper",
        "pg_foreign_server",
        "pg_user_mapping",
        "pg_extension",
    ],
)
@pytest.mark.parametrize("boundary", ["initial", "preimage", "terminal"])
def test_unreferenced_undeclared_objects_refuse_before_capture_or_terminal_hash(
    synthetic_catalog,
    category,
    boundary,
):
    from app.maintenance import erp_successor_catalog as successor

    # This object has no incoming reference from the 72 canonical tables or
    # seven functions; dependency closure alone cannot discover its presence.
    synthetic_catalog["undeclared"] = (category,)
    with pytest.raises(fresh.FreshProductRefused):
        if boundary == "initial":
            fresh._initial_empty(object())
        elif boundary == "preimage":
            successor.observe(object())
        else:
            fresh.catalog_fingerprint(object())
    census = next(sql for sql in synthetic_catalog["queries"] if "SELECT 'pg_collation' WHERE EXISTS" in sql)
    assert "n.nspname NOT IN ('pg_catalog','information_schema')" in census
    assert "umoptions" not in census and "srvoptions" not in census and "fdwoptions" not in census
