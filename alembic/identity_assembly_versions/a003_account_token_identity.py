"""Recorded AccountToken canonical FK adoption; all branches fail closed.

The caller stages genuine selected Kernel/prerequisites -> exact a002 -> actual
identity import -> full heads, on ONE app_admin Connection/root. Historical
entry requires the exact pre-relocation capture and genuine issued import
receipt. Early heads cannot create/drop/reissue/repair historical tokens.
"""

from dataclasses import replace

import sqlalchemy as sa
from dotmac_kernel.migrations.identity_history import IdentityHistoryImportRefused
from sqlalchemy.engine import Connection

from alembic import op
from app.maintenance.account_token_identity import (
    _consume_migration_entry,
    _record_migration_catalog,
    _root,
    _TokenCatalog,
)

revision = "a003_account_token_identity"
down_revision = "a002_credential_reset_state"
branch_labels = None
depends_on = None


_FAMILIES = (
    "tenants",
    "tenant_domains",
    "people",
    "user_credentials",
    "auth_sessions",
    "roles",
    "person_roles",
    "audit_events",
)


def _require(condition: bool) -> None:
    if not condition:
        raise IdentityHistoryImportRefused("Academy account token adoption refused; root rollback required")


def _attribute_numbers(connection: Connection, oid: int, names: tuple[str, ...]) -> tuple:
    return tuple(
        connection.scalar(
            sa.text("SELECT attnum FROM pg_attribute WHERE attrelid=:oid AND attname=:name AND NOT attisdropped"),
            {"oid": oid, "name": name},
        )
        for name in names
    )


def _oid(connection: Connection, relation: str) -> int | None:
    return connection.scalar(sa.text("SELECT to_regclass(:relation)::oid"), {"relation": relation})


def _tuples(connection: Connection, sql: str, **params: object) -> tuple:
    def freeze(value):
        return tuple(freeze(v) for v in value) if isinstance(value, (list, tuple)) else value

    return tuple(freeze(tuple(r)) for r in connection.execute(sa.text(sql), params))


def _catalog(connection: Connection) -> _TokenCatalog:
    """Catalog and complete ID cohort only; NEVER fetch stored token values."""
    params = {"oid": _oid(connection, "public.account_tokens")}
    _require(params["oid"] is not None)
    q = lambda sql: _tuples(connection, sql, **params)  # noqa: E731
    return _TokenCatalog(
        relation=q(
            "SELECT oid,relkind,pg_get_userbyid(relowner),relrowsecurity,relforcerowsecurity,"
            "relhassubclass,relispartition,relpersistence,reloptions,relreplident,reltablespace "
            "FROM pg_class WHERE oid=:oid"
        )[0],
        columns=q(
            "SELECT a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,"
            "pg_get_expr(d.adbin,d.adrelid),a.attidentity,a.attgenerated,a.attcollation FROM pg_attribute a "
            "LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum "
            "WHERE a.attrelid=:oid AND a.attnum>0 ORDER BY a.attnum"
        ),
        keys=q(
            "SELECT conname,contype,conkey,convalidated,condeferrable,condeferred "
            "FROM pg_constraint WHERE conrelid=:oid AND contype<>'f' ORDER BY conname"
        ),
        foreign_keys=q(
            "SELECT conname,conkey,confrelid,confkey,confdeltype,confupdtype,confmatchtype,"
            "convalidated,condeferrable,condeferred FROM pg_constraint "
            "WHERE conrelid=:oid AND contype='f' ORDER BY conname"
        ),
        indexes=q(
            "SELECT c.oid,c.relname,i.indisunique,i.indisprimary,i.indisvalid,i.indisready,"
            "i.indislive,i.indkey::text,pg_get_expr(i.indpred,i.indrelid),"
            "pg_get_expr(i.indexprs,i.indrelid),pg_get_indexdef(c.oid),i.indnkeyatts,i.indnatts,"
            "i.indisclustered,i.indisreplident,c.reloptions,c.reltablespace,pg_get_userbyid(c.relowner),"
            "c.relacl::text FROM pg_index i "
            "JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=:oid ORDER BY c.relname"
        ),
        policies=q(
            "SELECT p.oid,p.polname,p.polcmd,p.polpermissive,p.polroles,"
            "pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid) "
            "FROM pg_policy p WHERE p.polrelid=:oid ORDER BY p.polname"
        ),
        policy_dependencies=q(
            "SELECT d.classid::regclass::text,d.refclassid::regclass::text,"
            "d.refobjid,d.refobjsubid,d.deptype FROM pg_depend d JOIN pg_policy p "
            "ON d.classid='pg_policy'::regclass AND d.objid=p.oid "
            "WHERE p.polrelid=:oid ORDER BY 1,2,3,4,5"
        ),
        acl=q(
            "SELECT pg_get_userbyid(a.grantor),CASE WHEN a.grantee=0 THEN 'PUBLIC' "
            "ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable "
            "FROM pg_class c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "
            "WHERE c.oid=:oid ORDER BY 1,2,3,4"
        ),
        column_acl=q(
            "SELECT attname,attacl::text FROM pg_attribute WHERE attrelid=:oid AND attacl IS NOT NULL ORDER BY attnum"
        ),
        rules=q("SELECT oid FROM pg_rewrite WHERE ev_class=:oid"),
        triggers=q("SELECT oid FROM pg_trigger WHERE tgrelid=:oid AND NOT tgisinternal"),
        ids=_tuples(connection, "SELECT id,tenant_id,person_id FROM public.account_tokens ORDER BY id"),
    )


def _shape(connection: Connection, catalog: _TokenCatalog, targets: dict, *, historical: bool) -> None:
    """Frozen catalog contract. No runtime ORM metadata or mutable DDL recipe."""
    _require(catalog.relation[1:] == ("r", "app_admin", True, True, False, False, "p", None, "d", 0))
    types = (
        "uuid",
        "uuid",
        "uuid",
        "character varying(20)",
        "character varying(64)",
        "timestamp with time zone",
        "timestamp with time zone",
        "timestamp with time zone",
        "timestamp with time zone",
    )
    names = ("id", "tenant_id", "person_id", "kind", "token_hash", "expires_at", "used_at", "created_at", "updated_at")
    default_collation = connection.scalar(sa.text("SELECT 'pg_catalog.default'::regcollation::oid"))
    _require(
        catalog.columns
        == tuple(
            (
                n,
                t,
                n != "used_at",
                "now()" if n in {"created_at", "updated_at"} else None,
                "",
                "",
                default_collation if n in {"kind", "token_hash"} else 0,
            )
            for n, t in zip(names, types, strict=True)
        )
    )
    _require(
        catalog.keys
        == (
            ("account_tokens_pkey", "p", (1,), True, False, False),
            ("uq_account_tokens_tenant_id_id", "u", (2, 1), True, False, False),
            ("uq_account_tokens_tenant_token_hash", "u", (2, 5), True, False, False),
        )
    )
    if historical:
        expected_fks = (
            (
                "account_tokens_tenant_id_fkey",
                (2,),
                targets["tenants"],
                _attribute_numbers(connection, targets["tenants"], ("id",)),
                "c",
                "a",
                "s",
                True,
                False,
                False,
            ),
            (
                "fk_account_tokens_tenant_person",
                (2, 3),
                targets["people"],
                _attribute_numbers(connection, targets["people"], ("tenant_id", "id")),
                "c",
                "a",
                "s",
                True,
                False,
                False,
            ),
        )
    else:
        expected_fks = (
            (
                "account_tokens_tenant_id_fkey",
                (2,),
                targets["tenants"],
                _attribute_numbers(connection, targets["tenants"], ("id",)),
                "c",
                "a",
                "s",
                True,
                False,
                False,
            ),
            (
                "fk_account_tokens_person",
                (3,),
                targets["party_persons"],
                _attribute_numbers(connection, targets["party_persons"], ("party_id",)),
                "c",
                "a",
                "s",
                True,
                False,
                False,
            ),
            (
                "fk_account_tokens_tenant_person",
                (2, 3),
                targets["parties"],
                _attribute_numbers(connection, targets["parties"], ("tenant_id", "id")),
                "c",
                "a",
                "s",
                True,
                False,
                False,
            ),
        )
    _require(catalog.foreign_keys == expected_fks)
    _require(not catalog.column_acl and not catalog.rules and not catalog.triggers)
    _require(
        connection.scalar(
            sa.text(
                "SELECT count(*)=:count AND bool_and(t.tgenabled='O' AND c.contype='f' "
                "AND c.conrelid=t.tgrelid) FROM pg_trigger t LEFT JOIN pg_constraint c ON c.oid=t.tgconstraint "
                "WHERE t.tgrelid=:oid AND t.tgisinternal"
            ),
            {"oid": catalog.relation[0], "count": (4 if historical else 6)},
        )
        is True
    )

    indexes = {
        "account_tokens_pkey": (True, True, "1"),
        "uq_account_tokens_tenant_id_id": (True, False, "2 1"),
        "uq_account_tokens_tenant_token_hash": (True, False, "2 5"),
        "ix_account_tokens_tenant_id": (False, False, "2"),
        "ix_account_tokens_person_id": (False, False, "3"),
        "ix_account_tokens_token_hash": (False, False, "5"),
    }
    _require(len(catalog.indexes) == len(indexes))
    for index in catalog.indexes:
        (
            _,
            name,
            unique,
            primary,
            valid,
            ready,
            live,
            keys,
            pred,
            expr,
            definition,
            nkeys,
            natts,
            clustered,
            replica,
            options,
            tablespace,
            owner,
            acl,
        ) = index
        _require(nkeys == natts == len(keys.split()) and not clustered and not replica)
        _require(options is None and tablespace == 0 and owner == "app_admin" and acl is None)
        _require(name in indexes and (unique, primary, keys) == indexes[name])
        columns = {
            "1": "id",
            "2": "tenant_id",
            "3": "person_id",
            "5": "token_hash",
            "2 1": "tenant_id, id",
            "2 5": "tenant_id, token_hash",
        }[keys]
        _require(
            definition == f"CREATE {'UNIQUE ' if unique else ''}INDEX {name} "
            f"ON public.account_tokens USING btree ({columns})"
        )
        _require(valid and ready and live and pred is None and expr is None)
    _require(
        _tuples(
            connection,
            "SELECT rolname,rolsuper,rolbypassrls FROM pg_roles "
            "WHERE rolname IN ('app_user','platform_api') ORDER BY rolname",
        )
        == (("app_user", False, False), ("platform_api", False, False))
    )
    privileges = {
        row[0]
        for row in _tuples(
            connection,
            "SELECT privilege_type FROM aclexplode(acldefault('r', "
            "(SELECT oid FROM pg_roles WHERE rolname='app_admin'))) ",
        )
    }
    standard = {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
    # PostgreSQL 17+ adds owner MAINTAIN; online roles still receive CRUD only.
    _require(standard <= privileges <= standard | {"MAINTAIN"})
    expected_acl = {("app_admin", "app_admin", p, False) for p in privileges}
    expected_acl |= {
        ("app_admin", r, p, False)
        for r in ("app_user", "platform_api")
        for p in ("SELECT", "INSERT", "UPDATE", "DELETE")
    }
    _require(set(catalog.acl) == expected_acl)
    for role in ("app_user", "platform_api"):
        for privilege in privileges:
            allowed = connection.scalar(
                sa.text("SELECT has_table_privilege(:role,'public.account_tokens',:p)"), {"role": role, "p": privilege}
            )
            _require(allowed is (privilege in {"SELECT", "INSERT", "UPDATE", "DELETE"}))
            if privilege in {"REFERENCES", "SELECT", "INSERT", "UPDATE"}:
                # Detect inherited column-only privilege escalation as well.
                _require(
                    connection.scalar(
                        sa.text("SELECT has_any_column_privilege(:role,'public.account_tokens',:p)"),
                        {"role": role, "p": privilege},
                    )
                    is (privilege != "REFERENCES")
                )
    _require(len(catalog.policies) == 1)
    _, name, command, permissive, roles, using, check = catalog.policies[0]
    _require((name, command, permissive, roles) == ("account_tokens_tenant_isolation", "*", True, (0,)))
    _require(
        using == check
        and using in {"(tenant_id = app_current_tenant_id())", "(tenant_id = public.app_current_tenant_id())"}
    )
    function_oid = connection.scalar(sa.text("SELECT 'public.app_current_tenant_id()'::regprocedure::oid"))
    _require(
        set(catalog.policy_dependencies)
        == {
            ("pg_policy", "pg_class", catalog.relation[0], 0, "a"),
            ("pg_policy", "pg_class", catalog.relation[0], 2, "n"),
            ("pg_policy", "pg_proc", function_oid, 0, "n"),
        }
    )


def _canonical_targets(connection: Connection) -> dict:
    targets = {}
    for name in ("tenants", "parties", "party_persons"):
        oid = _oid(connection, "public." + name)
        _require(oid is not None)
        _require(
            connection.execute(
                sa.text("SELECT relkind,pg_get_userbyid(relowner) FROM pg_class WHERE oid=:oid"), {"oid": oid}
            ).one()
            == ("r", "app_admin")
        )
        targets[name] = oid
    return targets


def _create_fresh() -> None:
    # Frozen established 0014 shape, canonical references only. No IF NOT EXISTS.
    op.create_table(
        "account_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("person_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="account_tokens_pkey"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_account_tokens_tenant_id_id"),
        sa.UniqueConstraint("tenant_id", "token_hash", name="uq_account_tokens_tenant_token_hash"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["public.tenants.id"], name="account_tokens_tenant_id_fkey", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "person_id"],
            ["public.parties.tenant_id", "public.parties.id"],
            name="fk_account_tokens_tenant_person",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["person_id"], ["public.party_persons.party_id"], name="fk_account_tokens_person", ondelete="CASCADE"
        ),
        schema="public",
    )
    for column in ("tenant_id", "person_id", "token_hash"):
        op.create_index("ix_account_tokens_" + column, "account_tokens", [column], schema="public")
    op.execute("ALTER TABLE public.account_tokens ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE public.account_tokens FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY account_tokens_tenant_isolation ON public.account_tokens "
        "USING (tenant_id = public.app_current_tenant_id()) "
        "WITH CHECK (tenant_id = public.app_current_tenant_id())"
    )
    op.execute("GRANT SELECT,INSERT,UPDATE,DELETE ON public.account_tokens TO app_user,platform_api")


def upgrade() -> None:
    connection = op.get_bind()
    root = _root(connection)
    entry = _consume_migration_entry(connection)
    _require(entry.root is root)
    targets = _canonical_targets(connection)
    connection.execute(
        sa.text("LOCK TABLE public.tenants,public.parties,public.party_persons IN SHARE ROW EXCLUSIVE MODE")
    )
    # Lock before rereading exact OIDs, preventing concurrent replacement.
    _require(_canonical_targets(connection) == targets)
    if entry.historical:
        _require(_oid(connection, "public.account_tokens") == entry.catalog.relation[0])
        connection.execute(sa.text("LOCK TABLE public.account_tokens IN ACCESS EXCLUSIVE MODE"))
        _require(all(_oid(connection, "academy_identity_compat." + n) == oid for n, oid in entry.relations))
        before = _catalog(connection)
        _shape(connection, before, dict(entry.relations), historical=True)
        _require(before == entry.catalog)
        # Every token, including used/expired/ical_feed, must have the same
        # tenant/person UUIDs in actual canonical Tenant + Party + PartyPerson.
        _require(
            connection.scalar(
                sa.text(
                    "SELECT NOT EXISTS (SELECT 1 FROM public.account_tokens t "
                    "LEFT JOIN public.tenants n ON n.id=t.tenant_id "
                    "LEFT JOIN public.parties p ON p.tenant_id=t.tenant_id AND p.id=t.person_id "
                    "LEFT JOIN public.party_persons s ON s.party_id=t.person_id "
                    "WHERE n.id IS NULL OR p.id IS NULL OR s.party_id IS NULL)"
                )
            )
            is True
        )
        op.drop_constraint("account_tokens_tenant_id_fkey", "account_tokens", type_="foreignkey", schema="public")
        op.drop_constraint("fk_account_tokens_tenant_person", "account_tokens", type_="foreignkey", schema="public")
        op.create_foreign_key(
            "account_tokens_tenant_id_fkey",
            "account_tokens",
            "tenants",
            ["tenant_id"],
            ["id"],
            source_schema="public",
            referent_schema="public",
            ondelete="CASCADE",
        )
        op.create_foreign_key(
            "fk_account_tokens_tenant_person",
            "account_tokens",
            "parties",
            ["tenant_id", "person_id"],
            ["tenant_id", "id"],
            source_schema="public",
            referent_schema="public",
            ondelete="CASCADE",
        )
        op.create_foreign_key(
            "fk_account_tokens_person",
            "account_tokens",
            "party_persons",
            ["person_id"],
            ["party_id"],
            source_schema="public",
            referent_schema="public",
            ondelete="CASCADE",
        )
    else:
        _require(_oid(connection, "public.account_tokens") is None)
        _require(all(_oid(connection, "academy_identity_compat." + n) is None for n in _FAMILIES))
        _create_fresh()
    after = _catalog(connection)
    _shape(connection, after, targets, historical=False)
    if entry.historical:
        # FK constraints/internal FK triggers are the only deliberate changes.
        # All non-FK catalog facts, row IDs and table/index OIDs remain exact.
        _require(replace(after, foreign_keys=before.foreign_keys) == before)
    else:
        _require(not after.ids)
    _require(connection.get_transaction() is root and root.is_active)
    _record_migration_catalog(connection, entry, after)


def downgrade() -> None:
    raise RuntimeError("Account token reversal requires a reviewed new-facts disposition")
