"""Unprivileged, fixed-query, read-only candidate DB evidence; JSON stdin only.

Never executes migrations. Caller must bind stdin, helper hash and receipts in
root custody. Run only in the pinned source cwd using its new venv as dotmac.
"""
# ruff: noqa: E501 -- fixed SQL and exact catalog definitions remain directly auditable.

import hashlib
import io
import json
import os
import pwd
import re
import socket
import stat
import subprocess
import sys
from pathlib import Path

RETAINED_SOURCES = (
    "/home/dotmac/projects/academy-v2-csp-stage-d12260b6996b18b27e04a784042f764bd583952d",
    "/home/dotmac/projects/academy-v2-release-7ef72b3d1c23a5bf4d3268a6cf21a3d46673db46",
)
ENVIRONMENT_FILES = (
    "/home/dotmac/projects/dotmac_academy_v2/.env",
    "/home/dotmac/projects/academy-v2-csp-stage-d12260b6996b18b27e04a784042f764bd583952d/.env",
    "/home/dotmac/projects/academy-v2-release-7ef72b3d1c23a5bf4d3268a6cf21a3d46673db46/.env",
)
LEGACY_ENV_DIRECTORIES = frozenset(
    (
        "/home/dotmac/projects",
        "/home/dotmac/projects/dotmac_academy_v2",
        "/home/dotmac/projects/academy-v2-csp-stage-d12260b6996b18b27e04a784042f764bd583952d",
        "/home/dotmac/projects/academy-v2-release-7ef72b3d1c23a5bf4d3268a6cf21a3d46673db46",
    )
)

OIDC = "a0011_oidc_login_states"
KERNEL = "0031_rate_limit_buckets"
BASELINE = [OIDC]
VECTORS = {"before": BASELINE, "after": [KERNEL, OIDC]}
MIGRATION = "alembic/versions/a0011_oidc_login_states.py"
DDL_SHA256 = "21a4b74fe49e4dab6864a4657d2824a6356db5f3315552af51beb787881beaf5"
REQUIRED_FILES = {MIGRATION, "alembic.ini", "alembic/env.py", "app/migration_graph.py", "app/config.py"}
FIELDS = {
    "schema",
    "environment_file",
    "env_sha256",
    "mode",
    "candidate",
    "tree",
    "source",
    "venv",
    "hostname",
    "uid",
    "database",
    "retained_source",
    "helper_sha256",
    "source_file_sha256",
    "expected_before",
    "oidc_expect_empty",
}
REPORT = {
    "schema": 4,
    "ok": False,
    "migration_executed": False,
    "overall_readiness_claimed": False,
    "unmet_predicates": [],
}


class Refusal(Exception):
    pass


def require(ok, name):
    if not ok:
        raise Refusal(name)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    result = subprocess.run(  # noqa: S603 - argv restricted at every literal call below
        ["/usr/bin/git", "--no-optional-locks", *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
        timeout=20,
    )
    require(result.returncode == 0, "git_readback_failed")
    return result.stdout


def directory_fd(path, owners, strict=True):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute_directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = Path("/")
    try:
        for part in (None, *path.parts[1:]):
            if part is not None:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                current /= part
            info = os.fstat(fd)
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid in owners
                and (not info.st_mode & 2)
                and (not info.st_mode & 16 or (not strict and str(current) in LEGACY_ENV_DIRECTORIES)),
                "unsafe_opened_directory",
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(path, owners, limit=5000000, strict=True, mode=None):
    path = Path(path)
    parent = directory_fd(path.parent, owners, strict)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_uid in owners
                and (not before.st_mode & 18)
                and (before.st_size <= limit),
                "unsafe_regular_file",
            )
            require(mode is None or stat.S_IMODE(before.st_mode) == mode, "exact_file_mode")
            chunks, size = ([], 0)
            while True:
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                require(size <= limit, "file_growth_bound")
                chunks.append(chunk)
            after = os.fstat(fd)
            require(
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "file_changed_during_read",
            )
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def environment_payload(m):
    target = m["environment_file"]
    require(type(target) is str and target in ENVIRONMENT_FILES, "closed_environment_target")
    require(type(m["env_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", m["env_sha256"]), "environment_hash_shape")
    parent = directory_fd(Path(m["source"]), (0, m["uid"]))
    try:
        info = os.stat(".env", dir_fd=parent, follow_symlinks=False)
        require(
            stat.S_ISLNK(info.st_mode) and os.readlink(".env", dir_fd=parent) == target, "explicit_environment_link"
        )
        raw = read_file(Path(target), (0, m["uid"]), limit=2_000_000, strict=False, mode=0o600)
        require(digest(raw) == m["env_sha256"], "environment_file_pin")
        return raw
    finally:
        os.close(parent)


def identity(m):
    require(
        type(m) is dict and set(m) == FIELDS and m["schema"] == "AcademyCandidateDBReadinessInputs.v4", "input_schema"
    )
    require(m["mode"] in VECTORS, "mode")
    require(type(m["uid"]) is int and m["uid"] > 0, "uid_input")
    require(
        os.getuid() == os.geteuid() == m["uid"] and pwd.getpwuid(os.getuid()).pw_name == "dotmac", "unprivileged_dotmac"
    )
    require(socket.gethostname() == m["hostname"], "hostname")
    for key in ("candidate", "tree"):
        require(isinstance(m[key], str) and re.fullmatch(r"[0-9a-f]{40}", m[key]), key + "_format")
    for key in ("source", "venv", "retained_source"):
        require(isinstance(m[key], str) and Path(m[key]).is_absolute(), key + "_path")
        require(str(Path(m[key]).resolve()) == m[key], key + "_canonical")
    source, venv = Path(m["source"]), Path(m["venv"])
    require(Path.cwd() == source, "source_cwd")
    require(sys.prefix == str(venv) and sys.base_prefix != sys.prefix, "venv_prefix")
    require(Path(sys.executable).absolute() == venv / "bin/python", "venv_interpreter")
    require(sys.flags.isolated == 1 and sys.dont_write_bytecode, "isolated_no_bytecode_launch")
    require(digest(Path(__file__).read_bytes()) == m["helper_sha256"], "helper_hash")
    require(git("rev-parse", "HEAD").decode().strip() == m["candidate"], "git_head")
    require(git("rev-parse", "HEAD^{tree}").decode().strip() == m["tree"], "git_tree")
    require(not git("status", "--porcelain", "--untracked-files=no"), "tracked_source_clean")
    pins = m["source_file_sha256"]
    require(type(pins) is dict and set(pins) == REQUIRED_FILES, "source_pin_set")
    require(pins[MIGRATION] == DDL_SHA256, "reviewed_a0011_ddl_unchanged")
    for rel, expected in pins.items():
        path = source / rel
        require(path.resolve() == path and path.is_file(), "source_file_regular")
        data = path.read_bytes()
        require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "source_hash_format")
        require(digest(data) == expected and git("show", "HEAD:" + rel) == data, "source_file_pin")
    before = m["expected_before"]
    require(
        type(before) is list and all(isinstance(r, str) and re.fullmatch(r"[A-Za-z0-9_]+", r) for r in before),
        "revision_vector_shape",
    )
    require(before == BASELINE, "fixed_full_baseline_vector")
    require(m["oidc_expect_empty"] is True, "continued_oidc_darkness_empty_required")
    require(isinstance(m["database"], str) and re.fullmatch(r"[A-Za-z0-9_]+", m["database"]), "database_name")
    env_payload = environment_payload(m)
    REPORT.update(
        candidate=m["candidate"],
        tree=m["tree"],
        mode=m["mode"],
        hostname=m["hostname"],
        source_file_sha256=pins,
        environment_file=m["environment_file"],
    )
    return env_payload


def connect_settings(m, env_payload):
    # No inherited DB/config variables or per-user dotenv configuration.
    os.environ.clear()
    os.environ.update(HOME=pwd.getpwuid(os.getuid()).pw_dir, PATH=m["venv"] + "/bin:/usr/bin:/bin")
    sys.dont_write_bytecode = True
    sys.path.insert(0, m["source"])
    from dotenv import dotenv_values

    os.environ.update(
        {
            k: v
            for k, v in dotenv_values(stream=io.StringIO(env_payload.decode("utf-8")), interpolate=False).items()
            if v is not None
        }
    )
    for key in list(os.environ):
        if key.startswith(("PG", "PYTHON", "LD_")):
            del os.environ[key]
    import psycopg
    from sqlalchemy.engine import make_url

    from app.config import settings

    REPORT["oidc_enabled"] = bool(settings.oidc_enabled)
    REPORT["oidc_client_secret_present"] = bool(settings.oidc_client_secret)
    require(settings.oidc_enabled is False and not settings.oidc_client_secret, "oidc_dark_without_secret")
    url = make_url(str(settings.migration_database_url))
    require(url.get_backend_name() == "postgresql" and url.username == "app_admin", "migration_postgresql_app_admin")
    require(url.database == m["database"] and not url.query, "migration_database_no_url_options")
    # No libpq service/passfile/environment fallback. The URL is never emitted.
    require(bool(url.host) and bool(url.password), "explicit_connection_identity")
    return psycopg.connect(
        host=url.host,
        port=url.port or 5432,
        dbname=url.database,
        user=url.username,
        password=url.password,
        connect_timeout=10,
        application_name="academy_candidate_readiness",
        options="-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=3000 -c search_path=pg_catalog",
    )


def readback(conn, m):
    with conn.cursor() as cur:

        def query(sql):
            cur.execute(sql)
            return [list(row) for row in cur.fetchall()]

        cur.execute("SET TRANSACTION READ ONLY")
        cur.execute("SET LOCAL row_security = off")
        session = query(
            "SELECT current_user, current_database(), current_setting('transaction_read_only'), current_setting('default_transaction_read_only'), current_setting('row_security')"
        )
        REPORT["session"] = session
        require(session == [["app_admin", m["database"], "on", "on", "off"]], "readonly_session_identity")
        revisions = sorted(r[0] for r in query("SELECT version_num FROM public.alembic_version ORDER BY version_num"))
        REPORT["revision_vector"] = revisions
        expected = VECTORS[m["mode"]]
        require(revisions == expected, "exact_full_revision_vector")
        table = query(
            "SELECT c.relkind, pg_get_userbyid(c.relowner), c.relrowsecurity, c.relforcerowsecurity, c.relispartition FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='academy_oidc_login_states'"
        )
        REPORT["table"] = table
        roles = query(
            "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls FROM pg_roles WHERE rolname IN ('app_admin','app_user') ORDER BY rolname"
        )
        memberships = query(
            "SELECT pg_get_userbyid(roleid), pg_get_userbyid(member), admin_option FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='app_user') ORDER BY 1,2"
        )
        REPORT.update(roles=roles, app_user_memberships=memberships)
        require(
            len(roles) == 2
            and roles[1][0] == "app_user"
            and not any(roles[1][i] for i in (1, 2, 3, 5, 6))
            and not memberships,
            "no_app_user_privilege_bypass_or_inherited_roles",
        )
        defaults = query(
            "SELECT pg_get_userbyid(d.defaclrole), COALESCE(n.nspname,'*'), d.defaclobjtype, CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, a.privilege_type, a.is_grantable FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace CROSS JOIN LATERAL aclexplode(d.defaclacl) a WHERE d.defaclrole=(SELECT oid FROM pg_roles WHERE rolname='app_admin') AND (d.defaclnamespace=0 OR n.nspname='public') AND d.defaclobjtype='r' ORDER BY 1,2,3,4,5,6"
        )
        REPORT["default_acl"] = defaults
        require(
            all(
                r[3] == "app_admin"
                or (r[3] == "app_user" and r[4] in {"SELECT", "INSERT", "UPDATE", "DELETE"} and not r[5])
                for r in defaults
            ),
            "no_unexpected_default_acl",
        )
        ability = query(
            "SELECT has_schema_privilege('app_admin','public','CREATE'), has_schema_privilege('app_admin','public','USAGE'), has_table_privilege('app_admin','public.tenants','REFERENCES'), has_function_privilege('app_admin','public.app_current_tenant_id()','EXECUTE')"
        )
        REPORT["migration_privileges"] = ability
        require(ability == [[True, True, True, True]], "migration_schema_reference_function_privileges")
        kernel_readback(query, m)
        # Academy0011 already exists: its complete catalog and darkness are
        # mandatory in BOTH modes, independently of this Kernel-only execution.
        require(table == [["r", "app_admin", True, True, False]], "target_owner_forced_rls")
        columns = query(
            "SELECT a.attname, format_type(a.atttypid,a.atttypmod), a.attnotnull, pg_get_expr(d.adbin,d.adrelid), a.attidentity, a.attgenerated FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.academy_oidc_login_states'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum"
        )
        expected_columns = [
            ("id", "uuid"),
            ("tenant_id", "uuid"),
            ("state_hash", "character varying(64)"),
            ("provider_binding", "character varying(80)"),
            ("code_verifier", "text"),
            ("nonce", "text"),
            ("redirect_uri", "text"),
            ("return_to", "text"),
            ("issued_at", "bigint"),
            ("expires_at", "timestamp with time zone"),
            ("created_at", "timestamp with time zone"),
        ]
        REPORT["columns"] = columns
        require(
            columns == [[n, t, True, "now()" if n == "created_at" else None, "", ""] for n, t in expected_columns],
            "exact_columns",
        )
        policies = query(
            "SELECT polname, polcmd, polpermissive, polroles::text, pg_get_expr(polqual,polrelid), pg_get_expr(polwithcheck,polrelid) FROM pg_policy WHERE polrelid='public.academy_oidc_login_states'::regclass ORDER BY polname"
        )
        REPORT["policies"] = policies
        expr = "(tenant_id = public.app_current_tenant_id())"
        require(
            policies == [["academy_oidc_login_states_tenant_isolation", "*", True, "{0}", expr, expr]],
            "exact_tenant_policy",
        )
        constraints = query(
            "SELECT conname, contype, pg_get_constraintdef(oid), convalidated, condeferrable, condeferred FROM pg_constraint WHERE conrelid='public.academy_oidc_login_states'::regclass ORDER BY conname"
        )
        REPORT["constraints"] = constraints
        expected_constraints = [
            ["academy_oidc_login_states_pkey", "p", "PRIMARY KEY (id)", True, False, False],
            [
                "fk_academy_oidc_login_tenant",
                "f",
                "FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE",
                True,
                False,
                False,
            ],
            ["uq_academy_oidc_login_tenant_state", "u", "UNIQUE (tenant_id, state_hash)", True, False, False],
        ]
        require(constraints == expected_constraints, "exact_pk_unique_fk_cascade")
        indexes = query(
            "SELECT i.relname, pg_get_indexdef(i.oid), x.indisvalid, x.indisready FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid WHERE x.indrelid='public.academy_oidc_login_states'::regclass ORDER BY i.relname"
        )
        REPORT["indexes"] = indexes
        require(
            indexes
            == [
                [
                    "academy_oidc_login_states_pkey",
                    "CREATE UNIQUE INDEX academy_oidc_login_states_pkey ON public.academy_oidc_login_states USING btree (id)",
                    True,
                    True,
                ],
                [
                    "ix_academy_oidc_login_states_tenant_id",
                    "CREATE INDEX ix_academy_oidc_login_states_tenant_id ON public.academy_oidc_login_states USING btree (tenant_id)",
                    True,
                    True,
                ],
                [
                    "uq_academy_oidc_login_tenant_state",
                    "CREATE UNIQUE INDEX uq_academy_oidc_login_tenant_state ON public.academy_oidc_login_states USING btree (tenant_id, state_hash)",
                    True,
                    True,
                ],
            ],
            "exact_indexes",
        )
        acl = query(
            "SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, pg_get_userbyid(a.grantor), a.privilege_type, a.is_grantable FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid='public.academy_oidc_login_states'::regclass ORDER BY 1,2,3,4"
        )
        REPORT["acl"] = acl
        nonowner = [r for r in acl if r[0] != "app_admin"]
        require(
            nonowner == [["app_user", "app_admin", p, False] for p in ["DELETE", "INSERT", "SELECT", "UPDATE"]],
            "public_revoked_exact_app_user_crud_no_other_grants",
        )
        require(all(r[1] == "app_admin" for r in acl if r[0] == "app_admin"), "owner_acl_grantor")
        owner_access = query(
            "SELECT has_table_privilege('app_admin','public.academy_oidc_login_states','SELECT'), has_table_privilege('app_admin','public.academy_oidc_login_states','INSERT'), has_table_privilege('app_admin','public.academy_oidc_login_states','UPDATE'), has_table_privilege('app_admin','public.academy_oidc_login_states','DELETE'), has_table_privilege('app_admin','public.academy_oidc_login_states','SELECT WITH GRANT OPTION'), has_table_privilege('app_admin','public.academy_oidc_login_states','INSERT WITH GRANT OPTION'), has_table_privilege('app_admin','public.academy_oidc_login_states','UPDATE WITH GRANT OPTION'), has_table_privilege('app_admin','public.academy_oidc_login_states','DELETE WITH GRANT OPTION')"
        )
        require(
            owner_access == [[True, True, True, True, True, True, True, True]], "owner_effective_crud_and_grant_options"
        )
        column_acl = query(
            "SELECT attname, attacl::text FROM pg_attribute WHERE attrelid='public.academy_oidc_login_states'::regclass AND attnum>0 AND attacl IS NOT NULL"
        )
        triggers = query(
            "SELECT tgname FROM pg_trigger WHERE tgrelid='public.academy_oidc_login_states'::regclass AND NOT tgisinternal ORDER BY tgname"
        )
        access = query(
            "SELECT has_schema_privilege('app_user','public','USAGE'), row_security_active('public.academy_oidc_login_states'::regclass)"
        )
        REPORT.update(column_acl=column_acl, noninternal_triggers=triggers, access=access)
        require(
            not column_acl and not triggers and access == [[True, False]], "no_extra_column_acl_triggers_or_hidden_rows"
        )
        count = query("SELECT count(*) FROM public.academy_oidc_login_states")
        REPORT["target_row_count"] = count[0][0]
        require(count == [[0]], "existing_oidc_target_empty")


def kernel_readback(query, m):
    # Literal catalogs only. Global platform table intentionally has NO RLS.
    table = query(
        "SELECT c.relkind, pg_get_userbyid(c.relowner), c.relrowsecurity, c.relforcerowsecurity, c.relispartition FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='rate_limit_buckets'"
    )
    REPORT["kernel_table"] = table
    if m["mode"] == "before":
        require(not table, "baseline_kernel_table_absent")
        roles = query("SELECT rolname FROM pg_roles WHERE rolname='platform_api'")
        REPORT["kernel_prerequisite_roles"] = roles
        require(roles == [["platform_api"]], "existing_platform_api_role_required_no_creation")
        return
    require(table == [["r", "app_admin", False, False, False]], "kernel_owner_global_no_rls")
    columns = query(
        "SELECT a.attname, format_type(a.atttypid,a.atttypmod), a.attnotnull, pg_get_expr(d.adbin,d.adrelid), a.attidentity, a.attgenerated FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid='public.rate_limit_buckets'::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum"
    )
    require(
        columns
        == [
            [n, t, True, None, "", ""]
            for n, t in [
                ("key_hash", "character varying(64)"),
                ("window_start", "timestamp with time zone"),
                ("hit_count", "integer"),
                ("expires_at", "timestamp with time zone"),
            ]
        ],
        "kernel_exact_columns_no_defaults",
    )
    policies = query(
        "SELECT polname FROM pg_policy WHERE polrelid='public.rate_limit_buckets'::regclass ORDER BY polname"
    )
    require(not policies, "kernel_no_tenant_policy")
    constraints = query(
        "SELECT conname, contype, pg_get_constraintdef(oid), convalidated, condeferrable, condeferred FROM pg_constraint WHERE conrelid='public.rate_limit_buckets'::regclass ORDER BY conname"
    )
    require(
        constraints
        == [
            ["ck_rate_limit_buckets_hit_count", "c", "CHECK ((hit_count >= 1))", True, False, False],
            ["pk_rate_limit_buckets", "p", "PRIMARY KEY (key_hash, window_start)", True, False, False],
        ],
        "kernel_exact_pk_check",
    )
    indexes = query(
        "SELECT i.relname, pg_get_indexdef(i.oid), x.indisvalid, x.indisready FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid WHERE x.indrelid='public.rate_limit_buckets'::regclass ORDER BY i.relname"
    )
    require(
        indexes
        == [
            [
                "ix_rate_limit_buckets_expires_at",
                "CREATE INDEX ix_rate_limit_buckets_expires_at ON public.rate_limit_buckets USING btree (expires_at)",
                True,
                True,
            ],
            [
                "pk_rate_limit_buckets",
                "CREATE UNIQUE INDEX pk_rate_limit_buckets ON public.rate_limit_buckets USING btree (key_hash, window_start)",
                True,
                True,
            ],
        ],
        "kernel_exact_indexes",
    )
    acl = query(
        "SELECT CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, pg_get_userbyid(a.grantor), a.privilege_type, a.is_grantable FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid='public.rate_limit_buckets'::regclass ORDER BY 1,2,3,4"
    )
    require(
        [r for r in acl if r[0] != "app_admin"]
        == [["platform_api", "app_admin", privilege, False] for privilege in ["DELETE", "INSERT", "SELECT", "UPDATE"]],
        "kernel_exact_platform_crud_public_app_user_denied",
    )
    require(all(r[1] == "app_admin" for r in acl if r[0] == "app_admin"), "kernel_owner_acl_grantor")
    owner_access = query(
        "SELECT has_table_privilege('app_admin','public.rate_limit_buckets','SELECT WITH GRANT OPTION'), has_table_privilege('app_admin','public.rate_limit_buckets','INSERT WITH GRANT OPTION'), has_table_privilege('app_admin','public.rate_limit_buckets','UPDATE WITH GRANT OPTION'), has_table_privilege('app_admin','public.rate_limit_buckets','DELETE WITH GRANT OPTION')"
    )
    require(owner_access == [[True, True, True, True]], "kernel_owner_effective_crud_grant_options")
    column_acl = query(
        "SELECT attname, attacl::text FROM pg_attribute WHERE attrelid='public.rate_limit_buckets'::regclass AND attnum>0 AND attacl IS NOT NULL"
    )
    triggers = query(
        "SELECT tgname FROM pg_trigger WHERE tgrelid='public.rate_limit_buckets'::regclass AND NOT tgisinternal ORDER BY tgname"
    )
    access = query(
        "SELECT has_table_privilege('app_user','public.rate_limit_buckets','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'), has_table_privilege('platform_api','public.rate_limit_buckets','SELECT'), has_table_privilege('platform_api','public.rate_limit_buckets','INSERT'), has_table_privilege('platform_api','public.rate_limit_buckets','UPDATE'), has_table_privilege('platform_api','public.rate_limit_buckets','DELETE'), has_table_privilege('app_admin','public.rate_limit_buckets','SELECT'), has_table_privilege('app_admin','public.rate_limit_buckets','INSERT'), has_table_privilege('app_admin','public.rate_limit_buckets','UPDATE'), has_table_privilege('app_admin','public.rate_limit_buckets','DELETE'), row_security_active('public.rate_limit_buckets'::regclass)"
    )
    require(
        not column_acl and not triggers and access == [[False, True, True, True, True, True, True, True, True, False]],
        "kernel_effective_privileges_no_hidden_rows",
    )
    count = query("SELECT count(*) FROM public.rate_limit_buckets")
    require(count == [[0]], "kernel_first_after_empty")
    REPORT.update(
        kernel_columns=columns,
        kernel_policies=policies,
        kernel_constraints=constraints,
        kernel_indexes=indexes,
        kernel_acl=acl,
        kernel_column_acl=column_acl,
        kernel_noninternal_triggers=triggers,
        kernel_access=access,
        kernel_row_count=count[0][0],
    )


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, "input_size")
        m = json.loads(raw)
        env = identity(m)
        with connect_settings(m, env) as conn:
            readback(conn, m)
            conn.rollback()
        REPORT["ok"] = True
    except Refusal as exc:
        REPORT["unmet_predicates"].append(str(exc))
    except Exception:
        # Never print exception messages/tracebacks: driver/config errors can carry DSNs.
        REPORT["unmet_predicates"].append("unexpected_error_details_suppressed")
    print(json.dumps(REPORT, sort_keys=True))
    return 0 if REPORT["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
