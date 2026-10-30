"""Academy physical providers for installed modules' logical prerequisites.

Graph-only Alembic commands never load env.py. The canonical migration CLI
sets DOTMAC_MIGRATION_BINDINGS to this module before constructing any graph;
revision resolve_depends_on calls can therefore use Kernel autoload_bindings.
Bindings describe real providers; live prerequisite verification remains required.
"""

from dotmac_kernel.prerequisites import PrerequisiteBinding

ASSEMBLY_PREREQUISITE_BINDINGS = (
    PrerequisiteBinding("tenant_scope_catalog.v1", "0001_initial_tenant_schema", "kernel"),
    PrerequisiteBinding("module_database_roles.v1", "0001_initial_tenant_schema", "kernel"),
    PrerequisiteBinding("party_person_catalog.v1", "0003_party_identity", "kernel"),
    PrerequisiteBinding("tenant_audit_log.v1", "0029_audit_history_shape", "kernel"),
)
