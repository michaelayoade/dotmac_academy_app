# Private retained row conservation groundwork

Source only. Tests are authored, NOT RUN. This slice issues no admission, product
phase, a004 permission, DDL, application activation or installed qualification.
The sole future issuer/registry/root Connection/physical XID/poison owner remains
`product_adoption`. It must store the exact returned private fragment under its
actual `_State`; equal constructed observations do not establish authority.
There is no new registry, handle, fence assertion, caller namespace or proof DTO.

## Acquisition remains closed

`_capture_retained_rows(connection, bindings)` calls the actual
`retained_schema._verify_historical_retained_schema` then actual
`retained_environment.observe_retained_environment` with a required exact typed
`HostedEnvironmentBindings`. Both gates currently always raise Unsupported.
The first refusal propagates immediately; there is no catch-and-continue or
internal-check substitute. No usable fragment can currently be returned. The
second real gate is independently exercised by a hosted refusal canary.
Internal observation helpers never create a fragment or product phase.

Future successful acquisition requires both gates to genuinely qualify, the
same real nonnested root/Connection, actual physical PostgreSQL XID, hidden SQL
parameters and disabled query logging, fixed schema/security checks, and actual
AccessExclusiveLock observations for all eleven retained relations. This helper
neither acquires locks nor establishes a fence. The product owner must first
fence/drain all actual writers including ERP senders and acquire its complete
ordered 47-table plus alembic lock set. Checking retained locks proves neither
that external fence nor lock acquisition order.

These helpers are strictly historical public-schema observations. Historical
fixed parent references cannot pass after canonical relocation or a004. Future
product integration must define/review exact actual identity-import continuity,
retained FK/internal RI-trigger delta, and final canonical source qualification;
this slice does not relax those checks or offer a namespace override. Admission
and a004 remain closed pending that work.

## Fixed byte protocol

The literal `_ROW_SPEC` is derived from the reviewed frozen62 retained schema:
eleven tables, every one of 166 columns, and the real primary key (`key` for
platform_settings, `tenant_id` for tenant_entrance_defaults, `id` elsewhere).
It includes all composite-key members and tenant/reference UUID cells. Expected
types and columns never come from observed catalogs. The retained fixed-source
structure/security checks run before any observation fingerprint; equal digests
are preservation evidence only, never initial data correctness evidence.

PostgreSQL computes one SHA256 per row using built-in `pg_catalog.sha256(bytea)`.
No extension is added. Row domain, table, each column name and exact source type
are length-framed UTF8 bytes; SQL NULL gets byte 00, nonnull gets byte 01 followed
by length-framed native payload. Every frame starts with network-order int8 byte
length. No separator collision, collation ordering or unordered aggregation is
used. Python receives only real PK identifier text and digest hex, then sorts
identifiers by UTF8 bytes. Row insertion, deletion and primary-key changes alter
the packet; whole-row replacement at an unchanged PK also alters the digest.

UUID/int4/bool/float8 use native PostgreSQL send bytes. Float8 distinguishes
signed zero and adjacent binary values without decimal rounding. JSONB uses its
native canonical text, with SQL NULL distinct from JSON null. Timestamptz uses
exact numeric epoch text, preserving microseconds and +/-Infinity independent
of session TimeZone. Dates use integer days from a fixed epoch and explicit
Infinity markers. Text uses exact UTF8 bytes. Native JSONB rendering is pinned
to the eventual qualified PostgreSQL environment; this is not cross-version
serialization or JSON business normalization.

No platform_settings.value, applicant token hash or other non-key cell is
returned to Python. Private fragments/table observations suppress repr. Digest
read driver exceptions become fixed generic errors without chained driver
DETAIL. Query logging/parameter visibility is refused by the established
preflight. Fragments capture the actual OIDs/full catalog, Connection/root/XID,
and all PK/digest pairs. Historical recheck repeats real qualification and fixed
source checks before comparing every row/OID/catalog and exact connection/root/
XID. Recheck is comparison only; it never authenticates a product phase.

## Hosted acceptance authored

`tests/test_academy_retained_history.py` requires its own empty, separately
provisioned `RETAINED_HISTORY_DATABASE_URL`, actual existing roles and explicit
non-secret environment bindings. It replays all genuine frozen62 migrations,
seeds existing actual historical identities and all eleven retained families,
and rolls test mutations back. No monkeypatch, fake successful gate, fabricated
admission, local Docker, create_all or current-ORM substitute is used.

Canaries cover real acquisition refusal with unchanged Connection.info, real
environment refusal, source166 correspondence, SQL NULL/JSON null and native
JSON object ordering, sensitive unchanged-ID mutations, tenant/composite members,
float8 signed zero/adjacent values, timestamp Infinity/timezone/microseconds,
insert/delete/real PK changes, missing locks, fixed namespace refusal, missing
relation/OID and composite-constraint drift, digest-only server comparison.

This partial source capsule inherits the exact 219-file manifest. Its historical
rehearsal fixture imports are intentionally unresolved until the genuine full
assembly supplies them; no source shim is introduced. Dedicated hosted DSN/CI
wiring, service-image/environment authentication, complete fixture assembly,
full runtime collection, installed dependencies and populated whole-assembly
qualification are owed. Neither helper comparisons nor authored tests close
these gates. ERP remains Integration-only; ACK state is inert here. Later
recovery must preserve newly accepted facts under the product owner's reviewed
recovery protocol; this slice performs no rollback/recovery writes.
