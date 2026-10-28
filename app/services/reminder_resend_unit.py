"""Fixed reminder receipts in the genuine caller transaction (source-only V3).

Private SQLAlchemy ancestry/association reads are version-pinned dependencies.
No engine, transaction authority, business policy or public capability is issued.
"""
import re
import sys
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field
from threading import RLock
from typing import NoReturn, NotRequired, Protocol, TypedDict, cast
from uuid import UUID
from weakref import WeakKeyDictionary

from dotmac_kernel.audit import AuditEvent
from dotmac_kernel.models import AuthSession, Party, PartyPerson, PartyRoleGrant, Role
from dotmac_kernel.transactions import (
    ConflictSavepointPhase,
    claim_conflict_savepoint_commit,
    conflict_savepoint_requires_rollback,
    current_conflict_savepoint,
)
from sqlalchemy import __version__ as sqlalchemy_version
from sqlalchemy import event, inspect, select
from sqlalchemy.engine import Connection, Transaction, TwoPhaseTransaction
from sqlalchemy.engine.default import DefaultDialect
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.orm import Session, SessionTransaction
from sqlalchemy.orm.session import SessionTransactionOrigin
from sqlalchemy.sql.compiler import Compiled
from sqlalchemy.sql.ddl import ExecutableDDLElement
from sqlalchemy.sql.elements import TextClause
from sqlalchemy.sql.visitors import iterate

from app.models.email_outbox import EmailOutbox
from app.models.identity_extensions import AcademyAccountProfile
from app.models.platform_settings import PlatformSetting
from app.models.reminder import ReminderLog

# Native dispatch records preserve the callable and the previous instance slot.
_ControlMethods = list[tuple[str, bool, object, Callable[..., object]]]
_ControlRecord = tuple[WeakKeyDictionary[Connection, "ReminderUnit"], _ControlMethods]
_DriverRecord = tuple[
    Callable[..., object], bool, object, Callable[..., object], dict[int, tuple[object, "ReminderUnit"]]
]


class _Deannotatable(Protocol):
    def _deannotate(self) -> object: ...


class _ControlClause(Protocol):
    __visit_name__: str
    ident: str


class _ControlScope(TypedDict):
    visit: str
    ident: str
    target: object
    clause: object | None
    depth: int
    consumed: bool


class _Command(TypedDict):
    logical: tuple[SessionTransaction, ...]
    physical: tuple[Transaction, ...]
    count: int
    tenant_id: NotRequired[UUID]
    prior: NotRequired[dict[str, dict[UUID, dict[str, object]]]]


# Additional SQLAlchemy 2.0.51 private call-site dependency. Only the immediate
# native _flush caller may enter the internal abort wrapper; never scan a stack.
_NATIVE_FLUSH_CODE = Session._flush.__code__
_LOCK = RLock()
_ACTIVE: WeakKeyDictionary[Session, "ReminderUnit"] = WeakKeyDictionary()
_TX_HANDLERS: WeakKeyDictionary[object, dict[str, Callable[..., object]]] = WeakKeyDictionary()
_TX_METHODS = {}
_DIALECTS: WeakKeyDictionary[Dialect, _DriverRecord] = WeakKeyDictionary()
_CONTROL_DIALECTS: WeakKeyDictionary[Dialect, _ControlRecord] = WeakKeyDictionary()
_CONNECTIONS: WeakKeyDictionary[Connection, "ReminderUnit"] = WeakKeyDictionary()
_SENTINELS: dict[type[Dialect], dict[str, Callable[..., None]]] = {}
_EXECUTION_EVENTS = ("do_execute", "do_execute_no_params", "do_executemany")
_AUTHORITY_TABLES = frozenset(model.__table__ for model in (
    AuthSession, Party, PartyPerson, AcademyAccountProfile, Role, PartyRoleGrant, PlatformSetting,
))
_CONTROL_VISITS = {"do_savepoint": "savepoint", "do_release_savepoint": "release_savepoint",
                   "do_rollback_to_savepoint": "rollback_to_savepoint"}
_MODE_OPTIONS = frozenset({"isolation_level", "autocommit", "schema_translate_map",
                           "postgresql_readonly", "postgresql_deferrable"})


class ReminderResendError(RuntimeError):
    """Refused command/custody; messages contain no token or recipient material."""


def values(row):
    return {column.key: deepcopy(getattr(row, column.key)) for column in row.__table__.columns}


def _chain(transaction, attribute):
    result = []
    while transaction is not None:
        result.append(transaction)
        transaction = getattr(transaction, attribute)
    return tuple(result)


def _read_sql(statement):
    """Conservative single SELECT: no comments, controls, quoting or separator tricks.

    A narrow recognizer is intentional. This does not attest arbitrary functions
    or arbitrary Python/DBAPI interference, which are outside this boundary.
    """
    try:
        sql, root, words = _sql_tokens(statement)
    except ReminderResendError:
        return False
    return (root == "SELECT" and len(words) >= 1 and len(sql.split(None, 1)) == 2
            and words[0] == "SELECT"
            and not {"INTO", "FOR", "COPY", "COMMIT", "ROLLBACK", "SAVEPOINT"}.intersection(words))


def pending_authority(db):
    """Observe native mapped pending history; no load, refresh, flush or expiry."""
    return any(inspect(row).mapper.local_table in _AUTHORITY_TABLES
               for row in (*db.new, *db.dirty, *db.deleted))


def authority_preflight(db):
    if pending_authority(db):
        unit = _unit(db)
        if unit is not None:
            unit.refuse("pending authority must be explicitly flushed before command reads")
        raise ReminderResendError("pending authority must be explicitly flushed before command reads")


def _transactional_mode(db, connection, root, physical):
    if (sqlalchemy_version != "2.0.51" or connection.dialect.name != "postgresql"
            or connection.dialect.driver != "psycopg" or db.twophase
            or isinstance(root, TwoPhaseTransaction) or root is None
            or connection._is_autocommit_isolation() or getattr(physical, "autocommit", None) is not False
            or connection.get_execution_options().get("schema_translate_map")):
        raise ReminderResendError("unqualified transactional PostgreSQL caller configuration")


def caller_configuration(db):
    if db.twophase:
        raise ReminderResendError("two-phase caller is outside the reminder contract")
    connection = db.connection()
    _transactional_mode(db, connection, connection.get_transaction(), connection.connection.dbapi_connection)
    _sentinel_admission(connection.dialect)


def _unwrapped(clause):
    return clause.statement if isinstance(clause, Compiled) else clause


def _lexical(statement):
    sql = str(statement).strip()
    if not sql or any(mark in sql for mark in (";", "--", "/*", "*/", "\\", "\x00")):
        raise ReminderResendError("unsupported rendered SQL grammar")
    match = re.match(r"[A-Za-z_]+", sql)
    return sql, "" if match is None else match[0].upper()


def _sql_tokens(statement):
    """Shared early/final grammar: quoted identifiers/values/binds are atomic.

    In particular INTO touching a quoted identifier is still an unquoted word.
    Parameter values are never an input to this recognizer.
    """
    sql, root = _lexical(statement)
    tokens = re.findall(
        r"%\([^)]+\)s|%s|(?<!:):[A-Za-z_][A-Za-z_0-9]*|\"(?:[^\"]|\"\")*\"|"
        r"'(?:[^']|'')*'|[A-Za-z_][A-Za-z_0-9$]*|[(),]|\S", sql,
    )
    words = [token.upper() for token in tokens if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9$]*", token)]
    return sql, root, words


def _classify(clause):
    """One structural/text classifier; rendered admission remains mandatory."""
    clause = _unwrapped(clause)
    if isinstance(clause, ExecutableDDLElement):
        raise ReminderResendError("DDL is outside the fixed reminder boundary")
    if getattr(clause, "__visit_name__", "") in _CONTROL_VISITS.values():
        return "control", clause
    if getattr(clause, "_is_text_clause", False):
        if not _read_sql(clause.text):
            raise ReminderResendError("textual SQL must be one conservative SELECT")
        return "text", clause
    if not (getattr(clause, "is_select", False) or getattr(clause, "is_dml", False)):
        raise ReminderResendError("unsupported statement construction")
    root_dml = clause if getattr(clause, "is_dml", False) else None
    for node in iterate(clause):
        if isinstance(node, ExecutableDDLElement):
            raise ReminderResendError("DDL cannot be embedded in a reminder statement")
        if getattr(node, "_is_text_clause", False) and not _read_sql(cast(TextClause, node).text):
            raise ReminderResendError("nested textual SQL must be one conservative SELECT")
        if getattr(node, "is_dml", False) and node is not root_dml:
            raise ReminderResendError("additional DML/CTE writes are refused")
        if getattr(node, "_prefixes", ()) or getattr(node, "_suffixes", ()):
            raise ReminderResendError("SQL prefix/suffix extensions are unsupported")
        if getattr(node, "is_literal", False):
            name = str(getattr(node, "name", ""))
            if not re.fullmatch(r"(?:[0-9]+|\*|[A-Za-z_][A-Za-z_0-9.]*)", name):
                raise ReminderResendError("literal SQL fragment is unsupported")
    if getattr(clause, "_is_textual", False):
        return "text", clause
    kind = ("insert" if getattr(clause, "is_insert", False) else
            "update" if getattr(clause, "is_update", False) else
            "delete" if getattr(clause, "is_delete", False) else "select")
    return kind, clause


def _rendered(statement, kind, clause):
    sql, root, words = _sql_tokens(statement)
    # Values remain bound parameters and never enter this grammar check.
    # Only the single native INSERT root may own INTO; a SELECT INTO is DDL.
    if words.count("INTO") != (1 if kind == "insert" else 0):
        raise ReminderResendError("rendered SQL contains an undeclared INTO clause")
    forbidden = {"COMMIT", "ABORT", "BEGIN", "START", "SAVEPOINT", "RELEASE", "PREPARE", "ROLLBACK",
                 "VACUUM", "ALTER", "DROP", "CREATE", "TRUNCATE", "COPY", "GRANT", "REVOKE", "DISCARD"}
    if forbidden.intersection(words) or re.search(r"\$[A-Za-z_0-9]*\$", sql):
        raise ReminderResendError("transaction/utility SQL is refused")
    counts = {word: 0 for word in ("INSERT", "UPDATE", "DELETE", "MERGE")}
    cases = 0
    for index, word in enumerate(words):
        if word == "CASE":
            cases += 1
        elif word == "END":
            if not cases:
                raise ReminderResendError("unscoped END control is refused")
            cases -= 1
        if word in counts:
            lock = (word == "UPDATE" and (words[max(0, index - 1):index] == ["FOR"]
                    or words[max(0, index - 3):index] == ["FOR", "NO", "KEY"]))
            upsert = word == "UPDATE" and kind == "insert" and words[max(0, index - 1):index] == ["DO"]
            if not lock and not upsert:
                counts[word] += 1
    for word, count in counts.items():
        expected = 1 if kind == word.lower() else 0
        if count != expected:
            raise ReminderResendError("rendered statement contains an additional/different DML root")
    if kind == "text":
        if root != "SELECT" or not _read_sql(sql):
            raise ReminderResendError("rendered textual SQL is not a supported SELECT")
    elif root != kind.upper():
        if root != "WITH" or not any(getattr(node, "__visit_name__", "") == "cte" for node in iterate(clause)):
            raise ReminderResendError("rendered root disagrees with admitted structure")
    return sql


def _exclusive(dialect):
    sentinels = _SENTINELS.get(type(dialect))
    if not dialect._has_events or sentinels is None:
        raise ReminderResendError("final dialect execution sentinels are absent")
    for name in _EXECUTION_EVENTS:
        if tuple(getattr(dialect.dispatch, name)) != (sentinels[name],):
            raise ReminderResendError("guarded dialect requires exclusive execution sentinels")


def _sentinel_admission(dialect):
    cls = type(dialect)
    with _LOCK:
        if cls not in _SENTINELS:
            sentinels: dict[str, Callable[..., None]] = {}
            _SENTINELS[cls] = sentinels
            for name in _EXECUTION_EVENTS:
                def sentinel(cursor, statement, *args, _name=name):
                    context = args[-1]
                    with _LOCK:
                        owner = _CONNECTIONS.get(context.root_connection)
                    if owner is not None:
                        owner.final_cursor(cursor, statement, context, _name)
                    return None
                try:
                    event.listen(cls, name, sentinel)
                except BaseException:
                    if event.contains(cls, name, sentinel):
                        sentinels[name] = sentinel
                    raise
                sentinels[name] = sentinel
            _SENTINELS[cls] = sentinels
        for name in _EXECUTION_EVENTS:
            if name not in _SENTINELS[cls]:
                def sentinel(cursor, statement, *args, _name=name):
                    context = args[-1]
                    with _LOCK:
                        owner = _CONNECTIONS.get(context.root_connection)
                    if owner is not None:
                        owner.final_cursor(cursor, statement, context, _name)
                    return None
                try:
                    event.listen(cls, name, sentinel)
                except BaseException:
                    if event.contains(cls, name, sentinel):
                        _SENTINELS[cls][name] = sentinel
                    raise
                _SENTINELS[cls][name] = sentinel
        _exclusive(dialect)


def _install_sql(unit):
    _sentinel_admission(unit.connection.dialect)
    with _LOCK:
        if unit.connection in _CONNECTIONS:
            raise ReminderResendError("a guarded Connection is already registered")
        unit.sql_registered = True
        _CONNECTIONS[unit.connection] = unit


def _control_guard(unit):
    dialect = unit.connection.dialect
    with _LOCK:
        record = _CONTROL_DIALECTS.get(dialect)
        if record is None:
            entries: WeakKeyDictionary[Connection, "ReminderUnit"] = WeakKeyDictionary()
            methods: _ControlMethods = []
            try:
                for name in _CONTROL_VISITS:
                    original = getattr(dialect, name)
                    if getattr(original, "__func__", None) is not getattr(DefaultDialect, name):
                        raise ReminderResendError("native control implementation requires separate qualification")
                    existed, previous = name in dialect.__dict__, dialect.__dict__.get(name)
                    def guarded(connection, ident, _name=name, _original=original):
                        with _LOCK:
                            owner = entries.get(connection)
                        if owner is not None:
                            return owner.native_control(_name, connection, ident, _original)
                        return _original(connection, ident)
                    methods.append((name, existed, previous, guarded))
                    setattr(dialect, name, guarded)
            except BaseException:
                for method, existed, previous, guarded in reversed(methods):
                    if dialect.__dict__.get(method) is guarded:
                        if existed:
                            setattr(dialect, method, previous)
                        else:
                            delattr(dialect, method)
                raise
            record = (entries, methods)
            _CONTROL_DIALECTS[dialect] = record
        if any(dialect.__dict__.get(name) is not guarded for name, _existed, _previous, guarded in record[1]):
            raise ReminderResendError("native control dispatch was replaced during a guarded lifetime")
        unit.control_registration = (dialect, record)
        record[0][unit.connection] = unit


def _remove_control_guard(unit):
    if unit.control_registration is None:
        return
    dialect, record = unit.control_registration
    with _LOCK:
        if record[0].get(unit.connection) is unit:
            record[0].pop(unit.connection)
        if not record[0]:
            for name, existed, previous, guarded in record[1]:
                if dialect.__dict__.get(name) is guarded:
                    if existed:
                        setattr(dialect, name, previous)
                    else:
                        delattr(dialect, name)
            if _CONTROL_DIALECTS.get(dialect) is record:
                _CONTROL_DIALECTS.pop(dialect)
    unit.control_registration = None


def _slot_method(obj, name):
    cls, key = type(obj), (type(obj), name)
    with _LOCK:
        if key not in _TX_METHODS:
            original = getattr(cls, name)
            _TX_METHODS[key] = original
            def dispatch(transaction, *args, **kwargs):
                with _LOCK:
                    handler = _TX_HANDLERS.get(transaction, {}).get(name)
                if handler is not None:
                    return handler(*args, **kwargs)
                return original(transaction, *args, **kwargs)
            setattr(cls, name, dispatch)
        return _TX_METHODS[key].__get__(obj, cls)


def _driver_guard(unit):
    """Final pre-driver latch after every Connection commit event callback.

    Registered by exact DBAPI identity; no lock spans a driver call. The captured
    original dispatch remains native for every unrelated physical connection.
    """
    dialect = unit.connection.dialect
    with _LOCK:
        record = _DIALECTS.get(dialect)
        if record is None:
            original = dialect.do_commit
            existed, previous = "do_commit" in dialect.__dict__, dialect.__dict__.get("do_commit")
            entries: dict[int, tuple[object, ReminderUnit]] = {}
            def guarded(connection):
                raw = getattr(connection, "dbapi_connection", connection)
                with _LOCK:
                    registered = entries.get(id(raw))
                    owner = registered[1] if registered is not None and registered[0] is raw else None
                if owner is not None:
                    owner.driver_commit()
                return original(connection)
            record = (original, existed, previous, guarded, entries)
            dialect.do_commit = guarded
            _DIALECTS[dialect] = record
        unit.driver_registration = (dialect, record)
        record[4][id(unit.physical)] = (unit.physical, unit)


def _remove_driver_guard(unit):
    if unit.driver_registration is None:
        return
    dialect, record = unit.driver_registration
    with _LOCK:
        entry = record[4].get(id(unit.physical))
        if entry is not None and entry[1] is unit:
            record[4].pop(id(unit.physical))
        if not record[4]:
            if dialect.__dict__.get("do_commit") is record[3]:
                if record[1]:
                    dialect.do_commit = record[2]
                else:
                    del dialect.do_commit
            if _DIALECTS.get(dialect) is record:
                _DIALECTS.pop(dialect)
    unit.driver_registration = None


@dataclass
class _Receipt:
    pins: tuple
    authority: object
    logical: tuple[SessionTransaction, ...]
    physical: tuple[Transaction, ...]
    baseline: tuple


@dataclass
class _Frame:
    operation: str
    entry: object
    logical: frozenset[object]
    physical: frozenset[object]
    target: object
    calls: set[tuple[int, str]] = field(default_factory=set)
    completed: set[object] = field(default_factory=set)
    sealed: bool = False


@dataclass
class _InternalAbort:
    transaction: object
    root: object
    epoch: int
    original: object
    existed: bool
    previous: object
    wrapper: object = None
    consumed: bool = False
    active: bool = False
    ended: bool = False


class ReminderUnit:
    def __init__(self, db):
        self.db, self.root = db, db.get_transaction()
        self.connection = db.connection()
        self.physical_root = self.connection.get_transaction()
        self.physical = self.connection.connection.dbapi_connection
        self.bind = db.get_bind()
        self.executing = self.failed = self.corrupt = self.ended = False
        self.phase = "read"
        self.frame: _Frame | None = None
        self.opening = None
        self.helper = self.helper_physical = None
        self.command: _Command | None = None
        self.pending: _Receipt | None = None
        self.receipts = []
        self.logical = set()
        self.physical_transactions = set()
        self.pairs = {}
        self.rollback_proofs = set()
        self.logical_aborts = set()
        self.waiting_aborts = set()
        self.patches = []
        self.installed = set()
        self.generation, self.stamp = 0, -1
        self.validating = self.fencing = 0
        self.deferred = False
        self.execute_depth = 0
        self.control_scope: _ControlScope | None = None
        self.internal_aborts = {}
        self.native_abort: _InternalAbort | None = None
        self.command_epoch = 0
        self.driver_registration = self.control_registration = None
        self.sql_registered = False
        self.listened = []
        self.listeners = (
            ("commit", self.connection_commit), ("rollback", self.connection_rollback),
            ("savepoint", self.connection_savepoint), ("release_savepoint", self.connection_release),
            ("rollback_savepoint", self.connection_recovery), ("before_execute", self.before_execute),
            ("before_cursor_execute", self.before_cursor_execute),
        )
        self.check_mode()
        with _LOCK:
            if db in _ACTIVE:
                raise ReminderResendError("a resend unit is already active")
            _ACTIVE[db] = self
        try:
            for obj, names in ((db, ("commit", "rollback", "close", "invalidate", "begin", "begin_nested", "prepare")),
                               (self.connection, ("commit", "rollback", "close", "invalidate", "begin", "begin_nested",
                                                  "execute", "execution_options", "detach", "begin_twophase",
                                                  "commit_prepared", "rollback_prepared", "recover_twophase"))):
                for name in names:
                    self.patch(obj, name)
            self.register_physical(self.physical_root)
            for transaction in _chain(self.connection.get_nested_transaction(), "_previous_nested"):
                self.register_physical(transaction)
            # SQLAlchemy's actual _connections association records the after_begin
            # relationship for already-materialized caller ancestors. Never zip names
            # or infer a logical pair from whichever savepoint is current later.
            for transaction in reversed(_chain(db.get_nested_transaction() or self.root, "parent")):
                self.register_logical(transaction)
                self.capture_association(transaction)
            for name, listener in self.listeners:
                self.listened.append((name, listener))
                event.listen(self.connection, name, listener)
            _install_sql(self)
            _control_guard(self)
            _driver_guard(self)
            self.require()
        except BaseException:
            self.clear()
            raise

    def refuse(self, message, *, corrupt=False) -> NoReturn:
        self.failed = True
        self.corrupt = self.corrupt or corrupt or self.command is None
        raise ReminderResendError(message)

    def register_logical(self, transaction):
        if transaction in self.logical:
            return
        if transaction is not self.root and not transaction.nested:
            return  # SQLAlchemy internal flush subtransactions are not nesting.
        if self.root not in _chain(transaction, "parent"):
            self.refuse("caller logical ancestry changed", corrupt=True)
        self.logical.add(transaction)
        for name in ("commit", "rollback", "close"):
            self.patch(transaction, name)

    def register_internal_abort(self, transaction):
        # after_transaction_create runs after native Session._transaction changes.
        # These objects are not logical caller boundaries or completion targets.
        if (not self.db._flushing or transaction.nested
                or transaction.origin is not SessionTransactionOrigin.SUBTRANSACTION
                or self.db._transaction is not transaction):
            return
        if self.root not in _chain(transaction, "parent"):
            self.refuse("internal flush ancestry changed", corrupt=True)
        with _LOCK:
            if transaction in self.internal_aborts:
                return
            record = _InternalAbort(transaction, self.root, self.command_epoch,
                transaction.rollback, "rollback" in transaction.__dict__, transaction.__dict__.get("rollback"))
            def abort(*args, **kwargs):
                # Obtain evidence here, BEFORE any generic wrapper or helper.
                # Never retain the frame, its locals, exception or traceback.
                caller = sys._getframe(1)
                try:
                    native = (caller.f_code is _NATIVE_FLUSH_CODE
                              and caller.f_locals.get("self") is self.db
                              and caller.f_locals.get("transaction") is transaction)
                finally:
                    del caller
                return self.internal_abort(record, native, args, kwargs)
            record.wrapper = abort
            self.internal_aborts[transaction] = record
            try:
                transaction.rollback = abort
            except BaseException:
                self.remove_internal_abort(record)
                raise

    def remove_internal_abort(self, record):
        with _LOCK:
            transaction = record.transaction
            if transaction is not None and transaction.__dict__.get("rollback") is record.wrapper:
                if record.existed:
                    transaction.rollback = record.previous
                else:
                    del transaction.rollback
            if self.internal_aborts.get(transaction) is record:
                self.internal_aborts.pop(transaction)
            record.transaction = record.root = record.original = record.previous = record.wrapper = None

    def internal_ended(self, transaction):
        with _LOCK:
            record = self.internal_aborts.get(transaction)
            if record is not None:
                record.ended = True
                if not record.active:
                    self.remove_internal_abort(record)

    def internal_abort(self, record: _InternalAbort, native, args, kwargs):
        transaction = record.transaction
        capture = kwargs.get("_capture_exception", args[0] if args else False)
        to_root = kwargs.get("_to_root", args[1] if len(args) > 1 else False)
        if (not native or capture is not True or to_root is not False or len(args) > 2
                or set(kwargs) - {"_capture_exception", "_to_root"}
                or sys.exception() is None or self.ended or not self.db._flushing
                or self.native_abort is not None or record.consumed or record.ended
                or self.internal_aborts.get(transaction) is not record
                or transaction is not self.db._transaction or record.root is not self.root
                or record.epoch != self.command_epoch or self.db.get_transaction() is not self.root
                or self.db.get_bind() is not self.bind or self.connection.closed or self.connection.invalidated
                or self.connection.get_transaction() is not self.physical_root
                or self.connection.connection.dbapi_connection is not self.physical):
            self.refuse("internal rollback has no exact native flush origin", corrupt=True)
        # Same nearest actual root/nested-boundary rule as native rollback.
        boundary = next((t for t in _chain(transaction, "parent") if t.parent is None or t.nested), None)
        target = self.pairs.get(boundary)
        association = set(boundary._connections.values()) if boundary is not None else set()
        if (boundary not in self.logical or target is None or not target.is_active
                or not association or any(c is not self.connection or p is not target
                                          for c, p, _commit, _close in association)
                or target not in self.physical_transactions
                or (target is not self.physical_root and self.connection.get_nested_transaction() is not target)):
            self.refuse("internal rollback boundary association changed", corrupt=True)
        outer = self.frame
        frame: _Frame | None = _Frame("abort", transaction, frozenset((boundary,)), frozenset((target,)), target)
        record.consumed = record.active = True
        self.failed = True
        self.stamp = -1
        if outer is not None:
            outer.sealed = False
        self.native_abort = record
        self.frame = frame
        original = record.original
        try:
            # Native rollback and safe_reraise retain the selected exception.
            # No manual root abort or fabricated physical success is permitted.
            return original(*args, **kwargs)
        except BaseException:
            if not self.ended:
                self.failed = self.corrupt = True
            raise
        finally:
            record.active = False
            self.remove_internal_abort(record)
            if not self.ended:
                self.native_abort = None
                self.frame = outer
                self.stamp = -1
                self.failed = True
            outer = frame = original = transaction = boundary = target = None

    def register_physical(self, transaction):
        if transaction is None or transaction in self.physical_transactions:
            return
        self.physical_transactions.add(transaction)
        for name in ("commit", "rollback", "close"):
            self.patch(transaction, name)

    def capture_association(self, logical):
        for connection, physical, _commit, _close in logical._connections.values():
            if connection is not self.connection:
                self.refuse("resend transaction acquired another Connection", corrupt=True)
            if physical is not self.physical_root and self.physical_root is not self.connection.get_transaction():
                self.refuse("resend physical root changed", corrupt=True)
            self.pairs[logical] = physical
            self.register_physical(physical)
            if self.frame is not None and logical in self.frame.logical:
                self.frame.physical = self.frame.physical | {physical}

    def patch(self, obj, name):
        key = (id(obj), name)
        if key in self.installed:
            return
        self.installed.add(key)
        slotted = not hasattr(obj, "__dict__")
        original = _slot_method(obj, name) if slotted else getattr(obj, name)
        existed, previous = (None, None) if slotted else (name in obj.__dict__, obj.__dict__.get(name))
        def guarded(*args, **kwargs):
            if self.ended:
                return original(*args, **kwargs)
            return self.dispatch(obj, name, original, args, kwargs)
        self.patches.append((obj, name, existed, previous, guarded))
        if slotted:
            with _LOCK:
                _TX_HANDLERS.setdefault(obj, {})[name] = guarded
        else:
            setattr(obj, name, guarded)

    def check_mode(self):
        _transactional_mode(self.db, self.connection, self.physical_root, self.physical)

    def require(self, *, prepared=False):
        self.check_mode()
        if self.failed:
            self.refuse("resend custody is already refused")
        current = self.db._transaction
        provisioning = (current in self.logical and current.nested
                        and getattr(current._state, "name", "") == "PROVISIONING_CONNECTION")
        active = self.db.is_active or (prepared and self.frame is not None) or provisioning
        if (self.ended or self.corrupt or not active or self.db.get_transaction() is not self.root
                or conflict_savepoint_requires_rollback(self.db, expected_root=self.root)
                or self.db.get_bind() is not self.bind or self.connection.closed or self.connection.invalidated
                or self.connection.get_transaction() is not self.physical_root or not self.physical_root.is_active
                or self.connection.connection.dbapi_connection is not self.physical):
            self.refuse("resend caller transaction custody changed", corrupt=True)
        if self.executing and (self.db.get_nested_transaction() is not self.helper
                               or self.connection.get_nested_transaction() is not self.helper_physical):
            self.refuse("resend helper ancestry changed", corrupt=True)

    def helper_phase(self, phase):
        state = current_conflict_savepoint(self.db)
        return (state is not None and state.root is self.root and state.savepoint is self.helper
                and state.phase is phase)

    def _pins(self, *, pending=True):
        folded = {}
        for receipt in (*self.receipts, *((self.pending,) if pending and self.pending is not None else ())):
            for row, expected in receipt.pins:
                folded[(row.__table__.name, expected["id"])] = (row, expected)
        return tuple(folded.values())

    def _dirty(self):
        for row, expected in self._pins():
            state = inspect(row)
            if state.deleted:
                self.refuse("a fixed resend consequence was deleted")
            # Direct dict/history access performs no lazy load in PREPARED.
            for key, value in expected.items():
                if key in state.dict and state.dict[key] != value:
                    self.refuse("a fixed resend consequence changed")
                history = state.attrs[key].history
                if history.has_changes() and (not history.added or history.added[0] != value):
                    self.refuse("a dirty resend consequence differs")

    def _persisted(self):
        for row, expected in self._pins():
            actual = self.connection.execute(select(*row.__table__.columns).where(
                row.__table__.c.id == expected["id"],
            )).mappings().one_or_none()
            if actual is None or dict(actual) != expected:
                self.refuse("a persisted resend consequence differs")

    def validate(self, *, dirty=True, defer=False):
        try:
            self.require()
            if self.failed or self.waiting_aborts:
                self.refuse("resend custody requires actual caller rollback")
            if dirty:
                self._dirty()  # Before authority reads can refresh any object.
            if pending_authority(self.db):
                self.stamp = -1
                self.deferred = True
                if defer:
                    return False
                self.refuse("pending authority cannot authorize physical completion")
            self.deferred = False
            self.validating += 1
            try:
                with self.db.no_autoflush:
                    for receipt in (*self.receipts, *((self.pending,) if self.pending is not None else ())):
                        receipt.authority()
                    self._persisted()
                self.require()
                self.stamp = self.generation
            finally:
                self.validating -= 1
        except BaseException:
            self.failed = True
            if self.command is None:
                self.corrupt = True
            raise

    def fence(self):
        self.require(prepared=True)
        if (self.failed or self.waiting_aborts or self.stamp != self.generation
                or self.deferred or pending_authority(self.db)):
            self.refuse("final resend authority stamp changed", corrupt=True)
        self.fencing += 1
        try:
            self._dirty()
            # The logical Session may already be PREPARED. These exact scalar
            # reads use its captured Connection, never Session.execute.
            self._persisted()
            self.require(prepared=True)
            self.stamp = self.generation
            cast(_Frame, self.frame).sealed = True
        finally:
            self.fencing -= 1

    def _targets(self, target):
        if target in (self.db, self.connection, self.root, self.physical_root):
            return (frozenset(t for t in self.logical if t.is_active or t is self.root),
                    frozenset(t for t in self.physical_transactions if t.is_active or t is self.physical_root))
        if target in self.logical:
            logical = frozenset(t for t in self.logical if target in _chain(t, "parent"))
            physical = frozenset(self.pairs[t] for t in logical if t in self.pairs)
            return logical, physical
        physical = frozenset(t for t in self.physical_transactions
                             if t is target or (hasattr(t, "_previous_nested")
                             and target in _chain(t, "_previous_nested")))
        logical = frozenset(t for t, p in self.pairs.items() if p in physical)
        return logical, physical

    def dispatch(self, obj, name, original, args, kwargs):
        if name == "execute":
            return self.execute_entry(original, args, kwargs)
        if name in ("prepare", "begin_twophase", "commit_prepared", "rollback_prepared", "recover_twophase", "detach"):
            self.refuse("unsupported transaction completion/configuration entry")
        if name == "execution_options":
            if _MODE_OPTIONS.intersection(kwargs):
                self.refuse("transaction-affecting execution options are fixed")
            return original(*args, **kwargs)
        if name in ("begin", "begin_nested"):
            return self.open(obj, name, original, args, kwargs)
        if self.native_abort is not None:
            # Proven native scope precedes the ordinary participant refusal.
            # It grants only this exact physical rollback, never Session or
            # Connection completion, close, sibling/root abort, or release.
            if obj is cast(_Frame, self.frame).target and name == "rollback":
                return self.cascade(obj, name, original, args, kwargs)
            self.refuse("completion cannot borrow the native flush abort")
        if self.db._flushing:
            # Flush/user/error callbacks cannot borrow the enclosing caller's
            # completion frame. Native physical commit happens after flush ends.
            self.refuse("flush callback attempted transaction completion")
        recovering = self.helper_phase(ConflictSavepointPhase.ROLLBACK)
        releasing = self.helper_phase(ConflictSavepointPhase.RELEASE)
        helper_target = obj is self.helper or obj is self.helper_physical
        if self.executing and not (recovering and helper_target and name in ("rollback", "close")):
            self.refuse("participant attempted transaction completion")
        if self.command is not None and not ((recovering or releasing) and helper_target):
            self.refuse("participant attempted completion during helper lifetime")
        if self.frame is not None:
            return self.cascade(obj, name, original, args, kwargs)
        operation = "commit" if name == "commit" else "abort"
        if helper_target:
            if not ((operation == "commit" and releasing and not self.failed)
                    or (operation == "abort" and recovering)):
                self.refuse("participant attempted helper completion")
            logical, physical = frozenset((self.helper,)), frozenset((self.helper_physical,))
            operation = "helper_release" if operation == "commit" else "helper_recovery"
        else:
            logical, physical = self._targets(obj)
        frame = _Frame(operation, obj, logical, physical, obj)
        self.frame = frame
        try:
            if operation in ("commit", "helper_release"):
                logical_entry = operation == "commit" and (obj is self.db or obj in self.logical)
                self.validate(defer=logical_entry)
            result = self.cascade(obj, name, original, args, kwargs)
            # Physical direct root completion is native; do not manufacture a
            # new logical Session transaction for SQLAlchemy's stale handle.
            if not self.ended and (self.connection.closed or self.connection.invalidated
                    or self.physical_root in self.rollback_proofs
                    or (operation == "commit" and self.physical_root in frame.completed)):
                self.clear()
            return result
        finally:
            if not self.ended:
                self.frame = None

    def cascade(self, obj, name, original, args, kwargs):
        frame = cast(_Frame, self.frame)
        if (obj not in frame.logical and obj not in frame.physical
                and obj not in (frame.entry, self.db, self.connection)):
            self.refuse("unrelated transaction attempted to borrow completion")
        key = (id(obj), name)
        if key in frame.calls:
            self.refuse("recursive transaction completion")
        committing = frame.operation in ("commit", "helper_release")
        if name == "commit" and not committing:
            self.refuse("abort cascade attempted commit")
        if name in ("rollback", "invalidate") and committing:
            if not self.failed or self.executing:
                self.refuse("commit cascade attempted rollback")
            # Native flush failure must retain its real abort/exception path.
            # A poisoned commit can gain only abort permission, never success.
            frame.operation = "abort"
            frame.sealed = False
            committing = False
        if name == "close" and committing and getattr(obj, "is_active", False):
            physical = self.pairs.get(obj, obj)
            if physical not in frame.completed:
                self.refuse("premature close attempted during commit cascade")
        frame.calls.add(key)
        was_active = getattr(obj, "is_active", False)
        try:
            if name == "commit" and obj in frame.physical:
                self.fence()
            result = original(*args, **kwargs)
            if self.ended:
                return result
            if obj in frame.physical and name in ("commit", "rollback", "close"):
                if obj.is_active:
                    self.refuse("physical transaction did not actually complete", corrupt=True)
                frame.completed.add(obj)
                if committing and obj is not self.physical_root:
                    frame.sealed = False
                if not committing and was_active:
                    self.rollback_proofs.add(obj)
                    self.reconcile_abort(obj)
                if obj is self.physical_root and (committing or was_active):
                    # Actual physical outcome precedes Session.after_commit/end.
                    # Leave subsequent native caller callbacks unguarded.
                    self.clear()
                    return result
            if (obj in frame.logical and obj is not self.helper and name == "close"
                    and not committing and not obj.is_active):
                self.logical_aborts.add(obj)
                physical = self.pairs.get(obj)
                if physical in self.rollback_proofs:
                    self.retire(obj, physical)
            return result
        except BaseException:
            if committing:
                self.failed = True
            raise
        finally:
            frame.calls.discard(key)

    def open(self, obj, name, original, args, kwargs):
        nested = name == "begin_nested" or kwargs.get("nested") is True
        if not nested:
            # Preserve native begin-on-active InvalidRequestError, without poison.
            if self.executing:
                self.refuse("participant attempted transaction rebinding")
            return original(*args, **kwargs)
        materializing = (obj is self.connection and self.frame is not None
                         and self.frame.operation == "commit" and self.command is None
                         and self.db.get_nested_transaction() in self.frame.logical
                         and self.db.get_nested_transaction() not in self.pairs)
        if self.executing or (self.frame is not None and not materializing):
            self.refuse("participant attempted unowned nesting")
        opening = self.opening
        if opening is None:
            self.require()
            self.opening = ("caller", obj)
        try:
            result = original(*args, **kwargs)
            if obj is self.connection:
                self.register_physical(result)
            else:
                self.register_logical(result)
            return result
        finally:
            if opening is None:
                self.opening = None

    def control(self, visit, ident, clause=None, *, final=False):
        scope = self.control_scope
        return (scope is not None and scope["visit"] == visit and scope["ident"] == ident
                and clause is scope["clause"] and clause is not None
                and self.execute_depth == scope["depth"] and not scope["consumed"])

    def native_control(self, name, connection, ident, original):
        if connection is not self.connection or self.control_scope is not None:
            self.refuse("native control dispatch has no exclusive scope")
        visit = _CONTROL_VISITS[name]
        target = None
        if visit == "savepoint":
            if self.opening is None or self.executing:
                self.refuse("native savepoint creation has no caller/helper scope")
        else:
            frame = self.frame
            committing = visit == "release_savepoint"
            if frame is None or frame.operation not in (("commit", "helper_release") if committing
                                                        else ("abort", "helper_recovery")):
                self.refuse("native completion has no exact frame")
            for transaction in frame.physical:
                methods = ("commit",) if committing else ("rollback", "close")
                if (getattr(transaction, "_savepoint", None) == ident
                        and any((id(transaction), method) in frame.calls for method in methods)):
                    target = transaction
            if target is None or self.connection.get_nested_transaction() is not target:
                self.refuse("native completion target is not the executing physical object")
            if committing:
                self.driver_release()
        scope: _ControlScope = {"visit": visit, "ident": ident, "target": target, "clause": None,
                 "depth": self.execute_depth + 1, "consumed": False}
        self.control_scope = scope
        try:
            result = original(connection, ident)
            if not scope["consumed"]:
                self.refuse("native control did not execute its one-use statement", corrupt=True)
            return result
        finally:
            self.control_scope = None

    def execute_entry(self, original, args, kwargs):
        clause = args[0] if args else kwargs.get("statement")
        self.execute_depth += 1
        try:
            scope = self.control_scope
            if scope is not None and scope["clause"] is None:
                if (self.execute_depth != scope["depth"]
                        or getattr(clause, "__visit_name__", "") != scope["visit"]
                        or getattr(clause, "ident", None) != scope["ident"]):
                    self.refuse("native control clause origin differs")
                scope["clause"] = clause
            return original(*args, **kwargs)
        finally:
            self.execute_depth -= 1

    def admit(self, clause):
        kind, clause = _classify(clause)
        if kind == "control":
            if not self.control(clause.__visit_name__, clause.ident, clause):
                self.refuse("hand-built/reentrant transaction control is refused")
            return kind, clause
        if self.frame is not None and self.frame.sealed and not self.fencing:
            self.refuse("SQL attempted after the final resend fence", corrupt=True)
        if kind in ("select", "text"):
            if self.executing or self.validating or self.fencing:
                authority_preflight(self.db)
            if self.fencing or self.validating:
                return kind, clause
            self.require(prepared=self.frame is not None)
            return kind, clause
        if self.fencing or self.validating:
            self.refuse("validator attempted a write", corrupt=True)
        self.require(prepared=self.frame is not None)
        if self.executing:
            table = getattr(clause, "table", None)
            if hasattr(table, "_deannotate"):
                table = cast(_Deannotatable, table)._deannotate()
            allowed = ((kind == "insert" and ((self.phase == "enqueue" and table is EmailOutbox.__table__)
                                              or (self.phase == "audit" and table is AuditEvent.__table__)))
                       or (kind == "update" and self.phase == "audit" and table is ReminderLog.__table__))
            if not allowed:
                self.refuse("participant attempted an unrelated canonical write")
        return kind, clause

    def before_execute(self, connection, clause, multiparams, params, execution_options):
        try:
            self.admit(clause)
        except ReminderResendError:
            self.refuse("unsupported reminder statement admission")

    def before_cursor_execute(self, connection, cursor, statement, parameters, context, executemany):
        # Observation is not the final SQL authority: later retval callbacks may
        # replace statement. The permanent dialect sentinel checks their output.
        compiled = getattr(context, "compiled", None)
        if compiled is not None:
            kind, clause = self.admit(compiled)
            if kind == "control":
                return
        else:
            if self.executing or not _read_sql(statement):
                self.refuse("uncompiled participant/control SQL is refused")
            self.require(prepared=self.frame is not None)
        self.generation += 1

    def final_cursor(self, cursor, statement, context, event_name):
        try:
            _exclusive(self.connection.dialect)
            if (context.root_connection is not self.connection or context.cursor is not cursor
                    or self.connection.connection.dbapi_connection is not self.physical):
                self.refuse("final cursor/context custody differs", corrupt=True)
            compiled = getattr(context, "compiled", None)
            if compiled is None:
                if self.executing or (self.frame is not None and self.frame.sealed) or not _read_sql(statement):
                    self.refuse("final raw SQL is outside the read contract")
                kind, clause = "text", None
            else:
                if type(compiled) is not self.connection.dialect.statement_compiler:
                    self.refuse("unsupported compiler at final dispatch")
                kind, clause = self.admit(compiled)
            if kind == "control":
                scope = cast(_ControlScope, self.control_scope)
                if not self.control(cast(_ControlClause, clause).__visit_name__,
                                    cast(_ControlClause, clause).ident, clause, final=True):
                    self.refuse("native control permit was consumed/rebound")
                quoted = self.connection.dialect.identifier_preparer.quote(scope["ident"])
                expected = {"savepoint": "SAVEPOINT ", "release_savepoint": "RELEASE SAVEPOINT ",
                            "rollback_to_savepoint": "ROLLBACK TO SAVEPOINT "}[scope["visit"]] + quoted
                if str(statement) != expected:
                    self.refuse("rendered native control differs", corrupt=True)
                if scope["visit"] == "release_savepoint":
                    self.driver_release()
                scope["consumed"] = True
                return
            _rendered(statement, kind, clause)
            if self.frame is not None and self.frame.sealed and not self.fencing:
                self.refuse("late transformed SQL attempted after the final fence", corrupt=True)
            self.generation += 1
        except ReminderResendError:
            self.refuse("final rendered statement refused before driver")
        except BaseException:
            self.failed = True
            self.corrupt = self.corrupt or self.command is None
            raise

    def driver_release(self):
        if (self.frame is None or not self.frame.sealed or self.failed or self.deferred
                or pending_authority(self.db) or self.generation != self.stamp):
            self.refuse("native savepoint release proof is stale", corrupt=True)
        self._dirty()

    def driver_commit(self):
        self.require(prepared=True)
        if (self.frame is None or self.frame.operation != "commit" or not self.frame.sealed
                or self.physical_root not in self.frame.physical or self.failed
                or self.waiting_aborts or self.generation != self.stamp
                or self.deferred or pending_authority(self.db)):
            self.refuse("final pre-driver resend latch refused commit", corrupt=True)
        self._dirty()  # No Session SQL or lazy loading after PREPARED.

    def connection_commit(self, connection):
        if self.frame is None or self.frame.operation != "commit" or not self.frame.sealed:
            self.refuse("physical commit lacks its exact final fence", corrupt=True)
        if self.physical_root not in self.frame.physical:
            self.refuse("physical commit target differs", corrupt=True)

    def connection_rollback(self, connection):
        if self.native_abort is not None and (connection is not self.connection
                or cast(_Frame, self.frame).target is not self.physical_root
                or (id(self.physical_root), "rollback") not in cast(_Frame, self.frame).calls):
            self.refuse("native root rollback target differs", corrupt=True)
        if self.frame is None or self.frame.operation != "abort":
            self.refuse("physical rollback lacks caller abort scope", corrupt=True)

    def connection_savepoint(self, connection, name):
        if self.opening is None or self.executing:
            self.refuse("participant attempted an unowned physical savepoint")

    def connection_release(self, connection, name, context):
        if (self.frame is None or self.frame.operation not in ("commit", "helper_release")
                or not self.frame.sealed):
            self.refuse("physical savepoint release lacks its exact fence")

    def connection_recovery(self, connection, name, context):
        if self.native_abort is not None and (connection is not self.connection
                or getattr(cast(_Frame, self.frame).target, "_savepoint", None) != name
                or (id(cast(_Frame, self.frame).target), "rollback") not in cast(_Frame, self.frame).calls):
            self.refuse("native savepoint rollback target differs", corrupt=True)
        if self.frame is None or self.frame.operation not in ("abort", "helper_recovery"):
            self.refuse("physical savepoint rollback lacks its exact abort")

    def pin(self, pins, revalidate):
        if self.command is None:
            self.refuse("resend receipt has no command epoch")
        copied = tuple((row, deepcopy(expected)) for row, expected in pins)
        prior = self.command["prior"]
        baseline = tuple((row, expected["id"], deepcopy(prior[row.__table__.name].get(expected["id"])))
                         for row, expected in copied)
        self.pending = _Receipt(copied, revalidate, self.command["logical"], self.command["physical"], baseline)

    def remember_rollback(self, tenant_id, logs, outboxes, audits):
        cast(_Command, self.command)["tenant_id"] = tenant_id
        cast(_Command, self.command)["prior"] = deepcopy({ReminderLog.__tablename__: logs,
                                          EmailOutbox.__tablename__: outboxes,
                                          AuditEvent.__tablename__: audits})

    def verify_helper_rollback(self):
        prior = cast(_Command, self.command).get("prior")
        if prior is None:
            return  # Read phase has no allowed write statements.
        self.fencing += 1
        try:
            for model in (ReminderLog, EmailOutbox, AuditEvent):
                actual = self.connection.execute(select(*model.__table__.columns).where(
                    model.__table__.c.tenant_id == cast(_Command, self.command)["tenant_id"],
                )).mappings().all()
                if {row["id"]: dict(row) for row in actual} != prior[model.__tablename__]:
                    self.refuse("helper rollback did not restore its original fixed inventories", corrupt=True)
        finally:
            self.fencing -= 1

    def reconcile_abort(self, physical):
        logical = next((t for t, p in self.pairs.items() if p is physical), None)
        if physical is self.helper_physical:
            return  # Public helper exit proves complete command recovery later.
        if logical is not None and logical not in self.logical_aborts:
            self.waiting_aborts.add(physical)
            return
        self.retire(logical, physical)

    def retire(self, logical, physical):
        if physical not in self.rollback_proofs:
            self.refuse("requested rollback has no actual physical outcome", corrupt=True)
        prior_pins = self._pins()
        retired = [r for r in self.receipts if logical in r.logical or physical in r.physical]
        rollback_values = {}
        for receipt in reversed(retired):
            for row, identity, expected in receipt.baseline:
                rollback_values[(row.__table__.name, identity)] = (row, identity, expected)
        self.fencing += 1
        try:
            for row, identity, expected in rollback_values.values():
                actual = self.connection.execute(select(*row.__table__.columns).where(
                    row.__table__.c.id == identity,
                )).mappings().one_or_none()
                if (None if actual is None else dict(actual)) != expected:
                    self.refuse("actual rollback did not restore fixed resend facts", corrupt=True)
        finally:
            self.fencing -= 1
        self.receipts = [r for r in self.receipts if r not in retired]
        self.waiting_aborts.discard(physical)
        # SQLAlchemy logical cleanup has restored/expired its snapshot. A direct
        # physical-only abort expires only fixed references, never expectations.
        if logical is None or logical in self.logical_aborts:
            for row, _expected in prior_pins:
                if inspect(row).persistent:
                    self.db.expire(row)
        if self.receipts:
            self.fencing += 1
            try:
                self._persisted()
            finally:
                self.fencing -= 1
        if not self.corrupt:
            self.failed = False
        self.stamp = -1

    def clear(self):
        if self.ended:
            return
        self.ended = True
        for record in tuple(self.internal_aborts.values()):
            self.remove_internal_abort(record)
        self.native_abort = None
        _remove_driver_guard(self)
        _remove_control_guard(self)
        with _LOCK:
            if self.sql_registered and _CONNECTIONS.get(self.connection) is self:
                _CONNECTIONS.pop(self.connection)
        for name, listener in self.listened:
            if event.contains(self.connection, name, listener):
                event.remove(self.connection, name, listener)
        for obj, name, existed, previous, handler in reversed(self.patches):
            if existed is None:
                with _LOCK:
                    handlers = _TX_HANDLERS.get(obj, {})
                    if handlers.get(name) is handler:
                        handlers.pop(name)
                    if not handlers:
                        _TX_HANDLERS.pop(obj, None)
            elif obj.__dict__.get(name) is handler:
                if existed:
                    setattr(obj, name, previous)
                else:
                    delattr(obj, name)
        with _LOCK:
            if _ACTIVE.get(self.db) is self:
                _ACTIVE.pop(self.db)
        self.receipts.clear()
        self.patches.clear()
        self.logical.clear()
        self.physical_transactions.clear()
        self.pairs.clear()
        self.rollback_proofs.clear()
        self.logical_aborts.clear()
        self.waiting_aborts.clear()
        self.pending = self.command = self.frame = self.opening = self.control_scope = None
        self.db = self.root = self.connection = self.physical_root = self.physical = self.bind = None
        self.helper = self.helper_physical = None


def _unit(db):
    with _LOCK:
        return _ACTIVE.get(db)


@event.listens_for(Session, "before_commit")
def _before_commit(db):
    unit = _unit(db)
    if unit is None:
        return
    if unit.helper_phase(ConflictSavepointPhase.RELEASE):
        if (unit.frame is None or unit.frame.operation != "helper_release"
                or not claim_conflict_savepoint_commit(db, expected_root=unit.root)):
            unit.refuse("helper release has no exact public claim")
    elif unit.frame is None or unit.frame.operation != "commit":
        unit.refuse("caller completion has no exact entry scope")
    unit.validate(defer=unit.frame.operation == "commit")


@event.listens_for(Session, "after_flush_postexec")
def _after_flush(db, flush_context):
    unit = _unit(db)
    if unit is not None and unit.frame is not None and unit.frame.operation == "commit":
        unit.validate(defer=True)


@event.listens_for(Session, "after_begin")
def _after_begin(db, transaction, connection):
    unit = _unit(db)
    if unit is not None:
        if connection is not unit.connection:
            unit.refuse("resend participant rebound the physical Connection", corrupt=True)
        unit.register_logical(transaction)
        unit.capture_association(transaction)


@event.listens_for(Session, "after_transaction_create")
def _transaction_created(db, transaction):
    unit = _unit(db)
    if unit is not None:
        unit.register_internal_abort(transaction)
    if unit is not None and transaction.nested:
        if unit.executing or (unit.command is not None and unit.opening is None):
            unit.refuse("participant created an unowned logical savepoint")
        unit.register_logical(transaction)


@event.listens_for(Session, "after_soft_rollback")
def _soft_rollback(db, transaction):
    unit = _unit(db)
    if unit is not None and transaction in unit.pairs:
        unit.logical_aborts.add(transaction)
        physical = unit.pairs[transaction]
        if transaction is not unit.helper and physical in unit.rollback_proofs:
            unit.retire(transaction, physical)


@event.listens_for(Session, "after_transaction_end")
def _root_ended(db, transaction):
    unit = _unit(db)
    if unit is not None:
        unit.internal_ended(transaction)
    if unit is not None and transaction is unit.root:
        frame = unit.frame
        accepted = frame is not None and frame.operation == "commit" and unit.physical_root in frame.completed
        aborted = (unit.physical_root in unit.rollback_proofs or unit.connection.closed
                   or unit.connection.invalidated)
        if accepted or aborted:
            unit.clear()
        else:
            unit.failed = unit.corrupt = True  # Actual physical abort still required.



def prepare_resend(db):
    unit = _unit(db)
    if unit is None:
        unit = ReminderUnit(db)
    else:
        if unit.command is not None or unit.executing:
            unit.refuse("recursive resend command refused")
        unit.validate()
    unit.require()
    logical = _chain(db.get_nested_transaction() or unit.root, "parent")
    physical = (*_chain(unit.connection.get_nested_transaction(), "_previous_nested"), unit.physical_root)
    unit.command_epoch += 1
    unit.command = {"logical": logical, "physical": physical, "count": len(unit.receipts)}
    unit.opening = ("helper", db)
    return unit


def enter_resend(db, previous: ReminderUnit):
    unit = previous
    state = current_conflict_savepoint(db)
    if (state is None or state.root is not unit.root
            or state.savepoint.parent is not cast(_Command, unit.command)["logical"][0]):
        unit.refuse("resend helper logical ancestry changed", corrupt=True)
    unit.helper = state.savepoint
    unit.register_logical(unit.helper)
    db.connection()  # Actual after_begin association, including lazy ancestry.
    unit.capture_association(unit.helper)
    unit.helper_physical = unit.pairs[unit.helper]
    expected: Transaction | None = cast(_Command, unit.command)["physical"][0]
    expected = None if expected is unit.physical_root else expected
    if unit.helper_physical._previous_nested is not expected:
        unit.refuse("resend helper physical ancestry changed", corrupt=True)
    unit.opening = None
    unit.executing = True
    unit.phase = "read"
    unit.require()
    return unit


def finish_resend(unit):
    if (unit.pending is None or unit.helper.is_active or unit.helper_physical.is_active
            or unit.db.get_nested_transaction() is not (None if unit.helper.parent is unit.root else unit.helper.parent)
            or unit.connection.get_nested_transaction() is not unit.helper_physical._previous_nested):
        unit.refuse("resend helper did not actually release", corrupt=True)
    unit.receipts.append(unit.pending)
    unit.pending = unit.command = None
    unit.helper = unit.helper_physical = None
    unit.stamp = -1
    unit.validate()


def recover_previous(unit):
    if unit.ended:
        return
    if unit.command is None or unit.helper is None or unit.helper_physical is None:
        unit.failed = unit.corrupt = True
        unit.executing = False
        unit.opening = None
        return
    unit.executing = False
    unit.opening = None
    if (unit.corrupt or conflict_savepoint_requires_rollback(unit.db, expected_root=unit.root)
            or unit.helper_physical not in unit.rollback_proofs or unit.helper not in unit.logical_aborts
            or unit.db.get_nested_transaction() is not (None if unit.command["logical"][0] is unit.root
                                                         else unit.command["logical"][0])
            or unit.connection.get_nested_transaction() is not unit.helper_physical._previous_nested):
        unit.failed = True
        return  # Exact root remains guarded for its genuine caller abort.
    unit.verify_helper_rollback()
    unit.pending = unit.command = None
    unit.helper = unit.helper_physical = None
    unit.failed = False
    if not unit.receipts:
        unit.clear()
    else:
        unit.validate()
