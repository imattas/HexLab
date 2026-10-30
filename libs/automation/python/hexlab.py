"""HexLab automation API v1, embedded by hexlab_python.

All projects are synchronous and bound to their creating thread. Scripts are
trusted Python programs. Close projects explicitly or use a with statement.
"""
import os
import json
import math
import tempfile
import time
from concurrent.futures import Future
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread, current_thread
import _hexlab

API_VERSION = 1
Error = _hexlab.Error
FUNCTION_CONVENTIONS = (
    "platform_default", "c_decl", "stdcall", "fastcall", "thiscall",
    "vectorcall", "sysv_abi", "ms_abi", "aapcs64",
)

class AnalysisCancelled(Exception):
    """Raised when native analysis, search, export, or a cooperative batch is canceled."""

class ProjectChangedDuringExport(Exception):
    """Raised when a project changes while its paged report is collected."""

class ProjectChangedDuringQuery(Exception):
    """Raised when a project changes while a multi-page query is collected."""

class CancellationToken:
    """Thread-safe token that can stop native analysis and debugger waits."""
    def __init__(self):
        self._handle = _hexlab.stop_source()

    @classmethod
    def _from_handle(cls, handle):
        token = cls.__new__(cls)
        token._handle = handle
        return token

    def cancel(self):
        _hexlab.request_stop(self._handle)

    @property
    def cancelled(self):
        return _hexlab.stop_requested(self._handle)

    def __call__(self):
        return self.cancelled

@dataclass(frozen=True)
class Address:
    space: int
    offset: int

@dataclass(frozen=True)
class FileOffset:
    offset: int

@dataclass(frozen=True)
class StackFrameInfo:
    """Recovered stack-frame summary; entry-SP allocation may be unknown."""
    function_id: int
    entry: Address
    maximum_stack_allocation_bytes: int | None
    slot_count: int
    complete: bool

@dataclass(frozen=True)
class StackSlotInfo:
    """One entry-SP-relative slot and its bounded ABI classification."""
    offset_from_entry_sp: int
    width: int
    access_count: int
    read: bool
    written: bool
    address_taken: bool
    incoming_argument: bool = False
    outgoing_call_argument_count: int = 0
    incoming_argument_abi: str | None = None

@dataclass(frozen=True)
class StackSlotCallArgumentInfo:
    """One outgoing stack argument source and the call boundary that consumes it."""
    push_instruction: Address
    call_instruction: Address
    source_instruction: Address
    source_kind: str

@dataclass(frozen=True)
class StackSlotAccessInfo:
    """One instruction site and its read/write/address-taken behavior."""
    instruction: Address
    read: bool
    written: bool
    address_taken: bool

@dataclass(frozen=True)
class SearchPage:
    """One bounded project search page; continue with its opaque cursor."""
    matches: list
    complete: bool
    source_complete: bool
    reason: str
    examined_candidates: int
    comparisons: int
    next: object

@dataclass(frozen=True)
class ReferencePage:
    """One bounded incoming-reference page and its optional next row offset."""
    references: list
    total: int
    next: object

@dataclass(frozen=True)
class HistoryPage:
    """Durable command metadata; next is an exclusive step cursor or None."""
    project_uuid: str
    source_revisions: dict
    history_cursor: int
    history_count: int
    entries: list
    next: object

@dataclass(frozen=True)
class HistoryAuditPage:
    """Verified structural-audit progress for one durable history page."""
    project_uuid: str
    source_revisions: dict
    history_cursor: int
    history_count: int
    next_after_step: int | None
    entries_verified: int
    delta_bytes: int
    has_more: bool

@dataclass(frozen=True)
class DebugImportPreview:
    """Native dry-run change counts; ready describes data, readonly the owner."""
    kind: str
    project_uuid: str
    edit_revision: int
    ready: bool
    readonly: bool
    reason: str
    error_code: int | None
    changes: int
    annotations: int
    types: int
    type_assignments: int
    functions: int
    variables: int

@dataclass(frozen=True)
class DebugVariableInfo:
    """Persisted local/parameter evidence, with independently paged locations."""
    id: int
    function_entry: Address
    name: str
    type_id: int | None
    is_parameter: bool
    scope_offset: int
    address: int | None
    cfa_offset: int | None
    origin: dict
    expression_size: int
    operation_count: int
    location_range_count: int

@dataclass(frozen=True)
class DebugLocationRangeInfo:
    """One half-open PC range; expression bytes and operations are separate."""
    begin: int
    end: int
    expression_size: int
    operation_count: int

@dataclass(frozen=True)
class ArchiveSummary:
    """Archive inventory, format, and symbol-index status."""
    member_count: int
    symbol_count: int
    has_symbol_index: bool
    symbol_index_complete: bool
    diagnostics: tuple
    thin: bool = False
    aix_big: bool = False

@dataclass(frozen=True)
class ArchiveMember:
    """One archive table row; offsets are relative to the archive file."""
    index: int
    name: str
    header_offset: int
    data_offset: int
    size: int
    kind: str

@dataclass(frozen=True)
class ArchiveSymbol:
    """One indexed symbol and its archive member index."""
    name: str
    member_index: int

@dataclass(frozen=True)
class Decompilation:
    """Detached structured pseudocode and diagnostics for one recovered function."""
    entry: Address
    text: str
    complete: bool
    used_fallback: bool
    fallback_reason: str
    diagnostics: tuple

@dataclass(frozen=True)
class ThreadRunState:
    """Session-scoped thread identity and its latest backend run-state observation."""
    thread_id: int
    state: "ThreadState"

class ThreadState(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    EXITED = "exited"
    UNKNOWN = "unknown"

class ThreadResumeKind(str, Enum):
    CONTINUE = "continue"
    STEP = "step"
    STOP = "stop"

@dataclass(frozen=True)
class ThreadResumeAction:
    """One action in an atomic stop-event thread schedule: continue, step, or stop."""
    thread_id: int
    kind: ThreadResumeKind

@dataclass(frozen=True)
class TypeSpec:
    """Portable recursive description accepted by project type commands."""
    kind: str
    arguments: tuple

    @classmethod
    def void(cls): return cls("void", ())
    @classmethod
    def boolean(cls, size, *, alignment=1): return cls("boolean", (size, alignment))
    @classmethod
    def integer(cls, name, size, *, alignment=1, signed=False): return cls("integer", (name, size, alignment, signed))
    @classmethod
    def floating(cls, name, size, *, alignment=1): return cls("floating", (name, size, alignment))
    @classmethod
    def vector(cls, element, lanes, *, alignment): return cls("vector", (element, lanes, alignment))
    @classmethod
    def pointer(cls, pointee, size, *, alignment=1): return cls("pointer", (pointee, size, alignment))
    @classmethod
    def array(cls, element, count): return cls("array", (element, count))
    @classmethod
    def named_reference(cls, name): return cls("named_reference", (name,))
    @classmethod
    def structure(cls, name, members, *, size, alignment=1):
        return cls("structure", (name, cls._members(members), size, alignment))
    @classmethod
    def union(cls, name, members, *, size, alignment=1):
        return cls("union", (name, cls._members(members), size, alignment))
    @staticmethod
    def _members(members):
        rows = []
        for row in members:
            if len(row) == 3:
                rows.append(tuple(row) + (None, None))
            elif len(row) == 5:
                rows.append(tuple(row))
            else:
                raise ValueError("members must be (name, type, offset) or include bit width and offset")
        return tuple(rows)
    @classmethod
    def enumeration(cls, name, underlying, enumerators): return cls("enumeration", (name, underlying, tuple(tuple(row) for row in enumerators)))
    @classmethod
    def function(cls, result, parameters=(), *, variadic=False, convention="platform_default"):
        if convention not in FUNCTION_CONVENTIONS:
            raise ValueError("convention must be one of " + ", ".join(FUNCTION_CONVENTIONS))
        return cls("function", (result, tuple(tuple(row) for row in parameters), variadic, convention))

    @classmethod
    def _from_native(cls, value):
        def decode(part):
            if isinstance(part, tuple) and len(part) >= 2 and part[0] == "type":
                return cls(part[1], tuple(decode(item) for item in part[2:]))
            if isinstance(part, tuple): return tuple(decode(item) for item in part)
            if isinstance(part, list): return tuple(decode(item) for item in part)
            return part
        return decode(value)

    def _to_native(self):
        def encode(part):
            if isinstance(part, TypeSpec): return part._to_native()
            if isinstance(part, (tuple, list)): return [encode(item) for item in part]
            return part
        return ("type", self.kind, *(encode(item) for item in self.arguments))

class SearchCursor:
    """Opaque, revision-bound continuation token returned by a search page."""
    def __init__(self, handle):
        self._handle = handle

def _location(value):
    if isinstance(value, Address):
        return ("va", value.space, value.offset)
    if isinstance(value, FileOffset):
        return ("file", value.offset)
    raise TypeError("location must be Address(space, offset) or FileOffset(offset)")

def _decode(value):
    if isinstance(value, tuple) and value:
        if value[0] == "type":
            return TypeSpec._from_native(value)
        if value[0] == "va":
            return Address(value[1], value[2])
        if value[0] == "file":
            return FileOffset(value[1])
    if isinstance(value, list):
        return [_decode(part) for part in value]
    if isinstance(value, dict):
        return {key: _decode(part) for key, part in value.items()}
    return value

def _json_value(value):
    if is_dataclass(value):
        return _json_value(asdict(value))
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: _json_value(part) for key, part in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(part) for part in value]
    return value

def _unsigned(value, name, maximum=(1 << 64) - 1):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an integer in 0..{maximum}")
    return value

def _type_spec_budget(value, nodes, active, depth=0):
    if depth > 64:
        raise ValueError("TypeSpec nesting exceeds 64 levels")
    if isinstance(value, TypeSpec):
        identity = id(value)
        if identity in active:
            raise ValueError("TypeSpec batch definitions cannot contain object cycles")
        nodes[0] += 1
        if nodes[0] > 262144:
            raise ValueError("TypeSpec batch exceeds 262144 type nodes")
        active.add(identity)
        _type_spec_budget(value.arguments, nodes, active, depth + 1)
        active.remove(identity)
    elif isinstance(value, (tuple, list)):
        identity = id(value)
        if identity in active:
            raise ValueError("TypeSpec batch definitions cannot contain container cycles")
        active.add(identity)
        for item in value:
            _type_spec_budget(item, nodes, active, depth + 1)
        active.remove(identity)

class Project:
    """A project owner. Successful commands persist immediately in normal history."""
    def __init__(self, handle, *, _captured=False):
        self._handle = handle
        self._captured = _captured

    @classmethod
    def _construct(cls, operation, *args, cancel=None):
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return cls(operation(*args, None if cancel is None else cancel._handle))
        except Error as error:
            if error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("project opening/import canceled") from None
            raise

    @classmethod
    def open(cls, path, *, readonly=True, api_version=API_VERSION, cancel=None):
        return cls._construct(_hexlab.open, os.fspath(path), readonly, api_version, cancel=cancel)

    @classmethod
    def create(cls, path, source, *, format="auto", api_version=API_VERSION, cancel=None):
        return cls._construct(_hexlab.create, os.fspath(path), os.fspath(source), format, "", 0, 0, None, "", api_version, cancel=cancel)

    @classmethod
    def create_raw(cls, path, source, *, mode="x86-64", base=0x1000, space=0, entry=None, api_version=API_VERSION, cancel=None):
        return cls._construct(_hexlab.create, os.fspath(path), os.fspath(source), "raw", mode, base, space, entry, "", api_version, cancel=cancel)

    @classmethod
    def create_profile(cls, path, source, profile, *, api_version=API_VERSION, cancel=None):
        return cls._construct(_hexlab.create, os.fspath(path), os.fspath(source), "profile", "", 0, 0, None, os.fspath(profile), api_version, cancel=cancel)

    def _call(self, method, *args):
        if self._handle is None:
            raise ValueError("project is closed")
        return _decode(_hexlab.call(self._handle, method, args))

    def close(self):
        if self._handle is not None:
            self._call("check_owner")  # no metadata serialization just to close
        self._handle = None

    def __enter__(self):
        if self._handle is None:
            raise ValueError("project is closed")
        return self

    def __exit__(self, *exception):
        self.close()

    def snapshot(self):
        """Detached metadata, entries, annotations, bookmarks and revision counters."""
        return self._call("snapshot")

    def _workspace_read_call(self, method, *args, cancel=None):
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call(method, *args, None if cancel is None else cancel._handle)
        except Error as error:
            if error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("workspace read canceled") from None
            raise

    def capture(self, *, expected_revision=None, cancel=None):
        """Return an independent read-only owner of this exact workspace snapshot.

        Bytes and analysis stay stable after source edits, analysis or close.
        History, edits, analysis and project saves require the live owner.
        """
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        return Project(self._workspace_read_call("capture", expected_revision, cancel=cancel), _captured=True)

    def _history_call(self, method, *args, cancel=None):
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call(method, *args, None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("history inspection canceled") from None
            raise

    def history(self, *, after_step=0, count=256, expected_revision=None, cancel=None):
        """Page applied and redo command metadata without changing the cursor.

        Continue with page.next while retaining page.source_revisions['edit']
        as expected_revision. A concurrent edit fails with conflict code 8.
        """
        _unsigned(after_step, "after_step")
        _unsigned(count, "count", 1024)
        if count == 0:
            raise ValueError("count must be in 1..1024")
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        return HistoryPage(**self._history_call("history", after_step, count,
                                               expected_revision, cancel=cancel))

    def iter_history(self, *, page_size=256, expected_revision=None, cancel=None):
        """Yield the full history, pinned to the first page's edit revision."""
        page = self.history(count=page_size, expected_revision=expected_revision, cancel=cancel)
        expected_revision = page.source_revisions["edit"]
        while True:
            yield from page.entries
            if page.next is None:
                return
            page = self.history(after_step=page.next, count=page_size,
                                expected_revision=expected_revision, cancel=cancel)

    def audit_history(self, *, after_step=0, max_steps=256,
                      max_delta_bytes=16 * 1024 * 1024,
                      expected_revision=None, cancel=None):
        """Verify one bounded page of database-defined history invariants.

        The page checks stored command metadata, payload extents and inverse
        pairing. It does not prove integrity of the external input file. For
        another page, pass ``next_after_step`` and the returned edit revision.
        """
        _unsigned(after_step, "after_step")
        _unsigned(max_steps, "max_steps", 4096)
        _unsigned(max_delta_bytes, "max_delta_bytes", 128 * 1024 * 1024)
        if not max_steps or not max_delta_bytes:
            raise ValueError("audit limits must be positive")
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        return HistoryAuditPage(**self._history_call(
            "audit_history", after_step, max_steps, max_delta_bytes,
            expected_revision, cancel=cancel))

    def iter_history_audit(self, *, page_steps=256,
                           page_bytes=16 * 1024 * 1024,
                           after_step=0, expected_revision=None,
                           max_pages=4096, total_bytes=512 * 1024 * 1024,
                           cancel=None):
        """Yield verified pages, pinning the edit revision across the walk.

        The iterator stops at ``max_pages`` or the aggregate byte budget. A
        yielded page with ``has_more`` true can be resumed by passing its
        ``next_after_step`` and ``source_revisions['edit']`` to a new iterator.
        """
        _unsigned(after_step, "after_step")
        _unsigned(page_steps, "page_steps", 4096)
        _unsigned(page_bytes, "page_bytes", 128 * 1024 * 1024)
        _unsigned(max_pages, "max_pages", 4096)
        _unsigned(total_bytes, "total_bytes", 2 * 1024 * 1024 * 1024)
        if not page_steps or not page_bytes or not max_pages or not total_bytes:
            raise ValueError("audit iterator limits must be positive")
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        consumed = 0
        for _ in range(max_pages):
            remaining = total_bytes - consumed
            if not remaining:
                return
            page = self.audit_history(
                after_step=after_step, max_steps=page_steps,
                max_delta_bytes=min(page_bytes, remaining),
                expected_revision=expected_revision, cancel=cancel)
            if expected_revision is None:
                expected_revision = page.source_revisions["edit"]
            consumed += page.delta_bytes
            yield page
            if not page.has_more:
                return
            after_step = page.next_after_step

    def preview_history(self, target_step, *, max_steps=256,
                        max_delta_bytes=16 * 1024 * 1024,
                        expected_revision=None, cancel=None):
        """Project one exact durable step into an independent read-only owner.

        Step zero, redo steps and positions inside a command group are allowed.
        Replay budgets fail the request rather than returning a partial state.
        Source revisions describe the current durable state, not the old step.
        """
        _unsigned(target_step, "target_step")
        _unsigned(max_steps, "max_steps", 4096)
        _unsigned(max_delta_bytes, "max_delta_bytes", 64 * 1024 * 1024)
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        handle = self._history_call("preview_history", target_step, max_steps,
                                    max_delta_bytes, expected_revision, cancel=cancel)
        return HistoricalState(handle)

    def read(self, location, count, *, cancel=None):
        _unsigned(count, "count", 1024 * 1024)
        return self._workspace_read_call("read", _location(location), count, cancel=cancel)

    def image_info(self):
        """Return detached loader, address-space, and mapping summary metadata."""
        return self._call("image_info")

    def annotations(self, *, start=0, count=256):
        """Page durable user names and comments in database order."""
        return self._call("annotations", start, count)

    def types(self, *, start=0, count=256):
        """Page durable type definitions, including their TypeSpec values."""
        return self._call("types", start, count)

    def type_assignments(self, *, start=0, count=256):
        """Page durable location-to-type assignments."""
        return self._call("type_assignments", start, count)

    def _debug_import_call(self, method, kind, *args, cancel=None):
        if not isinstance(kind, str) or kind not in ("symbols", "dwarf"):
            raise ValueError("kind must be symbols or dwarf")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call(method, kind, *args, None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("debug-information import canceled") from None
            raise

    def preview_debug_import(self, kind="dwarf", *, cancel=None):
        """Validate a symbols/DWARF import and count its changes without editing.

        Works on read-only owners. An unsupported source, unchanged import, or
        validation failure returns ready=False with the native reason/error_code.
        Use edit_revision as expected_revision when committing this same project.
        """
        return DebugImportPreview(kind=kind, **self._debug_import_call(
            "preview_debug_import", kind, cancel=cancel))

    def import_debug_info(self, kind="dwarf", *, expected_revision=None, group=0, cancel=None):
        """Commit one normal import command, with grouped undo and revision CAS.

        symbols imports available loader names. dwarf imports supported ELF
        DWARF names, types, prototypes, function decisions and scoped variables.
        No reanalysis is performed automatically; call analyze afterwards.
        """
        _unsigned(group, "group")
        if expected_revision is None:
            expected_revision = self._call("debug_edit_revision")
        _unsigned(expected_revision, "expected_revision")
        return self._debug_import_call("import_debug_info", kind, expected_revision,
                                       group, cancel=cancel)

    def _debug_query_call(self, method, *args, expected_revision=None, cancel=None):
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call(method, *args, expected_revision,
                              None if cancel is None else cancel._handle)
        except Error as error:
            if error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("debug-information query canceled") from None
            raise

    def debug_variables(self, function_entry=None, *, start=0, count=256,
                        expected_revision=None, cancel=None):
        """Page persisted variables, optionally filtered by exact function entry.

        This uses durable user state and remains available while analysis is
        stale. It reports recorded locations, without evaluating live values.
        expected_revision pins this read; cancel accepts a CancellationToken.
        """
        if function_entry is not None and not isinstance(function_entry, Address):
            raise TypeError("function_entry must be an Address or None")
        _unsigned(start, "start")
        self._check_page_size(count)
        return [DebugVariableInfo(**row) for row in self._debug_query_call(
            "debug_variables", None if function_entry is None else _location(function_entry), start, count,
            expected_revision=expected_revision, cancel=cancel)]

    def debug_location_ranges(self, variable_id, *, start=0, count=256,
                              expected_revision=None, cancel=None):
        """Page a variable's location-list metadata, in stored index order."""
        _unsigned(variable_id, "variable_id")
        _unsigned(start, "start")
        self._check_page_size(count)
        return [DebugLocationRangeInfo(**row) for row in self._debug_query_call(
            "debug_location_ranges", variable_id, start, count,
            expected_revision=expected_revision, cancel=cancel)]

    def debug_location_operations(self, variable_id, *, range_index=None, start=0, count=256,
                                  expected_revision=None, cancel=None):
        """Page recorded operations for the default expression or one PC range."""
        _unsigned(variable_id, "variable_id")
        _unsigned(start, "start")
        self._check_page_size(count)
        if range_index is not None:
            _unsigned(range_index, "range_index")
        return self._debug_query_call("debug_location_operations", variable_id, range_index, start, count,
                                      expected_revision=expected_revision, cancel=cancel)

    def read_debug_expression(self, variable_id, offset, count, *, range_index=None,
                              expected_revision=None, cancel=None):
        """Read at most 1 MiB of exact stored expression bytes, without evaluation."""
        _unsigned(variable_id, "variable_id")
        _unsigned(offset, "offset")
        _unsigned(count, "count", 1024 * 1024)
        if range_index is not None:
            _unsigned(range_index, "range_index")
        return self._debug_query_call("read_debug_expression", variable_id, offset, count, range_index,
                                      expected_revision=expected_revision, cancel=cancel)

    def _iterate_debug_rows(self, method, page_size, *args, expected_revision=None, cancel=None, **kwargs):
        self._check_page_size(page_size)
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        revision = self._call("debug_edit_revision") if expected_revision is None else expected_revision
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")

        def check_query():
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("debug-information query canceled")
            if self._call("debug_edit_revision") != revision:
                raise ProjectChangedDuringQuery("project changed during debug-information query")

        start = 0
        while True:
            check_query()
            try:
                page = getattr(self, method)(*args, start=start, count=page_size,
                                             expected_revision=revision, cancel=cancel, **kwargs)
            except Error as error:
                if error.code == _hexlab.CONFLICT_ERROR_CODE:
                    raise ProjectChangedDuringQuery("project changed during debug-information query") from None
                raise
            for row in page:
                check_query()
                yield row
            check_query()
            if len(page) < page_size:
                return
            start += len(page)

    def iter_debug_variables(self, function_entry=None, *, page_size=256,
                             expected_revision=None, cancel=None):
        """Yield variable summaries; check revision/cancellation before each row."""
        return self._iterate_debug_rows("debug_variables", page_size, function_entry,
                                        expected_revision=expected_revision, cancel=cancel)

    def iter_debug_location_ranges(self, variable_id, *, page_size=256,
                                   expected_revision=None, cancel=None):
        """Yield location ranges; enumerate the result to obtain range_index."""
        return self._iterate_debug_rows("debug_location_ranges", page_size, variable_id,
                                        expected_revision=expected_revision, cancel=cancel)

    def iter_debug_location_operations(self, variable_id, *, range_index=None, page_size=256,
                                       expected_revision=None, cancel=None):
        """Yield operations from the default expression or one location range."""
        return self._iterate_debug_rows("debug_location_operations", page_size, variable_id,
                                        range_index=range_index, expected_revision=expected_revision, cancel=cancel)

    def logical(self, selector, offset):
        return self._call("logical", selector, offset)

    def functions(self, *, start=0, count=256):
        return self._call("functions", start, count)

    def function_fingerprint_catalog(self, function_ids, provenance, *,
                                     max_instructions=512, max_blocks=1024,
                                     max_token_bytes=1024 * 1024,
                                     expected_revision=None, cancel=None):
        """Create a serialized normalized-fingerprint catalog in selection order.

        ``function_ids`` must contain 1..4096 unique recovered IDs. Stale IDs,
        duplicates, or functions that cannot be fingerprinted fail the whole
        operation. Pass ``expected_revision`` from ``snapshot()`` to reject a
        project edit that occurred before the catalog snapshot was captured;
        an edit or byte change during extraction raises
        :class:`ProjectChangedDuringQuery`.
        """
        if not isinstance(function_ids, (list, tuple)):
            raise TypeError("function_ids must be a list or tuple")
        if not 1 <= len(function_ids) <= 4096:
            raise ValueError("function_ids must contain 1 through 4,096 IDs")
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        try:
            return self._workspace_read_call(
                "function_fingerprint_catalog", function_ids, provenance,
                max_instructions, max_blocks, max_token_bytes,
                expected_revision, cancel=cancel)
        except Error as error:
            if error.code == _hexlab.CONFLICT_ERROR_CODE:
                raise ProjectChangedDuringQuery("project changed during fingerprint catalog creation") from None
            raise

    def recognize_flirt_catalogs(self, catalogs, *, expected_revision=None, cancel=None):
        """Read-only recognition over ordered ``(catalog_bytes, provenance)`` pairs.

        Each byte string may contain FLAIR text, gzip-wrapped text, or binary
        IDASGN v5-v10 data. Catalog order and duplicates are retained in each
        candidate's ``catalog_index``. The aggregate input and inflated bytes
        are each capped at 64 MiB, with 256 catalogs and 65,536 patterns.
        Results include every candidate, provenance, match count, and explicit
        ambiguity; no project names or annotations are changed. An edit or byte
        change during recognition raises :class:`ProjectChangedDuringQuery`.
        """
        if not isinstance(catalogs, (list, tuple)):
            raise TypeError("catalogs must be a list or tuple")
        if not 1 <= len(catalogs) <= 256:
            raise ValueError("catalogs must contain 1 through 256 entries")
        total_bytes = 0
        for item in catalogs:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise TypeError("each catalog must be a (bytes, provenance) pair")
            data, provenance = item
            if not isinstance(data, bytes):
                raise TypeError("catalog contents must be bytes")
            if not isinstance(provenance, str):
                raise TypeError("catalog provenance must be str")
            if len(provenance.encode("utf-8")) > 256:
                raise ValueError("catalog provenance exceeds 256 UTF-8 bytes")
            total_bytes += len(data)
            if total_bytes > 64 * 1024 * 1024:
                raise ValueError("aggregate catalog bytes exceed 64 MiB")
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        try:
            return self._workspace_read_call(
                "recognize_flirt_catalogs", catalogs, expected_revision, cancel=cancel)
        except Error as error:
            if error.code == _hexlab.CONFLICT_ERROR_CODE:
                raise ProjectChangedDuringQuery("project changed during FLAIR recognition") from None
            raise

    def function_signature_catalog(self, function_ids, provenance, *, max_bytes=128,
                                   min_exact_bytes=8, expected_revision=None, cancel=None):
        """Create a serialized, target scoped byte signature catalog.

        Selection order is retained. The selection must contain 1..4096 unique
        recovered function IDs; invalid or unsignable functions fail the whole
        operation. Catalog extraction is cancellation aware and raises
        :class:`ProjectChangedDuringQuery` if project bytes or edits change.
        """
        if not isinstance(function_ids, (list, tuple)):
            raise TypeError("function_ids must be a list or tuple")
        if not 1 <= len(function_ids) <= 4096:
            raise ValueError("function_ids must contain 1 through 4,096 IDs")
        if not isinstance(provenance, str):
            raise TypeError("provenance must be str")
        if len(provenance.encode("utf-8")) > 256:
            raise ValueError("provenance exceeds 256 UTF-8 bytes")
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        try:
            return self._workspace_read_call(
                "function_signature_catalog", function_ids, provenance,
                max_bytes, min_exact_bytes, expected_revision, cancel=cancel)
        except Error as error:
            if error.code == _hexlab.CONFLICT_ERROR_CODE:
                raise ProjectChangedDuringQuery("project changed during signature catalog creation") from None
            raise

    def recognize_function_signatures(self, catalog, *, expected_revision=None, cancel=None):
        """Recognize one serialized signature catalog at recovered entries.

        ``catalog`` is the text returned by :meth:`function_signature_catalog`
        (or another compatible signature catalog). Input is capped at 64 MiB;
        native recognition uses bounded candidate, comparison and result limits.
        Results retain ambiguity and never rename functions. Project changes
        during recognition raise :class:`ProjectChangedDuringQuery`.
        """
        if not isinstance(catalog, str):
            raise TypeError("catalog must be str")
        if len(catalog.encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("signature catalog exceeds 64 MiB")
        if expected_revision is not None:
            _unsigned(expected_revision, "expected_revision")
        try:
            return self._workspace_read_call(
                "recognize_function_signatures", catalog, expected_revision, cancel=cancel)
        except Error as error:
            if error.code == _hexlab.CONFLICT_ERROR_CODE:
                raise ProjectChangedDuringQuery("project changed during signature recognition") from None
            raise

    def function_at(self, address):
        """Return the unique recovered owner containing an address, or None.

        Exact function entries select that function. A shared interior address
        raises an ambiguity error; use ``function_owners`` to inspect candidates.
        """
        return self._call("function_at", _location(address))

    def function_owners(self, address):
        """Return stable ``id`` and ``entry`` candidates owning an address."""
        return self._call("function_owners", _location(address))

    def stack_frame(self, address):
        """Return recovered frame size/completeness for the unique function at address.

        Returns None when no frame record exists. Shared interior addresses raise
        HexLab.Error; use ``function_owners`` and pass a selected function entry.
        """
        row = self._call("stack_frame", _location(address))
        return None if row is None else StackFrameInfo(**row)

    def stack_slots(self, address, *, start=0, count=256):
        """Page stack slots with aggregate access flags and ABI argument facts."""
        rows = self._call("stack_slots", _location(address), start, count)
        return [StackSlotInfo(**row) for row in rows]

    def stack_slot_call_arguments(self, address, slot_index, *, start=0, count=256):
        """Page source/call provenance for one outgoing argument slot."""
        rows = self._call("stack_slot_call_arguments", _location(address), slot_index, start, count)
        return [StackSlotCallArgumentInfo(**row) for row in rows]

    def stack_slot_accesses(self, address, slot_index, *, start=0, count=256):
        """Page exact instruction sites for a slot from the current analysis."""
        rows = self._call("stack_slot_accesses", _location(address), slot_index, start, count)
        return [StackSlotAccessInfo(**row) for row in rows]

    def iter_stack_slots(self, address, *, page_size=256, max_rows=None, cancel=None):
        """Yield stack slots through bounded native pages."""
        return self._iterate_rows("stack_slots", page_size, address, max_rows=max_rows, cancel=cancel)

    def iter_stack_slot_call_arguments(self, address, slot_index, *, page_size=256, max_rows=None, cancel=None):
        """Yield outgoing source/call provenance through bounded native pages."""
        return self._iterate_rows("stack_slot_call_arguments", page_size, address, slot_index,
                                  max_rows=max_rows, cancel=cancel)

    def iter_stack_slot_accesses(self, address, slot_index, *, page_size=256, max_rows=None, cancel=None):
        """Yield one slot's read/write sites through bounded native pages."""
        return self._iterate_rows("stack_slot_accesses", page_size, address, slot_index, max_rows=max_rows, cancel=cancel)

    def decompile(self, address):
        """Lift a current recovered function and return structured pseudocode.

        ``address`` may be any uniquely owned address inside the function or
        one of its chunks. Shared interior addresses require choosing a function
        explicitly through ``function_owners`` and its entry address.
        Call ``analyze()`` after edits that invalidate derived analysis.
        """
        row = self._call("decompile", _location(address))
        return Decompilation(row["entry"], row["text"], row["complete"],
                             row["used_fallback"], row["fallback_reason"],
                             tuple(row["diagnostics"]))

    def instructions(self, *, start=0, count=256):
        return self._call("instructions", start, count)

    def presentation(self, location):
        """Effective name/comment and their user-name/orphaned flags."""
        return self._call("presentation", _location(location))

    def function_blocks(self, address, *, start=0, count=256):
        """Page detached block metadata for the function containing address.

        Block ids belong to current analysis. Fetch them again after reanalysis.
        Instructions and successors have their own bounded page methods.
        """
        return self._call("function_blocks", _location(address), start, count)

    def block_instructions(self, block_id, *, start=0, count=256):
        """Page instructions in one current analysis block, in decode order."""
        return self._call("block_instructions", block_id, start, count)

    def block_successors(self, block_id, *, start=0, count=256):
        """Page CFG edges with source, optional target/block, and named kind."""
        return self._call("block_successors", block_id, start, count)

    def segments(self, *, start=0, count=256):
        """Return mapped segment ranges, original file backing, and permissions."""
        return self._call("segments", start, count)

    def addresses_for_file_offset(self, offset):
        """Return every mapped virtual address backed by this source file byte."""
        return self._call("addresses_for_file_offset", offset)

    def pe_imports(self, *, start=0, count=256):
        """Page PE imports with name/ordinal, thunk, IAT, and delay-load status."""
        return self._call("pe_imports", start, count)

    def pe_exports(self, *, start=0, count=256):
        """Page PE exports, including ordinal-only rows and forwarders."""
        return self._call("pe_exports", start, count)

    def elf_dynamic_entries(self, *, start=0, count=256):
        """Page ELF dynamic entries with their table source and decoded string value."""
        return self._call("elf_dynamic_entries", start, count)

    def strings(self, *, start=0, count=256):
        return self._call("strings", start, count)

    @staticmethod
    def _check_page_size(page_size):
        if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 4096:
            raise ValueError("page_size must be in 1..4096")

    def _iterate_rows(self, method, page_size, *args, max_rows=None, cancel=None):
        self._check_page_size(page_size)
        if max_rows is not None:
            _unsigned(max_rows, "max_rows")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if max_rows == 0:
            return
        with self.capture(cancel=cancel) as reader:
            start = 0
            while max_rows is None or start < max_rows:
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("workspace iteration canceled")
                amount = page_size if max_rows is None else min(page_size, max_rows - start)
                page = getattr(reader, method)(*args, start=start, count=amount)
                for row in page:
                    if cancel is not None and cancel.cancelled:
                        raise AnalysisCancelled("workspace iteration canceled")
                    yield row
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("workspace iteration canceled")
                if len(page) < amount:
                    return
                start += len(page)

    def iter_function_blocks(self, address, *, page_size=256, max_rows=None, cancel=None):
        """Yield blocks in function order using bounded metadata pages."""
        return self._iterate_rows("function_blocks", page_size, address, max_rows=max_rows, cancel=cancel)

    def iter_block_instructions(self, block_id, *, page_size=256, max_rows=None, cancel=None):
        """Yield the instructions of a current block a page at a time."""
        return self._iterate_rows("block_instructions", page_size, block_id, max_rows=max_rows, cancel=cancel)

    def iter_block_successors(self, block_id, *, page_size=256, max_rows=None, cancel=None):
        """Yield current CFG successor edges a page at a time."""
        return self._iterate_rows("block_successors", page_size, block_id, max_rows=max_rows, cancel=cancel)

    def iter_functions(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield all recovered functions using bounded native query pages."""
        return self._iterate_rows("functions", page_size, max_rows=max_rows, cancel=cancel)

    def iter_annotations(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield durable names and comments using bounded pages."""
        return self._iterate_rows("annotations", page_size, max_rows=max_rows, cancel=cancel)

    def iter_types(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield durable type definitions using bounded pages."""
        return self._iterate_rows("types", page_size, max_rows=max_rows, cancel=cancel)

    def iter_type_assignments(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield durable type assignments using bounded pages."""
        return self._iterate_rows("type_assignments", page_size, max_rows=max_rows, cancel=cancel)

    def iter_instructions(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield all decoded instructions without accumulating the table."""
        return self._iterate_rows("instructions", page_size, max_rows=max_rows, cancel=cancel)

    def iter_segments(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield all mapped segments in bounded pages."""
        return self._iterate_rows("segments", page_size, max_rows=max_rows, cancel=cancel)

    def iter_pe_imports(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield PE imports across bounded pages."""
        return self._iterate_rows("pe_imports", page_size, max_rows=max_rows, cancel=cancel)

    def iter_pe_exports(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield PE exports across bounded pages."""
        return self._iterate_rows("pe_exports", page_size, max_rows=max_rows, cancel=cancel)

    def iter_elf_dynamic_entries(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield ELF dynamic entries in table order using bounded pages."""
        return self._iterate_rows("elf_dynamic_entries", page_size, max_rows=max_rows, cancel=cancel)

    def iter_strings(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield all scanned strings in bounded pages."""
        return self._iterate_rows("strings", page_size, max_rows=max_rows, cancel=cancel)

    def iter_all_references(self, *, page_size=256, max_rows=None, cancel=None):
        """Yield every indexed reference row using bounded native query pages."""
        self._check_page_size(page_size)
        if max_rows is not None:
            _unsigned(max_rows, "max_rows")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if max_rows == 0:
            return
        with self.capture(cancel=cancel) as reader:
            start = 0
            while max_rows is None or start < max_rows:
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("reference iteration canceled")
                amount = page_size if max_rows is None else min(page_size, max_rows - start)
                page = reader.all_references(start=start, count=amount)
                for row in page.references:
                    if cancel is not None and cancel.cancelled:
                        raise AnalysisCancelled("reference iteration canceled")
                    yield row
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("reference iteration canceled")
                if page.next is None:
                    return
                if page.next <= start or page.next != start + len(page.references):
                    raise RuntimeError("reference page cursor did not advance consistently")
                start = page.next

    def iter_references(self, location, *, page_size=256, max_rows=None, cancel=None):
        """Yield outgoing references from one location on a captured generation."""
        return self._iterate_rows("references", page_size, location,
                                  max_rows=max_rows, cancel=cancel)

    def iter_incoming_references(self, location, *, page_size=256, max_rows=None, cancel=None):
        """Yield incoming references to one location on a captured generation."""
        self._check_page_size(page_size)
        if max_rows is not None:
            _unsigned(max_rows, "max_rows")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if max_rows == 0:
            return
        with self.capture(cancel=cancel) as reader:
            start = 0
            while max_rows is None or start < max_rows:
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("reference iteration canceled")
                amount = page_size if max_rows is None else min(page_size, max_rows - start)
                page = reader.incoming_references(location, start=start, count=amount)
                for row in page.references:
                    if cancel is not None and cancel.cancelled:
                        raise AnalysisCancelled("reference iteration canceled")
                    yield row
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("reference iteration canceled")
                if page.next is None:
                    return
                if page.next <= start or page.next != start + len(page.references):
                    raise RuntimeError("incoming reference page cursor did not advance consistently")
                start = page.next

    def iter_incoming_references_range(self, address, size, *, page_size=256,
                                       max_rows=None, cancel=None):
        """Yield references to any byte in a half-open virtual-address range.

        One captured project generation backs every page. References whose
        target or resolved association falls in the range appear once.
        """
        if not isinstance(address, Address):
            raise TypeError("address must be an Address")
        _unsigned(size, "size")
        if size == 0:
            raise ValueError("size must be greater than zero")
        self._check_page_size(page_size)
        if max_rows is not None:
            _unsigned(max_rows, "max_rows")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if max_rows == 0:
            return
        with self.capture(cancel=cancel) as reader:
            start = 0
            while max_rows is None or start < max_rows:
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("reference iteration canceled")
                amount = page_size if max_rows is None else min(page_size, max_rows - start)
                page = reader.incoming_references_range(address, size, start=start, count=amount)
                for row in page.references:
                    if cancel is not None and cancel.cancelled:
                        raise AnalysisCancelled("reference iteration canceled")
                    yield row
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("reference iteration canceled")
                if page.next is None:
                    return
                if page.next <= start or page.next != start + len(page.references):
                    raise RuntimeError("incoming range reference cursor did not advance consistently")
                start = page.next

    def iter_outgoing_references_range(self, address, size, *, page_size=256,
                                       max_rows=None, cancel=None):
        """Yield references whose source is in a half-open virtual range.

        Pages come from one captured project generation. All reference kinds,
        including unresolved and external targets, are retained.
        """
        if not isinstance(address, Address):
            raise TypeError("address must be an Address")
        _unsigned(size, "size")
        if size == 0:
            raise ValueError("size must be greater than zero")
        self._check_page_size(page_size)
        if max_rows is not None:
            _unsigned(max_rows, "max_rows")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if max_rows == 0:
            return
        with self.capture(cancel=cancel) as reader:
            start = 0
            while max_rows is None or start < max_rows:
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("reference iteration canceled")
                amount = page_size if max_rows is None else min(page_size, max_rows - start)
                page = reader.outgoing_references_range(address, size, start=start, count=amount)
                for row in page.references:
                    if cancel is not None and cancel.cancelled:
                        raise AnalysisCancelled("reference iteration canceled")
                    yield row
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("reference iteration canceled")
                if page.next is None:
                    return
                if page.next <= start or page.next != start + len(page.references):
                    raise RuntimeError("outgoing range reference cursor did not advance consistently")
                start = page.next

    def call_graph(self, address, *, max_functions=1024, max_edges=16384,
                   max_instructions=1000000, cancel=None):
        """Walk resolved direct calls reachable from the function containing address.

        The walk follows current decoded call instructions and their call xrefs.
        It returns detached nodes and edges, including known external calls. Calls
        whose target is indirect, unresolved, or not owned by a recovered function
        are counted as unresolved and make ``complete`` false. The three explicit
        limits bound traversal; reaching one returns a partial graph with a
        ``truncated_reason``. A cancellation predicate/token is checked between
        native page queries. Analysis must be current before calling this method.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        limits = (("max_functions", max_functions, 1, 65536),
                  ("max_edges", max_edges, 1, 1000000),
                  ("max_instructions", max_instructions, 1, 10000000))
        for name, value, minimum, maximum in limits:
            if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be in {minimum}..{maximum}")
        if cancel is not None and not (callable(cancel) or isinstance(cancel, CancellationToken)):
            raise TypeError("cancel must be a zero-argument callable or CancellationToken")
        if cancel is not None and cancel():
            raise AnalysisCancelled("call graph walk canceled")
        if not self._captured:
            with self.capture(cancel=cancel if isinstance(cancel, CancellationToken) else None) as reader:
                return reader.call_graph(address, max_functions=max_functions, max_edges=max_edges,
                                         max_instructions=max_instructions, cancel=cancel)

        def check_cancel():
            if cancel is not None and cancel():
                raise AnalysisCancelled("call graph walk canceled")

        def revision(snapshot):
            return (snapshot.get("edit_revision"), snapshot.get("byte_revision"),
                    snapshot.get("decision_revision"))

        check_cancel()
        start_snapshot = self.snapshot()
        expected_revision = revision(start_snapshot)

        def check_revision():
            if revision(self.snapshot()) != expected_revision:
                raise ProjectChangedDuringQuery("project changed during call graph query")

        root = self.function_at(address)
        if root is None:
            raise ValueError("no recovered function contains the requested address")
        root_entry = root["entry"]
        nodes = [root]
        node_by_entry = {root_entry: 0}
        edges = []
        unresolved_calls = 0
        instructions_examined = 0
        truncated_reason = None
        recovered_functions_complete = True
        cursor = 0

        while cursor < len(nodes) and truncated_reason is None:
            check_cancel()
            check_revision()
            caller = nodes[cursor]
            recovered_functions_complete = recovered_functions_complete and caller["complete"]
            for block in self.iter_function_blocks(caller["entry"], page_size=256):
                check_cancel()
                check_revision()
                for instruction in self.iter_block_instructions(block["id"], page_size=256):
                    check_cancel()
                    instructions_examined += 1
                    if instructions_examined > max_instructions:
                        truncated_reason = "max_instructions"
                        break
                    if instruction.get("flow_name") != "call":
                        continue
                    start = 0
                    found_call_reference = False
                    while True:
                        check_cancel()
                        check_revision()
                        references = self.references(instruction["address"], start=start, count=256)
                        for reference in references:
                            if reference.get("kind_name") not in ("call", "imported_call"):
                                continue
                            found_call_reference = True
                            if len(edges) >= max_edges:
                                truncated_reason = "max_edges"
                                break
                            target = reference.get("target")
                            edge = {"caller": caller["entry"],
                                    "source": instruction["address"],
                                    "kind": reference["kind_name"],
                                    "target": target,
                                    "target_function": None}
                            if isinstance(target, Address):
                                callee = self.function_at(target)
                                if callee is None:
                                    unresolved_calls += 1
                                else:
                                    callee_entry = callee["entry"]
                                    edge["target_function"] = callee_entry
                                    if callee_entry not in node_by_entry:
                                        if len(nodes) >= max_functions:
                                            truncated_reason = "max_functions"
                                        else:
                                            node_by_entry[callee_entry] = len(nodes)
                                            nodes.append(callee)
                            elif not (isinstance(target, dict) and "library" in target):
                                # The target may carry an unresolved reason or a
                                # file offset. Preserve it verbatim for inspection.
                                unresolved_calls += 1
                            edges.append(edge)
                            if truncated_reason is not None:
                                break
                        if truncated_reason is not None or len(references) < 256:
                            break
                        start += len(references)
                    if not found_call_reference:
                        unresolved_calls += 1
                    if truncated_reason is not None:
                        break
                if truncated_reason is not None:
                    break
            cursor += 1

        check_cancel()
        check_revision()
        return {"root": root_entry, "nodes": tuple(nodes), "edges": tuple(edges),
                "complete": (truncated_reason is None and unresolved_calls == 0 and
                             recovered_functions_complete),
                "truncated_reason": truncated_reason,
                "unresolved_call_count": unresolved_calls,
                "instructions_examined": instructions_examined}

    def call_graph_model(self, address, *, call_depth=1, node_budget=1000,
                         edge_budget=10000, cancel=None):
        """Return the native, detached function-call ``GraphModel`` as JSON data.

        ``call_depth`` is limited to 1..4, ``node_budget`` to 1..1,000,000,
        and ``edge_budget`` to 1..4,000,000. A ``CancellationToken`` can stop
        collection and serialization in the native graph builder. The graph is
        based on current analysis and raises the native ambiguity error when the
        selected address belongs to multiple recovered functions.
        """
        for name, value, minimum, maximum in (
                ("call_depth", call_depth, 1, 4),
                ("node_budget", node_budget, 1, 1000000),
                ("edge_budget", edge_budget, 1, 4000000)):
            if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be in {minimum}..{maximum}")
        encoded = self._workspace_read_call(
            "call_graph_model", _location(address), call_depth, node_budget,
            edge_budget, cancel=cancel)
        return json.loads(encoded)

    def export_analysis_json(self, path, *, page_size=4096, cancel=None, progress=None,
                             include_cfg=False):
        """Refresh and atomically export a versioned, machine-readable analysis.

        Pages are streamed into a temporary sibling file, so row memory stays
        bounded by ``page_size`` and cancellation/failure never publishes a
        partial report. ``cancel`` is an optional zero-argument predicate;
        ``progress(stage, completed, total)`` is called at stage/page boundaries.
        ``include_cfg=True`` opts into schema version 2 with bounded block and
        successor tables; the default preserves the version-1 document shape.
        A CancellationToken can interrupt native analysis; plain predicates are
        checked between native operations. Edits during collection abort export.
        """
        self._check_page_size(page_size)
        if not isinstance(include_cfg, bool):
            raise TypeError("include_cfg must be a bool")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not callable(cancel):
            raise TypeError("cancel must be a zero-argument callable or CancellationToken")
        if progress is not None and not callable(progress):
            raise TypeError("progress must be a callable")

        def check_cancel():
            if cancel is not None and cancel():
                raise AnalysisCancelled("analysis export canceled")

        def report(stage, completed, total):
            if progress is not None:
                progress(stage, completed, total)

        def revision(snapshot):
            return (snapshot.get("edit_revision"), snapshot.get("byte_revision"),
                    snapshot.get("decision_revision"))

        def check_revision(expected):
            if revision(self.snapshot()) != expected:
                raise ProjectChangedDuringExport("project changed during analysis export")

        check_cancel()
        report("analysis", 0, 1)
        try:
            if not self._captured:
                self.analyze(cancel=cancel if isinstance(cancel, CancellationToken) else None)
        except Error as error:
            if (isinstance(cancel, CancellationToken) and cancel.cancelled and
                    error.code == _hexlab.CANCELED_ERROR_CODE):
                raise AnalysisCancelled("native analysis canceled") from None
            raise
        check_cancel()
        report("analysis", 1, 1)
        reader = self.capture(cancel=cancel if isinstance(cancel, CancellationToken) else None)
        snapshot = reader.snapshot()
        snapshot_revision = revision(snapshot)
        destination = os.path.abspath(os.fspath(path))
        directory = os.path.dirname(destination) or os.curdir
        prefix = "." + os.path.basename(destination) + "."
        descriptor, temporary = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
        row_counts = {"functions": 0, "instructions": 0, "segments": 0,
                      "references": 0, "strings": 0, "blocks": 0,
                      "block_successors": 0}
        encoded_bytes = 0
        encoder = json.JSONEncoder(ensure_ascii=False, indent=2, sort_keys=True)

        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                def write(value):
                    nonlocal encoded_bytes
                    output.write(value)
                    encoded_bytes += len(value.encode("utf-8"))

                def write_json(value):
                    for part in encoder.iterencode(_json_value(value)):
                        write(part)

                schema_version = 2 if include_cfg else 1
                write("{\n  \"schema_version\": " + str(schema_version) + ",\n  \"api_version\": ")
                write_json(API_VERSION)
                write(",\n  \"project\": ")
                write_json(snapshot)
                tables = (
                    ("functions", "functions", snapshot["function_count"]),
                    ("instructions", "instructions", snapshot["instruction_count"]),
                    ("segments", "segments", None),
                    ("references", "all_references", None),
                    ("strings", "strings", None),
                )
                for table, method, total in tables:
                    write(",\n  " + json.dumps(table) + ": [")
                    start = 0
                    completed = 0
                    first = True
                    while True:
                        check_cancel()
                        check_revision(snapshot_revision)
                        if method == "all_references":
                            page_object = reader.all_references(start=start, count=page_size)
                            page = page_object.references
                            next_start = page_object.next
                        else:
                            page = getattr(reader, method)(start=start, count=page_size)
                            next_start = start + len(page) if len(page) == page_size else None
                        for row in page:
                            if table == "instructions":
                                row["bytes_hex"] = row.pop("bytes").hex()
                            write("," if not first else "")
                            write("\n    ")
                            write_json(row)
                            first = False
                            completed += 1
                        row_counts[table] = completed
                        report(table, completed, total)
                        check_revision(snapshot_revision)
                        if next_start is None:
                            break
                        start = next_start
                    if not first:
                        write("\n  ")
                    write("]")
                if include_cfg:
                    # CFG identities are valid for this captured analysis only.
                    # Nest iteration by function so all block rows retain a
                    # stable owner even when block ids are process-local.
                    for table in ("blocks", "block_successors"):
                        write(",\n  " + json.dumps(table) + ": [")
                        first = True
                        completed = 0
                        function_start = 0
                        while True:
                            check_cancel()
                            check_revision(snapshot_revision)
                            function_page = reader.functions(start=function_start, count=page_size)
                            if not function_page:
                                break
                            for function in function_page:
                                owner = function["entry"]
                                block_start = 0
                                while block_start < function["block_count"]:
                                    check_cancel()
                                    check_revision(snapshot_revision)
                                    blocks = reader.function_blocks(owner, start=block_start,
                                                                    count=min(page_size, function["block_count"] - block_start))
                                    if not blocks:
                                        raise RuntimeError("captured CFG block page ended before its declared count")
                                    for block in blocks:
                                        if table == "blocks":
                                            row = dict(block)
                                            row["function_entry"] = owner
                                            write("," if not first else "")
                                            write("\n    ")
                                            write_json(row)
                                            first = False
                                            completed += 1
                                        else:
                                            edge_start = 0
                                            while edge_start < block["successor_count"]:
                                                check_cancel()
                                                check_revision(snapshot_revision)
                                                edges = reader.block_successors(
                                                    block["id"], start=edge_start,
                                                    count=min(page_size, block["successor_count"] - edge_start))
                                                if not edges:
                                                    raise RuntimeError("captured CFG edge page ended before its declared count")
                                                for edge in edges:
                                                    row = dict(edge)
                                                    row["block_id"] = block["id"]
                                                    row["function_entry"] = owner
                                                    write("," if not first else "")
                                                    write("\n    ")
                                                    write_json(row)
                                                    first = False
                                                    completed += 1
                                                edge_start += len(edges)
                                        report(table, completed, None)
                                    block_start += len(blocks)
                            function_start += len(function_page)
                        row_counts[table] = completed
                        if not first:
                            write("\n  ")
                        write("]")
                write("\n}\n")
                output.flush()
                os.fsync(output.fileno())
            check_cancel()
            check_revision(snapshot_revision)
            # A same-directory hard link publishes atomically and fails if the
            # requested destination already exists, on supported local filesystems.
            os.link(temporary, destination)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            finally:
                reader.close()
        return {"path": destination, "schema_version": schema_version,
                "function_count": row_counts["functions"],
                "instruction_count": row_counts["instructions"],
                "reference_count": row_counts["references"],
                "string_count": row_counts["strings"],
                "block_count": row_counts["blocks"],
                "block_successor_count": row_counts["block_successors"],
                "segment_count": row_counts["segments"],
                "bytes": encoded_bytes}

    def references(self, location, *, start=0, count=256):
        return self._call("references", _location(location), start, count)

    def incoming_references(self, location, *, start=0, count=256):
        """Find references to a typed address/file offset, with bounded paging."""
        row = self._call("incoming_references", _location(location), start, count)
        return ReferencePage(row["references"], row["total"], row["next"])

    def incoming_references_range(self, address, size, *, start=0, count=256):
        """Find references targeting any byte in ``[address, address + size)``."""
        if not isinstance(address, Address):
            raise TypeError("address must be an Address")
        _unsigned(size, "size")
        if size == 0:
            raise ValueError("size must be greater than zero")
        _unsigned(start, "start")
        self._check_page_size(count)
        row = self._call("incoming_references_range", _location(address), size, start, count)
        return ReferencePage(row["references"], row["total"], row["next"])

    def outgoing_references_range(self, address, size, *, start=0, count=256):
        """Page references whose source is in ``[address, address + size)``."""
        if not isinstance(address, Address):
            raise TypeError("address must be an Address")
        _unsigned(size, "size")
        if size == 0:
            raise ValueError("size must be greater than zero")
        _unsigned(start, "start")
        self._check_page_size(count)
        row = self._call("outgoing_references_range", _location(address), size, start, count)
        return ReferencePage(row["references"], row["total"], row["next"])

    def all_references(self, *, start=0, count=256):
        """Page every current reference row, including imports and relocations."""
        row = self._call("all_references", start, count)
        return ReferencePage(row["references"], row["total"], row["next"])

    def _search(self, query, cursor, max_results, cancel=None, start=None):
        if not isinstance(max_results, int) or isinstance(max_results, bool) or not 1 <= max_results <= 4096:
            raise ValueError("max_results must be in 1..4096")
        if cursor is not None and not isinstance(cursor, SearchCursor):
            raise TypeError("cursor must be a SearchCursor returned by this API")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        native_start = None if start is None else _location(start)
        try:
            row = self._call("search", query, None if cursor is None else cursor._handle,
                             max_results, None if cancel is None else cancel._handle, native_start)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("search canceled") from None
            raise
        continuation = row["next"]
        row["next"] = None if continuation is None else SearchCursor(continuation)
        return SearchPage(**row)

    def search_bytes(self, pattern, *, cursor=None, max_results=256, cancel=None, start=None):
        """Search effective bytes; start may be a mapped Address or FileOffset."""
        return self._search(("bytes", pattern), cursor, max_results, cancel, start)

    def search_text(self, text, *, encoding="utf8", case_sensitive=True, cursor=None,
                    max_results=256, cancel=None, start=None):
        """Search encoded text with optional ASCII-only case folding."""
        if type(case_sensitive) is not bool:
            raise TypeError("case_sensitive must be bool")
        encodings = {"ascii": 0, "utf8": 1, "utf16le": 2, "utf16be": 3, "utf32le": 4, "utf32be": 5,
                     "windows1252": 6, "iso8859_1": 7}
        try:
            selected = encodings[encoding.lower()]
        except (AttributeError, KeyError):
            raise ValueError("encoding must be ascii, utf8, utf16le, utf16be, utf32le, utf32be, windows1252, or iso8859_1") from None
        return self._search(("text", text, selected, case_sensitive), cursor, max_results, cancel, start)

    def _iterate_search(self, method, *args, page_size=256, max_rows=None, cancel=None, **kwargs):
        self._check_page_size(page_size)
        if max_rows is not None:
            _unsigned(max_rows, "max_rows")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if max_rows == 0:
            return
        cursor = None
        yielded = 0
        while max_rows is None or yielded < max_rows:
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("search iteration canceled")
            amount = page_size if max_rows is None else min(page_size, max_rows - yielded)
            try:
                page = getattr(self, method)(*args, cursor=cursor, max_results=amount,
                                             cancel=cancel, **kwargs)
            except Error as error:
                if error.code == _hexlab.CONFLICT_ERROR_CODE:
                    raise ProjectChangedDuringQuery("project changed during search iteration") from None
                raise
            for match in page.matches:
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("search iteration canceled")
                yield match
                yielded += 1
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("search iteration canceled")
            if page.complete:
                return
            if page.next is None:
                raise RuntimeError("search stopped before completion: " + page.reason)
            cursor = page.next
            if "start" in kwargs:
                kwargs["start"] = None

    def iter_search_bytes(self, pattern, *, page_size=256, max_rows=None, cancel=None, start=None):
        """Yield effective-byte matches across revision-bound pages."""
        return self._iterate_search("search_bytes", pattern, page_size=page_size,
                                    max_rows=max_rows, cancel=cancel, start=start)

    def iter_search_text(self, text, *, encoding="utf8", case_sensitive=True,
                         page_size=256, max_rows=None, cancel=None, start=None):
        """Yield encoded-text matches; case folding is limited to ASCII A-Z."""
        return self._iterate_search("search_text", text, encoding=encoding, case_sensitive=case_sensitive,
                                    page_size=page_size,
                                    max_rows=max_rows, cancel=cancel, start=start)

    def iter_search_immediate(self, value, *, width=64, signed=False,
                              page_size=256, max_rows=None, cancel=None, start=None):
        """Yield immediate-operand matches across revision-bound pages."""
        if not isinstance(width, int) or isinstance(width, bool) or width not in (8, 16, 32, 64):
            raise ValueError("width must be 8, 16, 32, or 64")
        return self._iterate_search("search_immediate", value, width=width, signed=bool(signed),
                                    page_size=page_size, max_rows=max_rows, cancel=cancel, start=start)

    def search_immediate(self, value, *, width=64, signed=False, cursor=None, max_results=256, cancel=None, start=None):
        """Search decoded instructions; start may be an Address or FileOffset."""
        if not isinstance(width, int) or isinstance(width, bool) or width not in (8, 16, 32, 64):
            raise ValueError("width must be 8, 16, 32, or 64")
        return self._search(("immediate", str(value), width, bool(signed)), cursor, max_results, cancel, start)

    def rename(self, location, name, *, group=0):
        return self._call("rename", _location(location), name, group)

    def comment(self, location, text, *, group=0):
        return self._call("comment", _location(location), text, group)

    def bookmark(self, location, label="", *, remove=False, group=0):
        return self._call("bookmark", _location(location), label, remove, group)

    def apply_annotations(self, rows, *, group=0, expected_revision=None, merge="replace", return_report=False, cancel=None):
        """Atomically import a bounded batch of names, comments, and bookmarks.

        Each row is a mapping with ``location`` and any of ``name``,
        ``comment``, or ``bookmark``. A ``None`` bookmark removes the current
        bookmark; a string sets its label. All operations are validated against
        one projected state and committed as one persistent history step.
        Capture ``snapshot()['edit_revision']`` while planning and pass it as
        ``expected_revision`` to reject a stale manifest. ``merge='replace'``
        applies provided fields (the default); ``merge='preserve'`` fills only
        empty name/comment fields and absent bookmarks. Preserve mode requires
        a complete snapshot of no more than 4096 existing annotations and
        bookmarks, so it never treats truncated state as absent.
        When ``return_report=True``, return a mapping containing the resulting
        ``snapshot``, per-field ``applied`` and ``skipped`` counts, the pinned
        ``expected_revision``, the resulting ``result_revision``, the number
        of ``planned_edits``, and whether the project revision changed in
        ``committed``. A preserve-mode no-op reports the same revision before
        and after and ``committed=False``. The default return value remains
        the snapshot for compatibility. ``cancel`` may be a CancellationToken;
        cancellation stops bounded planning and native validation before the
        atomic commit.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if merge not in ("replace", "preserve"):
            raise ValueError("merge must be 'replace' or 'preserve'")
        current = None
        existing_annotations = {}
        existing_bookmarks = set()
        existing_names = {}
        pending_annotations = {}
        pending_bookmarks = set()
        if merge == "preserve":
            current = self.snapshot()
            if expected_revision is None:
                expected_revision = current["edit_revision"]
            annotation_rows = current["annotations"]
            bookmark_rows = current["bookmarks"]
            if (current["annotation_count"] > len(annotation_rows) or
                    current["bookmark_count"] > len(bookmark_rows)):
                raise ValueError("merge='preserve' requires at most 4096 existing annotations and bookmarks")

            def key_of(location):
                if isinstance(location, Address):
                    return ("va", location.space, location.offset)
                if isinstance(location, FileOffset):
                    return ("file", location.offset)
                if isinstance(location, tuple) and location:
                    return location
                raise ValueError("project snapshot contains an unsupported annotation location")

            for annotation in annotation_rows:
                key = key_of(annotation["location"])
                existing_annotations[key] = annotation
                if key[0] == "va" and annotation["name"]:
                    existing_names[(key[1], annotation["name"])] = key
            for bookmark in bookmark_rows:
                existing_bookmarks.add(key_of(bookmark["location"]))
        commands = []
        text_bytes = 0
        row_count = 0
        skipped_fields = 0
        allowed = {"location", "name", "comment", "bookmark"}
        for row in rows:
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation import canceled during planning")
            row_count += 1
            if row_count > 4096:
                raise ValueError("annotation import requires at most 4096 rows")
            if not isinstance(row, dict) or "location" not in row:
                raise TypeError("each annotation row must be a mapping with location")
            if any(not isinstance(key, str) for key in row):
                raise TypeError("annotation field names must be strings")
            unknown = set(row) - allowed
            if unknown:
                raise ValueError("unknown annotation fields: " + ", ".join(sorted(unknown)))
            location = _location(row["location"])
            location_key = location
            row_commands = []
            for field in ("name", "comment", "bookmark"):
                if field not in row:
                    continue
                value = row[field]
                if field == "bookmark" and value is None:
                    row_commands.append(("bookmark", location, "", True))
                else:
                    if not isinstance(value, str):
                        raise TypeError(field + " must be text" + (" or None" if field == "bookmark" else ""))
                    text_bytes += len(value.encode("utf-8"))
                    if text_bytes > 16 * 1024 * 1024:
                        raise ValueError("annotation import text exceeds 16 MiB")
                    if field == "bookmark":
                        row_commands.append(("bookmark", location, value, False))
                    else:
                        row_commands.append((field, location, value))
                if len(commands) + len(row_commands) > 4096:
                    raise ValueError("annotation import expands to more than 4096 edits")
            if merge == "preserve":
                current_annotation = existing_annotations.get(location_key, {})
                pending_fields = pending_annotations.setdefault(location_key, set())
                for command in row_commands:
                    field, _, value, *extra = command
                    if field == "bookmark":
                        if location_key in existing_bookmarks or location_key in pending_bookmarks or extra[0]:
                            skipped_fields += 1
                            continue
                    elif current_annotation.get(field):
                        skipped_fields += 1
                        continue
                    elif field in pending_fields:
                        skipped_fields += 1
                        continue
                    elif value == "":
                        skipped_fields += 1
                        continue
                    elif field == "name" and isinstance(row["location"], Address):
                        previous = existing_names.get((row["location"].space, value))
                        if previous is not None and previous != location_key:
                            skipped_fields += 1
                            continue
                    commands.append(command)
                    if field == "bookmark":
                        pending_bookmarks.add(location_key)
                    else:
                        pending_fields.add(field)
                        if field == "name" and isinstance(row["location"], Address):
                            existing_names[(row["location"].space, value)] = location_key
            else:
                commands.extend(row_commands)
            if len(commands) > 4096:
                raise ValueError("annotation import expands to more than 4096 edits")
        if row_count == 0:
            raise ValueError("annotation import requires at least one row")
        if not commands and merge == "preserve":
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation import canceled")
            if expected_revision is None:
                expected_revision = current["edit_revision"]
            _unsigned(expected_revision, "expected_revision")
            if expected_revision != current["edit_revision"]:
                raise ValueError("expected_revision does not match the preserve snapshot")
            if return_report:
                return {"snapshot": current, "applied": 0, "skipped": skipped_fields,
                        "expected_revision": expected_revision,
                        "result_revision": current["edit_revision"],
                        "planned_edits": 0, "committed": False}
            return current
        if not commands:
            raise ValueError("annotation import contains no edits")
        if len(commands) > 4096:
            raise ValueError("annotation import expands to more than 4096 edits")
        if expected_revision is None:
            expected_revision = self.snapshot()["edit_revision"]
        _unsigned(expected_revision, "expected_revision")
        if (merge == "preserve" and
                expected_revision != current["edit_revision"]):
            raise ValueError("expected_revision does not match the preserve snapshot")
        try:
            result = self._call("apply_annotations", commands, group, expected_revision,
                                None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("annotation import canceled") from None
            raise
        if return_report:
            result_revision = result["edit_revision"]
            return {"snapshot": result, "applied": len(commands), "skipped": skipped_fields,
                    "expected_revision": expected_revision, "result_revision": result_revision,
                    "planned_edits": len(commands), "committed": result_revision != expected_revision}
        return result

    def export_annotations_csv(self, path, *, cancel=None):
        """Atomically export a bounded CSV of names, comments, and bookmarks.

        The snapshot and output are limited to 4096 annotation and bookmark
        rows and 16 MiB. The destination must not already exist. A sibling
        temporary file and hard link prevent partial output from being published.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if cancel is not None and cancel.cancelled:
            raise AnalysisCancelled("annotation export canceled")
        snapshot = self.snapshot()
        if (snapshot["annotation_count"] != len(snapshot["annotations"]) or
                snapshot["bookmark_count"] != len(snapshot["bookmarks"])):
            raise ValueError("annotation CSV export is limited to 4096 annotations and bookmarks")

        by_location = {}
        for annotation in snapshot["annotations"]:
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation export canceled while collecting rows")
            location = annotation["location"]
            if isinstance(location, Address):
                key = ("va", location.space, location.offset)
            elif isinstance(location, FileOffset):
                key = ("file", location.offset)
            else:
                raise ValueError("project snapshot contains an unsupported annotation location")
            by_location[key] = {"name": annotation["name"], "comment": annotation["comment"], "bookmark": ""}
        for bookmark in snapshot["bookmarks"]:
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation export canceled while collecting rows")
            location = bookmark["location"]
            if isinstance(location, Address):
                key = ("va", location.space, location.offset)
            elif isinstance(location, FileOffset):
                key = ("file", location.offset)
            else:
                raise ValueError("project snapshot contains an unsupported bookmark location")
            by_location.setdefault(key, {"name": "", "comment": "", "bookmark": ""})["bookmark"] = bookmark["label"]
        if len(by_location) > 4096:
            raise ValueError("annotation CSV export exceeds 4096 combined location rows")

        import csv
        import io
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(("location_kind", "space", "offset", "name", "comment", "bookmark"))
        for key in sorted(by_location):
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation export canceled while collecting rows")
            values = by_location[key]
            writer.writerow((key[0], str(key[1]) if key[0] == "va" else "", hex(key[-1]),
                             values["name"], values["comment"], values["bookmark"]))
        encoded = buffer.getvalue().encode("utf-8")
        if len(encoded) > 16 * 1024 * 1024:
            raise ValueError("annotation CSV manifest exceeds 16 MiB")
        if cancel is not None and cancel.cancelled:
            raise AnalysisCancelled("annotation export canceled")
        if self.snapshot()["edit_revision"] != snapshot["edit_revision"]:
            raise ProjectChangedDuringExport("project changed during annotation export")

        destination = os.path.abspath(os.fspath(path))
        directory = os.path.dirname(destination) or os.curdir
        descriptor, temporary = tempfile.mkstemp(prefix="." + os.path.basename(destination) + ".",
                                                 suffix=".tmp", dir=directory)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation export canceled")
            if self.snapshot()["edit_revision"] != snapshot["edit_revision"]:
                raise ProjectChangedDuringExport("project changed during annotation export")
            os.link(temporary, destination)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return {"path": destination, "row_count": len(by_location), "bytes": len(encoded),
                "source_edit_revision": snapshot["edit_revision"]}

    def export_annotations_json(self, path, *, cancel=None):
        """Atomically export a bounded, versioned names/comments/bookmarks manifest.

        The snapshot and output are limited to 4096 annotation and bookmark
        rows and 16 MiB of UTF-8 JSON. The destination must not already exist.
        A same-directory temporary file and hard link prevent a canceled or
        failed export from publishing a partial manifest.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if cancel is not None and cancel.cancelled:
            raise AnalysisCancelled("annotation export canceled")
        snapshot = self.snapshot()
        if (snapshot["annotation_count"] != len(snapshot["annotations"]) or
                snapshot["bookmark_count"] != len(snapshot["bookmarks"])):
            raise ValueError("annotation manifest export is limited to 4096 annotations and bookmarks")

        rows = []
        by_location = {}
        def location_value(location):
            if isinstance(location, Address):
                return {"kind": "va", "space": location.space, "offset": location.offset}
            if isinstance(location, FileOffset):
                return {"kind": "file", "offset": location.offset}
            raise ValueError("project snapshot contains an unsupported annotation location")

        def key(location):
            if isinstance(location, Address):
                return ("va", location.space, location.offset)
            return ("file", location.offset)

        for annotation in snapshot["annotations"]:
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation export canceled while collecting rows")
            location = annotation["location"]
            record = {"location": location_value(location)}
            if annotation["name"]:
                record["name"] = annotation["name"]
            if annotation["comment"]:
                record["comment"] = annotation["comment"]
            by_location[key(location)] = record
            rows.append(record)
        for bookmark in snapshot["bookmarks"]:
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation export canceled while collecting rows")
            location = bookmark["location"]
            record = by_location.get(key(location))
            if record is None:
                record = {"location": location_value(location)}
                by_location[key(location)] = record
                rows.append(record)
            record["bookmark"] = bookmark["label"]
        manifest = {"schema_version": 1, "api_version": API_VERSION,
                    "source_edit_revision": snapshot["edit_revision"], "rows": rows}
        encoded = json.dumps(manifest, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":")).encode("utf-8") + b"\n"
        if len(encoded) > 16 * 1024 * 1024:
            raise ValueError("annotation manifest exceeds 16 MiB")
        if cancel is not None and cancel.cancelled:
            raise AnalysisCancelled("annotation export canceled")
        if self.snapshot()["edit_revision"] != snapshot["edit_revision"]:
            raise ProjectChangedDuringExport("project changed during annotation export")

        destination = os.path.abspath(os.fspath(path))
        directory = os.path.dirname(destination) or os.curdir
        prefix = "." + os.path.basename(destination) + "."
        descriptor, temporary = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation export canceled")
            if self.snapshot()["edit_revision"] != snapshot["edit_revision"]:
                raise ProjectChangedDuringExport("project changed during annotation export")
            os.link(temporary, destination)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return {"path": destination, "schema_version": 1, "row_count": len(rows),
                "bytes": len(encoded), "source_edit_revision": snapshot["edit_revision"]}

    def import_annotations_json(self, path, *, group=0, expected_revision=None,
                                merge="replace", return_report=False, cancel=None):
        """Import a strict versioned annotation manifest as one atomic edit batch.

        Input is bounded to 16 MiB and 4096 rows. Duplicate JSON keys and
        unknown fields are rejected. Unless overridden, the native batch pins
        the target project's current edit revision before it validates changes.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if cancel is not None and cancel.cancelled:
            raise AnalysisCancelled("annotation import canceled")
        try:
            with open(path, "rb") as source:
                raw = source.read(16 * 1024 * 1024 + 1)
        except OSError:
            raise
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("annotation manifest exceeds 16 MiB")

        def strict_object(pairs):
            value = {}
            for name, item in pairs:
                if name in value:
                    raise ValueError("annotation manifest contains a duplicate JSON key")
                value[name] = item
            return value

        try:
            manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object,
                                  parse_constant=lambda value: (_ for _ in ()).throw(
                                      ValueError("invalid JSON constant: " + value)))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("annotation manifest is not valid UTF-8 JSON") from error
        except RecursionError as error:
            raise ValueError("annotation manifest nesting exceeds parser limits") from error
        if not isinstance(manifest, dict) or set(manifest) != {
                "schema_version", "api_version", "source_edit_revision", "rows"}:
            raise ValueError("annotation manifest has an unsupported shape")
        _unsigned(manifest["schema_version"], "schema_version", 1)
        _unsigned(manifest["api_version"], "api_version", API_VERSION)
        if manifest["schema_version"] != 1 or manifest["api_version"] != API_VERSION:
            raise ValueError("annotation manifest version is not supported")
        _unsigned(manifest["source_edit_revision"], "source_edit_revision")
        rows = manifest["rows"]
        if not isinstance(rows, list) or len(rows) > 4096:
            raise ValueError("annotation manifest rows must contain at most 4096 items")
        decoded_rows = []
        for index, row in enumerate(rows):
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("annotation import canceled during parsing")
            if not isinstance(row, dict) or "location" not in row or not set(row) <= {
                    "location", "name", "comment", "bookmark"}:
                raise ValueError("annotation manifest row " + str(index) + " has an unsupported shape")
            where = row["location"]
            if not isinstance(where, dict):
                raise ValueError("annotation manifest location must be an object")
            if where.get("kind") == "va" and set(where) == {"kind", "space", "offset"}:
                location = Address(_unsigned(where["space"], "space"),
                                   _unsigned(where["offset"], "offset"))
            elif where.get("kind") == "file" and set(where) == {"kind", "offset"}:
                location = FileOffset(_unsigned(where["offset"], "offset"))
            else:
                raise ValueError("annotation manifest location has an unsupported shape")
            item = {"location": location}
            for field in ("name", "comment", "bookmark"):
                if field in row:
                    value = row[field]
                    if not isinstance(value, str):
                        raise ValueError("annotation manifest " + field + " must be text")
                    try:
                        value.encode("utf-8")
                    except UnicodeEncodeError as error:
                        raise ValueError("annotation manifest " + field + " must contain valid Unicode") from error
                    item[field] = value
            if len(item) == 1:
                raise ValueError("annotation manifest row has no annotation fields")
            decoded_rows.append(item)
        if not decoded_rows:
            _unsigned(group, "group")
            if merge not in ("replace", "preserve"):
                raise ValueError("merge must be 'replace' or 'preserve'")
            current = self.snapshot()
            if expected_revision is not None:
                _unsigned(expected_revision, "expected_revision")
                if expected_revision != current["edit_revision"]:
                    raise ValueError("expected_revision does not match the current project")
            result = {"snapshot": current, "applied": 0, "skipped": 0}
            return result if return_report else current
        return self.apply_annotations(decoded_rows, group=group,
            expected_revision=expected_revision, merge=merge,
            return_report=return_report, cancel=cancel)

    def import_annotations_csv(self, path, *, group=0, expected_revision=None,
                               merge="replace", return_report=False, cancel=None):
        """Import a bounded UTF-8 annotation CSV through one atomic batch.

        The header requires ``location_kind`` and ``offset`` and may include
        ``space``, ``name``, ``comment``, and ``bookmark``. CSV exported by
        :meth:`export_annotations_csv` is accepted directly. Input is capped
        at 16 MiB and 4096 data rows; edits use the same revision, merge, and
        cancellation rules as :meth:`apply_annotations`.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if cancel is not None and cancel.cancelled:
            raise AnalysisCancelled("annotation CSV import canceled")
        with open(os.fspath(path), "rb") as source:
            raw = source.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("annotation CSV manifest exceeds 16 MiB")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeError as error:
            raise ValueError("annotation CSV manifest is not valid UTF-8") from error

        import csv
        import io
        try:
            reader = csv.reader(io.StringIO(text, newline=""), strict=True)
            header = next(reader, None)
            if not header:
                raise ValueError("annotation CSV manifest is empty")
            if len(set(header)) != len(header):
                raise ValueError("annotation CSV manifest contains duplicate column names")
            allowed = {"location_kind", "space", "offset", "name", "comment", "bookmark"}
            if (not set(header) <= allowed or
                    not {"location_kind", "offset"} <= set(header)):
                raise ValueError("annotation CSV header requires location_kind and offset and allows only space/name/comment/bookmark")
            if not set(header) & {"name", "comment", "bookmark"}:
                raise ValueError("annotation CSV header must include an annotation column")
            decoded_rows = []
            text_bytes = 0
            for row_number, values in enumerate(reader, 2):
                if cancel is not None and cancel.cancelled:
                    raise AnalysisCancelled("annotation CSV import canceled during parsing")
                if not values:
                    continue
                if len(values) != len(header):
                    raise ValueError("annotation CSV row " + str(row_number) + " has the wrong number of columns")
                fields = dict(zip(header, values))

                def parse_number(value, field):
                    stripped = value.strip()
                    if not stripped:
                        raise ValueError(field + " must contain an integer")
                    try:
                        number = int(stripped, 0)
                    except ValueError:
                        if not stripped.isdecimal():
                            raise ValueError(field + " must contain a decimal or prefixed integer")
                        number = int(stripped, 10)
                    return _unsigned(number, field)

                try:
                    offset = parse_number(fields["offset"], "offset")
                    kind = fields["location_kind"]
                    if kind == "va":
                        if "space" not in fields or not fields["space"].strip():
                            raise ValueError("VA location requires space")
                        location = Address(parse_number(fields["space"], "space"), offset)
                    elif kind == "file":
                        if "space" in fields and fields["space"].strip():
                            raise ValueError("file location must leave space blank")
                        location = FileOffset(offset)
                    else:
                        raise ValueError("location_kind must be va or file")
                except ValueError as error:
                    raise ValueError("annotation CSV row " + str(row_number) + ": " + str(error)) from error

                item = {"location": location}
                for field in ("name", "comment", "bookmark"):
                    value = fields.get(field, "")
                    if value:
                        text_bytes += len(value.encode("utf-8"))
                        if text_bytes > 16 * 1024 * 1024:
                            raise ValueError("annotation CSV text exceeds 16 MiB")
                        item[field] = value
                if len(item) == 1:
                    raise ValueError("annotation CSV row " + str(row_number) + " has no nonempty annotation fields")
                decoded_rows.append(item)
                if len(decoded_rows) > 4096:
                    raise ValueError("annotation CSV manifest exceeds 4096 rows")
        except csv.Error as error:
            raise ValueError("malformed annotation CSV manifest: " + str(error)) from error

        if not decoded_rows:
            _unsigned(group, "group")
            if merge not in ("replace", "preserve"):
                raise ValueError("merge must be 'replace' or 'preserve'")
            current = self.snapshot()
            if expected_revision is not None:
                _unsigned(expected_revision, "expected_revision")
                if expected_revision != current["edit_revision"]:
                    raise ValueError("expected_revision does not match the current project")
            result = {"snapshot": current, "applied": 0, "skipped": 0}
            return result if return_report else current
        return self.apply_annotations(decoded_rows, group=group,
            expected_revision=expected_revision, merge=merge,
            return_report=return_report, cancel=cancel)

    def apply_batch(self, operations, *, group=0, expected_revision=None, cancel=None):
        """Apply diverse project edits as one bounded, revision-pinned action.

        Supported tuple forms are documented in ``docs/python-automation-batches.md``.
        The batch commits as one history step. CancellationToken stops native
        validation or commit work; all operations are validated before commit.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        _unsigned(group, "group")
        if expected_revision is None:
            expected_revision = self.snapshot()["edit_revision"]
        _unsigned(expected_revision, "expected_revision")
        commands = []
        text_bytes = patch_bytes = chunk_count = 0
        type_nodes = [0]
        active = set()
        allowed_references = {"code", "data", "call", "jump", "read", "write", "address"}
        allowed_breakpoints = {"software", "hardware", "execute", "read", "write", "access"}

        def add_text(value, name):
            nonlocal text_bytes
            if not isinstance(value, str):
                raise TypeError(name + " must be text")
            text_bytes += len(value.encode("utf-8"))
            if text_bytes > 16 * 1024 * 1024:
                raise ValueError("Automation batch text exceeds 16 MiB")
            return value

        for operation in operations:
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("automation batch canceled during planning")
            if len(commands) >= 4096:
                raise ValueError("Automation batch is limited to 4096 operations")
            if not isinstance(operation, (tuple, list)) or not operation or not isinstance(operation[0], str):
                raise TypeError("each operation must be a nonempty tuple/list beginning with a command name")
            kind = operation[0]
            if kind in ("rename", "comment"):
                if len(operation) != 3:
                    raise ValueError(kind + " requires (kind, location, text)")
                commands.append((kind, _location(operation[1]), add_text(operation[2], kind)))
            elif kind == "bookmark":
                if len(operation) != 4 or not isinstance(operation[3], bool):
                    raise ValueError("bookmark requires (kind, location, label, remove_bool)")
                commands.append((kind, _location(operation[1]), add_text(operation[2], "bookmark label"), operation[3]))
            elif kind == "patch":
                if len(operation) != 3:
                    raise ValueError("patch requires (kind, location, bytes)")
                if not isinstance(operation[2], (bytes, bytearray, memoryview)):
                    raise TypeError("patch payload must be bytes-like")
                payload = bytes(operation[2])
                if len(payload) > maximum_read:
                    raise ValueError("Each automation batch patch is limited to 1 MiB")
                patch_bytes += len(payload)
                if patch_bytes > 16 * 1024 * 1024:
                    raise ValueError("Automation batch patches exceed 16 MiB")
                commands.append((kind, _location(operation[1]), payload))
            elif kind in ("code", "data"):
                if len(operation) != 3 or not isinstance(operation[1], Address):
                    raise ValueError(kind + " requires (kind, Address, size)")
                commands.append((kind, _location(operation[1]), _unsigned(operation[2], "size")))
            elif kind == "function":
                if len(operation) != 2 or not isinstance(operation[1], Address):
                    raise ValueError("function requires (kind, Address)")
                commands.append((kind, _location(operation[1])))
            elif kind == "suppress_function":
                if len(operation) != 3 or not isinstance(operation[1], Address) or not isinstance(operation[2], bool):
                    raise ValueError("suppress_function requires (kind, Address, suppressed_bool)")
                commands.append((kind, _location(operation[1]), operation[2]))
            elif kind == "reference":
                if (len(operation) != 5 or not isinstance(operation[3], str) or
                        operation[3] not in allowed_references or not isinstance(operation[4], bool)):
                    raise ValueError("reference requires (kind, source, target, reference_kind, remove_bool)")
                commands.append((kind, _location(operation[1]), _location(operation[2]), operation[3], operation[4]))
            elif kind == "chunks":
                if len(operation) != 3 or not isinstance(operation[1], Address) or not isinstance(operation[2], (tuple, list)):
                    raise ValueError("chunks requires (kind, function_entry, sequence_of_(Address,size))")
                if len(operation[2]) > 4096:
                    raise ValueError("A function chunk list is limited to 4096 ranges")
                chunk_count += len(operation[2])
                if chunk_count > 65536:
                    raise ValueError("Automation batch exceeds 65536 total function chunks")
                ranges = []
                for chunk in operation[2]:
                    if not isinstance(chunk, (tuple, list)) or len(chunk) != 2 or not isinstance(chunk[0], Address):
                        raise ValueError("each chunk must be an (Address, size) pair")
                    ranges.append((_location(chunk[0]), _unsigned(chunk[1], "chunk size")))
                commands.append((kind, _location(operation[1]), ranges))
            elif kind == "type_assignment":
                if len(operation) != 4 or not isinstance(operation[1], Address) or not isinstance(operation[3], bool):
                    raise ValueError("type_assignment requires (kind, Address, type_id, remove_bool)")
                commands.append((kind, _location(operation[1]), _unsigned(operation[2], "type_id"), operation[3]))
            elif kind == "update_type":
                if len(operation) != 4 or not isinstance(operation[2], str) or not isinstance(operation[3], TypeSpec):
                    raise ValueError("update_type requires (kind, type_id, name, TypeSpec)")
                name = add_text(operation[2], "type name")
                _type_spec_budget(operation[3], type_nodes, active)
                commands.append((kind, _unsigned(operation[1], "type_id"), name, operation[3]._to_native()))
            elif kind == "breakpoint":
                if (len(operation) != 10 or not isinstance(operation[1], Address) or
                        not isinstance(operation[2], str) or operation[2] not in allowed_breakpoints):
                    raise ValueError("breakpoint requires (kind, Address, breakpoint_kind, size, enabled, remove, condition, logpoint, log_message, ignore_count)")
                if not isinstance(operation[4], bool) or not isinstance(operation[5], bool) or not isinstance(operation[7], bool):
                    raise TypeError("breakpoint enabled, remove, and logpoint fields must be bool")
                commands.append((kind, _location(operation[1]), operation[2],
                                 _unsigned(operation[3], "breakpoint size", 255), operation[4], operation[5],
                                 add_text(operation[6], "breakpoint condition"), operation[7],
                                 add_text(operation[8], "breakpoint log message"),
                                 _unsigned(operation[9], "ignore_count")))
            else:
                raise ValueError("unsupported automation batch operation: " + kind)
        if not commands:
            raise ValueError("automation batch requires at least one command")
        try:
            return self._call("apply_batch", commands, group, expected_revision,
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("automation batch canceled") from None
            raise

    def patch(self, location, replacement, *, expected_revision=None, group=0):
        """Apply a bounded byte patch only if edit history is at expected revision.

        Capture ``snapshot()["edit_revision"]`` before preparing a patch and
        pass it here to reject stale scripts. Omitted values use the current
        local snapshot revision; SQLite CAS still rejects external races.
        """
        if expected_revision is None:
            expected_revision = self.snapshot()["edit_revision"]
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            raise ValueError("expected_revision must be a non-negative integer")
        return self._call("patch_at_revision", _location(location), bytes(replacement), expected_revision, group)

    def define_code(self, address, size, *, group=0):
        return self._call("code", _location(address), size, group)

    def define_data(self, address, size, *, group=0):
        return self._call("data", _location(address), size, group)

    def define_function(self, address, *, group=0):
        return self._call("function", _location(address), group)

    def suppress_function(self, address, *, suppressed=True, group=0):
        return self._call("suppress", _location(address), suppressed, group)

    def set_reference(self, source, target, *, kind="data", remove=False, group=0):
        return self._call("reference", _location(source), _location(target), kind, remove, group)

    def set_function_chunks(self, entry, chunks, *, group=0):
        """Set explicit (Address, size) ranges through the shared command validator."""
        return self._call("chunks", _location(entry), [(_location(at), size) for at, size in chunks], group)

    def define_type(self, name, type_spec, *, group=0):
        """Persist a named recursive type and return its project identity."""
        if not isinstance(type_spec, TypeSpec):
            raise TypeError("type_spec must be a TypeSpec")
        return self._call("define_type", name, type_spec._to_native(), group)

    def update_type(self, type_id, name, type_spec, *, group=0):
        """Replace one named type definition using normal history validation."""
        if not isinstance(type_spec, TypeSpec):
            raise TypeError("type_spec must be a TypeSpec")
        return self._call("update_type", type_id, name, type_spec._to_native(), group)

    def assign_type(self, address, type_id, *, remove=False, group=0):
        """Assign or remove a named type at a mapped virtual address."""
        return self._call("assign_type", _location(address), type_id, remove, group)

    def import_types(self, definitions, assignments=(), *, group=0):
        """Atomically import a recursive named type graph and location assignments.

        ``definitions`` may be a name-to-TypeSpec mapping or an iterable of
        ``(name, TypeSpec)`` pairs. Assignments are ``(Address | FileOffset,
        type_name)`` pairs. Existing destination names are updated in place,
        preserving their IDs. Both input collections are limited to 4096 rows
        per command.
        """
        rows = list(definitions.items()) if isinstance(definitions, dict) else list(definitions)
        assignment_rows = list(assignments)
        if len(rows) > 4096 or len(assignment_rows) > 4096:
            raise ValueError("portable type import is limited to 4096 definitions and assignments")
        planning_snapshot = self.snapshot()
        existing = {row["name"]: row["id"] for row in planning_snapshot["types"]}
        encoded_definitions = []
        checked_definitions = []
        for row in rows:
            if len(row) != 2:
                raise ValueError("definitions must contain (name, TypeSpec) pairs")
            name, type_spec = row
            if not isinstance(name, str):
                raise TypeError("type names must be strings")
            if not isinstance(type_spec, TypeSpec):
                raise TypeError("type definitions must be TypeSpec values")
            encoded_definitions.append((name, type_spec._to_native(), existing.get(name)))
            checked_definitions.append((name, type_spec))
        available_names = set(existing)
        available_names.update(name for name, _ in checked_definitions)

        def named_references(value):
            if isinstance(value, TypeSpec):
                if value.kind == "named_reference":
                    yield value.arguments[0]
                for part in value.arguments:
                    yield from named_references(part)
            elif isinstance(value, (tuple, list)):
                for part in value:
                    yield from named_references(part)

        for name, type_spec in checked_definitions:
            for reference in named_references(type_spec):
                if reference not in available_names:
                    raise ValueError(f"type {name!r} references unknown type {reference!r}")
        encoded_assignments = []
        for row in assignment_rows:
            if len(row) != 2:
                raise ValueError("assignments must contain (Address or FileOffset, type_name) pairs")
            at, type_name = row
            if not isinstance(at, (Address, FileOffset)):
                raise TypeError("type assignments require Address or FileOffset values")
            if not isinstance(type_name, str):
                raise TypeError("assigned type names must be strings")
            if type_name not in available_names:
                raise ValueError(f"assignment refers to unknown type {type_name!r}")
            encoded_assignments.append((_location(at), type_name))
        return self._call("import_types_at_revision", encoded_definitions, encoded_assignments, group,
                          planning_snapshot["edit_revision"])

    def undo(self):
        return self._call("undo")

    def redo(self):
        return self._call("redo")

    def analyze(self, *, instruction_budget=None, function_budget=None,
                 block_budget=None, membership_budget=None, string_budget=None,
                 string_scan_work_budget=None, min_string_characters=None,
                 progress=None, cancel=None):
        """Refresh derived analysis with optional bounded budgets and progress.

        Progress receives ``(stage, completed, total)`` while native work runs
        without holding the GIL. Return False to cancel, return None to
        continue, or raise to propagate the callback exception unchanged.
        Omitted budget values keep this project's current configuration.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if progress is not None and not callable(progress):
            raise TypeError("progress must be callable or None")
        bounds = {
            "instruction_budget": (instruction_budget, 50_000_000),
            "function_budget": (function_budget, 1_000_000),
            "block_budget": (block_budget, 10_000_000),
            "membership_budget": (membership_budget, 100_000_000),
            "string_budget": (string_budget, 10_000_000),
            "string_scan_work_budget": (string_scan_work_budget, 500_000_000),
            "min_string_characters": (min_string_characters, 64),
        }
        options = {}
        for name, (value, maximum) in bounds.items():
            if value is not None:
                options[name] = _unsigned(value, name, maximum)
                if options[name] == 0:
                    raise ValueError(f"{name} must be greater than zero")
        try:
            return self._call("analyze", options, progress,
                              None if cancel is None else cancel._handle)
        except Error as error:
            if error.code == _hexlab.CANCELED_ERROR_CODE and (
                    (cancel is not None and cancel.cancelled) or progress is not None):
                raise AnalysisCancelled("native analysis canceled") from None
            raise

    def save(self, *, cancel=None):
        """Checkpoint the project, optionally canceling the native checkpoint."""
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("save", None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("project checkpoint canceled") from None
            raise

    def save_as(self, path, *, cancel=None):
        """Write an independent copy, optionally canceling the native copy."""
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("save_as", os.fspath(path),
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("project copy canceled") from None
            raise

    def backup_to(self, path, *, replace=False, cancel=None):
        """Create a consistent restore point without changing this project's path.

        Returns a dictionary with the backup path and preserved project UUID.
        Existing destinations are refused unless replace=True.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("backup_to", os.fspath(path), bool(replace),
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("project backup canceled") from None
            raise

    def archive_external_source(self, path, *, max_bytes=256 * 1024 * 1024, cancel=None):
        """Archive the saved project's external input with UUID and digest identity."""
        _unsigned(max_bytes, "max_bytes")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("archive_external_source", os.fspath(path), max_bytes,
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("source archive creation canceled") from None
            raise

    def verify_source_archive(self, path, *, max_bytes=1024 * 1024 * 1024, cancel=None):
        """Verify an external source archive against this project's saved input identity."""
        _unsigned(max_bytes, "max_bytes")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("verify_source_archive", os.fspath(path), max_bytes,
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("source archive verification canceled") from None
            raise

    def restore_source_archive(self, archive, output, *, max_bytes=1024 * 1024 * 1024, cancel=None):
        """Restore a verified source archive to a new path without editing project provenance."""
        _unsigned(max_bytes, "max_bytes")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("restore_source_archive", os.fspath(archive), os.fspath(output), max_bytes,
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("source archive restore canceled") from None
            raise

    def backup_to_rotating(self, base, *, retain=5, cancel=None):
        """Write a timestamped restore point and prune old generations."""
        _unsigned(retain, "retain")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("backup_to_rotating", os.fspath(base), retain,
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("rotating project backup canceled") from None
            raise

    def list_rotated_backups(self, base, *, cancel=None):
        """List timestamped backups; `complete` reports whether scanning finished."""
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("list_rotated_backups", os.fspath(base),
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("backup listing canceled") from None
            raise

    def prune_rotated_backups(self, base, *, retain, cancel=None):
        """Keep at most `retain` rotated generations and report pruning status."""
        _unsigned(retain, "retain")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("prune_rotated_backups", os.fspath(base), retain,
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("backup pruning canceled") from None
            raise

    @staticmethod
    def inspect_recovery_directory(directory, *, api_version=API_VERSION, cancel=None):
        """Inspect bounded, complete HexLab recovery artifacts without changing files.

        Returns validated candidates, bounded rejection diagnostics, and scan
        counts, including ``complete`` and ``omitted_candidates`` when directory
        or candidate caps are reached. Only interrupted-save and previous-version
        staging names are considered; this does not repair arbitrary damaged
        databases.
        """
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return _hexlab.inspect_recovery_directory(
                os.fspath(directory), api_version,
                None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("project recovery scan canceled") from None
            raise

    @staticmethod
    def restore_recovery_artifact(artifact, output, *, replace=False,
                                  api_version=API_VERSION, cancel=None):
        """Restore a discovered recovery artifact as an independent project.

        The artifact is rediscovered and revalidated before publication. The
        returned project receives a fresh UUID; the source artifact is retained.
        """
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return _hexlab.restore_recovery_artifact(
                os.fspath(artifact), os.fspath(output), bool(replace), api_version,
                None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("project recovery restore canceled") from None
            raise

    @staticmethod
    def restore_backup_in_place(backup, target, *, api_version=API_VERSION, cancel=None):
        """Restore a backup after closing all project owners for target.

        Reopen target afterward to refresh its workspace snapshot.
        """
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return _hexlab.restore_backup_in_place(
                os.fspath(backup), os.fspath(target), api_version,
                None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("project restore canceled") from None
            raise

    def export_binary(self, path, *, cancel=None):
        """Export effective bytes, optionally canceling the native write.

        The exporter refuses to replace existing paths and runs without holding
        the interpreter lock while it snapshots and writes the project image.
        """
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        try:
            return self._call("export", os.fspath(path),
                              None if cancel is None else cancel._handle)
        except Error as error:
            if cancel is not None and cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("binary export canceled") from None
            raise

class Archive:
    """Read-only, thread-affine ar archive with bounded member reads."""
    def __init__(self, handle):
        self._handle = handle

    @classmethod
    def open(cls, path, *, api_version=API_VERSION):
        return cls(_hexlab.open_archive(os.fspath(path), api_version))

    def _call(self, method, *args):
        if self._handle is None:
            raise ValueError("archive is closed")
        return _hexlab.archive_call(self._handle, method, args)

    def close(self):
        if self._handle is not None:
            self._call("summary")
        self._handle = None

    def __enter__(self):
        if self._handle is None:
            raise ValueError("archive is closed")
        return self

    def __exit__(self, *exception):
        self.close()

    def summary(self):
        row = self._call("summary")
        return ArchiveSummary(row["member_count"], row["symbol_count"],
                              row["has_symbol_index"], row["symbol_index_complete"],
                              tuple(row["diagnostics"]), row["thin"], row["aix_big"])

    def members(self, *, start=0, count=256):
        return [ArchiveMember(**row) for row in self._call("members", start, count)]

    def iter_members(self, *, page_size=256):
        if not 1 <= page_size <= 4096:
            raise ValueError("page_size must be from 1 through 4096")
        total = self.summary().member_count
        for start in range(0, total, page_size):
            yield from self.members(start=start, count=page_size)

    def symbols(self, *, start=0, count=256):
        return [ArchiveSymbol(**row) for row in self._call("symbols", start, count)]

    def iter_symbols(self, *, page_size=256):
        if not 1 <= page_size <= 4096:
            raise ValueError("page_size must be from 1 through 4096")
        total = self.summary().symbol_count
        for start in range(0, total, page_size):
            yield from self.symbols(start=start, count=page_size)

    def read_member(self, index, offset, count):
        """Read at most 1 MiB from a regular member at the given offset."""
        return self._call("read_member", index, offset, count)

    def iter_member_bytes(self, index, *, chunk_size=256 * 1024):
        """Stream a regular member in bounded chunks without buffering it all."""
        if not 1 <= chunk_size <= 1024 * 1024:
            raise ValueError("chunk_size must be from 1 through 1048576")
        member = next((row for row in self.members(start=index, count=1) if row.index == index), None)
        if member is None:
            raise IndexError("archive member index is out of range")
        if member.kind != "regular":
            raise ValueError("only regular archive members contain readable data")
        for offset in range(0, member.size, chunk_size):
            yield self.read_member(index, offset, min(chunk_size, member.size - offset))


class HistoricalState:
    """Immutable exact-step user state and effective file bytes.

    This owner remains usable after the live Project is closed or edited.
    It has no undo/redo, write, analysis, or virtual-address mapping methods.
    """
    def __init__(self, handle):
        self._handle = handle

    def _call(self, method, *args):
        if self._handle is None:
            raise ValueError("historical state is closed")
        return _decode(_hexlab.history_call(self._handle, method, args))

    def close(self):
        self._handle = None

    def __enter__(self):
        if self._handle is None:
            raise ValueError("historical state is closed")
        return self

    def __exit__(self, *exception):
        self.close()

    def snapshot(self):
        """Source identity/revisions, exact target step, replay work and counts."""
        return self._call("snapshot")

    def read(self, offset, count):
        """Read up to 1 MiB at FileOffset coordinates using historical patches."""
        if not isinstance(offset, FileOffset):
            raise TypeError("historical reads require FileOffset(offset)")
        return self._call("read", _location(offset), count)

    def annotations(self, *, start=0, count=256):
        return self._call("annotations", start, count)

    def bookmarks(self, *, start=0, count=256):
        return self._call("bookmarks", start, count)

    def types(self, *, start=0, count=256):
        """Named TypeSpec definitions including declaration kind and provenance."""
        return self._call("types", start, count)

    def type_assignments(self, *, start=0, count=256):
        return self._call("type_assignments", start, count)

    def patches(self, *, start=0, count=256):
        """Canonical patch extents; use read() for their effective bytes."""
        return self._call("patches", start, count)

    def regions(self, *, start=0, count=256):
        return self._call("regions", start, count)

    def function_decisions(self, *, start=0, count=256):
        """User function entries, suppression state and explicit chunk counts."""
        return self._call("function_decisions", start, count)

    def function_chunks(self, decision_id, *, start=0, count=256):
        return self._call("function_chunks", decision_id, start, count)

    def user_references(self, *, start=0, count=256):
        return self._call("user_references", start, count)

    def _iterate_rows(self, method, page_size, *args):
        Project._check_page_size(page_size)
        start = 0
        while True:
            page = getattr(self, method)(*args, start=start, count=page_size)
            yield from page
            if len(page) < page_size:
                return
            start += len(page)

    def iter_annotations(self, *, page_size=256):
        return self._iterate_rows("annotations", page_size)

    def iter_bookmarks(self, *, page_size=256):
        return self._iterate_rows("bookmarks", page_size)

    def iter_types(self, *, page_size=256):
        return self._iterate_rows("types", page_size)

    def iter_type_assignments(self, *, page_size=256):
        return self._iterate_rows("type_assignments", page_size)

    def iter_patches(self, *, page_size=256):
        return self._iterate_rows("patches", page_size)

    def iter_regions(self, *, page_size=256):
        return self._iterate_rows("regions", page_size)

    def iter_function_decisions(self, *, page_size=256):
        return self._iterate_rows("function_decisions", page_size)

    def iter_function_chunks(self, decision_id, *, page_size=256):
        return self._iterate_rows("function_chunks", page_size, decision_id)

    def iter_user_references(self, *, page_size=256):
        return self._iterate_rows("user_references", page_size)


class DebuggerSession:
    """Owner-thread native or GDB-remote debugging session.

    Events are acknowledged explicitly: pass the event's sequence to
    ``continue_event`` or ``single_step`` before waiting for another event.
    Memory operations are bounded to 1 MiB per call.
    """
    IDLE, RUNNING, STOPPED, EXITED, DETACHED, FAULTED = range(6)
    def __init__(self, handle):
        self._handle = handle

    @classmethod
    def native(cls):
        """Create a session using the host's native backend."""
        return cls(_hexlab.debugger())

    def _call(self, method, *args):
        if self._handle is None:
            raise ValueError("debugger session is closed")
        return _hexlab.debug_call(self._handle, method, args)

    @property
    def state(self):
        return self._call("state")

    def processes(self):
        """Return a bounded snapshot of processes visible to this backend."""
        return tuple(self._call("processes"))

    def launch(self, executable, arguments=(), *, working_directory="", environment=()):
        """Launch locally or start a new inferior through an extended-remote session.

        ``environment`` is an ordered sequence of ``(name, value)`` changes;
        ``None`` unsets a name and ``\"\"`` sets it to an empty value. Remote
        launch supports at most 256 unique changes and 64 KiB of UTF-8 name and
        value data. Local launch rejects nonempty remote environment changes.
        """
        if not isinstance(environment, (list, tuple)):
            raise TypeError("environment must be a list or tuple of (name, value-or-None) pairs")
        if len(environment) > 256:
            raise ValueError("remote environment exceeds 256 changes")
        normalized_environment = []
        seen_names = set()
        total_bytes = 0
        for change in environment:
            if not isinstance(change, (list, tuple)) or len(change) != 2:
                raise TypeError("each environment change must be a (name, value-or-None) pair")
            name, value = change
            if not isinstance(name, str):
                raise TypeError("remote environment names must be str")
            if value is not None and not isinstance(value, str):
                raise TypeError("remote environment values must be str or None")
            name_bytes = name.encode("utf-8")
            value_bytes = b"" if value is None else value.encode("utf-8")
            if not name_bytes or b"=" in name_bytes or b"\0" in name_bytes or b"\0" in value_bytes:
                raise ValueError("remote environment names must be nonempty without '=' or NUL, and values cannot contain NUL")
            if len(name_bytes) > 4096 or len(value_bytes) > 16 * 1024:
                raise ValueError("remote environment name or value exceeds its byte limit")
            if name in seen_names:
                raise ValueError("remote environment repeats a variable name")
            seen_names.add(name)
            total_bytes += len(name_bytes) + len(value_bytes)
            if total_bytes > 64 * 1024:
                raise ValueError("remote environment exceeds the 64 KiB byte limit")
            normalized_environment.append((name, value))
        return self._call("launch", os.fspath(executable), tuple(os.fspath(arg) for arg in arguments),
                          os.fspath(working_directory), tuple(normalized_environment))

    def attach(self, process_id):
        return self._call("attach", process_id)

    def connect_remote(self, host, port):
        """Connect through HexLab's GDB Remote Serial Protocol backend."""
        return self._call("connect_remote", host, port)

    def attach_remote_process(self, process_id):
        """Select another inferior from a multiprocess extended-remote session.

        The ID must come from ``processes()``. A successful selection replaces
        the active inferior and any pending stop event for the previous one.
        """
        _unsigned(process_id, "process_id")
        if process_id == 0:
            raise ValueError("process_id must be nonzero")
        return self._call("attach_remote_process", process_id)

    def detach_remote_process(self, process_id):
        """Detach a secondary listed inferior while retaining the active one."""
        _unsigned(process_id, "process_id")
        if process_id == 0:
            raise ValueError("process_id must be nonzero")
        return self._call("detach_remote_process", process_id)

    def wait_event(self, timeout_ms=1000, *, cancel=None):
        """Wait for a debugger event; an optional token cancels the wait promptly."""
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        if cancel is None:
            return self._call("wait_event", timeout_ms)
        try:
            return self._call("wait_event", timeout_ms, cancel._handle)
        except Error as error:
            if cancel.cancelled and error.code == _hexlab.CANCELED_ERROR_CODE:
                raise AnalysisCancelled("debugger event wait canceled") from None
            raise

    def continue_event(self, sequence, *, status="handled"):
        return self._call("continue", sequence, status)

    def single_step(self, sequence, *, status="handled"):
        return self._call("step", sequence, status)

    def interrupt(self):
        return self._call("interrupt")

    def terminate(self):
        """Permanently terminate the selected target; distinct from detach/close."""
        return self._call("terminate")

    def detach(self):
        return self._call("detach")

    def read_memory(self, address, count):
        return self._call("read_memory", address, count)

    def write_memory(self, address, data):
        return self._call("write_memory", address, bytes(data))

    def evaluate_expression(self, thread_id, expression):
        """Evaluate a bounded register/memory expression on a stopped thread."""
        if not isinstance(expression, str):
            raise TypeError("expression must be str")
        if len(expression.encode("utf-8")) > 256:
            raise ValueError("expression exceeds 256 bytes")
        return self._call("evaluate_expression", thread_id, expression)

    def search_memory(self, pattern, *, ranges=(), writable=None, executable=None,
                      alignment=1, chunk_size=64 * 1024,
                      max_bytes=64 * 1024 * 1024,
                      max_comparisons=64 * 1024 * 1024,
                      max_results=4096, max_read_failures=64,
                      stop_on_read_failure=False, cancel=None):
        """Search readable target maps with a byte pattern and explicit work caps.

        Returns a report even when canceled or capped, preserving partial matches
        and read failures alongside an explicit completion status.
        """
        if not isinstance(pattern, str):
            raise TypeError("pattern must be str")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        options = {
            "ranges": tuple(ranges), "writable": writable, "executable": executable,
            "alignment": alignment, "chunk_size": chunk_size,
            "max_bytes": max_bytes, "max_comparisons": max_comparisons,
            "max_results": max_results, "max_read_failures": max_read_failures,
            "stop_on_read_failure": stop_on_read_failure,
        }
        token_handle = None if cancel is None else cancel._handle
        return self._call("search_memory", pattern, options, token_handle)

    def threads(self):
        return self._call("threads")

    def thread_run_states(self):
        """Return the backend's bounded snapshot as typed, session-scoped rows."""
        return tuple(ThreadRunState(row["thread_id"], ThreadState(row["state"]))
                     for row in self._call("thread_run_states"))

    def resume_threads(self, sequence, actions):
        """Apply one validated per-thread schedule for a pending stop event.

        Each action must be a ThreadResumeAction. IDs must come from this
        session's current thread listing/state snapshot. The backend rejects
        unsupported schedules and stale stop sequences.
        """
        if not isinstance(sequence, int) or isinstance(sequence, bool) or not 0 <= sequence <= 0xffffffffffffffff:
            raise ValueError("sequence must be an unsigned 64-bit integer")
        if not isinstance(actions, (list, tuple)) or not 1 <= len(actions) <= 4096:
            raise ValueError("actions must be a list or tuple with 1 to 4096 records")
        records = []
        seen = set()
        resumes_any = False
        for action in actions:
            if not isinstance(action, ThreadResumeAction):
                raise TypeError("actions must contain ThreadResumeAction records")
            thread_id = action.thread_id
            if not isinstance(thread_id, int) or isinstance(thread_id, bool) or not 0 < thread_id <= 0xffffffffffffffff:
                raise ValueError("thread_id must be a nonzero unsigned 64-bit integer")
            if thread_id in seen:
                raise ValueError("thread resume schedule contains a duplicate thread_id")
            if not isinstance(action.kind, ThreadResumeKind):
                raise TypeError("kind must be a ThreadResumeKind")
            if action.kind not in (ThreadResumeKind.CONTINUE, ThreadResumeKind.STEP, ThreadResumeKind.STOP):
                raise ValueError("kind must be continue, step, or stop")
            seen.add(thread_id)
            resumes_any = resumes_any or action.kind is not ThreadResumeKind.STOP
            records.append({"thread_id": thread_id, "kind": action.kind.value})
        if not resumes_any:
            raise ValueError("thread resume schedule must continue or step at least one thread")
        return self._call("resume_threads", sequence, records)

    def modules(self):
        return self._call("modules")

    def memory_regions(self):
        return self._call("memory_regions")

    def registers(self, thread_id):
        return self._call("registers", thread_id)

    def write_registers(self, thread_id, registers):
        return self._call("write_registers", thread_id, list(registers))

    def breakpoints(self):
        return self._call("breakpoints")

    def add_breakpoint(self, address, *, kind="software", size=1):
        return self._call("add_breakpoint", address, kind, size)

    def remove_breakpoint(self, breakpoint_id):
        return self._call("remove_breakpoint", breakpoint_id)

    def enable_breakpoint(self, breakpoint_id, enabled=True):
        return self._call("enable_breakpoint", breakpoint_id, enabled)

    def set_breakpoint_ignore_count(self, breakpoint_id, count):
        """Ignore the first ``count`` hits; a zero count reports every hit."""
        if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 0xffffffffffffffff:
            raise ValueError("count must be an unsigned 64-bit integer")
        return self._call("set_breakpoint_ignore_count", breakpoint_id, count)

    def set_breakpoint_condition(self, breakpoint_id, expression):
        """Set a bounded register-only condition, or clear it with an empty string."""
        if not isinstance(expression, str):
            raise TypeError("expression must be str")
        if len(expression.encode("utf-8")) > 256:
            raise ValueError("condition exceeds 256 bytes")
        return self._call("set_breakpoint_condition", breakpoint_id, expression)

    def set_breakpoint_logpoint(self, breakpoint_id, enabled=True, message=""):
        """Configure literal log output; empty text uses the default address/ID message."""
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be bool")
        if not isinstance(message, str):
            raise TypeError("message must be str")
        if len(message.encode("utf-8")) > 1024:
            raise ValueError("log message exceeds 1024 bytes")
        return self._call("set_breakpoint_logpoint", breakpoint_id, enabled, message)

    def close(self):
        if self._handle is not None:
            if self.state in (1, 2, 3):
                self.detach()
            self._handle = None

    def __enter__(self):
        if self._handle is None:
            raise ValueError("debugger session is closed")
        return self

    def __exit__(self, *exception):
        self.close()


class DebuggerJob:
    """Thread-safe result handle for one queued ``DebuggerWorker`` operation."""
    __slots__ = ("_future", "_cancel_token", "job_id")

    def __init__(self, job_id, future, cancel_token):
        self.job_id = job_id
        self._future = future
        self._cancel_token = cancel_token

    def cancel(self):
        """Cancel queued work or request cooperative cancellation if running."""
        self._cancel_token.cancel()
        return self._future.cancel()

    @property
    def done(self):
        return self._future.done()

    def result(self, timeout=None):
        return self._future.result(timeout)

    def exception(self, timeout=None):
        return self._future.exception(timeout)

    def add_done_callback(self, callback):
        if not callable(callback):
            raise TypeError("callback must be callable")
        self._future.add_done_callback(lambda _future: callback(self))


@dataclass(frozen=True)
class DebuggerWorkerStatus:
    """Detached point-in-time worker lifecycle and bounded-queue counters."""
    ready: bool
    closing: bool
    stopped: bool
    failed: bool
    failure_type: str | None
    active_job_id: int | None
    queued_jobs: int
    queued_input_bytes: int
    queued_input_items: int
    queued_events: int
    pending_sequence: int | None


class DebuggerWorker:
    """Asynchronous thread-safe command and event bridge for one debugger.

    A private non-daemon thread creates and owns the native ``DebuggerSession``.
    Other threads submit bounded jobs and receive detached event dictionaries;
    session methods never run on the caller or GUI thread.
    """
    _METHODS = frozenset({
        "state", "processes", "launch", "attach", "connect_remote",
        "attach_remote_process", "detach_remote_process",
        "continue_event", "single_step", "interrupt", "terminate", "detach",
        "read_memory", "write_memory", "evaluate_expression", "search_memory",
        "threads", "thread_run_states", "resume_threads", "modules",
        "memory_regions", "registers", "write_registers", "breakpoints",
        "add_breakpoint", "remove_breakpoint", "enable_breakpoint",
        "set_breakpoint_ignore_count", "set_breakpoint_condition",
        "set_breakpoint_logpoint",
    })
    _ACK_METHODS = frozenset({"continue_event", "single_step", "resume_threads"})
    _WAIT_TIMEOUT_MESSAGES = frozenset({
        "debug event wait timed out", "remote target has not stopped yet",
    })
    _MAX_INPUT_BYTES = 16 * 1024 * 1024
    _MAX_QUEUED_INPUT_BYTES = 64 * 1024 * 1024
    _MAX_INPUT_ITEMS = 65536
    _MAX_QUEUED_INPUT_ITEMS = 262144
    _MAX_INPUT_DEPTH = 16

    def __init__(self, *, max_pending=32, max_events=128,
                 event_poll_ms=50, shutdown_timeout=5.0):
        for value, label in ((max_pending, "max_pending"), (max_events, "max_events")):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 256:
                raise ValueError(f"{label} must be in 1..256")
        if not isinstance(event_poll_ms, int) or isinstance(event_poll_ms, bool) or not 10 <= event_poll_ms <= 250:
            raise ValueError("event_poll_ms must be in 10..250")
        if (not isinstance(shutdown_timeout, (int, float)) or isinstance(shutdown_timeout, bool) or
                not math.isfinite(shutdown_timeout) or not 0 <= shutdown_timeout <= 60):
            raise ValueError("shutdown_timeout must be in 0..60 seconds")
        self._commands = Queue(maxsize=max_pending)
        self._events = Queue(maxsize=max_events)
        self._event_poll_ms = event_poll_ms
        self._shutdown_timeout = float(shutdown_timeout)
        self._shutdown = CancellationToken()
        self._lock = Lock()
        self._closed = False
        self._next_job_id = 1
        self._queued_input_bytes = 0
        self._queued_input_items = 0
        self._active_job = None
        self._pending_sequence = None
        self._failure = None
        self._stopped = Event()
        self._ready = Future()
        self._thread = Thread(target=self._run, name="HexLab debugger worker", daemon=False)
        self._thread.start()
        try:
            self._ready.result(timeout=10)
        except BaseException:
            self.close(timeout=self._shutdown_timeout)
            raise

    def submit(self, method, *args, **kwargs):
        """Queue one allowed ``DebuggerSession`` call and return its job handle.

        Inputs are detached at submission time and bounded to 16 MiB and 65,536
        values. ``wait_event`` is intentionally not a job: this worker pumps
        events automatically into its bounded event queue.
        """
        if not isinstance(method, str) or method not in self._METHODS:
            raise ValueError("unsupported asynchronous debugger operation")
        if method == "search_memory" and "cancel" in kwargs:
            raise ValueError("search_memory cancellation is controlled by its DebuggerJob")
        if method == "launch":
            if not args:
                raise TypeError("launch requires an executable path")
            args = (os.fspath(args[0]),) + tuple(args[1:])
            if len(args) > 1:
                if not isinstance(args[1], (list, tuple)) or len(args[1]) > 4096:
                    raise ValueError("launch arguments must be a sequence of at most 4096 paths or strings")
                args = (args[0], tuple(os.fspath(arg) for arg in args[1])) + tuple(args[2:])
            if "working_directory" in kwargs:
                kwargs["working_directory"] = os.fspath(kwargs["working_directory"])
        if method == "state" and (args or kwargs):
            raise TypeError("state does not accept arguments")
        if method == "write_memory" and len(args) > 1 and len(args[1]) > 1024 * 1024:
            raise ValueError("debugger memory writes are limited to 1 MiB")
        budget = [0, 0, set()]
        args = self._snapshot_input(tuple(args), budget)
        kwargs = self._snapshot_input(dict(kwargs), budget)
        input_bytes = budget[0]
        input_items = budget[1]
        future = Future()
        cancel = CancellationToken()
        with self._lock:
            if self._closed or self._stopped.is_set():
                cancel.cancel()
                raise RuntimeError("debugger worker is closed")
            if input_bytes > self._MAX_QUEUED_INPUT_BYTES - self._queued_input_bytes:
                cancel.cancel()
                raise RuntimeError("debugger worker queued input budget is full")
            if input_items > self._MAX_QUEUED_INPUT_ITEMS - self._queued_input_items:
                cancel.cancel()
                raise RuntimeError("debugger worker queued value budget is full")
            job_id = self._next_job_id
            self._next_job_id += 1
            job = DebuggerJob(job_id, future, cancel)
            try:
                self._commands.put_nowait((job, method, args, kwargs, input_bytes, input_items))
            except Full:
                cancel.cancel()
                raise RuntimeError("debugger worker command queue is full") from None
            self._queued_input_bytes += input_bytes
            self._queued_input_items += input_items
        return job

    def get_event(self, timeout=None):
        """Return the next detached stop event, or ``None`` after worker exit.

        Events are never dropped. When the bounded queue fills, the worker stops
        polling until a consumer drains it, leaving the target stopped.
        """
        if timeout is not None:
            if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
                    not math.isfinite(timeout) or timeout < 0):
                raise ValueError("timeout must be a nonnegative number or None")
            deadline = time.monotonic() + timeout
        while True:
            try:
                return self._events.get_nowait()
            except Empty:
                pass
            if self._stopped.is_set() and self._events.empty():
                if self._failure is not None:
                    raise RuntimeError("debugger worker failed") from self._failure
                return None
            wait = 0.05
            if timeout is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("timed out waiting for debugger event")
                wait = min(wait, remaining)
            try:
                return self._events.get(timeout=wait)
            except Empty:
                continue

    @property
    def status(self):
        """Return a detached, nonblocking snapshot of worker and queue state.

        Queue counters are instantaneous observations, not reservations; submit
        and event consumption may change them immediately after this property
        returns. No debugger backend call is made on the caller thread.
        """
        with self._lock:
            active_job_id = None if self._active_job is None else self._active_job.job_id
            failure = self._failure
            return DebuggerWorkerStatus(
                ready=self._ready.done() and self._ready.exception() is None,
                closing=self._closed,
                stopped=self._stopped.is_set(),
                failed=failure is not None,
                failure_type=None if failure is None else type(failure).__name__,
                active_job_id=active_job_id,
                queued_jobs=self._commands.qsize(),
                queued_input_bytes=self._queued_input_bytes,
                queued_input_items=self._queued_input_items,
                queued_events=self._events.qsize(),
                pending_sequence=self._pending_sequence,
            )

    def iter_events(self, *, poll_interval=0.1, max_events=None, cancel=None):
        """Yield detached stop events until worker exit, a row cap, or cancellation.

        ``poll_interval`` bounds cancellation latency while waiting for the
        worker's bounded event queue. Cancellation is observed between waits;
        events already removed from the queue are yielded before another check.
        """
        if (not isinstance(poll_interval, (int, float)) or isinstance(poll_interval, bool) or
                not math.isfinite(poll_interval) or not 0.01 <= poll_interval <= 10):
            raise ValueError("poll_interval must be in 0.01..10 seconds")
        if max_events is not None:
            _unsigned(max_events, "max_events")
        if cancel is None:
            cancel = globals().get("_hexlab_console_cancellation_token")
        if cancel is not None and not isinstance(cancel, CancellationToken):
            raise TypeError("cancel must be a CancellationToken")
        yielded = 0
        while max_events is None or yielded < max_events:
            if cancel is not None and cancel.cancelled:
                raise AnalysisCancelled("debugger event iteration canceled")
            try:
                event = self.get_event(timeout=poll_interval)
            except TimeoutError:
                continue
            if event is None:
                return
            yielded += 1
            yield event

    def close(self, *, timeout=None):
        """Request orderly detach and join; return False if the call outlives timeout."""
        if timeout is None:
            timeout = self._shutdown_timeout
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
                not math.isfinite(timeout) or timeout < 0):
            raise ValueError("timeout must be a nonnegative number")
        with self._lock:
            if not self._closed:
                self._closed = True
                self._shutdown.cancel()
                if self._active_job is not None:
                    self._active_job._cancel_token.cancel()
        self._cancel_queued(RuntimeError("debugger worker is closing"))
        if current_thread() is self._thread:
            return False
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def __enter__(self):
        if self._closed:
            raise RuntimeError("debugger worker is closed")
        return self

    def __exit__(self, *exception):
        self.close()

    @classmethod
    def _snapshot_input(cls, value, budget, depth=0):
        if depth > cls._MAX_INPUT_DEPTH:
            raise ValueError("debugger job input is nested too deeply")
        budget[1] += 1
        if budget[1] > cls._MAX_INPUT_ITEMS:
            raise ValueError("debugger job contains too many input values")
        if value is None or type(value) in (bool, float):
            budget[0] += 8
            cls._check_input_budget(value, budget)
            return value
        if type(value) is int:
            integer_bytes = max(8, (value.bit_length() + 7) // 8)
            budget[0] += integer_bytes
            cls._check_input_budget(value, budget)
            return value
        if isinstance(value, str):
            if len(value) > cls._MAX_INPUT_BYTES - budget[0]:
                raise ValueError("debugger job input exceeds 16 MiB")
            encoded = value.encode("utf-8")
            budget[0] += len(encoded)
            clone = encoded.decode("utf-8")
            return cls._check_input_budget(clone, budget)
        if isinstance(value, (bytes, bytearray, memoryview)):
            source_size = value.nbytes if isinstance(value, memoryview) else len(value)
            if source_size > cls._MAX_INPUT_BYTES - budget[0]:
                raise ValueError("debugger job input exceeds 16 MiB")
            clone = bytes(value)
            budget[0] += len(clone)
            return cls._check_input_budget(clone, budget)
        if isinstance(value, ThreadResumeKind):
            budget[0] += 8
            cls._check_input_budget(value, budget)
            return value
        if isinstance(value, ThreadResumeAction):
            thread_id = cls._snapshot_input(value.thread_id, budget, depth + 1)
            kind = cls._snapshot_input(value.kind, budget, depth + 1)
            return ThreadResumeAction(thread_id, kind)
        if isinstance(value, (list, tuple)):
            if id(value) in budget[2]:
                raise ValueError("cyclic debugger job inputs are unsupported")
            budget[2].add(id(value))
            result = tuple(cls._snapshot_input(item, budget, depth + 1) for item in value)
            budget[2].remove(id(value))
            return result
        if isinstance(value, dict):
            if id(value) in budget[2]:
                raise ValueError("cyclic debugger job inputs are unsupported")
            budget[2].add(id(value))
            result = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("debugger job mapping keys must be strings")
                budget[0] += len(key.encode("utf-8"))
                cls._check_input_budget(None, budget)
                result[key] = cls._snapshot_input(item, budget, depth + 1)
            budget[2].remove(id(value))
            return result
        raise TypeError("debugger job inputs must be immutable scalar, sequence, mapping, or byte values")

    @classmethod
    def _check_input_budget(cls, value, budget):
        if budget[0] > cls._MAX_INPUT_BYTES:
            raise ValueError("debugger job input exceeds 16 MiB")
        return value

    def _publish_event(self, event):
        # Ordinary backpressure never drops a stop. Explicit close abandons an
        # event still in transit because session.close() detaches the target.
        while not self._shutdown.cancelled:
            try:
                self._events.put(event, timeout=0.05)
                return True
            except Full:
                continue
        return False

    def _execute(self, session, job, method, args, kwargs):
        future = job._future
        if not future.set_running_or_notify_cancel():
            return
        with self._lock:
            closing = self._closed
            if not closing:
                self._active_job = job
        if closing:
            job._cancel_token.cancel()
            future.set_exception(RuntimeError("debugger worker is closing"))
            return
        try:
            if method in self._ACK_METHODS:
                if not args or self._pending_sequence is None or args[0] != self._pending_sequence:
                    raise ValueError("event sequence does not identify the worker's current pending stop")
            if method == "attach_remote_process" and self._pending_sequence is not None:
                raise ValueError("acknowledge the worker's pending stop event before selecting another remote process")
            call_args = list(args)
            call_kwargs = dict(kwargs)
            if method == "search_memory":
                if "cancel" in call_kwargs:
                    raise ValueError("search_memory cancellation is controlled by its DebuggerJob")
                call_kwargs["cancel"] = job._cancel_token
            if method == "state":
                result = session.state
            else:
                result = getattr(session, method)(*call_args, **call_kwargs)
            if method in self._ACK_METHODS:
                self._pending_sequence = None
            future.set_result(result)
        except BaseException as error:
            if not future.done():
                future.set_exception(error)
        finally:
            with self._lock:
                if self._active_job is job:
                    self._active_job = None

    def _cancel_queued(self, error):
        while True:
            try:
                job, _method, _args, _kwargs, input_bytes, input_items = self._commands.get_nowait()
            except Empty:
                break
            with self._lock:
                self._queued_input_bytes -= input_bytes
                self._queued_input_items -= input_items
            job._cancel_token.cancel()
            if not job._future.done():
                job._future.set_exception(error)

    def _run(self):
        session = None
        try:
            session = DebuggerSession.native()
            self._ready.set_result(True)
            while not self._shutdown.cancelled:
                try:
                    command = self._commands.get(timeout=0.025)
                except Empty:
                    if (session.state not in (DebuggerSession.RUNNING, DebuggerSession.STOPPED) or
                            self._pending_sequence is not None):
                        continue
                    try:
                        event = session.wait_event(
                            timeout_ms=self._event_poll_ms, cancel=self._shutdown)
                    except AnalysisCancelled:
                        if self._shutdown.cancelled:
                            break
                        raise
                    except Error as error:
                        if error.message in self._WAIT_TIMEOUT_MESSAGES:
                            continue
                        raise
                    self._pending_sequence = event["sequence"]
                    if not self._publish_event(event):
                        break
                    continue
                with self._lock:
                    self._queued_input_bytes -= command[4]
                    self._queued_input_items -= command[5]
                self._execute(session, *command[:4])
        except BaseException as error:
            self._failure = error
            if not self._ready.done():
                self._ready.set_exception(error)
        finally:
            if session is not None:
                try:
                    session.close()
                except BaseException as error:
                    if self._failure is None:
                        self._failure = error
            self._cancel_queued(RuntimeError("debugger worker stopped"))
            self._stopped.set()
