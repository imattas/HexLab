# Debugger session inspection

`DebugSession` is the boundary shared by the desktop debugger, scripts, native
backends, and the GDB Remote Serial Protocol backend. The backend router keeps
host process discovery attached to its native backend: `processes()` lists
processes on the local machine even when the session is idle. A remote target
does not expose host process enumeration through this API and returns an
explicit `unsupported` result.

Inspection results are bounded to keep a malformed or unusually large target
from causing unbounded allocations. Process and thread snapshots are limited to
4096 entries, module snapshots to 4096 entries, memory maps to 65536 entries,
and a single memory read to 1 MiB. The session checks process and thread results
even when a backend does not apply the same limit itself. Backends that can
detect overflow return `resource_limit` rather than silently truncating a
snapshot, because partial process or thread lists can mislead lifecycle and
thread-selection workflows.

Thread IDs are backend-defined session identifiers. Native backends expose OS
thread IDs; RSP assigns stable session tokens to remote wire IDs. Thread state
may be `unknown` when the transport cannot report it. Enumeration does not
stop a running target or promise an atomic snapshot; callers should use stop
events and backend-specific guarantees when inspecting mutable state.
