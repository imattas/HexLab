# Debugger inspection

The debugger panel can inspect a selected process and thread, request a bounded
memory page by address, enumerate loaded modules with base, image size, name,
and path, and list process memory regions with start, size, permissions, and
mapping type. **Refresh Processes** populates the process selector from the active
backend; selecting a process copies its PID into the attach field. Selecting a
thread refreshes its register set. Memory reads are exposed through
`DebugSession::read_memory` and capped at 1 MiB per call; address wrap is rejected
before reaching the backend. Module enumeration is capped at 4096 entries.

The UI offers 64-, 256-, and 1024-byte pages, with previous/next navigation and
an explicit read action. A stop event refreshes modules and reads the page at
the event address when one is supplied. Selecting a module navigates to its
base and reads a page there. Process changes and detach clear stale inspection
data. Selecting a region navigates to its start and reads a page there. Failed
memory reads replace the previous dump with an error, while module and region
enumeration failures appear in their lists and debugger output.

Register, memory, module, and memory-region refreshes run through one serialized
background inspection queue. The UI applies a result only if its request token
and debug-session generation still match; changing targets or clearing inspection
state invalidates pending results. Closing the debugger view drops queued work,
and a running request cannot access the view after destruction. Backend commands
and these inspections share a serialization mutex. Stack-frame unwinding,
symbol and source labeling, and local-variable evaluation run as queued
inspection requests using the selected immutable document snapshot and register
set. Changing the selected thread, frame, session, active document, document revision,
or project snapshot invalidates older results. Completions also require the
same pending stop sequence and a still-stopped target.

Inspection calls remain bounded: a memory page is at most 1024 bytes, module
and process results are capped at 4096 records, and memory-region results at
65536 records. The Windows backend uses `VirtualQueryEx`
to enumerate committed, reserved, and free ranges, with page protections mapped
to readable, writable, and executable flags. Region enumeration is a
point-in-time snapshot and can fail if the target exits or access is denied.
RSP transport operations retain their deadlines. The session API permits
backend memory reads while running, but the desktop refreshes automatically at
stops so displayed bytes correspond to a stable debug event where possible.
Module enumeration is an optional backend operation; unsupported backends return
an explicit `unsupported` error. The Windows backend uses a Toolhelp module
snapshot, so its view is a point-in-time enumeration and does not yet provide
symbols, section maps, or guaranteed atomicity with concurrent target changes.
The Linux ptrace backend reads `/proc/<pid>/maps` for memory regions and groups
file-backed mappings into module ranges. Region permissions and private/shared
state come from each mapping; module sizes span the lowest through highest
mapping address, including gaps. Both operations are point-in-time snapshots,
limited to 65536 region records and 4096 module records, and can fail if the
target exits or procfs denies access during inspection. Anonymous and
bracket-named kernel mappings
are included as regions but excluded from the module list.

The memory pane renders hexadecimal bytes and printable ASCII. Its **Write
bytes** action accepts hexadecimal byte pairs separated by spaces, commas, or
colons and writes them at the current address. Empty, odd-nibble, or non-hex
input is rejected before calling the backend. Each write is capped at the
selected 64-, 256-, or 1024-byte page size, and address wrap is rejected. A
successful write clears the input and refreshes the visible page; a backend
failure leaves the entered bytes available for correction or retry. Stopped
stack-frame choices resolve the runtime PC through the matched module base to
the project's preferred image base, then display the containing recovered
function name and offset when available (or an exact imported/user symbol).
When the active image contains imported PDB C13, ELF DWARF, or linked Mach-O
DWARF line rows, the frame choice also shows the source file, line, and column
for the row covering that PC. Resolution is scoped to the selected project's
image and matched main module, respects that module's runtime base, and rejects
ambiguous overlapping source rows. It does not load separate debug files on
demand or query symbol servers. Line lookup is capped at 250,000 rows per
request; larger tables still retain function/symbol labels without a source
location.
`DebugSession` exposes memory regions from
the Windows, Linux, and RSP backends when the target supports enumeration.

On Linux x86-64, register inspection exposes the AVX-512 `zmm0`-`zmm31`
registers and `k0`-`k7` opmask registers when the tracer CPU and kernel enable
the complete XSAVE components. Register writes preserve the other bytes in the
XSAVE image and activate only the state components touched by the write. The
128-bit `xmm` and 256-bit `ymm` views remain available as aliases for the low
parts of `zmm0`-`zmm15`; as with other overlapping register aliases, writing
both views in one request applies the full `zmm` value to their shared bytes.
When AVX-512 state is unavailable, the backend continues to expose the
register sets supported by the target, such as `xmm` and `ymm`. Compacted XSAVE
images and targets that expose incomplete component layouts are rejected.

The **Search** tab scans readable mapped memory for hexadecimal byte patterns.
Pairs may contain full or nibble wildcards (`??`, `A?`, or `?F`). Searches can
be restricted to a start and length, aligned to absolute addresses, and filtered
to executable, writable, or non-executable regions. The default scan budgets
are 64 MiB requested, 64 Mi comparisons, and 4096 matches; read failures and
cancellation are reported with partial results retained. Double-clicking a hit
opens its address in the bounded memory page. Search work uses the same
serialized backend queue as other inspections, and stale results are discarded
when the target changes or the view closes. The underlying API and bounds are
described in `libs/debugger/docs/memory-search.md`.

## GDB Remote Serial Protocol

The debugger panel can connect to a TCP GDB Remote Serial Protocol (RSP) endpoint
by entering a host and port and selecting **Connect RSP**. The default endpoint
is `127.0.0.1:1234`, commonly used by local emulators and remote stubs. The
connection negotiates `qSupported`, reads the initial stop state, then uses the
same event controls as a native session. **Detach / Disconnect** sends `D` and
closes the TCP connection. Socket reads, writes, and connect attempts have
deadlines and check cancellation while waiting for readiness; RSP packets and
memory queries remain size bounded. Hostname resolution uses the platform's
synchronous resolver, so DNS lookup time is outside the socket connect deadline.

The remote backend supports continue, single-step, thread enumeration and
selection, bounded memory reads and writes, and RSP software/hardware/watch
breakpoints when the stub accepts them. Multiprocess thread IDs retain their
full `pPID.TID` spelling through enumeration, stop events, and register
selection; public thread handles are unique for the connected session even when
different processes reuse the same thread number. When advertised,
`qXfer:threads:read` supplies XML thread names and running/stopped/exited state;
the backend validates the XML document, rejects malformed or duplicate thread
IDs, and decodes predefined and numeric XML entities used in names. When the stub
does not advertise the annex or returns it empty, paginated `qfThreadInfo` /
`qsThreadInfo` remains the fallback; those IDs receive generic names and an
unknown state because the thread-list packets do not report either value. In
multiprocess mode, the connected session is bound to the exact process in its initial `pPID.TID`
stop. Thread enumeration omits other processes, register access rejects their
thread tokens, and later stop/exit events must retain that process identity.
If multiprocess mode is advertised but the initial stop does not identify its
process, connection fails closed. When advertised,
`qXfer:features:read`
provides target XML that maps the bulk `g` packet onto named registers, widths,
numbers, groups, and byte order. Register writes validate all supplied names,
numbers, widths, and byte orders against that metadata, then read original
values before sending individual `P` packets. If a later write fails, the
backend attempts to restore earlier values. RSP has no transaction primitive,
so a stub can also reject rollback.

Stop events use the stop packet's reason fields: `swbreak`, `hwbreak`, `watch`,
`rwatch`, and `awatch` become breakpoint events, with watchpoint addresses
copied into the event. A signal 5 (`SIGTRAP`) is a single-step event only when
the session had requested a step; an unsolicited trap remains an exception.
This avoids treating every x86 breakpoint trap as a completed step. The event
message preserves whether the remote reported a software breakpoint, hardware
breakpoint, or read/access/write watchpoint.

When `qSupported` advertises `QNonStop+`, the client negotiates non-stop mode
for the connection. Stop notifications are delivered through the normal session
event API and acknowledged in order with `vStopped`; the transport bounds
queued notification count and bytes. Continuing an event resumes its exact
stopped thread with `vCont;c:thread-id`; single-step uses the same event owner.
Thread-qualified continue rejects a different thread while that event is
pending, so it cannot discard one thread's stop while resuming another. A
non-stop interrupt uses the framed `vCtrlC` request and requires an `OK`
response; all-stop mode keeps the raw Ctrl-C byte. If the peer does not support
non-stop mode or returns the protocol's unsupported response to negotiation,
the client uses all-stop mode; other negotiation errors fail connection. The shared
session model exposes one unacknowledged event at a time, so queued notifications
are surfaced serially and acknowledged one at a time. The desktop thread list
refreshes `DebugSession::thread_run_states()` alongside thread enumeration, then
overlays the token-keyed state snapshot and keeps known exited threads visible
even when they disappear from the current enumeration. `unknown` stays visible
as unknown; it is not guessed to mean running or stopped. Backends that do not
provide this snapshot keep their own thread-list states and disable per-thread
context actions.
Right-clicking a known thread exposes Continue, Step, and Stop when a pending
event and authoritative state snapshot are available. Continuing or stepping a
thread other than the event owner sends an atomic schedule that keeps the event
owner stopped. Stopping another running thread must consume the pending event,
so the UI labels that action to make clear that it also resumes the event owner.
The operation is rejected if the remote did not advertise a required `vCont`
action (for example, thread stop `t`); failed schedules leave the event pending.
The existing global controls remain available. Native backends do not yet
provide atomic per-thread schedules, so the context actions stay disabled for
those sessions. Linux x86/x86-64 reports a thread-state snapshot from its
traced-thread and ptrace-stop ledgers. Tasks visible in `/proc/<pid>/task` before
the backend adopts their ptrace clone event are reported as `unknown`; the
snapshot does not infer that they are running. A process exit marks retained
traced IDs as exited. Other native backends may continue to reject snapshots.
Non-stop `vCont` requests consume and validate their `OK` packet reply before
returning; interleaved `%Stop` notifications are queued during that exchange.
This applies in both ACK and no-ACK packet modes, preventing a stale `OK` from
being parsed as the next stop event.

Target descriptions may split register metadata across remote annexes using
`<xi:include href="core.xml"/>`. The backend retrieves each named annex with
`qXfer:features:read` and parses it at the inclusion point, following the
[GDB target-description inclusion rules](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Target-Description-Format.html).
Implicit register numbering continues across included documents; register
fragments inherit the surrounding feature's group, and the target's byte order
applies to the assembled register view. Included registers support the same
inspection and rollback-aware editing as inline registers. Conventional
`target` and `feature` document declarations referencing `gdb-target.dtd` are
accepted without loading a DTD.

The entire description is bounded to 1 MiB of XML, 64 document transfers, and
16 simultaneously nested documents, counting `target.xml` in each limit.
Repeated inclusions count again toward the transfer and size limits. Cycles,
missing annexes, malformed inclusion elements, and duplicate register numbers
fail connection before publishing a process. Annex names remain remote object
names; the backend does not load local files or fetch URLs. The supported
inclusion syntax uses the conventional `xi:include` spelling with `href` and an
optional standard `xmlns:xi` attribute. XPointer, fallback elements, text-mode
includes, DTD entity expansion, and other inclusion attributes are unsupported.
Existing restrictions on contiguous register numbering and bounded register
widths remain in effect.

The remote regression covers nested includes, document declarations, register
reads and writes, process-qualified thread selection, stepping, and detach
through a scripted byte transport that fragments reads and writes. It also
covers inclusion failure bounds and stop-reason classification. This validates protocol/session behavior;
interoperability with individual GDB server builds remains a separate runtime
check.

The desktop register list has a single-register editor. Select a register, edit
its displayed hexadecimal value, and use **Write register** while the target is
stopped. The value must contain exactly the selected register's byte width;
the displayed high-to-low hexadecimal order is converted using the register's
known byte order (little-endian is assumed when a native backend omits it).
Successful edits re-read the selected thread's register set so the list shows
the backend's resulting state. Backend errors leave the entered value available
for correction. The editor is bounded to 512 bytes per register.

When `qXfer:libraries:read` is advertised, the backend fetches the bounded
`library-list` XML and reports module names, paths, and load bases from the
library text address or first segment address. Module image sizes remain zero
because the standard listing does not provide a portable size. Missing
capabilities, malformed XML, and unsupported register metadata return explicit
errors. When `qXfer:memory-map:read` is advertised, `DebugSession::memory_regions`
fetches and validates the bounded memory-map XML, rejects overflowing or
overlapping ranges, and reports RAM, ROM, and flash regions. The protocol gives
only a region type, not execute permissions; the API marks regions readable,
marks RAM writable, and leaves executable false. Local launch and attach
continue to use the native backend.


## Navigation between runtime and static addresses

**Show thread PC** navigates to the selected stopped thread's register PC.
**Show frame PC** navigates to the PC of the selected inspected stack frame.
Both actions use the current active document's `DocumentId` and route through
`DocumentManager::navigate`, preserving its normal selection history. They never
use the debug event's address, watchpoint access address, or memory-pane address
as an instruction PC. Frames must finish inspecting before these actions work.

The **Debug > Toggle software breakpoint at listing selection** action maps the
active document's current listing selection into a live address. It removes an
existing software breakpoint at that address, or adds one through the same
session API as the debugger's Add/Remove controls. A mapped file-offset
selection is accepted; an unmapped offset or data-only address is rejected.
The debugger panel opens to show success or a specific unavailable reason.

All three actions require a stopped target. Mapping requires exactly one loaded
module whose absolute, lexically normalized full path equals the source
provenance path. Windows module paths are decoded strictly from UTF-8, then normalized as
UTF-16 and compared with Unicode-aware ordinal case-insensitive comparison.
POSIX spelling is preserved and compares case-sensitively. Invalid encoding,
embedded nulls, comparison/conversion failures, or excessive Windows path
lengths produce an unavailable reason in both frame inspection and direct
navigation/breakpoint actions. There is no basename, process-name, relative-path, symlink, remote
path-translation, or archive-member fallback. Duplicate exact-path modules are
ambiguous and rejected. Nonzero module and static image sizes must agree
exactly, and the known target architecture must match the static image's known
architecture. Backends with missing paths, sizes, or architecture therefore
cannot use this bridge. In particular, procfs module extents rounded to pages
may differ from ELF segment extents and are conservatively rejected.

Conversion subtracts the runtime module base and adds the preferred image base
(or reverses those operations). Module/image extents and arithmetic must not
wrap, and each destination must lie in a mapped executable segment with code
coverage. Gaps, data segments, excluded/encrypted code, addresses outside the
module extent, and other address spaces are rejected. Explicitly rebased static
PE images are currently rejected because frame/local inspection uses preferred
image coordinates. A module snapshot is fetched again for every navigation or
breakpoint action; changed bases or extents invalidate inspected frames. Module
refresh, new debug events, resume/step, target/session reset, and document
changes also invalidate frames. Late asynchronous results cannot populate a
closed or switched document or a different stop.

`ModuleInfo` currently exposes no per-module machine ID, timestamp, UUID, or
build ID, so the bridge validates machine architecture using the target process
and cannot compare format-specific build identity. Exact path, size, and
architecture are conservative compatibility checks, not proof of identical
bytes. A binary replaced at the same path with the same size and architecture
cannot be distinguished by the available runtime metadata. This also limits
mixed-architecture module identification. Module snapshots remain point-in-time
backend observations, not atomic locks against external target mutation.

## Watch expressions

The **Watches** tab evaluates up to 64 user expressions against the selected
stopped thread. Expressions reuse the bounded breakpoint expression grammar:
register names, decimal/hexadecimal constants, arithmetic, shifts, bitwise
complement, comparisons, boolean operators, and `mem8`/`mem16`/`mem32`/`mem64`
reads. Memory reads use the target byte order and require an exact-width result.
Each expression is capped at 256 bytes and 64 operands with nesting capped at
16 levels. Values display as hexadecimal; parse, register, and memory errors
remain visible in the row. Watches refresh explicitly or when the selected
thread's register context changes at a stop. Switching to a running thread or
resuming the target replaces stale values with a status marker. Watches are
session-local and are retained when changing threads, but are cleared from the
view when the debug session is detached or reset.
