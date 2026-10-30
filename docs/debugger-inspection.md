# Debugger inspection

The debugger panel can inspect a selected process and thread, request a bounded
memory page by address, enumerate loaded modules with base, image size, name,
and path, and list process memory regions with start, size, permissions, mapping
type, and an optional flash erase block size. The erase-block value can be
searched and is included when copying selected or visible region rows and in
the inspection JSON. **Refresh Processes** populates the process selector from the active
backend; selecting a process copies its PID into the attach field. Selecting a
thread refreshes its register set. Memory reads are exposed through
`DebugSession::read_memory` and capped at 1 MiB per call; address wrap is rejected
before reaching the backend. Module enumeration is capped at 4096 entries.
`DebugSession::write_memory` applies the same 1 MiB and address-wrap checks
centrally, so every backend receives only a bounded, non-wrapping write range.
On a stopped target that supports memory-tag reads, the Memory page also offers
**Read tags** for the current page range. The type field is passed as a signed
decimal selector. The view interprets each returned byte as one four-bit
allocation tag for a 16-byte granule and lists the aligned granule address, its
offset from the first granule, and the tag nibble. For an unaligned requested
address, the first row starts at the containing granule. The view is capped at
256 KiB of returned tag bytes and displays only tags actually returned; a
short read leaves the remaining granules unknown. Backend errors, including
unsupported or untagged-range results, remain visible as errors. This view
does not infer mapping eligibility or whether an access will pass tag
checking. Tag reads are invalidated when the selected page or debug session
changes.
The **Save raw** action exports the bytes from the latest successfully
displayed memory read as a binary file. It preserves short reads exactly and
does not pad the requested page size. Starting another read or changing the
debug session invalidates the cached export; the file contains only the bytes
returned by that read, with no address header or metadata.
Use **Browse...** beside **Executable** to choose an existing local file and fill
the executable field. The picker does not launch it; arguments and working
The Working directory's **Browse...** action fills that field from an existing
local directory; the chosen path must be valid for the target backend. Both
pickers leave the other launch fields unchanged.
With the debugger panel active, press **F5** to Continue, **F8** to Step, or
**Shift+F5** to Detach / Disconnect. These keys invoke the same actions and
state checks as their buttons.

The current event detail includes a **first chance** or **second chance** label
when the backend supplies exception-chance metadata. Windows native exception
events provide this distinction; backends that do not expose it leave the label
out rather than inferring a chance from the exception code.
Windows exception events also preserve up to the 15 raw `ExceptionInformation`
values from `EXCEPTION_RECORD`, exposing them in event detail and copied JSON.
Their meanings depend on the exception code (for example, an access violation
uses them for operation and address data), so HexLab does not decode them as a
shared cross-platform structure. A reported count beyond the OS record bound is
truncated and marked.

Choose **Copy inspection JSON** in the Debugger output heading to copy one
versioned `hexlab.debugger-inspection.v1` report. It combines the current target
identity and a structured cached event object (kind, sequence, thread, address,
code, message, optional first/second-chance state, raw Windows exception
parameters and owned breakpoint IDs)
with the visible thread/register rows,
the currently displayed memory-page text and the exact cached raw bytes with
their read address and byte count, visible modules, visible memory
regions, and visible owned breakpoints. It records each view's source snapshot
count, visible filter, and relevant sort/state options so filtered arrays are
not mistaken for complete inventories. The report uses cached UI snapshots and
does not issue backend reads; the target may have changed between those
snapshots, so the JSON explicitly marks that it is not an atomic capture. Raw
memory bytes are included as lowercase hexadecimal only when a successful
read is cached; the encoded field is bounded by the 1024-byte page limit. The
separate **Save raw** action writes those same bytes without metadata or page
padding.
The complete UTF-8 JSON must fit within 4 MiB; oversized reports are refused
rather than truncated. Copying does not change the selected thread, address,
breakpoints, or target state.

The **Memory regions** table has a case-insensitive text filter for the
displayed start address, size, `rwx` permissions, and mapping type. It filters
the current region snapshot in place and reports visible versus indexed counts;
the permission menu can further restrict rows to readable, writable, or
executable mappings. Both filters combine, and selecting a filtered row still
navigates to that exact source region. The text query is limited to 2,048
characters. The table searches at most the first 65,536
regions returned by the backend, and the status identifies when additional
rows were omitted. The filter clears when the inspected process/session changes.
Choose **Open start** to switch to the Memory tab and read a page beginning at
the selected region's start address. The normal memory-page size and backend
readability checks still apply; this action does not dump the entire region.

The **Loaded modules** table has a case-insensitive filter over base address,
image size, module name, and full path. Its visible/total count follows the
current module snapshot. Selecting a filtered row still reads memory from that
module's exact base address. Queries are limited to 2,048 characters and only
the first 4,096 modules returned by the backend are shown and searched; the
status labels additional omitted rows. The query clears when the inspected
process/session changes.
The sort menu orders the visible modules by ascending base, ASCII-case-insensitive
name, or descending size; ties use ascending base. Changing the order preserves
the selected module while it remains in the filtered table.

**Copy selected** exports the selected module's base, size, name, and path as a
one-row TSV record with a header. It copies the source module behind the
selected filtered row and refuses payloads larger than 64 KiB.
**Copy visible** exports all currently displayed rows in sort order, applying
the module text filter. It uses the same columns and refuses exports larger
than 1 MiB.

The UI offers 64-, 256-, and 1024-byte pages, with previous/next navigation and
an explicit read action. **Copy view** copies the currently displayed completed
memory dump text to the clipboard; it does not issue a new memory read and
reports when a read is pending or has failed. A stop event refreshes modules and reads the page at
the event address when one is supplied. Selecting a module navigates to its
base and reads a page there. Process changes and detach clear stale inspection
data. Selecting a region navigates to its start and reads a page there. Failed
memory reads replace the previous dump with an error, while module and region
enumeration failures appear in their lists and debugger output.
**Copy address** parses the current address field and copies its canonical
hexadecimal value (including the `0x` prefix). It does not read memory or
change the current address; invalid input and clipboard failures are reported.
Choose **Set BP** to attempt a software breakpoint at the address currently in
the Memory address field. It uses the normal breakpoint validation and backend
operation without requiring another memory read; it does not inspect page
permissions before making the request.

The Threads table filter matches a substring of the thread ID, name, run state,
core, or native kernel state, ignoring ASCII case. The count reports visible and
total threads; filtering does not change the underlying snapshot. The state menu
can show all threads or only stopped, running, exited, or unknown threads; it
combines with the text filter. If either filter hides the selected thread, the
first visible non-exited thread becomes selected when available. The query is
limited to 2,048 characters and clears when the debug session is reset or
detached. The sort menu orders visible rows by numeric ID, case-insensitive
name, run state (running, stopped, exited, unknown), or core. Core order is
ascending, places threads without reported core metadata after numbered cores,
and uses numeric thread ID to break ties. Equal names or states also use numeric
ID as the tie-breaker. Changing sort keeps the selected thread when it remains
visible.

Choose **8 / row**, **16 / row**, or **32 / row** to change the number of bytes
shown on each memory-dump line. This affects formatting on the next read; it
does not change the selected page size or backend read length.

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

Queued requests run in interactive priority order: register reads, memory pages,
module and region lists, frame/local inspection, watches, then memory searches.
Repeated queued requests of the same kind replace older queued work, while
watches and memory searches remain independent request kinds. Starting an
interactive inspection cancels a running memory search; its bounded scan returns
partial results when available. Clearing inspection state on a target change
drops all queued work from the old target, and session/request tokens still
discard any in-flight completion that arrives later. This keeps quick inspection
actions responsive when a large search is underway without applying snapshots
from a previous process or selected thread.

Inspection calls remain bounded: a memory page is at most 1024 bytes, module
and process results are capped at 4096 records, and memory-region results at
65536 records. The Windows backend uses `VirtualQueryEx`
to enumerate committed, reserved, and free ranges, with page protections mapped
to readable, writable, and executable flags. Region enumeration is a
point-in-time snapshot and can fail if the target exits or access is denied.

The memory-search result list has **Copy matches** for completed results. It
copies a CRLF-delimited text list with a `Match address`
header and one hexadecimal address per row, capped at 1 MiB. Partial and
canceled searches copy only the matches actually returned by the bounded
search report; the completion and coverage counts remain in the status line.
Copying does not reread target memory or change the selected address.
**Copy report JSON** exports the complete bounded backend search report as
`hexlab.debugger-memory-search.v1`. It includes the machine-readable completion
state, completeness flag, exact decimal-string coverage/comparison counts, every
returned match address, and each read failure's address range, error code, and
message. It copies partial and canceled reports too, does not use the visible
result filter, and refuses payloads larger than 1 MiB rather than truncating.
Starting another search or resetting the inspection replaces or clears the
report.
Filter hit addresses by a hexadecimal substring to narrow the result table; the
visible/total count updates as you type. Double-clicking a filtered hit still
opens its original address. **Copy matches** includes the full result set,
regardless of the table filter. The query is limited to 2,048 characters and
clears when a new search starts or the debug session resets.

## Copy visible breakpoints

The breakpoint controls' **Copy visible** action exports the currently displayed
breakpoint rows as TSV, including ID, address, kind, enabled state, hit and ignore
counts, rule, and one-shot state. The current filter and sort order determine
which rows are copied and their order. Control characters in cells are escaped;
exports larger than 1 MiB are refused rather than truncated.
Use **Enabled only** with the text filter to hide disabled breakpoints. The
visible count and **Copy visible** output reflect both filters; turn it off to
inspect or toggle disabled rows.
After refreshing modules, the address column adds a recovered function or
symbol name, displacement, and available source location when the selected
process architecture and an exact active-project module mapping agree. Without
that mapping the raw runtime address remains visible. The annotation is display
metadata; breakpoint ownership and navigation continue to use the exact runtime
address.
Double-click or press Enter on a breakpoint row to toggle its enabled state,
the same action as the **Toggle enabled** control. The change is applied to the
debugger and, when the address maps into the active project image, synchronized
to the project breakpoint record.
Select a breakpoint and choose **Load Rule** to put its condition, logpoint
flag and message, ignore count, and one-shot setting into the rule editor.
Update those fields and choose **Save Rule** to apply them to the selected
breakpoint and save project-backed fields when its address maps to the active
image. The debugger validates and applies condition, logpoint, message, ignore
count, and one-shot fields together; invalid input leaves the existing session
rule unchanged. Project persistence remains a separate save after that session
update succeeds. One-shot configuration is saved with a project breakpoint and
restored when **Apply Project** installs it; the runtime disarm after one hit
is session-local, so a later application re-arms the configured rule. HXEX v9
preserves that setting, while older exchange versions import it as disabled.
One-shot can be used with software,
hardware execution, and hardware data breakpoints when the backend can disable
the owned hit. It disarms after the hit passes its ignore count and condition;
if disabling fails, the stop remains visible with a diagnostic. Loading a rule
only fills the editor; it does not change the breakpoint.
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
Select a row in the Memory regions table and choose **Copy selected** to copy a
single CRLF-delimited TSV record with its start address, size, permissions, and
type. The selected row is resolved through the filtered table mapping, so the
export matches the row the user chose. The export is capped at 64 KiB and
reports selection, clipboard, or size errors without changing the current memory
address.
Choose **Copy visible** to export the currently displayed region rows in table
order, using both the text and permission filters. The TSV uses the same
Start, Size, Permissions, and Type columns; control characters in type names are
escaped. Exports larger than 1 MiB are refused rather than truncated.
The sort menu orders visible rows by start address, largest region first, or
ASCII-case-insensitive type. Largest-first ties and type-order ties use start
address; sorting preserves the selected start address while it remains visible.

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

**Copy snapshot** in the Registers header copies the currently displayed
selected-thread register set as `name = value` rows, prefixed with the thread
ID. It uses the existing completed snapshot and does not query the target again.
The clipboard payload is capped at 1 MiB; missing snapshots and clipboard
failures are reported in the debugger output.
Select a visible row and choose **Copy selected** to copy one TSV row containing
the thread ID, register name, bank, value, and current Change status. It uses
the same completed snapshot and the filtered row mapping; unavailable values
are copied as displayed. The row is capped at 64 KiB and is not refreshed by
the copy action.
**Copy visible TSV** exports the rows currently shown after the register text
filter and **Changes only** option, with thread ID, register name, bank, value,
and change status columns. Values come from the same completed snapshot; copying
does not query the target. The clipboard output is capped at 1 MiB. If that
limit is reached, the status reports how many visible rows were copied and that
the remaining rows were omitted.

The register list includes floating-point/vector and special registers present
in the selected backend snapshot. The Bank column labels backend groups and
adds an architecture name when target metadata or recognizable register names
provide one; native snapshots may have only a partial architecture label.
This view does not synthesize registers that the backend did not return.
The filter matches ASCII-case-insensitive substrings in register name, bank,
value, or change status. Its visible/total count follows the current snapshot;
filtering does not change snapshot copying, and the query clears when the debug
session is reset or detached. Queries are limited to 2,048 characters.
Use the value-format selector to show eligible available scalar integer and
special registers as unsigned or signed decimal. Values up to 64 bits use the
register's declared byte order; registers without known byte order, wider
registers, vectors, and floating-point banks stay hexadecimal. The edit field
remains hexadecimal with exact-width validation. Snapshot and TSV copy actions
use the same selected display format.
**Changes only** combines with the text filter and keeps registers marked
Changed or New against the immediately preceding completed snapshot for the
same selected thread. A thread's first snapshot is a baseline, so it has no
changed rows yet; switching threads starts that thread's baseline. The visible
count reflects the combined filters, and the option clears when inspection
state is reset.
Choose **Pin baseline** after a selected thread has a completed register
snapshot to compare later snapshots against those fixed values. The Change
column and **Changes only** then use that pinned snapshot for the pinned
thread, while other threads continue to compare with their preceding snapshot.
Choose **Clear baseline** to return to consecutive-snapshot comparisons. Pinning
is limited to one thread at a time; clear the current pin before pinning another
thread. The baseline is held only for the current inspection session and is
cleared when the target is detached or inspection state resets.
Select an available register up to 64 bits and choose **Read address** to use
its value as the next Memory-tab address. The value is decoded with the
register's byte order, and the normal bounded memory-page read follows. The
action does not verify that a register is a pointer; it reads the selected
scalar value as an address.
Unavailable target values display as `Unavailable`, never as zero. A defensive
UI bound accepts at most 1024 rows, 512 bytes per register, and 1 MiB of
rendered register text; an oversized snapshot is rejected with a visible
message rather than truncated.

Select a row in **Threads** and choose **Copy selected** to copy that row's
thread ID, name, run state, core, and native kernel state as one TSV record
with a header. Backslashes, tabs and line breaks in text fields are escaped, and payloads
over 64 KiB are rejected. The action copies the currently displayed thread
snapshot; it does not refresh or otherwise query the target.
Choose **Copy visible** to export every row currently shown in the Threads
table, in sort order. Text and state filters determine the exported rows; fields
use the same TSV columns, control characters are escaped, and exports larger
than 1 MiB are refused.

For selected AMD64 PE frames whose register snapshot contains an exact-width
`RSP`, the Locals table also shows source-backed FH3/FH4 C++ EH facts for the
current instruction: active cleanup actions, try-block catch candidates,
handler addresses, and the planner's dispatch classification. These rows describe metadata candidates;
the debugger does not call destructors or handlers. The live exception object
and its decorated type are not available from an ordinary stop, so typed catch
matching is shown as unknown/ambiguous. Frames without a readable `RSP`, and
other PE architectures, do not receive these rows. The planner uses the
selected frame's current `RSP` as its frame base; the caller CFA shown for that
frame is not substituted.

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
`qXfer:threads:read` supplies XML thread names, running/stopped/exited state,
and an optional numeric processor core. When reported, the core number appears
in the thread list; legacy thread enumeration and targets that omit the
attribute leave it blank. Malformed core values reject the XML snapshot.
The backend validates the XML document, rejects malformed or duplicate thread
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

The **Remote monitor** tab sends GDB `qRcmd` commands while a stop event is
pending. Commands are bounded to 4,096 printable bytes and encoded as required
by RSP; the UI runs them on the inspection worker and drops results if the
session or stop changes. Captured output is capped at 1 MiB in the API and
64 KiB in the display. The target stub defines which monitor commands exist.

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
context actions. An empty or unavailable snapshot during a live session retains
the last usable rows; a process-exit refresh may clear them when no retained
thread states remain.
Selecting a row updates the summary below the thread list with the selected
thread's name, hexadecimal ID, state, optional core, and whether it owns the
pending stop. This keeps the active inspection context visible while reviewing
the corresponding register snapshot.
The thread table also retains each thread's latest event kind and event code.
Use the **Latest event** sort choice to bring the most recently reported event
to the top, or include event text in the thread filter. **Copy selected** and
**Copy visible** include this column in their TSV snapshots. Event context is
historical: continuing a thread does not erase its last event, and a later
event replaces it. The desktop retains at most 4,096 thread summaries and clears
them when the debugger inspection is reset. Events without a thread ID and
debug-output notifications are not assigned to a thread.
Right-clicking a known thread exposes Continue, Step, and Stop when a pending
event and authoritative state snapshot are available. Continuing or stepping a
thread other than the event owner sends an atomic schedule that keeps the event
owner stopped. Stopping another running thread must consume the pending event,
so the UI labels that action to make clear that it also resumes the event owner.
The operation is rejected if the remote did not advertise a required `vCont`
action (for example, thread stop `t`); failed schedules leave the event pending.
For negotiated RSP non-stop sessions, the same menu also offers **Interrupt
thread** for an exact known-running thread when the peer advertises `vCont;t`.
This sends a thread-only stop request without resuming or stopping its peers;
the run-state snapshot remains unchanged until the matching signal-zero stop
reply arrives. Linux AArch64 also offers the action for one known-running,
session-owned `PTRACE_SEIZE` thread. Its matching `PTRACE_EVENT_STOP` becomes
the one pending event while other threads remain running; **Continue** resumes
that event owner and leaves peers alone. Memory and target-wide mutations still
require all threads stopped. Linux x86-64 and AArch64 offer this native action
for one known-running, session-owned seized thread; other native all-stop
sessions do not. The session API rejects it while another event awaits
acknowledgement.
The thread heading also has a **Run stopped peers** action. When the fresh
run-state snapshot for the current event confirms that its owner is stopped,
the action sends one bounded schedule that keeps the owner stopped and
continues every other known-stopped thread. Running, exited, and unknown-state
threads are omitted; a new event, target change, or stale snapshot disables the
action until refreshed. A backend that cannot atomically schedule the set
returns its error without consuming the pending event. Remote stops with a
pending signal may also reject a schedule that keeps the owner stopped, because
RSP cannot preserve a signal on its thread-stop action.
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

The register list's **Change** column compares each successful read with the
previous successful snapshot when it belongs to the same selected thread. It
shows `Baseline` on the first read for a thread, then `Same` or `Changed` for
matching register number/name/bank identities; newly reported registers show
`New`. A read error leaves the previous snapshot intact. Switching to another
thread establishes that thread's baseline, and resetting or changing the debug
session clears the comparison snapshot.

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
The Watches table's **Change** column compares each completed result with the
previous completed evaluation for the same thread and unchanged watch list. It
shows **Baseline** on the first evaluation, **Same** or **Changed** for successful
values, and **Error** when evaluation fails. Switching threads, editing or
reordering watches, changing the inspected document, or resetting the target
starts a new baseline; change labels are not persisted.

## Copy debugger output

On Windows, `OutputDebugStringA/W` events read at most 1 KiB of ANSI data or
2 KiB of UTF-16 data from the stopped target. The backend uses
`WaitForDebugEventEx` when available so the system can deliver Unicode output;
older systems fall back to `WaitForDebugEvent`. Unicode strings are converted from UTF-16 to UTF-8;
non-ASCII bytes in ANSI strings are escaped because the target code page is not
declared. The event's `nDebugStringLength` field exposes only its lower 16 bits,
so a zero length cannot distinguish an empty string from a length that wrapped;
HexLab reports that content as unavailable. Output read errors and truncation
are visible in the event message. These are acknowledged Windows debug events,
so use **Continue** to release the target after reviewing the text. See the
[Windows debug-string event structure](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-output_debug_string_info).

The **Follow new output** option is enabled by default. Turn it off to keep the
current insertion point and selection in place as new messages arrive; turn it
back on to follow the newest message. If the output cap trims older text, the
view adjusts the saved position to the retained text.

The **Debugger output** heading has a **Copy output** action that places the
currently displayed output text on the system clipboard. Empty output is
reported without opening the clipboard. Copying is limited to 1 MiB of UTF-8
text; larger output remains available in the pane and is not truncated into a
partial clipboard result. The action copies the pane contents as displayed and
does not clear or otherwise change the log.

The adjacent **Clear** action removes the current pane text immediately. It
does not clear backend state, pending events, breakpoint counts, or saved
project data; subsequent debugger messages start filling the empty pane again.

**Copy matches** uses the output search query and **Match case** setting to
copy only retained lines containing the query. Matching is ASCII case-insensitive
unless **Match case** is enabled. The action copies complete lines, reports when
there are no matches, and refuses a result larger than 1 MiB instead of copying
a truncated subset. It does not move the current search selection or alter the
output pane.

Use **Match case** beside the output search field to make the next and previous
searches case-sensitive. With it off, matching ignores ASCII letter case. The
setting applies to the retained output text and resets the search position when
changed.

## Process picker filter

The process picker filter matches a substring of the decimal process ID, name,
or reported architecture, without ASCII case sensitivity. Process choices show
the architecture label in brackets; unknown metadata is shown as `unknown`.
The count below it shows visible and total process counts. Refresh retains the
active or previously selected process when it still matches. Attach and remote
secondary-process detach use the visible selection; the PID field remains
available for manual entry. The filter and sort choice are local to the open
debugger pane and are not persisted.

Choose **PID order**, **Name order**, or **Architecture order** beside the
filter to sort the visible processes. PID order is numeric ascending; name
order compares names without ASCII case; architecture order compares the
displayed architecture labels without ASCII case and puts unknown architectures
last. PID breaks ties in name and architecture order. Changing the order retains
the selected process when it is still visible.

Press **Enter** in the PID field to attach to the entered process ID. It uses
the same decimal/hex validation and local-versus-remote attach behavior as the
**Attach** button.

## Copy inspected stack frames

The **Copy frames** action beside the frame selector copies the current stopped
thread's inspected caller chain, including runtime PCs, available symbols, and
recovered call-frame addresses. It requires a fresh inspection for the current
stop and document. The chain is bounded by the existing unwinder limit of 64
frames, may be shorter when unwind metadata or memory is unavailable, and is
capped at 64 KiB for clipboard transfer. This is a snapshot of recovered frames,
not a promise of a complete native stack trace.

The adjacent **Frame registers** tab shows the register snapshot captured for
the selected unwind frame, including its runtime PC and available CFA. Selecting
another frame refreshes the view from the same bounded unwind path. The live
frame shows the stopped thread snapshot; caller frames show only values the
unwinder recovered, so omitted registers are unknown rather than zero. The table
is read-only, capped at 1,024 rows, 512 bytes per value, and 1 MiB of display
data, and it is cleared when the stop, thread, session, or inspected document
changes.

Choose **32 Ki chars**, **128 Ki chars**, or **1 Mi chars** from the output
pane's **Retain** menu; 32 Ki chars is the default. Changing the limit applies
it immediately. When output crosses the selected cap, oldest complete lines
are removed and a marker is added at the start. If one message is longer than
the retained window, its leading text may be trimmed to keep the most recent
portion. The setting is local to the open debugger pane and is not persisted.
Changing it also resets the output-search position.
Choose **Save output** to write the retained pane text as UTF-8 through a file
picker. It does not query the target again and refuses exports larger than
4 MiB; text trimmed earlier by the retention cap is not included.

## Inspect a local value as a target address

Select a row in the locals table and choose **Inspect address** to read target
memory beginning at its displayed value. The action accepts only a plain decimal
or `0x`-prefixed unsigned value and requires a stopped target. It treats the
value as an address by explicit user request; the debugger does not infer
pointer types or evaluate richer local expressions. The normal memory pane
limits, target permissions, and read-failure reporting apply.
Choose **Inspect CFA** beside the frame selector to read a memory page beginning
at the selected frame's call frame address. The action requires the current
stopped-frame snapshot and an available CFA; it navigates the Memory tab through
the normal bounded read path. CFA values may be absent or unreadable for a
particular backend or frame, in which case the action reports the limitation or
the memory-read error.
Choose **Copy locals** to export the currently displayed frame's local rows as
TSV with frame PC, name, kind, scope/origin, location, and value columns. It
copies the existing stopped snapshot without another target query; tabs and
line breaks in cells are escaped, and payloads over 1 MiB are refused.

To edit an existing watch, select its row, change the expression field, and
choose **Update selected**. Selection loads the expression into the field. The
update keeps the row in place, rejects duplicates elsewhere in the list, saves
the replacement with the project's watch settings, and refreshes its value.

## Search one memory region

Select a readable row in the Memory regions table and choose **Search region**
to copy its start and length into the bounded memory-search range, switch to
Search, and run the current byte pattern. This resets the search region filter
to all readable regions while the exact range constrains the scan. The chosen
pattern and alignment are retained. Unreadable, empty, or wrapping regions are
rejected; normal search byte, comparison, result, and cancellation limits apply.

Use the **Find in debugger output** field with **Next** or **Previous** to search
the currently retained pane text. Matching is ASCII case-insensitive, the match
is selected and brought into view, and searches wrap at either end. Search is
limited to the latest text retained by the output cap; older trimmed messages
cannot be found.

## Copy OS data as TSV

The OS data tab has a **Copy TSV** action after a successful table read. It
exports one row per table row and column, with `Row`, `Name`, and `Value` fields;
embedded tabs and line breaks are escaped. Complete exports are limited to 4 MiB.
If a table exceeds that limit, the on-screen bounded rendering remains available
but clipboard export is disabled rather than returning a partial table. A new
read or target reset invalidates the prior export.

The **Signal info** tab reads bytes for the current pending stop event through
`DebugSession::signal_info()`. **Read current event** runs on the serialized
inspection worker and discards results after the session, pending event, or
selected display format changes. The view identifies the event sequence,
thread, architecture, and event code, then shows bounded bytes with offsets,
hex, and ASCII columns. The default is raw. Optional Linux 32-bit and 64-bit
modes decode only the fixed `si_signo`, `si_errno`, and `si_code` integers after
explicit user selection; remote byte order must be declared by the target
description, and local decoding uses host byte order. The signal-specific union
remains raw. Do not select a Linux mode for a non-Linux target or an ABI with a
different `siginfo_t` layout. Targets or stop types without a readable record
show an explicit unsupported state; read errors remain visible in the status
and byte pane.

Use the **Find in displayed OS data** field with **Next** or **Previous** to
locate text in the current on-screen rendering. Matching ignores ASCII case by
default; **Match case** enables case-sensitive matching. Searches wrap at the
ends and use only the displayed text, which is capped at 4 MiB. Queries are
limited to 2,048 characters. Editing the query or changing case resets the
search position; a new read or target reset clears the query and position, and
a target reset restores case-insensitive matching.

## Active target identity

The Debugger summary shows the active target process name and ID beside its
run state and last event. The value refreshes with debugger state changes and
clears when there is no active process. It identifies the process currently
controlled by the session; it does not enumerate secondary remote processes.

In the Memory tab, press **Enter** in the address field to read from that
address using the currently selected page size. It runs the same validation
and target-memory request as the **Read** button.

## Copy the auxiliary vector

The Auxv tab's **Copy TSV** action exports the displayed Linux auxiliary-vector
entries as decimal type IDs and hexadecimal values. Complete clipboard exports
are limited to 4 MiB. If the table exceeds the limit, the full on-screen table
remains available while copying is disabled rather than returning a partial
export. Refreshing the table or resetting the target invalidates the prior copy.
Use the Auxv filter to match a substring of the decimal type ID or hexadecimal
value, ignoring ASCII case. The table labels common generic Linux entries with
their `AT_*` name alongside the numeric ID; unknown or architecture-specific IDs
remain numeric. Filtering also matches the displayed symbolic name. **Copy TSV**
continues to export decimal IDs and hexadecimal values for the full vector. The
filter clears on refresh or target reset and is limited to 2,048 characters.
Choose **Copy visible** to export only the rows currently shown by that filter,
in their displayed order and with the same decimal type and hexadecimal value
columns. The export is capped at 4 MiB and refuses oversized results rather
than truncating them.

## Memory address history

The Memory tab's **Back** and **Forward** actions revisit valid addresses
previously submitted to the memory pane, including addresses opened from a
region, local, or search result. Consecutive duplicate addresses are skipped;
new navigation after going back discards the forward branch. History is kept in
memory for the current debugger inspection, capped at 64 addresses, and cleared
when the inspection is reset. Failed reads may still appear because history
records the requested address, not read success.
Choose an address from the history menu to jump directly to that entry; the
selected entry stays synchronized with Back and Forward navigation.

## Write UTF-8 text to memory

The Memory pane's **UTF-8 text** option interprets the write field as literal
UTF-8 text instead of hexadecimal byte pairs. It writes the encoded bytes
without adding a NUL terminator. The encoded text is limited to 1,024 bytes and
must fit within the selected memory page; address overflow and backend write
errors use the same checks and reporting as hexadecimal writes. The option is
not persisted.

In the Registers pane, select a supported register and choose **Watch selected**
to add its name as an expression and open the Watches tab. The action requires
a stopped target and an available register no wider than 64 bits. Existing watch
limits, duplicate checks, project persistence, and evaluation behavior apply.

On Linux AArch64, active SME streaming-vector registers (`ssve_zN`, `ssve_pN`,
`ssve_ffr`, `ssve_fpsr`, and `ssve_fpcr`) can be edited while the thread is
stopped. Writes use the kernel's `NT_ARM_SSVE` regset and require the exact
vector-length-derived width shown for each register. The debugger rejects mixed
streaming and ordinary register writes, inactive streaming state, unknown
streaming names, stale regset metadata, and unsupported kernel regset writes.
SME matrix state (`za_*`, `zt0`) and streaming-mode controls remain read-only.

In the Memory tab, **Watch byte** creates a `mem8(address)` watch at the current
address and opens the Watches tab. The target must be stopped. The expression
uses the existing watch limits, duplicate handling, persistence, and evaluation
rules; change `mem8` to another supported width in the Watches editor when a
wider read is needed.

The Watches tab's value-format menu displays successful `0x` scalar results as
hexadecimal, unsigned decimal, or signed decimal. Signed decimal interprets the
64-bit result as a two's-complement value; this changes display only and does not
change expression evaluation. Error/status rows and persisted watches are
unchanged. The display choice is saved per project and restored when that
project is selected; projects without a saved choice use hexadecimal.

Select a row in Watches and choose **Copy selected** to copy its expression and
currently displayed value as a tab-separated pair. This copies the visible
snapshot, including an error/status value when present; it does not reevaluate
the expression or read target memory.

Use **Move up** and **Move down** to reorder a selected watch in the list. The
new order is saved with the project's watch expressions and is used on the next
refresh; moving a row keeps its currently displayed value with that expression.
The first row cannot move up and the last row cannot move down.
