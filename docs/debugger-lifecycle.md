# Native debugger process lifecycle

`DebugSession::processes` provides read-only process discovery before attaching.
On Windows the native backend takes a Toolhelp process snapshot, returns at
most `max_inspection_processes` (4096) entries, converts executable names to
UTF-8, and reports architecture as unknown when the process cannot be queried.
On Linux x86-64 it enumerates numeric `/proc` entries, reads the process name
and ELF architecture where available, and omits processes that disappear during
inspection. The session rejects oversized results from any backend. Process
enumeration does not attach to or modify any listed process. macOS uses a
Mach/ptrace backend with process-wide stopped snapshots and single-thread
execution restrictions described in
[Darwin debugger scope](debugger-darwin.md). Other native platforms return
`unsupported` and can use the remote GDB RSP backend where a server is available.

On Windows, `DebugSession::launch` starts the target with
`DEBUG_ONLY_THIS_PROCESS`; `DebugSession::attach` uses `DebugActiveProcess` for
an existing process. Both paths return before the initial debug events have
been consumed. Call `wait_event` to receive each event, inspect the stopped
thread as needed, and acknowledge that exact sequence with `continue_execution`
or `single_step_execution`. A process-exit event is terminal and must also be
acknowledged before detaching the session object.

`continue_thread_execution` is supported for Windows debug events when the
selected thread owns that exact pending event. The backend validates both the
event sequence and thread ID before using the normal Windows event-acknowledge
path, so peer-suspension recovery, event-handle cleanup, and exit handling stay
consistent with `continue_execution`. A process-exit event has no resumable
thread and must use the ordinary event acknowledgement operation.

The Win32 backend closes the process, thread, and image-file handles supplied
with create-process, create-thread, and load-DLL events only after
`ContinueDebugEvent` succeeds. Detach from either a launched or attached target
restores debugger-owned software breakpoint bytes while a pending event still
holds the target stopped. If no event is pending, it requests a break and waits
for the resulting debug event before cleanup. It clears debugger-owned hardware
breakpoint state, acknowledges the event, then calls
`DebugActiveProcessStop`. Detach ends the debugging relationship and releases
the backend's process handle; it does not terminate a launched target. If event
continuation, breakpoint restoration, hardware-state cleanup, or detachment
fails, the error is returned and the backend keeps its remaining target state
for a retry. The Windows integration test requests a stop from a running child
and observes the resulting breakpoint event. That behavior remains subject to
Windows configuration and process policy. An already-exited target is
recognized through its process handle and cleaned up without another stop
request.

On Windows, `DebugSession::terminate()` works for launched and attached targets
when the process handle grants termination access. It requests process
termination, acknowledges any current debug event, then drains and acknowledges
target events through `EXIT_PROCESS_DEBUG_EVENT` before releasing the process
handle and event-owned handles. The wait is bounded to five seconds per call;
if Windows does not deliver the exit event in that interval, the call reports a
timeout and retains backend state so termination can be retried. Attaching to a
process without terminate rights still permits inspection and detach but cannot
terminate it.

Win32 memory writes are limited to 1 MiB and stage the original target bytes
before applying the edit. If a write overlaps debugger-owned software
breakpoints, the `INT3` bytes stay installed and the edited bytes become the
new saved originals restored when those breakpoints are removed or the session
detaches. A failed or short write attempts to restore the staged original
range; the error reports when that rollback also fails. Hardware breakpoints
do not alter target memory.

On Linux x86-64, native launch holds the child behind a close-on-exec socketpair
until the parent has attached with `PTRACE_SEIZE`. The backend enables exec and
clone events before releasing the child, then waits for the exec event before
publishing the session. This makes launched targets interruptible using the
same seized-thread mechanism as attached targets. If setup fails or `exec`
cannot start the requested image, launch kills and reaps the child and leaves
the backend available for another launch. `request_interrupt` interrupts all
currently running traced threads; each resulting stop is reported and must be
acknowledged with its own event sequence. New threads are tracked as seized
through clone events and remain covered by later process-wide interrupt
requests.

Windows integration coverage exercises launch through exit, launched-target
detach from a pending event with owned breakpoints and target survival,
stopped-thread register reads, repeated event-handle cleanup, attach,
pending-event detach, target resumption, reattach, pending process-exit cleanup,
and the existing single-step path. Linux integration coverage exercises launch,
exec failure cleanup, asynchronous interruption of a launched process, and
detach with target survival. Other non-Windows native backends remain explicitly
unsupported.

The Linux lifecycle regression is platform-gated and requires Linux x86-64
with ptrace permission. A Windows build can check shared debugger APIs and
desktop integration, but it does not compile or execute the Linux ptrace
backend; runtime validation must be performed on Linux.

For GDB Remote Serial Protocol sessions, detach clears the session only after
the target replies `OK` to `D`. An empty response means the peer does not
support detach; the error is returned and the session remains connected so the
caller can choose another cleanup path or retry.
