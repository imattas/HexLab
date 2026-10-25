# Native thread resume schedules

`DebugSession::resume_threads(sequence, actions)` uses the current owned stop
event and exact thread IDs from that session. Each action requests continue,
one instruction step, or remaining stopped. A plan contains at most 4,096 unique,
nonzero IDs and must run at least one thread. Omitted threads are not newly
resumed. Native all-stop backends require the pending event owner in the plan,
including a stop action when another thread runs. The session becomes running
only after backend acceptance; notification-only acknowledgements preserve the
stopped state and continue draining queued events.

The [RSP server](../../../docs/debug-server.md) resolves `vCont` left to right
against a bounded live-thread census. Every unmatched live thread receives a
stop action. Selector `0` chooses the event thread; omitted selectors and `-1`
match all live threads. An all-continue result retains the existing process-wide
continue path. Other schedules reach the shared API intact. The server still
accepts only `c`/`s` actions, uses all-stop replies, and does not negotiate
multiprocess, non-stop, signal-delivery, range-step or explicit `t` packets.
These selector rules follow the [GDB packet specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).

## Supported native subsets

| Backend | Supported filtered schedule | Explicit restrictions |
| --- | --- | --- |
| Linux x86/x64 | One selected thread continues or steps; multiple selected threads may continue while others stay stopped. The event owner can remain stopped when another thread runs. | Every traced thread must be stopped. Deferred-event owners cannot be rescheduled. A pending software-breakpoint step-over limits runnable selection; multi-thread continue through that breakpoint is rejected. Mixed step/continue and multiple steps remain unsupported. |
| Linux AArch64 | One selected thread continues or steps; multiple selected threads may continue. The event owner can remain stopped when another thread runs. | All-thread-stop, hardware configuration, deferred-event and pending-step checks remain active. Pending software/hardware execute-breakpoint step-over limits selection; mixtures and multiple steps remain unsupported. |
| Windows | The event thread steps alone, or a continue-only subset including the event owner runs. Unselected peers retain one debugger-owned suspend count. | Foreign-thread steps, a held event owner with other runnable threads, mixed step/continue, multiple steps and an active displaced software-breakpoint step reject. ARM32 stepping remains unsupported. A Windows ARM64 execute-breakpoint step-over cannot run a multi-thread subset. |
| Darwin | One exact continue or step action for a target proven to contain one thread. | Process-wide ptrace cannot implement multithread schedules; the existing Mach-thread census and stop-identity restrictions remain conservative. |

The Linux resume mechanisms predate this server integration. Explicit stop
actions now preserve deferred-event owners instead of rejecting an otherwise
safe schedule; trying to run those owners still fails. Backend feature/action
availability does not imply support for every possible schedule combination.

## Windows suspension ownership

Windows freezes the affected process while a debug event is pending. The backend
enumerates all target threads with a 4,096-thread cap and requires a complete
Toolhelp enumeration. Before acknowledging a filtered continuation, it opens
handles for every unselected peer and acquires exactly one extra suspend count
per peer. Failure rolls back acquired counts; failed rollback counts and handles
remain owned for cleanup retry. It never resets or drains suspend counts owned
by the application or another tool. Selected threads keep any independent
application-owned suspension, so acceptance does not promise they will execute.

`ContinueDebugEvent` releases the pending debug stop while unselected peers stay
held. At the next debug event, the process is frozen again before the owned
counts are released. Global continue, detach, termination and handle cleanup use
the same ownership bookkeeping. Per-thread run snapshots report held peers as
stopped; outside a pending event they leave other threads unknown rather than
guessing about unrelated suspend counts. These mechanics use the documented
[Windows debugging-event suspension rules](https://learn.microsoft.com/windows/win32/debug/debugging-events)
and [ContinueDebugEvent](https://learn.microsoft.com/windows/win32/api/debugapi/nf-debugapi-continuedebugevent).

## Breakpoint filtering and failures

Ignored hits, false breakpoint conditions and logpoints reuse the accepted
thread continuation filter. They cannot turn a selected-thread run into global
continue. If the filter cannot be reapplied, the owned breakpoint stop is
returned with a diagnostic and remains available for an explicit scheduling
decision. A breakpoint reached by a user step remains visible even if it would
otherwise be suppressed; repeating the step could execute an extra instruction.

Syntax, identity and unsupported-shape rejections do not consume the pending
event. OS failures can still occur after a native thread has run. Linux attempts
to stop threads already released; Windows retains failed suspension cleanup for
retry while the debug event remains owned. Neither can undo instructions already
executed. This is one validated scheduling operation, not processor-atomic
execution. No rejected filtered schedule is retried as a global continuation.

This increment was reviewed from source only. No builds, tests or live debugging
were run. Follow up with serial debugger/server compilation on Windows x64 and
the architecture-specific native builds, then live multithread validation.
