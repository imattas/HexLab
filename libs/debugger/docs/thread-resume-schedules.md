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
stop action. Explicit `t` actions also reach the shared API as stop actions,
and prevent later matching actions from resuming that thread. Selector `0`
chooses the event thread; omitted selectors and `-1` match all live threads.
For example, `vCont;t:TID;c` holds that thread and continues its peers, while
`vCont;c:TID;t` continues only that thread. An all-continue result retains the
existing process-wide continue path. Other schedules reach the shared API
intact, including an explicit stop for the pending event owner when selected.
The all-stop server accepts `c`/`s`/`t` and advertises `t` in `vCont?`; a
stop-only result returns `E01` without consuming the event because the shared
API requires at least one runnable thread. No new stop notification is needed
for a thread already stopped. The server does not negotiate multiprocess,
non-stop or range-step packets. Signal actions `C`/`S` are advertised only when
the backend supports scheduled signal disposition.
These selector rules follow the [GDB packet specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html).

## Remote thread lifecycle events

During RSP connection setup, HexLab requests `QThreadEvents:1` when the stub
advertises `QThreadEvents+`. A successful negotiation lets the backend receive
thread-created and thread-exited stop replies as they occur, instead of
discovering changes only when the user refreshes the thread list. The normal
owned-event sequence still applies: the event is surfaced to the desktop and
must be explicitly continued or scheduled. Stubs that do not advertise or
accept this optional feature continue to use thread-list refreshes and do not
fail connection setup. Malformed or transport-level negotiation failures do
fail setup so a broken RSP exchange is not silently treated as a capability
decline.

The outbound RSP backend uses exact `t:TID` or `t:pPID.TID` wire actions in
mixed schedules only when the peer advertises `t`. Process-qualified IDs retain
both components and must belong to the selected inferior. A stop action cannot
preserve or disposition a pending nonzero remote stop signal; that schedule
fails before transmission. Syntax, identity, and unsupported-action errors
retain the owned event, with no retry as an unfiltered continuation.

## Supported native subsets

| Backend | Supported filtered schedule | Explicit restrictions |
| --- | --- | --- |
| Linux x86/x64 | One selected thread continues or steps; multiple selected threads may continue while others stay stopped. One schedule may single-step the pending event owner while other selected threads continue, or step one non-owner while the event owner remains stopped and other peers continue. | Every traced thread must be stopped. Deferred-event owners cannot be rescheduled. A pending software-breakpoint step-over limits runnable selection; multi-thread schedules through that breakpoint are rejected. Mixed schedules support at most one step; multiple steps remain unsupported. |
| Linux AArch64 | One selected thread continues or steps; a multi-thread schedule may combine one single-step action with any number of continue actions. The event owner can remain stopped when another thread runs. A scheduled action may preserve/redeliver its queued signal by default or suppress it with `signal_disposition = handled`; `not_handled` explicitly requests redelivery. | Every traced thread must be stopped. At most one single-step may be outstanding; a later schedule cannot resume that step thread or issue another step until its event is collected. Pending software/hardware execute-breakpoint step-over still limits the schedule to one runnable thread. |
| Windows | The event thread steps alone, or a continue-only subset including the event owner runs. Unselected peers retain one debugger-owned suspend count. | Foreign-thread steps, a held event owner with other runnable threads, mixed step/continue, multiple steps and an active displaced software-breakpoint step reject. ARM32 stepping remains unsupported. A Windows ARM64 execute-breakpoint step-over cannot run a multi-thread subset. |
| Darwin | One exact continue or step action for a target proven to contain one thread. | Process-wide ptrace cannot implement multithread schedules; the existing Mach-thread census and stop-identity restrictions remain conservative. |

The Linux x86-64 mixed schedule issues peer continuations first, the pending
event owner last among continuations, and the single-step last. A non-owner
step is accepted only when the event owner has an explicit stop action; this
keeps the original event available if the final step request fails. If a
continuation or final step request fails, already continued peers are
interrupted and collected before the owned event is returned for retry. A
failed rollback blocks further resume until recovery. Continuing the event
owner before a non-owner step is rejected because that would consume the owned
event before the step can be accepted.

The Linux resume mechanisms predate this server integration. Explicit stop
actions now preserve deferred-event owners instead of rejecting an otherwise
safe schedule; trying to run those owners still fails. Backend feature/action
availability does not imply support for every possible schedule combination.

Linux AArch64 may issue one `PTRACE_SINGLESTEP` alongside `PTRACE_CONT`
requests in a multi-thread schedule. Continuations run first, with the pending
event owner last among continuations, and the single-step request runs last.
This ordering means a later ptrace failure rolls back only continued threads;
the backend never has to roll back a step already issued. Multiple concurrent
single-step actions remain unsupported because the backend tracks one pending
step result at a time. A pending breakpoint displaced-instruction step-over
also remains restricted to a single runnable thread.

On Linux AArch64, a stopped action retains its pending signal for a later
resume; `handled` explicitly suppresses it. Continue and single-step actions
inject the retained signal unless `handled` is specified. Injecting a signal
while a software or hardware execute breakpoint is pending bypasses the
displaced-instruction step-over for that resume, leaving the breakpoint in
place for a later encounter after signal handling. Queued signals are removed
only after a successful resume or explicit suppression. This follows Linux
ptrace signal-delivery semantics: the signal is injected by the next restart
operation, and a zero signal suppresses it ([ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)).
The RSP server advertises `C`/`S` when this scheduled disposition is supported;
it accepts suppression or redelivery of the pending event owner's signal.

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

The explicit RSP stop-action integration was checked with a Windows x64 Debug
debugger/server build. No tests or live debugging were run. Architecture-specific
native builds and live multithread validation remain follow-up work.
