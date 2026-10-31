# Debugger stepping

`DebugSession::single_step_execution` resumes the thread that raised the pending
debug event with the processor trap flag set. The next event is returned as a
normal stopped event and must be explicitly continued, matching the session's
event-sequence contract.

The desktop Debugger view exposes this operation as **Step** beside Continue.
It requires a pending stop event, resumes one instruction, and restarts the
event poller so the next stop refreshes thread/register state and locals. The
**Step** is instruction-level. **Step over** first tries to stop at the next
distinct source line within the same complete recovered function. It scans at
most 16,384 instruction facts and performs at most 256 source-location
lookups, requires unambiguous source locations and a fresh loaded-image
mapping, and plants a one-shot software breakpoint at the next line. Functions
with incomplete recovery, ambiguous or missing line
records, or no later line use the instruction-level behavior: for a decoded
call at the stopped PC it plants a one-shot breakpoint at the fall-through
instruction; other or unavailable instruction facts perform one instruction
step. A source-line or call-return breakpoint requires a free address with no
existing breakpoint. A scan that reaches either bound reports the limit and
leaves the target stopped. Any intervening stop, thread change, or process
change cancels the temporary run. Step-over continues only the thread that
owns the pending event, leaving peers stopped. The Debugger view also offers a
conservative source-level **Step out** operation, described below.

## Source step-out

Source step-out uses the current stopped thread's recovered stack frames. It
requires fresh frames for the pending event, an identifiable event-owning
thread, and a caller frame whose return PC belongs to the same currently loaded
module as the stopped PC. Both PCs must resolve to unambiguous source-line
records in that image, and the caller return PC must be in initialized
executable data and round-trip through the module mapping. The current module
mapping is refreshed and must match the mapping used to recover those frames.

When these conditions hold, the desktop view places a one-shot session
breakpoint at the caller return PC and continues the pending event. It removes
the temporary breakpoint on the next target stop and reports whether the
caller return address was reached. A stop in another thread, any intervening
stop, process exit, or module/process change cancels the operation. The user
can cancel it by removing the temporary breakpoint from the breakpoint list.
The target is bound to the process, thread, source document identity and
revision observed when the operation starts; the UI reports if the source
document changes while execution continues.

The implementation does not guess when frames are stale or unavailable,
source-line records are absent or ambiguous, the caller crosses into another
module, an existing breakpoint occupies the return address, or the target
architecture is outside the recovered x86/x64/AArch64 frame path. In those
cases it reports why source step-out cannot proceed.

On Windows, when the pending event is an `INT3` at a software breakpoint owned
by the backend, stepping temporarily restores the byte saved when that
breakpoint was installed. Windows reports the instruction pointer just after
`INT3`; the backend rewinds it to the breakpoint address, performs one
instruction, then reinstalls `INT3` when that thread next raises a debug event.
Unowned breakpoints, including the process's initial loader breakpoint, are
passed through without rewinding.

For Windows x86/x64 owned-breakpoint steps, setup captures the original RIP/EIP
before rewinding. If later flag access, trap-flag setup, step-state setup,
peer suspension, or `ContinueDebugEvent` fails, rollback restores the captured
instruction pointer together with `INT3` and any changed flags. The original
event remains pending. This keeps a successful rollback retryable from the
same post-`INT3` context; reinstalling the trap while leaving RIP/EIP rewound
would otherwise make the next step re-enter the trap. If register, memory, or
suspension rollback also fails, the error includes those failures and does not
claim that the target state was restored. Windows x64 Debug compilation covers
this path; failure-injection and live WOW64 validation remain pending.

The displaced-step protocol is isolated in a platform-neutral state helper and
covered by deterministic tests for IP matching, single outstanding step,
thread matching, retry after a failed rearm, and teardown clearing. A Win32
child-process integration test stops on an owned software breakpoint, steps
the displaced instruction, and checks that `INT3` was reinserted before the
target resumes. The backend clears that state on process exit and handle
teardown.

The Win32 implementation supports software execute breakpoints and x86/x64
register contexts. On an ARM64 build it also reports the target architecture
using `IsWow64Process2`, reads and writes the native `x0`–`x30`, `sp`, `pc`,
and `cpsr` context fields, and installs aligned four-byte software breakpoints
using `BRK #0xF000` (the instruction emitted by MSVC `__debugbreak`). ARM64
processor breakpoints and single-step are explicitly unsupported: the current
backend's trap-flag protocol uses x86 `EFLAGS.TF`, which has no ARM64 equivalent
in the Win32 context interface used here. A non-ARM64 debugger build can still
identify an ARM64 process, but returns `unsupported` when asked to read or edit
its ARM64 register context.

For each supported single-step operation it adds one suspend count to
every other live target thread before resuming the event thread. When the next
debug event arrives, those counts are released before the event is returned to
the session. A thread created during the step is stopped by its own create
thread debug event before it can run; the step's peer-thread handles are
released as that event is processed.

If acquiring a peer suspension fails, earlier acquisitions are rolled back. A
failed rollback or release keeps the affected thread handles so the backend can
retry before acknowledging an event or detaching. The event message reports a
release failure, and continuing that event returns the retry error while keeping
the event pending. This cannot make OS thread suspension atomic, and a failed
Windows resume operation can leave a peer suspended until a later retry or
backend teardown. Source-level step-over and hardware/data breakpoint
step-over are not implemented by this operation.

Over GDB Remote Serial Protocol, the backend checks `vContSupported` and then
queries `vCont?` for the actions the stub actually implements. It uses
`vCont;c` only when the unqualified `c` action is listed; otherwise it falls
back to legacy `c`. A stop reply that identifies its thread with `thread:<id>`
is single-stepped using `vCont;s:<id>` only when the stub lists a
thread-qualified step action; the original ID spelling is preserved, including
multiprocess IDs such as `p1.2`. An unqualified `vCont;s` applies to every
thread, so it is not used for a single-step request. Legacy `s` is used only
when the stop reply has no exact thread ID; it steps the stub-selected current
thread. If the stop names a thread but the stub does not advertise
thread-qualified step, the backend returns unsupported instead of risking a
step on the wrong thread.
This avoids stepping every thread and avoids treating the presence of the
`vCont` packet as proof that every action is supported. The RSP backend retains
the signal number from the pending stop. The default `handled` disposition
suppresses that signal; `not_handled` uses `Sxx` when the peer advertises the
signal-bearing action, or legacy `Sxx` when the single-process resume path can
target the stopped thread. A rejected or unsupported resume leaves the stop
available for retry. `DebugSession::resume_threads` also sends an exact mixed
per-thread `vCont` schedule, and can preserve/redeliver or suppress the pending
signal on its owning thread. The schedule requires the peer to advertise the
needed `c`, `s`, `t`, `C`, or `S` action, and never applies a signal
disposition to a different thread. HexLab exposes one current stop event at a
time, even when the remote is in non-stop mode.
