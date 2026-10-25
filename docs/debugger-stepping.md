# Debugger stepping

`DebugSession::single_step_execution` resumes the thread that raised the pending
debug event with the processor trap flag set. The next event is returned as a
normal stopped event and must be explicitly continued, matching the session's
event-sequence contract.

The desktop Debugger view exposes this operation as **Step** beside Continue.
It requires a pending stop event, resumes one instruction, and restarts the
event poller so the next stop refreshes thread/register state and locals. The
step is instruction-level; it does not perform source-level step-over or
step-out.

On Windows, when the pending event is an `INT3` at a software breakpoint owned
by the backend, stepping temporarily restores the byte saved when that
breakpoint was installed. Windows reports the instruction pointer just after
`INT3`; the backend rewinds it to the breakpoint address, performs one
instruction, then reinstalls `INT3` when that thread next raises a debug event.
Unowned breakpoints, including the process's initial loader breakpoint, are
passed through without rewinding.

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
backend teardown. Hardware/data breakpoints and source-level step-over are not
implemented.

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
`vCont` packet as proof that every action is supported. HexLab still models one
current stop at a time and does not enable non-stop mode or expose
target-specific thread scheduling controls.
