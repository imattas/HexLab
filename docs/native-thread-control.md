# Native debugger thread state and control

The thread pane combines the thread list with an explicit run-state snapshot.
Unknown states disable thread actions. Every action is tied to the currently
pending debug-event sequence; stale events, duplicate thread IDs, exited
threads, and threads not owned by the active session are rejected.

## Linux ptrace

The x86/x86-64 and AArch64 ptrace backends report the state they track for traced
threads and return `unknown` for visible but untraced tasks. While handling a
stop event, each backend can schedule one runnable thread at a time: continue,
single-step, or leave the thread stopped. Other threads remain ptrace-stopped
until a later event. Rejecting schedules with multiple runnable threads avoids
turning a requested schedule into a sequence of partially applied resumes.
Deferred real stop events must be handled through the event queue before that
thread can be resumed. A pending software-breakpoint owner cannot be left behind
while a different thread is scheduled, because the breakpoint displacement
state belongs to that event.

## Windows debug events

While a `DEBUG_EVENT` is pending, Windows holds the debuggee process threads;
the snapshot reports them as stopped. Outside a pending event, the backend
reports `unknown` because Windows does not provide a race-free query for
arbitrary target-owned suspension counts. The event owner can be continued or
single-stepped using the existing debug-event protocol. Peer schedules are
explicitly unsupported: `ContinueDebugEvent` resumes the process as a unit,
and the backend does not claim atomic peer-thread scheduling.

These snapshots describe debugger-observed states, not application-level
intent. Thread creation/exit can still race a thread-list refresh; an ID is
validated again by the backend immediately before applying a schedule.
