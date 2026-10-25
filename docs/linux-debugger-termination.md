# Linux debugger target termination

The Linux x86-64 ptrace backend implements `DebugSession::terminate()` for
launched and attached targets. It sends `SIGKILL` to the target process, resumes
threads held at ptrace stops so termination can proceed, and drains ptrace
thread-exit notifications before reporting success. Clone events encountered
while draining are followed so newly traced threads are reaped as well.

Termination waits up to ten seconds for the traced threads to exit. A wait or
ptrace error is returned to the caller; after a timeout or partial failure the
target remains marked as kill-requested in the kernel and the operation may be
retried. On success, the backend retains the known thread IDs as exited in
thread and run-state snapshots until `detach()` clears the session's target
bookkeeping. No breakpoint bytes are restored because the target address space
is being destroyed.

The operation uses `SIGKILL`; it does not provide graceful shutdown or a choice
of exit signal. Permission policy can reject termination of an attached target.
The operation is intentionally different from `detach()`, which restores
debugger-owned breakpoint state and lets an attached process continue.
