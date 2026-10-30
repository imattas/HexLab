# Win32 x86/x64 hardware breakpoints

`DebugSession::add_breakpoint(address, kind, size)` routes execute, write, and
access kinds to the Win32 DR0-DR7 implementation. Read-only watchpoint requests
are rejected because x86 debug registers cannot encode that condition. Software breakpoints keep
their existing INT3 path. Hardware requests are installed in local DR0-DR3
slots for every thread in the debuggee and applied to threads as their create
thread events arrive. Updates require a pending debug event, which keeps the
target stopped while contexts are changed.

Windows software breakpoint disable, re-enable, and removal, and Linux x86
software breakpoint disable, re-enable, and removal first compare the target
bytes with the exact bytes expected for the current owned state. Linux removal
also requires every traced thread to be stopped. If the
instruction bytes have changed since the breakpoint was installed, the
operation returns a conflict and leaves the patch and ownership record intact.
This prevents removal or a toggle from silently overwriting code that the
debuggee or another debugger modified. Adding a breakpoint still captures the
bytes that were present at installation time. The check is performed while the
target is stopped where the architecture requires it; it is not an atomic
memory compare-and-swap against another process writer.

The Linux x86-64/i386 path also verifies owned bytes before displaced-step
restore/rearm and before detach cleanup. Missing traps and changed original
instructions fail closed; rearm errors remain visible and block resume.
Detach preflights all software records and retains per-address restoration
progress for retry after a partial failure. Existing unowned `INT3` bytes
cannot be claimed by installation, and software records are capped at 4,096.
See [Linux breakpoint lifecycle](linux-ptrace-debugging.md) for retry behavior
and the remaining external-writer atomicity limit.

The desktop debugger exposes Software, Hardware execute, Hardware read,
Hardware write, and Hardware access choices beside the breakpoint address.
Selecting a data watchpoint enables the 1/2/4/8-byte length control; execute
and software breakpoints use a one-byte length. The breakpoint list shows the
kind and selected length so watchpoints remain distinguishable after creation.

There are four hardware slots per thread. Execute breakpoints require size 1.
Data lengths are 1, 2, or 4 bytes on x86 and 1, 2, 4, or 8 bytes on x64; the
address must be aligned to the selected length. DR7 encodes write-only with
RW=01 and read/write with RW=11. x86/x64 provides no read-only data condition,
so `BreakpointKind::read` is rejected instead of being silently encoded as
access and also stopping on writes.
This is a hardware encoding limitation, not a missing Windows access right or
an unvalidated read-watchpoint path. Supporting only reads would require a
separate instruction-access emulation/filtering design; a read/write hardware
slot cannot truthfully implement the current read-only request. Windows native
read requests continue to fail before target debug-register writes.
For `EXCEPTION_SINGLE_STEP`, the backend reads DR6 and maps its B0-B3 status
bits to the corresponding owned `BreakpointId` values in
`DebugEvent::breakpoint_ids`. An event with at least one owned slot hit is
reported as `EventKind::breakpoint`; a single-step trap with no owned hit
remains `EventKind::single_step`. The backend clears only DR6's B0-B3 bits so
the same status does not leak into a later event. If reading or clearing DR6
fails, the event is still returned and its message includes the diagnostic;
when the read fails, the event cannot identify the hit IDs.

Owned hardware breakpoints can be disabled and re-enabled through
`DebugSession::set_breakpoint_enabled`. The operation keeps the same breakpoint
ID and requested address/kind/size. Windows applies the new active slot set to
the stopped process threads transactionally; toggles require a pending debug
event. Linux x86-64 requires all traced threads stopped and transactionally
updates their debug registers. Remote RSP sends `z`/`Z` for the exact owned
tuple. Backends that do not implement hardware toggles return `unsupported`.

The backend rejects a thread whose DR0-DR3 slot configuration differs from the
debugger-owned configuration. It preserves DR7 control bits outside the slot
enable and RW/LEN fields, and it preserves address registers for slots this
debugger does not own. A slot must be clear before the debugger first claims
it; after a request is removed, its address register returns to zero. A newly
created thread may either inherit the exact debugger configuration or arrive
with clear registers, in which case the current requests are installed. The
backend does not virtualize preexisting active debug-register users, and an
unknown machine context is rejected rather than treated as x64.

Add, remove, and detach update all currently enumerated thread contexts
transactionally: if a context update fails, earlier successful updates are
restored in reverse order, and owned requests change only after the whole
update succeeds. The platform-neutral transaction test injects a failure after
one successful update and verifies restoration.

Rollback still depends on Windows accepting the restoring `SetThreadContext`
call. If the operating system or a thread-state race rejects that rollback,
the operation returns the original update error with the rollback failure
appended, but the threads may then hold mixed state; the backend cannot make
several OS thread-context writes truly atomic. Threads created after the
snapshot receive the currently owned configuration from their create-thread
event. The deterministic encoder tests cover DR7 enable/RW/LEN fields,
four-slot capacity, alignment, and x86/x64 length constraints. A Win32
integration test installs an execute breakpoint at the stopped instruction
pointer, verifies that the resulting event identifies the owned breakpoint,
removes it, and confirms the target can exit normally.
