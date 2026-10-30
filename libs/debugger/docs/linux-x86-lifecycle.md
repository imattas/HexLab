# Linux x86/x64 ptrace lifecycle deadlines

The default Linux backend remains an x86-64 tracer supporting x86-64 and
compatible i386 ELF processes. Its launch, attach, clone initial-stop capture,
peer suspension, termination and cleanup waits use `waitpid` with
`__WALL | WNOHANG`. Register, instruction-pointer, INT3 displaced-step and x86
hardware-debug handling remain local to this backend. No architecture-shared
helper imposes AArch64 register or trap semantics on x86 targets.

One outer operation owns a steady-clock deadline. Nested per-thread waits,
suspension recovery and rollback reuse that deadline; `EINTR` and additional
threads never restart it. The default budget is 5,000 ms. Set
`HEXLAB_LINUX_PTRACE_TIMEOUT_MS` before backend construction to a decimal value
from 1 through 60,000; missing/invalid values use the default. Event polling
uses the smaller of its requested timeout and this budget. A zero timeout can
still consume a status that is already available. Poll sleeps are one
millisecond, and deadline exhaustion returns `busy`.

`request_interrupt` posts an atomic request while an operation is active.
During event polling, the tracer thread translates it into ordinary
`PTRACE_INTERRUPT` requests and presents the resulting target stop. During
other lifecycle polling it returns `canceled`. Startup and resume rollback
ignore cancellation while retaining the original deadline. All other backend
operations must remain serialized on the tracer thread; the atomic request
does not make arbitrary backend calls concurrently safe.

A debugger-generated `PTRACE_EVENT_STOP` carrying `SIGTRAP` is surfaced as an
`interrupted` event, separate from a target exception. Job-control group stops
remain exception events and retain their real stop signal for later delivery.

Launch uses a close-on-exec socket gate, installs `PTRACE_SEIZE` options before
releasing the child and waits for the exact exec stop. A failed launch receives
SIGKILL and bounded reap attempts. Attach retains the existing 16-round,
4,096-thread stable census and enables clone tracing only after that census
has stopped. Both paths record ownership as soon as it is acquired. Failed
attach cleanup detaches only acquired threads and preserves real signal stops.
If cleanup times out, the backend retains its exact remaining ownership and
reports that cleanup needs retry. The next backend launch/attach attempt,
explicit backend detach or destruction retries the retained cleanup.

Clone event TIDs are range-checked and recorded before waiting for initial
stops. A timeout retains both the child and the consumed parent clone status.
Pending initial stops and per-child hardware-debug setup must complete before
resume. The normal 4,096-thread cap blocks further execution when exceeded;
automatically owned children remain recorded for bounded cleanup. Peer polling
uses a TID snapshot because collecting a clone's initial stop can modify the
pending-interrupt set. Real signal, clone and exit statuses collected during
suspension or rollback remain deferred events.

Existing displaced-step recovery, trap rearming, register rollback and hardware
slot ownership remain part of the resume barrier. Failed or timed-out recovery
does not acknowledge the caller's pending event. Termination retains pending
control state and remaining TIDs until exits are drained; a timeout blocks
ordinary resume and allows another termination attempt. Newly observed clone
TIDs during termination are included in that drain.

Detach first stops owned threads, saves each real signal for reinjection,
restores original software bytes and clears owned hardware slots. An owned
INT3 stop rewinds EIP/RIP to the original instruction before release; owned
hardware and trace-step SIGTRAPs are suppressed. Partial preparation or detach
blocks resume. Successful detach calls remove only their own TIDs, so a retry
does not require already released peers to be traced again. Saved signals and
completed hardware cleanup survive that retry.

Deadlines bound userspace polling, not the duration of an individual kernel
syscall or `/proc` access. An unresponsive task can require later cleanup
attempts. Destruction makes one bounded best-effort attempt; callers needing
confirmed detach/reap must retry failed cleanup before destroying the backend.
An attached process is not killed merely to force detach. Fork/vfork inferior
tracking and general cross-architecture tracing remain unsupported.

This change received source review only. No builds or tests were run. Follow
up with a serial Linux x86-64 build of `hexlab_debugger` and the debug server;
Windows and AArch64 builds do not compile this source.
