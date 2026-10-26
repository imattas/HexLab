# Linux AArch64 native debugger backend

The Linux AArch64 build selects `native_backend_linux_aarch64.cpp` when CMake
reports an AArch64 host. It uses ptrace directly and does not depend on a
separate debugger daemon. The x86-64 host build continues to select
`native_backend_linux.cpp`.

## Supported today

- Launching and attaching to AArch64 ELF processes.
- Initial stop, continue, interrupt, single-step, and detach, with ptrace clone
  events used to follow new threads.
- Attach performs a bounded repeated `/proc/<pid>/task` census, seizes and
  interrupts each observed TID, and succeeds only after two stable censuses
  show every observed thread stopped. Launch and attach enable clone tracing.
- A process event stops traced peer threads before presentation. Normal continue
  resumes stopped threads while preserving deferred signal/clone events;
  thread-specific continue resumes only the selected event thread.
- Thread-created and thread-exited events are reported separately from process
  exit. Cloned TIDs are range-checked and the configured thread limit is
  enforced before waiting for the child's initial ptrace stop.
- Reading and writing `x0` through `x30`, `sp`, `pc`, and `pstate` through the Linux
  `NT_PRSTATUS` regset. `w0` through `w30` and `wsp` expose their low 32-bit
  aliases; `fp` and `lr` alias `x29` and `x30`.
- Process and thread listing, and ptrace memory reads and writes.
- Reading and writing the fixed Linux `NT_FPREGSET` FPSIMD view (`v0` through `v31`,
  `fpsr`, and `fpcr`) when the kernel exposes it. Scalar `d0` through `d31`
  expose the low eight bytes of those vectors for DWARF register locations and
  ELF caller-frame recovery.
- Reading active Linux `NT_ARM_SVE` scalable state (`z0` through `z31`, `p0`
  through `p15`, and `ffr`) with the low 128-bit `v0` through `v31` aliases;
  writes preserve untouched payload bytes and vector length.
- Aligned four-byte `BRK #0` software breakpoints, including enable/disable,
  hit reporting, displaced-instruction stepping, and instruction restoration.
- `NT_ARM_HW_BREAK` execute breakpoints and `NT_ARM_HW_WATCH` read/write/access
  watchpoints, with slot ownership, cloned-thread setup, and execute-hit step-over.
- File-backed module inspection from `/proc/<pid>/maps`, grouped by exact path.
  Reported spans cover the min/max mapped range and can include gaps.

Linux arm64 reports the BRK fault address from `instruction_pointer(regs)`;
that helper returns `regs->pc`. The ptrace `NT_PRSTATUS` GPR view exposes the
same PC field, so breakpoint matching and rewind use the BRK instruction's
address directly.

The register interface reports each full general register as an eight-byte
value and each W alias as a four-byte value, with explicit little-endian
metadata, including when optional vector state is unavailable. A W write
zero-extends into its X register, and a WSP write zero-extends into SP. A
write batch rejects two names for the same underlying general register (such
as `x29` and `fp`, or `x0` and `w0`) before changing target state. PC writes
must be four-byte aligned. This also makes general registers usable by watch
and breakpoint condition expressions. The build requires an LP64 little-endian AArch64 host;
other host/tracee byte orders and ILP32 tracer builds are unsupported.

D-register writes update the low eight bytes of the existing V/Z payload and
preserve the remaining bytes. A write batch accepts only one alias from Dn,
Vn and Zn for each vector register; canonical lowercase names are required.
Zn writes must contain exactly VL bytes, and Pn/FFR writes exactly VL/8 bytes,
using the stopped thread's validated SVE header. Width and alias validation
finish before payload copies or any `SETREGSET` call. Explicit big-endian write
metadata is rejected; absent metadata retains the native little-endian contract.

Memory reads and writes are limited to 1 MiB per request and use aligned
native-word ptrace accesses, copying only the requested byte slice. Partial
writes preserve neighboring bytes. This permits unaligned inspection and a
four-byte BRK in the last instruction slot of a mapped page without reading
the following page. Existing breakpoint-aware memory writes retain original
instruction bytes and attempt rollback on failure.

## Current limits

The backend is intentionally scoped to AArch64 Linux tracees on AArch64 Linux.
Memory and breakpoint modifications compare `/proc/<pid>/task` against the
traced-and-stopped TID set and return busy if any sibling is untracked or
running. When active SVE is unavailable, the backend exposes only the fixed
128-bit FPSIMD view. Header-only SVE returns the valid general-register snapshot
without substituting an unavailable vector payload; vector writes in that state
and SME streaming registers remain unsupported. Module spans are derived from mappings rather than ELF program headers,
so they are not load-bias records and may cover gaps. AArch64-host runtime
validation of clone races, hardware debug slots, thread exit, and attach
stabilization remains outstanding in this environment.

Attach bounds its task census to 16 rounds and 4,096 threads. All parent-side
`waitpid` calls use `__WALL | WNOHANG`; launch, attach, clone initial stops,
peer suspension, termination and rollback share the same polling/deadline policy.
An outer operation gets one steady-clock deadline. Nested suspension, per-thread
waits and cleanup reuse it, and neither additional threads nor `EINTR` restart it.
Poll sleeps are one millisecond. The default budget is 5,000 ms, configured once
when constructing the backend through `HEXLAB_AARCH64_PTRACE_TIMEOUT_MS`.
Decimal values from 1 through 60,000 are accepted; absent/invalid values use
the default. `wait_event` uses the smaller of its requested timeout and this
configured budget, and a zero timeout still polls already available statuses.

`request_interrupt` signals an active operation through an atomic flag without
inspecting mutable ptrace ownership sets from the requesting thread. During
event polling, the tracer thread converts that request into ordinary
`PTRACE_INTERRUPT` operations and reports the resulting stop event. During
other lifecycle waits, it cancels the active poll. Outside an active operation
it retains ordinary `PTRACE_INTERRUPT` behavior. Lifecycle cancellation returns
`canceled`, deadline exhaustion returns `busy`,
and consumed real signal/clone/exit statuses remain queued for retry. Startup
rollback and resume rollback ignore the cancellation flag while retaining the
original deadline. This does not make other backend methods concurrently safe;
all operations other than requesting cancellation must remain serialized on
the tracer thread.

Failed launch/attach cleanup retains its exact acquired TIDs until each is
detached or reaped. A failed launch is killed; a failed attach releases only
owned threads and reinjects real signal stops. If the shared deadline expires,
the error reports retained cleanup. The next backend launch/attach attempt,
explicit backend detach, or destruction retries it with a fresh bounded
operation. A clone TID is recorded before its initial-stop wait, and the
parent's consumed clone status is retained on timeout. Pending initial stops
must complete before resume. Automatically owned children beyond the ordinary
thread cap remain tracked for cleanup; further resume fails closed.
Peer polling uses a TID snapshot so collecting a clone's initial stop can safely
remove another pending interrupt without invalidating the polling loop.

Termination removes only TIDs whose exit was consumed or which are no longer
waitable by the tracer. A timeout leaves remaining ownership and stop statuses
available for a termination retry. Detach restores owned breakpoint state
before releasing threads and records successful releases individually. A
partial detach can be retried without requiring already released peers to be
traced again; resume is blocked until cleanup completes. Real signals are
reinserted on detach, while owned software/hardware traps and single-step traps
are suppressed.

These deadlines bound userspace polling, not time spent inside an individual
kernel syscall or `/proc` access. An unresponsive tracee may require later
cleanup retries. Destruction makes one bounded best-effort cleanup attempt;
callers requiring confirmed detach/reap must retry a failed cleanup before
destroying the backend. No unconditional successful cleanup is claimed after
a timeout, and attached processes are not killed merely to force detach.
Fork/vfork inferior tracking, cross-architecture AArch32 tracees, cross-endian
tracees and schedules with multiple concurrent single-step actions remain
unsupported. One single-step may run alongside continue actions while all
traced threads are stopped.

Thread resume schedules support signal-aware continue and single-step actions.
An action without a signal disposition preserves/redelivers its queued signal;
`handled` suppresses it and `not_handled` explicitly requests reinjection.
Signals belonging to stop actions remain queued for that thread until a later
resume or detach. When a signal is injected during a pending execute-breakpoint
stop, the displaced-instruction helper is deferred so the original breakpoint
remains installed and can be observed after the signal handler returns. Failed
ptrace resumes retain queued signal state for retry. These rules use the
documented ptrace restart signal argument ([ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html));
the RSP server does not yet expose signal-delivery packets.

The kernel's [SVE ptrace interface](https://docs.kernel.org/arch/arm64/sve.html)
defines VL in bytes and separate Z/P/FFR layouts. General and vector state
remain explicit stopped-thread snapshots; inactive vector state is never
fabricated. This extension received source review only. No builds, tests or
live AArch64 validation were run. Follow up with a serial AArch64 Linux
`hexlab_debugger` and debug-server build; a Windows build does not compile this
architecture-selected source.

The existing integration fixture in `tests/debugger/debugger_tests.cpp` runs
under the headless debugger test executable on AArch64 Linux. It checks
launch-stop, register access, BRK installation, hit reporting, single-step, and
restoration. It does not currently exercise multithread attach or clone races;
this work did not run tests or open the desktop UI.
