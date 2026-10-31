# Darwin native debugger backend

CMake selects `native_backend_macos.cpp` on Darwin. The backend uses Darwin
ptrace for lifecycle events and Mach task/thread APIs for inspection. It targets
native x86-64 processes on x86-64 macOS and native AArch64 processes on AArch64
macOS. OS permissions for `task_for_pid` and ptrace remain required.

## Process, memory, and threads

The backend lists processes, launches or attaches to a target, reports its
initial stop, continues or single-steps an acknowledged event, requests an
interrupt, detaches, and terminates. Stop events retain their sequence until
the caller explicitly continues them. Detach restores owned software
breakpoints before releasing the target.

On native AArch64, stopped single-thread targets can install four-byte aligned
hardware execute breakpoints and read, write, or read/write data watchpoints
through Mach `ARM_DEBUG_STATE64`. Execute breakpoints use a logical size of one
byte, matching the instruction-breakpoint API convention. Watchpoint widths
are 1, 2, 4, or 8 bytes; each must be naturally aligned and stay within one
eight-byte granule. Native x86-64 supports one-byte execution breakpoints and write or
read/write data watchpoints through Mach `x86_DEBUG_STATE64`; read-only
watchpoints are unsupported by x86 debug registers. Data widths are 1, 2, 4,
or 8 bytes and addresses must be naturally aligned. Execute and data
comparators share four slots on x86-64; AArch64 uses the architecture's
separate instruction and data comparator banks. Both architectures preserve the selected
comparator's prior disabled state, verify the programmed comparator, and
restore that state on disable, removal, and detach. Comparator changes made by
another debugger are reported as conflicts rather than overwritten. Both
remain limited to single-thread targets. On AArch64, an owned execute hit is
matched against the stopped PC, its comparator is disabled for one instruction
while the target single-steps, then the comparator is restored before the
single-step event is delivered. A failed re-enable retains the pending event
and comparator ownership so the caller can retry or detach cleanly.
On x86-64, DR6 identifies owned execution and data comparator hits and the
backend clears the reported hit bits before the stop is resumed. On AArch64,
the backend attributes a data-watchpoint stop only when ESR identifies a valid,
precise comparator hit owned by the session. Hardware execute stops require an
AArch64 breakpoint exception class and an exact match to an enabled owned
comparator at PC; other traps remain generic.

Lifecycle waits use a backend-local steady-clock deadline and
`waitpid(WNOHANG | WUNTRACED)` polling with one-millisecond sleeps. The default
budget is 5,000 ms. `HEXLAB_DARWIN_PTRACE_TIMEOUT_MS`, read at backend
construction, accepts decimal values from 1 to 60,000; invalid or missing
values use the default. Nested startup rollback, stop acquisition and cleanup
reuse the outer operation's deadline. `EINTR` never restarts it. Event polling
also respects its shorter caller-supplied timeout; zero still polls an already
available status. Deadline exhaustion returns `busy`.

An interrupt requested during an active event poll is delivered as SIGSTOP by
the tracer thread and appears through the usual stop-event path. During other
lifecycle polling it cancels that poll with `canceled`. Startup rollback and
post-SIGKILL reap ignore cancellation but retain the shared deadline. Only this
atomic request can run concurrently; other operations remain serialized.

Acquired ptrace ownership is recorded immediately. Failed launch cleanup kills
and reaps the child; failed attach cleanup detaches without killing the target.
Timeouts retain the remaining PID, stop signal and cleanup phase. A later
backend launch/attach or explicit detach retries startup cleanup. Detach and
termination retain their own retry phases, and execution stays blocked until
cleanup finishes. Real stop signals are reinjected on detach, while recognized
owned breakpoint/step traps and debugger-requested SIGSTOPs are suppressed.
There is no sender-level distinction for coincident SIGSTOPs in this ptrace
interface. An ambiguous multithread SIGTRAP with installed breakpoints can
fail closed when its instruction owner cannot be established safely.

Each successful `task_suspend` now retains the exact Mach task send right
that acquired the debugger's hold. `task_resume` uses that right, preserving
it on failure, and deallocates it after a successful resume. Confirmed process
exit releases the now-dead task right without pretending to resume a live task.
Other task/thread inspection rights retain their existing matching deallocation
paths. If ptrace has already accepted continue/step and Mach resume fails, a
retry finishes that same resume without issuing a second ptrace action.
Consumed raw stop statuses remain cached across Mach/thread inspection errors;
retrying does not lose the stop or synthesize a new signal. Existing module
notification ordering and acknowledgement semantics are preserved.

These budgets bound userspace polling rather than time inside a kernel/Mach
call or process-path read. Unresponsive tasks can need later cleanup retries.
Destruction makes bounded best-effort cleanup, attempts to balance its Mach
hold and releases its owned send right. Callers requiring confirmed detach and
balanced suspension must retry failed cleanup before destruction; a timeout
does not claim successful target release.

Memory reads and writes use Mach virtual-memory operations, with a 1 MiB
per-operation limit. The memory map reports current read/write/execute
permissions. Writes preserve installed software traps and update their saved
original bytes. The existing writer attempts to restore temporary page
protection changes and reports failures.

Mach thread identifiers are exposed as thread IDs. Register and module
inspection requires a stopped task with a debugger-owned task suspension.
Execution is limited to a single-thread target: launch/attach and continuation
check the thread census. Thread-qualified continue accepts only the sole known
thread, so ptrace cannot silently resume a different thread. A target that
creates additional threads can no longer be continued or single-stepped
through this backend; it can still be inspected or detached. A multithreaded
stop returns `unsupported` because ptrace alone does not establish the faulting
Mach thread's identity. Mach exception-port handling and per-thread execution
of multithread targets remain future work.

`resume_threads_event` accepts one exact continue or step action only after the
same single-thread census. A schedule with multiple entries, a foreign thread,
or stop-only actions is rejected. Informational module acknowledgements retain
the session's stopped state and queued-notification handling.

## Loaded images

`modules()` reads `TASK_DYLD_INFO` and the 64-bit `dyld_all_image_infos` image
array from the stopped target. Each module includes its dyld path, filename,
runtime segment base, and the span through the final mapped Mach-O segment.
ASLR is derived from the segment containing the Mach-O header. `__PAGEZERO` is
excluded; gaps between other segments remain part of the reported span. Use
the memory map to determine whether an individual address is mapped.

The reader bounds the image count at 4096, each path at 4096 bytes, and each
image's load commands at 1 MiB. It rejects malformed command/segment extents
and address overflow. It reports errors for unreadable images rather than
returning a silently incomplete list. An uninitialized dyld record or a null
image-array pointer returns `busy`; dyld may be stopped in the middle of a
loader update and needs to reach a later stop. The image-list prefix is checked
again before returning a snapshot.

The list represents dyld's loaded-image array. It does not synthesize entries
for JIT allocations or a loader image absent from that array, and it does not
emit notifications for JIT changes. The 32-bit dyld ABI and
non-little-endian/non-64-bit Mach-O images return `unsupported`.

At each later ptrace stop, the backend compares a fresh dyld image snapshot to
the prior successful snapshot. It queues `module_unloaded` events before
`module_loaded` events and then presents the original stop event. Each module
notification is acknowledged with continue; acknowledging it leaves the
process stopped while the queued notifications and original stop are
delivered. Module events report the image base and path. A transient dyld
snapshot error suppresses notifications for that stop and retains the previous
snapshot so a later stop can report the change. This polling approach observes
image changes only when the single-thread target stops; it does not report
loader changes while the target runs, and it does not synthesize JIT events.

## Thread snapshots

Thread enumeration uses Mach thread identifiers and names as before, and now
also queries `THREAD_BASIC_INFO` for each thread's run state. `RUNNING`,
`WAITING`, and `UNINTERRUPTIBLE` map to the debugger's running state; `STOPPED`
and `HALTED` map to stopped. Unknown kernel values or a failed optional
`THREAD_BASIC_INFO` query remain unknown rather than being guessed. While the
backend owns a task-wide suspension for a debugger stop, every enumerated
thread is reported stopped regardless of its individual query result. This
snapshot reflects Mach's reported scheduler state; it does not distinguish
application-level blocking reasons or provide atomic per-thread scheduling.
The public run-state definitions and `THREAD_BASIC_INFO` layout are in Apple's
[XNU thread information header](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/thread_info.h).

## Registers and breakpoints

On x86-64, general registers include `rax` through `r15`, `rip`, `rflags`,
`cs`, `fs`, and `gs`. The `x86_FLOAT_STATE64` view adds:

- `st0` through `st7`: ten-byte x87 values, excluding each slot's padding.
- `xmm0` through `xmm15`: sixteen-byte SIMD values.
- `fcw`, `fsw`, `fop`, `fcs`, and `fds`: two bytes each; `ftw`: one byte.
- `fip` and `fdp`: four-byte offsets as exposed by the Darwin ABI.
- `mxcsr`: four bytes, checked against the kernel's supported-bit mask on write.

These widths follow Darwin's ABI. The x87 pointer fields use separate offsets
and selectors. Floating-point and SIMD fields preserve padding and reserved
state. A register-write batch rejects duplicate names, unknown names, and
incorrect widths before setting registers. Mixed general/floating-point writes
stage both contexts and attempt to restore the previous floating-point context
if the subsequent general-context commit fails. A failed rollback is reported
explicitly. AVX/AVX-512 upper registers are not exposed.

On AArch64, the interface exposes `x0` through `x30` and their four-byte
`w0` through `w30` aliases, plus `sp`, `pc`, `cpsr`, `v0` through `v31`,
`fpsr`, and `fpcr` through the general and NEON Mach state flavors. W reads
return the low 32 bits; W writes zero-extend into the corresponding X register.
A batch that writes both aliases of one register is rejected before any Mach
state is changed. Register values use the native little-endian byte order.

Software breakpoints use x86 `INT3` or aligned AArch64 `BRK #0`, with
enable/disable, restoration, and displaced-instruction stepping. Cross-architecture debugging,
translated Rosetta register contexts, and accurate universal-binary slice
identification during attach remain outside the current contract.

## Verification limits

This change was developed on Windows. The portable dyld/Mach-O inspection
helper was instantiated and compiled with Clang in C++20 syntax-only mode with
warnings treated as errors. This does not compile the Mach/ptrace translation
unit or establish macOS runtime correctness. Native x86-64 and Apple Silicon
SDK builds, permission handling, shared-cache image extents, floating-point
round trips, and lifecycle behavior still require macOS validation. No tests
were edited or run, and the desktop UI was not opened.

The lifecycle deadline and Mach suspension ownership changes received source
review only, with no builds or tests. Compile follow-up requires native macOS
x86-64 and Apple Silicon SDK builds of `hexlab_debugger` and the debug server;
Windows/Linux builds exclude this translation unit.

The remote layouts and state fields are based on Apple's published
[dyld image ABI](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_images.h),
[Mach task information ABI](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task_info.h),
and [x86 thread-state declarations](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/i386/_structs.h).
