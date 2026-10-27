# Darwin native debugger backend

On macOS, `make_native_backend()` selects a Mach/ptrace implementation for
x86-64 and AArch64 hosts. It enumerates processes with `sysctl`, reads target
architecture from the executable's Mach-O header, launches with
`PT_TRACE_ME`, and attaches/detaches with `PT_ATTACHEXC`/`PT_DETACH`. A launch or
attach exposes the initial stop as a normal debugger event. Continued stops
are observed through `waitpid`; continue, single-step, and interrupt use
`PT_CONTINUE`, `PT_STEP`, and `SIGSTOP`.

Thread IDs, optional kernel thread names, and registers come from Mach
task/thread APIs. Thread names use `THREAD_EXTENDED_INFO`; when the kernel does
not return a name, the snapshot keeps its `thread <id>` label. Thread-state
snapshots report the backend's process stop boundary for each listed thread;
they do not attempt to report scheduler wait/sleep states. While a process-wide
task suspension is held, register reads and edits address the requested thread
ID, including in a multi-threaded process. The x86-64 path exposes the 64-bit
general, x87, and XMM register state; the AArch64 path exposes x0-x30, SP, PC,
and CPSR. On Apple Silicon, the AArch64 register view also exposes
`v0`-`v31`, `fpsr`, and `fpcr` through the separate `ARM_NEON_STATE64` Mach
thread-state flavor. Register writes validate names and widths before applying
the vector state; if the subsequent general-register update fails, the prior
vector state is restored. Memory reads use `mach_vm_read_overwrite`; writes use
`mach_vm_write` and preserve original bytes beneath owned software breakpoints.
Software traps use `INT3` on x86-64 and aligned `BRK` instructions on AArch64.
For writes to non-writable regions, the backend temporarily requests write
permission only when the region's existing maximum protection allows it,
removes execute permission during that window, and attempts to restore the
original protection. Code-signing policy or mapping limits can still reject
code patches, and a protection-restore failure is returned explicitly.
Breakpoint state is restored on removal or detach. Module enumeration reads
the stopped process's 64-bit dyld image information, and memory-region
enumeration uses Mach VM region queries. Hardware breakpoints and watchpoints
remain unsupported.

Darwin task suspension is held while the backend inspects a stopped target,
which gives thread enumeration and register access a process-wide stop
boundary. Thread snapshots are bounded at `max_inspection_threads` and
report every thread as stopped only while that suspension is held; a running
snapshot reports running threads. Attach still requires a single-thread
initial stop because the current ptrace path cannot identify which Mach thread
caused an attach-time event.

Execution remains deliberately limited to a single-thread target. Darwin's
process-level `waitpid`/ptrace path does not expose the Mach thread that caused
a later stop, and `PT_STEP` accepts a process ID rather than an explicit Mach
thread port. The backend therefore returns unsupported when a multi-threaded
target stops instead of assigning the event to an arbitrary thread or stepping
the wrong thread. The task remains suspended after that unsupported result so
the target is not accidentally resumed. Full multi-thread event routing and
selected-thread stepping require the Mach exception-port path used by native
Darwin debuggers; it is not implemented here. That path needs a MIG-generated
`mach_exc_server` receive loop and a per-event reply handoff: the exception
server must retain each thread's exception until the matching debugger event is
continued, while task suspension keeps peer threads stopped. It must also
preserve and chain the target's existing exception handlers, return the right
Mach exception state when resuming, and use thread-qualified stepping rather
than `PT_STEP`'s process ID. Merely installing an exception port and returning
success would consume target exceptions; returning failure without preserving
the prior handlers can lose the target's normal exception delivery.

The exception behavior also has to comply with macOS process restrictions.
Apple documents that hardened-process platform restrictions disallow setting
exception ports with `EXCEPTION_DEFAULT` and require protected identity/state
behaviors; identity tokens must be converted to authorized thread ports. The
backend must keep a clear unsupported result when it cannot establish that
identity or safely preserve the original exception route.
Targets whose architecture differs from the backend host architecture are also
unsupported. For universal Mach-O files, architecture discovery chooses the
backend host slice; attaching to a process explicitly started under Rosetta
can therefore be ambiguous. `task_for_pid` access is subject to macOS
code-signing, entitlement, SIP, and process-ownership policy.

The backend source and CMake selection have not been compiled or run on a
Darwin host in this environment. Mach structure names, ptrace behavior,
architecture reporting, process authorization, and software-breakpoint
displacement require macOS x86-64 and Apple Silicon validation before this
backend should be treated as production-ready.

The AArch64 NEON register names and state flavor follow Apple's XNU Mach thread
status definitions: [`ARM_NEON_STATE64` and `arm_neon_state64_t`](https://github.com/apple/darwin-xnu/blob/main/osfmk/mach/arm/thread_status.h),
with the public vector and status fields declared in
[`_structs.h`](https://github.com/apple/darwin-xnu/blob/main/osfmk/mach/arm/_structs.h).

Apple API references: [`mach_exc_server`](https://developer.apple.com/documentation/kernel/1559919-mach_exc_server),
[`task_set_exception_ports`](https://developer.apple.com/documentation/kernel/1538049-task_set_exception_ports), and
[Mach IPC security restrictions](https://developer.apple.com/documentation/xcode/conforming-to-mach-ipc-security-restrictions).
