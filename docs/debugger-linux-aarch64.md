# Linux AArch64 debugger backend

The native Linux AArch64 backend supports ELF64 AArch64 targets through
`ptrace`. Launch uses a gated `PTRACE_SEIZE` start and reports the exec stop.
Attach seizes and interrupts every visible task, repeats the `/proc/<pid>/task`
census until it stabilizes, enables clone tracing, and rolls back acquired
threads if ownership cannot be established. The bounded thread limit is 4096.

After launch or attach, thread creation is tracked through
`PTRACE_O_TRACECLONE`. Stop events suspend the remaining owned threads before
they are published. Global continue resumes stopped owned threads; a
thread-qualified continue and single-step resume only the event thread. A
thread-resume schedule can continue several selected stopped threads while
leaving other owned threads stopped. If a ptrace continue fails partway through
such a schedule, the backend interrupts and re-stops the threads it already
resumed before returning the original error. If rollback is incomplete, the
session blocks further resume operations until it has retried stopping those
peers; signal, clone, exit, and other racing statuses are retained as deferred
events and are not attributed to the schedule's pending event. A schedule must
include the exact pending event owner, and every listed thread must be uniquely
owned and stopped by this session. The schedule API has no signal-delivery
field, so schedules fail closed when the pending event is a real signal stop;
use the signal-aware continue operation instead. Multi-thread schedules accept
continue actions only and cannot step over a pending software or hardware
breakpoint; single-step schedules remain limited to one runnable thread.
These ptrace operations use stop-and-rollback and are not atomic.
Memory reads and writes, breakpoint changes, detach, and register writes
require the entire process thread group to be owned and stopped. If the task
list and ptrace ownership do not match, these operations fail closed.

Register inspection and writes cover x0-x30, sp, pc, pstate, and vector state.
The backend reads `NT_ARM_SVE` header-first, then fetches its complete bounded
payload using the UAPI `size`, `max_size`, `vl`, `max_vl`, and format flags.
For active SVE-format state it exposes z0-z31 at the current vector length,
p0-p15, ffr, fpsr, fpcr, and v0-v31 as low-128-bit aliases of the Z registers.
Writes keep the existing vector length and preserve all untouched payload and
extension bytes. `sve_vl` and `sve_max_vl` are reported as read-only metadata.
When SVE is unsupported by the kernel, the backend falls back to the legacy
128-bit `NT_FPREGSET` FPSIMD v0-v31, fpsr, and fpcr state.

The backend bounds the maximum accepted vector length to the Linux UAPI limit
of 8192 bytes and every regset allocation to 512 KiB; malformed or larger
header/payload sizes fail closed without truncating state. A header-only
`NT_ARM_SVE` view is treated as inactive SVE state and rejected instead of
falling back to FPSIMD. Linux uses this view while SME streaming mode is
active; this backend does not read or write `NT_ARM_SSVE`, so it cannot inspect
or change streaming SVE state. Execution control includes per-thread single stepping and aligned
four-byte software breakpoints using AArch64 `BRK`; software breakpoint
displacement restores the original instruction for one step and rearms the
trap before publishing the next event. Hardware breakpoint support is
described below. The backend also provides bounded `/proc/<pid>/maps`
inspection and target termination with wait/reap handling.

The backend also supports ptrace hardware breakpoints and watchpoints through
Linux `NT_ARM_HW_BREAK` and `NT_ARM_HW_WATCH` regsets. Execute breakpoints use
the debugger's logical size 1 and require four-byte alignment; the kernel BAS
selects the full four-byte AArch64 instruction. Read, write, and access watchpoints
accept sizes 1, 2, 4, or 8 when the watched range fits within one aligned
eight-byte BAS granule. The backend intersects free slot numbers across all
owned threads, preserves slots it does not own, rolls back partial register
updates, and reapplies owned slots to newly cloned threads. A slot that becomes
unavailable or changes outside the session causes an explicit error. Owned
execution hits are matched by PC; watchpoint IDs are attached only when
`siginfo.si_addr` falls inside exactly one owned watched range. When overlapping
read/write slots make the access direction ambiguous, the trap remains visible
without assigning a guessed ID. Linux notes that AArch64 watchpoint fault
addresses can be imprecise for accesses spanning watched and unwatched bytes,
so those traps also remain visible without a guessed breakpoint ID.
On an execute hit, the backend saves that thread's debug regset, disables the
matching execute slots on that thread, single-steps one instruction, and
restores the saved regset before reporting the next event. If restoration fails,
the target stays stopped and later resume attempts retry the restore.

File-backed module inspection groups `/proc/<pid>/maps` ranges by exact mapped
path, ignores anonymous and bracketed kernel mappings, and reports each path's
basename plus the minimum start and maximum end across its mappings. The
reported span can include unmapped gaps and represents the mapped path range,
not a parsed ELF load bias. Enumeration is bounded by the common 4096-module
and 65,536-mapping inspection limits.

The regset layout and control-word encoding follow the Linux arm64 UAPI and
kernel implementation: [`user_sve_header` and `NT_ARM_SVE` layout](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/ptrace.h),
[`SVE vector layout macros`](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/sve_context.h),
[`SVE ptrace header semantics`](https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/ptrace.c),
[`user_hwdebug_state`](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/ptrace.h),
[`encode_ctrl_reg`](https://github.com/torvalds/linux/blob/master/arch/arm64/include/asm/hw_breakpoint.h),
and [watchpoint hit attribution](https://github.com/torvalds/linux/blob/master/arch/arm64/kernel/hw_breakpoint.c).

The updated source passed a syntax-only compile with the AArch64 backend guard
enabled under x86_64 WSL, using the host Linux headers. The available host is
not AArch64, so this does not validate native AArch64 ptrace UAPI behavior or
runtime breakpoint handling. No tests or target runtime checks have been run.
