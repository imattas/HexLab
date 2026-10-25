# Debugger backend platform coverage

The debugger library keeps host-specific process control behind the `Backend`
interface. `make_native_backend()` selects one native implementation at build
time. The portable GDB Remote Serial Protocol backend remains available on
every host with the platform's TCP transport, so an unsupported native target
can still be debugged through a compatible remote server.

| Host platform and architecture | Native backend selection | Scope |
| --- | --- | --- |
| Windows | Win32 backend | x86/x64 process control; native ARM64 builds support stopped-thread GPR/FPSIMD context access and safe edits, software BRK breakpoints with PSTATE single-step, and up to two execution plus two data hardware breakpoints; ARM32 remains unsupported |
| Linux x86-64 | x86-64 ptrace backend | x86-64 and compat i386 targets, including register, memory, event, and breakpoint operations described in [Linux ptrace debugging](linux-ptrace-debugging.md) |
| Linux AArch64 | AArch64 ptrace backend | AArch64 GPR/FPSIMD, process lifecycle, memory, software breakpoints, hardware execute/watchpoints, and per-thread run-state; scalable SVE state is conditional on kernel regset availability |
| macOS x86-64 / Apple Silicon | Darwin Mach/ptrace backend | Bounded thread enumeration, task-suspended per-thread register inspection/editing, memory and module/region inspection; single-thread process execution, stepping, and software breakpoints; multi-thread stop attribution/stepping and hardware watchpoints are unsupported |
| Other OS/architecture combinations | Explicit unsupported backend | Native calls return `unsupported`; the library and RSP backend remain usable |

Darwin selects its Mach/ptrace backend only on macOS. Linux backend selection is
explicit. Known x86-64 and AArch64 CMake processor names select their matching
ptrace implementation. Other Linux processor names select the unsupported
backend instead of compiling x86-64-only ptrace code and failing later with an
architecture preprocessor error. This is a build-selection safeguard, not
native support for those architectures.

Windows ARM64 context access uses `GetThreadContext`/`SetThreadContext` with
the ARM64 context flags ([`ARM64_NT_CONTEXT`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-arm64_nt_context), [`GetThreadContext`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)) and is restricted to the stop window while a debug event is pending. Register reads expose X0 through X30, SP, PC, CPSR, V0 through V31, FPCR, and FPSR. Writes validate register sizes, keep PC instruction aligned and SP 16-byte aligned, restrict CPSR changes to NZCV flags, and reject X18 writes because Windows reserves it for the thread environment pointer. Vector state is the fixed 128-bit V register bank; scalable SVE/SME state is not exposed.

ARM64 software breakpoints use the four-byte `BRK #0xF000` encoding and can
only be added, removed, or toggled while the process is stopped at a debug
event. Single-step uses PSTATE.SS, suspends peer threads, restores the displaced
instruction before stepping, and reinstalls the trap after the resulting stop.
Failure paths attempt to restore the original PC/CPSR, trap instruction, and
peer-thread suspension state. Code patches snapshot the prior bytes and page
protection; short writes trigger byte rollback, and a protection-restore failure
after a successful write triggers a rollback attempt. Errors include byte or
protection restoration failures so callers can report incomplete recovery.

Hardware breakpoint updates are transactional across the process's current
threads and are reapplied to new threads. They preserve slots not owned by this
backend and reject external changes to owned slots. The backend uses two
execution slots and two data-watch slots, matching the Windows ARM64 debugger
limit documented in [Debugging on Arm64](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-arm64). Execution hit IDs are matched from the reported event address. Windows does not provide a hit-slot mask in the exposed ARM64 context, so a data-watchpoint stop is reported without an exact breakpoint ID. Hardware breakpoints can only be changed during a pending debug event.

When a handled ARM64 execution-breakpoint event is continued, the backend
temporarily disables the matching execute slot on the event thread, sets
PSTATE.SS, and resumes with peer threads suspended. It restores the exact
owned slot state when that thread next stops. Restoration failure leaves the
process stopped and is retried before the event can be acknowledged; conflicting
external slot edits fail closed. Watchpoints remain enabled during this
instruction step and can therefore produce their own stop.

This matrix describes the implemented feature boundary. Darwin and Linux
platform-specific runtime behavior still needs validation on their native
hosts. Windows ARM64 source has been syntax-checked with clang-cl targeting
`aarch64-pc-windows-msvc` against the installed Windows SDK, but runtime
behavior still needs validation on a native ARM64 host. See
[Darwin debugger scope](debugger-darwin.md) for the conservative macOS backend
limits.
