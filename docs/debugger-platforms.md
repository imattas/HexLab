# Debugger backend platform coverage

The debugger library keeps host-specific process control behind the `Backend`
interface. `make_native_backend()` selects one native implementation at build
time. The portable GDB Remote Serial Protocol backend remains available on
every host with the platform's TCP transport, so an unsupported native target
can still be debugged through a compatible remote server.

| Host platform and architecture | Native backend selection | Scope |
| --- | --- | --- |
| Windows | Win32 backend | x86/x64 process control and four-slot execution/data hardware breakpoints; native ARM32 builds expose stopped-thread GPR/NEON context edits, ARM/Thumb software breakpoints, bounded sequential-instruction steps and up to eight hardware execute breakpoints; native ARM64 builds support stopped-thread GPR/FPSIMD context access and safe edits, software BRK breakpoints with PSTATE single-step, and up to two execution plus two data hardware breakpoints |
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

Native ARM32 builds use the Windows [Arm32 `CONTEXT`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context-r1)
through `GetThreadContext`/`SetThreadContext` only while a debug event is
pending. The selected thread must belong to the target process. Reads expose
R0-R12, SP, LR, PC, CPSR, Q0-Q15, and FPSCR. Writes validate exact widths and
little-endian bytes, keep SP eight-byte aligned, and check PC alignment against
CPSR.T (two bytes in Thumb state, four in ARM state). CPSR edits are limited to
NZCV and T; changing T requires a PC edit and a clear IT state. A failed
context write attempts to restore the captured context.

ARM32 software breakpoints patch the first Thumb halfword with `BKPT #0` or
the four-byte ARM instruction with `BKPT #0`. ARMNT addresses default to Thumb;
at the stopped event thread's PC, CPSR.T selects the mode. The low bit of a
breakpoint address can explicitly tag Thumb and is cleared before patching.
An ARM-mode breakpoint away from the stopped PC cannot be selected through the
current address-only API. Breakpoint overlap and suspected placement in the
second half of a wide Thumb instruction are rejected. ARM32 breakpoint and
memory changes require a pending stop; memory writes touching an owned
breakpoint instruction or its preceding Thumb halfword are rejected to retain
the recorded instruction width.

ARM32 has no CPSR single-step bit exposed by this API. The bounded step path
accepts verified sequential instructions: common 16-bit Thumb scalar and
load/store forms, 32-bit Thumb MOVW/MOVT, and ARM data-processing immediates
that do not write PC. It rejects branches, calls, returns, interworking,
unknown encodings, and a successor overlapping a user breakpoint. A Thumb
context with nonzero CPSR ITSTATE, including the final instruction of an IT
block, is rejected before releasing peer suspensions, changing PC, or patching
code. For an accepted step, the backend restores an owned breakpoint
instruction if needed,
patches a temporary trap at the decoded successor, suspends peer threads, and
continues the event owner. At the next stop it rewinds a post-trap PC, restores
the successor bytes, and rearms the owned breakpoint. Restoration failure
keeps the event stopped and is retried before continuation; the temporary
breakpoint exception must be continued as handled. Windows ARM32
hardware breakpoints use up to eight BVR/BCR execute comparators exposed by the Windows ARM32 context ([Armv7-A/R Architecture Reference Manual](https://developer.arm.com/documentation/ddi0406/b/Application-Level-Architecture/Introduction-to-the-ARM-Architecture/Debug)). Since hardware may implement fewer, each update verifies the programmed context and fails with `unsupported` if the requested comparator count is unavailable. Only execute
breakpoints are supported; data watchpoints remain unsupported. ARM addresses
must be four-byte aligned. Thumb addresses use the low address bit as a Thumb
tag, which selects the indicated halfword in the aligned word; the current API
therefore supports tagged 16-bit Thumb instruction breakpoints. Updates require
a pending debug event and are transactional across the current target threads.
New threads receive the active configuration at their creation event. The
backend preserves unowned comparators, rejects occupied slots and external edits
to owned slots, and matches execution stops to the configured instruction
addresses after clearing the low Thumb tag from both the configured and reported`r`naddresses. Removing breakpoints and detaching clear the owned comparators.
Runtime behavior still requires validation on native ARM32 Windows.

Windows x86 and x64 hardware breakpoints use DR0-DR3/DR7. Execution
breakpoints and write/access watchpoints share the four available slots. Data
watchpoints accept aligned 1, 2, 4, or 8 byte ranges (8 bytes requires an x64
target); x86/x64 cannot distinguish read-only accesses, so read-only watchpoints
return `unsupported`. Changes require a pending debug event. Updates check the
debugger-owned slot state on every current target thread and apply
transactionally, rolling back earlier threads if a later thread update fails.
New threads receive the active configuration before their creation event is
returned. DR6 identifies hit slots and the backend clears the hit bits before
the event is continued. Removing breakpoints and detaching clears owned slots;
process and thread exit discard the corresponding session/thread state. Slots
already used by another debugger or changed outside HexLab cause a conflict
rather than being overwritten.

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
hosts. Windows ARM32 source has been syntax-checked for `armv7-w64-windows-gnu`
against available Windows headers; native runtime behavior remains unverified.
Windows ARM64 source has been syntax-checked with clang-cl targeting
`aarch64-pc-windows-msvc` against the installed Windows SDK, but runtime
behavior still needs validation on a native ARM64 host. See
[Darwin debugger scope](debugger-darwin.md) for the conservative macOS backend
limits.
