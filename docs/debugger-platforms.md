# Debugger backend platform coverage

The debugger library keeps host-specific process control behind the `Backend`
interface. `make_native_backend()` selects one native implementation at build
time. The portable GDB Remote Serial Protocol backend remains available on
every host with the platform's TCP transport, so an unsupported native target
can still be debugged through a compatible remote server.

The desktop refreshes the thread list and per-thread run states on its inspection
worker, so a slow native or remote backend does not block the UI. Results are
discarded when the debug session, stop event, or selected thread changes while
the query is in flight; the view then requests a fresh list for the current
selection.

| Host platform and architecture | Native backend selection | Scope |
| --- | --- | --- |
| Windows | Win32 backend | x86/x64 process control and four-slot execution/data hardware breakpoints; exception events expose chance metadata and up to 15 raw `EXCEPTION_RECORD.ExceptionInformation` values; `OutputDebugStringA/W` events read bounded target memory and display their text; x64 stopped-thread register inspection includes AVX-512 ZMM/opmask state when CPU, OS, and XState components support it; native ARM32 builds expose stopped-thread GPR/NEON context edits, ARM/Thumb software breakpoints, bounded sequential-instruction steps and up to eight hardware execute breakpoints; native ARM64 builds support stopped-thread GPR/FPSIMD context access and safe edits, software BRK breakpoints with PSTATE single-step, and up to two execution plus two data hardware breakpoints |
| Linux x86-64 | x86-64 ptrace backend | x86-64 and compat i386 targets, including register, memory, event, breakpoint, raw pending-event siginfo, and thread-qualified PTRACE_INTERRUPT for one known-running seized thread while peers keep running, as described in [Linux ptrace debugging](linux-ptrace-debugging.md); hardware execute and data breakpoints for both target widths |
| Linux AArch64 | AArch64 ptrace backend | AArch64 GPR/FPSIMD and conditional SVE state, optional read-only TTBR0 PAC masks, MTE allocation-tag reads when supported by the kernel and mapping, raw pending-event siginfo, thread-qualified PTRACE_INTERRUPT for one known-running seized thread while peers keep running, process lifecycle, memory, software breakpoints, hardware execute/watchpoints, and per-thread run-state |
| macOS x86-64 / Apple Silicon | Darwin Mach/ptrace backend | Bounded named-thread and process-stop-state snapshots, task-suspended per-thread register inspection/editing, memory and module/region inspection; AArch64 exposes X/W registers, SP/WSP, FP/LR, and NEON state; single-thread execution, stepping, and software breakpoints; x86-64 write/access watchpoint hits map through DR6, and AArch64 precise watchpoint exceptions map through ESR comparator indices to owned breakpoint IDs; read-only data watchpoints and multi-thread stop attribution/stepping remain unsupported; x86-64 supports one-byte hardware execute breakpoints in the same four DR0-DR3 slots, while AArch64 execute comparators remain unsupported |
| Other OS/architecture combinations | Explicit unsupported backend | Native calls return `unsupported`; the library and RSP backend remain usable |

Native Windows launch converts the executable, arguments and working directory
from strict UTF-8. Invalid UTF-8 and embedded NUL characters are rejected before
calling `CreateProcessW`; the quoted command line is bounded to 32,766 UTF-16
characters so its terminator fits the Win32 32,767-character limit. This avoids
silently replacing malformed input or passing a truncated command line.

Darwin selects its Mach/ptrace backend only on macOS. Linux backend selection is
explicit. Known x86-64 and AArch64 CMake processor names select their matching
ptrace implementation. Other Linux processor names select the unsupported
backend instead of compiling x86-64-only ptrace code and failing later with an
architecture preprocessor error. This is a build-selection safeguard, not
native support for those architectures.

On Darwin AArch64, a SIGTRAP is attributed to an owned data watchpoint only
when the saved ESR identifies a watchpoint exception, marks the comparator
index valid and precise, and that index names an enabled debugger-owned slot.
Other traps, invalid or possibly false-positive ESR records, and unowned
comparator hits remain generic breakpoint events.

The Linux x86-64 ptrace backend uses the x86 debug-register slots for both
64-bit and compat i386 processes. i386 requests are range-checked to 32-bit
addresses, and data breakpoint widths are limited by the i386 debug-register
encoding. Both modes expose four hardware slots; execute breakpoints use a
one-byte encoding, while data breakpoints support write or read/write access
at aligned 1-, 2-, or 4-byte widths. The x86 debug registers cannot represent
read-only watchpoints.

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
that do not write PC. It also follows A32 B/BL (including known NZCV
conditions), A32 BX/BLX register and BLX immediate, Thumb 16-bit B/B<cond>,
Thumb BX/BLX register, and Thumb BL/BLX immediate. A32 BLX immediate uses the
split signed displacement from PC+8, applies H as displacement bit 1, and
switches the successor to Thumb state. Thumb BL reconstructs the signed
25-bit displacement from S/J1/J2 and the immediate fields relative to PC+4;
Thumb BLX immediate uses the same J-bit transform, word-aligns PC+4, and
switches the successor to ARM state. These wide branches require the final IT
slot when inside an IT block and use checked target alignment and range,
following the [Arm BL/BLX immediate definitions](https://documentation-service.arm.com/static/5f8daeb7f86e16515cdb8c4e).
Branch targets and ARM/Thumb interworking are derived from the
stopped context. A32 `LDR pc, [pc, #+/-imm12]` now reads the literal word
from the stopped process, evaluates the instruction condition, and derives the
successor instruction state from the loaded address low bit; unreadable literal
data and unaligned ARM-state targets fail the step without resuming the target.
Thumb `POP {reglist, pc}` T1 is followed by reading only the PC word at
`SP + 4 * popcount(reglist)`. The encoded stack extent and alignment are checked;
the loaded low bit selects Thumb versus ARM state, and the remaining target
alignment is validated. An unreadable stack word, malformed range, or invalid
ARM-state target fails closed. Inside an IT block, this PC-writing form is
accepted only in the final slot and the active predicate determines whether
the stack word is read. The debugger does not emulate the POP register or SP
updates; the target executes the original instruction after its successor trap
is installed. The PC load's interworking behavior follows Arm's
[Thumb POP definition](https://class.ece.iastate.edu/cpre288/resources/docs/Thumb-2SupplementReferenceManual.pdf).
A32 ordinary `LDMIA`, `LDMIB`, `LDMDA` and `LDMDB` with PC in the register
list are followed using one four-byte read of the highest register's transfer
slot. The condition is evaluated before any memory read. General and control
registers are both requested from Windows so register-based successors use
captured values. The debugger checks word alignment, the complete transfer
extent, optional writeback range, and loaded ARM/Thumb target alignment.
PC bases, writeback with the base in the list, big-endian data state, and
`S=1` user-bank/exception-return forms reject before mutation. A successor
trap overlapping the current instruction or any loaded register's transfer
slot also rejects, preventing the trap from changing values the instruction
will read. The target executes the original LDM, including register/writeback
updates, under the existing peer-suspension and temporary-trap rollback path.
Addressing order and PC interworking follow the
[Armv7-A/R LDM definitions](https://documentation-service.arm.com/static/5f8daeb7f86e16515cdb8c4e).
The A32 LDM addition passed a Windows x64 Debug debugger build and an ARMv7
Windows clang-cl syntax check against the installed MSVC/Windows SDK headers;
native ARM32 linking and runtime stepping remain unverified. The context
request follows Windows' [GetThreadContext flags contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext).
Unconditional Thumb-2 B.W is decoded with its T4
J1/J2-immediate transformation and 25-bit signed displacement, and conditional
Thumb-2 B<cond>.W uses the T3 direct J1/J2 fields and signed 21-bit
displacement. Conditional wide branches require a valid condition and, inside
an IT block, a matching final-slot predicate. Thumb CBZ/CBNZ are also decoded
from their low-register operands; they compare without consuming NZCV and
branch forward from Align(PC, 4) using the encoded imm6 offset. CBZ/CBNZ are
prohibited in IT blocks, so the backend rejects them there. If the comparison
is false, the step successor is the next halfword. Other PC-relative register
branches, other PC-writing instructions, unknown encodings, and a successor
overlapping a user breakpoint remain unsupported. Thumb-2 LDMIA/LDMDB forms with
PC in the register list are followed for supported non-PC bases and unambiguous
register lists, including writeback when the base is outside the list. A32
exception-return loads remain unsupported because the backend cannot prove the
restored SPSR state. Thumb-2 TBB/TBH is followed
using the stopped register context and the selected byte or little-endian
halfword table entry; the entry is scaled by two and added to PC+4. The PC may
serve as the table base, while SP/PC index registers and SP base use are
rejected. A false IT predicate advances to the next instruction; an executed
table branch is accepted only in the final IT slot. Unreadable table entries
fail the step without resuming the target. The implementation follows the
[Arm TBB/TBH operation and constraints](https://web.eecs.umich.edu/~prabal/teaching/eecs373-f10/readings/ARMv7-M_ARM.pdf).
A Thumb branch in an active IT block is
accepted only in the final slot, and the IT predicate is applied before
choosing its destination; conditional branches in IT must match the active IT
condition. Sequential instructions may be stepped from any IT
slot: nested IT encodings are rejected, the temporary Thumb BKPT traps
unconditionally, and the backend restores the exact advanced ITSTATE when it
rewinds the post-trap PC. For an accepted
step, the backend restores an owned breakpoint instruction if needed, patches
a temporary trap at the decoded successor, suspends peer threads, and
continues the event owner. Only that thread's breakpoint at the tracked
successor is classified as completion. At the next stop it rewinds PC and
ITSTATE, restores the successor bytes, and rearms the owned breakpoint.
Restoration failure keeps the event stopped and is retried before
continuation; the temporary breakpoint exception must be continued as
handled. Windows ARM32
hardware breakpoints use up to eight BVR/BCR execute comparators exposed by the Windows ARM32 context ([Armv7-A/R Architecture Reference Manual](https://developer.arm.com/documentation/ddi0406/b/Application-Level-Architecture/Introduction-to-the-ARM-Architecture/Debug)). Since hardware may implement fewer, each update verifies the programmed context and fails with `unsupported` if the requested comparator count is unavailable. Only execute
breakpoints are supported; data watchpoints remain unsupported. ARM addresses
must be four-byte aligned. Thumb addresses use the low address bit as a Thumb
tag, which selects the indicated halfword in the aligned word; the current API
therefore supports tagged 16-bit Thumb instruction breakpoints. Updates require
a pending debug event and are transactional across the current target threads.
New threads receive the active configuration at their creation event. The
backend preserves unowned comparators, rejects occupied slots and external edits
to owned slots, and matches execution stops to the configured instruction
addresses after clearing the low Thumb tag from both the configured and reported addresses. Removing breakpoints and detaching clear the owned comparators.
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
the ARM64 context flags ([`ARM64_NT_CONTEXT`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-arm64_nt_context), [`GetThreadContext`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)) and is restricted to the stop window while a debug event is pending. Register reads expose X0 through X30 and their W0 through W30 low-word aliases, SP/WSP, PC, CPSR, FP/LR aliases, V0 through V31 and their Q/B/H/S/D aliases, FPCR, and FPSR. W-register writes zero-extend into X; writes through overlapping aliases in one batch are rejected. Writes validate register sizes, keep PC instruction aligned and SP 16-byte aligned, restrict CPSR changes to NZCV flags, and reject X18/W18 writes because Windows reserves that register for the thread environment pointer. Vector state is the fixed 128-bit V register bank; scalable SVE/SME state is not exposed.

All Windows register reads and writes require a nonzero 32-bit thread ID and
verify that the opened thread still belongs to the debugged process before
requesting or changing its context. This prevents a truncated or
foreign-process thread ID from reaching the native context APIs.

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
limit documented in [Debugging on Arm64](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-arm64). Execution hit IDs are matched from the reported event address. For data watchpoints, Windows supplies the access kind and accessed address in the exception record; the backend matches that address against enabled owned watchpoint ranges and reports matching IDs. A missing or unmatched access record remains a generic watchpoint stop. Hardware breakpoints can only be changed during a pending debug event.

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
