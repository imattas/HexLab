# Linux native debugger backend

On Linux x86-64, `make_native_backend()` selects the x86-64 ptrace backend. It uses
`/proc` for process and thread enumeration, `fork`/`execv` plus
`PTRACE_TRACEME` to launch, and ptrace seize/interrupt to attach. Events are surfaced
as explicit `DebugSession` event sequences and require `continue_execution` or
`single_step_execution` acknowledgement. General register inspection and
mutation use the Linux x86-64 `user_regs_struct`; x86-64 additionally exposes
the x87 control/status fields, 80-bit `st0`-`st7`, `mxcsr`, and `xmm0`-`xmm15`
through the Linux FXSAVE-compatible FP state. When the host CPU and kernel expose
the standard-format `NT_X86_XSTATE` regset with a complete AVX component, it also
exposes the 128-bit upper halves as `ymm0h`-`ymm15h`; `xmmN` continues to name the
low half. The backend checks XSAVE/OSXSAVE and CPUID leaf `0xD`, validates the
returned regset length and component layout, and omits the upper-half bank when
the capability is unavailable. Compacted XSAVE images are rejected. FP and GPR
register writes validate all fields before applying, and the original XSAVE or
FXSAVE state is restored if a subsequent GPR write fails. Other XSAVE
components are not exposed. When the host, kernel, and target expose the
standard-format AVX-512 XSAVE components, the register view additionally
includes `zmm0`-`zmm31` (64 bytes each) and `k0`-`k7` (64 bits each). The backend
checks CPUID component offsets/sizes, OSXSAVE/XCR0 enablement, regset extent,
and rejects compacted layouts. Writes through overlapping `xmmN`, `ymmNh`, and
`zmmN` names are accepted only when overlapping captured bytes agree; conflicts
are rejected before any register bank is written. Memory inspection and
software execution breakpoints use `PTRACE_PEEKDATA`/`PTRACE_POKEDATA`. A 64-bit tracer also
supports ELF32 i386 targets through the 32-bit `NT_PRSTATUS` register set,
including 32-bit register reads and writes, instruction-pointer correction for
software breakpoints, single stepping, and `INT3` software breakpoints. For
i386 floating-point state, the backend reads and writes the standard-format
`NT_X86_XSTATE` legacy FXSAVE area. It exposes the 32-bit FPU instruction/data
pointers and selectors, x87 `st0`-`st7`, `mxcsr`, and `xmm0`-`xmm7`, validating
the compat widths and preserving the rest of the XSAVE image on writes. Mixed
GPR and FPU/SSE writes restore the original XSAVE image if a later GPR update
fails. Kernels without a usable standard-format XSAVE regset return an
GPR-only register view, and FP/SSE writes return an explicit unsupported
error; compacted layouts are not guessed. When the host exposes the AVX
component and the target regset contains its standard-format layout, the i386
view also exposes and edits `ymm0h`-`ymm7h`, preserving all other XSAVE bytes
and restoring the original vector image if a later GPR update fails. These are
the eight compat upper 128-bit lanes; AVX-512 state and hardware debug-register
breakpoints remain unsupported for i386.

The backend also supports a thread-qualified interrupt for one known-running
TID already seized and owned by the session. It sends `PTRACE_INTERRUPT` only
to that thread. The matching `PTRACE_EVENT_STOP` is retained even if peer-stop
collection observes it first, then surfaced as the session's single pending
event without interrupting other running peers. Acknowledging it with Continue
resumes only the event owner. The request is rejected if an event, poller,
global interrupt, step, rollback, or target cleanup is already active. Memory
and target-wide breakpoint operations continue to require an all-stop target;
the backend does not yet provide atomic per-thread run-state scheduling.

Process discovery, launch, and attach report architecture from the target's
ELF class and machine fields. Malformed headers, unsupported endianness, and
inconsistent class/machine pairs are reported as `unknown`; launch and attach
do not label every target as x86-64. Target architecture selects x86-64 or i386
register state. Other ELF architectures are reported during discovery but
rejected by launch and attach because this backend does not implement their
register ABIs.

While a stop event is pending, `DebugSession::signal_info()` returns the
selected event thread's raw `siginfo_t` bytes through `PTRACE_GETSIGINFO` on
Linux x86-64 and AArch64. The record is capped by the session's 64 KiB
inspection limit and remains target-ABI data; HexLab does not reinterpret
fields using the host ABI or translate signal-specific unions. Synthetic
ptrace events and group stops without a kernel siginfo record report
`unsupported`; the query does not acknowledge or resume the stop.

The thread list includes a separate `Kernel state` value read from field 3 of
`/proc/<pid>/task/<tid>/stat` on Linux x86-64 and AArch64. It handles the
parenthesized command field by locating its final closing parenthesis, and
leaves the value empty if the proc entry disappears or the record is malformed.
The label preserves Linux's state code, such as `R (running)`, `S (sleeping)`,
`t (tracing stop)`, or `Z (zombie)`. This is a point-in-time scheduler snapshot;
the debugger's separate `State` column remains based on ptrace tracking and
owned stop events. Kernel sleeping/stopped states do not change thread resume
eligibility or resume behavior.

On Linux AArch64, the native ptrace backend exposes the 34 64-bit
`NT_PRSTATUS` registers and, when the kernel accepts `PTRACE_GETREGSET` with
`NT_FPREGSET`, also exposes `v0`-`v31` as 16-byte values plus 32-bit `fpsr`
and `fpcr`. This follows the fixed 528-byte arm64 UAPI `user_fpsimd_state`
layout: 32 128-bit vector slots, the two status words, and two reserved
32-bit words. The backend requires the returned regset length to match that
layout exactly and retains the reserved words when writing. If the kernel
does not provide the regset (for example, `EINVAL`, `EIO`, `ENODEV`, or
`ENOSYS`), reads return the GPR view and an FP/SIMD write reports unsupported.
Register writes validate every name and byte width before applying changes;
unrequested regsets and bytes within each FPSIMD image are preserved. Mixed
GPR/FPSIMD updates snapshot both banks, apply FPSIMD then GPR, and attempt to
restore both snapshots if either update fails. Single-bank update failures
also trigger a best-effort restore. Ptrace has no atomic multi-regset
transaction; a failed rollback is reported and can leave mixed state.

When the target kernel exposes `NT_ARM_PAC_MASK`, register inspection also
includes read-only `pac_data_mask` and `pac_instruction_mask` 64-bit values in
the `system` group. These are the distinct TTBR0 data-pointer and
instruction-pointer PAC masks defined by the Linux arm64 UAPI. They are
omitted when the regset is unavailable; an unexpected returned size is treated
as malformed instead of being guessed. The masks describe PAC bit positions,
not authentication keys, and are not suitable for interpreting TTBR1/kernel
pointers.

`NT_FPREGSET` represents the base FPSIMD view. When `NT_ARM_SVE` is available,
the register view also exposes the active vector length, `z0`-`z31`,
`p0`-`p15`, `ffr`, and FPSR/FPCR; `vN` and `dN` remain aliases of the low
128- and 64-bit portions of `zN`. SVE register writes preserve the rest of the
returned regset and reject conflicting writes through aliases. SVE vector
length metadata is read-only here. Optional SME streaming state is exposed as
separate read-only `ssve_*` registers, with bounded `za_row*` matrix rows,
`zt0`, and the extended `tpidr2_el0` TLS slot. Variable SSVE and ZA snapshots
validate header/layout/response consistency under 512 KiB and 1 MiB payload
bounds respectively. Inactive banks expose metadata without guessed values;
normal vector writes reject during active streaming to avoid changing mode.
See [AArch64 SME inspection](../libs/debugger/docs/linux-aarch64-backend.md).
The implementation validates Linux arm64 UAPI regset lengths and
layout bounds rather than guessing layouts from arbitrary kernel responses.
Native AArch64 SME runtime validation remains outstanding.

The Linux AArch64 backend can read MTE allocation tags through
`PTRACE_PEEKMTETAGS` when the kernel and target mapping support it. This is
available through `DebugSession::read_memory_tags` with GDB ARM tag type `1`;
logical tag type `0` and tag writes remain unsupported. Reads require all
traced process threads to be stopped and are bounded to the selected address
range and caller result limit. The kernel aligns an unaligned address down to
its 16-byte MTE granule and may return fewer tag bytes than requested when the
range ends at inaccessible or untagged memory. The UI displays each returned
byte in the valid 0x0..0xF range as the allocation tag for one 16-byte granule,
with its aligned address and offset; it keeps short reads short and marks omitted
granules unknown. Kernels without the request report unsupported, while
invalid or untagged ranges retain the kernel error. See the [Linux MTE ptrace
interface](https://www.kernel.org/doc/html/latest/arch/arm64/memory-tagging-extension.html#the-ptrace-interface)
and [GDB ARM memory tag types](https://sourceware.org/gdb/current/onlinedocs/gdb.html/ARM-Memory-Tag-Types.html).

Memory writes require every tracked target thread to be stopped. Writes that
overlap active software breakpoints keep the `INT3` byte installed and update
the saved original byte, so removing the breakpoint restores the user's latest
edit instead of stale pre-breakpoint code. Writes are staged and attempted as
a range; on a ptrace failure the backend restores the original bytes and
reports if rollback also fails. The Linux lifecycle test edits the byte under
an active breakpoint, verifies that the trap remains visible, and checks that
removal restores the edited byte.

For x86-64 and i386 software breakpoints, installation rejects an existing
unowned `INT3` instead of adopting it as a debugger trap. The backend retains
at most 4,096 software-breakpoint records, including disabled records. Before
displacing a trap for Continue or Step, it verifies the exact `INT3` byte
before changing PC. Restoring the original instruction and reinserting the
trap both compare the expected owned byte first. Step rollback and rearm
retries accept an already rearmed trap, or the exact saved original byte;
different bytes return a conflict and remain untouched. A rearm failure is
included in the visible stop's message and blocks further resume until
recovery succeeds. This covers self-modifying instructions and external code
changes without silently replacing them with an old instruction or trap.

Detach stops all owned threads and preflights every software-breakpoint byte
before rewinding any PCs or restoring any instructions. Disabled breakpoints
must still match their saved original; an active displaced instruction can
match its saved original or rearmed trap. If restoring a later breakpoint
fails, the backend retains the exact addresses already restored. A retry
verifies those original bytes and resumes the remaining cleanup rather than
expecting traps at every address. Ownership records and ptrace attachment
remain until cleanup succeeds; memory/register edits, breakpoint mutations,
event polling and resume are blocked once detach preparation starts. Retry
detach after correcting the cause, or explicitly terminate the target.
No forced overwrite or detach-on-conflict fallback is performed.

These checks use the stopped-tracee memory operations described by
[Linux ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html).
Reads and writes are separate syscalls, so this is not atomic against an
independent process writing the same address. Runtime failure-injection and
live i386 validation remain outstanding; this slice adds no tests.

Attach is subject to the kernel's ptrace access policy (including Yama,
credentials, and capabilities). The backend requires a Linux x86-64 tracer and
supports x86-64 and i386 tracees. It seizes and interrupts every task in
`/proc/<pid>/task`, then rescans
until two consecutive task snapshots agree and all observed threads are
stopped. Attach is rolled back if enumeration, permissions, or stabilization
fails; process churn is capped at 4096 threads and 16 scans. This closes the
former gap where attach could return with worker threads still running.

On x86-64, execute and data breakpoints use the four per-thread DR0-DR3 slots,
DR7 local enables, and DR6 status. Execute requests require size 1; watchpoint
sizes are 1, 2, 4, or 8 bytes and must be naturally aligned. Read watchpoints
use the x86 read/write condition and can also stop on writes. Hardware changes
are accepted only while a debug event is pending and every tracked thread is
stopped. The backend verifies existing DR0-DR7 state against its owned slots,
updates all stopped threads with rollback on a partial failure, and clears
owned state before detach. A thread reported by a clone event receives the
currently owned slots before it is resumed. DR6 B0-B3 bits map back to owned
breakpoint IDs in `DebugEvent::breakpoint_ids`; status bits outside the
debugger's slots are preserved when the owned status is cleared.
`DebugSession::set_breakpoint_enabled` toggles an owned hardware slot without
changing its ID. The new configuration is applied to all stopped threads with
the same rollback behavior as add/remove; disabled records do not consume DR
slots or receive hit attribution. The toggle is rejected unless all traced
threads are stopped.
The kernel does not provide an atomic write across several thread register
sets; if a rollback write also fails, the returned diagnostic reports that
some threads may retain mixed state.

Linux integration coverage includes an aligned eight-byte write watchpoint on
shared target memory. The test attaches before the child performs its store,
checks that DR6 identifies the debugger-owned watchpoint after the value has
changed, removes the watchpoint while the event is pending, and acknowledges
the stop so the child can exit normally. Hardware watchpoint addresses are
target virtual addresses; the hit event reports the owned breakpoint IDs and
the stopped instruction pointer.

When a Linux x86-64 compiler and 32-bit link runtime are available, debugger
CTest also builds a static i386 fixture and checks launch architecture,
register width and mutation, x87/SSE context read/write/restore,
software-breakpoint hit/step/restore, and the explicit hardware-breakpoint
limitation. Linux-only integration coverage launches and attaches traced children and
checks discovery, stop/register/memory-map inspection, continue, process exit,
hardware execute and write-watchpoint hit attribution, multi-thread DR
installation/removal, and attach cleanup. These checks require a Linux x86-64 build and a kernel configuration
that permits the test process to trace its child. A Windows-host build does
not compile or execute the Linux backend tests; Linux behavior remains
unverified on that host. The host-independent FXSAVE and XSAVE layout and
register-write validation checks run in the ordinary debugger unit test on
Windows as well as Linux. A Linux-host test also verifies live x87/XMM reads
plus an XMM write and restore at the launch exec stop, and writes/restores
`ymm0h` when the kernel exposes AVX state.
