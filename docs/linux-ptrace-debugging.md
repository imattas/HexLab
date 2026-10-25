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
FXSAVE state is restored if a subsequent GPR write fails. AVX-512/ZMM and other
XSAVE components are not exposed. Memory inspection and
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
error; compacted layouts are not guessed. YMM upper
halves and hardware debug-register breakpoints remain unsupported for i386.

Process discovery, launch, and attach report architecture from the target's
ELF class and machine fields. Malformed headers, unsupported endianness, and
inconsistent class/machine pairs are reported as `unknown`; launch and attach
do not label every target as x86-64. Target architecture selects x86-64 or i386
register state. Other ELF architectures are reported during discovery but
rejected by launch and attach because this backend does not implement their
register ABIs.

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

`NT_FPREGSET` represents the base FPSIMD view. SVE/SME vector and predicate
state, scalable vector lengths, and other arm64 extension state are not
exposed or modified. This implementation assumes the Linux arm64 UAPI
`user_fpsimd_state` layout and the `NT_FPREGSET` regset note number; it does
not infer layouts from arbitrary kernel responses. The current host is
Windows, so this Linux-only source path has not been compiled or exercised
here.

Memory writes require every tracked target thread to be stopped. Writes that
overlap active software breakpoints keep the `INT3` byte installed and update
the saved original byte, so removing the breakpoint restores the user's latest
edit instead of stale pre-breakpoint code. Writes are staged and attempted as
a range; on a ptrace failure the backend restores the original bytes and
reports if rollback also fails. The Linux lifecycle test edits the byte under
an active breakpoint, verifies that the trap remains visible, and checks that
removal restores the edited byte.

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
