# Independent authored16 execution oracle

This test boots original fixed assembly under two pinned external emulators.
Neither emulator nor NASM is linked into HexLab or installed with the application.
Only this authored image is executed; user binaries are never used as test code.

Run `powershell -NoProfile -File tests/provision_x86_16_tools.ps1 -Download`
once. The script verifies pinned archives, extracts into `out/tools`, checks the
executables/firmware and preserves vendor notices. It never executes an installer.
`-Offline` verifies/reconstructs the same local tools from cached archives without
network access. See `tools.json` for exact URLs, archive hashes, binary/firmware
hashes and the distinction between publisher hashes and observed HTTPS hashes.
A current7-Zip supporting NSIS is required for first extraction; the Lua9.10
copy on PATH cannot read these installers. No global package installation occurs.

Build tests normally and run `ctest --preset windows-headless -R x86_segment_cpu`.
Missing tools, changed hashes, missing records and wrong measured values fail.
Each execution has an8-second deadline. The machines have no network devices,
host mounts, monitor or interactive display and use a readonly authored floppy.

QEMU's pinned Windows snapshot reports11.1.0-12130-ge470268ff4. It independently
executes14 safe size/default-segment/alias/A20 records under TCG's pentium3 model.
The initial full run exposed EIP truncation at a translated-page boundary and
omitted ordinary segment-limit checks. It is therefore not the boundary oracle.
This matches QEMU's documented limitations concerning per-access segmentation;
see the [developer discussion](https://lists.gnu.org/archive/html/qemu-devel/2019-02/msg07133.html)
and [translator implementation](https://github.com/qemu/qemu/blob/master/target/i386/tcg/translate.c).
No production semantics were changed to match that observed emulator limitation.

Bochs3.1, p3_katmai model, executes the full24 records: real and protected defaults,
DS/BX versus SS/BP, aliases and A20, stack value16/32 and independent SS.B, high
EIP sequential/untaken/taken paths, near CALL16 return truncation, far CALL/RETF
16/32 stack slots, a real complete-access limit fault, a protected data fault,
and a protected code-limit fault recording full EIP10000. The image is the same
probe with only the final host-control sequence changed. QEMU's subset exits
through isa-debug-exit; Bochs prints DONE and enters CLI/HLT. Its host runner
requires that completion record while the process is alive, then stops only its
own emulator process. Earlier faults/crashes, excessive output and timeouts fail.
This avoids the vendor Windows binary's intermittent ACPI cleanup access violation.

The observed default16 rules preserve full EIP for ordinary continuation and an
untaken conditional path, use a16-bit taken target where the encoding specifies
it, and push only low IP for a16-bit near CALL. A large D0 code segment permits
high EIP; a64KiB code segment faults at EIP10000. These agree with Intel's
[segmentation rules](https://cdrdv2-public.intel.com/819714/253668-sdm-vol-3a.pdf)
and [mixed16/32 and real-mode rules](https://cdrdv2-public.intel.com/874250/253669-090-sdm-vol-3b.pdf).
These are emulator observations under the stated models, not measurements on
physical386/286/8086 CPUs. Those generation variants remain open in the full matrix.

The STL-only checker checks literal values and complete record identity; it does
not call HexLab's decoder. Task4 separately compares original decoder facts with
these executed byte sequences. Artifacts include images, NASM listings, native
records and Bochs logs under each build's `tests/x86-segment-oracle/<config>`.
