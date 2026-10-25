# Binary analysis validation

Validated on Windows x64 with MSVC 19.44, Windows SDK 10.0.26100.0 and the pinned wxWidgets 3.2.12 checkout. The implementation follows the approved binary-analysis specification and plan. Full application scope remains active.

## Executed verification

| Configuration | Result | Scope |
| --- | --- | --- |
| Debug desktop | 13/13 CTests passed | Core, image, PE/raw loaders, original processor, self-authored LEA CPU oracle, analysis, workspace, paging/jobs, CLI integration, fixture-backed desktop, both foundation docking regressions |
| Release headless | 10/10 CTests passed | All engine and CLI tests plus the self-authored CPU oracle; checks remain active in Release |
| Disconnected headless | 10/10 CTests passed | `out/build/binary-analysis-offline` was configured fresh and rebuilt after the LEA correction; `FETCHCONTENT_FULLY_DISCONNECTED=ON`; no `_deps` directory |
| Installed distribution | Passed | Fresh `out/install/BinaryAnalysisDebug`; six engine DLLs, import libraries, generated headers, wx runtimes, notices, installed inspect/disassemble and launch/floating checks |
| Installed engines with GUI components | Passed | Real desktop integration driver copied to `out/installed-binary-tests`, separate from build DLLs; installed bin directory supplied through PATH |

Commands and detailed logs remain under `out/`: `desktop-binary-build.log`, `binary-analysis-release-build.log`, `binary-analysis-offline-configure.log`, `binary-analysis-offline-build.log`, `binary-analysis-install.log`, and CTest `Testing/Temporary/LastTest.log` in each build tree. All tests use original generated fixtures. No input executable was executed as a target.

`tests/support/pe_fixture.hpp` defines literal PE32/PE32+ fixtures, section mappings, imports by name/ordinal, exports/forwarders and relocation blocks. Tests check truncation, integer/range boundaries, zero fill, gaps, malformed optional metadata and adjacent initialized mappings. Raw fixtures pin architecture, base, entry, permissions and unknown-format behavior. Read-only file handles retain stable mapped bytes and block modification while held.

`tests/processor_tests.cpp` pins register identity, operand widths, addressing, displacement, flow and exact length for enabled forms, including truncated multibyte cases and unsupported extensions. `tests/fixtures/x64_scalar.asm` was independently assembled with MASM and checked with dumpbin; artifacts are `out/x64_scalar.obj` and `out/x64_scalar-disasm.txt`. This selected independent cross-check does not establish all x86-64 encodings. See `x64-coverage.csv` for partial families and missing variants.

The follow-up LEA audit reproduced incorrect FS/GS register dependencies and suppressed effective-address resolution in already supported LEA forms. New regression cases failed with 10 processor assertions and two CPU-oracle assertions before the correction. LEA now omits ignored segment bases from its effective operand facts while preserving original encoded bytes; actual FS/GS memory loads retain their segment dependency. `tests/processor_lea_cpu_tests.cpp` calls only the self-authored leaf functions in `tests/fixtures/x64_lea_segments.asm`, checking absolute/based results and wrapping against decoder facts. This test runs on the verified MSVC x64 configuration, without executing an opened target. Compiler options are scoped to C++ so they do not leak into MASM. Latest build logs are `out/lea-regression-build.log`, `out/lea-desktop-build.log`, `out/lea-release-build.log` and `out/lea-offline-build.log`.

Reachability fixtures cover loops, branches, direct calls, unreachable data, indirect targets and invalid/unsupported/truncated stops. Strings are bounded, chunked ASCII and UTF-16LE candidates, including surrogate and chunk-boundary checks; the printable-scalar heuristic can include false positives. String previews are bounded while records retain full extents. Budgets produce explicit incomplete results.

Reachable decoding now reuses a bounded 4 KiB source window instead of issuing a separate backing read for each instruction. Refills stop at initialized executable segment extents and `Image::code_window` policy boundaries, with per-address checks retained for aliases. `tests/analysis_tests.cpp` exercises a 256 KiB mapped-file linear scan and an exclusion/refill case. One Windows x64 Debug run reported 262,145 instructions in 7,666 ms with 187 backing reads (2 of at most 15 bytes) and 4,191,857 requested bytes; the previous per-instruction fetch path would add 262,145 small code reads to the same string-scan workload. This timing is a local microbenchmark, not a cross-machine latency claim.

## Desktop evidence

The real wx event loop opens generated PE fixtures and checks entry `0x140001000`, file offset `0x200`, NOP/RET rendering, single-click instruction/byte/string selection into synchronized locations, nonfirst branch follow/back/forward, both jump-dialog location modes, invalid numeric and unmapped jumps, raw-dialog overflow/entry validation, clipboard bytes/text/address, failed replacement, cancellation, rapid replacement with an empty raw image, compact layout, floating pane reset and closing during active analysis. Ticket reduction tests separately check reversed/stale completion behavior deterministically.

Workers never access windows. The controller polls a job mailbox on the GUI thread, invalidates canceled tickets, and joins its worker during destruction before child windows are destroyed. View pages are bounded; virtual controls do not preformat an entire input. Selecting an addressable row navigates; double-click also works. Instruction rows distinguish reachable instructions, manual decode and data. Byte rows distinguish file backing from synthesized zero fill. Native row rendering is suspended during model replacement, including deselection notifications that can request old rows.

Actual installed-app screenshots were captured and visually inspected:

- `out/binary-analysis-disassembly.png`: entry bytes, original decoded text and reachable/data labels.
- `out/binary-analysis-bytes.png`: bytes, ASCII preview and backing column.
- `out/binary-analysis-strings.png` and `out/binary-analysis-imports.png`: actual parsed fixture records.
- `out/binary-analysis-small.png`: 900 by 650 window; metadata moves below the listing so addresses and bytes remain readable.
- `out/binary-malformed-disassembly.png`: truncated PE diagnostic in Output and status.

Captures use only the application's own window. Native notebook clicks were used because the local UI Automation tree did not expose notebook tab items. This is not an accessibility audit. Physical keyboard focus, high DPI, screen readers and other operating systems remain unverified. Horizontal scrolling is available for long metadata and instruction text.

## Distribution and limits

`out/binary-analysis-dependents.txt` records dumpbin imports. The GUI imports workspace, processor, core and wx DLLs; workspace imports image, loader and analysis engines. Every engine DLL is free of wx imports. The CLI uses the same engine services without a GUI dependency. This developer Debug distribution requires the installed Microsoft Debug runtime; fresh-machine redistributable packaging is still pending.

PE normal and delay imports, exports and base relocations are parsed with source provenance. `load_pe_at_base` applies supported relocation records through an immutable overlay; the original file remains unchanged and preferred/runtime bases stay distinct. Delay descriptors and thunk walks are bounded by directory/image mappings; RVA-based descriptors and legacy VA-based PE32 descriptors are exposed with source spans. See `pe-relocations.md` for the exact machine/type inventory and limits. Bound-import tables and other nonempty directories are reported as unsupported; malformed optional tables preserve useful image data with diagnostics. Only raw x86-64 and PE32/PE32+ are implemented. Other CPU metadata may be inspectable, but only the documented x86-64 subset has instruction analysis. SIMD, x87, full prefix/width coverage and semantic lifting remain absent or partial.

Entry/direct-target candidates are not complete functions. Bounded function/chunk recovery now uses typed flow facts for x86-16/32/64, A64, RV32/RV64/RV64C and NMOS 6502; A32 remains guarded until predicate-aware PC-write and return modeling is integrated. The exact partial boundary is documented in [multi-architecture function recovery](function-recovery-multiarc.md). Persistent project depth, broader processor coverage, names/comments editing, type systems, decompilation, debugging, scripting and the extension SDK remain active work. Windows results do not verify Linux/macOS. No Git commits were fabricated: repository identity remains unset, so source and evidence are preserved in the working tree.

## Independent review

One independent read-only review found no Critical findings and two Important findings: selection was routed only on activation while Copy/Follow used the first page row, and accepted LOCK instructions lost their modifier in typed facts and formatted text. Both received failing regression tests before fixes. Selection now routes through the shared location and commands resolve the corresponding row; valid LOCK is retained explicitly and rendered, while invalid LOCK forms still fail. The whole Debug desktop and Release headless suites were rerun after the fix pass.

Deferred minor: document-dependent menu commands remain enabled on the welcome screen; later command routing work will disable unavailable operations. The review did not establish exhaustive hostile-input safety, production-scale performance, full ISA coverage, other platforms, accessibility, or fresh-machine packaging. Those remain explicit inventory gaps rather than accepted claims of full application completion.


# x86-64 indirect control references

Reference derivation resolves register-indirect calls and jumps when a full-width
`mov reg, imm64` or RIP-relative `lea reg, [rip+disp]` in the same basic block
establishes a target in an executable image segment. Any subsequent write to
that register clears the fact before it can be used. The analysis deliberately
does not carry these facts across blocks or infer values from partial-width
writes, memory loads, arithmetic, phis, or calls; those targets remain explicit
unresolved register expressions. `tests/reference_tests.cpp` covers successful
resolution and write invalidation in the focused `references` CTest.
