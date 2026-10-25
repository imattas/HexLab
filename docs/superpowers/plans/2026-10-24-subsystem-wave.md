# HexLab Subsystem Expansion Work Plan

> **For agentic workers:** Use the subagent-driven-development workflow. Each workstream is an independent vertical slice and owns its implementation plus focused documentation.

**Goal:** Advance three major HexLab subsystems toward the approved full IDA-scale destination without coupling their implementation state.

**Architecture:** Keep debug-format semantics in the shared type importer, optimizer rewrites in typed IR passes, and target-specific process control in the Darwin debugger backend behind the existing backend API. The wxWidgets application and headless tools continue to consume the shared libraries.

**Tech Stack:** C++20, CMake, wxWidgets application shell, existing shared type/IR/debugger APIs.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Preserve the original C++20 monorepo and wxWidgets product scope.
- Do not launch, foreground, or interact with the desktop application.
- Do not add or run tests; compile changed Windows-supported library sources without linking DLLs loaded by the open app.
- Keep every parser, analysis, and optimization bounded, cancellable where the API supports it, and fail closed on ambiguity or unsupported semantics.
- Do not edit `libs/decompiler/src/decompiler.cpp`, `docs/decompiler-structuring.md`, active decompiler tests, or shared build/ledger files during parallel implementation.

## Independent Workstreams

1. **CodeView/PDB qualifier import** — decode `LF_MODIFIER` and supported pointer qualifiers into the shared qualified-type model, preserve references through graph resolution/import, and update the PDB type support docs. Own `libs/types/src/pdb.cpp`, `libs/types/src/pdb_import.cpp`, `libs/types/include/hexlab/types/pdb.hpp`, and PDB documentation only.
2. **Incremental analysis invalidation** — improve dependency precision for source/mode/context and user-decision changes so only affected strings, instructions, functions, and references are recomputed while stale facts remain impossible to publish. Own `libs/analysis/src/incremental.cpp`, `libs/analysis/src/dependencies.cpp`, necessary dependency recording in `libs/analysis/src/functions.cpp`, and analysis documentation.
3. **Darwin debugger multi-thread behavior** — extend the existing Darwin backend beyond its current single-thread execution restriction while preserving stop/resume, selected-thread stepping, breakpoint displacement, and cleanup invariants. Own `libs/debugger/src/native_backend_macos.cpp`, Darwin debugger docs, and platform build wiring only if necessary.

## Integration

- Review changes for file ownership conflicts, bounded work, rollback behavior, and truthful support documentation.
- Compile affected Windows-supported library targets without linking over the running app's loaded modules. Darwin code may receive source-level review only on this Windows host.
- Do not run tests in this wave.
- Update `docs/capabilities.csv` only after integration review.
- This wave does not reduce or complete the full IDA-scale objective.

## Wave Progress

- **CodeView/PDB:** `LF_MODIFIER` preserves const/volatile on referenced types. Supported flat `LF_POINTER` const/volatile/restrict flags qualify the pointer node; unsupported modes, unaligned bits, and reserved flags fail closed. Unknown high attribute bits are retained for rejection. LLVM's published [CodeView Type Records](https://www.llvm.org/docs/PDB/CodeViewTypes.html) document the option mask, pointer-size field, and flag definitions.
- **Incremental analysis:** identical source mapping and loader metadata now permit instruction-fact candidates across context/code-policy revisions. Recovery revalidates context, permissions, and bytes where ranges were not proven, then rebuilds current ownership/control flow/references. Strings are retained only when their address-to-file mapping is unchanged.
- **Darwin debugger:** task-wide suspension supports coherent bounded thread enumeration and thread register snapshots. Multi-thread attach and unattributed stop events remain unsupported; ptrace does not identify the Mach thread, so the backend does not invent event ownership or promise selected-thread stepping. The source needs Intel and Apple Silicon macOS validation.
- Windows Debug source compilation passed for `hexlab_loaders`, `hexlab_types`, `hexlab_analysis`, and `hexlab_automation` (`ClCompile`, no link). MSVC emitted the existing exported-`Type` DLL-interface warnings. No tests were added or run, and the desktop was not touched.
