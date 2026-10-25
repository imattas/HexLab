# Native Analysis Depth Wave Implementation Plan

> **For agentic workers:** Use independent subsystem ownership and task review. Compile only; do not add or run tests.

**Goal:** Improve ELF exception unwind metadata, native call semantics in the decompiler, and debugger-to-static navigation.

**Architecture:** Extend the existing ELF unwind parser, typed SSA pipeline, and wxWidgets debugger/workspace connection. Keep the three lanes independent and preserve conservative behavior whenever evidence is unresolved.

**Tech Stack:** C++20, existing ELF/DWARF metadata model, decompiler IR/SSA, wxWidgets, current project/workspace and debugger APIs.

**Spec:** `docs/superpowers/specs/2026-10-24-native-analysis-depth-wave.md`

## Global Constraints

- Preserve bounded reads, checked arithmetic, cancellation where supported, and explicit malformed/unsupported states.
- Do not change project or database formats; image-derived metadata must remain source-backed.
- Keep changes in separate loader, decompiler, and desktop file sets; root owns the capability ledger and combined integration.
- Do not add or run tests; compile affected Debug targets only.
- Do not read, write, clean, or build `out/`; do not activate the user's foreground application.

## Review Focus

- ELF augmentation lengths, pointer encodings/applications, indirect pointers, and FDE program boundaries must remain exact and bounded.
- Calls must snapshot ABI arguments before clobbering, invalidate overlapping register aliases, preserve callee-saved values, and create join phis.
- Debugger mapping must reject ambiguous modules, overflow, unmapped image ranges, stale documents/sessions, and non-PC event addresses.
- No unsupported ABI, pointer encoding, debugger target, or module mapping may be represented as resolved.

## Tasks

### Task 1: ELF `.eh_frame` C++ augmentations

**Files:** `libs/loaders/src/elf_unwind.cpp`, `libs/image/include/hexlab/image/elf_metadata.hpp`, `docs/elf-dwarf-unwind.md`, existing fixture data in `tests/elf_image_tests.cpp` (correct the encoded CIE pointer; add no test cases).

**Interfaces:** Consume existing ELF section and pointer readers. Extend `ElfEhFrameFunction` append-only with optional personality and LSDA metadata, source offsets, and encoding details. Keep existing `ElfUnwindRange` publication unchanged so function discovery receives accepted FDE ranges.

- [x] Parse the bounded CIE `z` augmentation payload in declared character order for supported `P`, `L`, and `R` fields; preserve unsupported-tag diagnostics.
- [x] Decode the FDE augmentation length and LSDA pointer with the CIE's LSDA encoding, then begin CFI instructions after the entire augmentation payload.
- [x] Resolve the FDE backward CIE pointer from the pointer field to the CIE record start, not the CIE identifier field.
- [x] Preserve valid unresolved indirect personality/LSDA references distinctly from malformed encodings; reject unsupported pointer applications and relocatable-object cases explicitly.
- [x] Document supported augmentations, retained source information, and remaining LSDA limitations.
- [x] Compile `hexlab_loaders` Debug (MSBuild exit code 0); inspect the parser paths for bounds and atomic section publication.

### Task 2: ABI-aware call outputs in native SSA

**Files:** `libs/decompiler/include/hexlab/decompiler/decompiler.hpp`, `libs/decompiler/include/hexlab/decompiler/type_recovery.hpp`, `libs/decompiler/src/ssa.cpp`, `libs/decompiler/src/type_recovery.cpp`, `libs/decompiler/src/optimizer.cpp`, `libs/decompiler/src/dead_code.cpp`, `libs/decompiler/src/call_effects.cpp` (new), `libs/decompiler/CMakeLists.txt`, `apps/cli/commands.cpp`, `apps/desktop/pseudocode_view.cpp`, `docs/decompiler-type-recovery.md`.

**Interfaces:** Add `AbiDescription::caller_saved_registers`; add `Call::register_writes` and parallel `register_output_versions`; expose `Result<LiftedFunction> prepare_call_effects(const LiftedFunction &, const AbiDescription &)`. This pass annotates calls before `to_ssa`. SSA captures `register_inputs` before defining outputs and uses the matching output version for a modeled `return_register`.

- [x] Populate caller-saved GPR, XMM, and represented flags for Windows x64 and System V AMD64; leave other ABIs unchanged and conservative.
- [x] Annotate calls, normalizing overlapping aliases and avoiding duplicate return-register definitions.
- [x] Include call outputs in SSA def/use collection, rename, and phi placement; preserve call argument snapshots and return typing.
- [x] Update type recovery, optimizer validation, constant invalidation, and dead-code use collection for the new call outputs. Keep current call optimization barriers.
- [x] Route CLI and desktop native decompilation through ABI call preparation before SSA when an ABI is known.
- [x] Document ABI coverage and remaining limits.
- [x] Compile `hexlab_decompiler` Debug, `hexlab_cli` Debug, and `hexlab_desktop_components` Debug (all MSBuild exit 0); inspect call and alias paths.

### Task 3: Debugger-to-static workspace navigation

**Files:** `apps/desktop/debugger_view.hpp`, `apps/desktop/debugger_view.cpp`, `apps/desktop/debugger_locals.hpp`, `apps/desktop/debugger_locals.cpp` or a new focused address-mapping helper, `apps/desktop/main_frame.hpp`, `apps/desktop/main_frame.cpp`, `docs/debugger-inspection.md`.

**Interfaces:** Extend `DebuggerView` construction with callbacks keyed by `DocumentId`: navigation to a static `Location` and a request to toggle a software breakpoint from the main-frame listing selection. Keep callbacks routed through `DocumentManager::navigate` and existing breakpoint APIs.

- [x] Create a checked runtime/preferred-image address mapping only for one exact normalized module path match with compatible nonzero image size and known target-process architecture equal to the static image architecture; never match by basename alone. Check arithmetic and mapped segment coverage.
- [x] Add navigation for the stopped thread's PC and the selected frame's PC through document-scoped callbacks and existing navigation history.
- [x] Add the Debug menu action to set/remove a software breakpoint from the current mapped listing selection using the inverse mapping.
- [x] Invalidate mapping after session, target module, document, or active-document changes; reject stale async inspection completion and ambiguous basename matches.
- [x] Surface clear reasons when navigation or breakpoint conversion is unavailable; do not use watchpoint data or non-PC event addresses for instruction navigation.
- [x] Document matching and mapping limits.
- [x] Compile `hexlab_desktop_components` Debug (MSBuild exit 0); inspect callback lifetime and stale-document guards.
- [x] Compile `hexlab` Release (MSBuild exit 0; produced `switch-desktop-build/bin/Release/hexlab.exe`).

### Root integration

- [x] Review subsystem changes for separate ownership, public record compatibility, and no schema changes.
- [x] Compile integrated `hexlab_desktop_components` Debug, `hexlab_cli` Debug, and `hexlab` Release outside `out/`.
- [x] Update evidence-backed capability rows in `docs/capabilities.csv`.
- [x] Run source whitespace and `git diff --check` review; `git diff --check` exited 0 (only line-ending conversion warnings).
- [x] Leave the overall IDA-class objective active; this wave does not complete the full reference capability inventory.
