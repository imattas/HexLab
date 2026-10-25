# Native Analysis Depth Wave Design

## Intent

Advance HexLab toward an original IDA-class reverse-engineering application by improving three workflows that currently lose useful information: exception-enabled ELF unwind metadata, caller-saved register flow through native calls, and movement between live debugger stops and the static project.

This design extends the existing modular C++20 engine and wxWidgets desktop. It does not replace any subsystem or use another reverse-engineering application as an embedded engine.

## Goals

- Parse bounded `zP`, `zL`, and `zR` augmentation payloads in ELF `.eh_frame`, retaining valid CIE/FDE range and source information even when personality pointers are unresolved.
- Model ABI-defined caller-saved GPR, SIMD, and represented flag outputs in SSA for Windows x64 and System V AMD64, preserving pre-call argument values and callee-saved registers.
- Let users navigate from a stopped thread/frame into the correct static document and create a live software breakpoint from a selected mapped address.
- Keep malformed, unsupported, ambiguous, stale, or unmapped evidence explicit and conservative.

## Non-goals

- Decode ELF LSDA call-site/action tables or execute language personalities.
- Add call-clobber semantics for unclassified ABIs or architectures.
- Change project/database formats, debugger backends, or target process control semantics.
- Claim complete IDA equivalence; this is one implementation wave in the broader approved roadmap.

## Constraints

- Preserve bounded reads, checked arithmetic, cancellation where already supported, and explicit unsupported results.
- Reparse image-derived loader metadata from retained source bytes; avoid redundant persistence.
- Preserve existing public aggregate initialization and ABI/API compatibility where practical; append fields when extending public aggregate records.
- Use source evidence and compile-only verification. Do not add or run tests in this wave.
- Do not access or modify `out/`; do not activate or move the user's foreground application.
- Keep source ownership separate: ELF loader; decompiler IR/SSA/call preparation; desktop debugger/static navigation.

## Approaches

1. **One subsystem at a time:** strongest isolation but advances only one major workflow per wave.
2. **Three independent subsystem lanes (selected):** gives useful progress across loader, decompiler, and desktop in parallel; requires explicit file ownership and a final integration pass.
3. **Broad shared refactor:** unify exception, call, and debugger address models before adding behavior; rejected because it couples unrelated public APIs and delays user-visible improvements.

The selected lanes use existing subsystem boundaries and integrate only through the existing loaded-image, IR, and desktop document APIs.

## Design

### ELF unwind augmentations

Extend the existing `.eh_frame` parser to support bounded CIE `P`, `L`, and `R` payloads for every ordering and subset composed only from those supported fields, in addition to empty and existing `zR` forms. Resolve each FDE's backward CIE pointer from the pointer field to the CIE record start, as required by `.eh_frame`. Decode augmentation data using its declared length and the augmentation string's field order; preserve the FDE instruction-program start after consumed augmentation bytes. Retain encoding and source offsets for personality and LSDA values. A valid indirect personality encoding may remain unresolved; it must not be treated as malformed or fabricated as a direct target. Unknown tags, unsupported applications/formats, malformed lengths, and relocatable-object cases remain explicit failures. Existing unwind-range consumers should receive accepted ranges without changes.

### ABI-aware call clobbers in SSA

Extend call IR with explicit clobber/output register metadata and add a convention-aware call-preparation pass for Windows x64 and System V AMD64. The pass snapshots arguments before defining volatile outputs, including the flags register where it is represented by the lifted IR. It handles register alias overlap so a call invalidates stale values in overlapping subregister views; callee-saved GPR values remain unchanged. SSA renaming creates new versions for call outputs and normal phis at control-flow joins. Typed return values remain represented once and are consistent with the corresponding call output. Unknown ABIs keep current conservative behavior. Existing optimizer barriers remain until a separate soundness review supports removing them.

### Debugger-to-static navigation

Add a document-scoped address mapping between a uniquely matched loaded module and the active static image. Require an exact normalized module path match, compatible nonzero image size, and a known process-target architecture equal to the static image architecture; never match on basename alone. Compare module-specific build identity when the loaded-module model exposes it, and reject known mismatches. The current `ModuleInfo` model has no per-module machine or build identifier, so document the process-architecture proxy and same-path replacement limitation. Also require checked base arithmetic, mapped image coverage, and a still-open matching `DocumentId` when asynchronous inspection completes. Expose navigation for the stopped thread's current PC and selected stack frame through the existing workspace navigation API. Add a Debug action to set/remove a software breakpoint at the current listing selection using the inverse mapping. Invalidate mappings when the target/module/document/session changes. Explain unavailable mappings in the debugger view. Watchpoint data and non-PC event addresses are never used for instruction navigation.

## Completion evidence

Each lane must compile its owning target, the combined desktop target must compile after integration, independent review must find no unresolved correctness issue, affected capability entries and subsystem documentation must match implementation, and `out/` must remain untouched. No tests are added or run under the current workspace constraints.
