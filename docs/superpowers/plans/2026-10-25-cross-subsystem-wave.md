# Cross-Subsystem Capability Wave Implementation Plan

> **For agentic workers:** Implement the scoped tasks independently; source-only compile verification is allowed. Do not add or run tests.

**Goal:** Advance four major HexLab capabilities: persistent signature recognition, supplementary DWARF type resolution, PE language-specific exception metadata, and x86 SIMD processing.

**Architecture:** Keep each deliverable inside its owning library/API and documentation, with bounded parsing and explicit unsupported states. Root reviews integrations and compiles affected source targets.

**Tech Stack:** C++20, existing HexLab libraries, wxWidgets desktop integration only if already required by an owning subsystem.

**Spec:** `docs/capabilities.csv` rows `analysis.signatures`, `loader.elf`, `loader.pe`, and `processor.x86_simd`.

## Global Constraints

- Preserve bounded parsing, cancellation, provenance, and fail-closed behavior.
- Do not touch active decompiler edits.
- Do not add/run tests or link targets.
- Preserve all existing `out/` contents.

## Review Focus

- Stale or mismatched recognition facts must not rename functions.
- Supplementary DWARF identities and offsets must be checked before resolving.
- PE handler payloads must be associated only with validated handler identities and bounded payload ranges.

### Task 1: Persistent signature recognition

Own `libs/analysis` and relevant project persistence/CLI integration. Persist recognition evidence with source identity and stale-fact checks; preserve ambiguity and no-auto-rename policy. Update signature documentation and ledger.

### Task 2: Supplementary DWARF references

Own `libs/symbols` and `libs/loaders` DWARF-specific files. Advance `.debug_sup` reference resolution under explicit identity validation and existing parse budgets; document supported versus unresolved cases.

### Task 3: PE language-specific exception metadata

Own PE exception metadata parsing/model/docs. Decode additional language-specific payload only where the handler RVA and payload bounds are validated; retain opaque data otherwise.

### Integration

Root reviews ownership and API interactions, then runs source-only compilation for changed targets. No test commands.

### Task 4: x86 SIMD processor coverage

Own `libs/processors` x86 SIMD decoding and execution semantics. Expand a cohesive SIMD family slice without modifying the active decompiler implementation; document exact support and gaps. Use source-only compilation only.

