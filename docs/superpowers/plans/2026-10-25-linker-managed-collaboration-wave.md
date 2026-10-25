# Linker, Managed Metadata, and Collaboration Wave

**Goal:** Advance three independent engine areas toward the full reverse-engineering product scope.

**Architecture:** Extend the existing bounded AMD64 COFF linker, managed metadata parser, and SQLite collaboration rebase engine in place. Preserve explicit unsupported results whenever the subset cannot prove correct linking, token identity, or merge intent.

**Tech Stack:** C++20, CMake monorepo, SQLite project store, existing archive/PE/CLI and managed CIL APIs.

**Spec:** `docs/superpowers/specs/2026-10-19-hexlab-design.md`

## Global Constraints

- Preserve the original C++20 monorepo and wxWidgets product scope.
- Do not interact with the desktop window; it stays on the user's second monitor.
- Do not add or run tests in this wave. Compile affected translation units/targets only.
- Preserve bounded input parsing, cancellation, checked arithmetic, and explicit unsupported cases.
- Each agent owns only its named subsystem source and focused documentation. The integrator owns the capability ledger and this plan. Do not edit tests, CMake/build lists, or another workstream's files.
- Do not clean `out/` or link a DLL into the running desktop process.

## Review Focus

- Duplicate COMDAT keys, malformed auxiliary records, discarded-section relocations, and associative cycles must never produce a wrong executable.
- TypeRef scopes, nested names, TypeSpec signatures, invalid coded indices, and recursive TypeSpec graphs must retain token identity or fail explicitly.
- Concurrent additions/deletions to references and code ownership decisions must not silently drop user edits or accept overlapping incompatible decisions.

## Independent Workstreams

### Task 1: AMD64 COFF COMDAT linking

**Files:** `libs/loaders/src/coff_link.cpp`; `docs/coff-static-linking.md`.

Implement bounded COMDAT section-definition auxiliary parsing and correct selection for the supported selection modes. Keep deterministic tie handling. Resolve external symbols through the chosen section definition, discard losing section payloads and relocations, and preserve associative ownership only when the parent selection is validated. For any mode or reference pattern that cannot be represented safely by the static PE output, fail explicitly rather than duplicate or guess. Document supported and unsupported selection modes.

Reference: Microsoft [PE/COFF format, COMDAT sections](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

### Task 2: Managed TypeRef/TypeSpec resolution

**Files:** `libs/loaders/include/hexlab/loaders/managed.hpp`; `libs/loaders/src/managed.cpp`; `docs/managed-call-signatures.md` and/or `docs/managed-metadata.md`.

Extend the existing bounded signature/catalog flow to resolve TypeDefOrRef coded indices across TypeDef, TypeRef, and TypeSpec records. Preserve original metadata tokens and nested TypeRef resolution scopes. Parse TypeSpec blobs with the existing signature grammar, bound recursion and row/string/blob reads, detect cycles, and retain unresolved external assembly scopes as explicit unresolved identities rather than inventing local definitions.

Reference: ECMA-335 metadata TypeRef and TypeSpec tables and signature grammar.

### Task 3: Collaboration references and analysis decisions

**Files:** `libs/database/src/collaboration.cpp`; `docs/collaboration-ui.md`.

Extend caller-rebased conflict acceptance to `ReferenceChange`, `RegionChange`, and `FunctionChange`. Merge only provably independent or convergent operations; allocate fresh IDs for safe insertions when a concurrent edit used the proposed ID; reject stale before-values, semantic collisions, and overlapping incompatible ownership ranges so proposals remain available for review. Keep commit and conflict resolution atomic under the existing revision check.

## Integration

- Review selection, token-resolution, and three-way-merge invariants against the current APIs.
- Compile each affected library/source without running tests or linking into the desktop process.
- Update capability evidence only after source review and compile success.
- Record remaining boundaries; the full product objective remains active after this wave.

## Wave Progress

- **COFF COMDAT:** the AMD64 static linker validates section-definition auxiliary records and supports `NODUPLICATES`, `ANY`, `SAME_SIZE`, `EXACT_MATCH`, `LARGEST`, and same-object `ASSOCIATIVE` parent chains. It lays out only selected sections, redirects external references to the selected provider, and rejects discarded local references, unsupported `NEWEST`, malformed chains, and extended relocation-overflow sections. `hexlab_loaders` Debug `ClCompile` passed; no tests or link ran.
- **Managed TypeRef/TypeSpec:** `parse_managed_type_catalog` retains TypeRef/TypeSpec tokens, resolves nested TypeRef names/scopes, and resolves signature coded indices to TypeDef/TypeRef/TypeSpec tokens. External AssemblyRef/ModuleRef and null scopes remain unresolved; invalid tags/rows and nested/TypeSpec cycles fail. Direct `managed.cpp` compilation and integrated `hexlab_loaders` Debug `ClCompile` passed; no tests or link ran.
- **Collaboration:** references merge field-wise and convergent insertions; region extents merge atomically; function entries/chunks merge only when ownership changes are independent or convergent. Conflicting proposals remain pending, and projected range checks use sorted indexes, cancellation checks, and a conservative candidate-work limit. `hexlab_database` Debug `ClCompile` passed; no tests or link ran.
- The capability ledger is updated. The full IDA-scale objective remains active; network collaboration transport and type-definition rebasing remain open.
