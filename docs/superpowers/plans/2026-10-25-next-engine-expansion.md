# Native Engine Expansion Plan

> **For agentic workers:** Use the subsystem workstream assignments in `docs/superpowers/specs/2026-10-25-next-engine-expansion.md`. Keep changes in isolated worktrees and commit each completed workstream.

**Goal:** Add one substantial, bounded capability in x87 stack state, ELF32 runtime relocations, and PDB IPI/type-server resolution.

**Architecture:** Extend the existing processor, loader, and type-import pipelines independently. Preserve unknown or ambiguous states rather than inferring machine state, symbol identity, or type ownership.

**Tech Stack:** C++20, existing HexLab processor/loader/types libraries, CMake, Visual Studio Debug builds.

**Spec:** `docs/superpowers/specs/2026-10-25-next-engine-expansion.md`

## Global Constraints

- Preserve cancellation, bounds, and conservative behavior.
- Do not add or run tests; compile affected Debug targets only.
- Do not read, write, clean, or build `out/`.
- Keep all work headless; root owns `docs/capabilities.csv` and integration review.

## Review Focus

- x87 TOP rotation and tag updates must use the correct pre/post instruction state and must not infer values after opaque environment restore or ambiguous CFG joins.
- ELF32 arithmetic must preserve implicit addends, reject overflow, and never apply a partially validated relocation set.
- PDB IDs must resolve against the correct type-server identity and local index namespace; duplicate or cyclic identities must not select an arbitrary record.

## Tasks

### Task 1: x87 TOP and tag transitions

**Files:** `libs/processors/src/x64_x87.cpp`, `libs/processors/include/hexlab/processors/`, `libs/decompiler/src/`, and x87 documentation as needed.

- [ ] Inspect existing x87 register effects and stack-depth handling; define the smallest API-compatible TOP/tag state representation.
- [ ] Implement supported push/pop and TOP-rotation transfer semantics with conservative handling for unknown restores and joins.
- [ ] Document the modeled instruction subset and limits; compile affected processor and decompiler Debug targets.

### Task 2: ELF32 i386 runtime relocation application

**Files:** `libs/loaders/src/elf_dynamic_relocations.cpp`, relevant public ELF runtime relocation headers, and focused ELF runtime relocation docs.

- [ ] Confirm the existing ET_DYN overlay/transaction model and exact dynamic relocation table ownership.
- [ ] Add bounded i386 REL support for `R_386_RELATIVE`, `R_386_GLOB_DAT`, and `R_386_JMP_SLOT` using checked 32-bit addresses and exact external bindings.
- [ ] Keep unsupported rows explicit and preserve source-row provenance; compile `hexlab_loaders` and dependent CLI Debug targets.

### Task 3: PDB IPI resolution across type servers

**Files:** `libs/types/src/pdb.cpp`, `libs/types/src/pdb_import.cpp`, public PDB type headers, and PDB type-import docs.

- [ ] Confirm current IPI parsing/import coverage and type-server identity handling before editing.
- [ ] Resolve only supported function/member-function IPI references in their owning PDB's TPI/IPI namespace, with exact GUID/age, cycle, ambiguity, and depth checks.
- [ ] Preserve unresolved records and source provenance; compile `hexlab_types`, `hexlab_loaders`, and `hexlab_workspace` Debug targets.

### Integration

- [ ] Review independent changes for bounds, exact identity, semantic fidelity, and non-overlapping files.
- [ ] Compile the integrated Debug targets serially; do not run tests or launch the desktop.
- [ ] Update capability evidence from source and build output, then verify `out/` was untouched.
