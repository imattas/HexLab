# ABI, Debug Types, and Desktop Views Wave

> **For agentic workers:** Work only in the assigned subsystem. Source-only compilation is allowed; do not add or run tests.

**Goal:** Improve three core HexLab surfaces: ABI classification, imported debug type fidelity, and interactive disassembly/byte inspection.

**Architecture:** Extend current C++20 public models with bounded, explicit semantics. Persist metadata through the established type/database paths; keep GUI behavior on existing wxWidgets document/workspace abstractions. Root reviews cross-layer consistency and updates the shared capability ledger.

**Tech Stack:** C++20, wxWidgets, existing HexLab libraries and project schema.

**Spec:** `docs/capabilities.csv` rows `analysis.abi`, `types.debug`, `views.listing`, `views.bytes`.

## Global Constraints

- Do not add or run tests; use source-only ClCompile where possible.
- Do not edit active `libs/decompiler/src/decompiler.cpp` changes.
- Do not clean `out/` or interact with the GUI.
- Preserve architecture, address-space, cancellation, and persistence invariants.

## Review Focus

- ABI classifications must account for hidden arguments, register exhaustion, aggregate splitting/indirection, and stack alignment.
- Debug type metadata must not claim a static virtual-base offset when runtime vbtable data is required.
- Listing and byte views must stay synchronized across mapped/file address spaces and preserve project edits/navigation.

### Task 1: ABI classifier

Own `libs/analysis/src/abi.cpp`, its public model/header if needed, and `docs/abi-classification.md`. Add a substantial aggregate/hidden-result classification slice for common 64-bit ABIs; document exact supported classes and fail-closed cases.

### Task 2: Debug type model

Own `libs/types`, `libs/symbols` CodeView/PDB import, required database codecs/schema, and type validation docs. Add bounded virtual-base metadata through import and persistence while clearly distinguishing vbptr/vbtable-relative data from fixed member offsets.

### Task 3: Desktop listing and bytes

Own `apps/desktop/data_views.*`, narrowly needed view models, and desktop navigation/view docs. Advance the actual interactive assembly/byte inspector behavior as one integrated product surface: address mapping, selection/highlight/navigation, and useful actions should remain coherent.

### Integration

Root reviews scope and persistence, reconciles docs and ledger, and performs source-only compilation not already covered by agents. No tests or link targets.
