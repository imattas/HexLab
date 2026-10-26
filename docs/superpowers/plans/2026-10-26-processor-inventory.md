# Processor Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the decoder's canonical supported architecture/mode/endian combinations through the processor library and `hexlab_cli processors`.

**Architecture:** The processor library owns the list of canonical `DecodeContext` values and materializes records using the existing `processor_capabilities` function. The CLI renders those records without maintaining a second support table.

**Tech Stack:** C++20, existing processor capability API, existing CLI.

**Spec:** `docs/superpowers/specs/2026-10-26-processor-inventory-design.md`

## Global Constraints

- Decoder inventory rows must derive enabled state, display name, and instruction byte limit from `processor_capabilities`.
- Inventory claims decoder support only; it must not imply complete ISA or downstream-layer support.
- Do not alter serialized architecture or mode enum values.

## Review Focus

- Big-endian MIPS32/MIPS64 and PowerPC32/64 contexts must be represented separately.
- RV64C is enabled while RV32C is not; do not invent the latter.
- x86-16 remains the existing bounded subset and must not be presented as a complete 16-bit ISA.
- The CLI must handle an empty inventory without indexing a first element.
- Output labels must preserve distinct modes where architectures share a family.

---

### Task 1: Processor library inventory

**Files:**
- Modify: `libs/processors/include/hexlab/processors/decoder.hpp`
- Modify: `libs/processors/src/dispatch.cpp`

**Interfaces:**
- Produces `ProcessorVariantInfo { std::string_view id; DecodeContext context; ProcessorCapabilities capabilities; }` and `std::span<const ProcessorVariantInfo> processor_variant_inventory() noexcept`.

- [ ] Add the public record and exported inventory declaration.
- [ ] Enumerate canonical contexts and materialize each record through `processor_capabilities`.
- [ ] Confirm every listed context is enabled and all meaningful endian variants are present by reviewing the returned records.

### Task 2: CLI and documentation

**Files:**
- Modify: `apps/cli/commands.cpp`
- Modify: `docs/building.md`
- Create: `docs/processor-inventory.md`
- Modify: `docs/capabilities.csv`

**Interfaces:**
- Consumes `processor_variant_inventory()`; adds `hexlab_cli processors` with text output.

- [ ] Add architecture, execution-mode, and byte-order label helpers local to the CLI.
- [ ] Route `processors` and print each inventory row's id, target labels, byte limit, and capability display name.
- [ ] Document the command and its decoder-only scope.
- [ ] Change `processor.inventory` from absent to partial and record the remaining per-layer coverage gap.
- [ ] Build the processor and CLI targets; run `hexlab_cli processors` and inspect the output. Do not run tests in this task.
