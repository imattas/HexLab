# Mach-O CFI expression evaluator expansion plan

## Ownership

Modify only `libs/loaders/src/macho_unwind.cpp`, `libs/loaders/include/hexlab/loaders/macho_unwind.hpp`, `docs/macho-compact-unwind.md`, and this workstream's SDD artifacts. Do not touch shared CMake, tests, capability ledger, root plan, or `out/`.

## Task 1: Extend the bounded expression VM

- [x] Add helpers for stack-depth checks, little-width masks, checked signed division, and defined fixed-width shift behavior.
- [x] Implement the six stack manipulation opcodes with exact DWARF operand conventions and existing 16-element stack bound.
- [x] Implement supported unary/binary arithmetic, bitwise, shift, and comparison opcodes. Preserve DWARF 64-bit addressing arithmetic; return malformed/overflow for invalid divisors, unrepresentable absolute/negated values, and shift counts rather than invoking C++ undefined behavior.
- [x] Implement `DW_OP_deref_size` with strict width validation (1..8) through the supplied memory callback, preserving the current 8-byte `DW_OP_deref` behavior.
- [x] Keep 64-operation and expression-block limits; unsupported opcodes remain explicit.

## Task 2: Interface documentation and source review

- [x] Update the public callback comment and compact-unwind documentation with requested memory widths and exact expression support.
- [x] Review every operator for truncation, signed-edge, underflow, reader failure, and stack-bound behavior without adding or running tests.
- [ ] Root runs `hexlab_loaders` Debug compile-only after integration; no test commands.
