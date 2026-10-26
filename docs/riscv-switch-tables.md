# RV64 jump table recovery

Switch analysis recognizes two RV64 table layouts at an indirect `JALR X0`.
The existing absolute-pointer layout uses eight-byte entries. A signed-offset
layout uses four-byte entries whose values are relative to the table base:

```text
AUIPC base, hi                 ; optional ADDI base, base, lo follows
ADDI  base, base, lo           ; optional
SLLI  index, selector, 2
ADD   address, base, index
LW    offset, 0(address)
ADD   target, base, offset
JALR  x0, 0(target)
```

The analysis accepts the `AUIPC` form with or without its adjacent `ADDI`.
Every instruction in this signed-offset sequence must be contiguous in one
recovered basic block, use the same RV64 context, and fall through to the next
instruction. The register relationships must prove that `base` survives the
index calculation and word load. In-place index, address, offset, and target
registers are allowed where the operands still prove the same data flow. The
table address must resolve from the checked `AUIPC[/ADDI]` pair. Other table
bases, load displacements, entry widths, and scale values remain unresolved.

`LW` sign-extends each 32-bit entry to XLEN. A case target is the table base
plus that signed value; the analysis checks the arithmetic, requires the
entry bytes to be readable and file-backed, and accepts the target only when
it decodes in executable file-backed bytes under the same RV64 context.
The shared table reader handles supported relocation overlays and carries
their source rows into each recovered case. An unresolved relocation or an
invalid target ends the verified prefix and marks the site incomplete.
At most 4096 entries are read. Without a proven count, at least two valid
entries are required to publish a switch.

A complete function snapshot can establish a count and default arm when an
adjacent `SLTIU guard, selector, positive_bound` and `BEQ guard, x0, default`
prove the in-range fallthrough path to table setup. The immediate must be in
`1..2047`, the guard register must differ from the selector, and the existing
bounded CFG proof rejects alternate entries and selector changes before
setup. A proven count limits reads and permits a one-case table. This guard
also applies to the existing RV64 absolute-pointer layout. Unrecognized
guards leave the count and default unknown, so verified-prefix scanning is
used.

This is a conservative instruction-pattern recovery. It does not infer
arbitrary register values, noncontiguous signed-offset sequences, entries
relative to the entry address, runtime-filled tables, or additional indirect
targets from an incomplete prefix. The new pattern has no dedicated runtime
fixture yet; the affected Windows Debug analysis and CLI targets compiled
successfully.
