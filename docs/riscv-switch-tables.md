# RISC-V jump table recovery

Switch analysis recognizes XLEN-sized absolute-pointer tables in both RV32 and
RV64 at an indirect `JALR x0`. The analyzer dispatches the absolute-table
recognizer only when the target architecture and execution mode agree: RV32
uses four-byte entries and RV64 uses eight-byte entries. The table base may
come from a nearby `AUIPC`/`ADDI` or `LUI`/`ADDI` definition. Selector scaling,
address calculation, target load, and `JALR` must form the recognized data
flow. The signed-offset layout below applies to both RV32 and RV64 and uses
four-byte entries relative to the table base. A compact signed-halfword
variant is also recognized when the selector is scaled by one and the entry
is loaded with `LH`:

```text
AUIPC base, hi                 ; or LUI base, hi
ADDI  base, base, lo           ; optional low-immediate adjustment
SLLI  index, selector, 2
ADD   address, base, index
LW    offset, 0(address)
ADD   target, base, offset
JALR  x0, 0(target)
```

```text
AUIPC base, hi                 ; or LUI base, hi
ADDI  base, base, lo           ; optional low-immediate adjustment
SLLI  index, selector, 1
ADD   address, base, index
LH    offset, 0(address)
ADD   target, base, offset
JALR  x0, 0(target)
```

The absolute-pointer layout uses `SLLI` by two, `ADD`, `LW`, and `JALR` in
RV32, and `SLLI` by three, `ADD`, `LD`, and `JALR` in RV64. It requires a
nearby, unambiguous `AUIPC[/ADDI]` or `LUI[/ADDI]` table-base definition and a
guarded selector range to claim an exact case count. Without a proven count,
the bounded verified-prefix behavior is retained.

For the signed-offset layout, the analysis accepts `AUIPC` and absolute
`LUI` table bases, with or without the adjacent `ADDI` low-immediate
adjustment. `AUIPC` remains relative to the instruction address; `LUI` is
interpreted with XLEN sign extension before the architecture-width low-immediate
addition.
When relocations are present, only a resolved
operand address is accepted.
Every instruction in either signed-offset sequence must be contiguous in one
recovered basic block, use the same RV32 or RV64 context, and fall through to the next
instruction. The register relationships must prove that `base` survives the
index calculation and word load. In-place index, address, offset, and target
registers are allowed where the operands still prove the same data flow. The
table address must resolve from the checked `AUIPC` or `LUI[/ADDI]` setup.
Only `LW` with shift two or `LH` with shift one and zero load displacement are
accepted.

`LW` sign-extends each 32-bit entry and `LH` sign-extends each 16-bit entry to
XLEN. A case target is the table base plus that signed byte displacement;
RV32 addition wraps at 32 bits, while RV64 uses checked
64-bit address arithmetic. The analysis requires entry bytes to be readable
and file-backed, and accepts a target only when it decodes in executable
file-backed bytes under the matching RV32 or RV64 context.
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
setup. Guard, selector, and zero-register widths must match the active XLEN;
the `SLTIU` immediate must be a positive signed 12-bit value so its XLEN
sign-extension cannot turn it into a large unsigned bound. A proven count
limits reads and permits a one-case table. This guard applies to both the
RV32/RV64 signed-offset and absolute-pointer layouts. Unrecognized guards
leave the count and default unknown, so verified-prefix scanning is used.

This is a conservative instruction-pattern recovery. It does not infer
arbitrary register values, noncontiguous signed-offset sequences, entries
relative to the entry address, runtime-filled tables, or additional indirect
targets from an incomplete prefix. The RV32 signed-offset extension has no
dedicated runtime fixture yet.
