# MIPS delay-slot lifting

The analysis CFG keeps a MIPS transfer and its delay-slot instruction in
separate basic blocks connected by a `delay_slot` edge. For ordinary delayed
transfers, decompiler lifting keeps that graph intact while moving the transfer
statement to the slot block after the slot's ordinary effects. For decoded
branch-likely forms, the condition remains in the source block: the taken edge
enters the slot, while the false edge bypasses it to PC+8. The slot block then
performs an unconditional transfer to the taken target. This preserves the
annul rule instead of executing slot effects on the not-taken path.

For ordinary delayed transfers, transfer inputs are evaluated from state at the
transfer instruction, before the delay slot runs. The lifted `Branch`, `Call`,
or `Return` records the source block and instruction for those inputs. SSA uses
the register and memory versions at that point, even though the statement is
placed after the slot. This matters when a slot overwrites a compared register,
a `jr`/`jalr` target, or memory used to form an indirect target. Branch-likely
conditions stay in their source block, so their SSA inputs are captured before
the slot and the condition controls whether the slot executes.

Link-register assignments remain in the transfer block before its delay-slot
edge, so a slot that writes the same register gets a later SSA version. A
`jalr` target snapshot is captured before that link assignment, preserving the
old value when source and link registers alias. Direct targets continue to use
the recovered CFG destination; indirect `jr` targets remain explicit
expressions in the lifted branch and pseudocode. Branch-likely lifting requires
an owned slot plus resolved taken and annulled-fallthrough destinations; if
those CFG edges are missing or ambiguous, lifting reports unsupported rather
than guessing.

Focused regression coverage lives in `tests/decompiler/decompiler_tests.cpp`
and `tests/decompiler/mips64_lifting_tests.cpp` and runs in the headless
`decompiler` and `decompiler_mips64_lifting` CTest targets.
