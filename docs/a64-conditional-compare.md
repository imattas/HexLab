# AArch64 conditional compares

The A64 decoder accepts 32-bit and 64-bit `CCMP` and `CCMN` in both register
and five-bit immediate forms. The decoded instruction retains its source
operands, four-bit fallback NZCV value, condition code, NZCV dependency, and
NZCV write. Register 31 denotes `WZR` or `XZR`. Encodings with nonzero fixed
bits 10 or 4 remain unsupported.

`CCMP` subtracts its second operand from its first; `CCMN` adds them. When the
incoming condition is true, the four output flags come from that fixed-width
operation. Otherwise the output is the encoded fallback nibble. The lifted
expression calculates `N`, `Z`, `C`, and `V` separately and selects between
the computed nibble and the fallback. Its carry and overflow formulas use the
operand width, so 32-bit `W` comparisons wrap at 32 bits. `AL` and `NV` select
the arithmetic result without reading prior NZCV.

Ordinary `ADDS`, `SUBS`, and `ANDS` now provide explicit NZCV values to SSA.
The `CMP`, `CMN`, and `TST` aliases still have no destination register write.
For A64 `ANDS`, both the immediate and shifted-register forms set `C=0` and
`V=0`; the shift does not contribute a carry bit. This follows the
[Arm A64 instruction reference](https://documentation-service.arm.com/static/68da52dfbd7cab51328c0622).
Conditional branches use the current SSA NZCV value when no simpler comparison
fact is available. Acyclic comparison propagation carries `CCMP` and `CCMN`
through agreeing CFG predecessors, allowing a following branch or conditional
select to display the chained predicate. Propagation stops after six
conditional compares or when a source register is overwritten; the SSA NZCV
value remains available after that limit.

The current decoder does not cover floating-point conditional comparisons or
other A64 flag-setting instructions. Loop-carried symbolic compare facts are
not inferred.
