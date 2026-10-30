# x86 DAA and DAS semantics

The legacy decoder recognizes `DAA` (`27`) and `DAS` (`2f`) in 16-bit and
32-bit modes. Both use implicit AL and FLAGS effects and are rejected in
64-bit long mode.

`evaluate_x86_daa_das_instruction` accepts the incoming AL byte and FLAGS
bits, then returns the adjusted AL value and only the architecturally defined
flag outputs. The low correction is selected when AL's original low nibble is
greater than nine or incoming AF is set. The high correction is selected when
the original AL exceeds `99h` or incoming CF is set. DAA adds six and/or
`60h`; DAS subtracts them. AF and CF report whether their respective
corrections were selected. PF, ZF, and SF are derived from final AL. OF is
undefined and is omitted from `flags_defined_mask`.

The helper does not preserve or compute unrelated FLAGS bits, model decimal
arithmetic beyond these legacy adjust instructions, or provide a decompiler
lift.
