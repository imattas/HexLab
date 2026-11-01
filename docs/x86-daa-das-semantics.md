# x86 DAA and DAS semantics

The legacy decoder recognizes `DAA` (`27`) and `DAS` (`2f`) in 16-bit and
32-bit modes. Both use implicit AL and FLAGS effects and are rejected in
64-bit long mode.

`evaluate_x86_daa_das_instruction` accepts the incoming AL byte and FLAGS
bits, then returns the adjusted AL value and only the architecturally defined
flag outputs. The low correction is selected when AL's original low nibble is
greater than nine or incoming AF is set. The high correction is selected when
the original AL exceeds `99h` or incoming CF is set. DAA adds six and/or
`60h`; DAS subtracts them. AF reports low correction; CF reports high
correction or, for DAS, low-correction borrow. PF, ZF, and SF derive from AL. OF is
undefined and is omitted from `flags_defined_mask`.

For DAS, a borrow from the low correction also sets CF when no high correction
is selected, including AL below six with incoming AF set. The helper accepts
the ignored size and segment prefixes admitted by the typed decoder and rejects
malformed register effects, memory effects, LOCK, and long-mode forms.

The helper returns defined arithmetic flags only. The decompiler now provides
parallel AL and FLAGS output formulas, preserves non-arithmetic flags, and
leaves OF unknown. See [decimal adjustment](x86-decimal-adjust.md) for AAA/AAS
and the shared evaluator. No runtime machine-state executor is provided.
