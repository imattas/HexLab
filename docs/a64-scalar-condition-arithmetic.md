# AArch64 scalar conditional arithmetic

The A64 decoder recognizes scalar W/X `UDIV` and `SDIV`, plus the conditional
select family `CSEL`, `CSINC`, `CSINV`, and `CSNEG`. It retains typed source
and destination registers, the condition code, NZCV reads where needed, and
the 64-bit architectural write for W-register destinations. Register 31 is
modeled as the zero register for these data-processing forms.

Pseudocode represents division as `a64_udiv(lhs, rhs)` or
`a64_sdiv(lhs, rhs)`. Keeping the operation named preserves the A64 divide by
zero result (zero) and avoids implying host-language division behavior.
Signed division is represented as a fixed-width operation; the rendering does
not claim a source-language type or overflow policy.

Conditional selects become typed conditional expressions. When an earlier
`SUBS` compare to the zero register reaches the instruction through an
acyclic CFG and agrees at every predecessor, the condition is derived from the
compared operands. Otherwise the expression names the corresponding condition
over the current NZCV value. `CSINC`, `CSINV`, and `CSNEG` transform the false
arm by adding one, bitwise complementing, or negating it, respectively. The
`AL` and `NV` encodings select the first source unconditionally.

This slice does not model every A64 integer instruction, independently track
NZCV bits through arbitrary instructions, or recover higher-level idioms such
as `CSET`/`CSETM` aliases. Existing compare propagation remains limited to
supported acyclic paths; unsupported definitions retain an explicit NZCV-based
condition instead of guessed operands.
