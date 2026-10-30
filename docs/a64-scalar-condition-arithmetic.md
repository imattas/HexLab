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

Integer `CCMP`/`CCMN` now chain flag conditions with encoded false-path NZCV
values; see [AArch64 conditional compares](a64-conditional-compare.md).

`EXTR` is decoded for W/X registers when the `N` bit matches the operation
width and the shift amount is in range. Pseudocode models the architectural
`Rn:Rm` concatenation with `Rm` as the low half, then shifts right by `lsb`;
the W form zero-extends its result to the architectural 64-bit destination.
The operation does not read or write NZCV. Other bitfield and extract forms
remain outside this slice.

The caller-driven `evaluate_a64_add_sub_register_instruction` evaluates
shifted-register `ADD`, `ADDS`, `SUB`, and `SUBS` in W/X width. It revalidates
the encoded instruction and decoded operand/register effects, then applies
LSL, LSR, or ASR before the fixed-width arithmetic. Flag-setting forms return
NZCV; non-flag-setting forms do not. Extended-register forms, SP-based forms,
and unrelated opcodes return no result. Inputs are raw register bits, and the
caller owns register-state reads and commits.
