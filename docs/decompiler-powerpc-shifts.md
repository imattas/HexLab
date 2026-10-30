# PowerPC scalar shift lifting

The PowerPC decompiler lifts the already decoded `slw`, `srw`, `sraw`,
`srawi`, `sld`, `srd`, `srad`, and `sradi` families, including their Rc forms.
The word forms work in PPC32 and PPC64; doubleword forms require PPC64.
This adds typed value and status formulas without changing the decoder,
analysis references, project schema, or instruction opcode identities.

## Width and count rules

| Form | Input bits | Variable count | Result |
| --- | --- | --- | --- |
| `slw`, `srw` | Low 32 source bits | Low six RB bits | Logical word result, zero-extended in PPC64 |
| `sraw` | Low 32 source bits | Low six RB bits | Arithmetic word result, sign-extended in PPC64 |
| `srawi` | Low 32 source bits | Encoded 0–31 | Arithmetic word result, sign-extended in PPC64 |
| `sld`, `srd` | All 64 source bits | Low seven RB bits | Logical doubleword result |
| `srad` | All 64 source bits | Low seven RB bits | Arithmetic doubleword result |
| `sradi` | All 64 source bits | Encoded 0–63 | Arithmetic doubleword result |

A variable word count whose bit 5 is set produces zero for logical shifts
and a replicated sign bit for arithmetic shifts. Doubleword shifts use bit 6
in the same way. Higher count bits are ignored. Thus word counts 32–63
overshift, while count 64 acts as zero; doubleword counts 64–127 overshift,
while count 128 acts as zero. These are not ordinary shifts masked only by
31 or 63. IBM documents the word behavior for
[`slw`](https://www.ibm.com/docs/en/aix/7.1.0?topic=set-slw-sl-shift-left-word-instruction)
and the doubleword sign-fill/carry behavior for
[`srad`](https://www.ibm.com/docs/en/aix/7.3.0?topic=set-srad-shift-right-algebraic-double-word-instruction).

The IR separates the overshift bit from the low count and uses a typed
conditional selection around an ordinary shift. Every actual IR shift operand
is below the operation width, including branches of the selection that are
not taken. Host-language undefined shifts and implicit count wrapping are
therefore unnecessary. PPC64 word operands first receive explicit `trunc32`;
the completed word result then receives the required zero or sign extension.

For example, a PPC64 `srw` of a source whose low word is `0x80000001` by zero
has the bit pattern `0x0000000080000001`. `srawi` of the same source by zero
has `0xffffffff80000001`. A variable arithmetic word count of 32 produces
`0xffffffffffffffff`, while a count of 64 again acts as zero. These examples
describe the formulas; no execution or test result is claimed here.

## Carry and record effects

Arithmetic right shifts define XER.CA as:

```text
source is negative AND (overshift OR any discarded low bit is one)
```

The discarded-bit mask is `(1 << low_count) - 1`, evaluated only with a count
below the source width. A zero count clears CA even for a negative source.
Overshifting a negative source sets CA, and a nonnegative source clears it.
These formulas retain the original source and count, including when RA, RS,
and RB alias.

The XER output preserves SO, OV, OV32, and every represented bit other than
CA and the profile-dependent CA32 position. CA has its exact formula.
CA32 remains a one-bit unknown named
`ppc_shift_ca32_profile_dependent`: modern Power ISA defines a CA32 update,
while older implementations treat that position as reserved. The generic
PPC profile has no ISA-revision/compatibility selector. The lifter therefore
does not claim either modern CA32 execution or preservation of a legacy
reserved bit. See the [Power ISA specification](https://openpower.foundation/specifications/isa/)
and the POWER9 manual's
[XER compatibility discussion](https://wiki.raptorcs.com/w/images/c/ce/POWER9_um_OpenPOWER_v21_10OCT2019_pub.pdf).

Rc forms derive CR0 LT/GT/EQ from the completed GPR-width result and retain
the existing XER.SO dependency. In PPC64 this means a zero-extended logical
word result is compared as a 64-bit result, while an arithmetic word result
has already been sign-extended. Arithmetic forms use one memory-free
intrinsic with parallel GPR/XER output formulas; Rc adds CR0 as another
parallel output. Logical non-Rc forms are direct assignments. Every output
reads pre-instruction inputs; no sequential destination write can overwrite
an aliased source or count before another output uses it. The implicit old
XER read is explicit in the IR even when decoder facts list only GPR sources.

## Validation and remaining scope

Lifting checks operand count, GPR bank/index/width, immediate range and encoded
width, operand access, source and destination register effects, fallthrough,
instruction length, and absence of memory effects. Invalid or inconsistent
facts retain an explicit conservative `ppc_malformed_shift*` intrinsic with
the decoded effects. No guessed shift value is emitted for those cases.

This remains partial PowerPC support. ISA-version-specific CA32 precision,
concrete execution and exception modeling, general carry arithmetic, update
memory semantics, and full CR/ABI recovery remain outside this slice. No
tests or builds were run for this source change; integration compilation and
target execution are separate validation work.
