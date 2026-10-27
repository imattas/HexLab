# PowerPC/POWER decoder slice

Encoding review follows the [OpenPOWER Power ISA v3.1C specification](https://openpower.foundation/specifications/isa/) (reference source `P02`). The current implementation is a deliberately bounded subset.

HexLab includes an original fixed-width PowerPC decoder for PPC32 and PPC64 in either ELF byte order. The current integer slice covers immediate add/shifted-add and carry-add, multiply/subtract-immediate, signed/unsigned immediate compares, logical immediate operations, word rotate-and-mask (`rlwimi`, `rlwinm`, and `rlwnm`, including record forms), PPC64 doubleword rotate-and-mask (`rldicl`, `rldicr`, `rldic`, `rldimi`, `rldcl`, and `rldcr`, including record forms), selected X-form add/subtract/carry arithmetic, multiply/divide, logical operations, word/doubleword shifts, and register compares. It decodes D/DS-form and indexed integer loads/stores, including update forms, plus LR/CTR/XER transfers, `mfcr`/`mtcrf`, direct/conditional/LR-indirect/CTR-indirect branches, and system-call traps. Register operands and effects use explicit GPR, CR-field, LR, CTR, and XER banks. ELF e_machine 20/21 plus matching class select PPC32/PPC64; matching big- and little-endian files are supported. Raw CLI profiles are `ppc32le`, `ppc32be`, `ppc64le`, and `ppc64be`.

The instruction decoder preserves the difference between truncated input, reserved encodings, and valid instructions outside this subset. Immediate compare records the selected CR field and 32-/64-bit compare width; `rlw*` operands describe the 32-bit rotate/mask fields while destination register effects follow the selected GPR width. PPC64 `rld*` forms use six-bit shifts and mask indices, including the implicit `ME=63-SH` mask for `rldic` and `rldimi`. `subfic` records its XER carry effect, and `sc` is accepted only with its reserved bits clear and fixed suffix intact. The X-form integer subset also includes complementing logical operations (`andc`, `nand`, `nor`, `orc`, `eqv`), count-leading-zero (`cntlzw` and PPC64 `cntlzd`), and sign-extension (`extsb`, `extsh`, and PPC64 `extsw`), with Rc forms recording their CR0 write. PPC64 `lwa` (opcode 58 DS-form selector 10) is recognized as valid but remains outside the decoded subset; selector 11 is reserved.

The scalar floating-point slice decodes `lfs`, `lfd`, `stfs`, and `stfd` D-form memory operations; `fadds`, `fsubs`, `fmuls`, `fdivs`, `fadd`, `fsub`, `fmul`, and `fdiv`, including Rc forms; `fcmpu`/`fcmpo`; and `fmr`, `fneg`, `fabs`, and `frsp`, including Rc forms. FPR operands are named `f0` through `f31`, and FPSCR is represented as an explicit 32-bit register. Floating comparisons write the selected four-bit CR field as LT/GT/EQ/unordered and retain a conservative unknown FPSCR result; named floating predicates preserve ordered versus NaN behavior. Arithmetic and `frsp` expose conservative post-operation FPSCR values, with the selected CR1 output derived from that post-operation value for Rc forms. Non-rounding unary Rc forms copy the current FPSCR summary into CR1 without claiming an FPSCR update. `frsp` retains a single-precision rounding operation represented in the FPR value. Invalid reserved arithmetic fields fail as malformed instructions. Update-form floating memory operations, fused operations, FPSCR access instructions, and detailed exception/FPSCR bit semantics remain unsupported.

The conversion family follows Book I section 4.6.7.2 of the [official OpenPOWER ISA download](https://files.openpowerfoundation.org/s/AKX2KtLkwCXxEaC). Opcode 63 uses exact ten-bit X-form XO values 14 (`fctiw`), 15 (`fctiwz`), 142 (`fctiwu`), 143 (`fctiwuz`), 814 (`fctid`), 815 (`fctidz`), 846 (`fcfid`), 942 (`fctidu`), 943 (`fctiduz`), and 974 (`fcfidu`). `fcfids` uses primary opcode 59 and XO 846. The unused FRA field must be zero in each conversion. Word-result conversions are enabled in PPC32/PPC64; doubleword conversions, `fcfidu`, and `fcfids` are enabled only in the repository's PPC64 profile, which has no separate processor-capability selector for a 64-bit implementation running 32-bit code. All forms accept Rc and format its trailing dot.

The conversion lifter reads floating binary64 sources for `fcti*` and a signed or unsigned integer64 FPR payload for `fcfid`, `fcfidu`, and `fcfids`. Named typed operations retain FPSCR RN rounding for non-z `fcti*`, fixed toward-zero rounding for z forms, signed or unsigned saturation after rounding, and the ISA-defined NaN result (signed minimum for signed conversions, zero for unsigned conversions). `fcfids` rounds the integer-to-float result to single precision; `fcfid`/`fcfidu` produce double precision. Word results occupy the low 32 FPR bits with an explicit undefined high half. Enabled invalid-operation write suppression retains the previous destination bits through a symbolic source/FPSCR predicate; the destination is therefore also a decoded read for `fcti*`. FPSCR exception and result fields remain unknown, and Rc derives CR1 from that post-operation FPSCR. These operations remain symbolic; detailed exception delivery and concrete FP evaluation are not implemented.

The bounded VMX integer slice decodes the exact opcode-4 VX forms `vaddubm`, `vadduhm`, `vadduwm`, `vsububm`, `vsubuhm`, `vsubuwm`, `vand`, `vandc`, `vor`, `vxor`, and `vnor` in PPC32 and PPC64. The add and subtract forms are modulo 8-, 16-, or 32-bit lanes across a 128-bit vector (16 bytes, 8 halfwords, or 4 words). The logical forms act on all 128 bits and have no lane arrangement. Each instruction names `v0` through `v31`, reads VA and VB, and writes VD; source/destination aliasing is allowed. The decoder reads the instruction word in the selected ELF byte order, matches all 11 extended-opcode bits, and leaves other opcode-4 forms unsupported. There are no record, VSCR, or memory effects in this slice.

The PPC lifter retains each VMX operation as a typed, memory-free common-IR intrinsic with two vector source expressions, one vector register write, and a result type. The intrinsic name identifies the operation and `i8x16`, `i16x8`, `i32x4`, or opaque `bits128` shape; the vector type carries the same width and lane metadata. The lifter validates the decoder's operand, access, effect, and shape metadata before emitting that intrinsic. It does not evaluate lanes or claim concrete vector execution. Saturating arithmetic, comparisons, permutes, vector memory operations, VSX, and other VMX forms remain outside this slice.

The decompiler also lifts `mullw`, `mulld`, `divw`, `divwu`, `divd`, and `divdu`. Word forms consume 32-bit operands in PPC64 mode and extend their result to the GPR width: signed multiply/divide sign-extend, while unsigned word division zero-extends. Doubleword forms are PPC64-only. Divide expressions use explicit `ppc_sdivw`, `ppc_udivw`, `ppc_sdivd`, and `ppc_udivd` IR operation names so their architectural exceptional cases are not treated as ordinary host division. Rc forms produce the GPR result and CR0 from the same pre-instruction inputs; the CR0 summary includes the symbolic XER.SO bit. Division by zero, signed minimum divided by negative one, and implementation-specific result details are not concretely evaluated.

Indexed byte-reversed memory coverage includes `lhbrx`, `lwbrx`, `sthbrx`, and `stwbrx`, plus PPC64 `ldbrx` and `stdbrx` (X-form XO 532 and 660). These use `(RA|0) + RB`, record their memory and register effects, and reject doubleword forms in PPC32.

Analysis recovers reachable functions through direct, conditional, LR, and CTR control flow, with PPC32/PPC64 address widths. The decompiler now lowers ordinary `addi`/`addis`, logical immediates and selected X-form logical/arithmetic operations, count-leading-zero and sign-extension operations, non-record `rlwimi`/`rlwinm`/`rlwnm` and PPC64 `rldicl`/`rldicr`/`rldic`/`rldimi`/`rldcl`/`rldcr`, `mulli`, non-update integer loads and stores, direct branches/calls, conditional branches, indirect LR/CTR transfers, and canonical LR returns into typed expressions, memory effects, or control-flow statements. Word and doubleword rotates use symbolic rotate-left operations with the exact wrapped PPC mask; insert forms preserve bits outside the mask, including PPC64's high word for `rlwimi`, while clear forms zero bits outside their selected mask. For branches that test a CR bit while ignoring CTR, the branch predicate identifies the exact BI bit in its CR field and whether the branch expects that bit to be set. CR compare forms (`cmp`, `cmpl`, `cmpi`, and `cmpli`) now produce the selected four-bit CR field from signed or unsigned less-than, greater-than, equality, and the symbolic XER.SO bit. Record-form add/subtract, logical, rotate/mask, count-leading-zero, sign-extension, and logical-immediate instructions produce their GPR and CR0 outputs in parallel from the pre-instruction state. BO/BI branch predicates now include exact CR polarity and post-decrement CTR tests. Counted non-link branches preserve their unconditional CTR update before the transfer; linked forms retain LR updates through a statement prefix or an explicit parallel-effect intrinsic. Update-form memory operations and carry-producing record arithmetic remain explicit effects. Branch predicates test CR bits directly; no comparison-operand recovery is inferred.

Byte-reversed indexed loads and stores lift through explicit `bswap16`, `bswap32`, or `bswap64` integer operations. Narrow PPC64 loads are zero-extended after byte reversal, and narrow stores are truncated before reversal. The typed operation represents native scalar byte-order reversal without expanding it into byte-wise accesses. Remaining scalar floating-point forms, vector forms beyond the VMX integer slice above, privileged/system instructions beyond the system-call trap, SPRs other than XER/LR/CTR/FPSCR, uncommon integer forms, ABI-specific function calling conventions, relocation-based target resolution, and complete POWER/PowerPC semantics are not implemented. Counted branches use typed CTR decrement/test expressions, and condition-register branches use explicit bit masks and polarity. Complete CR/CTR emulation and cross-instruction relational recovery are not claimed. PPC32 arithmetic target behavior is modeled at 32-bit addresses; exception and reservation effects are not modeled. Debugger register support and architecture-specific ABI recovery are not included.


## BO/BI control-flow lifting

The PPC32/PPC64 lifter interprets every BO bit combination accepted by the
original decoder for `bc`, `bclr` and `bcctr`. In the encoded five-bit value,
mask 16 ignores CR, mask 8 selects CR-set versus CR-clear, mask 4 ignores CTR,
and mask 2 selects zero versus nonzero after decrement. Bit zero is retained
as a prediction hint and does not alter the execution predicate. BI 0?31 selects
CR field `BI/4` and the field mask `1 << (3 - BI%4)`. Ignored inputs do not
create false CR/CTR dependencies.

When CTR is tested, it is decremented modulo the decoded register width before
testing; that update occurs even if the CR test fails. The final predicate is
the conjunction of the active CR and CTR tests. When LK is present, LR becomes
the next instruction address even when a conditional transfer is not taken.
PPC32 link addresses wrap at 32 bits. Indirect destinations clear the low two
address bits.

| Decoded transfer | Lifted representation |
| --- | --- |
| Non-link direct `b`/`bc`, without CTR update | Generic branch with an unconditional or explicit CR predicate |
| Non-link counted `bc`/`bclr` | Unconditional CTR assignment followed by a branch that reads the updated CTR; `bclr` targets the unchanged masked LR |
| Non-link CR-tested `bclr`/`bcctr` | Generic indirect branch with the masked LR/CTR target and explicit CR polarity |
| Canonical unconditional non-link `bclr` return | Existing generic void return |
| Unconditional linked direct `b`/`bc` or CTR-target `bcctr` | Unconditional LR assignment followed by a generic call |
| Conditional LK forms and every linked LR-target `bclr` | Explicit linked-branch intrinsic containing the full predicate and pre-update target, with parallel CTR/LR output formulas |

Generic branch nodes cannot themselves define CTR, so function lifting emits
bounded update statements before the transfer, under the same source instruction
origin. SSA consequently tests the post-decrement counter while retaining the
pre-instruction state for provenance. Internal callers that do not accept a
statement prefix receive an explicit effect instead of silently losing a write.
A generic conditional Call has no predicate, and an LR assignment before an
LR-target call would overwrite its target; those shapes deliberately remain one
intrinsic. Its output formulas read all inputs before defining any output.

Explicit effects retain BO, BI, both ignore flags, CR polarity, the CTR zero
selector, the prediction hint, the taken predicate, target and address domain.
Linked effects conservatively have unknown memory effects. Unsupported or
inconsistent operand/flow/register-effect metadata remains an explicit intrinsic
with the decoded writes and input registers intact. A `bcctr` requesting CTR
decrement/testing remains invalid/unmodeled, as in the decoder. Prediction
behavior, indirect-target resolution, conditional-call ABI recovery, exception
behavior and full POWER instruction semantics remain outside this slice.

This expansion was reviewed in source only. No builds or tests were run; serial
decompiler compilation and PPC branch/SSA checks remain follow-up work.
