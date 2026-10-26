# A32 and Thumb decompiler coverage

The decompiler consumes the existing decoded `Instruction` operands, access facts, flow facts, and `ArmInstructionInfo`. It does not decode instruction bytes itself. The table below describes the current decoder families and what the decompiler emits for them.

| Decoded family | Lifted form | Limits |
| --- | --- | --- |
| A32/Thumb AND, EOR, SUB, RSB, ADD, ADC, SBC, RSC, ORR, MOV, BIC, MVN | Width-typed expressions and assignments; RSB/RSC preserve reversed source order; BIC uses AND with complemented operand | Logical flag-setting forms expose parallel destination and packed NZCV output formulas as well as readable flag operands. Known non-PC-writing arithmetic forms expose N/Z/C/V formulas, including incoming carry/borrow for ADC/SBC/RSC. Predicated formulas select the prior destination and flags on the false path; unsupported/unknown flag masks remain opaque |
| A32/Thumb TST, TEQ, CMP, CMN | Explicit flag-producing compare intrinsic | Logical TST/TEQ effects include the same N/Z/C/V formulas; CMP/CMN expose arithmetic formulas when the decoder marks the flag semantics known |
| Thumb MUL | Typed multiply assignment | When flags are written, an explicit multiply-and-flags effect is retained |
| A32 MUL, MLA, MLS, UMULL, UMLAL, SMULL, SMLAL | Typed 32-bit product/accumulate expressions; typed 64-bit signed/unsigned products and accumulation, with explicit register-pair result intrinsics | Long forms use an explicit concatenation of the prior high/low pair; N/Z updates remain a named multiply intrinsic. Predication is retained as a guarded assignment or conditional intrinsic |
| A32/Thumb scalar LDR/STR, byte and halfword forms, signed byte/halfword loads | Typed memory values, stores, sign/zero extension, immediate and shifted-register addresses | Register-controlled shift amounts remain explicit unknown address expressions |
| A32/Thumb pre/post-indexed writeback loads and stores | Explicit load/store writeback intrinsic including the effective address, updated base, and register outputs | Kept as one memory-effect intrinsic because the common statement IR has no multi-effect instruction node |
| A32 LDM/STM and Thumb PUSH/POP/register-list forms | Explicit register-list memory intrinsic with mode, writeback, and decoded register outputs | Per-register transfer addresses are not yet expanded into separate typed loads/stores |
| A32 and Thumb literal loads; Thumb ADR | Literal loads use the decoder's resolved address; ADR becomes a constant address assignment | Invalid/out-of-domain target remains unresolved by the decoder and is not guessed |
| A32/Thumb direct branches and conditional branches; Thumb CBZ/CBNZ | Branch statements with direct targets and explicit predicates | All fourteen ARM condition codes are rendered from N/Z/C/V tests; condition AL is unconditional and the reserved condition is not decoded |
| A32/Thumb calls and BX/BLX mode changes | Explicit ARM call/branch/return intrinsics preserve target mode, return mode, link address, and LR/PC effects | These remain intrinsics because generic Call/Branch nodes do not carry execution-mode transitions |
| Thumb IT blocks | Known IT predicates guard assignments, stores, calls, returns, traps, and indirect transfers; the decoder advances ITSTATE once per instruction | Missing or unknown incoming IT metadata remains an explicit opaque effect with a diagnostic; no predicate is guessed |
| NOP, SVC, BKPT, unsupported, and unpredictable encodings | NOP intrinsic or explicit trap/opaque behavior; conditional traps retain a predicate operand | Traps conservatively affect unknown memory. Decoder-declared unconditional Thumb BKPT remains unconditional even with unknown incoming ITSTATE |

## Verification scope

`tests/decompiler/arm32_lifting_tests.cpp` decodes real A32/Thumb byte sequences before lifting them. It covers RSB operand ordering, conditional A32 arithmetic and compare effects, the complete A32 NZCV condition table, logical MOVS N/Z and C/V preservation, shifter carry reconstruction, false-path flag preservation, known and unknown IT context, ITSTATE advancement, Thumb literal addressing, writeback register effects, guarded stores, direct A32 call mode/link effects, BLX interworking, and indirect BX interworking. The existing general decompiler tests also cover synthetic ARM memory operands.

This is typed semantic coverage for common compiler output, not complete ARM architecture emulation. Runtime register-controlled shifter carry is retained symbolically; it is not evaluated to concrete runtime bits. Saturating, coprocessor, system-register, exclusive-access, and exception-return encodings remain unsupported by the current decoder or explicit opaque forms. Mode-sensitive CFG reconstruction, precise multiple-transfer addresses, complete call ABI clobbers, and a multi-statement instruction IR remain gaps.

## Predication and parallel logical outputs

For decoded flag-setting AND, EOR, ORR, BIC, MOV, MVN, TST and TEQ,
`Intrinsic::register_output_values` now defines packed NZCV in architectural
N/Z/C/V bit order. Data operations also define their destination in the same
parallel output list. Every expression reads the pre-instruction register state;
the flag expression never accidentally reads the newly written destination.
N comes from the ALU result sign bit, Z from a zero comparison, C from the
decoded symbolic shifter carry or incoming C, and V from incoming V.

For condition codes EQ through LE (0 through 13), those output formulas use
typed boolean N/Z/C/V tests and native `select_if` expressions. When the
predicate fails, both the old destination and the complete old NZCV value are
preserved. The readable intrinsic arguments retain the established
`arm_guard`/`arm_select` spelling. Unconditional instructions need no guard.
No cross-instruction comparison or IT state is inferred from nearby bytes.

Predicated load-multiple returns and indirect mode-changing transfers retain
their predicate as the first operand of a guarded intrinsic, together with
decoded memory and register effects. Conditional SVC uses a guarded trap
intrinsic; trap effects conservatively invalidate unknown memory. These forms
remain explicit intrinsics rather than expanding multiple transfers or
inventing a resolved indirect target.

## Unknown IT state

Thumb instructions with missing `ArmInstructionInfo`, unknown incoming
`it_before`, or `unknown_it` predicate metadata become `thumb_unknown_it_*`
intrinsics with a diagnostic. Invalid conditional metadata with condition 14
or above becomes an opaque `arm_unknown_predicate_*` effect. Neither case
falls through to an unconditional assignment, store, call or return.

Unknown-IT effects retain decoded register writes, incoming flags and prior
output-register values. When the decoder reports unknown implicit flag-update
behavior, or metadata is missing, NZCV also receives a conservative definition.
Unknown-IT calls conservatively define NZCV and unknown memory; unknown-IT
traps conservatively affect unknown memory. A decoder-declared unconditional
Thumb BKPT is the explicit exception to IT predication. The lifter does not
reconstruct missing ITSTATE, infer that an instruction lies outside an IT
block, or reinterpret unsupported/unpredictable encodings.

This expansion was reviewed in source only. No builds or tests were run for
the new parallel outputs and fail-closed paths; serial decompiler compilation
and the focused ARM lifting checks remain follow-up work.
