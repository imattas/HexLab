# AVX-512 opmask test instructions

The VEX.128.0F.W0 KTEST/KORTEST forms accept K-register operands and derive B/W/D/Q width from the mandatory prefix and W bit. Implemented encodings are 98 /r (KORTEST) and 99 /r (KTEST), with VEX.L=0 and reserved VEX.vvvv. EVEX encodings, memory operands, and extended K registers are rejected.

The first ModRM operand is DEST and the second is SRC. KTEST sets ZF when DEST AND SRC is zero and CF when DEST AND NOT SRC is zero. KORTEST sets ZF when DEST OR SRC is zero and CF when DEST OR SRC is all ones. Both clear OF, SF, AF, and PF. The evaluator returns a RFLAGS bit-vector and a written-bit mask so callers can preserve bits outside the architectural write set.

The decompiler emits a typed `x86_ktest{8,16,32,64}` or `x86_kortest{8,16,32,64}` intrinsic and an explicit whole-RFLAGS bit-vector result. It retains the input flags with CF, PF, AF, ZF, SF, and OF masked out, then inserts only the defined CF and ZF results, so untouched RFLAGS bits are preserved and cleared flags remain zero. The evaluator similarly returns the written-bit mask for callers that need to compose the update.

Reference: Intel 64 and IA-32 Architectures SDM, Volume 2A, KTEST/KORTEST entries, https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf

## Register arithmetic

The VEX opmask decoder also accepts the register-only KADD B/W/D/Q forms
(map 0F, opcode 4A), KUNPCKBW/WD/DQ (map 0F, opcode 4B), and KSHIFTL/R
B/W/D/Q (map 0F3A, opcodes 30–33). These forms require K0–K7 operands and
reject memory and extended-register encodings. KADD wraps at its element width;
KSHIFT returns zero when the immediate count is at least the operation width;
KUNPCK interleaves the low half of each source into the result. The value
evaluator validates decoded operand/access/register facts before returning the
zero-extended destination value. The decompiler lowers each instruction to a
typed intrinsic whose register output is an explicit i64 expression: KADD
masks modulo-width addition, KSHIFT masks its source and yields zero when the
immediate is at least the operation width, and KUNPCK explicitly extracts and
interleaves the low source bytes. Unsupported operand/access/register facts
retain the normal conservative fallback.

References: Intel SDM Volume 2A, KSHIFTL/KSHIFTR entries,
https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf;
Intel Architecture Instruction Set Extensions Programming Reference,
KADD/KUNPCK entries,
https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf

## Boolean logic

The VEX opmask decoder accepts register-only KANDB/W/D/Q, KANDNB/W/D/Q,
KORB/W/D/Q, KXORB/W/D/Q, KXNORB/W/D/Q, and KNOTB/W/D/Q. These use K0-K7
registers; memory and extended-register encodings are rejected. Each operation
uses only the selected low 8, 16, 32, or 64 bits and clears the remaining bits
of its 64-bit destination. KANDN computes `(~SRC1) & SRC2`, and KNOT computes
`~SRC`; all operations preserve flags.

The decompiler emits a typed `x86_kand_iN`, `x86_kandn_iN`, `x86_kor_iN`,
`x86_kxor_iN`, `x86_kxnor_iN`, or `x86_knot_iN` intrinsic (where N is 8,
16, 32, or 64) with an explicit zero-extended i64 destination expression.
Unsupported operand, access, register, or instruction-context facts retain the
normal conservative fallback.

Reference: Intel 64 and IA-32 Architectures SDM, Volume 2A, KAND/KANDN/KOR/KXOR/
KXNOR/KNOT entries, https://www.intel.com/content/dam/www/us/en/developer/
articles/technical/intel-sdm.html
