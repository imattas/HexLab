# x86 SSE2 integer and scalar floating-point coverage

Legacy `PSADBW` (`66 0F F6 /r`) is decoded as a destructive XMM operation with
an XMM or 128-bit memory source. It sums eight unsigned byte absolute
differences independently in each 8-byte half and writes the two sums into
the low qword of each half; the upper qword of each 64-bit result group is
zero. Formatting uses the canonical mnemonic, the typed lift retains the
128-bit result with 64-bit unsigned lanes, and the pure packed-integer
evaluator computes both sums. Memory fetching remains caller-owned.

Legacy SSE, VEX, and non-SAE EVEX floating compare lifts now provide explicit
parallel SSA output expressions for the compare result and MXCSR status. The
MXCSR expression depends on incoming MXCSR and the compared operands, and
retains the evaluator's sticky invalid/denormal update semantics. EVEX SAE
forms continue to omit the MXCSR write.

EVEX `VPANDND` and `VPANDNQ` decode map 1 opcode `DF` with `pp=66`, selecting
dword or qword lanes with `W`. They compute `~SRC1 & SRC2` for 128-, 256-, and
512-bit vectors, preserve merge/zero opmask behavior, and clear upper ZMM state
for shorter vector lengths. The pure EVEX integer evaluator and typed lift use
the existing lane-mask and upper-register handling.

EVEX `VPSHUFB` decodes map 2 opcode `00` with `pp=66` at all three vector
lengths. Each control byte selects a data byte within its own 128-bit lane;
the high control bit writes zero. Writemasks apply per output byte, and
128-/256-bit forms clear the unwritten upper ZMM portion.

EVEX `VPERMD` decodes map 2 opcode `36` with `pp=66` and `W=0` at 128, 256,
and 512 bits. Each dword selector indexes the complete active vector, rather
than restarting at 128-bit boundaries; the writemask merges or zeroes each
destination dword, and shorter vector lengths clear the upper ZMM portion.

EVEX `VPERMB` decodes map 2 opcode `8D` with `pp=66` and `W=0` at 128, 256,
and 512 bits. Each index selects a byte from the full active vector; low index
bits select within that vector and higher bits are ignored. The writemask
merges or zeroes each destination byte, and short forms clear upper ZMM state.
The EVEX `VPERMI2B` and `VPERMT2B` three-source forms remain unsupported.

EVEX `VPSHUFD` decodes map 1 opcode `70` with `pp=66` at 128, 256, and 512
bits. The imm8 selects dwords independently within each 128-bit lane. Merge
and zero masks apply per dword, and 128-/256-bit forms clear upper ZMM state.

EVEX `VPSADBW` decodes map 2 opcode `F6` with `pp=66` and `W=0`. Each
128-bit block forms two unsigned sums of eight byte absolute differences and
places each sum in a 64-bit destination lane. Writemasks merge or zero by
qword result lane; short vectors clear upper ZMM state.

EVEX `VPTERNLOGD/Q` decodes map 3 opcode `25` with `pp=66`; `W` selects
32-bit or 64-bit lanes. All 256 imm8 truth tables are retained and evaluated
per bit over the pre-instruction destination, EVEX.vvvv source, and ModRM
source. Opmask merge/zero behavior applies per dword or qword, and shorter
vectors clear upper ZMM state. EVEX.b is rejected.

EVEX `VPMULLQ` decodes map 2 opcode `40` with `pp=66` and `W=1` for 128-,
256-, and 512-bit vectors. It returns the low 64 bits of each unsigned
qword-lane product; the EVEX integer evaluator applies lane masks and upper
ZMM clearing. The W=0 dword form remains `VPMULLD`.

EVEX qword min/max forms use the W=1 alternatives of map 2 opcodes `39`,
`3B`, `3D`, and `3F`: signed `VPMINSQ`/`VPMAXSQ` and unsigned
`VPMINUQ`/`VPMAXUQ`. They support all three vector lengths, apply masks per
qword, and preserve the existing upper-ZMM clearing behavior. Map 2 W=0
dword min/max forms remain supported; additional byte/word EVEX min/max forms
outside the whitelist remain unsupported.

EVEX mask/vector conversions decode with map 2 opcode `28`/`38` for
`VPMOVM2B/W/D/Q` and `29`/`39` for `VPMOVB/W/D/Q2M`, all with `pp=F3`; `W`
selects each opcode pair's narrower or wider element width. Mask-to-vector
converts each K bit to an all-zero or all-one lane. Vector-to-mask copies each
lane's sign bit to the matching K bit and clears bits above the active vector
length. Only VL128/256/512 register forms are supported; memory operands,
EVEX.aaa/EVEX.z, and EVEX.b are rejected.

EVEX immediate packed shifts support word, dword, and qword logical left and
right forms plus arithmetic right word and dword forms. They use map 1
opcodes `71`/`72`/`73`, `pp=66`, and the documented ModRM group selectors;
the imm8 is applied without count masking, so counts at or above element
width produce zero or sign fill. Opmasks merge or zero per shifted element.
EVEX whole-128-bit byte shifts (`VPSLLDQ`/`VPSRLDQ`) remain outside this slice.

EVEX `VPOPCNTB/W/D/Q` decode map 2 opcodes `54`/`55` with `pp=66`; `W`
selects byte/word or dword/qword lanes. Each active lane returns its number of
set bits, with merge/zero masking per lane. This slice supports register and
full-vector memory sources at VL128/256/512, but rejects EVEX.b broadcast
forms, including the dword/qword forms that have architectural broadcasts.

## Remaining boundaries

The EVEX decoder remains a per-opcode whitelist, not full AVX-512 coverage.
In particular, EVEX `VPERMI2B`/`VPERMT2B` and the corresponding dword/qword
three-source permutations, EVEX whole-128-bit byte shifts, compress/expand,
and gather/scatter forms are not
implemented by this slice. Legacy/VEX/EVEX floating compare predicates are
fully covered for the supported compare mnemonics as described above; other
compare and test instruction families remain unsupported.

Scalar SSE and packed VEX/EVEX floating add/subtract/multiply/divide now lift
explicit destination and MXCSR output expressions. The expressions carry the
active-lane rounded result, preserved scalar/EVEX merge lanes, VEX/EVEX upper
clears, and sticky IE/DE/ZE/OE/UE/PE status update with MXCSR control inputs.
For EVEX arithmetic, exception aggregation is filtered by the opmask, so
masked-off lanes cannot contribute sticky status bits.
These are symbolic decompiler formulas: this slice does not evaluate exact
rounding, denormal handling, exception masks, or trap delivery at runtime.
Floating compare families retain their explicit IE/DE status outputs. CPU
feature availability and masked-memory fault suppression are not simulated by
the pure lane evaluators.

Predicate coverage is complete for the compare-immediate families currently
decoded: legacy SSE `CMPPS/PD/SS/SD` accepts predicates 0-7, and VEX/EVEX
floating `VCMPPS/PD` accepts predicates 0-31. The IEEE evaluator handles the
distinct ordered/unordered results and signaling behavior for all 32 floating
predicates; VEX/EVEX decode rejects reserved upper immediate bits. Integer
EVEX `VPCMPB/W/D/Q` and unsigned variants accept predicates 0-7 (equal,
less-than, less-or-equal, false, not-equal, not-less-than, not-less-or-equal,
and true), with reserved upper bits rejected. This leaves no missing immediate
predicate value in these supported families; other compare instruction
families remain outside the decoded subset.

## Scalar COMISS and UCOMISS

The legacy `0F 2F /r` `COMISS` and `0F 2E /r` `UCOMISS` forms decode with
two read operands (XMM or scalar `m32`), an EFLAGS write, and MXCSR read/write
effects. The `66`-prefixed `COMISD/UCOMISD` forms decode the same effects with
XMM or scalar `m64` sources. No vector destination is written.

`evaluate_x86_sse_scalar_compare` compares caller-supplied binary32 bits;
`evaluate_x86_sse_scalar_compare_double` handles binary64 bits. Neither uses
host floating-point operations. Ordered less/equal/greater produce CF/ZF/PF
values `100`, `010`, and `000`; unordered produces `111`. All six arithmetic
condition flags are updated: OF/SF/AF are cleared and CF/PF/ZF carry the
comparison result. Other EFLAGS bits are preserved. COMISS/COMISD raise invalid
for any NaN, while UCOMISS/UCOMISD raise invalid only for signaling NaNs.
Denormal operands raise DE unless MXCSR.DAZ is set, in which case their
sign-preserving zero replacements participate in the comparison. IE/DE are
accumulated in MXCSR even when unmasked; if either raised exception is
unmasked, EFLAGS retirement is suppressed and `completed` is false. Memory
reads/faults, CPU feature checks, exception delivery, and decompiler lifting
remain caller-owned or unsupported. The double-precision encodings and flag
behavior follow Intel's [COMISD reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).

HexLab's initial original SIMD decoder slice is scoped to these instruction
families:

| Family | Forms |
| --- | --- |
| Packed moves | `movdqa`, `movdqu` |
| Packed integer arithmetic | `paddb/w/d/q`, `psubb/w/d/q`, signed and unsigned saturating byte/word add/sub (`paddsb/sw`, `paddusb/usw`, `psubsb/sw`, `psubusb/usw`) |
| Packed integer logic | `pand`, `pandn`, `por`, `pxor` |
| Packed integer shifts | Variable-count and immediate-count `psllw/d/q`, `psrlw/d/q`, `psraw/d`; immediate whole-vector byte shifts `pslldq`, `psrldq` |
| Packed integer compare | `pcmpeqb/w/d`, `pcmpgtb/w/d` |
| Packed/scalar floating compare | `cmpps`, `cmppd`, `cmpss`, `cmpsd`, immediate predicates 0-7 |
| Packed integer multiply/min/max | `pmullw`, `pmulhw`, `pmulhuw`, `pmuludq`, `pmaddwd`, `pminub`, `pmaxub`, `pminsw`, `pmaxsw` |
| Packed integer rounded average | `pavgb`, `pavgw` |
| Packed byte absolute differences | `psadbw` |
| SSSE3 horizontal integer arithmetic | `phaddw/d/sw`, `phsubw/d/sw` |
| SSSE3 byte/word operations | `pmaddubsw`, `pmulhrsw`, `psignb/w/d`, `pabsb/w/d` |
| Packed integer shuffle | `pshufd` with its encoded byte selector; SSSE3 `pshufb` |
| Packed byte alignment | SSSE3 `palignr` XMM form; AVX2 `vpalignr` XMM/YMM forms, independently within each 128-bit lane |
| Scalar moves | `movss`, `movsd` |
| Scalar arithmetic | `addss`, `addsd`, `subss`, `subsd`, `mulss`, `mulsd`, `divss`, `divsd` |
| AVX packed floating decoder | VEX.128/.256 `vmovups`, `vaddps/pd`, `vsubps/pd`, `vmulps/pd`, `vdivps/pd`, `vxorps/pd`, `vandps/pd`; EVEX.128/.256/.512 `vaddps/pd`, `vsubps/pd`, `vmulps/pd`, `vdivps/pd` |
| AVX2 packed integer subtraction | VEX.128/.256 `vpsubb/w/d/q` |
| AVX2 packed integer comparisons | VEX.128/.256 `vpcmpeqb/w/d/q`, `vpcmpgtb/w/d/q` |
| AVX2 immediate packed shifts | VEX.128/.256 `vpsllw/d/q`, `vpsrlw/d/q`, `vpsraw/d`, `vpslldq`, `vpsrldq` |
| AVX2 packed word multiply | VEX.128/.256 `vpmullw`, `vpmulhw`, `vpmulhuw` |
| AVX2 packed integer dataflow | VEX.128/.256 `vpandn`, `vpavgb/w`, `vpsignb/w/d`, `vpsadbw` |
| AVX2 packed absolute value | VEX.128/.256 `vpabsb/w/d` |
| AVX2 remaining min/max | VEX.128/.256 `vpminsb/sd/uw/ud`, `vpmaxsb/sd/uw/ud` |
| AVX2 dword multiply and multiply-add | VEX.128/.256 `vpmulld`, `vpmuldq`, `vpmuludq`, `vpmaddwd`, `vpmaddubsw` |
| AVX2 horizontal integer arithmetic | VEX.128/.256 `vphaddw/d/sw`, `vphsubw/d/sw` |
| AVX2 lane routing and narrowing | VEX.128/.256 `vpunpcklbw/lwd/ldq/lqdq`, `vpunpckhbw/hwd/hdq/hqdq`, `vpacksswb/ssdw/uswb/usdw`, `vpshufb` |
| AVX2 immediate dword shuffle | VEX.128/.256 `vpshufd`, with independent 128-bit-lane selectors |
| AVX-512 packed compare to mask | EVEX.128/.256/.512 `vpcmpb/w/d/q` and `vpcmpub/uw/ud/uq`, with immediate predicates 0-7; floating `vcmpps/pd` supports broadcast memory input or register-source SAE |
| AVX-512 AND-NOT | EVEX.128/.256/.512 `vpandnd/q` with merge/zero masking and upper-ZMM clearing |
| AVX-512 byte shuffle | EVEX.128/.256/.512 `vpshufb`, lane-local to each 128-bit group with merge/zero masking |
| AVX-512 dword permutation | EVEX.128/.256/.512 `vpermd` with full-vector dword selectors, merge/zero masking, and upper-ZMM clearing |
| AVX-512 VBMI byte permutation | EVEX.128/.256/.512 `vpermb` with full-vector byte selectors, merge/zero masking, and upper-ZMM clearing |
| AVX-512 dword immediate shuffle | EVEX.128/.256/.512 `vpshufd`, lane-local imm8 selectors with merge/zero masking |
| AVX-512 sum of absolute byte differences | EVEX.128/.256/.512 `vpsadbw`, per-eight-byte sums with qword-result masking |
| AVX-512 ternary logic | EVEX.128/.256/.512 `vpternlogd/q`, all imm8 truth tables with merge/zero masking |
| AVX-512 low qword multiply | EVEX.128/.256/.512 `vpmullq`, low 64 bits per lane with merge/zero masking |
| AVX-512 qword min/max | EVEX.128/.256/.512 `vpminsq/uq`, `vpmaxsq/uq` with signed or unsigned qword comparisons |
| AVX-512 mask/vector conversion | EVEX.128/.256/.512 `vpmovm2b/w/d/q` and `vpmovb/w/d/q2m` |
| AVX-512 immediate packed shifts | EVEX.128/.256/.512 `vpsllw/d/q`, `vpsrlw/d/q`, `vpsraw`, `vpsrad` with per-lane masking |
| AVX-512 population count | EVEX.128/.256/.512 `vpopcntb/w/d/q` with per-lane masking |

The intended typed model uses 128-bit XMM register operands, 128-bit packed
memory operands, and 32-/64-bit scalar memory operands. Read/write access on
the destination captures the packed and scalar arithmetic inputs; move
destinations are writes. Address base/index and memory read/write effects use
the existing x86 finalization rules.

The exact mandatory prefixes select the form: `66` for the listed packed
operations and `movdqa`, `F3` for `movdqu` and single precision, and `F2` for
double precision. Long mode supports XMM0–XMM15 through REX register fields;
16-/32-bit modes use XMM0–XMM7. Truncated supported instructions remain
truncated, malformed prefix combinations are invalid, and instructions outside
the implemented subset remain unsupported.

SSSE3 `PALIGNR` (`66 0F 3A 0F /r ib`) concatenates the old destination as the
high 16 bytes and the ModRM source as the low 16 bytes, shifts that 32-byte
value right by the unsigned immediate, and writes the low 16 bytes. Counts at
or above 32 produce zero. AVX2 `VPALIGNR` (`VEX.256.66.0F3A 0F /r ib`) uses
VEX.vvvv as the high half and ModRM r/m as the low half, repeating the same
operation independently in each 128-bit lane; VEX.128 also clears the upper
half of the destination YMM state. The bounded
`evaluate_x86_palignr`/`evaluate_x86_vpalignr` helpers accept caller-supplied
source bytes and return the exact result. Memory fetching and register-state
commit remain caller-owned. EVEX `VPALIGNR`, MMX `PALIGNR`, and other 0F3A
instructions remain unsupported.

Legacy scalar `ADDSS/ADDSD`, `SUBSS/SUBSD`, `MULSS/MULSD`, and `DIVSS/DIVSD`
carry an implicit whole-MXCSR read/write dependency in the decoded effects and
typed lift. The lift passes the incoming MXCSR value to the scalar arithmetic
intrinsic and defines an opaque outgoing MXCSR version. It does not calculate
rounding, sticky exception flags, or unmasked-exception retirement.

Legacy SSE `CMPPS`, `CMPPD`, `CMPSS`, and `CMPSD` decode the eight immediate
predicates (equal, less, less-equal, unordered, not-equal, not-less-than,
not-less-equal, and ordered) with exact 32- or 64-bit lane shapes. The pure
evaluator compares IEEE encodings, treats signed zeroes as equal, applies
MXCSR.DAZ, reports denormal and invalid exceptions, and marks results
uncommittable when an exception is unmasked. Signaling NaNs raise invalid for
every predicate; quiet NaNs raise invalid for predicates 1, 2, 5, and 6.
Packed forms produce all-zero/all-one lane masks. Scalar forms replace only
the low lane and preserve the old destination's upper bits. `mxcsr_after`
accumulates the invalid-operation and denormal-operand sticky bits while
preserving caller-provided controls; the caller still owns memory reads and
committing the returned destination/MXCSR state.

The SSSE3 `PHADDW/D/SW` and `PHSUBW/D/SW` forms use the legacy `66 0F 38`
map. They read the old XMM destination and the register or 128-bit memory
source, then write adjacent pair sums or differences from the old destination
into the lower half and from the explicit source into the upper half. Word and
dword forms wrap; the `SW` forms saturate signed word results. The packed
integer evaluator computes these lane results, and the typed lift records
signed word/dword lane inputs and results. These encodings follow Intel's
[SSSE3 instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

Legacy SSSE3 `PSHUFB` uses `66 0F 38 00 /r`. The old XMM destination supplies
the 16 data bytes, while the register or 128-bit memory operand supplies 16
control bytes. Each control byte selects a byte from the old destination with
its low four bits; setting its high bit writes zero. Selection remains within
the single 128-bit vector. Decode effects mark the destination read/write and
the explicit source read, and the typed lift retains the 16-byte vector shape.
The packed integer evaluator implements both low-nibble selection and
high-bit-zeroing.

The original legacy decoder also accepts the SSSE3 `66 0F 38` byte/word
operations `PMADDUBSW`, `PMULHRSW`, `PSIGNB/W/D`, and `PABSB/W/D`.
`PMADDUBSW`, `PMULHRSW`, and `PSIGN*` are destructive two-operand forms with
XMM/m128 source reads. `PABS*` forms write the XMM destination without reading
its old value. Decoder facts
retain the 128-bit vector width, the operation's result-lane width, and the
register or memory access direction. Other legacy `0F 38` forms remain
unsupported by this slice.

Packed comparisons use destructive XMM destinations and do not modify EFLAGS.
The packed integer execution helper evaluates byte/word/dword/qword wrapping
add/sub, byte/word signed and unsigned saturating add/sub, bitwise logic, and
logical left/right and arithmetic right word/dword/qword shifts. Variable shift
counts come from the low 64 bits of the second XMM value; immediate forms use
the encoded unsigned byte. Counts at or above lane width zero logical shifts,
and arithmetic right shifts fill with the original sign bit. `pandn` computes
the bitwise complement of the old destination ANDed with its source. The helper
does not model flags (these operations leave EFLAGS unchanged), upper YMM state,
or memory reads; callers supply the second 128-bit value. It also evaluates
the six byte/word/dword compare forms. The six compare forms compare lanes for
equality or signed greater-than; qword and unsigned greater-than variants are
outside this slice. In the typed
decompiler IR, signed-greater-than operands are signed lane vectors, while the
result is an unsigned vector of all-zero/all-one bit masks.

The selected AVX decoder forms parse long-mode VEX2/VEX3 map selection and
the inverted register fields, produce typed XMM/YMM operands, and retain vector
memory widths. Arithmetic destinations are non-destructive and carry a third
source; moves enforce the reserved `vvvv` field and direction-specific memory
effects. Unsupported maps/opcodes are not accepted. Packed floating arithmetic
is represented as typed intrinsics; the helper below evaluates only the
explicitly listed integer and bitwise operations.

The listed legacy SSE2 packed-integer instructions now have typed decompiler
intrinsics across wrapping and saturating arithmetic, bitwise logic, variable
and immediate shifts, and equality/signed-greater comparisons. Intrinsics retain
the 128-bit vector shape and lane width; signed saturating arithmetic and
signed-greater inputs retain signed lane types, and immediate counts remain
8-bit scalar operands. These are typed, effect-aware lifted operations, not a
claim that the optimizer evaluates their lane semantics.

Additional typed SSE2 intrinsics now cover signed and unsigned low/high word
multiplication, unsigned even-dword-to-qword multiplication, signed word
multiply-add to dwords, signed/unsigned byte/word min/max, and `pshufd` lane
selection. `pmaddwd` and `pmuludq` retain distinct input and output lane shapes;
`pshufd` keeps the unsigned selector as an 8-bit scalar. These new forms have
compile-only evidence and no fixture coverage yet.

Legacy SSE2 `PAVGB` and `PAVGW` compute `(a + b + 1) >> 1` independently for
unsigned byte and word lanes. They use destructive XMM destinations with a
register or 128-bit memory source, do not change EFLAGS, and lift to unsigned
8-bit or 16-bit lane intrinsics. The pure packed-integer evaluator also
computes the exact rounded lane results; CPU feature gating remains outside
the decoder. The encoding and rounding operation follow Intel's `PAVGB/PAVGW`
instruction reference ([Intel SDM](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)).

The currently decoded AVX subset lifts VEX.128 and VEX.256 `vmovups`,
`vaddps/pd`, `vsubps/pd`, `vmulps/pd`, `vdivps/pd`, `vxorps/pd`, and `vandps/pd` into typed
intrinsics. VEX.128 register destinations define both the XMM result and the
full YMM view with the upper 128 bits cleared; the intrinsic name includes
`zero_upper` and its result type is 256 bits. VEX.128 stores remain 128-bit
memory writes. VEX.256 forms retain their full YMM results.

Packed floating `vaddps/pd`, `vsubps/pd`, `vmulps/pd`, and `vdivps/pd` record MXCSR as
an implicit 32-bit read/write dependency. Their typed intrinsics consume the
incoming MXCSR value and define its outgoing version alongside the vector
result, so later SSA can observe the state dependency. The whole register is
retained because per-flag exception behavior and control-field effects are not
computed. `vdivps/pd` decode for VEX.128/.256 and EVEX.128/.256/.512 with exact
vector and memory widths, opmask merge/zero behavior, and upper-register
clearing. The decompiler preserves division as a typed MXCSR-dependent
intrinsic; the lane evaluator does not execute floating-point division or
calculate MXCSR flags.

`x86_avx_semantics.hpp` provides a pure evaluator for the decoded AVX2 wrapping
integer add/subtract families (`vpaddb/w/d/q`, `vpsubb/w/d/q`), integer logical
operations (`vpand`, `vpor`, `vpxor`), floating-vector bitwise operations
(`vandps/pd`, `vxorps/pd`), and `vmovups`. The caller supplies source bytes,
including bytes loaded from memory; the helper does not read or write process
memory. It rejects unsupported instructions and mismatched register/memory
widths. A VEX.128 register result has zero bytes in the upper half of its
256-bit result and reports that the architectural YMM upper half was cleared;
a VEX.128 store remains only 128 bits. Integer add/subtract wraps
independently in each lane and does not update EFLAGS. The bitwise forms operate
on every bit, including floating encodings, without interpreting NaNs. These
rules follow Intel's [AVX/AVX2 instruction reference](https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf)
and [Intel SDM discussion of VEX.128 upper-register clearing](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf).

The helper evaluates VEX packed equality and signed-greater-than comparisons
for byte, word, dword, and qword lanes. Each output lane is all ones when its
comparison succeeds and zero otherwise. Qword variants use VEX map 2; byte,
word, and dword variants use map 1. Typed decode records the non-destructive
destination write and both source reads, retains XMM/YMM or full-width memory
operands, and records VEX.128 upper-YMM clearing. The helper does not evaluate packed floating-point add/subtract/multiply/division:
rounding mode, denormal handling, and MXCSR exception bits are not executed by
the lane evaluator. The decompiler retains the packed floating arithmetic forms
as typed state-aware intrinsics, not concrete FP evaluation or constant folding.
The integer and bitwise
helper is not a complete CPU emulator and does not model faults or state outside
the destination vector.
The AVX2 integer subset now includes VEX.128/.256 `vpaddb/w/d/q` and `vpand`,
`vpor`, and `vpxor`, with exact XMM/YMM and memory widths and the same VEX.128
upper-YMM clearing effect. It now also decodes VEX.128/.256 `vpsubb/w/d/q` as
non-destructive three-operand operations with the same exact lane/vector widths
and upper-YMM clearing. The original instruction model records destination
write and both source reads, including full vector memory width. The decompiler
emits typed lane-shape intrinsics such as `x86_vpsubb_i8x16_zero_upper`; these
preserve both source vector types, result shape, memory-read effect, and vector
register writes. Exact pure lane evaluation is available for the integer and
bitwise subset above; it is not yet integrated into a full x86 machine-state
interpreter.
The AVX2 multiply subset adds VEX.128/.256 `vpmullw`, `vpmulhw`, and
`vpmulhuw`. These decode with the usual three-operand XMM/YMM effects and are
lifted as typed 16-bit lane intrinsics; the pure lane evaluator models low-word,
signed-high-word, and unsigned-high-word products exactly.
The next AVX2 packed byte/word subset adds signed and unsigned saturating
`vpaddsb/sw`, `vpaddusb/usw`, `vpsubsb/sw`, and `vpsubusb/usw`, plus unsigned
byte and signed word `vpminub`, `vpminsw`, `vpmaxub`, and `vpmaxsw`. These forms
require VEX map 1 with `pp=66`, use three-operand XMM/YMM or full-width memory
sources, and clear the upper YMM half for VEX.128 register results. The lane
evaluator clamps saturating results to the signed or unsigned lane range and
selects min/max according to the instruction's signedness. Typed decompiler
intrinsics preserve the 8- or 16-bit lane shape and exact register writes.
The bounded AVX-512 slice now also decodes 64-bit-mode EVEX.512 `VMOVUPS`,
`VADDPS`, `VSUBPS`, `VMULPS`, `VADDPD`, `VSUBPD`, and `VMULPD`. It exposes
ZMM0-ZMM31 and K0-K7, preserves full 512-bit register and memory widths, and
records mask-register reads. K0 is unmasked; K1-K7 support merge masking and
destination zeroing for loads/arithmetic, and merge masking for stores. EVEX
compressed disp8 on these full-width non-broadcast forms scales by 64 bytes.
Packed floating arithmetic also accepts memory broadcast (`EVEX.b=1`) for
`VADDPS/PD`, `VSUBPS/PD`, `VMULPS/PD`, and `VDIVPS/PD` at 128/256/512-bit
vector widths. The memory operand is one 32- or 64-bit lane, compressed disp8
scales by that element width, and typed decompiler effects mark the scalar
input as broadcast across result lanes. EVEX.b with a register source selects
embedded rounding and remains unsupported, as do broadcast tuples for other
instruction families, reserved encodings, and unsupported EVEX maps. This follows the EVEX `Load+Op` broadcast and tuple-scale rules in Intel SDM Vol. 2, sections 2.6.5 and 2.6.6 ([manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developers-manual.pdf)).

EVEX packed floating compare-to-mask now decodes `VCMPPS` and `VCMPPD` at
128/256/512-bit widths with all 32 immediate predicates, K0-K7 destinations,
optional execution masks, vector or memory sources, and 32/64-bit memory
broadcast. Register-source EVEX.b selects embedded SAE; it suppresses MXCSR
exception-state writes while preserving the MXCSR control read used for DAZ.
The typed decompiler retains the predicate, source shapes, mask, broadcast or
SAE marker, and K result.
The pure lane evaluator implements all 32 predicate truth tables directly from
binary32/binary64 bit patterns, including signed-zero equivalence, ordered and
unordered NaN results, signaling-NaN behavior, and predicate-dependent quiet-
NaN invalid exceptions. It honors MXCSR.DAZ for subnormal inputs and reports
denormal/invalid exceptions plus whether an unmasked exception suppresses the K
result. `mxcsr_after` accumulates MXCSR.IE and MXCSR.DE from active lanes while
preserving all caller-provided controls and unsupported status bits. Masked-off
lanes are neither compared nor allowed to raise exceptions, and the output is
limited to the active low K bits. Embedded SAE permits the K result to retire
even when the corresponding exceptions are unmasked; the helper still reports
the comparison's invalid/denormal conditions and leaves `mxcsr_after` unchanged
for SAE. Destination zeroing and invalid encodings are rejected.
VEX.128/.256 packed floating
compare-to-vector forms are also decoded and lifted for all 32 immediate
predicates. They retain vector operands and results, VEX.128 upper-YMM clearing,
memory reads, and MXCSR input/output dependencies.
`evaluate_x86_avx_float_compare` now executes those VEX forms from caller-supplied
32-byte source arrays and MXCSR, returning all-ones or zero 32-/64-bit lanes,
vector/lane widths, upper-YMM clearing, invalid/denormal conditions and a
`completed` retirement flag. It shares the exact bit-pattern predicate engine
with the EVEX helper: all 32 quiet/signaling predicates, signed-zero equivalence,
infinity ordering, qNaN/sNaN, and DAZ use the same rules without host floating
point. The shared signaling table includes `ORD_S` (predicate 23), correcting
its previously missing quiet-NaN invalid exception in the EVEX helper as well.
Both compare result types carry `mxcsr_after`, accumulating IE/DE sticky bits
for VEX and EVEX operations; EVEX SAE suppresses those writes.
An unmasked invalid or denormal exception suppresses the entire vector
write and VEX.128 upper clearing, even if the exception arose in a later lane;
callers must check `completed` before committing either effect. Out-of-width
registers, wrong memory widths, reserved predicate bits, and EVEX-only metadata
fail closed. The original integer/bitwise `evaluate_x86_avx_packed` helper
continues to reject floating compares because it has no MXCSR input.
Memory reads/faults, CPU feature checks, and delivery
of operating-system exceptions remain the caller's responsibility. Scalar VEX
comparisons and packed floating arithmetic execution remain unsupported.
The opcode forms and predicate width follow Intel SDM Vol. 2's `VCMPPS` and
`VCMPPD` entries (same [manual](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developers-manual.pdf)).

EVEX.512 packed integer wrapping add/sub now covers `VPADDB/W/D/Q` and
`VPSUBB/W/D/Q` with ZMM register and 512-bit memory operands. K1-K7 masking is
decoded as a mask-register read; merge forms also read the destination, while
`{z}` forms define inactive lanes as zero. The pure evaluator computes exact
modular lane results for 8/16/32/64-bit lanes and applies each mask bit to the
corresponding lane. The caller supplies the runtime K-register value; for merge
masking it must also supply the old destination bytes. Memory remains caller-owned. The decompiler preserves the ZMM lane shape,
old-destination dependency for merge mode, and mask-register input in a typed
intrinsic. The additional integer forms below have their own explicit opcode
selection and shape metadata; they are not inferred from neighboring opcodes.

The EVEX integer subset covers the following forms in 64-bit mode at
EVEX.128/.256/.512 widths. Every form requires `pp=66`, a vector first source,
and a same-width vector or memory second source. The table's map 1 means `0F`;
map 2 means `0F38`.
`WIG` accepts either W bit, while W0/W1 are checked explicitly.

| Family | Forms | Map / opcode / W | Destination mask element |
| --- | --- | --- | --- |
| Signed saturating byte/word add/sub | `vpaddsb/sw`, `vpsubsb/sw` | 1 / EC, ED, E8, E9 / WIG | byte or word |
| Unsigned saturating byte/word add/sub | `vpaddusb/usw`, `vpsubusb/usw` | 1 / DC, DD, D8, D9 / WIG | byte or word |
| Signed/unsigned saturating word-to-byte pack | `vpacksswb`, `vpackuswb` | 1 / 63, 67 / WIG | byte |
| Signed/unsigned saturating dword-to-word pack | `vpackssdw`, `vpackusdw` | 1 / 6B / W0; 2 / 2B / W0 | word |
| Unsigned byte and signed word min/max | `vpminub`, `vpminsw`, `vpmaxub`, `vpmaxsw` | 1 / DA, EA, DE, EE / WIG | byte or word |
| Signed byte and unsigned word min/max | `vpminsb`, `vpminuw`, `vpmaxsb`, `vpmaxuw` | 2 / 38, 3A, 3C, 3E / WIG | byte or word |
| Signed/unsigned dword min/max | `vpminsd/ud`, `vpmaxsd/ud` | 2 / 39, 3B, 3D, 3F / W0 | dword |
| Rounded unsigned byte/word average | `vpavgb/w` | 1 / E0, E3 / WIG | byte or word |
| Low/signed-high/unsigned-high word multiply | `vpmullw`, `vpmulhw`, `vpmulhuw` | 1 / D5, E5, E4 / WIG | word |
| Low dword multiply | `vpmulld` | 2 / 40 / W0 | dword |
| Signed/unsigned even-dword products | `vpmuldq`, `vpmuludq` | 2 / 28 / W1; 1 / F4 / W1 | qword |
| Signed adjacent word multiply-add | `vpmaddwd` | 1 / F5 / WIG | dword |
| Unsigned-by-signed adjacent byte multiply-add | `vpmaddubsw` | 2 / 04 / WIG | word |

These encodings and writemask rules follow the instruction tables in the
[Intel instruction-set reference](https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf)
and the [Intel SDM](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf).
The dword min/max, low-dword multiply and even-dword product forms belong to
AVX-512F; the byte/word forms in this extension require AVX-512BW. Decoding does
not query the host CPU or certify runtime feature availability.

All of these forms retain width-matched XMM/YMM/ZMM0-ZMM31 operands and
128/256/512-bit memory widths, address base/index reads, and full-vector
compressed disp8 scales of 16/32/64 bytes. EVEX P0.R
extends ModRM.reg by 8 and P0.R' extends it by 16, preserving the distinct
ZMM8-15 and ZMM16-23 destination ranges. The reserved encoded all-ones
vvvv/V' fields on EVEX `vmovups` are checked as decoded inverted value zero.
The integer forms have
no EFLAGS or MXCSR effect. K0 encoding means unmasked operation and supplies no
K0 dependency. K1-K7 supply an explicit 64-bit mask-register read. Merge mode
adds a read of the old ZMM destination; zeroing mode adds no implicit old-
destination read, while explicit aliased source operands still read that
register. The decoded destination is written in both modes. No new opcode IDs
or serialized instruction fields are introduced.

`vector_element_bits` describes the result element. In particular, `vpmuldq`
and `vpmuludq` consume even 32-bit source elements but produce eight 64-bit
results, so only mask bits 0-7 select their output qwords. `vpmaddwd` combines
adjacent signed word products into 16 dwords and uses mask bits 0-15.
`vpmaddubsw` combines unsigned first-source bytes with signed second-source
bytes, saturates each adjacent pair sum into a signed word, and uses mask bits
0-31. Mask bits beyond the output element count are ignored. The old
destination is preserved or zeroed at that same output element width.

The four EVEX pack forms narrow both signed source vectors independently
within each 128-bit group. Each group's low 64 result bits come from source
one and its high 64 result bits from source two. `vpacksswb/dw` clamp to
signed byte/word ranges; `vpackuswb/dw` clamp the signed inputs to unsigned
byte/word ranges, so negative inputs become zero. The writemask selects the
narrowed destination bytes or words after packing. Unmasked, merge and `{z}`
forms all retain this ordering at 128, 256 and 512 bits. VL forms clear the
remaining upper ZMM bits. Full-width memory inputs use the existing
16/32/64-byte disp8 tuple scaling; broadcast (including dword-to-word
`m32bcst`), rounding, and W1 dword-to-word encodings remain unsupported.
The existing shared lane evaluator and typed EVEX decompiler path now admit
these four forms through the explicit EVEX shape whitelist, preserving signed
input types, narrowed result types, mask and old-destination dependencies,
memory-read effects, and upper-register clearing.
Windows Debug `hexlab_processors` and `hexlab_decompiler` targets built
successfully in `agent-x86-simd-build` for this extension; no tests were added
or run.

`evaluate_x86_evex_integer` evaluates all explicitly decoded integer forms,
including the original wrapping add/sub subset. It accepts caller-supplied
64-byte source vectors, an optional old destination, and a runtime mask; VL
forms evaluate only their active 16 or 32 bytes and clear the higher bytes.
Masked merge requires old-destination bytes; zero masking does not. The helper
validates width-matched XMM/YMM/ZMM indices and widths, source-memory width, mask identity, and the result
shape before evaluating. Saturating results clamp to the appropriate signed or
unsigned range, averages round up, low products wrap to their result width,
and high-word products retain the specified signedness. Signed word
multiply-add keeps its defined wrapping exceptional result; mixed byte
multiply-add saturates to signed words. Shared bounded lane routines serve
both the existing VEX evaluator and this EVEX evaluator.

The EVEX bitwise subset includes `vpandd/q`, `vpord/q`, and `vpxord/q` for
VL128, VL256, and VL512. These use map 0F, `pp=66`, and opcode DB, EB, or EF;
W=0 selects the dword mnemonic and W=1 selects the qword mnemonic. Each form
uses the same full-width vector register or memory source, result-element
masking, merge/zero behavior, and upper-ZMM clearing as the other supported
EVEX integer operations. Their typed intrinsic shapes preserve 32- or 64-bit
unsigned lanes, and the pure evaluator applies the bitwise operation over the
active vector bytes. Reserved pp values and unsupported maps remain rejected;
the existing VEX `vpand`, `vpor`, and `vpxor` opcode identities are unchanged.

EVEX map `0F3A`, `pp=66` packed integer compare forms decode to a K0-K7
destination and full-width XMM/YMM/ZMM or memory sources. Opcodes `3F/3E`
select signed/unsigned byte lanes with W=0 and word lanes with W=1;
`1F/1E` select signed/unsigned dword lanes with W=0 and qword lanes with W=1.
The 8-bit immediate selects EQ, LT, LE, FALSE, NE, NLT, NLE, or TRUE using
values 0-7. Its upper five bits are reserved. Source lanes use signed or
unsigned ordering according to the mnemonic. A memory source has the full
16/32/64-byte vector width, including compressed disp8 scaling. Register
sources retain the EVEX extension bits; the K destination rejects ModRM.reg
extension because only K0-K7 exist.

EVEX.aaa=0 compares all active lanes and does not read K0. A nonzero aaa
reads its K register and clears output bits for masked-off lanes. K0 is valid
as the destination, including when another K register supplies the mask.
Every output bit beyond the active lane count is zero. The decoder rejects
EVEX.z for this family; it does not add an old-K destination dependency.
`evaluate_x86_evex_mask_compare` returns the exact 64-bit output mask and
active bit count from caller-supplied source bytes and runtime opmask. The
decompiler records a typed lane comparison, optional mask AND, and active-bit
AND as the explicit K output formula. Broadcast and embedded-rounding EVEX.b
forms remain outside this subset.

The decompiler has a separate EVEX integer route rather than extending VEX
comparison or shuffle rules to unrelated encodings. Each intrinsic retains the
two full-width source shapes, the result shape, signedness, optional old
destination, and mask input. For example, a masked mixed-byte multiply-add has
a name ending in `u8x64_i8x64_to_i16x32_evex512_k3_merge`. These remain typed
opaque operations in common IR; pure helper evaluation is not optimizer
constant folding. A memory source is conservatively recorded as a possible
128-, 256-, or 512-bit read according to EVEX.LL. Neither helper nor IR executes memory access/fault suppression,
alignment faults, or CPU feature checks.

Broadcast, embedded rounding, qword min/max selected by W1, low-qword
multiply, EVEX compare-to-mask destinations, and all unlisted maps/prefix/opcode
forms remain explicitly unsupported. EVEX VL vector register indices 16-31
are retained in decoding and formatting. A wrong W
selector cannot silently become a dword operation. Existing reserved prefix
and zeroing-with-K0 checks remain in force. The EVEX whitelist deliberately
does not infer support from an operation's VEX opcode identity.

The common AVX2 integer dataflow slice adds 39 VEX.128/.256 operations in the
families listed above. They decode as non-destructive destination writes with
a full-width register first source and a full-width register or memory second
source, preserve encoded address
dependencies, and clear the upper YMM half for XMM results. Only their exact
0F or 0F38 opcode map with `pp=66` is accepted; other maps and prefix selectors
remain explicitly rejected. These forms use WIG, so either VEX.W value is
accepted. They leave EFLAGS unchanged. New opcode enum members are appended
after all previously persisted IDs.

The pure evaluator covers each added operation using caller-supplied bytes.
`vpandn` complements source one before AND; unsigned averages round up;
signed and unsigned min/max use the specified interpretation. Sign operations
zero, copy, or negate a lane according to the second source, including modular
negation of the most-negative value. `vpmulld` keeps the low dword;
`vpmuldq/udq` multiply only the even dwords into qwords. `vpmaddwd` adds signed
word products with dword wrap, including its exceptional most-negative pair;
`vpmaddubsw` multiplies unsigned source-one bytes by signed source-two bytes,
adds adjacent products, and saturates to signed words. `vpsadbw` writes each
eight-byte absolute-difference sum into a zero-extended qword.

Horizontal add/sub, saturating horizontal word add/sub, pack/unpack, and byte
shuffle operate independently in each 128-bit half of a YMM value. Pack forms
interpret both inputs as signed lanes, then clamp to signed or unsigned output
ranges; their source-one results precede source-two results within each half.
Unpack forms interleave the selected low or high half of both inputs.
`vpshufb` uses each control byte's low four bits as an index within its own
128-bit half and zeros results whose control byte has bit seven set.

Shared operation shape metadata drives decoder result-lane metadata and typed
decompiler intrinsics. Inputs and results retain separate lane widths and
signedness, including mixed-sign multiply-add and narrowing/widening forms;
intrinsic names expose both input shapes, the active output shape, 128-bit
lane grouping, and upper-YMM clearing. Intrinsics retain caller-owned memory
read effects and all decoded register writes. This evaluator remains a pure
helper, not optimizer constant folding or a fault/CPU-feature emulator.
The Debug `hexlab_processors` and `hexlab_decompiler` builds passed for this
expanded subset; no tests were run.

Other EVEX opcodes and exact floating-point execution remain unsupported. MMX, most AVX/VEX forms,
packed floating-point execution, remaining packed integer forms
(including rounded high-word multiply, immediate shuffles/blends,
cross-128-bit permutations, and unsigned comparisons),
other compare/test instructions, precise MXCSR flag/rounding behavior, and exact
upper-lane merge behavior remain outside this slice. See the
[design](superpowers/specs/2026-10-22-x86-simd-design.md) and
[implementation plan](superpowers/plans/2026-10-22-x86-simd.md) for the
integration contract and test matrix.

The variable packed shift family adds AVX2 VEX.128/.256
`vpsllv{d,q}`, `vpsrlv{d,q}`, and `vpsravd`, plus EVEX.128/.256/.512
`vpsllv{w,d,q}`, `vpsrlv{w,d,q}`, and `vpsrav{w,d,q}`. The word forms use map 2 opcodes
10/11/12 (logical right, arithmetic right, logical left); dword and qword
forms use 45/46/47 respectively, with W selecting qword forms and W=0
selecting dwords. The first vector source supplies shifted data; the second
vector source (the ModRM register or full-width memory operand) supplies
per-lane shift counts.
K masking applies per destination lane; merge masking reads the old destination,
and zeroing writes zero to inactive lanes. Counts at or above lane width produce
zero for logical shifts and sign-fill for arithmetic shifts. The pure VEX
evaluator computes dword/qword AVX2 lane results; the EVEX evaluator also
applies result-lane writemasks. VEX `vpsravd` treats W as ignored; qword
arithmetic-right shifts are available only in EVEX. The typed decompiler
retains the lane shape and, for EVEX, mask effects.

The AVX2 immediate packed-shift family decodes VEX.128/.256 `vpsllw/d/q`,
`vpsrlw/d/q`, `vpsraw/d`, and the per-128-bit-lane byte shifts `vpslldq` and
`vpsrldq`. The VEX.vvvv field selects the non-destructive destination, ModRM
r/m supplies the vector source, and the final operand is an unsigned imm8.
Shift counts at or above the element width produce zero for logical shifts and
sign-fill for arithmetic shifts; byte shifts at or above 16 clear each 128-bit
lane. XMM destinations clear the upper YMM half. The pure lane evaluator and
typed decompiler intrinsic retain the immediate count, lane width, memory read,
and upper-half effect.

The AVX `vpabsb/w/d` family decodes VEX.128/.256 `VPABSB`, `VPABSW`, and
`VPABSD` with `VEX.pp=66`, map `0F38`, opcodes `1C/1D/1E`, and the reserved
`vvvv` encoding. The ModRM register is a write-only destination; the register
or full-width memory r/m operand is read. VEX.128 results clear the upper half
of the YMM destination. The pure lane evaluator interprets each input lane as a
signed byte/word/dword, emits its absolute value as an unsigned lane, and
preserves the two's-complement bit pattern for the most-negative input, as the
architectural width cannot represent its positive magnitude. The decompiler
emits a typed unary intrinsic with signed input and unsigned result lane types.
These forms follow Intel's [packed absolute-value instruction definition](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
and Ghidra's [AVX](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/data/languages/avx.sinc#L1397-L1417)
and [AVX2 SLEIGH definitions](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/data/languages/avx2.sinc#L17-L36).

The original 128-bit packed-integer evaluator now covers the already-decoded
`PMINUB`, `PMAXUB`, `PMINSW`, `PMAXSW`, `PMULLW`, `PMULHW`, `PMULHUW`,
`PMULUDQ`, and `PMADDWD` forms. It computes byte/word min/max, low or high
word-product halves, the even-dword unsigned products, and adjacent signed
word-product sums with architectural lane ordering and widths. The API remains
fail-closed on unsupported opcodes and malformed/non-128-bit operand shapes;
callers supply memory bytes. See [SSE2 packed integer semantics](x86-sse2-integer-semantics.md)
for the precise subset.

VEX `VSHUFPS` (`pp=00`) and `VSHUFPD` (`pp=66`) are decoded for 128- and
256-bit vectors. Each has the non-destructive VEX.vvvv source, a register or
full-vector memory source, and an unsigned imm8 selector. The floating-point
payloads are moved as bits: the 32-bit form selects four dwords per independent
128-bit lane (two from each source), while the 64-bit form selects one qword
from each source per lane. For 256-bit `VSHUFPD`, imm8 bits 0/1 control the
low 128-bit lane and bits 2/3 control the high lane; upper imm8 bits are
ignored. VEX.128 clears the destination's upper YMM half. The pure evaluator
and typed decompiler intrinsic preserve lane-local selection, immediate,
memory-read, and upper-half effects. This does not model floating-point
exceptions because these instructions only rearrange bits. EVEX forms and
other AVX shuffle instructions remain outside this slice. See Intel's
[VSHUFPD instruction pseudocode](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)
and [VSHUFPS instruction reference](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf).

AVX2 `VPERMD` decodes only the VEX.256 form of map `0F38`, opcode `36`,
with mandatory `66` and `W=0`. The VEX.vvvv operand supplies one index per
destination lane, and ModRM r/m supplies the vector to permute. Each index uses
its low three bits to select across the eight dwords of the entire 256-bit
vector, rather than independently in each 128-bit half. The pure evaluator
applies the same lane selection to caller-supplied bytes, and typed lifting
retains the 32-bit integer lane shape. VEX.128 and W=1 encodings are rejected;
EVEX variants, including masked forms, remain unsupported. This matches Intel's
[AVX/AVX2 instruction reference](https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf).

## AVX2 immediate dword shuffle

The decoder accepts VEX.128 and VEX.256 `VPSHUFD` (`66 0F 70 /r ib`), requires
the reserved `vvvv` field, and retains the immediate as an explicit operand.
Each 128-bit lane uses its four consecutive two-bit immediate fields to select
the source dword for each destination dword; a 256-bit shuffle therefore does
not cross the lane boundary. The packed evaluator applies the same rule to
caller-owned bytes, while typed lifting records an integer dword vector and
the VEX.128 upper-YMM clearing effect. EVEX and other immediate shuffle forms
remain unsupported. See Intel's
[AVX/AVX2 instruction reference](https://www.intel.com/content/dam/develop/external/us/en/documents/319433-024-697869.pdf).


## SSE4.2 scalar CRC32C

The native scalar decoder now recognizes the SSE4.2 CRC32 instruction's
`F2 0F 38 F0 /r` byte-source form and `F2 0F 38 F1 /r` word/dword/qword
source forms. The mandatory F2 prefix distinguishes CRC32 from MOVBE. Its
destination is a read/write 32-bit GPR in legacy16/32 and by default in long
mode. REX.W selects a 64-bit destination in long mode. F0 always reads eight
source bits; F1 selects the source width through ordinary operand-size rules
(16/32 in legacy modes, 16/32/64 in long mode). For REX.W, the supported source
width is 8 or 64. Source may be a register or matching-width memory operand;
there is no immediate or memory destination. Byte-register/REX restrictions,
address-size overrides, segment/SIB/displacement parsing and truncation limits
remain native scalar rules. No XMM/YMM register, MXCSR, or FLAGS effect is
introduced. Conflicting mandatory prefixes and LOCK are rejected by the
existing prefix policy.

CRC32 consumes only the old destination's low 32 bits and always produces a
32-bit CRC. A 64-bit destination receives explicit zero-extension; a 32-bit
long-mode destination also defines its full 64-bit view as zero-extended.
The typed lifter keeps the old seed and data as pre-instruction inputs, with
the memory-read effect retained for memory forms. The polynomial operation is
named `x86_crc32c` and is distinct from ordinary integer arithmetic.

`evaluate_x86_crc32c` performs the exact reflected Castagnoli recurrence with
polynomial `0x82F63B78`, equivalent to Intel's normal-form `0x11EDC6F41`.
It consumes low source bytes first and applies no implicit initial/final XOR.
Sources are bounded to 8/16/32/64 bits; unsupported widths return no result.
`evaluate_x86_crc32c_instruction` additionally checks that the decoded
instruction has a read/write GPR seed, a read-only GPR or memory source of a
supported width, and no memory destination before invoking that helper. The
caller still supplies the sampled seed/source and commits the result.
The optimizer calls this helper only for typed constant seed/data expressions,
then uses ordinary zero-extension folding for a wider destination. Unknown
inputs remain typed formulas. Memory bytes and CPU state are caller-owned.

Encoding, polynomial, zero-extension, and flag behavior follow Intel's primary
[CRC32 instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf).
CPUID.SSE4_2 availability and memory/segment faults are not executed or assumed
proved by decoding. APX/EVEX CRC32 variants, complete cross-width GPR aliases,
and independent encoding/CPU-oracle validation remain unsupported.


## Legacy SSE4.2 signed qword greater-than

The legacy `66 0F 38 37 /r` `PCMPGTQ` form decodes with a 128-bit XMM
destination and register or 128-bit memory source. It compares the two
64-bit lanes as signed two's-complement integers; each destination lane is
all ones when the destination's old lane is greater, and zero otherwise.
The destination is read/write, and the typed lifter uses signed qword inputs
and two qword result lanes. The pure evaluator compares sign-biased unsigned
bit patterns, avoiding signed-overflow corner cases at `INT64_MIN` and
`INT64_MAX`. The mandatory 66 prefix and 0F38 opcode map are validated.
SSE4.2 feature availability, memory faults, and execution are caller-owned;
other legacy qword predicate forms remain outside this slice.

## VEX signed qword greater-than

VEX.128/.256 `VPCMPGTQ` now has explicit signed-64 input and unsigned-64
mask-result dataflow shapes shared by the evaluator and typed lifter. Each
source lane is interpreted as a two's-complement `int64_t`, compared directly
without subtracting, and produces `0xffffffffffffffff` only when source one
is strictly greater than source two; equal or lesser lanes produce zero.
This includes INT64_MIN, INT64_MAX, negative values, and sign-boundary pairs
without signed arithmetic overflow. The existing generic lane evaluator
already supported this signed comparison; the dedicated shape now also
covers its explicit dataflow dispatch and rejects contradictory lane metadata.

The lifter preserves signed qword source types and unsigned qword mask types,
with two active lanes for XMM and four for YMM. It uses the architectural
`vpcmpgtq` name and fixes the fallback dispatch's missing 64-bit lane width,
which could previously select a zero-width lane shape. VEX.128's upper YMM
clearing and register/memory source effects are retained. A contradictory
nonzero element width becomes an opaque effect rather than a guessed type.
Other equality, ordered, and immediate-predicate families are unchanged.

The operation follows Intel's primary [PCMPGTQ/VPCMPGTQ reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).
EVEX compare-to-K variants, CPU feature/fault execution, and independent
oracle validation remain outside this bounded change.

## MOVMSK extraction

Legacy `MOVMSKPS`, `MOVMSKPD`, and `PMOVMSKB`, plus 64-bit-mode VEX.128/.256
`VMOVMSKPS`, `VMOVMSKPD`, and `VPMOVMSKB`, write a 32-bit GPR from an XMM or
YMM register source. REX.W/VEX.W do not widen the result. The typed lifter
emits an integer32 scalar result from a lane-typed vector input: each floating
form extracts one sign bit per 32- or 64-bit lane, while the byte form extracts
one sign bit per byte lane. All output bits above the active lane count are
zero. These operations do not modify FLAGS or MXCSR.

`x86_mask_extract.hpp` provides the single caller-driven
`evaluate_x86_mask_extract` adapter for all six forms. It accepts source bytes
in architectural order, validates the decoded register operands and vector
width, and returns a low-bit-first mask. It computes the mask only; register
reads/writes and CPU feature checks remain caller-owned or unsupported. EVEX
forms are not included.

## AVX2 VPSIGN lifting

The VEX.128 and VEX.256 `VPSIGNB`, `VPSIGNW`, and `VPSIGND` forms now lift to typed packed-integer intrinsics with exact 8-, 16-, or 32-bit lane shapes. The signed control lane selects the result for each lane: zero clears it, a negative value negates the matching data lane modulo the lane width, and a positive value preserves it. The intrinsic keeps the original data/control operand order, memory-source read effect, destination write, and VEX.128 upper-YMM clear from the decoded instruction. Exact integer evaluation remains available through `evaluate_x86_avx_packed`; no flags or MXCSR state are involved.

## SSE4.1 PTEST

The legacy `66 0F 38 17 /r` form decodes as `PTEST xmm, xmm/m128`, with two
read operands and an EFLAGS read/write to preserve unaffected bits.
`evaluate_x86_ptest_instruction` validates
the decoded shape and caller-supplied 128-bit values. It defines CF when
`left & right` is zero and ZF when `~left & right` is zero; OF, SF, AF, and PF
are cleared. The returned mask identifies those six defined EFLAGS bits; all
other state and memory reads remain caller-owned. SSE4.1 feature gating and
fault delivery are not modeled. The operation follows Intel's
[PTEST instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

VEX `VPTEST` is decoded for XMM and YMM register/memory forms. VEX.L selects
the 128- or 256-bit test width; `VEX.vvvv` must have its reserved encoding,
and the mandatory prefix is 66. `evaluate_x86_vptest_instruction` applies the
same CF/ZF subset tests and clears OF/SF/AF/PF over the active vector width.
The caller supplies vector bits and receives only the six defined flag bits;
memory fetch, AVX feature checks, and fault delivery remain caller-owned.
Typed decompiler lifting is not included. Encoding and flag behavior follow
Intel's [PTEST/VPTEST reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-manual-volume-2b-manual.pdf).

## SSSE3 packed absolute value

The original decoder's `PABSB`, `PABSW`, and `PABSD` forms now have typed
signed-lane lift and the caller-driven `evaluate_x86_ssse3_absolute_instruction`
helper. Each source lane is
interpreted as a two's-complement 8-, 16-, or 32-bit integer and converted to
its magnitude modulo the same lane width. The most-negative input remains
unchanged, as required by fixed-width two's-complement representation. The
destination is a write-only XMM value; register and m128 sources are reads.
FLAGS and MXCSR are unchanged. Feature gating and runtime memory access remain
caller-owned.

## EVEX unpack interleave

EVEX map-1 `66` forms `VPUNPCKLBW/LWD/LDQ/LQDQ` and
`VPUNPCKHBW/HWD/HDQ/HQDQ` now decode in 128-, 256-, and 512-bit vector lengths.
They reuse the existing packed integer lane dataflow, so the evaluator
interleaves the low or high half independently in each 128-bit lane. EVEX
destination writemasks use the interleaved result element width; merge masking
preserves the old destination and zeroing masking clears inactive elements.
The decompiler retains the operation as a typed packed-integer intrinsic and
preserves source memory reads, opmask state, and upper-vector clearing for
VL forms. This adds no broadcast, embedded rounding, or new flag behavior.

The decoder accepts the instruction family's WIG encoding and requires the
normal EVEX packed-integer prefix rules. Memory access and CPU feature checks
remain caller-owned. Decoder fixtures were added for all eight ZMM register
forms; tests/builds were not run for this change.
