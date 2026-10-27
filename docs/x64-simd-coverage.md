# x86 SSE2 integer and scalar floating-point coverage

HexLab's initial original SIMD decoder slice is scoped to these instruction
families:

| Family | Forms |
| --- | --- |
| Packed moves | `movdqa`, `movdqu` |
| Packed integer arithmetic | `paddb/w/d/q`, `psubb/w/d/q`, signed and unsigned saturating byte/word add/sub (`paddsb/sw`, `paddusb/usw`, `psubsb/sw`, `psubusb/usw`) |
| Packed integer logic | `pand`, `pandn`, `por`, `pxor` |
| Packed integer shifts | Variable-count and immediate-count `psllw/d/q`, `psrlw/d/q`, `psraw/d` |
| Packed integer compare | `pcmpeqb/w/d`, `pcmpgtb/w/d` |
| Packed integer multiply/min/max | `pmullw`, `pmulhw`, `pmulhuw`, `pmuludq`, `pmaddwd`, `pminub`, `pmaxub`, `pminsw`, `pmaxsw` |
| Packed integer shuffle | `pshufd` with its encoded byte selector |
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
| AVX-512 packed compare to mask | EVEX.128/.256/.512 `vpcmpb/w/d/q` and `vpcmpub/uw/ud/uq`, with immediate predicates 0-7; floating `vcmpps/pd` supports broadcast memory input or register-source SAE |

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

Legacy scalar `ADDSS/ADDSD`, `SUBSS/SUBSD`, `MULSS/MULSD`, and `DIVSS/DIVSD`
carry an implicit whole-MXCSR read/write dependency in the decoded effects and
typed lift. The lift passes the incoming MXCSR value to the scalar arithmetic
intrinsic and defines an opaque outgoing MXCSR version. It does not calculate
rounding, sticky exception flags, or unmasked-exception retirement.

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
result; sticky MXCSR flag updates remain the caller's responsibility. Masked-off
lanes are neither compared nor allowed to raise exceptions, and the output is
limited to the active low K bits. Embedded SAE permits the K result to retire
even when the corresponding exceptions are unmasked; the helper still reports
the comparison's invalid/denormal conditions, and callers must suppress sticky
status updates for SAE. Destination zeroing and invalid encodings are rejected.
VEX.128/.256 packed floating
compare-to-vector forms are also decoded and lifted for all 32 immediate
predicates. They retain vector operands and results, VEX.128 upper-YMM clearing,
memory reads, and MXCSR input/output dependencies. Their exact lane truth
tables and exception retirement are not evaluated by the VEX lane helper; the
compare evaluator described above accepts only EVEX compare-to-K instructions.
Sticky MXCSR flag updates remain the caller's responsibility; floating
arithmetic remains an opaque state-aware intrinsic.
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
