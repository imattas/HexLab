# RISC-V vector configuration decoding

The processor decoder recognizes the RVV 1.0 `vsetvli`, `vsetivli`, and `vsetvl`
configuration instructions in RV32 and RV64 contexts. It preserves the scalar
destination and AVL operands, the encoded vtype immediate or scalar vtype source,
and the implicit `vl` and `vtype` register writes. All three forms also reset
`vstart` to zero. Vector operations and memory forms now retain implicit reads
of `vl`, `vtype`, and `vstart`, and write `vstart` as zero on successful
completion. The generic instruction model preserves these
effects and the formatter renders supported immediate vtype settings in
`eSEW, LMUL, tail-policy, mask-policy` form; unsupported/reserved settings keep
their raw immediate.

The decompiler emits `vsetvli`, `vsetivli`, and `vsetvl` as named intrinsics
whose operands include AVL/vtype inputs and implicit configuration reads (for
the `rd=x0, rs1=x0` current-VL form). Their writes include `vl`, `vtype`,
`vstart`, and the scalar `rd` where applicable. This is an effect-preserving
operation record; the decompiler does not infer runtime AVL values or update
configuration state across control flow.

`evaluate_riscv_vector_configuration` evaluates one decoded configuration
instruction from caller-supplied XLEN, implementation VLEN, source GPR values,
and the previous VL. It applies the AVL rules for register, immediate, and
`x0` forms, computes `VLMAX` from SEW and signed LMUL, and returns the new
encoded vtype, VL, and zero VSTART. When AVL exceeds VLMAX it deterministically
chooses VLMAX, a spec-permitted result even in the implementation-defined
balancing interval just above VLMAX. For an invalid vtype it
returns the architectural `vill` state with VL and VSTART zero. The result
retains optional SEW/LMUL and the `vta`/`vma` policy bits when the setting is
valid. This is a caller-driven single-instruction evaluator; it does not track
GPR values or propagate vector configuration through control flow. Its
supported implementation model is VLEN 64..65528 bits, SEW 8..64, and LMUL
mf8..m8; implementation-specific ELEN and execution limits remain outside the
model. The register effect describes normal completion; trap-time `vstart`
updates and restart behavior are not modeled.

The decoder also recognizes a bounded RVV integer elementwise subset:
VADD.VV/VX/VI, VSUB.VV/VX, VRSUB.VX/VI, and VAND/VOR/VXOR VV/VX/VI. It records
vector and scalar operand classes and implicit v0 reads for masked forms.
VRSUB's vector-vector encoding is rejected as reserved. These operations lift
as named conservative intrinsics. Integer compares (VMSEQ/VMSNE/VMSLT[U]/VMSLE[U]
and VMSGT[U], in the architectural VV/VX/VI forms) and shift/min-max operations
are also decoded and lifted by name. Vector multiply-low/high signedness forms
and the VV/VX forms of VDIVU, VDIV, VREMU, and VREM are recognized. The
formatter retains operation form and the `.t` masked suffix.

`evaluate_riscv_vector_integer_operation` provides a lane evaluator for these
currently supported elementwise operations: add/sub/reverse-subtract, logical
operations, shifts, signed/unsigned min/max, low/high multiply, signed/unsigned
divide/remainder, and comparisons. It also evaluates `vrgather.vv/vx/vi`,
`vslideup.vx/vi`, and `vslidedown.vx/vi`, including gather indices beyond
VLMAX yielding zero and slide-up's preserved low destination elements. Its
configuration can be supplied directly
or constructed from a checked architectural `vtype` value by
`make_riscv_vector_integer_config`. The caller supplies implementation VLEN,
current VL/VSTART, source lane arrays, an optional v0 predicate-byte array, and
old destination lanes. It calculates VLMAX from SEW and signed LMUL encodings,
checks the lane-array shapes, applies the active range and predicate, and
preserves inactive, prestart, and tail lanes conservatively. Signed and
unsigned divide/remainder honor RISC-V's divide-by-zero and signed-overflow
results. Integer comparisons return 0/1 mask bits per lane.

Lifting preserves these operations as named intrinsics, includes implicit
`vl`/`vtype` input dependencies for vector operations, and includes v0 when the
instruction is masked. Result operations also carry the old destination as
an input because prestart, masked-off, slide-up, and undisturbed tail elements
can preserve its value. Vector loads retain the same destination dependency.
The generic instruction shape does not carry decoded
SEW/LMUL/VL values, so decompilation does not currently produce statically
typed lane expressions or execute masks/tails. The lane evaluator handles
mask/tail undisturbed behavior only; when vma/vta request agnostic results it
chooses the old destination as a conservative representative. Fractional LMUL
is supported when VLMAX is integral. Unsupported SEW, reserved LMUL, `vill`,
implementation-specific limits, whole-register operations, reductions,
permutation/slide operations, saturating/averaging operations, widening
arithmetic beyond MAC, and narrowing forms remain outside this slice.

Unit-stride integer `vle8.v`, `vle16.v`, `vle32.v`, `vle64.v` and corresponding
`vse*.v` forms are recognized for RV32 and RV64. The decoder accepts only
`nf=0`, `mew=0`, `mop=00`, and zero `lumop`/`sumop`; it records the scalar base,
vector operand, element width, memory read/write, and implicit v0 read for
masked (`vm=0`) forms. Formatting retains the width and `.t` mask suffix. The
decompiler represents these as conservative `vle.unit`/`vse.unit` intrinsics
with read/write memory effects.

Single-field integer strided `vlse8/16/32/64.v` and `vsse8/16/32/64.v` forms
are also decoded. The scalar stride register is retained as an explicit read,
alongside the base, vector data operand, element width, memory effect, and
implicit v0 read when masked. Formatting retains the `vlse`/`vsse` mnemonic,
width, stride register, and `.t` mask suffix; lifting uses named
`vlse.strided`/`vsse.strided` memory intrinsics.

`plan_riscv_vector_memory_accesses` evaluates active element addresses for
unit-stride and strided integer forms from an explicit implementation VLEN,
checked `vtype`, `vl`, `vstart`, XLEN-width base/stride values, and optional
predicate bytes. It validates the derived EMUL range, skips prestart, masked,
and tail elements, and rejects address wrap instead of guessing. It returns an
address plan; it does not read/write memory or model alignment/access faults,
fault-only-first behavior, or partial-fault updates. Strided and unit-stride
loads/stores share the same VLMAX lane count for valid EEW/SEW/LMUL
combinations.

Single-field indexed integer `vluxei*.v`, `vloxei*.v`, `vsuxei*.v`, and
`vsoxei*.v` forms are also decoded for index EEW 8, 16, 32, or 64. Indexed
loads and stores preserve the vector index register, scalar base, index EEW,
mask read, and `vl`/`vtype` dependencies. The decompiler emits explicit
ordered or unordered indexed-memory intrinsics with read/write memory effects.
`plan_riscv_vector_indexed_memory_accesses` accepts zero-extended byte offsets
for each index lane, checks the derived index EMUL, lane count, mask length,
and base-plus-offset range, then returns active addresses. Index values wider
than XLEN are truncated to their low XLEN bits before address addition. It does
not perform memory accesses or model aliasing, ordering, faults, or partial
vector updates.
Segmented and fault-only-first forms remain unsupported.

The gather/slide subset recognizes `vrgather.vv/vx/vi`, `vslideup.vx/vi`, and
`vslidedown.vx/vi`. The decoder preserves the vector/scalar source class,
zero-extended five-bit immediate index/offset, destination/source vector
registers, masked-v0 read, and implicit `vl`/`vtype` dependencies. These
operations lift as named opaque intrinsics; the generic IR does not know the
runtime VLEN/LMUL group boundaries, so it cannot fold them during decompilation
or prove the architecturally required group non-overlap. The standalone lane
evaluator accepts caller-supplied VLEN/vtype and preserves masked, prestart,
and tail lanes from the supplied destination. Slide1, segmented loads/stores,
fault-only-first, floating-point vector memory, and other vector memory forms
remain unsupported.

Segmented, whole-register, fault-only-first, and other vector memory forms
remain unsupported. The decoder preserves encoded EEW and
vtype dependencies without knowing implementation VLEN. The execution helper
validates a caller-supplied configuration; implementation-specific ELEN and
actual memory accesses remain outside this bounded static model.

The decoder supports the encoded RVV 1.0 forms listed here without claiming a
complete RVV implementation; implementation-specific VLEN/ELEN and execution
semantics remain outside this bounded static representation.

## Base vector floating-point elementwise slice

The RVV decoder recognizes base `vfadd`, `vfsub`, `vfmul`, and `vfdiv` in
`.vv`/`.vf`; `vfsgnj`, `vfsgnjn`, `vfsgnjx`, `vfmin`, and `vfmax` in those same
forms; and mask-producing `vmfeq`, `vmfne`, `vmflt`, and `vmfle` in `.vv`/`.vf`
plus `vmfgt.vf` and `vmfge.vf`. These encodings use the OPFVV/OPFVF operand
classes and retain vector versus scalar FPR sources. SEW is runtime state, so
the decoder does not claim a specific lane width. The base floating-point
operations require an implementation setting with SEW 32 or 64; SEW 16 and
other unsupported settings remain runtime constraints rather than being
evaluated by this stateless decoder.

The eight single-width fused multiply-add/subtract operations (`vfmacc`,
`vfnmacc`, `vfmsac`, `vfnmsac`, `vfmadd`, `vfnmadd`, `vfmsub`, and `vfnmsub`)
are recognized in `.vv` and `.vf` forms. They retain `frm` and accrued
`fflags` dependencies, masked `v0`, and old `vd` input; `.vf` retains its FPR
scalar source. Each remains a named floating-vector intrinsic because this
stateless decode/lift path does not choose a runtime rounding mode or compute
fused IEEE lane results and exception flags.

The fused instruction equations and operand-overwrite forms follow the
[RISC-V V specification, §30.1.13.6](https://docs.riscv.org/reference/isa/unpriv/v-st-ext.html#vector-single-width-floating-point-fused-multiply-add-instructions).
For comparison with Ghidra's RISC-V SLEIGH work, see its
[RVV SLEIGH support change](https://github.com/NationalSecurityAgency/ghidra/pull/5778);
that change describes instruction recognition and explicitly notes that it
does not yet provide p-code semantics, so this implementation uses the ISA
specification for operation effects rather than treating SLEIGH as an
authoritative semantic source.

The decompiler keeps the operations as named floating-vector or boolean-mask
intrinsics. Every operation retains implicit `vl`, `vtype`, and `vstart` reads,
the normal-completion `vstart` write, masked `v0`, and the old destination
input needed for prestart, masked-off, and undisturbed tail lanes. Rounded
add/subtract/multiply/divide additionally read `frm`; they and the comparison
and min/max families read the old sticky `fflags` value and write its updated
value. Sign-injection operations do not read `frm` or `fflags` and do not write
`fflags`. An invalid `frm` value makes execution reserved even for operations
that do not consult rounding state; this static decoder does not inspect the
runtime CSR value. Equality and inequality comparisons may set NV for
signaling NaNs, while ordered comparisons may set NV for quiet or signaling
NaNs. Min/max may set NV for signaling NaNs. The intrinsic preserves the
family and these state dependencies without calculating IEEE-754 results or
per-lane exception values. A reserved `frm` remains outside this static check.

The standalone `evaluate_riscv_vector_floating_operation` helper now evaluates
the bit-exact `vfsgnj`, `vfsgnjn`, and `vfsgnjx` sign-injection families,
`vfmin`/`vfmax`, and all decoded vector floating comparisons for SEW 32 or 64.
It accepts raw IEEE element bit patterns, caller-unboxed scalar FPR bits,
`vstart`, `vl`, masked predicate lanes, and the old destination. It preserves
inactive and tail lanes, handles signed zero, propagates a numeric operand for
single-NaN min/max, returns the canonical NaN for two NaN inputs, and reports
the union of per-active-lane NV exceptions in `fflags_set`. FEQ/FNE raise NV
only for signaling NaNs; ordered comparisons raise NV for any NaN. Sign
injection is bitwise and does not raise flags. Floating arithmetic, dynamic
rounding, inexact/underflow/overflow/divide-by-zero flags, and wider or
half-precision lanes remain outside the evaluator.

Reductions, conversions, classification, reciprocal and
square-root operations, widening floating-point arithmetic, half-precision
vector operations, and all other vector floating-point encodings remain
unsupported. A recognized FP funct6 with a reserved operand class is invalid;
FP funct6 values outside this slice remain unsupported.

The decoder and lane evaluator also support the non-widening integer
multiply-accumulate/subtract forms `vmacc.vv/vx`, `vnmsac.vv/vx`,
`vmadd.vv/vx`, and `vnmsub.vv/vx`. They use the destructive destination as an
input. `vmacc`/`vnmsac` accumulate the low product into the old destination;
`vmadd`/`vnmsub` multiply the old destination by the second multiplicand and
add/subtract it from `vs2`. Masked encodings retain the v0 predicate dependency,
while inactive and tail lanes retain the caller-supplied destination value.
These operation equations, operand classes, and funct6 assignments follow
[RVV 1.0 section 30.1.11.13](https://docs.riscv.org/reference/isa/v20240411/unpriv/v-st-ext.html#vector-single-width-integer-multiply-add-instructions).
The decoder also recognizes seven widening integer multiply-accumulate forms:
`vwmaccu.vv/vx`, `vwmacc.vv/vx`, `vwmaccsu.vv/vx`, and `vwmaccus.vx`.
These overwrite a 2*SEW-bit accumulator with the full signed/unsigned product
plus its old value. The lane evaluator reports the result element width and
handles SEW 8/16/32 and effective destination LMUL at most 8, including
masked/prestart/tail preservation. SEW 64 would require 128-bit lanes and
therefore remains symbolic only. The lane API does not receive physical vector
register group identities, so it cannot validate group alignment or overlap.
The seven encodings and operand signedness follow the official RVV 1.0
[widening multiply-add specification](https://docs.riscv.org/reference/isa/unpriv/v-st-ext).
Non-accumulating widening multiply is also decoded and lifted for
`vwmulu.vv/vx`, `vwmulsu.vv/vx`, and `vwmul.vv/vx`. The lane evaluator returns
the full 2*SEW product for SEW 8/16/32 and effective destination LMUL at most
8, preserving masked, prestart, and tail lanes; 128-bit SEW=64 results remain
symbolic. `vwmulsu` treats `vs2` as signed and `vs1`/`x[rs1]` as unsigned.
The encoding and signedness follow the official RVV 1.0
[widening integer multiply specification](https://docs.riscv.org/reference/isa/unpriv/v-st-ext).
The decoder and decompiler also recognize widening add/subtract `vwadd`,
`vwaddu`, `vwsub`, and `vwsubu` in `.vv`, `.vx`, `.wv`, and `.wx` forms.
Narrow-source forms sign- or zero-extend both narrow operands to 2*SEW;
wide-source forms combine a 2*SEW vector operand with an extended narrow
vector or scalar operand. The decompiler keeps each as a named vector effect,
including the old destination, mask, and configuration dependencies.
The lane evaluator executes these forms for SEW 8, 16, and 32, reports the
2*SEW result width, and rejects configurations whose widened EMUL exceeds m8.
Wide-source forms use the `vs2` lane at 2*SEW and the `vs1` lane or scalar at
SEW; signed forms sign-extend the narrow operand and unsigned forms zero-extend
it. The output lane count is unchanged because both EEW and EMUL double. Masked,
prestart, and tail lanes retain the caller-supplied old destination. SEW 64
requires 128-bit lane values and remains symbolic. Destination group alignment
and overlap cannot be validated because the lane API receives no physical
register group identities; implementation-specific vector limits also remain
outside the model.
