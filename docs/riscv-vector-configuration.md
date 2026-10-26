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
fault-only-first, floating-point, and other vector memory forms remain unsupported.

Segmented, whole-register, fault-only-first, floating-point, and other vector
memory forms remain unsupported. The decoder preserves encoded EEW and
vtype dependencies without knowing implementation VLEN. The execution helper
validates a caller-supplied configuration; implementation-specific ELEN and
actual memory accesses remain outside this bounded static model.

The decoder supports the encoded RVV 1.0 forms listed here without claiming a
complete RVV implementation; implementation-specific VLEN/ELEN and execution
semantics remain outside this bounded static representation.

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
Carry/borrow and other widening operations are not included.
