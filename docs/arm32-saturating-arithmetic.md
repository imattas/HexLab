# A32 and Thumb-2 saturating arithmetic

The decoders recognize `QADD`, `QSUB`, `QDADD`, and `QDSUB` in A32 and
Thumb-2, plus scalar `SSAT` and `USAT` in A32 and Thumb-2. All forms retain
destination and source register access facts and are marked as potentially setting sticky
APSR.Q. They do not write NZCV. PC operands are rejected. Thumb-2 SP operands
are rejected; A32 accepts encodings with SP where permitted by the form.

`evaluate_arm32_saturating_instruction` takes the Rm and Rn values as 32-bit
bit patterns plus incoming Q. QADD/QSUB saturate signed 32-bit addition or
subtraction. QDADD/QDSUB first double and saturate Rn, then add/subtract that
result from Rm with a second signed saturation. The returned Q bit is sticky:
incoming Q OR any saturation in either stage. Callers resolve predicates and
commit results.

For SSAT/USAT, the helper takes Rn's bit pattern as its `rm` argument;
`rn` is ignored. It applies the decoded LSL/ASR before clamping. `SSAT #n`
admits 1 through 32 signed result bits (encoded field n−1); `USAT #n` admits 0
through 31 unsigned result bits. LSL #0 leaves the input unchanged. In A32,
ASR with encoded imm5 zero is ASR #32. Thumb-2 uses split imm3:imm2 shift
encoding and reserves ASR with zero shift for SSAT16/USAT16, which this scalar
decoder rejects. Bounds are exact, including the USAT #0 range [0,0]. Incoming
Q remains set, and a clamp sets it. Callers resolve the A32 condition or Thumb
IT predicate and commit the result and Q state.

The A32 decoder admits only the SSAT/USAT fixed patterns with LSL or ASR
selectors and GPRs R0–R14. The Thumb-2 T1 decoder admits the corresponding
split immediate shift forms with GPRs R0–R12. Both reject PC operands; the
Thumb-2 scalar decoder also rejects SP and the SSAT16/USAT16 selector pattern.

The supported operation and saturation behavior follow Arm's
[A32/T32 instruction reference](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab)
and [Cortex-M4 instruction guide](https://documentation-service.arm.com/static/5f2ac76d60a93e65927bbdc5?token=).

## Decompiler lifting

A32 and Thumb QADD/QSUB/QDADD/QDSUB lift to 32-bit signed saturation
operations. Predicated A32 forms and known Thumb IT predicates select the
prior destination when false; unknown Thumb IT state remains opaque. The IR
does not yet model Q as an independently versioned flag, so Q is represented
as a sticky-Q effect marker rather than a concrete flag output.

A32 and Thumb-2 SSAT/USAT lift with their decoded shift, exact signed/unsigned
saturation width, and sticky-Q marker. Conditional forms select the prior destination if
the condition fails. Q remains an effect marker rather than a separately
versioned flag value in the IR.
