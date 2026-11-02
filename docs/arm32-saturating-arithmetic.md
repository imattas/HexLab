# A32 and Thumb-2 saturating arithmetic

The decoders recognize `QADD`, `QSUB`, `QDADD`, and `QDSUB` in A32 and
Thumb-2. All forms retain destination and source register access facts and are
marked as potentially setting the sticky APSR.Q bit. They do not write NZCV.
PC operands are rejected. Thumb-2 SP operands are rejected; A32 accepts
encodings with SP where permitted by the instruction form.

`evaluate_arm32_saturating_instruction` takes the Rm and Rn values as 32-bit
bit patterns plus the incoming Q state. `QADD` and `QSUB` saturate signed
32-bit addition/subtraction. `QDADD` and `QDSUB` first double and saturate Rn,
then add/subtract that result from Rm with a second signed saturation. The
returned Q bit is sticky: it is the incoming bit OR any saturation in either
stage. The helper evaluates arithmetic only; callers resolve A32 conditions
or Thumb IT predicates and commit results.

The supported operation and saturation behavior follow Arm's
[A32/T32 instruction reference](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab)
and [Cortex-M4 instruction guide](https://documentation-service.arm.com/static/5f2ac76d60a93e65927bbdc5?token=).

## Decompiler lifting

A32 and Thumb QADD/QSUB/QDADD/QDSUB lift to 32-bit signed saturation operations, retaining each architecture's signed overflow behavior. Predicated A32 forms and known Thumb IT predicates select the prior destination when false; unknown Thumb IT state remains an opaque effect. The lifted destination expression is named `qadd_s32_sticky_q_may_set`, `qsub_s32_sticky_q_may_set`, `qdadd_s32_sticky_q_may_set`, or `qdsub_s32_sticky_q_may_set` to preserve the distinction from wrapping arithmetic and make the possible sticky Q update visible. The IR does not yet model Q as an independently versioned flag, and this lowering does not reconstruct a concrete overflow condition for Q.