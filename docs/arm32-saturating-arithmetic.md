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
