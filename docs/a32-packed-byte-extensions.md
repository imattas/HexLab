# A32 and Thumb-2 packed-byte extension decoding and lifting

The A32 and Thumb-2 decoders recognize the packed-byte extension family:

- `SXTB16` and `UXTB16` extend two selected bytes into the two halfword lanes.
- `SXTAB16` and `UXTAB16` add those extended lanes to the corresponding halfwords
  of an accumulator register.

The source may be rotated right by 0, 8, 16, or 24 bits before byte selection.
The decoder retains that rotation as a shifted-register operand. It records the
destination write, source read, optional accumulator read, and conditional
execution. The `Rn = PC` alias selects the non-accumulating form; PC cannot be
used as `Rd` or `Rm`. These instructions do not write APSR.

The decompiler models each lane explicitly. It sign- or zero-extends the
selected low and high source bytes to 16 bits; extend-add forms add the
corresponding accumulator halfwords modulo 2^16. The two lanes are then packed
into the 32-bit destination. Rotation occurs before byte selection, so ROR #24
correctly transfers the low source byte into the high result lane. Conditional
A32 execution and known Thumb IT predicates preserve the old destination on
the false path. These operations preserve APSR.

The decoder does not check architecture-profile DSP availability, and ARMv8
SP register relaxations remain outside this profile-free path. Other packed
DSP operations are not covered. Encoding and operation details follow Arm's
[A32 SXTB16 reference](https://support.arm.com/documentation/ddi0406/b/Application-Level-Architecture/Instruction-Details/Alphabetical-list-of-instructions/SXTB16?lang=en)
and the corresponding SXTAB16/UXTB16/UXTAB16 instruction descriptions.
