# RISC-V Zfh scalar decode and lifting

The decoder recognizes the scalar half-precision Zfh forms on RV32 and RV64:
`FLH`/`FSH`; arithmetic and square root; sign injection, minimum/maximum and
FMA variants; ordered comparisons and classification; `FCVT` between H and
W/WU/L/LU or S/D; and `FMV.X.H`/`FMV.H.X`. The Zfa additions `FMINM.H`,
`FMAXM.H`, `FLEQ.H`, and `FLTQ.H` are also decoded. Existing `FLI.H`,
`FROUND.H`, and `FROUNDNX.H` remain available.

Typed effects use 16-bit logical floating values for H operations while the
architectural FPR register storage remains 64 bits. `FLH` reads 16 bits from
memory; `FSH` writes 16 bits. Conversion lifting keeps source and result widths
explicit, sign-extends W results on RV64 as required, and represents conversions
as named intrinsics so rounding, saturation, NaN, and exception behavior is not
lost. Exact widening (`FCVT.S.H`, `FCVT.D.H`, `FCVT.D.S`) does not read `frm`;
rounding conversions include the static mode or dynamic `frm`. Half comparisons
produce XLEN-sized integer results. Invalid format/reserved function encodings
remain rejected by the decoder.

This slice covers decode, formatting, generic dispatch, register and memory
effects, and typed lifting. It does not add a host-independent raw-bit evaluator
for the general H arithmetic family, extension-profile gating, physical FPR
NaN-boxing, or Zfh vector instructions. `FCVT.L*` and `FCVT.LU*` are only
accepted on RV64.

The supported instruction encodings follow the ratified RISC-V unprivileged
specification's [Zfh extension](https://docs.riscv.org/reference/isa/unpriv/zfh.html)
and [Zfa extension](https://docs.riscv.org/reference/isa/unpriv/zfa.html).
