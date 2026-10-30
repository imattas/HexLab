# x87 FSCALE Semantics

`evaluate_x87_scale` models exact normal-result cases of FSCALE from raw
binary80 operands. It truncates finite ST(1) toward zero, adds that integer to
ST(0)'s unbiased exponent, and leaves ST(0)'s significand and sign unchanged.
Signed zero in ST(0) is preserved. The helper clears FSW.C1 on the normal
nonempty-stack path and identifies C0/C2/C3 as undefined; other supplied FSW
bits are preserved.

The helper accepts zero or normal finite ST(1), and zero or normal finite
ST(0). A finite ST(1) whose truncated magnitude exceeds 32767 is unsupported.
For a nonzero ST(0), exponent underflow or overflow is unsupported, as are
subnormal and pseudo-denormal inputs, infinities, NaNs, unnormal encodings, and
stack faults. Those cases return no result rather than guessing exception,
rounding, or exponent-wrap behavior. The caller owns stack tags/TOP, exception
delivery, and retirement. This exact path does not depend on FCW precision or
rounding control because it changes only a normal result's exponent.

The truncation rule and condition-code behavior follow Intel's
[FSCALE instruction reference](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf).
