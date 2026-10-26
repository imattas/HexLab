# x87 Integer Conversion Semantics

`evaluate_x87_to_integer` evaluates the numeric and floating-point status
effects shared by FIST, FISTP, and FISTTP for canonical x87 binary80 values.
The caller supplies the control/status words, signed destination width (16,
32, or 64), and whether truncation is forced. Ordinary FIST/FISTP use the
control word's RC field: nearest with ties to even, toward negative infinity,
toward positive infinity, or toward zero. FISTTP selects toward zero regardless
of RC.

The conversion is performed with integer significand and exponent operations,
so it is independent of the host `long double` format and host rounding mode.
An exact result returns destination bits in two's-complement representation.
An inexact result sets the sticky precision flag; if precision is unmasked, the
result has no destination value and `completed` is false. FIST/FISTP C1 reports
whether the rounded integer is greater than the input; FISTTP clears C1. Invalid
classes and signed-range overflow set the invalid flag. With invalid masked,
the destination is the architectural integer-indefinite value (only the sign
bit set); with invalid unmasked, no destination is returned and the exception
summary/busy bits are set. Invalid takes priority over precision.

This API computes a conversion result only; it does not read a value from the
decompiler's SSA state, write memory, or apply FISTP/FISTTP stack popping. The
caller must apply a pop only when `completed` is true. It does not model stack
underflow/tag exceptions, pending-exception delivery, or memory faults. Only
canonical binary80 encodings, including pseudo-denormals, are accepted;
unsupported unnormal encodings raise invalid. Arithmetic and real-format
conversion (FST m32fp/m64fp and FLD m32fp/m64fp) remain symbolic/unsupported.

The same semantic API also exposes exact bit-level FCHS/FABS value transforms:
they toggle or clear only the binary80 sign bit and preserve the supplied
status word. That helper assumes a valid nonempty ST(0); it does not model stack
underflow or unsupported-encoding exceptions.

The rounding, destination, exception, and C1 rules follow Intel's [FIST/FISTP
and FISTTP instruction reference](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf).
