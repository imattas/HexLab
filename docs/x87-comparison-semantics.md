# x87 Comparison Semantics

`x87_semantics.hpp` exposes a caller-driven comparison evaluator for two x87
80-bit values. It compares integer significands and exponents directly; it does
not rely on the host's `long double` representation or rounding mode. This is
important on Windows, where `long double` commonly has only binary64 precision.

The exact comparator accepts signed zero, finite normal and subnormal values,
pseudo-denormals, and infinities. It treats the signs of zero as equal. NaNs
produce the unordered relation. Unsupported encodings such as unnormal values
are reported as an invalid operand by the instruction evaluator; the lower-level
exact comparator returns no relation for them.

`evaluate_x87_compare` models FCOM, FUCOM, FCOMI, and FUCOMI result effects.
FCOM and FCOMI raise invalid for any NaN; FUCOM and FUCOMI raise invalid for a
signaling NaN, while a quiet NaN yields unordered without an invalid exception.
Unmasked invalid sets the sticky invalid, exception-summary, and busy bits,
suppresses comparison condition outputs, and marks the instruction incomplete.
All four forms clear FSW C1. FCOM/FUCOM write the FSW C0/C2/C3 relation when
the result retires; FCOMI/FUCOMI leave those FSW bits alone, write EFLAGS
ZF/PF/CF when the result retires, and clear AF/SF/OF. For an unmasked
FCOMI/FUCOMI invalid exception, ZF/PF/CF remain unchanged while AF/SF/OF are
cleared.

The evaluator does not convert m32fp/m64fp values, perform arithmetic, model
exception delivery, track the physical x87 register stack/TOP/tag word, or apply
the pop side effects of FCOMP/FCOMIP/FUCOMIP. The caller must apply stack changes
only when the returned comparison completed. Arithmetic and conversion remain
symbolic in the decompiler until exact extended-precision arithmetic semantics
are available.

The comparison behavior follows Intel's instruction reference for [FCOM and
FCOMP](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-manual-volume-2a.pdf)
and [FCOMI/FUCOMI](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-manual-volume-2a.pdf).
