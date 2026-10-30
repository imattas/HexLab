# x87 packed BCD conversions

`evaluate_x87_load_packed_bcd` and `evaluate_x87_store_packed_bcd` provide
caller-driven numeric semantics for the already decoded `FBLD m80bcd` and
`FBSTP m80bcd` instructions. The packed operand has 18 decimal digits in its
low 72 bits, with the sign in bit 79. On loads, the seven reserved bits are
ignored; stores clear them. The FBLD result is exact in binary80, including a
negative zero.

FBLD accepts only digit nibbles from zero through nine. The architecture
defines an invalid packed digit as an undefined load result, so the helper
returns no value and does not invent an exception or payload.

FBSTP rounds the ST(0) value to an integer using FCW.RC, then checks the
rounded result against the signed 18-digit range. Inexact conversion sets PE
and records C1 when rounding increments the magnitude. A denormal source sets
DE. Invalid values or values outside the BCD range set IE; if masked, the
helper returns Intel's packed-BCD indefinite encoding. An unmasked DE, IE, or
PE suppresses the destination and marks the instruction incomplete. FBSTP's
stack pop and the actual memory read/write are left to the caller.

The packed representation, reserved-bit behavior, rounding, and indefinite
value follow Intel's [64 and IA-32 Architectures Software Developer's Manual,
Volume 1](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developers-manual-vol-1.pdf),
the packed-decimal format and FBLD/FBSTP instruction entries.
