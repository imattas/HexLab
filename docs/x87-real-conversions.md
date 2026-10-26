# x87 binary32/binary64 real conversions

`evaluate_x87_load_real` and `evaluate_x87_store_real` provide caller-driven
numeric semantics for the D9/DD real memory forms. The caller supplies the
little-endian memory value as an integer bit pattern and remains responsible
for memory access, x87 stack tags/TOP, stack overflow/underflow, and `FSTP`'s
pop.

`FLD m32real` and `FLD m64real` expand every finite IEEE value exactly into
binary80, preserving signed zero and infinity and mapping the IEEE NaN payload
into the extended significand. A source subnormal sets sticky DE; an sNaN sets
sticky IE and is quieted when invalid is masked. An unmasked DE or IE suppresses
the returned stack value.

`FST m32real`, `FSTP m32real`, `FST m64real`, and `FSTP m64real` convert from
binary80 with the FCW rounding-control field. The bounded integer conversion
handles signed zero, finite normal and subnormal values, infinities, and NaNs.
It reports sticky DE/OE/UE/PE and C1 rounding direction. A masked unsupported
binary80 encoding produces the target-format indefinite quiet NaN. Any
unmasked exception suppresses the returned memory value; the caller applies
the instruction's stack pop only according to the decoded instruction and
retirement model.

This API does not access memory or mutate an x87 stack state. It also does not
model pending exception delivery, stack faults, or exact instruction retirement
across multiple simultaneously unmasked exception classes. Decoder operands
and effects for the D9/DD memory forms are in `docs/x87-decoder-coverage.md`.

The format-conversion and exception behavior follows Intel's [64 and IA-32
Software Developer's Manual, Volume 2A](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developers-manual-vol-2a-manual.pdf),
the `FLD`/`FST` instruction entries and the x87 floating-point exception
rules.
