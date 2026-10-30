# Zfa round-to-integral evaluation

`evaluate_riscv_fround_operation` evaluates `FROUND.S`, `FROUNDNX.S`,
`FROUND.D`, or `FROUNDNX.D` directly from raw IEEE-754 source bits. The caller
passes the effective rounding mode after resolving a dynamic `rm=111` from
`frm`; supported modes are RNE, RTZ, RDN, RUP, and RMM (0 through 4). The
function returns raw destination bits plus the accrued `fflags` bits, without
converting through host floating point or changing the process rounding mode.

For finite inputs it rounds the significand to an integral value while
preserving the source sign, including signed zero. Inexact is reported only by
FROUNDNX and only when a non-NaN value changes. Infinities and zeros pass
through unchanged. Quiet NaNs retain their payload unchanged; signaling NaNs
are quieted while retaining the remaining payload bits and report NV, with no
NX. Binary32 results are masked to 32 bits; binary64 results retain all 64
bits. Non-FROUND opcodes and reserved rounding modes return no result.

The decompiler optimizer now calls this helper for the existing typed
`fround.s/d` and `froundnx.s/d` parallel value formulas when the IEEE source
and effective three-bit rounding mode are constant. The accepted source is a
width-exact binary32/binary64 floating constant, and the mode must be one of
0 through 4. Finite values, signed zeros, and infinities fold without host
floating-point arithmetic. For example, FLI.S 1.5 followed by FROUNDNX.S RTZ
has a binary32 value output of 1.0 and a raised-exception output of NX.

Matching `.exceptions` formulas fold to a five-bit exception constant, so
FROUNDNX's NX is retained even when the value is known. The intrinsic,
register definitions, and `old_fflags | raised_flags` formula remain in the
IR; an unknown incoming sticky state is preserved. Folding does not assume
`fflags` starts at zero or discard the instruction's status effect. A known
static mode works directly. The decompiler now lifts Zicsr reads and writes
for the floating status CSRs `fflags` (0x001), `frm` (0x002), and `fcsr`
(0x003) into their separate five-bit and three-bit SSA registers. A preceding
constant CSR write can therefore supply dynamic `rm=111` to the fold, and
later flag writes preserve the current `fflags` value. CSRRS and CSRRC updates
are represented as bitwise updates and fold when their inputs are known.
Unknown or reserved dynamic modes remain symbolic. Other CSRs stay opaque and
are not modeled as architectural state.

NaN source constants remain symbolic in this optimizer connection. The raw
helper's payload-preserving behavior is not promoted to an architectural NaN
policy, and this change does not infer NaN-boxing from physical FPR contents.
Malformed source/mode/result types also fail closed. The helper remains a
pure API and receives its effective mode through the typed SSA formula; it
does not read or mutate processor state directly. Downstream propagation of
all intrinsic output literals and broader floating
arithmetic/conversion folding remain unsupported. The decoded and lifted
instruction scope and remaining backend limits are listed in
[RISC-V coverage](riscv64-coverage.md) and [decompiler coverage](riscv-decompiler.md).

The implementation follows the ratified [RISC-V Zfa round-to-integer
specification](https://docs.riscv.org/reference/isa/unpriv/zfa.html#round-to-integer-instructions).
