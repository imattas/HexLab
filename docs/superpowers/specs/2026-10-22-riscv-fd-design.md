# RISC-V F/D Scalar Floating-Point Design

## Goal

Add an end-to-end, statically decoded subset of the RISC-V F and D
single/double-precision extensions. Supported floating instructions must retain
their register and memory effects, print useful assembly, and lift into typed
pseudocode or explicit intrinsics when the existing IR cannot represent an
architectural side effect.

## Existing Context

The processor has bounded RV32I/M/A and RV64I/M/A/C decoders. Generic operands
already carry typed register, immediate, and memory values, but the register
bank currently has no RISC-V floating-point bank. Generic decode and formatting
are adapted in `libs/processors/src/dispatch.cpp` and `format.cpp`. RISC-V
lifting is a focused branch in `libs/decompiler/src/decompiler.cpp`; its
existing expression types represent integer, boolean, and pointer values.

## Design

### Decoder and instruction model

Append a `riscv_fpr` register bank and the F/D opcodes without changing existing
enum ordinals. All FPR operands identify the 64-bit architectural register
bank enabled by this F/D decoder; S operations and FLW/FSW still carry 32-bit
value or memory widths. Decoded instructions cover:

- FLW/FSW and FLD/FSD;
- S/D add, subtract, multiply, divide, square root, sign injection, min/max,
  and the four fused multiply-add variants;
- S/D equality/less-than/less-or-equal comparisons and classification;
- S/D conversions to and from the XLEN-supported signed/unsigned integer
  widths, S-to-D and D-to-S conversion, and raw integer/FP moves.

Rounding-mode fields are retained as an optional instruction fact. Static modes
0 through 4 are recognized; dynamic mode 7 is retained as dynamic, while
reserved modes 5 and 6 are invalid. Instructions that update accrued FP
exception flags carry that side effect separately from integer and memory
effects. Reserved encodings in implemented groups are invalid; valid encodings
outside this bounded subset are unsupported.

### Generic decode and formatting

Generic dispatch preserves FPR bank identity and architectural bank width,
integer destination widths, memory address width, floating memory width,
rounding mode, and exception-flag writes. Assembly uses standard `.s`/`.d`
mnemonics and rounding suffixes for non-dynamic static modes. Register moves,
comparisons, and conversions print their source and destination banks in
architectural operand order.

### Decompiler

Add a floating scalar `ValueType` with width 32 or 64. FP load/store and
arithmetic use typed expressions where the existing IR can represent them.
Operations with rounding or accrued-flag effects that cannot be represented as
pure expressions remain named intrinsics with typed operands, destination
register outputs, and an explicit `fflags` output. Comparisons produce a
boolean intermediate and zero-extend into the integer destination. Conversions
use named typed operations rather than integer bitwise expressions. SSA treats
the appended FPR and FP-status banks as independent register files.

The lifter does not evaluate IEEE-754 values, infer FP constants, simulate NaN
boxing, choose a runtime `frm`, or compute precise accrued exception values.
Those effects remain explicit in pseudocode rather than being guessed.

## Compatibility and Non-Goals

Existing opcode and register-bank enum ordinals remain stable by appending
values. No third-party decoder dependency, top-level CMake change, floating
emulator, vector extension, compressed floating-point extension, ABI
classification, or capability-ledger edit is included. Existing atomic,
integer, and non-RISC-V lifters remain unchanged.

## Validation

Literal F/D encodings will check supported formats, operation identity,
register-bank width, memory widths, rounding fields, and implicit exception
effects. Malformed tests will cover reserved rounding values, invalid
funct/fmt/rs2 combinations, truncated instructions, and width-specific
conversion restrictions. Generic dispatch tests will check assembly and
retained effects. Lifter tests will inspect typed output for loads, stores,
arithmetic, FMA, comparisons, and conversions; SSA tests will confirm FPR and
integer destination versions stay independent. Focused RISC-V coverage and
decompiler documentation will state the supported families and unmodeled IEEE
runtime behavior.
