# x86 hardware random and seed instructions

HexLab decodes `RDRAND` (`0F C7 /6`, register ModRM) and `RDSEED`
(`0F C7 /7`, register ModRM) as typed scalar instructions in x86-16,
x86-32, and x86-64 contexts. Operand-size defaults and `66` select 16- or
32-bit destinations; `REX.W` selects 64-bit destinations in long mode.
`REX.B` extends the destination register. Neither instruction reads its
printed destination, accesses memory, or changes control flow. LOCK is
invalid and F2/F3 forms remain outside the enabled prefix subset. Memory
ModRM forms under `/6` and `/7` select VMX system instructions and remain
unsupported rather than being classified as malformed random instructions.

The destination is always written. When hardware reports success, it
receives the supplied sample truncated to its operand width and CF is set.
When hardware reports failure, it receives zero and CF is cleared.
OF, SF, ZF, AF, and PF are cleared in both cases. All other FLAGS bits are
preserved. Decoded whole-FLAGS reads and writes express that preservation;
the FLAGS view follows the existing 16/32/64-bit execution-context model.
A 16-bit destination preserves the wider GPR view, represented by an
additional incoming full-register dependency and output. A 32-bit write in
long mode also writes the full 64-bit view through zero extension.

`evaluate_x86_random(sample, available, width, incoming_flags)` is a pure
single-step value/FLAGS evaluator for either instruction. It requires a
caller-supplied sample and availability result; it does not generate entropy
or invoke the host CPU instruction. `evaluate_x86_random_instruction`
validates architecture/mode, destination shape, access, register effects,
flow, and memory/LOCK facts before evaluating the supplied outcome. It
returns the printed destination slice; the caller owns merging 16-bit
partial writes and zero-extending long-mode 32-bit writes. The decoded
adapter masks FLAGS to the tracked execution-context width.

The decompiler emits one `x86_rdrand_i16/i32/i64` or
`x86_rdseed_i16/i32/i64` intrinsic with no memory effect. Its explicit
parallel register outputs include the destination, FLAGS, and any wider
GPR alias. Unknown availability and sample values belong to that operation;
a select writes zero on failure and the same availability bit becomes CF.
The expressions clear the five other affected status flags, preserve all
other FLAGS bits, merge 16-bit partial GPR writes, and zero-extend long-mode
32-bit writes. No incoming destination dependency is invented for full
writes. Subsequent conditional instructions can consume the newly produced
FLAGS instead of a stale earlier comparison.

CPU feature checks, hardware entropy acquisition, retry scheduling,
processor errata, and exception/state execution remain outside this
implementation. Intrinsic outputs remain nondeterministic; they must not be
interpreted as cryptographic sample generation. CPUID feature requirements
are RDRAND and RDSEED respectively.

The architectural encoding and outcome contract follow Intel's
[Instruction Set Reference, volume 2B](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
and [Digital Random Number Generator guide](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html).

Validation for this change is compilation of the Debug processor and
decompiler targets. No tests were added or run, and no hardware entropy
instruction was executed.
