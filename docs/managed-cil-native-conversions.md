# Managed CIL native integer conversions

The decoder and lifter recognize the complete native-sized conversion family:

| Opcode | Destination | Source interpretation | Overflow |
| --- | --- | --- | --- |
| `conv.i` (`D3`) | native signed integer | Signed extension when widening an integer | Unchecked |
| `conv.u` (`E0`) | native unsigned integer | Zero extension when widening an integer | Unchecked |
| `conv.ovf.i` (`D4`) | native signed integer | Signed | `System.OverflowException` |
| `conv.ovf.u` (`D5`) | native unsigned integer | Signed | `System.OverflowException` |
| `conv.ovf.i.un` (`8A`) | native signed integer | Unsigned | `System.OverflowException` |
| `conv.ovf.u.un` (`8B`) | native unsigned integer | Unsigned | `System.OverflowException` |

Each consumes one evaluation-stack value and produces one native integer.
Stack underflow, invalid explicit native widths, and `max_stack` violations
remain errors. These operations retain their opcode identity instead of being
replaced by a C/C++ cast whose overflow or extension rules differ. The checked
source distinction follows Microsoft's descriptions of
[`conv.ovf.u`](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.conv_ovf_u)
and [`conv.ovf.i.un`](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.conv_ovf_i_un).

## Runtime width and provenance

`ManagedMethodAnalysis` carries `native_integer_bits` (`0`, `32`, or `64`),
the source PE machine, and the raw CLR runtime flags. Zero means unresolved;
it never means the width of HexLab's host process. Method inspection uses
architecture-specific AMD64/ARM64/IA64 machines for 64 bits, ARM/Thumb/ARMNT
machines for 32 bits, and non-IL-only I386 images for 32 bits when no conflicting
width flags are present. A true 32-bit requirement also gives 32 bits for a
non-64-bit image. Conflicting or reserved combinations remain unresolved.

The REQUIRED/PREFERRED flags are interpreted together. REQUIRED set with
PREFERRED clear is a 32-bit requirement; both set mean platform-neutral
prefer-32. An IL-only I386/PE32 AnyCPU assembly, including prefer-32, therefore
retains unknown width. A lone PREFERRED flag is reserved and also does not
establish a width. These rules follow the runtime's documented
[paired flag definitions](https://github.com/dotnet/runtime/blob/main/src/coreclr/inc/corhdr.h).

Direct API callers with an independently established runtime context may set
`native_integer_bits` to 32 or 64 before lifting. No new desktop runtime-width
selector is provided. The resulting `ManagedCilDecompilation` retains that
width. Native integer signature elements (`ELEMENT_TYPE_I/U`), native indirect
and array loads, and `ldlen` use the same width for stack/result types; they
remain width-zero integers when the runtime context is unknown. Managed
references are not reclassified as native integers.

## Integer formulas and overflow guards

Every emitted native conversion has a record in
`ManagedCilDecompilation::native_integer_conversions`, retaining its IL offset,
opcode, original source type, result type, checked/unsigned-source flags,
successful-value formula, overflow predicate when checked, and
`exact_integer_semantics` flag. Result types are signed or unsigned integers
of the resolved native width, including width zero for unresolved contexts.

For known integer values and a resolved width, the successful-value formula
uses exact truncation, sign extension, zero extension, or same-width retagging.
Narrow metadata integer/Boolean values first receive their ordinary I4 stack
extension. The conversion opcode then determines the signed interpretation;
an earlier unsigned display type does not turn `conv.ovf.i` into its `.un`
variant. For checked operations, the formula describes only the successful
path, after the recorded guard has accepted the input.

Guards retain the full pre-truncation value. Signed-to-signed narrowing checks
both destination bounds; signed-to-unsigned checks negativity and an upper
bound where needed. Unsigned sources compare against the signed or unsigned
destination maximum with an unsigned predicate. For example, on a 64-bit
runtime `conv.ovf.i.un` accepts every unsigned I4 value but rejects unsigned I8
values above `INT64_MAX`. On a 32-bit runtime it rejects values above
`INT32_MAX`. `conv.ovf.u` rejects negative signed values even when the native
destination is wider. These are typed expression formulas, not host arithmetic
or guessed constant results.

## Exceptional and opaque paths

Conversions are materialized as typed intrinsics with a stable result name.
In particular, a following `pop` cannot erase a checked conversion's exception
point. Checked conversions carry a `TrapEdge` naming `System.OverflowException`
and its guard. They also receive an instruction-specific exceptional source
block and use the existing CLR catch/filter/finally/fault dispatcher; an
uncaught conversion routes to an explicit unhandled terminal even when the
method has no EH clauses. The conversion has no memory write, so exceptional
memory state uses the pre-instruction version. In a filter, an exception
follows the existing false-filter continuation for the original exception.
The trap record denotes a managed exception, not an assertion that every
overflow terminates the process.

Exception CFG edges remain conservative; exact catch assignability and CLR
runtime execution are not simulated. Checked-conversion methods remain
`complete = false` even when their integer formulas and guards are exact.

Unknown runtime widths, unknown input categories, floating values, and
unchecked unresolved address conversions retain opcode-specific opaque
operations and make the result incomplete. Floating-to-integer conversion
truncates toward zero, but unchecked floating overflow has an unspecified
result and throws no conversion exception; the lifter does not invent
saturation, a numeric result, or an overflow trap for it. Checked floating
conversions retain an opaque OverflowException predicate, including exceptional
values and range checks. See Microsoft's
[`conv.i` behavior](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.conv_i).
The common managed pointer category cannot distinguish object references,
byrefs, and unmanaged pointers; checked conversions from that known unresolved
category fail explicitly rather than claim numeric semantics.

Fixed-width checked conversions, checked arithmetic, complete floating
conversion evaluation, distinct CLR stack-category verification, local/argument
SSA and type recovery, managed-address provenance, and complete runtime EH
behavior remain outside this slice. Existing method, instruction, block,
stack-cell and synthetic-dispatch limits continue to apply. Public result
headers changed; consumers must be rebuilt against the loader/decompiler
headers. No project schema or persisted codec changes are involved.
