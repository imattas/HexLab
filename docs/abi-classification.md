# ABI argument and return classification

`hexlab/analysis/abi.hpp` exposes `classify_abi_signature()` for System V AMD64,
Microsoft x64, 32-bit x86 `__cdecl`, `__stdcall`, `__fastcall`, and `__thiscall`,
and the AArch64 AAPCS64 and 32-bit Arm AAPCS32 base procedure-call conventions. It
accepts the existing immutable `hexlab::types::Type` function model and returns
one placement for each declared parameter and the result. Stack offsets are
byte offsets from the callee's stack pointer at function entry.

## AAPCS32 base PCS

`CallingConvention::aapcs32` and the retained `aapcs32` function qualifier
select the 32-bit Arm base procedure-call standard. The classifier uses R0-R3
for core argument words, then the stack. Arguments smaller than a word occupy
a four-byte register/stack container; composites are rounded to four bytes.
Values requiring double-word alignment advance the next core register to an
even register and use eight-byte stack alignment when placed on the stack.
Composite arguments can split between the final available core registers and
the stack under the base PCS C.5 rule, while later values use the stack.

Scalar results up to four bytes use R0 and eight-byte scalar results use R0/R1.
Composites up to four bytes use R0; larger composites use the hidden result
pointer in R0. The classifier models only the base PCS: floating scalars use
core registers or stack words, and VFP/Advanced SIMD register allocation and
homogeneous floating-point aggregates are unsupported. `classify_abi_call`
does not currently model AAPCS32 variadic call-site promotions. These rules
follow the [Arm AAPCS32 specification, §§6.4-6.5](https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst).

The overload `classify_abi_signature(function_type, platform_default)` honors
retained `sysv_abi`, `ms_abi`, and `aapcs64` type qualifiers. Explicit `cdecl`
selects the 32-bit cdecl model on 32-bit x86 and leaves the selected platform
model on 64-bit targets. `stdcall`, `fastcall`, and `thiscall` are accepted only
with the 32-bit x86 platform default. `vectorcall` maps to the x86 model when
the selected platform is 32-bit x86 and to the Microsoft x64 model when the
selected platform is Windows x64. Other platform defaults reject that
qualifier.

For x86-32, cdecl arguments are stack-passed and caller-cleaned; stdcall uses
the same placements and reports callee cleanup. Fastcall assigns the first two
eligible integer or pointer scalar arguments of at most four bytes to ECX and
EDX, then places remaining arguments on the stack; floating and aggregate
arguments are stack-passed. Thiscall reports the implicit `this` pointer in
ECX and places declared arguments on the stack. The model reports cleanup as
`AbiStackCleanup` and the callee-pop byte count, including a hidden stack result
pointer when present. Variadic x86 declarations use cdecl placement and caller
cleanup, except variadic thiscall, which remains explicitly unsupported because
its implicit `this` pointer moves to the stack and changes every argument offset.

Scalar support includes 1/2/4/8-byte integers, booleans, enums, and pointers,
plus 4/8-byte floating scalars. Nested structures/unions and arrays within an
aggregate are recursively classified using the computed x86 object layout;
nested qualified members are handled as their underlying type. Top-level array
parameters are rejected because C/C++ adjusts them to pointers, and array
results are invalid. For System V AMD64, aggregates up to two eightbytes merge
INTEGER, SSE, and SSEUP classes and can split across the corresponding GPR and XMM
register banks. Nested baseline vectors of 8 or 16 bytes are classified as SSE
values; a 16-byte vector uses an SSE/SSEUP pair carried by one XMM register.
The member must have its required 16-byte alignment, otherwise the aggregate is
memory-class. If an aggregate cannot fit in every required argument register,
register allocation rolls back for that aggregate and the whole value is
assigned to an aligned stack slot. Aggregates larger than 16 bytes or containing
unaligned members use memory. A memory-class result reports its hidden buffer
pointer separately in `hidden_result_pointer` at RDI and reports the returned
buffer address in RAX. The hidden pointer consumes the first integer argument
register, while declared arguments retain their original indices.

Microsoft x64 assigns each declared argument a single ordinal position shared
by the four register slots (RCX/RDX/R8/R9 for integer or pointer values and
XMM0–XMM3 for floating-point scalars) and subsequent stack slots. Aggregates
of exactly 1, 2, 4, or 8 bytes travel as integer values in the corresponding
ordinal GPR or stack slot. The classifier records the argument's complete
object size and its value offset; it does not split an aggregate across
registers. Aggregates with any other size are passed indirectly: the recorded
location is the pointer-sized ordinal GPR or stack slot and
`AbiValueLocation::indirect` is true. The temporary copy's address, alignment,
and lifetime are caller-side storage details and are not modeled as additional
locations.

Aggregate results of exactly 1, 2, 4, or 8 bytes use AL/AX/EAX/RAX. Other
aggregate results report the incoming hidden buffer pointer in
`hidden_result_pointer` at RCX and the ABI-mandated returned pointer echo in
RAX; the hidden pointer consumes ordinal position zero, while declared
argument indices remain stable and begin at position one. The classifier
reports the mandatory 32-byte shadow space, starts the first stack argument at
entry RSP+40, and accounts for 8-byte stack slots and 16-byte call-stack
alignment. Stack indirect aggregates occupy one pointer-sized slot; direct
aggregates occupy one slot as well. This is a layout-based model for
C-compatible/trivial aggregates. The type graph does not encode C++ copy
constructors or other non-trivial class properties, so those ABI exceptions
cannot be identified and are outside the supported contract. Variadic
signatures are explicitly unsupported by prototype-only classification;
`classify_abi_call` provides the call-site-aware path for supported scalar
variadic arguments. cdecl aggregate arguments occupy stack slots rounded to four bytes.
Aggregate results use a hidden pointer at entry offset four, before the
explicit arguments. Scalar 64-bit integer returns use RAX, and floating returns
use XMM0.

The result reports pointer width, required stack alignment, slot granularity,
shadow space, stack argument bytes, cleanup responsibility, callee-pop bytes,
and any implicit this location in addition to locations.

Decompiler type recovery consumes this classifier when a function has an
explicit project prototype and a recognized System V AMD64, Microsoft x64,
32-bit cdecl, or AAPCS64 profile. Single-location arguments constrain the
matching incoming register or proven entry-stack load; indirect aggregate
arguments constrain the address value as a pointer to the declared aggregate.
Split aggregate/scalar values are not forced into one recovered variable type.
When a supported prototype can be rendered, typed pseudocode labels each
parameter with its classified register or entry-stack offset. Unsupported
placements receive no annotation, and indirect-call signatures are never
invented from the classifier.

## Windows x64 C++ methods

`classify_abi_method(windows_x64, method)` handles the persisted method model,
where `Method::signature` contains only the declared result and parameters and
`Method::this_type` is stored separately. For a non-static method it classifies
a pointer receiver in the first available ordinal position and returns that
location in `implicit_this`; ordinary arguments remain indexed only by their
declared parameter order. A hidden aggregate result pointer consumes ordinal
position zero first, so the receiver then occupies RDX and explicit arguments
start at position two. If the receiver or any ordinary argument spills, stack
placement and `stack_argument_bytes` include that slot. Static methods use the
ordinary signature classifier and have no receiver location. The method's
`this_adjustment` is copied to the result as metadata; applying the adjustment
to an object pointer is outside ABI classification. This API currently rejects
non-Windows-x64 conventions, malformed method signatures, and prototype-only
variadic signatures using the base classifier's explicit unsupported result.
`AbiSignatureClassification::hidden_result_pointer` describes the hidden
caller-provided result buffer separately from declared parameters for each
modeled indirect result. `AbiValueLocation::indirect` indicates that a
location carries an address to an aggregate. `AbiLocation::role` distinguishes
the hidden result input pointer from an address echoed by the callee; SysV
AMD64 and Microsoft x64 expose that echo in RAX. A void result has no locations.
Unresolved types, incomplete members, bitfields in SysV aggregates, stack
placement overflow, unsupported alignment above 16 bytes, and non-scalar
floating formats carry an explicit reason and make the classification
incomplete. After an unsupported parameter, later placements are left
indeterminate rather than guessed. Prototype-only variadic SysV AMD64 and
Microsoft x64 signatures remain rejected because they lack call-site
promotions, the SysV vector-register count in AL, and Microsoft's duplicated
floating argument registers. The type graph also does not describe C++
non-trivial copy/constructor properties, so aggregate rules describe the
layout-based C-compatible/trivial case only. Target-specific packed-layout
metadata and non-default calling-convention attributes remain outside this
classifier.

## Variadic x64 call sites

`classify_abi_call(convention, function_type, actual_argument_types)` accepts a
variadic prototype and the argument types at one call site. Fixed arguments
use their declared parameter types, since those are the types after the
prototype's conversions. Arguments after the fixed parameters use the C
default argument promotions: booleans and sub-`int` integers/enums become
signed `int`, `float` becomes `double`, and top-level arrays/functions decay
to pointers. The returned `arguments` vector has one entry per actual argument
at the call site.

For System V AMD64, `sysv_vector_register_count` reports the number of XMM
argument registers used, capped by the ABI's eight-register argument bank; a
caller places that value in `%al`. For Microsoft x64, floating values assigned
to one of the first four positional registers have both their XMM location and
the corresponding GPR location. The GPR copy has `AbiLocation::duplicate`
set; stack-passed values do not have an extra location. This follows the
Microsoft [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170).

This call-site API supports only variadic SysV AMD64 and Microsoft x64 calls.
It does not classify unprototyped calls, `__vectorcall`, non-x64 variadic
conventions, or variadic vector types absent from the type model. Missing
call-site types for anonymous arguments and argument counts below the fixed
prototype are explicit incomplete results. The original
`classify_abi_signature()` API is unchanged for callers that only have a
prototype.

## Microsoft `__vectorcall`

`CallingConvention::x86_32_vectorcall` and
`CallingConvention::windows_x64_vectorcall` expose the Microsoft x86 and x64
variants directly. The function-type overload maps the existing
`FunctionConvention::vectorcall` qualifier from an x86-32 or Windows x64
platform default. Variadic signatures and other platform defaults remain
unsupported. The type graph has no target-specific `__m64`/`__m128`/`__m256`
names, so a vector is recognized by shape: 8, 16, or 32 bytes with matching
alignment; 32-bit and 64-bit floating scalars are also vector arguments.

HVA recognition accepts structures containing one through four identical
vector elements, including nested structures and arrays. Top-level array
parameters and results are rejected because C/C++ adjusts parameters to
pointers and does not permit array return types; nested arrays remain valid HVA
members. Member offsets come from the type layout service; bitfields, unions
containing vector elements, mixed vector shapes, and aggregates whose alignment
differs from their vector elements do not qualify as HVAs. Microsoft allocates ordinary vector arguments first, then
assigns each HVA's members to the remaining vector registers in ascending
register order. If an entire HVA does not fit, the value is passed by reference
instead of splitting it across registers.

On x86, the first two eligible integer arguments use ECX and EDX. The first six
vector arguments use XMM0–XMM5 or YMM0–YMM5; HVA members use the remaining vector
registers. Integer aggregates of at most four bytes may use ECX/EDX; other
aggregates are stack-passed by value. Vectors beyond the six-register bank and
HVAs that cannot fit are passed by reference on the stack. Stack offsets start
at entry ESP+4, arguments are rounded to four-byte slots, and the callee-pop
count equals the explicit stack argument bytes. Non-HVA aggregate results up to eight bytes use EDX:EAX
or EAX; scalar/vector/HVA results use the documented integer or vector return
registers. Larger indirect x86 result locations are not modeled and make the
whole signature incomplete.

On Windows x64, integer and small aggregate arguments use their parameter
positions in RCX, RDX, R8, and R9. Ordinary vector arguments use their parameter
positions in XMM0–XMM5 or YMM0–YMM5. A vector argument after position five is
passed by reference. HVAs use any remaining vector registers; if they do not
fit, an HVA in one of the first four positions uses the corresponding integer
register for its address, otherwise the address is stack-passed. Aggregates
larger than eight bytes are passed by reference. Stack arguments begin after
the reported shadow space. The base 32-byte Windows home area is extended by
one eight-byte home slot for each register-passed vector/HVA argument in
positions four and later. Large aggregate results use a hidden RCX pointer,
which consumes the first integer parameter position; scalar, vector, HVA, and
small integer-aggregate results use registers.

These rules follow Microsoft's published [__vectorcall specification](https://learn.microsoft.com/en-us/cpp/cpp/vectorcall?view=msvc-170). The classifier only reports types representable by the current type graph; it does not infer compiler-specific vector names, hidden `this` pointers, or vararg promotions.


AAPCS64 uses independent `x0`–`x7` and `v0`–`v7` argument banks, with stack
arguments beginning at entry `SP` and 16-byte stack alignment. Integer and
pointer scalars are reported in `xN`; floating scalars use their `hN`, `sN`,
`dN`, or `qN` view. Homogeneous floating-point aggregates (HFAs) with one to
four uniquely addressable members are recursively flattened across nested
structures, arrays, and unions when all members share a supported floating
size. Overlaid union alternatives at the same byte offset count as one HFA
member. An HFA uses one SIMD/FP register per member, or is placed wholly on the
stack when that bank is exhausted. Other composites up to 16 bytes use
consecutive `xN` registers when the whole value fits; larger composites are
represented indirectly through `hidden_result_pointer` in `X8`.

The following table compares an aggregate argument with a same-typed return.
The 8-byte value is `{u32, u32}`, the 16-byte value is `{u64, u64}`, and the
24-byte value is `{u64, u64, u64}`. The x86 cdecl argument begins at offset 8
when the aggregate result requires a hidden pointer at offset 4.

| Convention | 8-byte argument / result | 16-byte argument / result | 24-byte argument / result |
| --- | --- | --- | --- |
| System V AMD64 | RDI / RAX | RDI, RSI / RAX, RDX | Stack at entry +8 / hidden RDI, returned pointer in RAX |
| Microsoft x64 | RCX / RAX | Indirect in RDX / hidden RCX, returned pointer in RAX | Indirect in RDX / hidden RCX, returned pointer in RAX |
| x86 cdecl | Stack +8 / hidden pointer at entry +4 | Stack +8 / hidden pointer at entry +4 | Stack +8 / hidden pointer at entry +4 |
| AAPCS64 | X0 / X0 | X0, X1 / X0, X1 | Indirect in X0 / indirect through X8 |

For x86-32 scalar examples, fastcall places its first two eligible integer
arguments in ECX and EDX and puts further arguments on the stack. Thiscall
reports `this` in ECX and puts declared arguments on the stack. Stdcall uses
the cdecl stack locations and changes cleanup to callee. Fastcall and thiscall
also report callee cleanup for their stack arguments.

AAPCS64 HFA counting follows the specification's uniquely-addressable-member
rule: overlapping alternatives in a union at the same address occupy one
floating-point register.

The AAPCS64 classifier rejects variadic signatures explicitly because their
language promotions and anonymous-argument handling need a call-site-aware
model. This type graph has no distinct vector/HVA node, so it does not infer
vector classification from ordinary aggregates; unsupported scalar formats,
vector-like values, unresolved types, and invalid aggregate forms remain
explicitly unsupported. This slice follows the base AAPCS64 rules; scalable
vector and platform-specific PCS extensions are outside its model. See the
[Arm AAPCS64 specification](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst).
The register and stack rules follow the [System V AMD64 psABI](https://refspecs.linuxfoundation.org/elf/x86_64-SysV-psABI.pdf) and [Microsoft x64 calling-convention documentation](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170). Microsoft documents that an indirect result pointer is passed first and the same pointer is returned in RAX. The 32-bit floating and aggregate return conventions follow the [Intel386 System V ABI](https://www.uclibc.org/docs/psABI-i386.pdf).

## RISC-V base integer ABI

`CallingConvention::riscv32` and `CallingConvention::riscv64` select the base
integer psABI for RV32 and RV64. Integer, boolean, enum, and pointer scalars up
to XLEN use `a0`-`a7` in order. RV32 64-bit values use consecutive registers
when available and split across the final register plus the stack when only
one register remains. If no argument register remains, values are passed by
value on the stack. Narrow integer and floating scalars use an XLEN-sized
location. For example, RV64 places f16/f32 in an eight-byte `aN` container;
RV32 places f16 in a four-byte container. `AbiLocation::size` retains the
payload width, while `placement_size` reports the physical container width.

Aggregates and floating values under the base integer convention are
represented in memory order as one or two XLEN chunks. Values
larger than 2xXLEN are passed indirectly. An indirect result uses the
`hidden_result_pointer` location in `A0` and shifts explicit argument
allocation by one register. Direct
scalar and aggregate results use `a0` and, for two chunks, `a1`. Stack offsets
begin at zero from entry `sp`; values use the greater of their type alignment
and XLEN alignment, capped at the 16-byte stack alignment, and stack size
includes XLEN-slot padding. Split pieces retain their offset within the value.

Variadic signatures are reported unsupported because classifying their
aligned-pair and spill rules requires distinguishing fixed parameters from
ellipsis arguments. This API models the base integer convention only; it does
not infer hardware floating-point register conventions. Vector types are
unsupported until an explicit vector calling-convention model is added. The
register, chunk, aggregate, hidden-result, and stack rules follow sections
2.1, 2.2, and 2.7 of the [RISC-V psABI specification](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/).
