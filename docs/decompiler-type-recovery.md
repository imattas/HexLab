# Decompiler type recovery

`hexlab/decompiler/type_recovery.hpp` exposes an opt-in type recovery pass for
the lifted IR. It derives integer widths from IR values and register operands,
propagates signedness through sign extension and arithmetic shifts, and marks
register values used as memory bases as pointers. Copies and supported
pointer-plus/minus-value expressions carry those facts across SSA versions.
At a phi, pointer evidence is carried only when every incoming SSA value is
known to be a pointer. A mixed or incomplete join therefore remains an integer
or unknown type instead of inheriting pointer status from only one edge. This
is conservative: it may leave a pointer-valued phi unknown when one input lacks
evidence, but avoids assigning pointer semantics to a value that can also be an
integer.

Callers may supply an `AbiDescription` to map integer/floating register
positions and stack offsets to ABI argument positions and to state pointer
width. Helpers provide ordered integer and stack slot maps for x86-64 Windows,
x86-64 System V, AArch64, ARM32 AAPCS, RISC-V ILP32/LP64, and MIPS32 O32 /
MIPS64 N64. The ARM32 and RISC-V/MIPS additions currently describe integer
argument and return registers, caller-saved integer registers, and stack
slots; they do not claim complete floating-point, vector, aggregate, or
multi-register ABI classification. AArch64 additionally supports scalar
floating-point registers and the limited HFA handling described below. In
particular, those helpers should be
selected only for the named data model and calling convention, rather than
treated as automatic platform detection. The CLI and desktop pseudocode view
select these integer profiles for matching image architectures; 32-bit x86
uses the cdecl stack profile. Stack offsets are relative to the incoming value
of the configured stack base. Reads through SSA stack-pointer values derived
by constant copies or additions/subtractions are normalized back to that
incoming base before matching a stack argument slot. Cyclic, contradictory,
indexed, or otherwise untraceable addresses do not contribute parameters.
Stack-frame normalization also recognizes RISC-V `sp` (x2) and MIPS `sp`
(r29), so those integer profiles can resolve locals and incoming stack slots
through constant stack-pointer adjustments. ARM32 uses r13 as the stack base.
Callers can extend the map with floating register slots when their
ABI separates floating-point argument positions.
A `types::Type` function prototype
constrains argument register variables and supplies the function result type.
Without a prototype, return expressions or the ABI integer return register
supply a best-effort result type. When the lifted function has an explicit
return statement and its result type is known, the pass also proposes an
`inferred_prototype`: it uses the recovered return type (or `void` for a bare
return) and the contiguous prefix of ABI argument slots observed in the IR.
Value-returning functions with unknown or conflicting return evidence do not
receive a prototype with a guessed `void` result. If `AbiDescription::arguments` is
provided, its ordered slots control parameter order and can interleave integer
and floating register classes with exact stack locations. The slot class
supplies floating classification while the observed register or load width
supplies size; integer slots retain pointer and signedness evidence from the
IR. Vector slots infer a type only when lane metadata provides a supported,
internally consistent shape. A missing slot also ends the prefix, even when a
later slot is observed, since the prototype arity and skipped parameter type
are ambiguous. Parameters are named `arg0`, `arg1`, and so on. When the
ordered map is absent, the older integer-register plus exact-stack-offset
heuristic is retained. This is a reviewable heuristic candidate; callers
should not treat it as debug information or a confirmed signature. Results
are deterministic and do not mutate the lifted function.
For multiple value-return paths, the candidate result type is retained only
when every observed path has known, matching type evidence; mixed bare/value
returns or conflicting/unknown typed paths remain untyped and suppress inferred
prototypes.

Without an explicit prototype, x86-64 argument inference now uses the ABI's
floating register evidence as well as integer evidence. Windows x64 treats each
of the first four positions as one shared GPR/XMM choice, stops at the first
unobserved position, and continues into stack slots only after that prefix.
Conflicting GPR and XMM evidence for one position suppresses the candidate.
System V AMD64 can infer a contiguous register prefix when only one register
class is observed. Stack reads are retained as typed unresolved input evidence,
including alongside register evidence, because the ABI can place individual
arguments directly on the stack while other register classes remain available.
The evidence records offset, width, and any recoverable candidate type, but no
parameter ordinal; mixed register/stack or GPR/SSE use therefore leaves the
candidate prototype unresolved. Call-site inference does not use this exception.
This follows the boundary described in Ghidra's [SysV stack-parameter analysis](https://github.com/NationalSecurityAgency/ghidra/issues/9478):
a direct stack assignment rule affects active callee input recovery, while
call-site stack inference remains conservative. HexLab retains unplaced type
evidence instead of inferring an ordinal from that rule alone.
This does not infer vector ABI classes, variadic promotions, or aggregate
classifications.

Signed integer `slt` comparisons in instruction expressions and recovered switch
selectors add signedness evidence to direct register
operands, and that evidence follows zero-displacement same-width copies within
the same register bank.
`ult` comparisons in those expressions add unsigned interpretation evidence; when the same copied
SSA value is used by both forms, the pass leaves its inferred scalar type
unknown instead of choosing one interpretation. Explicit prototype or type
assignments remain authoritative. Existing `sext`/`zext` operations continue to
provide extension-derived signedness evidence, while direct conflicting uses
can still leave an unconstrained variable unknown. This currently covers typed
IR comparison operators, not architecture flag predicates or register values
nested inside other arithmetic expressions.

An explicitly signed integer annotation on a register expression or memory
load also supplies positive signedness evidence and propagates through the
existing assignment data flow. The IR's default `is_signed == false` is not
treated as unsigned evidence because most lifted integer expressions use that
default without classifying signedness. A later unsigned comparison that
conflicts with already-proven signed evidence suppresses the scalar type rather
than allowing one interpretation to silently take precedence.

Signedness-aware integer division and remainder operators (`sdiv`, `srem`,
`udiv`, `urem`, and the AArch64 `a64_sdiv`/`a64_udiv` forms) now provide the
same evidence for direct register operands. Evidence follows proven
same-width, zero-displacement register copies. If signed and unsigned
operations use the same value, the scalar type is left unknown; explicit
prototype constraints still take precedence. This does not infer signedness
for operands nested inside an expression or infer signedness from machine
condition flags. MIPS32 `mult`/`multu` and `div`/`divu` intrinsic operands also
provide signed/unsigned evidence for their direct register inputs. As with the
other operators, mixed interpretations suppress the inferred signedness, and
only proven same-width copies carry the evidence onward. This does not infer a
signed type for HI/LO results from the operation alone.

Vector lane metadata (`element_kind`, `element_bits`, and `lanes`) now produces
an immutable homogeneous vector type when its total width matches the IR value.
Typed vector ABI slots and vector return registers carry that recovered type
into candidate prototypes. Opaque vectors, conflicting vector phis, and
unsupported lane kinds remain untyped with a diagnostic; the pass does not
guess their element type or ABI position.

`format_pseudocode_with_types` composes stack-slot and type recovery with
structured pseudocode formatting. When an explicit prototype or conservative
inferred prototype is available, the function header includes its recovered
return and parameter declarations in ABI slot order. Inferred integer types
retain their observed width in the displayed fixed-width name. If any function
parameter or result needs an unsupported declarator, the formatter keeps the
generic function header instead of omitting that parameter. It also emits
declarations for locals with concrete recovered types before the basic-block
body, while leaving unsupported local declarators and uncertain slots out of
the declaration list. The output remains heuristic pseudocode and retains
instruction-origin comments; it does not become confirmed source debug data.

Each `RecoveredVariable` includes a stable display name and, for an observed
incoming ABI register slot, its parameter index. Parameter names use ABI slot
order (`arg0`, `arg1`, ...); other values use deterministic register-bank,
index, and SSA-version names. `TypeRecoveryResult::stack_variables` contains
typed records for slots accepted by `recover_stack_variables`, including the
canonical frame register, SSA version, and frame-relative offset. These
records let the Variables view use the same name and type as pseudocode's
recovered stack references. Register names remain metadata at this stage; the
machine-level assignment formatter still prints register destinations.

For pointer variables, direct memory accesses through a base register with a
constant displacement and no index contribute observed fields to the pointee
type. The pass uses each access width, creates unsigned integer members at the
observed byte offsets, and carries the layout across pointer copies and phi
inputs when all phi inputs are pointer-classified. Constant pointer copies and
`pointer +/- constant` assignments share field evidence in both directions,
translating offsets between pointer views and their enclosing object. This
includes a negative displacement through an interior pointer when the exact
copy/offset chain proves a non-negative field offset in another pointer view.
Alias paths with inconsistent accumulated offsets are rejected, and normalized
offsets remain subject to the one-megabyte layout bound. A field accessed
through an interior pointer therefore contributes its enclosing-object offset
to the original pointer's recovered structure while retaining its local offset
in the interior view when that offset is valid. A valid
non-overlapping layout becomes a recovered structure. A run of at least three
contiguous same-width fields is represented as an array member; shorter runs,
sparse accesses, and different-width fields remain separate members. This is
a shape heuristic based only on observed accesses and can mistake adjacent
record fields for an array. Unsupported widths, oversized offsets, or
overlapping members keep the conservative `byte*` pointee. Member names are
synthetic, signedness and semantic types are unknown, and aliasing between
different base registers is not resolved. Alias field propagation is bounded
by the number of SSA facts; if a non-zero-offset cycle prevents convergence,
aggregate layouts are suppressed and a diagnostic explains why.
If one pointer fact observes different access widths at the same byte offset,
the layout is ambiguous and aggregate inference for that pointer is suppressed.
This prevents a wider partial or overlapping access from silently replacing a
narrower observation. The ambiguity follows proven pointer copies, phis, and
constant-offset aliases; explicit prototype types remain authoritative.
In typed pseudocode, a constant-offset memory access through a recovered
pointer-to-structure prints as `base->field_N` only when the access width
matches that exact member. Constant offsets into a recovered array member print
as `base->field_N[index]` only for an exact element-width access. Unknown,
ambiguous, partial-width, or overlapping accesses keep the ordinary memory
expression.
When an explicit or recovered structure contains nested structures or fixed
arrays of structures, typed pseudocode can also follow a flattened constant
displacement through the complete member path, such as
`base->header.version` or `base->items[2].code`. Each enclosing structure must
have a bounded, complete, non-overlapping fixed layout; array size must agree
with its element size and count. The resolver is capped at eight nesting
levels and 4096 visited type/member steps. Unions, bitfields, virtual bases,
anonymous members, incomplete extents, ambiguous paths, dynamic indices, and
partial-width accesses retain the ordinary memory expression. This follows
Ghidra's type-directed member and subscript rendering in its native C printer
([`printc.cc`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/printc.cc)); HexLab applies its own stricter bounded layout checks.
When a pointer-width load into a pointer-classified value, or a pointer-valued
store, uses a constant-offset slot, that member is recovered as `void*` rather
than an integer. The pointer-field classification propagates through proven
constant pointer copies and offset aliases only when the same field extent is
present in the destination layout. When a classified pointer member is loaded
and that value is independently dereferenced at constant offsets, the member
can point to a recovered nested structure. This follows observed pointer loads
to a maximum of four nested pointee levels and one million combined memory
observation, alias-graph traversal, layout, comparison, and type-emission work
items per recovery. Cycles, excess
depth/work, missing child layouts, and conflicting observations
leave the affected pointer member as `void*`; these cases never create recursive
type ownership. Dynamic, partial-width, and ambiguous pointer slots remain
unsupported.

Stack locals can now retain scalar floating-point types when typed floating
loads or same-width floating stores provide evidence. Floating and integer
observations of the same slot make its scalar kind ambiguous, so the pass
leaves the local's type unknown rather than choosing one based on access order.
The desktop variable list and typed pseudocode declarations use the recovered
floating type through the existing stack-variable metadata path.

Indexed pointer accesses can provide array-element evidence when an integral
load/store uses an index whose effective byte scale exactly matches the access
width. This includes ARM-style `index << n` addressing represented as an LSL
index shift with the default scale of one. The recovered pointer element type
uses the observed access width. Other shift operations, subtractive indices,
nonzero displacements, mismatched scales, and conflicting element widths do not
produce this evidence; the pointer remains a byte pointer or uses its separately
recovered structure layout.

Stack locals can now retain pointee layout across a pointer spill and reload.
A full-width pointer store into a recovered stack slot carries the stored
pointer's observed fields into the local type; constant stack-slot loads are
linked to their destination SSA values, so dereferences after a reload can
also contribute those fields back to the local. A slot becomes a pointer only
when its stored value or every observed reload is pointer-classified. Conflicting
full-width pointer and non-pointer stores discard pointer and aggregate evidence
for that local. Conflicting access widths, shifted or indexed stack addresses,
and layouts that fail normal non-overlap validation remain conservative.

The optimizer also exposes `eliminate_dead_code` for SSA functions. It removes
unused assignments only when their expression consists of constants, register
references, and pure unary or binary operations. Dead phi nodes and chains are
removed iteratively. Memory loads and explicit effects are retained.

Floating prototype constraints preserve the type graph's floating kind, and a
configured floating return register can provide a floating return type when
width evidence exists. Scalar floating evidence from typed IR register and
memory values, floating intrinsic results, and copies now propagates through
SSA assignments. Intrinsic floating result facts apply only to floating
register banks, so an instruction's integer or status-register side effects do
not inherit the floating result type. Floating return expressions retain that
evidence, while a phi that mixes floating and non-floating inputs remains
untyped. Typed
homogeneous vectors preserve their element kind,
lane width, count, and total width through register recovery and persistent
type records.
`recover_interprocedural_types` accepts a set of lifted functions with one ABI
description per function and returns results in the same order. It resolves
direct calls and indirect calls whose target is proven to be one supplied
function entry through bounded SSA value flow.
Register argument and scalar return propagation also supports calls between
ABI descriptions over the same register file: call arguments are read from the
callee's declared argument registers, and the callee's return register is used
for its modeled result. A caller that targets different conventions invalidates
the union of their caller-saved registers at calls, which is conservative but
can discard values preserved by an individual target. The ABI-aware `to_ssa`
overload snapshots register arguments and each configured stack-base register;
known scalar, pointer, floating, and typed-vector return values get a new SSA
definition at the call. Register and stack-passed argument types are propagated
through a bounded fixed point. Stack arguments require a unique reaching store
before an exact direct call, a supported callee ABI slot, and a stack address
resolved through constant stack-pointer adjustments. The bounded backward CFG
search requires every path to reach the same exact SSA register value at a
full-width store to that slot. Calls, unknown memory writes, partial overlaps,
missing definitions, cycles, or disagreement between paths stop propagation.
The search is capped at 4,096 visited blocks and instructions per call. The
caller and callee may have different register-file maps for this stack-only
path when their stack-base register operand and pointer width are identical;
register arguments still require a shared register file. The scan
rejects unknown memory clobbers, overlapping stores, and source values without
a recovered type. All known non-recursive call sites for a parameter must
agree; an unknown recursive edge waits for a concrete seed from the same call
component. This avoids inventing a type when independent callers disagree.

The call, stack-alias, exact-width, and overlap stops follow the conservative
shape of Ghidra's [`ActionStackPtrFlow::repair`](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/decompile/cpp/coreaction.cc),
which traces across a block boundary only when there is a single predecessor.
HexLab uses its own C++ analysis and extends that path rule to joins only when
every predecessor proves the same exact SSA source value; cycles and partial
or conflicting evidence stay unresolved.
Indirect calls and cross-register-file register arguments are not propagated.
Stack arguments can cross that boundary only when caller and callee use the
same register operand for the stack base and the same pointer width; the callee
slot offset and caller's explicit call-stack adjustment must resolve to a
unanimous exact reaching store. Return values remain gated by the register-file map,
and aggregate return conventions without a modeled result location are not
propagated. Register arguments from a known callee prototype can now constrain
the caller's matching SSA value when no conflicting local type evidence exists;
conflicting formal types for the same call input remain ambiguous and are not
applied.

For compatible direct calls, a register argument whose callee parameter is a
pointer to a recovered structure can carry the callee's bounded field layout
back into the caller's SSA value. Explicit pointer-to-structure prototypes use
the same path. This lets the caller's typed pseudocode show fields it only
passes through to a helper. Layouts from conflicting callee signatures for the
same SSA value are discarded; explicit caller types and conflicting scalar,
floating, or vector evidence remain authoritative. The transfer is limited to
register-passed arguments with matching ABI slot maps and complete structures
up to 1 MiB. It copies only supported scalar and pointer fields, caps arrays at
4096 elements and nested pointee depth at four, with a separate one-million-
item per-function transfer budget and a cap of 4096 distinct caller values.
Unions, unsupported field kinds, and pointers with unresolved named pointee
definitions remain unsupported. All propagated shapes remain heuristic observations and do not
establish a confirmed source declaration.

Stack-passed pointer-to-structure shapes also flow from callers into an
unprototyped callee. The existing ABI slot map, matching pointer width, exact
all-path reaching store, and unanimous compatible caller types must prove
the argument first. The callee must load that exact nonoverlapping entry-relative
slot at pointer width into a full-width register. Only loads that still observe
incoming memory (whole-memory version zero or a proven slot partition at version
zero) receive the shape, so a reload after a slot overwrite does not inherit
incoming argument fields. Constant stack aliases and each ABI's explicit call
stack adjustment use the same proof as scalar stack arguments. This works with
the configured integer/pointer stack slots, including x86 cdecl and Windows x64;
no source parameter order is guessed for an ABI that cannot establish it.

The transferred fields use the existing bounded layout merge rather than an
exact type replacement. A callee's compatible local field observations can
therefore add to the caller's shape, while conflicting widths suppress its
aggregate inference. Explicit callee prototypes remain authoritative. Conflicting
caller layouts, unknown nonrecursive callers, overlapping slot reads, unknown
stores, dynamic stack addresses, and non-pointer-width transfers leave the shape
unresolved. Each slot retains at most 4096 distinct loaded SSA values, within
the existing 4096-value and one-million-item per-function transfer limits. This
shape consensus participates in the same bounded call-component fixed point as
parameter and return types.
The pass caps the function set at 4,096, aggregate blocks at 100,000,
instructions at 500,000, direct call edges at 250,000, tracked ABI registers
at 256, and iterations at 32. Existing locally recovered parameter types are
not replaced by conflicting call-site guesses. Allocation and limit failures
return resource-limit errors. CFG edges, phis, phi inputs, and switch cases each
have aggregate budgets of one million. An iteration-limit diagnostic
accompanies the latest conservative results.

Register maps require register operands representable by the current register
model. This pass is intentionally conservative and incomplete: stack arguments
are inferred only when a configured slot is read through a statically
traceable constant stack-pointer alias, and the ordered ABI map must provide
every preceding slot before one can be included. Dynamic stack allocation,
stack realignment, register save/restore conventions, and red zones are not
modeled. SysV direct-stack evidence is local to the active callee analysis and
does not become an ordered signature or a call-site argument slot.
`AbiDescription::call_stack_adjustment` accounts for implicit call
stack shifts: x64 uses 8 bytes for the return address and AArch64 uses 0 for
its link-register call. Custom ABIs default to 0 and must set this value when
their call mechanics shift the stack. Call clobbers for other conventions and
general aliasing between ordinary register assignments remain unsupported. Constant-offset aggregate inference recovers one nested pointer-to-structure level when both the pointer slot and the loaded pointee have direct evidence. It does not recover deeper nesting or unions. A pointer base use
is evidence of pointer semantics, not proof of a particular pointee type.
Unconstrained integer values are represented as signed or unsigned integer
types according to available IR evidence; this is not equivalent to full C
integer-promotion or ABI classification.

Recovered stack locals carry a width-aware integer name (`u32`/`i32`) when the
access width and signedness are known; pointer and floating locals retain their
recovered type kind. The desktop pseudocode variable list shows these locals
with their first access address, and shows ABI-constrained `argN` variables at
the function entry. Integer names encode their width; other recovered types
include the observed width in bits in the view.

An explicit project type assignment at a stack access can refine that recovered
local's declaration when the access maps to exactly one local. Assignments at
the local's other unambiguous access sites must agree by type identity; a
conflict suppresses the declaration rather than choosing an assignment or the
IR heuristic. Sites that access multiple recovered locals do not transfer a
type to any one of them. This uses project assignments as reviewed evidence.
Imported debug variables can also name and type a recovered stack local when
the active location at an actual access site is a single direct DWARF
base-register-plus-offset operation that exactly matches the recovered frame
register and byte offset, or a PDB frame-relative defrange that exactly matches
the owning procedure and frame-pointer offset. DWARF types use their project
type IDs. PDB types are applied only when one imported project type has the
exact display name and size recorded by the PDB. The mapping must be unique
across all accesses; conflicting names or types are left on the recovered
local instead of merged. Register-resident PDB parameters can replace an
inferred `argN` name only when the PC-entry register matches exactly one ABI
argument slot. Imported DWARF function prototypes already carry their source
parameter names and types. CFA-relative and other unmatched, composite,
indirect, or changing locations remain separate debug metadata and do not
alter pseudocode variables.

Stack-slot ambiguity is scoped to the overlapping byte ranges. If two accesses
describe partially overlapping storage, those slots are omitted while
independent non-overlapping locals in the same frame remain available. A
frame-derived value included in a captured call argument snapshot marks that
frame as escaped, so its stack accesses are not presented as private locals.
When distinct proven frame bases contain the same relative offset, recovered
names receive a deterministic frame suffix so their storage and type evidence
cannot be merged by the common `local_N` display name.

The desktop pseudocode view also accepts a function-type assignment at the
recovered entry as an explicit prototype. Imported DWARF prototypes and
user-assigned function types constrain variable recovery and replace the
generic function header when the declarators are supported. Windows x64 uses
the prototype's source argument positions to select the matching GPR or XMM
register; System V AMD64 maps scalar integer and floating parameters through
their independent register sequences. Unsupported aggregate or stack-slot
classification does not change the displayed prototype or invent register
types. An explicit `ms_abi` or `sysv_abi` function convention on the assigned
prototype selects the corresponding x64 register convention even when it
differs from the convention inferred from the image format. Other explicit
conventions retain the image-format default until a matching recovery map is
implemented.

System V AMD64 prototype recovery consumes the shared ABI classifier's
aggregate placements. Register-passed structures up to two eightbytes map each
INTEGER/SSE piece to its classified GPR/XMM location, retaining the original
parameter index for every piece. INTEGER pieces use a width-matched unsigned
integer view only when source fields cover the complete piece; an SSE piece keeps
its exact floating member type or a vector view only when contiguous equal-width
floating members fill the piece. Padding-only, ambiguous union, and unsupported
member views stay untyped. Stack-passed aggregate
bytes remain visible in the prototype placement, but the current call argument
snapshot cannot reconstruct arbitrary memory copies of aggregate values.

AArch64 AAPCS64 prototypes map scalar floating-point arguments to v0-v7
independently from x0-x7. Scalar floating results use v0. Explicit prototypes
also classify homogeneous floating-point aggregates (HFAs) with one to four
contiguous members of the same supported floating type into consecutive SIMD
argument registers; caller evidence for each member is propagated to the
callee's aggregate parameter. When all HFA members do not fit in the remaining
SIMD argument registers, the allocator exhausts that register bank and assigns
the complete aggregate to aligned incoming stack storage. Recovery represents
that spilled HFA as one stack slot per scalar member, so exact-width member
loads in the callee and direct register-to-stack member stores at a compatible
callsite can propagate each member's floating type. It does not reconstruct
aggregate copies, partial stores, or non-register store sources. Prototype
slots that cannot be classified stop at the first unsupported parameter. Aggregates
with padding, unions, mixed member types, or more than four members remain
unsupported. Multi-register HFA returns and ambiguous mixed-class argument
evidence without a prototype are left unresolved. Without a prototype,
argument inference is emitted only when evidence occupies a contiguous prefix
of one register class; seeing both integer and SIMD classes leaves source
parameter ordering ambiguous.


## Native call outputs

`prepare_call_effects(function, abi)` annotates calls before `to_ssa` using
`AbiDescription::caller_saved_registers`. Windows x64 covers RAX, RCX, RDX,
R8-R11 and XMM0-XMM5; System V AMD64 covers RAX, RCX, RDX, RSI, RDI, R8-R11
and XMM0-XMM15. Both invalidate represented x86 flags. Callee-saved GPRs and
the stack pointer retain their register state. Other ABI helpers keep an empty
caller-saved map and retain their existing conservative behavior.

The pass deduplicates exact register outputs and includes overlapping register
views present in the IR: GPR widths and high bytes, flags widths, and XMM/YMM
views. Represented whole YMM registers on Windows also become unknown because
the ABI preserves only the lower XMM6-XMM15 halves; their separate low XMM
views remain preserved. No value is inferred for any volatile output, and
partial SIMD preservation is not reconstructed as an expression.

`Call::register_writes` and its parallel `register_output_versions` describe
these outputs. SSA captures selected ABI argument registers before defining
outputs, then creates normal definitions and join phis. A modeled typed return
uses the matching output version, rather than defining the return register
twice. Type recovery records volatile outputs independently from incoming
arguments; explicit result types constrain the modeled return. Dead-code
elimination retains definitions used by call argument snapshots. Call-summary
validation, write summaries, and constant invalidation account for these
outputs, while existing call optimization barriers remain in effect.

Native CLI and desktop paths prepare call effects before SSA, as does each
interprocedural type-recovery iteration. Unknown targets still have the ABI's
volatile outputs when the caller ABI is known. Unknown conventions, x87 state,
AVX-512 registers, multiple-register aggregate returns, and general alias
semantics for ordinary assignments are not added by this pass.


Argument snapshots preserve live machine values but do not alone establish
source parameters. Candidate prototypes and `argN` identities require an
actual expression/memory-address read, a used phi feeding such a read, an
explicit parameter constraint, or a compatible known direct callee parameter.
Interprocedural recovery carries known callee use back to the corresponding
snapshot value and waits for candidate signatures as well as result types to
stabilize. Unknown calls therefore do not invent four Windows or six System V
parameters merely because those register slots were captured.

`Call::abi_upper_half_writes` preserves the provenance of Windows-generated
whole-YMM unknown values across repeated preparation. These outputs leave
separate preserved low XMM6-XMM15 views intact. An explicit whole-YMM write
has no such marker and invalidates overlapping low XMM views as well.

Interprocedural recovery can also accept caller-supplied `ExternalFunctionPrototype`
records for exact callable addresses whose bodies are outside the recovered set.
A direct call uses that record only when the address is unique, the prototype is
an explicit function type, and the target ABI shares the caller's register file.
Supported ABI register slots constrain the caller's argument values; a modeled
scalar, pointer, floating, or vector result constrains the target ABI return
register. The call's volatile-register effects include the external ABI, so
cross-ABI facts are not kept live across a call that may clobber them. Conflicting
records at one address suppress type propagation, while their represented
caller-saved effects remain conservative.

Indirect targets are resolved from exact pointer-width integer or pointer constants either directly or through SSA register copies and phis whose every incoming path resolves to the same callable entry across all participating address spaces. Target analysis accounts for the union of caller-saved registers across known ABIs on the same register file, so values that may be clobbered across a call do not create false targets. Cyclic or conflicting joins, dynamic loads, arithmetic transformations, and offsets that match multiple entries remain unresolved. A resolved indirect call is admitted to prototype propagation only when the target ABI description matches the caller ABI; cross-ABI candidates remain unknown even when they share a register file. The matched entry can be a recovered body or an external prototype binding, allowing it to join the same bounded caller/callee prototype fixed point as direct calls. Resolution is limited to 128 definition steps and 500,000 SSA definitions per function, with a 250,000-call graph edge cap. Stack-passed
arguments are propagated only for an exact ABI match when a bounded backward scan
finds a direct register store to the exact outgoing slot with matching width and
class; intervening calls, unknown memory effects, partial overlaps, or non-register
stores stop that proof. Aggregate returns without a modeled result register remain
untyped. Targets in a different register file and unsupported slot classes are
left unresolved.

Stack argument type back-propagation also requires the callee to load the exact
ABI entry-relative slot. Loads at that offset must agree on a byte-aligned width;
the width must equal the caller store width, and the observed stack-load range
must not overlap another observed range. Compatible callsites must agree on the
type before it constrains an unprototyped callee. Missing loads, conflicting
widths or types, and overlapping layouts suppress that stack parameter
inference. Explicit prototypes continue to define parameter locations and types
and are never replaced by caller evidence. The analysis supports constant stack
aliases and stack slots represented by the `AbiDescription`; dynamic, realigned,
and otherwise unmodeled layouts remain unsupported.

Explicit prototypes can model aggregate return registers when the decompiler
can represent the classified result pieces. System V AMD64 delegates this
decision to the shared eightbyte classifier. A single-location INTEGER or SSE
result uses RAX or XMM0, including mixed aggregate shapes classified into one
register. Two-location results are modeled only when both pieces are direct
GPR/XMM values, cover the aggregate exactly without gaps or overlap, and the
existing aggregate projection logic can derive each piece type. This supports
bounded INTEGER, SSE, and mixed INTEGER/SSE two-eightbyte returns. Hidden-result
pointers, x87 classes, unsupported layouts, and results with any other number
or arrangement of locations remain unresolved. Windows x64 retains its bounded
single-register cases. AAPCS64 supports one-member HFAs through v0 and
two-to-four member HFAs through v0-v3 when the classifier's floating-register
locations match each homogeneous element's exact size and contiguous object
offset. The lifter's call writes must include every result register before
those component types are propagated. This path is prototype-driven and never
guesses aggregate returns from observed register widths. For SysV AMD64 and
AAPCS64, explicit function prototypes with a complete structure or array result
classified as indirect also model the hidden result pointer. The classifier's
single exact register location (RDI for SysV AMD64 or X8 for AAPCS64) is used to
type the callee's incoming buffer pointer and, for known direct-call prototypes,
the caller's matching register input as a pointer to the declared result layout.
The call result type is retained as prototype metadata; the pass does not infer
stores through the buffer as a materialized aggregate value. Incomplete or
ambiguous layouts, missing register snapshots, and other ABIs remain unresolved.

PowerPC64 scalar recovery selects the ELFv2 profile only for an ELF64
`EM_PPC64` little-endian image whose `e_flags & EF_PPC64_ABI` value is 2. Raw
PPC64, big-endian ELF, ELFv1, and files with another ABI flag do not receive a
guessed profile. The supported scalar map uses R3-R10 and F1-F13 for incoming
integer and floating values, R3/F1 for integer/floating results, and R1-relative
parameter-save-area stack locations from the shared ELFv2 classifier. With an
explicit prototype, supported scalar register and stack arguments use that map.
Without one, register reads do not establish source parameter order because
GPR and FPR allocation is independent and unused incoming arguments are
possible; observed argument-register or stack use therefore leaves the
candidate parameter list unresolved. Integer-only 8-byte structures use R3,
and supported 16-byte structures are projected across R3/R4. Larger supported
structures use the classifier's hidden R3 result pointer. Variadic placement,
vector arguments, and aggregate layouts outside that bounded classifier subset
remain unsupported by this decompiler path.
The profile follows the [OpenPOWER 64-bit ELF ABI specification](https://openpower.foundation/specifications/64bitelfabi/).

MIPS N32 explicit prototypes now use the shared scalar classifier to constrain incoming `A0`–`A7` integer/pointer or `F12`–`F19` floating arguments and exact entry-relative 8-byte stack slots after the eight argument positions. The N32 data model retains 32-bit pointers with 64-bit GPR containers. Interprocedural argument propagation carries these classified scalar locations only when caller and callee ABI descriptions match, and uses the declared parameter index rather than treating the separate register classes as independently ordered. Scalar integer/pointer results use V0 and floating results use F0 through the existing MIPS N32 profile. Variadic, aggregate, array, vector and unprototyped mixed-class argument recovery remain unsupported; register observations alone do not establish parameter order.

For an explicit SysV AMD64 prototype, binary80 floating scalars (10-byte payloads) are classified as 16-byte aligned stack arguments or ST0 results. A matching entry-relative stack load can therefore inherit the exact prototype type, and return-register evidence recognizes the x87 ST0 class. This is prototype-driven ABI placement only; it does not infer long double signatures from unprototyped calls or model general x87 stack-state dataflow.
