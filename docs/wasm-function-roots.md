# WebAssembly exported-function roots

Function recovery now retains each validated export of a defined WebAssembly
function as a distinct `wasm_export` seed. The seed records the function index,
export row, resolved type index, export-section file offset, and export-entry
file offset. These fields survive derived-cache serialization; cache version 40
and function-engine fingerprint v66 invalidate older records that cannot carry
this evidence.

Before publishing the seed, recovery checks that the function index belongs to
the defined portion of the imported-then-defined function index space, the
export's resolved type agrees with the function type table, the export row
index and source offsets are consistent and within the source file, and the
corresponding function-relative address is the start of a complete initialized
executable code segment in the WebAssembly wasm32 context. An invalid exported
definition marks recovery incomplete and is retained as an unsupported
candidate. Multiple export names for one function preserve separate source
rows on the same function record.

The module loader already exposes each validated function body as an image
entry, so this addition enriches ownership provenance rather than discovering
new code bodies. Imported function exports remain host-provided and do not seed
local code. It does not add host linking, indirect-call target inference, or
function extents beyond each validated code-body segment.

The validated module start function is also retained as a distinct `wasm_start`
seed, because instantiation invokes it even when the module does not export it.
Its evidence records the function/type indices and source offsets. Recovery only
seeds a defined function after checking its function-type mapping, source offsets,
and complete initialized executable body. An imported start function remains a
host-provided callback and has no local code root. Cache version 45 and function
engine fingerprint v71 include the new seed evidence. This adds an execution root;
it does not model module instantiation or execute start-function side effects.

Every validated defined function body also contributes a `wasm_defined` seed,
including bodies with no export, start-section reference, element reference, or
direct-call edge. This makes otherwise disconnected local functions visible in
recovered function and chunk listings. Each seed records the combined function
index, resolved type index, and body file offset. Recovery rechecks that the
body is fully initialized executable code in a wasm32 function address space;
an inconsistent function/type/body mapping marks the snapshot incomplete and
produces a candidate. Imports remain excluded because they have no local code
body. Derived-cache version 48 and function-engine fingerprint v74 include this
root evidence.

Validated direct `call` instructions now use the same function-index address
spaces as those roots. A local edge is recorded only if the function/type index
and its complete executable body all validate. Decoder flow metadata marks
direct and indirect WebAssembly calls as calls, preserving their continuation
edges. Imported calls retain their exact module/name, function-space index, and
optional symbolic host binding in the function call record and reference index.
Function-call graph JSON emits them as symbolic external nodes with no code
address. `call_indirect` target resolution still needs stack-index and
runtime-table analysis. The start root is still only an analysis root: module
instantiation order and host callbacks are not executed or modeled.
