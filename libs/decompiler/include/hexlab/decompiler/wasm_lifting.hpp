#pragma once

#include "hexlab/decompiler/decompiler.hpp"

namespace hexlab::decompiler {

// Lifts the bounded, typed WebAssembly scalar-stack subset documented in
// docs/wasm-decompilation.md. Unsupported effects fail closed.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_wasm_function(const FunctionRecord &, const FunctionSnapshot &);
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_wasm_function(const FunctionRecord &, const FunctionSnapshot &, const WasmMetadata *metadata);

} // namespace hexlab::decompiler
