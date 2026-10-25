#pragma once

#include "hexlab/decompiler/decompiler.hpp"

namespace hexlab::decompiler {

// Lifts a bounded Dalvik subset into the common IR. Unresolved calls and
// memory references retain conservative effects; unsupported opcodes return
// ErrorCode::unsupported.
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction> lift_dex_function(
    const FunctionRecord &, const FunctionSnapshot &);

} // namespace hexlab::decompiler
