#pragma once
#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/image/jvm_metadata.hpp"
namespace hexlab::decompiler {
HEXLAB_DECOMPILER_EXPORT Result<LiftedFunction>
lift_jvm_function(const FunctionRecord &, const FunctionSnapshot &, const JvmMetadata *metadata = nullptr);
}
