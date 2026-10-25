#pragma once

#include "hexlab/decompiler/decompiler.hpp"

#include <cstddef>
#include <stop_token>

namespace hexlab::decompiler {

// Eligibility is an explicit contract supplied by the analysis owner. A
// complete body must include every possible register/memory effect and every
// normal exit. Imports, interposable symbols and unresolved bindings must set
// externally_bound. Architecture-specific call/return effects are separate
// from the lifted body (for example a link register or pushed return address).
struct CallSummaryInput {
    const LiftedFunction *function = nullptr;
    bool body_is_complete = false;
    bool externally_bound = false;
    bool boundary_register_effects_known = false;
    std::vector<RegisterOperand> boundary_register_writes;
    IntrinsicMemoryEffect boundary_memory_effect = IntrinsicMemoryEffect::unknown;
};

struct CallSummaryOptions {
    std::size_t max_functions = 4096;
    std::size_t max_blocks = 65536;
    std::size_t max_instructions = 1000000;
    std::size_t max_expression_nodes = 4000000;
    std::size_t max_expression_depth = 128;
    std::size_t max_call_depth = 64;
    std::size_t max_work = 16000000;
};

struct FunctionCallSummary {
    Address entry{{0}, 0};
    // False summaries carry no usable facts; their effects remain unknown.
    bool proven = false;
    bool register_effects_known = false;
    std::vector<RegisterOperand> register_writes;
    bool may_read_memory = true;
    bool may_write_memory = true;
    // Present only when every modeled return explicitly returns the same
    // locally proven, width-checked integer/boolean/pointer constant.
    std::optional<ConstantValue> return_constant;
    std::string reason;
};

struct CallSummaryOptimization {
    // Input ordering is preserved. Calls are retained, including pure calls.
    std::vector<LiftedFunction> functions;
    std::vector<FunctionCallSummary> summaries;
};

// Summarizes unique, complete, locally bound direct callees bottom-up. Unknown,
// indirect, recursive, conflicting and opaque callees remain barriers. Register
// constants are propagated only within a block; a summary invalidates every
// alias of its written registers. No-write calls unify their output memory SSA
// version with the input version throughout the caller, including memory phis.
// Existing single-function optimizer APIs retain their original behavior.
// Limits or cancellation return an error without publishing partial results.
HEXLAB_DECOMPILER_EXPORT Result<CallSummaryOptimization> optimize_with_call_summaries(
    std::span<const CallSummaryInput>, const CallSummaryOptions & = {}, std::stop_token = {});

} // namespace hexlab::decompiler
