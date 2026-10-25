#pragma once

#include "hexlab/workspace/project.hpp"
#include "hexlab/symbols/dwarf_location_values.hpp"

namespace hexlab {

// Returns the persisted DWARF variables whose function owner and PC-scoped
// location are active at `pc`. Variables without a location list are visible
// throughout their owning function; ranged variables are visible only inside
// one of their half-open location ranges.
HEXLAB_WORKSPACE_EXPORT std::vector<const database::DebugVariable *>
debug_variables_at(const ProjectSnapshot &, Address function_entry, std::uint64_t pc);

// Evaluates the selected variable location using caller-supplied machine
// registers, frame/CFA values, and memory access. This never attaches to or
// reads a debuggee process. Location-list ranges take precedence over the
// variable's default expression.
HEXLAB_WORKSPACE_EXPORT Result<symbols::EvaluatedLocation> evaluate_debug_variable(
    const database::DebugVariable &, std::uint64_t pc,
    const symbols::LocationEvaluationContext &);

// Composite-aware counterpart that retains each DW_OP_piece/bit_piece result,
// including unavailable fragments, while selecting the same persisted PC range.
HEXLAB_WORKSPACE_EXPORT Result<symbols::EvaluatedLocationSequence>
evaluate_debug_variable_sequence(const database::DebugVariable &, std::uint64_t pc,
                                 const symbols::LocationEvaluationContext &);

} // namespace hexlab
