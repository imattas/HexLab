#include "hexlab/workspace/debug_variables.hpp"
#include <algorithm>

namespace hexlab {
namespace {
Result<std::vector<symbols::LocationOperation>> materialize_operations(
    const std::vector<database::DebugLocationOperation> &stored) {
    std::vector<symbols::LocationOperation> operations;
    operations.reserve(stored.size());
    for (const auto &operation : stored) {
        if (operation.kind > static_cast<std::uint8_t>(symbols::LocationOperationKind::entry_value))
            return Error{ErrorCode::malformed, "project DWARF variable has an unknown location operation"};
        symbols::LocationOperation decoded{static_cast<symbols::LocationOperationKind>(operation.kind),
            operation.unsigned_operand, operation.signed_operand, operation.expression_offset,
            operation.second_unsigned_operand};
        if (decoded.kind == symbols::LocationOperationKind::implicit_value) {
            if (operation.second_unsigned_operand > 9)
                return Error{ErrorCode::malformed, "project DWARF implicit-value payload length is invalid"};
            const auto length = static_cast<std::size_t>(operation.second_unsigned_operand);
            decoded.block_operand.reserve(length);
            if (length == 9) decoded.block_operand.resize(length);
            else for (std::size_t i = 0; i < length; ++i)
                decoded.block_operand.push_back(static_cast<std::uint8_t>(operation.unsigned_operand >> (i * 8)));
        }
        operations.push_back(std::move(decoded));
    }
    return operations;
}
}

std::vector<const database::DebugVariable *> debug_variables_at(
    const ProjectSnapshot &snapshot, Address function_entry, std::uint64_t pc) {
    std::vector<const database::DebugVariable *> result;
    if (!snapshot.state || !snapshot.state->user) return result;
    for (const auto &variable : snapshot.state->user->debug_variables) {
        if (variable.function_entry != function_entry) continue;
        if (!variable.location_ranges.empty()) {
            const bool active = std::any_of(variable.location_ranges.begin(), variable.location_ranges.end(),
                [pc](const auto &range) { return !(range.begin == UINT64_MAX && range.end == UINT64_MAX) && range.begin <= pc && pc < range.end; });
            const bool has_default = std::any_of(variable.location_ranges.begin(), variable.location_ranges.end(),
                [](const auto &range) { return range.begin == UINT64_MAX && range.end == UINT64_MAX; });
            if (!active && !has_default) continue;
        }
        result.push_back(&variable);
    }
    return result;
}

Result<symbols::EvaluatedLocation> evaluate_debug_variable(
    const database::DebugVariable &variable, std::uint64_t pc,
    const symbols::LocationEvaluationContext &context) {
    const std::vector<database::DebugLocationOperation> *stored_operations = &variable.location_operations;
    if (!variable.location_ranges.empty()) {
        auto found = std::find_if(variable.location_ranges.begin(), variable.location_ranges.end(),
            [pc](const auto &range) { return !(range.begin == UINT64_MAX && range.end == UINT64_MAX) && range.begin <= pc && pc < range.end; });
        if (found == variable.location_ranges.end()) found = std::find_if(variable.location_ranges.begin(), variable.location_ranges.end(),
            [](const auto &range) { return range.begin == UINT64_MAX && range.end == UINT64_MAX; });
        if (found == variable.location_ranges.end()) return Error{ErrorCode::unsupported, "DWARF variable has no location at the selected PC"};
        stored_operations = &found->operations;
    }
    if (!stored_operations->empty()) {
        auto operations = materialize_operations(*stored_operations);
        if (!operations) return operations.error();
        return symbols::evaluate_location_expression(operations.value(), context);
    }
    if (variable.address) return symbols::EvaluatedLocation{symbols::EvaluatedLocationKind::memory, *variable.address};
    if (variable.cfa_offset && context.call_frame_cfa) {
        const auto mask = context.address_size == 8 ? UINT64_MAX
            : context.address_size == 1 || context.address_size == 2 || context.address_size == 4
                ? (std::uint64_t{1} << (context.address_size * 8)) - 1 : UINT64_MAX;
        return symbols::EvaluatedLocation{symbols::EvaluatedLocationKind::memory,
            (*context.call_frame_cfa + static_cast<std::uint64_t>(*variable.cfa_offset)) & mask};
    }
    return Error{ErrorCode::unsupported, "DWARF variable has no evaluable location"};
}

Result<symbols::EvaluatedLocationSequence> evaluate_debug_variable_sequence(
    const database::DebugVariable &variable, std::uint64_t pc,
    const symbols::LocationEvaluationContext &context) {
    const std::vector<database::DebugLocationOperation> *stored_operations = &variable.location_operations;
    if (!variable.location_ranges.empty()) {
        auto found = std::find_if(variable.location_ranges.begin(), variable.location_ranges.end(),
            [pc](const auto &range) { return !(range.begin == UINT64_MAX && range.end == UINT64_MAX) && range.begin <= pc && pc < range.end; });
        if (found == variable.location_ranges.end()) found = std::find_if(variable.location_ranges.begin(), variable.location_ranges.end(),
            [](const auto &range) { return range.begin == UINT64_MAX && range.end == UINT64_MAX; });
        if (found == variable.location_ranges.end()) return Error{ErrorCode::unsupported, "DWARF variable has no location at the selected PC"};
        stored_operations = &found->operations;
    }
    if (!stored_operations->empty()) {
        auto operations = materialize_operations(*stored_operations);
        if (!operations) return operations.error();
        return symbols::evaluate_location_expression_sequence(operations.value(), context);
    }
    symbols::EvaluatedLocationSequence result;
    if (variable.address) {
        result.location = {symbols::EvaluatedLocationKind::memory, *variable.address};
        return result;
    }
    if (variable.cfa_offset && context.call_frame_cfa) {
        const auto mask = context.address_size == 8 ? UINT64_MAX
            : context.address_size == 1 || context.address_size == 2 || context.address_size == 4
                ? (std::uint64_t{1} << (context.address_size * 8)) - 1 : UINT64_MAX;
        result.location = {symbols::EvaluatedLocationKind::memory,
            (*context.call_frame_cfa + static_cast<std::uint64_t>(*variable.cfa_offset)) & mask};
        return result;
    }
    return Error{ErrorCode::unsupported, "DWARF variable has no evaluable location"};
}

} // namespace hexlab
