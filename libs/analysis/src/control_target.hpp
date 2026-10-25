#pragma once
#include "hexlab/analysis/analysis.hpp"
namespace hexlab::analysis_detail {
inline std::uint32_t control_operand_index(const Instruction &instruction) {
    return hexlab::control_operand_index(instruction);
}
// Resolves only declared ordinary same-level code segments. Gates, privilege
// changes, conforming transfers and runtime segment-register state stay unknown.
inline std::optional<Address> control_target(const Image &image, const Instruction &instruction) {
    if (instruction.direct_target)
        return instruction.direct_target;
    if ((instruction.flow != FlowKind::call && instruction.flow != FlowKind::jump) || instruction.operands.empty())
        return {};
    const auto *pointer = std::get_if<FarPointerOperand>(&instruction.operands.front());
    const auto &profile = image.layout().x86_profile;
    if (!pointer || !profile)
        return {};
    const X86ImageBinding *source = nullptr, *destination = nullptr;
    for (const auto &binding : profile->bindings) {
        if (binding.space == instruction.address.space)
            source = &binding;
        if (binding.selector == pointer->selector)
            destination = &binding;
    }
    if (!source || !destination)
        return {};
    if (profile->environment == X86ImageEnvironment::protected386) {
        if (!source->descriptor || !destination->descriptor)
            return {};
        const auto &from = *source->descriptor, &to = *destination->descriptor;
        if (!from.executable || !to.executable || !from.present || !to.present || from.conforming || to.conforming ||
            from.dpl != to.dpl || (source->selector & 3) != from.dpl || (destination->selector & 3) != from.dpl)
            return {};
    }
    auto address = image.from_logical({pointer->selector, pointer->offset});
    if (!address)
        return {};
    const auto context = image.context_at(address.value());
    if (!context || !processor_capabilities(context.value()).can_decode ||
        !image.linear_spans(address.value(), 1, X86SegmentAccess::execute))
        return {};
    return address.value();
}
} // namespace hexlab::analysis_detail
