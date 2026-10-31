#include "compare_adapter.hpp"
#include <algorithm>
#include <map>
#include <tuple>

namespace hexlab::desktop {
compare::Result<std::vector<std::shared_ptr<const InstructionFact>>> review_compare_instructions(
    const FunctionSnapshot &snapshot, const compare::FunctionAddress &entry,
    std::uint64_t start, std::uint64_t count) {
    using Facts = std::vector<std::shared_ptr<const InstructionFact>>;
    if (!count) return Facts{};
    const auto shown = std::min<std::uint64_t>(count, compare_instruction_review_limit);
    if (start > UINT64_MAX - shown)
        return compare::Error{compare::ErrorCode::overflow, "Instruction review range overflows."};
    // Bound all lookup and sequence visits, including null records. A failed
    // lookup never publishes a misleading partial sequence.
    std::size_t remaining = 1'000'000;
    const auto visit = [&]() {
        if (!remaining) return false;
        --remaining;
        return true;
    };
    const auto budget_error = [] {
        return compare::Error{compare::ErrorCode::resource_limit, "Decoded instruction review lookup budget exhausted."};
    };
    const FunctionRecord *function = nullptr;
    for (const auto &candidate : snapshot.functions) {
        if (!visit()) return budget_error();
        if (candidate && candidate->entry.offset == entry.entry &&
            candidate->entry.space.value == entry.address_space) {
            function = candidate.get();
            break;
        }
    }
    if (!function)
        return compare::Error{compare::ErrorCode::invalid_argument, "Function is absent from the retained decoded snapshot."};
    std::map<std::uint64_t, const BasicBlock *> blocks;
    for (const auto id : function->blocks) {
        if (!visit()) return budget_error();
        blocks.emplace(id.value, nullptr);
    }
    for (const auto &block : snapshot.blocks) {
        if (!visit()) return budget_error();
        if (!block) continue;
        const auto found = blocks.find(block->id.value);
        if (found != blocks.end() && !found->second) found->second = block.get();
    }
    Facts result;
    result.reserve(static_cast<std::size_t>(shown));
    std::uint64_t position = 0;
    for (const auto id : function->blocks) {
        if (!visit()) return budget_error();
        const auto *block = blocks.at(id.value);
        // Feature extraction also skips absent blocks and null instruction facts.
        if (!block) continue;
        for (const auto &fact : block->instructions) {
            if (!visit()) return budget_error();
            if (!fact) continue;
            if (position++ < start) continue;
            result.push_back(fact);
            if (result.size() == shown) return result;
        }
    }
    return compare::Error{compare::ErrorCode::invalid_argument,
        "Instruction range is absent from the retained decoded snapshot."};
}

void populate_direct_call_neighborhoods(const FunctionSnapshot &snapshot,
                                        std::span<compare::FunctionFeature> features) {
    using QualifiedAddress = std::pair<std::uint32_t, std::uint64_t>;
    std::map<QualifiedAddress, std::size_t> feature_by_address;
    for (std::size_t i = 0; i < features.size(); ++i) {
        features[i].direct_calls.clear();
        features[i].direct_calls_complete = snapshot.complete;
        feature_by_address.emplace(QualifiedAddress{features[i].address_space, features[i].entry}, i);
    }

    std::map<std::uint64_t, std::size_t> feature_by_function;
    for (const auto &function : snapshot.functions) {
        if (!function) continue;
        const auto found = feature_by_address.find(
            QualifiedAddress{function->entry.space.value, function->entry.offset});
        if (found != feature_by_address.end())
            feature_by_function.emplace(function->id.value, found->second);
    }

    for (const auto &call : snapshot.calls) {
        if (!call.target) continue;
        const auto owner = feature_by_function.find(call.owner.value);
        const auto callee = feature_by_address.find(
            QualifiedAddress{call.target->space.value, call.target->offset});
        if (owner == feature_by_function.end() || callee == feature_by_address.end()) continue;
        const auto &target = features[callee->second];
        features[owner->second].direct_calls.push_back({target.entry, target.address_space});
    }

    for (auto &feature : features) {
        auto &calls = feature.direct_calls;
        std::sort(calls.begin(), calls.end(), [](const auto &a, const auto &b) {
            return std::tie(a.address_space, a.entry) < std::tie(b.address_space, b.entry);
        });
        calls.erase(std::unique(calls.begin(), calls.end()), calls.end());
    }
}
} // namespace hexlab::desktop
