#include "compare_adapter.hpp"
#include <algorithm>
#include <map>
#include <tuple>

namespace hexlab::desktop {
void populate_direct_call_neighborhoods(const FunctionSnapshot &snapshot,
                                        std::span<compare::FunctionFeature> features) {
    using QualifiedAddress = std::pair<std::uint32_t, std::uint64_t>;
    std::map<QualifiedAddress, std::size_t> feature_by_address;
    for (std::size_t i = 0; i < features.size(); ++i) {
        features[i].direct_calls.clear();
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
