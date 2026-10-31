// Build a reusable target-scoped byte or normalized-fingerprint catalog from
// the current recovered functions without silently truncating a project.
#include "hexlab/automation/api.hpp"
#include <iostream>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 3 || (std::string_view(argv[1]) != "signature" &&
                      std::string_view(argv[1]) != "fingerprint")) {
        std::cerr << "usage: hexlab_function_catalog signature|fingerprint project.hxproj\n";
        return 2;
    }
    auto fail = [](const hexlab::Error& error) {
        std::cerr << error.message << '\n';
        return 1;
    };
    auto opened = hexlab::automation::Project::open(argv[2]);
    if (!opened) return fail(opened.error());
    const auto& project = opened.value();
    auto state = project->snapshot();
    if (!state) return fail(state.error());
    constexpr std::size_t maximum_functions = 4096;
    auto functions = project->functions(0, maximum_functions);
    if (!functions) return fail(functions.error());
    if (functions.value().empty()) {
        std::cerr << "project has no recovered functions\n";
        return 1;
    }
    if (functions.value().size() == maximum_functions) {
        auto overflow = project->functions(maximum_functions, 1);
        if (!overflow) return fail(overflow.error());
        if (!overflow.value().empty()) {
            std::cerr << "project exceeds the 4,096-function catalog limit\n";
            return 1;
        }
    }
    auto current = project->snapshot();
    if (!current) return fail(current.error());
    if (current.value()->state->revisions.edit != state.value()->state->revisions.edit ||
        current.value()->state->revisions.bytes != state.value()->state->revisions.bytes) {
        std::cerr << "function snapshot changed while collecting catalog selection\n";
        return 1;
    }
    std::vector<hexlab::FunctionId> ids;
    ids.reserve(functions.value().size());
    for (const auto& function : functions.value()) ids.push_back(function.id);

    const auto revision = state.value()->state->revisions.edit;
    const std::string_view kind(argv[1]);
    if (kind == "signature") {
        auto catalog = project->function_signature_catalog(ids, "HexLab SDK example", {}, revision);
        if (!catalog) return fail(catalog.error());
        auto text = hexlab::serialize_signature_catalog(catalog.value());
        if (!text) return fail(text.error());
        std::cout << text.value();
        return std::cout ? 0 : 1;
    }
    auto catalog = project->function_fingerprint_catalog(ids, "HexLab SDK example", {}, revision);
    if (!catalog) return fail(catalog.error());
    auto text = hexlab::serialize_function_fingerprint_catalog(catalog.value());
    if (!text) return fail(text.error());
    std::cout << text.value();
    return std::cout ? 0 : 1;
}
