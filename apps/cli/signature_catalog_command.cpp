#include "signature_catalog_command.hpp"

namespace hexlab::cli {

Result<std::string> create_all_function_signature_catalog(
    const Image &image, const ByteStorage &bytes, const FunctionSnapshot &snapshot,
    std::string provenance, const FunctionSignatureOptions &options) {
    if (snapshot.functions.empty() || snapshot.functions.size() > 4096)
        return Error{ErrorCode::resource_limit,
                     "All-functions signature catalog requires 1 through 4,096 recovered functions"};
    if (!snapshot.complete || snapshot.omitted_functions)
        return Error{ErrorCode::resource_limit,
                     "All-functions signature catalog requires complete function recovery"};

    std::vector<FunctionId> selected;
    selected.reserve(snapshot.functions.size());
    for (const auto &function : snapshot.functions) {
        if (!function)
            return Error{ErrorCode::malformed, "Recovered function snapshot contains a missing function record"};
        selected.push_back(function->id);
    }
    auto catalog = create_function_signature_catalog(image, bytes, snapshot, selected,
                                                      std::move(provenance), options);
    if (!catalog) return catalog.error();
    return serialize_signature_catalog(catalog.value());
}

} // namespace hexlab::cli
