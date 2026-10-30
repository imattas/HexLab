#pragma once

#include "project_arguments.hpp"
#include "argument_text.hpp"
#include <fstream>
#include <sstream>

namespace hexlab::cli::project_detail {

struct ParsedSignatureInputs {
    SignatureCatalogSet catalogs;
    // Canonical, ordered catalog contents; length prefixes preserve duplicate
    // catalogs and remove concatenation ambiguity from persisted evidence IDs.
    std::string identity;
};

inline ParsedSignatureInputs load_signature_inputs(const Arguments &args) {
    struct Input { std::filesystem::path path; };
    std::vector<Input> inputs;
    if (args.signature_definitions_list.empty()) {
        inputs.push_back({args.signature_definitions});
    } else {
        std::error_code error;
        const auto size = std::filesystem::file_size(args.signature_definitions_list, error);
        require(!error && size <= 1024 * 1024,
                "Cannot read signature catalog list or list exceeds 1 MiB");
        std::ifstream stream(args.signature_definitions_list, std::ios::binary);
        require(bool(stream), "Cannot open signature catalog list");
        std::string contents(static_cast<std::size_t>(size), '\0');
        require(!size || bool(stream.read(contents.data(), static_cast<std::streamsize>(size))),
                "Cannot read signature catalog list");
        if (contents.starts_with("\xef\xbb\xbf")) contents.erase(0, 3);
        std::istringstream lines(contents);
        std::string line;
        while (std::getline(lines, line)) {
            const auto first = line.find_first_not_of(" \t\r");
            if (first == std::string::npos || line[first] == '#') continue;
            const auto last = line.find_last_not_of(" \t\r");
            const auto item = line.substr(first, last - first + 1);
            auto path = path_from_wide(utf8_to_wide(item));
            if (path.is_relative()) path = args.signature_definitions_list.parent_path() / path;
            inputs.push_back({std::move(path)});
            if (inputs.size() > 256)
                throw Failure{{ErrorCode::resource_limit, "Signature catalog list exceeds 256 entries"}};
        }
        require(!inputs.empty(), "Signature catalog list contains no paths");
    }

    ParsedSignatureInputs result;
    result.catalogs.catalogs.reserve(inputs.size());
    result.identity = args.signature_definitions_list.empty() ? std::string{} : "hexlab-signature-catalog-set-v1:";
    std::uint64_t total_bytes = 0;
    std::size_t total_definitions = 0;
    for (const auto &input_path : inputs) {
        std::error_code error;
        const auto size = std::filesystem::file_size(input_path.path, error);
        require(!error && size <= 1024 * 1024 && size <= 64ull * 1024 * 1024 - total_bytes,
                "Cannot read signature catalog or aggregate input exceeds its byte budget");
        std::ifstream stream(input_path.path, std::ios::binary);
        require(bool(stream), "Cannot open signature catalog");
        std::string text(static_cast<std::size_t>(size), '\0');
        require(!size || bool(stream.read(text.data(), static_cast<std::streamsize>(size))),
                "Cannot read signature catalog");
        total_bytes += size;
        auto catalog = take(parse_signature_catalog(text));
        if (catalog.definitions.size() > 4096 - total_definitions)
            throw Failure{{ErrorCode::resource_limit, "Signature catalog set exceeds 4,096 definitions"}};
        total_definitions += catalog.definitions.size();
        auto canonical = take(serialize_signature_catalog(catalog));
        if (inputs.size() == 1 && args.signature_definitions_list.empty()) {
            result.identity = std::move(canonical);
        } else {
            result.identity += std::to_string(canonical.size()) + ":" + canonical;
        }
        result.catalogs.catalogs.push_back(std::move(catalog));
    }
    return result;
}

} // namespace hexlab::cli::project_detail
