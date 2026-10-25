#pragma once

#include "hexlab/analysis/references.hpp"
#include "hexlab/analysis/strings.hpp"

namespace hexlab {

struct StringReference {
    ReferenceId reference;
    Location source;
    std::optional<std::uint32_t> operand_index;
    std::size_t string_index = 0;
    ReferenceKind kind = ReferenceKind::memory_address;
    bool operator==(const StringReference &) const = default;
};

struct StringReferenceScan {
    std::vector<StringReference> records;
    bool complete = true;
};

// Associates resolved incoming references with every discovered string extent
// containing their target. Only exact, unambiguous image locations are used.
HEXLAB_ANALYSIS_EXPORT Result<StringReferenceScan>
find_string_references(const ReferenceIndex &, const StringScan &, std::stop_token);

} // namespace hexlab
