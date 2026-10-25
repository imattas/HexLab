#pragma once
#include "hexlab/types/types.hpp"
#include <string_view>

namespace hexlab::types {
// Parses comma-separated enumerators in the form NAME or NAME = VALUE.
// Values accept decimal or 0x-prefixed hexadecimal notation. Unassigned
// values start at zero and continue from the preceding value.
HEXLAB_TYPES_EXPORT hexlab::Result<std::vector<Enumerator>> parse_enumerators(std::string_view text,
                                                                             TypePtr underlying);
// Formats exact stored values, using signed decimal notation for signed enums.
HEXLAB_TYPES_EXPORT hexlab::Result<std::string> format_enumerators(const Type &enumeration);
}
