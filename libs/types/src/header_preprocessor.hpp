#pragma once

#include "hexlab/types/header_import.hpp"

namespace hexlab::types::detail {
hexlab::Result<std::string> preprocess_header(std::string_view source,
    const HeaderImportOptions &options);
}
