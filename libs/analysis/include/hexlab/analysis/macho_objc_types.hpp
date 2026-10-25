#pragma once

#include "hexlab/analysis/analysis_export.hpp"
#include "hexlab/types/types.hpp"
#include "hexlab/core/result.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace hexlab {

struct MachOObjCEncodingLimits {
    std::size_t max_input_bytes = 4096;
    std::size_t max_depth = 32;
    std::size_t max_types = 256;
    std::uint8_t pointer_bytes = 8;
};

struct MachOObjCMethodEncoding {
    types::TypePtr signature;
    std::string status;
    std::size_t encoded_types = 0;
};

struct MachOObjCPropertyEncoding {
    types::TypePtr type;
    std::string status;
    std::size_t encoded_types = 0;
};

// Parses a complete Objective-C method type encoding into a detached function
// type. Unsupported encodings return a result with an empty signature and a
// status; callers can preserve and display the original encoding unchanged.
HEXLAB_ANALYSIS_EXPORT Result<MachOObjCMethodEncoding>
parse_macho_objc_method_encoding(std::string_view, const MachOObjCEncodingLimits & = {});

// Parses one complete Objective-C property type encoding. Property attribute
// lists (for example `T@"NSString",C,N`) should pass only the `T` value.
HEXLAB_ANALYSIS_EXPORT Result<MachOObjCPropertyEncoding>
parse_macho_objc_property_encoding(std::string_view, const MachOObjCEncodingLimits & = {});

} // namespace hexlab
