#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hexlab {
struct DexDebugLine {
    std::uint32_t address = 0; // Byte offset in the method-relative address space.
    std::uint32_t line = 0;
    std::string source_file;
    bool operator==(const DexDebugLine &) const = default;
};
struct DexDebugLocal {
    std::uint32_t register_index = 0;
    std::uint32_t begin = 0, end = 0; // Half-open byte offsets in the method.
    std::optional<std::string> name, type, signature;
    bool parameter = false;
    bool operator==(const DexDebugLocal &) const = default;
};
struct DexMethodDebug {
    std::uint32_t method_index = 0;
    std::uint32_t line_start = 0;
    std::vector<std::optional<std::string>> parameter_names;
    std::vector<DexDebugLine> lines;
    std::vector<DexDebugLocal> locals;
    bool operator==(const DexMethodDebug &) const = default;
};
struct DexExceptionHandler {
    std::uint32_t address = 0; // Byte offset in the method-relative address space.
    std::optional<std::uint32_t> type_index; // Empty for the encoded catch-all.
    bool operator==(const DexExceptionHandler &) const = default;
};
struct DexExceptionRegion {
    std::uint32_t begin = 0, end = 0; // Half-open byte offsets in the method.
    std::vector<DexExceptionHandler> handlers; // Encoded order, including catch-all last.
    bool operator==(const DexExceptionRegion &) const = default;
};
struct DexMethodCode {
    std::uint32_t method_index = 0;
    std::uint32_t register_count = 0;
    std::uint32_t incoming_register_count = 0;
    std::vector<DexExceptionRegion> exception_regions;
    bool operator==(const DexMethodCode &) const = default;
};
struct DexMetadata {
    std::vector<DexMethodDebug> methods;
    std::vector<DexMethodCode> code;
    bool operator==(const DexMetadata &) const = default;
};
}
