#pragma once

#include "hexlab/types/types.hpp"

#include <functional>

namespace hexlab::types {

// Data model used to lay out C-like data types. This intentionally describes
// object layout only; calling convention rules are outside its scope.
enum class Abi { x86_32, x86_64, aarch64, aarch32 };

struct MemberLayout {
    std::string name;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint64_t alignment = 1;
    std::optional<std::uint32_t> bit_width;
    std::optional<std::uint32_t> bit_offset;
    // True when this is the final incomplete-array member of a structure.
    // Its object extent is zero in the containing type's fixed layout.
    bool flexible_array = false;
};

struct PaddingRange {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
};

struct TypeLayout {
    std::uint64_t size = 0;
    std::uint64_t alignment = 1;
    std::uint64_t pointer_size = 0;
    std::vector<MemberLayout> members;
    std::vector<PaddingRange> padding;
};

using NamedTypeResolver = std::function<hexlab::Result<TypePtr>(std::string_view)>;

// Caps natural alignment applied to aggregate members and nested aggregates.
// Zero uses the ABI default. Non-zero values must be powers of two up to 16.
// Recorded compiler-derived member alignments remain exact; this option models
// common #pragma pack / packed-attribute caps on otherwise natural alignment.
struct LayoutOptions {
    std::uint64_t maximum_member_alignment = 0;
    // Optional project-level definition lookup for symbolic named references.
    // The returned type graph must be retained by the resolver's owner.
    NamedTypeResolver resolve_named_type;
};

// Computes a fresh layout without mutating the immutable Type graph. Struct
// offsets and padding are derived from members; stored aggregate size, offsets,
// and alignment are treated as prior metadata and are not reused.
HEXLAB_TYPES_EXPORT hexlab::Result<TypeLayout> layout(const Type &type, Abi abi, LayoutOptions options = {});
HEXLAB_TYPES_EXPORT std::uint64_t pointer_size(Abi abi) noexcept;

} // namespace hexlab::types
