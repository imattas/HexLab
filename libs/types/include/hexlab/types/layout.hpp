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

// Allocation behavior for bitfields while recomputing an aggregate. The
// recorded policy treats Member::offset and Member::bit_offset as exact source
// coordinates; it does not infer compiler allocation-unit rules. Microsoft
// C/C++ and the bounded common Itanium-family subset are explicit opt-ins
// because architecture alone does not identify the compiler ABI that produced
// a type. Itanium delegates ordinary allocation to the platform C ABI.
enum class BitfieldLayoutPolicy { recorded, microsoft, itanium };

// Caps natural alignment applied to aggregate members and nested aggregates.
// Zero uses the ABI default. Non-zero values must be powers of two up to 16.
// Recorded compiler-derived member alignments remain exact; this option models
// common #pragma pack / packed-attribute caps on otherwise natural alignment.
struct LayoutOptions {
    std::uint64_t maximum_member_alignment = 0;
    // Optional project-level definition lookup for symbolic named references.
    // The returned type graph must be retained by the resolver's owner.
    NamedTypeResolver resolve_named_type;
    // Appended to preserve the existing aggregate-initialization order of the
    // pack cap and named-type resolver fields.
    BitfieldLayoutPolicy bitfield_policy = BitfieldLayoutPolicy::recorded;
};

// Computes a fresh layout without mutating the immutable Type graph. Ordinary
// struct offsets and padding are derived from members; recorded bitfield byte
// and bit coordinates are honored as explicit metadata. Stored aggregate size
// and alignment are treated as prior metadata and are not reused as extents.
// Bitfield allocation without explicit coordinates remains unsupported unless
// an allocation policy is explicitly selected.
HEXLAB_TYPES_EXPORT hexlab::Result<TypeLayout> layout(const Type &type, Abi abi, LayoutOptions options = {});
HEXLAB_TYPES_EXPORT std::uint64_t pointer_size(Abi abi) noexcept;

} // namespace hexlab::types
