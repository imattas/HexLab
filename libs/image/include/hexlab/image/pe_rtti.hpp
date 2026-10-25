#pragma once
#include "hexlab/image/pe_source.hpp"
#include <optional>
#include <string>

namespace hexlab {
enum class PeRttiRecordState : std::uint8_t { decoded, malformed, unsupported, unresolved, ambiguous };
enum class PeRttiSlotState : std::uint8_t { executable, null_pointer, in_image_nonexecutable, unmapped_or_uninitialized, outside_image };
enum class PeRttiTableEnd : std::uint8_t { unresolved_boundary, next_locator_prefix, null_pointer, nonexecutable_pointer, section_end, scan_limit, slot_limit };

struct PeRttiTypeDescriptor {
    std::uint32_t rva = 0;
    std::uint64_t type_info_vftable_va = 0, spare = 0;
    std::optional<std::uint32_t> type_info_vftable_rva;
    std::string decorated_name;
    PeRecordSource header_source, name_source;
    bool operator==(const PeRttiTypeDescriptor &) const = default;
};
struct PeRttiBaseClass {
    std::uint32_t descriptor_rva = 0, type_descriptor_rva = 0, contained_bases = 0, attributes = 0;
    std::int32_t member_displacement = 0, vbptr_displacement = -1, vbtable_displacement = 0;
    std::optional<std::uint32_t> hierarchy_rva, parent_index;
    PeRecordSource array_entry_source, descriptor_source;
    bool operator==(const PeRttiBaseClass &) const = default;
};
struct PeRttiClassHierarchy {
    std::uint32_t rva = 0, signature = 0, attributes = 0, base_array_rva = 0;
    PeRttiRecordState state = PeRttiRecordState::decoded;
    PeRecordSource source, base_array_source;
    std::vector<PeRttiBaseClass> bases;
    bool operator==(const PeRttiClassHierarchy &) const = default;
};
struct PeRttiCompleteObjectLocator {
    std::uint32_t rva = 0, signature = 0, object_offset = 0, constructor_displacement = 0;
    std::uint32_t type_descriptor_rva = 0, hierarchy_rva = 0, self_rva = 0;
    PeRttiRecordState state = PeRttiRecordState::unresolved;
    PeRecordSource source;
    std::string diagnostic;
    bool operator==(const PeRttiCompleteObjectLocator &) const = default;
};
struct PeRttiVftableSlot {
    std::uint32_t index = 0, rva = 0;
    std::uint64_t encoded_va = 0;
    PeRttiSlotState state = PeRttiSlotState::outside_image;
    std::optional<std::uint32_t> target_rva;
    bool matches_runtime_function_begin = false;
    // The first non-executable word is retained as a boundary observation,
    // without asserting that it belongs to the vftable.
    bool boundary_probe = false;
    PeRecordSource source;
    bool operator==(const PeRttiVftableSlot &) const = default;
};
struct PeRttiVftable {
    std::uint32_t prefix_rva = 0, address_point_rva = 0, locator_rva = 0;
    PeRttiRecordState state = PeRttiRecordState::unresolved;
    PeRttiTableEnd end = PeRttiTableEnd::unresolved_boundary;
    PeRecordSource prefix_source;
    std::vector<PeRttiVftableSlot> slots;
    std::string diagnostic;
    bool operator==(const PeRttiVftable &) const = default;
};
// Structural candidates from original file bytes. All links/targets are RVAs;
// encoded pointer VAs remain tied to the preferred image base, even after rebase.
struct PeMsvcRttiMetadata {
    bool discovery_complete = true;
    std::uint64_t scanned_bytes = 0;
    std::vector<PeRttiTypeDescriptor> types;
    std::vector<PeRttiClassHierarchy> hierarchies;
    std::vector<PeRttiCompleteObjectLocator> locators;
    std::vector<PeRttiVftable> vftables;
    std::string diagnostic;
    bool operator==(const PeMsvcRttiMetadata &) const = default;
};
} // namespace hexlab
