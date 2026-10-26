#pragma once
#include "hexlab/analysis/relocations.hpp"
#include "hexlab/types/types.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace hexlab {

struct MachOObjCMethod {
    Address entry{};
    std::optional<std::string> selector;
    std::string selector_status = "not-read";
    std::optional<std::string> type_encoding;
    std::string type_status = "not-read";
    types::TypePtr signature;
    std::string signature_status = "not-read";
    std::optional<Address> implementation;
    std::string implementation_status = "not-read";
    bool relative_encoding = false;
    // Preserve the resolved pointer evidence separately from a validated code
    // address. ARM32 IMP bit zero encodes Thumb state, not an address byte.
    std::optional<Address> encoded_implementation;
    std::string implementation_pointer_status = "not-read";
    std::optional<ExecutionMode> implementation_mode;
};

struct MachOObjCIvar {
    Address entry{};
    std::optional<std::string> name, type_encoding;
    std::string name_status = "not-read", type_status = "not-read";
    std::optional<Address> offset_address;
    std::optional<std::uint32_t> offset, size, alignment, alignment_raw;
    std::string offset_status = "not-read";
};

struct MachOObjCProperty {
    Address entry{};
    std::optional<std::string> name, attributes;
    std::string name_status = "not-read", attributes_status = "not-read";
    std::optional<std::string> type_encoding;
    types::TypePtr type;
    std::string type_status = "not-read";
};

struct MachOObjCProtocolReference {
    Address slot{};
    std::optional<Address> address;
    std::string pointer_status = "unresolved";
    std::optional<std::string> name;
    std::string name_status = "not-read";
    std::optional<std::size_t> definition_index;
};

struct MachOObjCListOrigin {
    std::uint32_t section = 0;
    std::uint64_t index = 0;
    Address slot{};
    bool operator==(const MachOObjCListOrigin &) const = default;
};

struct MachOObjCList {
    std::optional<Address> address;
    std::optional<std::uint32_t> count;
    std::optional<std::uint32_t> stride;
    std::uint32_t encoded_flags = 0;
    std::string status;
    std::vector<MachOObjCMethod> methods;
    std::vector<MachOObjCIvar> ivars;
    std::vector<MachOObjCProperty> properties;
    std::vector<MachOObjCProtocolReference> protocol_references;
};

struct MachOObjCClass {
    std::uint32_t classlist_section = 0;
    std::uint64_t classlist_index = 0;
    Address classlist_slot{};
    std::vector<MachOObjCListOrigin> origins;
    std::optional<Address> class_address;
    std::string class_pointer_status;
    std::optional<Address> metaclass_address;
    std::string metaclass_pointer_status = "not-read";
    std::optional<Address> metaclass_ro_address;
    std::string metaclass_ro_pointer_status = "not-read";
    std::optional<std::string> metaclass_name;
    std::string metaclass_name_status = "not-read";
    MachOObjCList class_methods;
    std::optional<Address> superclass_address;
    std::string superclass_pointer_status;
    std::optional<Address> class_ro_address;
    std::string class_ro_pointer_status;
    std::optional<std::string> name;
    std::string name_status = "not-read";
    std::optional<std::string> superclass_name;
    std::optional<std::size_t> superclass_index;
    std::optional<std::uint32_t> flags;
    std::optional<std::uint32_t> instance_start;
    std::optional<std::uint32_t> instance_size;
    MachOObjCList methods, protocols, ivars, properties;
    std::vector<std::size_t> category_indices;
    bool complete = true;
};

struct MachOObjCCategory {
    std::uint32_t categorylist_section = 0;
    std::uint64_t categorylist_index = 0;
    Address categorylist_slot{};
    std::vector<MachOObjCListOrigin> origins;
    std::optional<Address> address, target_class;
    std::optional<std::size_t> target_class_index;
    std::string pointer_status = "unresolved", target_class_status = "unresolved";
    std::optional<std::string> name, target_class_name;
    std::string name_status = "not-read";
    std::string target_class_link_status = "unlinked";
    MachOObjCList instance_methods, class_methods, protocols, instance_properties;
    bool complete = true;
};

struct MachOObjCProtocol {
    std::uint32_t protolist_section = 0;
    std::uint64_t protolist_index = 0;
    Address protolist_slot{};
    std::vector<MachOObjCListOrigin> origins;
    std::optional<Address> address;
    std::string pointer_status = "unresolved";
    std::optional<std::string> name;
    std::string name_status = "not-read";
    MachOObjCList adopted_protocols;
    MachOObjCList required_instance_methods, required_class_methods;
    MachOObjCList optional_instance_methods, optional_class_methods;
    MachOObjCList instance_properties;
    bool complete = true;
};

struct MachOObjCLimits {
    std::size_t max_classes = 100000;
    std::size_t max_categories = 100000;
    std::size_t max_protocols = 100000;
    std::uint64_t max_metadata_bytes = 64ull * 1024 * 1024;
    std::size_t max_name_bytes = 4096;
    std::uint32_t max_list_entries = 1000000;
};

struct MachOObjCScan {
    std::vector<MachOObjCClass> classes;
    std::vector<MachOObjCCategory> categories;
    std::vector<MachOObjCProtocol> protocols;
    std::uint64_t metadata_bytes = 0;
    bool complete = true;
    std::string reason;
    std::uint8_t pointer_bytes = 0;
};

// Parses 32-bit and 64-bit little-endian Objective-C class-list, class_ro_t,
// protocol, and category ObjC2 metadata from mapped Mach-O images. Both widths
// accept validated absolute and 32-bit field-relative method entries; ObjC1
// __OBJC records remain unsupported. Pointer slots use
// exact relocation/dyld resolution where available; only unassociated
// initialized bytes are treated as raw pointers.
HEXLAB_ANALYSIS_EXPORT Result<MachOObjCScan>
scan_macho_objc_classes(const Image &, const ImageMetadata &, const MachOObjCLimits & = {}, std::stop_token = {});

} // namespace hexlab
