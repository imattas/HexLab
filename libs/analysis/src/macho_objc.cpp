#include "hexlab/analysis/macho_objc.hpp"
#include "hexlab/analysis/macho_objc_types.hpp"
#include <algorithm>
#include <bit>
#include <functional>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <utility>

namespace hexlab {
namespace {
struct Budget {
    const MachOObjCLimits &limits;
    MachOObjCScan &scan;
    std::stop_token stop;
    std::uint8_t pointer_bytes = 8;
    bool arm32 = false;
    bool arm64_32 = false;
    bool consume(std::uint64_t bytes) {
        if (stop.stop_requested()) return false;
        if (bytes > limits.max_metadata_bytes - std::min(scan.metadata_bytes, limits.max_metadata_bytes)) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C metadata byte budget exhausted";
            return false;
        }
        scan.metadata_bytes += bytes;
        return true;
    }
};

std::uint64_t read_integer(std::span<const std::byte> bytes, std::size_t at, std::size_t width) {
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < width; ++i)
        result |= std::uint64_t(std::to_integer<std::uint8_t>(bytes[at + i])) << (8 * i);
    return result;
}

bool backed_readable(const Image &image, Address at, std::uint64_t size) {
    const auto *domain = image.space(at.space);
    if (!domain) return false;
    if (domain->width_bits < 64) {
        const auto limit = UINT64_C(1) << domain->width_bits;
        if (at.offset >= limit || size > limit - at.offset) return false;
    } else if (size > UINT64_MAX - at.offset) return false;
    const auto *segment = image.segment_at(at);
    if (!segment || !segment->readable || at.offset < segment->begin.offset) return false;
    const auto relative = at.offset - segment->begin.offset;
    return relative <= segment->size && size <= segment->size - relative &&
           relative <= segment->file_size && size <= segment->file_size - relative &&
           image.plaintext_window(at, size) == size;
}

Result<std::vector<std::byte>> read_exact(const Image &image, Address at, std::size_t size, Budget &budget) {
    if (budget.stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
    if (!backed_readable(image, at, size)) return Error{ErrorCode::out_of_bounds, "Pointer leaves initialized readable image bytes"};
    if (!budget.consume(size)) {
        if (budget.stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
        return Error{ErrorCode::resource_limit, "Objective-C metadata byte budget exhausted"};
    }
    return image.read(at, size);
}

std::optional<Address> add(Address base, std::uint64_t amount) {
    if (amount > UINT64_MAX - base.offset) return {};
    return Address{base.space, base.offset + amount};
}

std::optional<Address> add_relative(Address field, std::int32_t displacement) {
    if (displacement >= 0) return add(field, static_cast<std::uint32_t>(displacement));
    const auto magnitude = static_cast<std::uint64_t>(-static_cast<std::int64_t>(displacement));
    if (magnitude > field.offset) return {};
    return Address{field.space, field.offset - magnitude};
}

using MetadataAddressKey = std::pair<std::uint32_t, std::uint64_t>;
MetadataAddressKey address_key(Address value) { return {value.space.value, value.offset}; }

struct Pointer {
    std::optional<Address> address;
    std::string status = "unresolved";
};

bool pointer_domain(const Image &image, Address address, const Budget &budget) {
    const auto *domain = image.space(address.space);
    if (!domain || domain->order != ByteOrder::little)
        return false;
    if (budget.arm64_32)
        return domain->width_bits == 64 && address.offset <= UINT32_MAX;
    return domain->width_bits == budget.pointer_bytes * 8 &&
           (budget.pointer_bytes == 8 || address.offset <= UINT32_MAX);
}

Pointer pointer_at(const Image &image, const RelocationResolver &resolver, Address slot, Budget &budget) {
    const auto width = static_cast<std::uint64_t>(budget.pointer_bytes);
    if (!pointer_domain(image, slot, budget)) return {{}, "pointer-width-mismatch"};
    if (slot.offset % budget.pointer_bytes) return {{}, "misaligned-pointer-slot"};
    if (!backed_readable(image, slot, width)) return {{}, "uninitialized-or-unmapped"};
    auto bytes = read_exact(image, slot, budget.pointer_bytes, budget);
    if (!bytes) return {{}, bytes.error().code == ErrorCode::canceled ? "canceled" :
                            bytes.error().code == ErrorCode::resource_limit ? "budget" : "raw-read-failed"};
    auto resolved = resolver.data_at(image, slot, budget.pointer_bytes, budget.stop);
    if (!resolved) return {{}, resolved.error().code == ErrorCode::canceled ? "canceled" : "fixup-error"};
    if (resolved.value().address) {
        if (!pointer_domain(image, *resolved.value().address, budget)) return {{}, "resolved-pointer-width-mismatch"};
        const auto status = resolved.value().dyld ? "dyld-resolved"
                           : !resolved.value().relocations.empty() ? "relocation-resolved"
                                                                    : "resolved";
        return {resolved.value().address, status};
    }
    // A fixup owns the field even when it cannot be interpreted. Never read
    // the encoded storage bits as if they were a preferred-address pointer.
    if (resolved.value().relocated()) {
        if (resolved.value().dyld) {
            const auto reason = resolved.value().dyld->resolution.reason;
            switch (reason) {
            case MachODyldResolutionReason::runtime_binding: return {{}, "dyld-runtime-binding"};
            case MachODyldResolutionReason::authenticated: return {{}, "dyld-authenticated"};
            case MachODyldResolutionReason::ambiguous: return {{}, "dyld-ambiguous"};
            case MachODyldResolutionReason::field_mismatch: return {{}, "dyld-field-mismatch"};
            case MachODyldResolutionReason::unsupported: return {{}, "dyld-unsupported"};
            case MachODyldResolutionReason::unavailable_field: return {{}, "dyld-unavailable"};
            case MachODyldResolutionReason::overflow: return {{}, "dyld-overflow"};
            case MachODyldResolutionReason::non_pointer: return {{}, "dyld-non-pointer"};
            case MachODyldResolutionReason::missing_anchor: return {{}, "dyld-missing-anchor"};
            case MachODyldResolutionReason::unmapped_target: return {{}, "dyld-unmapped-target"};
            case MachODyldResolutionReason::none: return {{}, "dyld-unresolved"};
            case MachODyldResolutionReason::resolved: break;
            }
            return {{}, "dyld-unresolved"};
        }
        return {{}, "relocation-unresolved"};
    }
    const auto value = read_integer(bytes.value(), 0, budget.pointer_bytes);
    if (!value) return {{}, "null"};
    Address target{slot.space, value};
    if (!image.segment_at(target)) return {{}, "unmapped-raw"};
    return {target, "raw"};
}

std::optional<std::string> read_name(const Image &image, Address address, Budget &budget, std::string &status) {
    const auto *segment = image.segment_at(address);
    if (!segment || !segment->readable || address.offset < segment->begin.offset) {
        status = "name-unmapped";
        return {};
    }
    const auto relative = address.offset - segment->begin.offset;
    if (relative >= segment->file_size) {
        status = "name-uninitialized";
        return {};
    }
    const auto available = segment->file_size - relative;
    const auto request = static_cast<std::size_t>(std::min<std::uint64_t>(available, budget.limits.max_name_bytes));
    if (!request) {
        status = "name-limit";
        return {};
    }
    auto bytes = read_exact(image, address, request, budget);
    if (!bytes) {
        status = bytes.error().code == ErrorCode::canceled ? "canceled" : "name-read-failed";
        return {};
    }
    const auto end = std::find(bytes.value().begin(), bytes.value().end(), std::byte{0});
    if (end == bytes.value().end()) {
        status = available > request ? "name-limit" : "unterminated-name";
        return {};
    }
    status = "resolved";
    const auto length = static_cast<std::size_t>(end - bytes.value().begin());
    return std::string(reinterpret_cast<const char *>(bytes.value().data()), length);
}

bool add_incomplete(MachOObjCScan &scan, MachOObjCClass &row, std::string reason) {
    row.complete = false;
    scan.complete = false;
    if (scan.reason.empty()) scan.reason = std::move(reason);
    return false;
}

bool add_incomplete(MachOObjCScan &scan, MachOObjCCategory &row, std::string reason) {
    row.complete = false;
    scan.complete = false;
    if (scan.reason.empty()) scan.reason = std::move(reason);
    return false;
}

bool add_incomplete(MachOObjCScan &scan, MachOObjCProtocol &row, std::string reason) {
    row.complete = false;
    scan.complete = false;
    if (scan.reason.empty()) scan.reason = std::move(reason);
    return false;
}

void mark_incomplete(MachOObjCScan &scan, bool &owner_complete, std::string reason);

MachOObjCList parse_list(const Image &image, const RelocationResolver &resolver, Address pointer_slot,
                         unsigned kind, Budget &budget, MachOObjCScan &scan, bool &owner_complete) {
    MachOObjCList output;
    output.pointer_slot = pointer_slot;
    const auto pointer = pointer_at(image, resolver, pointer_slot, budget);
    output.pointer_status = pointer.status;
    if (!pointer.address) {
        output.status = pointer.status;
        if (pointer.status != "null") mark_incomplete(scan, owner_complete, "Objective-C metadata contains an unresolved list pointer");
        return output;
    }
    output.address = pointer.address;
    if (pointer.address->offset % (kind == 2 ? budget.pointer_bytes : 4u)) {
        output.status = "tagged-or-misaligned-list-pointer";
        mark_incomplete(scan, owner_complete, "Objective-C list pointer alignment or tagged-list encoding is unsupported");
        return output;
    }
    const auto header_size = kind == 2 ? static_cast<std::uint64_t>(budget.pointer_bytes) : UINT64_C(8);
    if (!backed_readable(image, *pointer.address, header_size)) {
        output.status = "list-header-uninitialized";
        mark_incomplete(scan, owner_complete, "Objective-C list header is outside initialized readable bytes");
        return output;
    }
    auto header = read_exact(image, *pointer.address, static_cast<std::size_t>(header_size), budget);
    if (!header) {
        output.status = header.error().code == ErrorCode::canceled ? "canceled" : "list-header-unreadable";
        mark_incomplete(scan, owner_complete, "Objective-C list header could not be read");
        return output;
    }
    std::uint64_t count = 0;
    std::uint64_t stride = 0;
    if (kind == 1) { // method_list_t: entsizeAndFlags, count
        const auto encoded_stride = static_cast<std::uint32_t>(read_integer(header.value(), 0, 4));
        // The low two bits are runtime fixup markers, not part of entsize.
        stride = encoded_stride & 0x0000fffcu;
        output.encoded_flags = encoded_stride & 0xffff0003u;
        count = read_integer(header.value(), 4, 4);
        output.count = static_cast<std::uint32_t>(count);
        output.stride = static_cast<std::uint32_t>(stride);
        const bool relative = (output.encoded_flags & 0x80000000u) != 0;
        if ((output.encoded_flags & 0x3fff0000u) ||
            (!relative && (output.encoded_flags & 0x40000000u))) {
            output.status = "unsupported-method-flags";
            mark_incomplete(scan, owner_complete, "Objective-C method encoding flags are unsupported");
            return output;
        }
        const std::uint64_t minimum = (output.encoded_flags & 0x80000000u)
                                          ? 12
                                          : 3 * static_cast<std::uint64_t>(budget.pointer_bytes);
        if (stride < minimum || stride > 4096 || stride % (relative ? 4u : budget.pointer_bytes)) {
            output.status = "invalid-method-stride";
            mark_incomplete(scan, owner_complete, "Objective-C method list stride is invalid");
            return output;
        }
    } else if (kind == 2) { // protocol_list_t: uintptr_t count, then pointers
        count = read_integer(header.value(), 0, budget.pointer_bytes);
        stride = budget.pointer_bytes;
    } else { // ivar_list_t/property_list_t: entsize, count
        stride = read_integer(header.value(), 0, 4);
        count = read_integer(header.value(), 4, 4);
        const std::uint64_t minimum = kind == 3 ? 3 * budget.pointer_bytes + 8
                                                 : 2 * budget.pointer_bytes;
        if (stride < minimum || stride > 4096 || stride % budget.pointer_bytes) {
            output.status = kind == 3 ? "invalid-ivar-stride" : "invalid-property-stride";
            mark_incomplete(scan, owner_complete, "Objective-C list entry stride is invalid");
            return output;
        }
    }
    if (count > budget.limits.max_list_entries || count > UINT32_MAX ||
        (count && stride > (UINT64_MAX - header_size) / count)) {
        output.status = "list-limit";
        mark_incomplete(scan, owner_complete, "Objective-C list count exceeds configured limit");
        return output;
    }
    const auto extent = header_size + count * stride;
    if (!backed_readable(image, *pointer.address, extent)) {
        output.status = "list-extent-uninitialized";
        mark_incomplete(scan, owner_complete, "Objective-C list extent exceeds initialized readable bytes");
        return output;
    }
    // Count the extent for work accounting without dereferencing element
    // pointers or interpreting method/property/protocol payloads.
    if (!budget.consume(extent - header_size)) {
        output.status = "budget";
        mark_incomplete(scan, owner_complete, "Objective-C metadata byte budget exhausted");
        return output;
    }
    output.count = static_cast<std::uint32_t>(count);
    output.stride = static_cast<std::uint32_t>(stride);
    output.status = pointer.status + "/extent-validated";
    return output;
}

void mark_incomplete(MachOObjCScan &scan, bool &owner_complete, std::string reason) {
    owner_complete = false;
    scan.complete = false;
    if (scan.reason.empty()) scan.reason = std::move(reason);
}

std::optional<Address> relative_pointer(const Image &image, Address field, Budget &budget, std::string &status) {
    if (!pointer_domain(image, field, budget)) {
        status = "relative-field-pointer-width-mismatch";
        return {};
    }
    auto raw = read_exact(image, field, 4, budget);
    if (!raw) {
        status = raw.error().code == ErrorCode::canceled ? "canceled" : "relative-offset-unreadable";
        return {};
    }
    const auto offset = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(read_integer(raw.value(), 0, 4)));
    const auto target = add_relative(field, offset);
    if (!target) {
        status = "relative-offset-overflow";
        return {};
    }
    if (!pointer_domain(image, *target, budget)) {
        status = "relative-target-pointer-width-mismatch";
        return {};
    }
    if (!image.segment_at(*target)) {
        status = "relative-target-unmapped";
        return {};
    }
    status = "relative";
    return target;
}

std::optional<std::string> direct_string_pointer(const Image &image, const RelocationResolver &resolver,
                                                Address slot, Budget &budget, std::string &status) {
    const auto pointer = pointer_at(image, resolver, slot, budget);
    if (!pointer.address) {
        status = pointer.status;
        return {};
    }
    return read_name(image, *pointer.address, budget, status);
}

std::optional<std::string> relative_string(const Image &image, Address field, Budget &budget,
                                           std::string &status) {
    const auto target = relative_pointer(image, field, budget, status);
    if (!target) return {};
    return read_name(image, *target, budget, status);
}

std::optional<std::string> relative_selector(const Image &image, const RelocationResolver &resolver,
                                             Address field, bool direct, Budget &budget,
                                             std::string &status) {
    const auto target = relative_pointer(image, field, budget, status);
    if (!target) return {};
    if (direct) return read_name(image, *target, budget, status);
    const auto selector = pointer_at(image, resolver, *target, budget);
    if (!selector.address) {
        status = selector.status;
        return {};
    }
    return read_name(image, *selector.address, budget, status);
}

std::optional<std::string> property_type_encoding(std::string_view attributes, std::string &status) {
    if (attributes.empty() || attributes.front() != 'T') {
        status = "type-attribute-missing";
        return {};
    }
    if (attributes.size() == 1) {
        status = "type-attribute-empty";
        return {};
    }
    std::vector<char> closing;
    bool quoted = false;
    bool escaped = false;
    for (std::size_t i = 1; i < attributes.size(); ++i) {
        const char ch = attributes[i];
        if (quoted) {
            if (escaped) escaped = false;
            else if (ch == '\\') escaped = true;
            else if (ch == '"') quoted = false;
            continue;
        }
        if (ch == '"') {
            quoted = true;
            continue;
        }
        if (ch == '[') closing.push_back(']');
        else if (ch == '{') closing.push_back('}');
        else if (ch == '(') closing.push_back(')');
        else if (ch == ']' || ch == '}' || ch == ')') {
            if (closing.empty() || closing.back() != ch) {
                status = "type-attribute-unbalanced";
                return {};
            }
            closing.pop_back();
        } else if (ch == ',' && closing.empty()) {
            if (i == 1) {
                status = "type-attribute-empty";
                return {};
            }
            status = "resolved";
            return std::string(attributes.substr(1, i - 1));
        }
    }
    if (quoted || escaped || !closing.empty()) {
        status = "type-attribute-unbalanced";
        return {};
    }
    status = "resolved";
    return std::string(attributes.substr(1));
}

void decode_property_attribute_semantics(MachOObjCProperty &property) {
    if (!property.attributes) {
        property.attribute_semantics_status = "attributes-unavailable";
        return;
    }
    const auto &raw = *property.attributes;
    if (raw.empty() || raw.front() != 'T' || !property.type_encoding) {
        property.attribute_semantics_status = "type-attribute-invalid";
        return;
    }
    const auto suffix_begin = std::size_t{1} + property.type_encoding->size();
    if (suffix_begin >= raw.size()) {
        property.attribute_semantics_status = "parsed";
        return;
    }
    if (raw[suffix_begin] != ',') {
        property.attribute_semantics_status = "type-attribute-invalid";
        return;
    }
    unsigned seen = 0;
    bool unknown = false, malformed = false;
    auto mark = [&](unsigned bit) {
        if (seen & bit) malformed = true;
        seen |= bit;
    };
    std::size_t at = suffix_begin + 1;
    while (at <= raw.size()) {
        const auto end = raw.find(',', at);
        const auto part = std::string_view(raw).substr(at, end == std::string::npos ? raw.size() - at : end - at);
        if (part.empty()) { malformed = true; break; }
        switch (part.front()) {
        case 'R': mark(1u << 0); property.readonly = part.size() == 1; if (part.size() != 1) malformed = true; break;
        case 'C': mark(1u << 1); property.copy = part.size() == 1; if (part.size() != 1) malformed = true; break;
        case '&': mark(1u << 2); property.strong = part.size() == 1; if (part.size() != 1) malformed = true; break;
        case 'W': mark(1u << 3); property.weak = part.size() == 1; if (part.size() != 1) malformed = true; break;
        case 'N': mark(1u << 4); property.nonatomic = part.size() == 1; if (part.size() != 1) malformed = true; break;
        case 'D': mark(1u << 5); property.dynamic = part.size() == 1; if (part.size() != 1) malformed = true; break;
        case 'G':
            mark(1u << 6);
            if (part.size() == 1) malformed = true;
            else property.custom_getter = std::string(part.substr(1));
            break;
        case 'S':
            mark(1u << 7);
            if (part.size() == 1) malformed = true;
            else property.custom_setter = std::string(part.substr(1));
            break;
        case 'V': // Runtime backing-ivar name; retained in the raw record.
            if (part.size() == 1) malformed = true;
            else property.backing_ivar = std::string(part.substr(1));
            break;
        default: unknown = true; break;
        }
        if (end == std::string::npos) break;
        at = end + 1;
    }
    if ((property.copy && property.strong) || (property.copy && property.weak) ||
        (property.strong && property.weak)) malformed = true;
    property.attribute_semantics_status = malformed ? "malformed-attributes" :
        unknown ? "parsed-with-unknown-attributes" : "parsed";
}

bool decode_methods(const Image &image, const RelocationResolver &resolver, MachOObjCList &list,
                    Budget &budget, MachOObjCScan &scan, bool &owner_complete) {
    if (!list.address || !list.count || !list.stride) return true;
    const bool small = (list.encoded_flags & 0x80000000u) != 0;
    const bool direct_selector = (list.encoded_flags & 0x40000000u) != 0;
    for (std::uint32_t i = 0; i < *list.count; ++i) {
        if (budget.stop.stop_requested()) return false;
        if (scan.metadata_bytes >= budget.limits.max_metadata_bytes) {
            list.status += "/budget-partial";
            mark_incomplete(scan, owner_complete, "Objective-C method decoding exhausted its metadata byte budget");
            return true;
        }
        const auto entry = add(*list.address, 8ull + std::uint64_t{i} * *list.stride);
        if (!entry) {
            mark_incomplete(scan, owner_complete, "Objective-C method entry address overflow");
            return false;
        }
        MachOObjCMethod row;
        row.entry = *entry;
        row.relative_encoding = small;
        if (small) {
            const auto name_slot = *entry;
            const auto types_slot = add(*entry, 4);
            const auto imp_slot = add(*entry, 8);
            if (!types_slot || !imp_slot) {
                mark_incomplete(scan, owner_complete, "Objective-C relative method field address overflow");
                return false;
            }
            row.selector = relative_selector(image, resolver, name_slot, direct_selector, budget, row.selector_status);
            row.type_encoding = relative_string(image, *types_slot, budget, row.type_status);
            row.implementation = relative_pointer(image, *imp_slot, budget, row.implementation_status);
        } else {
            const auto types_slot = add(*entry, budget.pointer_bytes);
            const auto imp_slot = add(*entry, 2ull * budget.pointer_bytes);
            if (!types_slot || !imp_slot) {
                mark_incomplete(scan, owner_complete, "Objective-C method field address overflow");
                return false;
            }
            row.selector = direct_string_pointer(image, resolver, *entry, budget, row.selector_status);
            row.type_encoding = direct_string_pointer(image, resolver, *types_slot, budget, row.type_status);
            const auto implementation = pointer_at(image, resolver, *imp_slot, budget);
            row.implementation = implementation.address;
            row.implementation_status = implementation.status;
        }
        row.encoded_implementation = row.implementation;
        row.implementation_pointer_status = row.implementation_status;
        if (row.implementation) {
            auto target = *row.implementation;
            std::uint64_t code_bytes = 1;
            if (budget.arm32) {
                const bool thumb = (target.offset & 1) != 0;
                row.implementation_mode = thumb ? ExecutionMode::thumb : ExecutionMode::a32;
                target.offset &= ~UINT64_C(1);
                code_bytes = thumb ? 2 : 4;
            }
            const auto *segment = image.segment_at(target);
            std::string failure;
            if (!pointer_domain(image, target, budget)) failure = "target-pointer-width-mismatch";
            else if (budget.arm32 && target.offset % code_bytes) failure = "target-misaligned";
            else if (!segment || !segment->executable) failure = "target-not-executable";
            else {
                const auto relative = target.offset - segment->begin.offset;
                if (relative >= segment->file_size || code_bytes > segment->file_size - relative ||
                    code_bytes > segment->size - relative) failure = "target-uninitialized";
                else if (image.plaintext_window(target, code_bytes) != code_bytes ||
                         image.code_window(target, code_bytes) != code_bytes) failure = "target-code-unavailable";
                else if (budget.arm32 && image.layout().arm_profile) {
                    const auto context = image.context_at(target);
                    if (!context || context.value().mode != *row.implementation_mode) failure = "target-mode-mismatch";
                }
            }
            if (failure.empty()) row.implementation = target;
            else {
                row.implementation.reset();
                row.implementation_status = std::move(failure);
            }
        }
        if (row.type_encoding) {
            MachOObjCEncodingLimits encoding_limits;
            encoding_limits.pointer_bytes = budget.pointer_bytes;
            auto parsed = parse_macho_objc_method_encoding(*row.type_encoding, encoding_limits);
            if (!parsed) row.signature_status = "parse-error:" + parsed.error().message;
            else {
                row.signature = parsed.value().signature;
                row.signature_status = parsed.value().status;
            }
        } else {
            row.signature_status = "encoding-unavailable";
        }
        if (!row.selector || !row.type_encoding || !row.implementation) {
            mark_incomplete(scan, owner_complete, "Objective-C method entry has an unresolved selector, type, or implementation");
        }
        list.methods.push_back(std::move(row));
    }
    return true;
}

bool decode_ivars(const Image &image, const RelocationResolver &resolver, MachOObjCList &list,
                  Budget &budget, MachOObjCScan &scan, bool &owner_complete) {
    if (!list.address || !list.count || !list.stride) return true;
    for (std::uint32_t i = 0; i < *list.count; ++i) {
        if (budget.stop.stop_requested()) return false;
        const auto entry = add(*list.address, 8ull + std::uint64_t{i} * *list.stride);
        if (!entry) {
            mark_incomplete(scan, owner_complete, "Objective-C ivar entry address overflow");
            return false;
        }
        MachOObjCIvar row;
        row.entry = *entry;
        const auto name_slot = add(*entry, budget.pointer_bytes);
        const auto type_slot = add(*entry, 2ull * budget.pointer_bytes);
        const auto align_slot = add(*entry, 3ull * budget.pointer_bytes);
        const auto size_slot = add(*entry, 3ull * budget.pointer_bytes + 4);
        if (!name_slot || !type_slot || !align_slot || !size_slot) {
            mark_incomplete(scan, owner_complete, "Objective-C ivar field address overflow");
            return false;
        }
        const auto offset_pointer = pointer_at(image, resolver, *entry, budget);
        row.offset_address = offset_pointer.address;
        row.offset_status = offset_pointer.status;
        if (offset_pointer.address) {
            auto value = read_exact(image, *offset_pointer.address, 4, budget);
            if (value) row.offset = static_cast<std::uint32_t>(read_integer(value.value(), 0, 4));
            else row.offset_status = value.error().code == ErrorCode::canceled ? "canceled" : "offset-unreadable";
        }
        row.name = direct_string_pointer(image, resolver, *name_slot, budget, row.name_status);
        row.type_encoding = direct_string_pointer(image, resolver, *type_slot, budget, row.type_status);
        auto align = read_exact(image, *align_slot, 4, budget);
        auto size = read_exact(image, *size_slot, 4, budget);
        if (align) {
            row.alignment_raw = static_cast<std::uint32_t>(read_integer(align.value(), 0, 4));
            if (*row.alignment_raw == UINT32_MAX) row.alignment = budget.pointer_bytes;
            else if (*row.alignment_raw < 31) row.alignment = std::uint32_t{1} << *row.alignment_raw;
        }
        if (size) row.size = static_cast<std::uint32_t>(read_integer(size.value(), 0, 4));
        if (!row.offset || !row.name || !row.type_encoding || !row.size || !row.alignment)
            mark_incomplete(scan, owner_complete, "Objective-C ivar entry contains unresolved fields");
        list.ivars.push_back(std::move(row));
    }
    return true;
}

bool decode_properties(const Image &image, const RelocationResolver &resolver, MachOObjCList &list,
                       Budget &budget, MachOObjCScan &scan, bool &owner_complete) {
    if (!list.address || !list.count || !list.stride) return true;
    for (std::uint32_t i = 0; i < *list.count; ++i) {
        if (budget.stop.stop_requested()) return false;
        const auto entry = add(*list.address, 8ull + std::uint64_t{i} * *list.stride);
        if (!entry) {
            mark_incomplete(scan, owner_complete, "Objective-C property entry address overflow");
            return false;
        }
        MachOObjCProperty row;
        row.entry = *entry;
        row.list_address = list.address;
        row.list_index = i;
        const auto attributes_slot = add(*entry, budget.pointer_bytes);
        if (!attributes_slot) {
            mark_incomplete(scan, owner_complete, "Objective-C property field address overflow");
            return false;
        }
        row.name = direct_string_pointer(image, resolver, *entry, budget, row.name_status);
        row.attributes = direct_string_pointer(image, resolver, *attributes_slot, budget, row.attributes_status);
        if (row.attributes) {
            row.type_encoding = property_type_encoding(*row.attributes, row.type_status);
            decode_property_attribute_semantics(row);
            if (row.type_encoding) {
                MachOObjCEncodingLimits encoding_limits;
                encoding_limits.pointer_bytes = budget.pointer_bytes;
                auto parsed = parse_macho_objc_property_encoding(*row.type_encoding, encoding_limits);
                if (!parsed) row.type_status = "parse-error:" + parsed.error().message;
                else {
                    row.type = parsed.value().type;
                    row.type_status = parsed.value().status;
                }
            }
        } else {
            row.type_status = "attributes-unavailable";
            decode_property_attribute_semantics(row);
        }
        if (!row.name || !row.attributes)
            mark_incomplete(scan, owner_complete, "Objective-C property entry contains unresolved strings");
        list.properties.push_back(std::move(row));
    }
    return true;
}

bool decode_protocol_references(const Image &image, const RelocationResolver &resolver, MachOObjCList &list,
                                Budget &budget, MachOObjCScan &scan, bool &owner_complete) {
    if (!list.address || !list.count || !list.stride) return true;
    for (std::uint32_t i = 0; i < *list.count; ++i) {
        if (budget.stop.stop_requested()) return false;
        const auto slot = add(*list.address, static_cast<std::uint64_t>(budget.pointer_bytes) +
                                                   std::uint64_t{i} * *list.stride);
        if (!slot) {
            mark_incomplete(scan, owner_complete, "Objective-C protocol reference slot address overflow");
            return false;
        }
        MachOObjCProtocolReference row;
        row.slot = *slot;
        const auto protocol = pointer_at(image, resolver, *slot, budget);
        row.address = protocol.address;
        row.pointer_status = protocol.status;
        if (protocol.address) {
            const auto name_slot = add(*protocol.address, budget.pointer_bytes); // isa precedes mangledName
            if (name_slot) row.name = direct_string_pointer(image, resolver, *name_slot, budget, row.name_status);
            else row.name_status = "name-slot-overflow";
        } else {
            row.name_status = protocol.status;
        }
        if (!row.address || !row.name)
            mark_incomplete(scan, owner_complete, "Objective-C protocol reference or name is unresolved");
        list.protocol_references.push_back(std::move(row));
    }
    return true;
}

bool decode_list(const Image &image, const RelocationResolver &resolver, MachOObjCList &list, unsigned kind,
                 Budget &budget, MachOObjCScan &scan, bool &owner_complete) {
    // Rejected headers retain count/stride evidence, but must never authorize
    // payload decoding (notably 32-bit relative or unknown method encodings).
    if (!list.status.ends_with("/extent-validated")) return true;
    if (kind == 1) return decode_methods(image, resolver, list, budget, scan, owner_complete);
    if (kind == 2) return decode_protocol_references(image, resolver, list, budget, scan, owner_complete);
    if (kind == 3) return decode_ivars(image, resolver, list, budget, scan, owner_complete);
    return decode_properties(image, resolver, list, budget, scan, owner_complete);
}

bool decode_metaclass(const Image &image, const RelocationResolver &resolver, MachOObjCClass &row,
                      Budget &budget, MachOObjCScan &scan) {
    if (!row.class_address) return true;
    const auto pointer_bytes = static_cast<std::uint64_t>(budget.pointer_bytes);
    const auto class_size = 5 * pointer_bytes;
    // Through baseMethods on LP64; the full stable ILP32 prefix is also 40 bytes.
    const auto class_ro_size = UINT64_C(40);
    const auto class_ro_name_offset = budget.pointer_bytes == 8 ? UINT64_C(24) : UINT64_C(16);
    const auto class_ro_methods_offset = budget.pointer_bytes == 8 ? UINT64_C(32) : UINT64_C(20);
    const auto isa_slot = *row.class_address;
    const auto meta = pointer_at(image, resolver, isa_slot, budget);
    row.metaclass_address = meta.address;
    row.metaclass_pointer_status = meta.status;
    if (!meta.address) {
        add_incomplete(scan, row, "Objective-C class metaclass pointer is unresolved");
        return false;
    }
    if (!backed_readable(image, *meta.address, class_size)) {
        row.metaclass_pointer_status += "/class-uninitialized";
        add_incomplete(scan, row, "Objective-C metaclass object is outside initialized readable bytes");
        return false;
    }
    auto bytes = read_exact(image, *meta.address, static_cast<std::size_t>(class_size), budget);
    if (!bytes) {
        add_incomplete(scan, row, "Objective-C metaclass object could not be read");
        return false;
    }
    const auto data_slot = add(*meta.address, 4 * pointer_bytes);
    if (!data_slot) {
        add_incomplete(scan, row, "Objective-C metaclass data field address overflow");
        return false;
    }
    const auto data = pointer_at(image, resolver, *data_slot, budget);
    row.metaclass_ro_pointer_status = data.status;
    if (!data.address) {
        add_incomplete(scan, row, "Objective-C metaclass class_ro_t pointer is unresolved");
        return false;
    }
    const auto fast_data_mask = budget.pointer_bytes == 8 ? UINT64_C(7) : UINT64_C(3);
    const Address ro{data.address->space, data.address->offset & ~fast_data_mask};
    row.metaclass_ro_address = ro;
    if (!backed_readable(image, ro, class_ro_size)) {
        add_incomplete(scan, row, "Objective-C metaclass class_ro_t prefix is outside initialized readable bytes");
        return false;
    }
    auto ro_bytes = read_exact(image, ro, static_cast<std::size_t>(class_ro_size), budget);
    if (!ro_bytes) {
        add_incomplete(scan, row, "Objective-C metaclass class_ro_t prefix could not be read");
        return false;
    }
    if (read_integer(ro_bytes.value(), 0, 4) & 0xe0000000u) {
        row.metaclass_ro_pointer_status += "/runtime-class-data-unsupported";
        add_incomplete(scan, row, "Objective-C metaclass data describes an unsupported realized/future runtime object");
        return false;
    }
    row.metaclass_flags = static_cast<std::uint32_t>(read_integer(ro_bytes.value(), 0, 4));
    const auto name_slot = add(ro, class_ro_name_offset);
    const auto methods_slot = add(ro, class_ro_methods_offset);
    if (!name_slot || !methods_slot) {
        add_incomplete(scan, row, "Objective-C metaclass class_ro_t field address overflow");
        return false;
    }
    const auto name = pointer_at(image, resolver, *name_slot, budget);
    row.metaclass_name_status = name.status;
    if (name.address)
        row.metaclass_name = read_name(image, *name.address, budget, row.metaclass_name_status);
    if (!row.metaclass_name)
        add_incomplete(scan, row, "Objective-C metaclass name is unresolved");
    row.class_methods = parse_list(image, resolver, *methods_slot, 1, budget, scan, row.complete);
    return decode_list(image, resolver, row.class_methods, 1, budget, scan, row.complete);
}

} // namespace

std::vector<std::string> macho_objc_class_ro_flag_names(std::uint32_t flags) {
    // Values are the compiler-emitted class_ro_t flags in Apple's objc4
    // runtime header. Do not decode RW_* realization bits here.
    static constexpr std::pair<std::uint32_t, const char *> known[] = {
        {1u << 0, "metaclass"},
        {1u << 1, "root-class"},
        {1u << 2, "cxx-structors"},
        {1u << 4, "hidden"},
        {1u << 5, "objc-exception"},
        {1u << 6, "swift-initializer"},
        {1u << 7, "arc"},
        {1u << 8, "cxx-dtor-only"},
        {1u << 9, "weak-layout-without-arc"},
        {1u << 10, "forbids-associated-objects"},
    };
    std::vector<std::string> result;
    for (const auto &[mask, name] : known)
        if ((flags & mask) != 0) result.emplace_back(name);
    return result;
}

Result<MachOObjCScan> scan_macho_objc_classes(const Image &image, const ImageMetadata &metadata,
                                              const MachOObjCLimits &limits, std::stop_token stop) {
    try {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
    if (!metadata.macho) return Error{ErrorCode::invalid_argument, "Objective-C scan requires Mach-O metadata"};
    const auto &macho = *metadata.macho;
    if (macho.selected_slice >= macho.container.slices.size())
        return Error{ErrorCode::malformed, "Selected Mach-O slice is outside its container"};
    const auto &slice = macho.container.slices[macho.selected_slice];
    if (slice.header.order != ByteOrder::little)
        return Error{ErrorCode::unsupported, "Objective-C runtime scan supports little-endian Mach-O only"};
    constexpr std::uint32_t cpu_type_arm64_32 = 0x0200000cu;
    constexpr std::uint32_t abi64_32_flag = 0x02000000u;
    const bool arm64_32 = slice.header.cpu_type == cpu_type_arm64_32 && slice.header.is_64;
    if ((slice.header.cpu_type & abi64_32_flag) && !arm64_32)
        return Error{ErrorCode::unsupported, "Objective-C supports only the arm64_32 32-bit pointer ABI variant"};
    const std::uint8_t pointer_bytes = arm64_32 ? 4 : slice.header.is_64 ? 8 : 4;
    const bool address_domain_matches = arm64_32
        ? image.layout().space.width_bits == 64 &&
              (image.layout().architecture == Architecture::unknown ||
               (image.layout().architecture == Architecture::arm64 && image.layout().mode == ExecutionMode::a64))
        : image.layout().space.width_bits == pointer_bytes * 8;
    if (!address_domain_matches || image.layout().space.order != ByteOrder::little)
        return Error{ErrorCode::conflict, "Objective-C selected slice and mapped-image pointer width or byte order disagree"};
    if (!limits.max_classes || !limits.max_categories || !limits.max_protocols || !limits.max_metadata_bytes ||
        !limits.max_name_bytes || !limits.max_list_entries || !limits.max_protocol_inheritance_depth ||
        !limits.max_protocol_requirement_work)
        return Error{ErrorCode::invalid_argument, "Objective-C scan limits must be nonzero"};
    auto resolver = RelocationResolver::create(image, metadata, stop);
    if (!resolver) return resolver.error();

    MachOObjCScan scan;
    scan.pointer_bytes = pointer_bytes;
    Budget budget{limits, scan, stop, pointer_bytes, !slice.header.is_64 && slice.header.cpu_type == 12, arm64_32};
    std::vector<const MachOSection *> classlists;
    for (const auto &section : macho.sections)
        if (section.name == "__objc_classlist") classlists.push_back(&section);
        else if (pointer_bytes == 4 && section.segment_name == "__OBJC" && section.size) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Legacy Objective-C 1 __OBJC runtime records are unsupported";
        }

    std::map<MetadataAddressKey, std::size_t> classes_by_address;
    for (const auto *section : classlists) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
        if ((section->flags & 0xffu) != 0 || !section->file_offset || section->size % pointer_bytes != 0) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C class-list section is not a bounded regular file-backed array";
            continue;
        }
        const Address section_begin{image.layout().space.id, section->address};
        const auto mapped_file = image.to_file_offset(section_begin);
        if (!mapped_file || mapped_file.value() != *section->file_offset || !backed_readable(image, section_begin, section->size)) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C class-list section does not map to initialized readable image bytes";
            continue;
        }
        const auto count = section->size / pointer_bytes;
        const auto remaining = limits.max_classes - std::min(scan.classes.size(), limits.max_classes);
        if (count > remaining) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C class count exceeds configured limit";
        }
        const auto take_count = std::min<std::uint64_t>(count, remaining);
        for (std::uint64_t index = 0; index < take_count; ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
            if (scan.metadata_bytes >= limits.max_metadata_bytes) {
                scan.complete = false;
                if (scan.reason.empty()) scan.reason = "Objective-C metadata byte budget exhausted";
                break;
            }
            const auto slot = add(section_begin, index * pointer_bytes);
            if (!slot) {
                scan.complete = false;
                if (scan.reason.empty()) scan.reason = "Objective-C class-list address overflow";
                break;
            }
            MachOObjCClass row;
            row.classlist_section = section->ordinal;
            row.classlist_index = index;
            row.classlist_slot = *slot;
            row.origins.push_back({section->ordinal, index, *slot});
            const auto class_pointer = pointer_at(image, resolver.value(), *slot, budget);
            row.class_address = class_pointer.address;
            row.class_pointer_status = class_pointer.status;
            if (!class_pointer.address) {
                if (class_pointer.status != "null") add_incomplete(scan, row, "Objective-C class-list pointer is unresolved");
                scan.classes.push_back(std::move(row));
                continue;
            }
            if (const auto existing = classes_by_address.find(address_key(*class_pointer.address));
                existing != classes_by_address.end() && existing->second < scan.classes.size()) {
                scan.classes[existing->second].origins.push_back({section->ordinal, index, *slot});
                continue;
            }
            const auto class_size = static_cast<std::uint64_t>(5 * pointer_bytes);
            if (!backed_readable(image, *class_pointer.address, class_size)) {
                row.class_pointer_status += "/class-uninitialized";
                add_incomplete(scan, row, "Objective-C class object is outside initialized readable bytes");
                scan.classes.push_back(std::move(row));
                continue;
            }
            auto class_bytes = read_exact(image, *class_pointer.address, static_cast<std::size_t>(class_size), budget);
            if (!class_bytes) {
                if (class_bytes.error().code == ErrorCode::canceled) return class_bytes.error();
                add_incomplete(scan, row, "Objective-C class object could not be read");
                scan.classes.push_back(std::move(row));
                continue;
            }
            auto super_slot = add(*class_pointer.address, pointer_bytes);
            auto data_slot = add(*class_pointer.address, 4ull * pointer_bytes);
            if (!super_slot || !data_slot) {
                add_incomplete(scan, row, "Objective-C class field address overflow");
                scan.classes.push_back(std::move(row));
                continue;
            }
            const auto superclass = pointer_at(image, resolver.value(), *super_slot, budget);
            row.superclass_address = superclass.address;
            row.superclass_pointer_status = superclass.status;
            if (!superclass.address && superclass.status != "null")
                add_incomplete(scan, row, "Objective-C superclass pointer is unresolved");
            const auto data_pointer = pointer_at(image, resolver.value(), *data_slot, budget);
            row.class_ro_pointer_status = data_pointer.status;
            if (!data_pointer.address) {
                add_incomplete(scan, row, "Objective-C class_ro_t pointer is unresolved");
                scan.classes.push_back(std::move(row));
                continue;
            }
            // class_t.data is a fast-data pointer with low flag bits.
            const auto fast_data_mask = pointer_bytes == 8 ? UINT64_C(7) : UINT64_C(3);
            const Address ro_address{data_pointer.address->space, data_pointer.address->offset & ~fast_data_mask};
            row.class_ro_address = ro_address;
            const auto class_ro_size = pointer_bytes == 8 ? UINT64_C(72) : UINT64_C(40);
            if (!backed_readable(image, ro_address, class_ro_size)) {
                add_incomplete(scan, row, "Objective-C class_ro_t is outside initialized readable bytes");
                scan.classes.push_back(std::move(row));
                continue;
            }
            auto ro = read_exact(image, ro_address, static_cast<std::size_t>(class_ro_size), budget);
            if (!ro) {
                if (ro.error().code == ErrorCode::canceled) return ro.error();
                add_incomplete(scan, row, "Objective-C class_ro_t could not be read");
                scan.classes.push_back(std::move(row));
                continue;
            }
            if (read_integer(ro.value(), 0, 4) & 0xe0000000u) {
                row.class_ro_pointer_status += "/runtime-class-data-unsupported";
                add_incomplete(scan, row, "Objective-C class data describes an unsupported realized/future runtime object");
                scan.classes.push_back(std::move(row));
                continue;
            }
            row.flags = static_cast<std::uint32_t>(read_integer(ro.value(), 0, 4));
            row.instance_start = static_cast<std::uint32_t>(read_integer(ro.value(), 4, 4));
            row.instance_size = static_cast<std::uint32_t>(read_integer(ro.value(), 8, 4));
            if (*row.instance_start > *row.instance_size)
                add_incomplete(scan, row, "Objective-C class instance range is inconsistent");
            const auto name_slot = add(ro_address, pointer_bytes == 8 ? 24 : 16);
            const auto methods_slot = add(ro_address, pointer_bytes == 8 ? 32 : 20);
            const auto protocols_slot = add(ro_address, pointer_bytes == 8 ? 40 : 24);
            const auto ivars_slot = add(ro_address, pointer_bytes == 8 ? 48 : 28);
            const auto properties_slot = add(ro_address, pointer_bytes == 8 ? 64 : 36);
            if (!name_slot || !methods_slot || !protocols_slot || !ivars_slot || !properties_slot) {
                add_incomplete(scan, row, "Objective-C class_ro_t field address overflow");
                scan.classes.push_back(std::move(row));
                continue;
            }
            const auto name_pointer = pointer_at(image, resolver.value(), *name_slot, budget);
            if (name_pointer.address) {
                row.name = read_name(image, *name_pointer.address, budget, row.name_status);
                if (!row.name) add_incomplete(scan, row, "Objective-C class name could not be read");
            } else {
                row.name_status = name_pointer.status;
                add_incomplete(scan, row, name_pointer.status == "null"
                                        ? "Objective-C class name pointer is null"
                                        : "Objective-C class name pointer is unresolved");
            }
            row.methods = parse_list(image, resolver.value(), *methods_slot, 1, budget, scan, row.complete);
            row.protocols = parse_list(image, resolver.value(), *protocols_slot, 2, budget, scan, row.complete);
            row.ivars = parse_list(image, resolver.value(), *ivars_slot, 3, budget, scan, row.complete);
            row.properties = parse_list(image, resolver.value(), *properties_slot, 4, budget, scan, row.complete);
            if (!decode_list(image, resolver.value(), row.methods, 1, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.protocols, 2, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.ivars, 3, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.properties, 4, budget, scan, row.complete) ||
                !decode_metaclass(image, resolver.value(), row, budget, scan)) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
            }
            classes_by_address.try_emplace(address_key(*class_pointer.address), scan.classes.size());
            scan.classes.push_back(std::move(row));
        }
    }

    // Protocol definitions are independent runtime objects. Decode the stable
    // protocol_t prefix, then use its size field to guard optional tail fields.
    std::map<MetadataAddressKey, std::size_t> protocols_by_address;
    std::vector<const MachOSection *> protolists;
    for (const auto &section : macho.sections)
        if (section.name == "__objc_protolist") protolists.push_back(&section);
    for (const auto *section : protolists) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
        if ((section->flags & 0xffu) != 0 || !section->file_offset || section->size % pointer_bytes != 0) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C protocol-list section is not a bounded regular file-backed array";
            continue;
        }
        const Address section_begin{image.layout().space.id, section->address};
        const auto mapped_file = image.to_file_offset(section_begin);
        if (!mapped_file || mapped_file.value() != *section->file_offset ||
            !backed_readable(image, section_begin, section->size)) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C protocol-list section does not map to initialized readable image bytes";
            continue;
        }
        const auto count = section->size / pointer_bytes;
        const auto remaining = limits.max_protocols - std::min(scan.protocols.size(), limits.max_protocols);
        if (count > remaining) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C protocol count exceeds configured limit";
        }
        for (std::uint64_t index = 0; index < std::min<std::uint64_t>(count, remaining); ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
            const auto slot = add(section_begin, index * pointer_bytes);
            if (!slot) {
                scan.complete = false;
                if (scan.reason.empty()) scan.reason = "Objective-C protocol-list address overflow";
                break;
            }
            MachOObjCProtocol row;
            row.protolist_section = section->ordinal;
            row.protolist_index = index;
            row.protolist_slot = *slot;
            row.origins.push_back({section->ordinal, index, *slot});
            const auto protocol = pointer_at(image, resolver.value(), *slot, budget);
            row.address = protocol.address;
            row.pointer_status = protocol.status;
            if (!protocol.address) {
                if (protocol.status != "null") add_incomplete(scan, row, "Objective-C protocol-list pointer is unresolved");
                scan.protocols.push_back(std::move(row));
                continue;
            }
            if (const auto existing = protocols_by_address.find(address_key(*protocol.address));
                existing != protocols_by_address.end() && existing->second < scan.protocols.size()) {
                scan.protocols[existing->second].origins.push_back({section->ordinal, index, *slot});
                continue;
            }
            const auto protocol_prefix_size = static_cast<std::uint64_t>(8 * pointer_bytes);
            if (!backed_readable(image, *protocol.address, protocol_prefix_size)) {
                add_incomplete(scan, row, "Objective-C protocol_t prefix is outside initialized readable bytes");
                scan.protocols.push_back(std::move(row));
                continue;
            }
            auto prefix = read_exact(image, *protocol.address,
                                     static_cast<std::size_t>(protocol_prefix_size), budget);
            if (!prefix) {
                if (prefix.error().code == ErrorCode::canceled)
                    return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
                add_incomplete(scan, row, "Objective-C protocol_t prefix could not be read");
                scan.protocols.push_back(std::move(row));
                continue;
            }
            const auto name_slot = add(*protocol.address, pointer_bytes);
            const auto adopted_slot = add(*protocol.address, 2ull * pointer_bytes);
            const auto instance_slot = add(*protocol.address, 3ull * pointer_bytes);
            const auto class_slot = add(*protocol.address, 4ull * pointer_bytes);
            const auto optional_instance_slot = add(*protocol.address, 5ull * pointer_bytes);
            const auto optional_class_slot = add(*protocol.address, 6ull * pointer_bytes);
            const auto properties_slot = add(*protocol.address, 7ull * pointer_bytes);
            if (!name_slot || !adopted_slot || !instance_slot || !class_slot ||
                !optional_instance_slot || !optional_class_slot || !properties_slot) {
                add_incomplete(scan, row, "Objective-C protocol_t field address overflow");
                scan.protocols.push_back(std::move(row));
                continue;
            }
            row.name = direct_string_pointer(image, resolver.value(), *name_slot, budget, row.name_status);
            if (!row.name) add_incomplete(scan, row, "Objective-C protocol name is unresolved");
            row.adopted_protocols = parse_list(image, resolver.value(), *adopted_slot, 2, budget, scan, row.complete);
            row.required_instance_methods = parse_list(image, resolver.value(), *instance_slot, 1, budget, scan, row.complete);
            row.required_class_methods = parse_list(image, resolver.value(), *class_slot, 1, budget, scan, row.complete);
            row.optional_instance_methods = parse_list(image, resolver.value(), *optional_instance_slot, 1, budget, scan, row.complete);
            row.optional_class_methods = parse_list(image, resolver.value(), *optional_class_slot, 1, budget, scan, row.complete);
            row.instance_properties = parse_list(image, resolver.value(), *properties_slot, 4, budget, scan, row.complete);
            const auto size_flags_slot = add(*protocol.address, 8ull * pointer_bytes);
            if (size_flags_slot && backed_readable(image, *size_flags_slot, 8)) {
                auto size_flags = read_exact(image, *size_flags_slot, 8, budget);
                if (!size_flags) {
                    if (size_flags.error().code == ErrorCode::canceled)
                        return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
                } else {
                    const auto runtime_size = static_cast<std::uint32_t>(read_integer(size_flags.value(), 0, 4));
                    const auto minimum_size = 8ull * pointer_bytes + 8;
                    if (runtime_size >= minimum_size && backed_readable(image, *protocol.address, runtime_size)) {
                        row.runtime_size = runtime_size;
                        const auto class_properties_offset = minimum_size + 2ull * pointer_bytes;
                        const auto class_properties_end = class_properties_offset + pointer_bytes;
                        if (runtime_size >= class_properties_end) {
                            const auto class_properties_slot = add(*protocol.address, class_properties_offset);
                            if (class_properties_slot) {
                                row.class_properties = parse_list(image, resolver.value(), *class_properties_slot,
                                    4, budget, scan, row.complete);
                                row.class_properties_status = row.class_properties.pointer_status;
                            }
                        } else {
                            row.class_properties_status = "not-present-by-runtime-size";
                        }
                    }
                }
            }
            if (!decode_list(image, resolver.value(), row.adopted_protocols, 2, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.required_instance_methods, 1, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.required_class_methods, 1, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.optional_instance_methods, 1, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.optional_class_methods, 1, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.instance_properties, 4, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.class_properties, 4, budget, scan, row.complete)) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
            }
            protocols_by_address.try_emplace(address_key(*protocol.address), scan.protocols.size());
            scan.protocols.push_back(std::move(row));
        }
    }

    // Categories are separate nodes that attach method/property/protocol
    // lists to a class. Only the six pointer fields present in the on-disk
    // category_t prefix are read; newer optional tail fields are not guessed.
    std::map<MetadataAddressKey, std::size_t> categories_by_address;
    std::vector<const MachOSection *> categorylists;
    for (const auto &section : macho.sections)
        if (section.name == "__objc_catlist" || section.name == "__objc_nlcatlist") categorylists.push_back(&section);
    for (const auto *section : categorylists) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
        if ((section->flags & 0xffu) != 0 || !section->file_offset || section->size % pointer_bytes != 0) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C category-list section is not a bounded regular file-backed array";
            continue;
        }
        const Address section_begin{image.layout().space.id, section->address};
        const auto mapped_file = image.to_file_offset(section_begin);
        if (!mapped_file || mapped_file.value() != *section->file_offset ||
            !backed_readable(image, section_begin, section->size)) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C category-list section does not map to initialized readable image bytes";
            continue;
        }
        const auto count = section->size / pointer_bytes;
        const auto remaining = limits.max_categories - std::min(scan.categories.size(), limits.max_categories);
        if (count > remaining) {
            scan.complete = false;
            if (scan.reason.empty()) scan.reason = "Objective-C category count exceeds configured limit";
        }
        const auto take_count = std::min<std::uint64_t>(count, remaining);
        for (std::uint64_t index = 0; index < take_count; ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
            const auto slot = add(section_begin, index * pointer_bytes);
            if (!slot) {
                scan.complete = false;
                if (scan.reason.empty()) scan.reason = "Objective-C category-list address overflow";
                break;
            }
            MachOObjCCategory row;
            row.categorylist_section = section->ordinal;
            row.categorylist_index = index;
            row.categorylist_slot = *slot;
            row.origins.push_back({section->ordinal, index, *slot});
            const auto category = pointer_at(image, resolver.value(), *slot, budget);
            row.address = category.address;
            row.pointer_status = category.status;
            if (!category.address) {
                if (category.status != "null") add_incomplete(scan, row, "Objective-C category pointer is unresolved");
                scan.categories.push_back(std::move(row));
                continue;
            }
            if (const auto existing = categories_by_address.find(address_key(*category.address));
                existing != categories_by_address.end() && existing->second < scan.categories.size()) {
                scan.categories[existing->second].origins.push_back({section->ordinal, index, *slot});
                continue;
            }
            const auto category_prefix_size = static_cast<std::uint64_t>(6 * pointer_bytes);
            if (!backed_readable(image, *category.address, category_prefix_size)) {
                add_incomplete(scan, row, "Objective-C category_t prefix is outside initialized readable bytes");
                scan.categories.push_back(std::move(row));
                continue;
            }
            auto fields = read_exact(image, *category.address,
                                     static_cast<std::size_t>(category_prefix_size), budget);
            if (!fields) {
                if (fields.error().code == ErrorCode::canceled) return fields.error();
                add_incomplete(scan, row, "Objective-C category_t prefix could not be read");
                scan.categories.push_back(std::move(row));
                continue;
            }
            const auto name_slot = *category.address;
            const auto class_slot = add(*category.address, pointer_bytes);
            const auto instance_methods_slot = add(*category.address, 2ull * pointer_bytes);
            const auto class_methods_slot = add(*category.address, 3ull * pointer_bytes);
            const auto protocols_slot = add(*category.address, 4ull * pointer_bytes);
            const auto properties_slot = add(*category.address, 5ull * pointer_bytes);
            if (!class_slot || !instance_methods_slot || !class_methods_slot || !protocols_slot || !properties_slot) {
                add_incomplete(scan, row, "Objective-C category_t field address overflow");
                scan.categories.push_back(std::move(row));
                continue;
            }
            row.name = direct_string_pointer(image, resolver.value(), name_slot, budget, row.name_status);
            const auto target_class = pointer_at(image, resolver.value(), *class_slot, budget);
            row.target_class = target_class.address;
            row.target_class_status = target_class.status;
            if (!row.name || (!row.target_class && target_class.status != "null"))
                add_incomplete(scan, row, "Objective-C category name or target class is unresolved");
            row.instance_methods = parse_list(image, resolver.value(), *instance_methods_slot, 1, budget, scan, row.complete);
            row.class_methods = parse_list(image, resolver.value(), *class_methods_slot, 1, budget, scan, row.complete);
            row.protocols = parse_list(image, resolver.value(), *protocols_slot, 2, budget, scan, row.complete);
            row.instance_properties = parse_list(image, resolver.value(), *properties_slot, 4, budget, scan, row.complete);
            if (!decode_list(image, resolver.value(), row.instance_methods, 1, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.class_methods, 1, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.protocols, 2, budget, scan, row.complete) ||
                !decode_list(image, resolver.value(), row.instance_properties, 4, budget, scan, row.complete)) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
            }
            // category_t gained a trailing classProperties pointer in newer
            // runtimes. Older records have only six fields, so treat the tail
            // as optional and recognize it only when it points to a complete,
            // structurally plausible property list.
            const auto class_properties_slot = add(*category.address, 6ull * pointer_bytes);
            if (!class_properties_slot || !backed_readable(image, *category.address, 7ull * pointer_bytes)) {
                row.class_properties_status = "not-present-by-bounds";
            } else {
                row.class_properties.pointer_slot = *class_properties_slot;
                const auto candidate = pointer_at(image, resolver.value(), *class_properties_slot, budget);
                row.class_properties.pointer_status = candidate.status;
                if (!candidate.address) {
                    row.class_properties_status = candidate.status == "null" ? "not-present" :
                        candidate.status == "budget" || candidate.status == "canceled" ? candidate.status :
                        "unresolved-optional-tail";
                    if (candidate.status == "budget")
                        add_incomplete(scan, row, "Objective-C optional category class-property scan exceeded its byte budget");
                    if (candidate.status == "canceled")
                        return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
                } else if ((candidate.address->offset % 4) == 0 &&
                           backed_readable(image, *candidate.address, 8)) {
                    const auto header = read_exact(image, *candidate.address, 8, budget);
                    if (!header) {
                        if (header.error().code == ErrorCode::canceled) return header.error();
                        row.class_properties_status = "optional-tail-header-unreadable";
                        if (header.error().code == ErrorCode::resource_limit)
                            add_incomplete(scan, row, "Objective-C optional category class-property scan exceeded its byte budget");
                    } else {
                        const auto stride = read_integer(header.value(), 0, 4);
                        const auto count = read_integer(header.value(), 4, 4);
                        const auto minimum_stride = 2ull * pointer_bytes;
                        const bool bounded = stride >= minimum_stride && stride <= 4096 &&
                            stride % pointer_bytes == 0 && count <= limits.max_list_entries &&
                            count <= (UINT64_MAX - 8) / stride;
                        const auto extent = bounded ? 8 + count * stride : 0;
                        if (bounded && backed_readable(image, *candidate.address, extent)) {
                            row.class_properties = parse_list(image, resolver.value(), *class_properties_slot,
                                                              4, budget, scan, row.complete);
                            row.class_properties_status = row.class_properties.status;
                            if (!decode_list(image, resolver.value(), row.class_properties, 4,
                                             budget, scan, row.complete) && stop.stop_requested())
                                return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
                        } else row.class_properties_status = "not-property-list-or-legacy-tail";
                    }
                } else row.class_properties_status = "not-property-list-or-legacy-tail";
            }
            categories_by_address.try_emplace(address_key(*category.address), scan.categories.size());
            scan.categories.push_back(std::move(row));
        }
    }

    std::map<MetadataAddressKey, std::string> class_names_by_address;
    std::map<MetadataAddressKey, std::size_t> class_indices_by_address;
    for (std::size_t i = 0; i < scan.classes.size(); ++i) {
        const auto &row = scan.classes[i];
        if (!row.class_address) continue;
        class_indices_by_address.try_emplace(address_key(*row.class_address), i);
        if (row.name) class_names_by_address.try_emplace(address_key(*row.class_address), *row.name);
    }
    std::map<MetadataAddressKey, std::size_t> protocol_indices_by_address;
    std::map<MetadataAddressKey, std::string> protocol_names_by_address;
    for (std::size_t i = 0; i < scan.protocols.size(); ++i) {
        const auto &row = scan.protocols[i];
        if (!row.address) continue;
        protocol_indices_by_address.try_emplace(address_key(*row.address), i);
        if (row.name) protocol_names_by_address.try_emplace(address_key(*row.address), *row.name);
    }
    const auto link_protocols = [&](MachOObjCList &list) {
        for (auto &reference : list.protocol_references) {
            if (!reference.address) continue;
            if (const auto found = protocol_indices_by_address.find(address_key(*reference.address));
                found != protocol_indices_by_address.end()) {
                reference.definition_index = found->second;
                if (!reference.name) {
                    if (const auto named = protocol_names_by_address.find(address_key(*reference.address));
                        named != protocol_names_by_address.end()) {
                        reference.name = named->second;
                        reference.name_status = "resolved-from-protocol-definition";
                    }
                }
            }
        }
    };
    for (auto &row : scan.classes) link_protocols(row.protocols);
    for (std::size_t category_index = 0; category_index < scan.categories.size(); ++category_index) {
        auto &row = scan.categories[category_index];
        if (row.target_class) {
            const auto found = class_names_by_address.find(address_key(*row.target_class));
            if (found != class_names_by_address.end()) row.target_class_name = found->second;
            if (const auto indexed = class_indices_by_address.find(address_key(*row.target_class));
                indexed != class_indices_by_address.end()) {
                row.target_class_index = indexed->second;
                row.target_class_link_status = "resolved";
                scan.classes[indexed->second].category_indices.push_back(category_index);
            } else {
                row.target_class_link_status = "target-class-not-scanned";
            }
        } else {
            row.target_class_link_status = row.target_class_status;
        }
    }
    for (auto &row : scan.categories) link_protocols(row.protocols);
    for (auto &row : scan.protocols) link_protocols(row.adopted_protocols);
    // Check required methods for protocols directly adopted by each class,
    // including those protocols' bounded adopted-protocol contracts. Only
    // selectors in validated method lists count; superclass methods and
    // categories outside the scanned image are not guessed.
    const auto complete_method_list = [](const MachOObjCList &list) {
        return (list.status == "null" || list.status.ends_with("/extent-validated")) &&
            std::all_of(list.methods.begin(), list.methods.end(),
                [](const MachOObjCMethod &method) {
                    return method.selector.has_value() && method.implementation.has_value();
                });
    };
    const auto complete_protocol_method_list = [](const MachOObjCList &list) {
        return (list.status == "null" || list.status.ends_with("/extent-validated")) &&
            std::all_of(list.methods.begin(), list.methods.end(),
                [](const MachOObjCMethod &method) { return method.selector.has_value(); });
    };
    struct ProtocolContract {
        std::vector<MachOObjCProtocolRequirementResult> requirements;
        bool complete = false;
    };
    std::vector<std::optional<ProtocolContract>> protocol_contracts(scan.protocols.size());
    std::vector<std::uint8_t> protocol_contract_state(scan.protocols.size(), 0);
    std::size_t protocol_contract_work = 0;
    std::function<ProtocolContract(std::size_t, std::size_t)> collect_protocol_contract;
    collect_protocol_contract = [&](std::size_t index, std::size_t depth) -> ProtocolContract {
        if (index >= scan.protocols.size() || depth > limits.max_protocol_inheritance_depth)
            return {};
        if (protocol_contracts[index]) return *protocol_contracts[index];
        if (protocol_contract_state[index] == 1) return {}; // adoption cycle
        protocol_contract_state[index] = 1;
        const auto &protocol = scan.protocols[index];
        ProtocolContract contract;
        contract.complete = protocol.complete &&
            complete_protocol_method_list(protocol.required_instance_methods) &&
            complete_protocol_method_list(protocol.required_class_methods) &&
            (protocol.adopted_protocols.status == "null" ||
             protocol.adopted_protocols.status.ends_with("/extent-validated"));
        const auto append_required = [&](const MachOObjCList &list, bool class_method) {
            for (const auto &method : list.methods) {
                if (!method.selector) {
                    contract.complete = false;
                    continue;
                }
                if (protocol_contract_work >= limits.max_protocol_requirement_work) {
                    contract.complete = false;
                    continue;
                }
                MachOObjCProtocolRequirementResult requirement;
                requirement.selector = *method.selector;
                requirement.class_method = class_method;
                requirement.declaring_protocol_index = index;
                contract.requirements.push_back(std::move(requirement));
                ++protocol_contract_work;
            }
        };
        append_required(protocol.required_instance_methods, false);
        append_required(protocol.required_class_methods, true);
        for (const auto &adopted : protocol.adopted_protocols.protocol_references) {
            if (!adopted.definition_index || *adopted.definition_index >= scan.protocols.size()) {
                contract.complete = false;
                continue;
            }
            auto inherited = collect_protocol_contract(*adopted.definition_index, depth + 1);
            contract.complete = contract.complete && inherited.complete;
            for (auto &requirement : inherited.requirements) {
                if (protocol_contract_work >= limits.max_protocol_requirement_work) {
                    contract.complete = false;
                    break;
                }
                contract.requirements.push_back(std::move(requirement));
                ++protocol_contract_work;
            }
        }
        protocol_contract_state[index] = 2;
        protocol_contracts[index] = contract;
        return contract;
    };
    using SelectorIndex = std::map<std::string, std::vector<std::optional<Address>>, std::less<>>;
    const auto add_method_candidates = [](SelectorIndex &index, const MachOObjCList &methods) {
        for (const auto &method : methods.methods) {
            if (method.selector)
                index[*method.selector].push_back(method.implementation);
        }
    };
    std::size_t emitted_protocol_requirement_work = 0;
    const auto check_protocol_requirements = [&](MachOObjCProtocolReference &reference,
        const ProtocolContract &contract,
        const SelectorIndex &instance_methods, const SelectorIndex &class_methods,
        bool fully_checked) {
        fully_checked = fully_checked && contract.complete;
        for (const auto &declared : contract.requirements) {
            if (emitted_protocol_requirement_work >= limits.max_protocol_requirement_work) {
                fully_checked = false;
                break;
            }
            auto result = declared;
            const auto &index = result.class_method ? class_methods : instance_methods;
            const auto found = index.find(result.selector);
            if (found != index.end() && found->second.size() > 1)
                result.status = "ambiguous-implementation";
            else if (found != index.end() && !found->second.empty()) {
                if (found->second.front()) {
                    result.implementation = *found->second.front();
                    result.status = "implemented";
                } else result.status = "implementation-unresolved";
            } else result.status = fully_checked ? "missing-in-scanned-image" : "unverified-incomplete-method-lists";
            reference.requirements.push_back(std::move(result));
            ++emitted_protocol_requirement_work;
        }
        if (reference.requirements.empty() && fully_checked) reference.conformance_status = "no-required-methods";
        else if (!fully_checked) reference.conformance_status = "partial-method-evidence";
        else if (std::all_of(reference.requirements.begin(), reference.requirements.end(),
                     [](const auto &requirement) { return requirement.status == "implemented"; }))
            reference.conformance_status = "required-methods-present-in-scanned-image";
        else if (std::any_of(reference.requirements.begin(), reference.requirements.end(),
                     [](const auto &requirement) { return requirement.status == "ambiguous-implementation"; }))
            reference.conformance_status = "ambiguous-method-evidence";
        else reference.conformance_status = "required-methods-missing-from-scanned-image";
    };
    for (auto &owner : scan.classes) {
        SelectorIndex instance_methods, class_methods;
        bool fully_checked = scan.complete && complete_method_list(owner.methods) &&
            complete_method_list(owner.class_methods);
        add_method_candidates(instance_methods, owner.methods);
        add_method_candidates(class_methods, owner.class_methods);
        for (const auto index : owner.category_indices) {
            if (index >= scan.categories.size()) { fully_checked = false; continue; }
            const auto &category = scan.categories[index];
            fully_checked = fully_checked && complete_method_list(category.instance_methods) &&
                complete_method_list(category.class_methods);
            add_method_candidates(instance_methods, category.instance_methods);
            add_method_candidates(class_methods, category.class_methods);
        }
        for (auto &reference : owner.protocols.protocol_references) {
            reference.requirements.clear();
            reference.conformance_status = "protocol-definition-unavailable";
            if (!reference.definition_index || *reference.definition_index >= scan.protocols.size()) continue;
            const auto contract = collect_protocol_contract(*reference.definition_index, 1);
            check_protocol_requirements(reference, contract,
                instance_methods, class_methods, fully_checked);
        }
    }
    const auto link_backing_ivars = [](MachOObjCList &properties, const MachOObjCClass *owner) {
        for (auto &property : properties.properties) {
            property.backing_ivar_index.reset();
            property.backing_ivar_link_status = property.backing_ivar ? "owner-class-not-scanned" : "not-declared";
            if (!property.backing_ivar || !owner) continue;
            std::optional<std::size_t> match;
            bool ambiguous = false;
            for (std::size_t index = 0; index < owner->ivars.ivars.size(); ++index) {
                const auto &ivar = owner->ivars.ivars[index];
                if (ivar.name && *ivar.name == *property.backing_ivar) {
                    if (match) { ambiguous = true; break; }
                    match = index;
                }
            }
            if (ambiguous) {
                property.backing_ivar_link_status = "ambiguous-ivar-name";
            } else if (match) {
                property.backing_ivar_index = *match;
                property.backing_ivar_link_status = "resolved";
            } else if (owner->ivars.status == "null" ||
                       owner->ivars.status.find("extent-validated") != std::string::npos) {
                property.backing_ivar_link_status = "ivar-not-found";
            } else {
                property.backing_ivar_link_status = "ivar-list-incomplete";
            }
        }
    };
    const auto link_accessors = [&scan](std::vector<MachOObjCProperty> &properties, const MachOObjCList &methods) {
        const auto complete_method_list = (methods.status == "null" ||
            methods.status.ends_with("/extent-validated")) &&
            std::all_of(methods.methods.begin(), methods.methods.end(),
                [](const auto &method) { return method.selector.has_value(); });
        std::size_t accessor_method_comparisons = 0;
        constexpr std::size_t max_accessor_method_comparisons = 200000;
        bool accessor_method_comparison_budget_exhausted = false;
        const auto same_type = [](const types::TypePtr &left, const types::TypePtr &right) {
            if (!left || !right) return false;
            const auto left_encoding = types::encode(*left);
            const auto right_encoding = types::encode(*right);
            return left_encoding && right_encoding && left_encoding.value() == right_encoding.value();
        };
        const auto find_method = [&](std::string_view selector, const MachOObjCProperty &property,
                                     bool setter, std::optional<Address> &address) {
            if (accessor_method_comparison_budget_exhausted)
                return std::string("accessor-signature-budget");
            const MachOObjCMethod *match = nullptr;
            for (const auto &method : methods.methods) {
                if (accessor_method_comparisons == max_accessor_method_comparisons) {
                    accessor_method_comparison_budget_exhausted = true;
                    scan.complete = false;
                    if (scan.reason.empty())
                        scan.reason = "Objective-C property accessor selector comparison budget exhausted";
                    return std::string("accessor-signature-budget");
                }
                ++accessor_method_comparisons;
                if (!method.selector || *method.selector != selector) continue;
                if (match) return std::string("ambiguous-selector");
                match = &method;
            }
            if (match && !complete_method_list) return std::string("method-list-incomplete");
            if (match) {
                if (!property.type || !match->signature || match->signature->kind() != types::Kind::function)
                    return std::string("accessor-signature-unavailable");
                const auto &signature = *match->signature;
                if ((!setter && signature.parameters().size() != 2) ||
                    (setter && signature.parameters().size() != 3))
                    return std::string("accessor-signature-arity-mismatch");
                if (setter) {
                    if (signature.result_type()->kind() != types::Kind::void_type ||
                        !same_type(signature.parameters()[2].type, property.type))
                        return std::string("accessor-signature-type-mismatch");
                } else if (!same_type(signature.result_type(), property.type)) {
                    return std::string("accessor-signature-type-mismatch");
                }
                address = match->entry;
                return std::string("resolved");
            }
            return complete_method_list ? std::string("method-not-found") : std::string("method-list-incomplete");
        };
        for (auto &property : properties) {
            property.getter_method.reset();
            property.setter_method.reset();
            if (property.attribute_semantics_status != "parsed" &&
                property.attribute_semantics_status != "parsed-with-unknown-attributes") {
                property.getter_link_status = "property-attributes-unavailable";
                property.setter_link_status = "property-attributes-unavailable";
                continue;
            }
            if (!property.name || property.name->empty()) {
                property.getter_link_status = "property-name-unavailable";
                property.setter_link_status = property.readonly ? "not-applicable-readonly" : "property-name-unavailable";
                continue;
            }
            const auto selector = property.custom_getter.value_or(*property.name);
            property.getter_link_status = find_method(selector, property, false, property.getter_method);
            if (property.readonly) {
                property.setter_link_status = "not-applicable-readonly";
            } else {
                std::string setter;
                if (property.custom_setter) {
                    setter = *property.custom_setter;
                } else {
                    const auto first = static_cast<unsigned char>(property.name->front());
                    if (first >= 'a' && first <= 'z') {
                        setter = "set";
                        setter.push_back(static_cast<char>(first - 'a' + 'A'));
                        setter.append(property.name->substr(1));
                        setter.push_back(':');
                    } else if ((first >= 'A' && first <= 'Z') || first == '_') {
                        setter = "set" + *property.name + ":";
                    } else {
                        property.setter_link_status = "default-setter-name-unsupported";
                        continue;
                    }
                }
                property.setter_link_status = find_method(setter, property, true, property.setter_method);
            }
        }
    };
    for (auto &row : scan.classes)
        link_accessors(row.properties.properties, row.methods);
    for (auto &row : scan.categories) {
        link_accessors(row.instance_properties.properties, row.instance_methods);
        link_accessors(row.class_properties.properties, row.class_methods);
    }
    for (auto &row : scan.classes) link_backing_ivars(row.properties, &row);
    for (auto &row : scan.categories) {
        const auto *owner = row.target_class_index && *row.target_class_index < scan.classes.size()
            ? &scan.classes[*row.target_class_index] : nullptr;
        link_backing_ivars(row.instance_properties, owner);
    }
    for (auto &row : scan.classes) {
        if (row.superclass_address) {
            const auto found = class_indices_by_address.find(address_key(*row.superclass_address));
            if (found != class_indices_by_address.end()) {
                row.superclass_index = found->second;
                row.superclass_name = scan.classes[found->second].name;
                row.superclass_link_status = "resolved";
            } else {
                row.superclass_link_status = "target-class-not-scanned";
            }
        } else if (row.superclass_pointer_status == "null") {
            row.superclass_link_status = "root-class";
        } else {
            row.superclass_link_status = row.superclass_pointer_status;
        }
    }

    // The direct superclass links form a functional graph. Detect malformed
    // cycles iteratively so adversarial class counts cannot exhaust the C++
    // call stack; every link outside the cycle remains individually useful.
    std::vector<std::uint8_t> hierarchy_state(scan.classes.size(), 0);
    constexpr auto no_path_position = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> path_position(scan.classes.size(), no_path_position);
    for (std::size_t start = 0; start < scan.classes.size(); ++start) {
        if (hierarchy_state[start] != 0) continue;
        std::vector<std::size_t> path;
        auto current = start;
        while (current < scan.classes.size() && hierarchy_state[current] == 0) {
            hierarchy_state[current] = 1;
            path_position[current] = path.size();
            path.push_back(current);
            const auto next = scan.classes[current].superclass_index;
            if (!next || *next >= scan.classes.size()) {
                current = scan.classes.size();
                break;
            }
            current = *next;
        }
        if (current < scan.classes.size() && hierarchy_state[current] == 1 &&
            path_position[current] != no_path_position) {
            for (std::size_t i = path_position[current]; i < path.size(); ++i) {
                auto &row = scan.classes[path[i]];
                row.superclass_link_status = "cycle";
            }
            scan.complete = false;
            if (scan.reason.empty())
                scan.reason = "Objective-C superclass metadata contains a cycle";
        }
        for (const auto index : path) {
            hierarchy_state[index] = 2;
            path_position[index] = no_path_position;
        }
    }
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Objective-C metadata scan canceled"};
    return scan;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Objective-C metadata scan"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Objective-C metadata allocation limit"};
    }
}

} // namespace hexlab
