#include "hexlab/loaders/macho.hpp"
#include <limits>
#include <map>
#include <new>
#include <string_view>

namespace hexlab {
namespace {
struct ImportCandidate {
    std::uint64_t address = 0;
    bool ambiguous = false;
};

bool add_signed(std::uint64_t base, std::int64_t addend, std::uint64_t &result) {
    if (addend >= 0) {
        const auto amount = static_cast<std::uint64_t>(addend);
        if (base > UINT64_MAX - amount) return false;
        result = base + amount;
        return true;
    }
    const auto amount = static_cast<std::uint64_t>(-(addend + 1)) + 1;
    if (base < amount) return false;
    result = base - amount;
    return true;
}

std::optional<std::uint32_t> pcrel32(std::uint64_t target, std::uint64_t place) {
    if (target >= place) {
        const auto distance = target - place;
        if (distance > static_cast<std::uint64_t>(INT32_MAX)) return {};
        return static_cast<std::uint32_t>(distance);
    }
    const auto distance = place - target;
    if (distance > (UINT64_C(1) << 31)) return {};
    const auto signed_distance = -static_cast<std::int64_t>(distance);
    return static_cast<std::uint32_t>(static_cast<std::int32_t>(signed_distance));
}
}

Result<std::vector<MachODyldBindTarget>> resolve_macho_dyld_binds(
    const MachOMetadata &metadata, std::span<const MachODyldImportAddress> imports,
    std::uint64_t image_slide, std::stop_token stop, MachODyldBindResolutionLimits limits) try {
    constexpr std::size_t hard_row_limit = 1'000'000;
    constexpr std::uint64_t hard_symbol_limit = 16 * 1024 * 1024;
    constexpr std::uint64_t hard_result_limit = 64 * 1024 * 1024;
    if (!limits.max_fixups || limits.max_fixups > hard_row_limit ||
        !limits.max_imports || limits.max_imports > hard_row_limit ||
        !limits.max_symbol_bytes || limits.max_symbol_bytes > hard_symbol_limit ||
        !limits.max_result_bytes || limits.max_result_bytes > hard_result_limit)
        return Error{ErrorCode::invalid_argument, "Invalid Mach-O classic bind resolution limits"};
    if (metadata.dyld_fixups.size() > limits.max_fixups || imports.size() > limits.max_imports)
        return Error{ErrorCode::resource_limit, "Mach-O classic bind resolution exceeds its row limit"};
    if (metadata.selected_slice >= metadata.container.slices.size())
        return Error{ErrorCode::invalid_argument, "Mach-O classic bind metadata has no selected slice"};

    using ImportKey = std::pair<std::int32_t, std::string_view>;
    std::map<ImportKey, ImportCandidate> candidates;
    std::uint64_t candidate_symbol_bytes = 0;
    for (const auto &import : imports) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O classic bind resolution canceled"};
        if (import.symbol.empty() || import.symbol.size() > 64 * 1024 ||
            import.symbol.size() > limits.max_symbol_bytes - std::min(limits.max_symbol_bytes, candidate_symbol_bytes))
            return Error{ErrorCode::resource_limit, "Mach-O classic bind import names exceed their configured limit"};
        candidate_symbol_bytes += import.symbol.size();
        const ImportKey key{import.library_ordinal, import.symbol};
        const auto [entry, inserted] = candidates.emplace(key, ImportCandidate{import.address, false});
        if (!inserted && entry->second.address != import.address) entry->second.ambiguous = true;
    }

    const auto &slice = metadata.container.slices[metadata.selected_slice];
    const auto pointer_size = static_cast<std::uint8_t>(slice.header.is_64 ? 8 : 4);
    std::vector<MachODyldBindTarget> output;
    std::uint64_t result_bytes = 0;
    for (std::size_t index = 0; index < metadata.dyld_fixups.size(); ++index) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O classic bind resolution canceled"};
        const auto &fixup = metadata.dyld_fixups[index];
        if (fixup.stream >= metadata.dyld_streams.size()) continue;
        const auto &stream = metadata.dyld_streams[fixup.stream];
        if (stream.kind != MachODyldStreamKind::bind && stream.kind != MachODyldStreamKind::lazy_bind)
            continue;
        if (result_bytes > limits.max_result_bytes || sizeof(MachODyldBindTarget) > limits.max_result_bytes - result_bytes)
            return Error{ErrorCode::resource_limit, "Mach-O classic bind result rows exceed their memory budget"};

        MachODyldBindTarget row;
        row.fixup_index = index;
        row.stream = fixup.stream;
        row.operation = fixup.operation;
        row.repeat_index = fixup.repeat_index;
        row.record_file_offset = fixup.record_file_offset;
        row.type = fixup.type;
        row.field_size = fixup.field_size;
        row.symbol_flags = fixup.symbol_flags;
        row.addend = fixup.addend;
        row.place = fixup.place;
        row.file_place = fixup.file_place;
        row.weak_import = (fixup.symbol_flags & 0x1u) != 0;
        if (fixup.library_ordinal) row.library_ordinal = *fixup.library_ordinal;
        if (fixup.symbol.size() <= 64 * 1024) row.symbol = fixup.symbol;

        const bool type_valid = (fixup.type == 1 && fixup.field_size == pointer_size) ||
            ((fixup.type == 2 || fixup.type == 3) && fixup.field_size == 4);
        const bool operation_valid = fixup.operation < metadata.dyld_operations.size() &&
            metadata.dyld_operations[fixup.operation].stream == fixup.stream &&
            (metadata.dyld_operations[fixup.operation].byte & 0xf0u) >= 0x90u &&
            (metadata.dyld_operations[fixup.operation].byte & 0xf0u) <= 0xc0u;
        if (!stream.complete || !fixup.place || !fixup.library_ordinal || fixup.symbol.empty() ||
            fixup.symbol.size() > 64 * 1024 || !type_valid || !operation_valid) {
            row.status = fixup.type < 1 || fixup.type > 3 || !type_valid
                ? MachODyldBindStatus::unsupported_type : MachODyldBindStatus::invalid_encoding;
        } else {
            const auto found = candidates.find({row.library_ordinal, row.symbol});
            if (found == candidates.end()) {
                row.status = MachODyldBindStatus::missing_import;
            } else if (found->second.ambiguous) {
                row.status = MachODyldBindStatus::ambiguous_import;
            } else {
                row.import_address = found->second.address;
                std::uint64_t target = 0;
                if (!add_signed(*row.import_address, row.addend, target)) {
                    row.status = MachODyldBindStatus::overflow;
                } else if (fixup.type == 1) {
                    if (pointer_size == 4 && target > UINT32_MAX)
                        row.status = MachODyldBindStatus::overflow;
                    else {
                        row.target_address = target;
                        row.value_to_write = target;
                        row.status = MachODyldBindStatus::resolved;
                    }
                } else if (fixup.type == 2) {
                    if (target > UINT32_MAX)
                        row.status = MachODyldBindStatus::overflow;
                    else {
                        row.target_address = target;
                        row.value_to_write = target;
                        row.status = MachODyldBindStatus::resolved;
                    }
                } else if (image_slide > UINT64_MAX - fixup.place->offset) {
                    row.status = MachODyldBindStatus::overflow;
                } else {
                    const auto place = fixup.place->offset + image_slide;
                    const auto displacement = pcrel32(target, place);
                    if (!displacement) row.status = MachODyldBindStatus::overflow;
                    else {
                        row.target_address = target;
                        row.value_to_write = *displacement;
                        row.status = MachODyldBindStatus::resolved;
                    }
                }
            }
        }
        if (row.symbol.size() > limits.max_result_bytes - std::min(limits.max_result_bytes, result_bytes) ||
            sizeof(MachODyldBindTarget) > limits.max_result_bytes - std::min(limits.max_result_bytes, result_bytes + row.symbol.size()))
            return Error{ErrorCode::resource_limit, "Mach-O classic bind result symbols exceed their memory budget"};
        result_bytes += sizeof(MachODyldBindTarget) + row.symbol.size();
        output.push_back(std::move(row));
    }
    return output;
} catch (const std::bad_alloc &) {
    return Error{ErrorCode::resource_limit, "Cannot allocate Mach-O classic bind resolution rows"};
}
} // namespace hexlab
