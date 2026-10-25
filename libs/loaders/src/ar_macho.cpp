#include "hexlab/loaders/ar.hpp"
#include "hexlab/loaders/macho.hpp"
#include <algorithm>
#include <unordered_set>

namespace hexlab {
Result<ArMemberSymbols> summarize_macho_ar_member(const ByteStorage &storage, std::size_t member_index,
                                                 std::stop_token stop, ArObjectLimits limits) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O archive member scan canceled"};
    if (storage.size() > limits.max_metadata_bytes)
        return Error{ErrorCode::resource_limit, "Mach-O archive member exceeds metadata limit"};
    auto owner = std::shared_ptr<const ByteStorage>(&storage, [](const ByteStorage *) {});
    auto loaded = load_macho(owner, {}, stop);
    if (!loaded) return loaded.error();
    if (!loaded.value().metadata.macho) return Error{ErrorCode::malformed, "Mach-O metadata unavailable"};
    const auto &metadata = *loaded.value().metadata.macho;
    const auto &header = metadata.container.slices[metadata.selected_slice].header;
    if (metadata.container.slices.size() != 1 || header.file_type != 1 || !header.is_64 ||
        header.order != ByteOrder::little ||
        (header.cpu_type != 0x01000007 && header.cpu_type != 0x0100000c))
        return Error{ErrorCode::unsupported,
                    "Archive member is not a thin little-endian x86-64 or ARM64 Mach-O object"};
    if (metadata.symbols.size() > limits.max_symbols)
        return Error{ErrorCode::resource_limit, "Mach-O archive symbol count limit exceeded"};
    if (metadata.sections.size() > limits.max_sections)
        return Error{ErrorCode::resource_limit, "Mach-O archive section count limit exceeded"};
    if (!metadata.symbols_complete)
        return Error{ErrorCode::unsupported, "Mach-O archive symbol metadata is incomplete"};
    ArMemberSymbols result;
    result.member_index = member_index;
    std::unordered_set<std::string> defs, undefs;
    for (const auto &symbol : metadata.symbols) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Mach-O archive member scan canceled"};
        if (!(symbol.type & 1) || symbol.name.empty()) continue;
        if (symbol.name.size() > limits.max_name_bytes)
            return Error{ErrorCode::resource_limit, "Mach-O archive symbol name exceeds limit"};
        if (symbol.state == MachOSymbolState::defined || symbol.state == MachOSymbolState::absolute ||
            symbol.state == MachOSymbolState::common) {
            if (defs.insert(symbol.name).second) result.definitions.push_back(symbol.name);
        } else if (symbol.state == MachOSymbolState::undefined && !(symbol.descriptor & 0x40)) {
            if (undefs.insert(symbol.name).second) result.undefined.push_back(symbol.name);
        }
    }
    result.undefined.erase(std::remove_if(result.undefined.begin(), result.undefined.end(),
        [&](const auto &name) { return defs.contains(name); }), result.undefined.end());
    return result;
}
} // namespace hexlab
