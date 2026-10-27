#include "hexlab/loaders/minidump.hpp"
#include "minidump_context.hpp"
#include <algorithm>
#include <array>
#include <limits>

namespace hexlab {
namespace {
constexpr std::uint32_t stream_thread_list = 3, stream_module_list = 4,
    stream_memory_list = 5, stream_exception = 6, stream_system_info = 7,
    stream_memory64_list = 9, stream_unloaded_module_list = 14,
    stream_misc_info = 15, stream_memory_info = 16, stream_thread_names = 24;
constexpr std::uint64_t max_streams = 4096, max_memory_regions = 131072,
    max_modules = 65536, max_threads = 65536, max_metadata_bytes = 64u * 1024u * 1024u;
constexpr std::uint64_t max_decoded_contexts = 4096;
constexpr std::size_t misc_info5_xstate_offset = 832;
constexpr std::size_t xstate_config_feature_size = 528;
constexpr std::size_t max_xstate_context_bytes = 64u * 1024u;

bool extent(std::uint64_t offset, std::uint64_t size, std::uint64_t total) {
    return offset <= total && size <= total - offset;
}
std::uint64_t u(std::span<const std::byte> bytes, std::size_t at, std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i)
        value |= std::uint64_t(std::to_integer<unsigned char>(bytes[at + i])) << (i * 8);
    return value;
}
Result<ByteView> read(const ByteStorage &storage, std::uint64_t offset, std::size_t size) {
    if (!extent(offset, size, storage.size()))
        return Error{ErrorCode::malformed, "Minidump file extent is outside the input"};
    auto bytes = storage.read_at({offset}, size);
    if (!bytes) return bytes.error();
    if (bytes.value().bytes.size() != size)
        return Error{ErrorCode::io, "Minidump source returned a short read"};
    return bytes.value();
}
Result<std::string> utf8(std::uint64_t rva, const ByteStorage &storage, std::uint64_t &budget) {
    auto length = read(storage, rva, 4);
    if (!length) return length.error();
    const auto count = static_cast<std::uint32_t>(u(length.value().bytes, 0, 4));
    if (count > 131072 || (count & 1) || !extent(std::uint64_t(rva) + 4, count, storage.size()))
        return Error{ErrorCode::malformed, "Minidump UTF-16 string has an invalid extent"};
    if (budget > max_metadata_bytes - std::min<std::uint64_t>(max_metadata_bytes, count))
        return Error{ErrorCode::resource_limit, "Minidump metadata exceeds its byte budget"};
    budget += count;
    auto data = read(storage, std::uint64_t(rva) + 4, count);
    if (!data) return data.error();
    std::string out;
    out.reserve(count);
    auto append = [&](std::uint32_t cp) {
        if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
        else if (cp <= 0x7ff) {
            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else if (cp <= 0xffff) {
            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        } else {
            out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
        }
    };
    for (std::size_t at = 0; at < count; at += 2) {
        std::uint32_t cp = static_cast<std::uint32_t>(u(data.value().bytes, at, 2));
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (at + 4 <= count) {
                const auto low = static_cast<std::uint32_t>(u(data.value().bytes, at + 2, 2));
                if (low >= 0xdc00 && low <= 0xdfff) {
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
                    at += 2;
                } else cp = 0xfffd;
            } else cp = 0xfffd;
        } else if (cp >= 0xdc00 && cp <= 0xdfff) cp = 0xfffd;
        append(cp);
    }
    return out;
}
struct StreamRow { std::uint32_t type, size, rva; };
struct Region { std::uint64_t begin, size, file; };
struct Protection { std::uint64_t begin, end; std::uint32_t protect, state, type; };
}

Result<LoadedImage> load_minidump(std::shared_ptr<const ByteStorage> storage, std::stop_token stop) {
    try {
        if (!storage) return Error{ErrorCode::invalid_argument, "Minidump loading requires input storage"};
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
        // Minidump mapping and metadata are derived from scattered stream and
        // memory records. Track every source read so patch invalidation can
        // prove whether a later project revision requires reparsing.
        auto tracking = TrackingStorage::create(std::move(storage));
        if (!tracking) return tracking.error();
        storage = tracking.value();
        auto header = read(*storage, 0, 32);
        if (!header) return header.error();
        if (u(header.value().bytes, 0, 4) != 0x504d444d)
            return Error{ErrorCode::malformed, "Invalid Minidump signature"};
        const auto stream_count = u(header.value().bytes, 8, 4);
        const auto directory_rva = u(header.value().bytes, 12, 4);
        if (stream_count > max_streams || !extent(directory_rva, stream_count * 12, storage->size()))
            return Error{ErrorCode::resource_limit, "Minidump stream directory exceeds validated limits"};
        auto directory = read(*storage, directory_rva, static_cast<std::size_t>(stream_count * 12));
        if (!directory) return directory.error();
        MinidumpMetadata metadata;
        metadata.timestamp = static_cast<std::uint32_t>(u(header.value().bytes, 20, 4));
        metadata.flags = u(header.value().bytes, 24, 8);
        metadata.flags_low = static_cast<std::uint32_t>(metadata.flags);
        std::vector<StreamRow> streams;
        streams.reserve(static_cast<std::size_t>(stream_count));
        for (std::uint64_t index = 0; index < stream_count; ++index) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
            const auto at = static_cast<std::size_t>(index * 12);
            StreamRow row{static_cast<std::uint32_t>(u(directory.value().bytes, at, 4)),
                          static_cast<std::uint32_t>(u(directory.value().bytes, at + 4, 4)),
                          static_cast<std::uint32_t>(u(directory.value().bytes, at + 8, 4))};
            if (!extent(row.rva, row.size, storage->size()))
                return Error{ErrorCode::malformed, "Minidump stream lies outside the input"};
            if (std::find_if(streams.begin(), streams.end(), [&](const auto &existing) {
                    return existing.type == row.type && (row.type == stream_thread_list || row.type == stream_module_list ||
                        row.type == stream_memory_list || row.type == stream_exception || row.type == stream_system_info ||
                        row.type == stream_memory64_list || row.type == stream_unloaded_module_list ||
                        row.type == stream_misc_info || row.type == stream_memory_info || row.type == stream_thread_names);
                }) != streams.end())
                return Error{ErrorCode::malformed, "Minidump contains duplicate standard streams"};
            streams.push_back(row);
            metadata.streams.push_back({row.type, row.size, row.rva});
        }

        std::uint64_t budget = streams.size() * sizeof(MinidumpStream);
        std::uint64_t decoded_contexts = 0, context_issue_count = 0;
        bool context_budget_reported = false;
        auto stream = [&](std::uint32_t type) -> std::optional<StreamRow> {
            auto found = std::find_if(streams.begin(), streams.end(), [&](const auto &row) { return row.type == type; });
            return found == streams.end() ? std::nullopt : std::optional<StreamRow>(*found);
        };
        if (auto sys = stream(stream_system_info)) {
            if (sys->size < 56) return Error{ErrorCode::malformed, "Minidump SystemInfo stream is truncated"};
            auto bytes = read(*storage, sys->rva, 56);
            if (!bytes) return bytes.error();
            metadata.processor_architecture = static_cast<std::uint16_t>(u(bytes.value().bytes, 0, 2));
            metadata.processor_count = static_cast<std::uint8_t>(u(bytes.value().bytes, 6, 1));
        } else metadata.diagnostics.emplace_back("Minidump has no SystemInfo stream; decode architecture is unknown");

        std::vector<minidump_detail::XstateFeatureInfo> xstate_features;
        std::uint32_t xstate_context_size = 0;
        if (auto misc = stream(stream_misc_info)) {
            if (misc->size < 4) {
                metadata.diagnostics.emplace_back("Minidump MiscInfo stream is truncated before SizeOfInfo");
            } else {
                auto size_bytes = read(*storage, misc->rva, 4);
                if (!size_bytes) return size_bytes.error();
                const auto declared = static_cast<std::size_t>(u(size_bytes.value().bytes, 0, 4));
                if (declared < 4 || declared > misc->size) {
                    metadata.diagnostics.emplace_back("Minidump MiscInfo SizeOfInfo is inconsistent with its stream extent");
                } else if (declared >= misc_info5_xstate_offset + xstate_config_feature_size) {
                    auto info = read(*storage, misc->rva, misc_info5_xstate_offset + xstate_config_feature_size);
                    if (!info) return info.error();
                    const auto info_size = static_cast<std::size_t>(u(info.value().bytes, misc_info5_xstate_offset, 4));
                    xstate_context_size = static_cast<std::uint32_t>(u(info.value().bytes, misc_info5_xstate_offset + 4, 4));
                    const auto enabled = u(info.value().bytes, misc_info5_xstate_offset + 8, 8);
                    bool valid = info_size >= xstate_config_feature_size &&
                                 info_size <= declared - misc_info5_xstate_offset &&
                                 xstate_context_size != 0 && xstate_context_size <= 1024u * 1024u;
                    for (std::size_t index = 0; index < 64; ++index) {
                        if (!(enabled & (std::uint64_t{1} << index))) continue;
                        const auto at = misc_info5_xstate_offset + 16 + index * 8;
                        const auto offset = static_cast<std::uint32_t>(u(info.value().bytes, at, 4));
                        const auto size = static_cast<std::uint32_t>(u(info.value().bytes, at + 4, 4));
                        if (!size || offset > xstate_context_size || size > xstate_context_size - offset) {
                            valid = false;
                            break;
                        }
                        xstate_features.push_back({static_cast<std::uint8_t>(index), offset, size});
                    }
                    if (!valid) {
                        xstate_features.clear();
                        xstate_context_size = 0;
                        metadata.diagnostics.emplace_back("Minidump MiscInfo5 XSTATE feature map is inconsistent or exceeds its validation bounds");
                    }
                }
            }
        }

        auto context_at = [&](std::uint32_t size, std::uint32_t rva)
            -> Result<std::optional<MinidumpContext>> {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump context decoding canceled"};
            if (!size) return std::optional<MinidumpContext>{};
            if (!rva || !extent(rva, size, storage->size()))
                return Error{ErrorCode::malformed, "Minidump nonempty context has a null or out-of-file RVA"};
            if (decoded_contexts >= max_decoded_contexts) {
                if (!context_budget_reported) {
                    metadata.diagnostics.emplace_back("Minidump thread-context decode limit reached; remaining contexts retain only their source extents");
                    context_budget_reported = true;
                }
                return std::optional<MinidumpContext>{};
            }
            const auto prefix = minidump_detail::context_prefix_size(metadata.processor_architecture);
            std::size_t capture_size = std::min<std::size_t>(size, prefix);
            auto initial = read(*storage, rva, capture_size);
            if (!initial) return initial.error();
            if (metadata.processor_architecture == 9 && initial.value().bytes.size() >= 52 &&
                (u(initial.value().bytes, 48, 4) & 0x40u) && xstate_context_size) {
                constexpr std::uint64_t amd64_xsave_base = 256;
                for (const auto &feature : xstate_features) {
                    if (feature.index < 2) continue;
                    const std::uint64_t end = amd64_xsave_base + feature.offset + feature.size;
                    if (end <= size && end <= prefix + max_xstate_context_bytes)
                        capture_size = std::max(capture_size, static_cast<std::size_t>(end));
                }
            }
            auto data = capture_size == initial.value().bytes.size()
                ? std::move(initial)
                : read(*storage, rva, capture_size);
            if (!data) return data.error();
            auto context = minidump_detail::decode_context(metadata.processor_architecture, data.value().bytes, rva, size,
                                                            xstate_context_size, xstate_features);
            if (context.status != MinidumpContextStatus::decoded) ++context_issue_count;
            std::uint64_t cost = sizeof(MinidumpContext) + context.registers.size() * sizeof(MinidumpRegister);
            cost += context.captured_prefix.size();
            for (const auto &reg : context.registers) cost += reg.name.size() + reg.bytes.size();
            for (const auto &diagnostic : context.diagnostics) cost += diagnostic.size();
            if (budget > max_metadata_bytes || cost > max_metadata_bytes - budget)
                return Error{ErrorCode::resource_limit, "Minidump register contexts exceed the metadata budget"};
            budget += cost;
            ++decoded_contexts;
            return std::optional<MinidumpContext>(std::move(context));
        };

        std::vector<Region> regions;
        if (auto list = stream(stream_memory_list)) {
            if (list->size < 4) return Error{ErrorCode::malformed, "Minidump MemoryList stream is truncated"};
            auto count_bytes = read(*storage, list->rva, 4);
            if (!count_bytes) return count_bytes.error();
            const auto count = u(count_bytes.value().bytes, 0, 4);
            if (count > max_memory_regions || regions.size() + count > max_memory_regions ||
                count > (list->size - 4) / 16)
                return Error{ErrorCode::resource_limit, "Minidump memory range count exceeds stream bounds"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(4 + count * 16));
            if (!bytes) return bytes.error();
            regions.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
                const auto at = static_cast<std::size_t>(4 + i * 16);
                const auto base = u(bytes.value().bytes, at, 8);
                const auto size = u(bytes.value().bytes, at + 8, 4);
                const auto rva = u(bytes.value().bytes, at + 12, 4);
                if (!size || !extent(rva, size, storage->size()) || base > UINT64_MAX - size)
                    return Error{ErrorCode::malformed, "Minidump memory descriptor has an invalid extent"};
                regions.push_back({base, size, rva});
            }
            budget += count * sizeof(Region);
        }
        if (auto list = stream(stream_memory64_list)) {
            if (list->size < 16) return Error{ErrorCode::malformed, "Minidump Memory64List stream is truncated"};
            auto header_bytes = read(*storage, list->rva, 16);
            if (!header_bytes) return header_bytes.error();
            const auto count = u(header_bytes.value().bytes, 0, 8);
            const auto base_rva = u(header_bytes.value().bytes, 8, 8);
            if (count > max_memory_regions || regions.size() + count > max_memory_regions ||
                count > (list->size - 16) / 16)
                return Error{ErrorCode::resource_limit, "Minidump Memory64 range count exceeds stream bounds"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(16 + count * 16));
            if (!bytes) return bytes.error();
            if (!extent(base_rva, 0, storage->size()))
                return Error{ErrorCode::malformed, "Minidump Memory64 payload starts outside the input"};
            std::uint64_t cursor = base_rva;
            regions.reserve(regions.size() + static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
                const auto at = static_cast<std::size_t>(16 + i * 16);
                const auto base = u(bytes.value().bytes, at, 8);
                const auto size = u(bytes.value().bytes, at + 8, 8);
                if (!size || !extent(cursor, size, storage->size()) || base > UINT64_MAX - size || cursor > UINT64_MAX - size)
                    return Error{ErrorCode::malformed, "Minidump Memory64 descriptor has an invalid extent"};
                regions.push_back({base, size, cursor});
                cursor += size;
            }
            budget += count * sizeof(Region);
        }
        if (regions.size() > max_memory_regions || budget > max_metadata_bytes)
            return Error{ErrorCode::resource_limit, "Minidump memory metadata exceeds configured limits"};

        std::vector<Protection> protections;
        if (auto list = stream(stream_memory_info)) {
            if (list->size < 16) return Error{ErrorCode::malformed, "Minidump MemoryInfoList stream is truncated"};
            auto header_bytes = read(*storage, list->rva, 16);
            if (!header_bytes) return header_bytes.error();
            const auto header_size = u(header_bytes.value().bytes, 0, 4);
            const auto entry_size = u(header_bytes.value().bytes, 4, 4);
            const auto count = u(header_bytes.value().bytes, 8, 8);
            if (header_size < 16 || header_size > 4096 || entry_size < 48 || entry_size > 4096 ||
                !extent(0, header_size, list->size) ||
                count > max_memory_regions || count > (list->size - header_size) / entry_size)
                return Error{ErrorCode::malformed, "Minidump MemoryInfoList header or entries are invalid"};
            const auto table_size = header_size + count * entry_size;
            if (table_size > max_metadata_bytes)
                return Error{ErrorCode::resource_limit, "Minidump MemoryInfoList exceeds its metadata budget"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(table_size));
            if (!bytes) return bytes.error();
            protections.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                const auto at = static_cast<std::size_t>(header_size + i * entry_size);
                const auto base = u(bytes.value().bytes, at, 8);
                const auto allocation_protect = u(bytes.value().bytes, at + 16, 4);
                (void)allocation_protect;
                const auto size = u(bytes.value().bytes, at + 24, 8);
                const auto state = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 32, 4));
                const auto protect = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 36, 4));
                const auto type = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 40, 4));
                if (!size || base > UINT64_MAX - size)
                    return Error{ErrorCode::malformed, "Minidump memory information has an invalid address range"};
                protections.push_back({base, base + size, protect, state, type});
            }
            std::sort(protections.begin(), protections.end(), [](const auto &a, const auto &b) { return a.begin < b.begin; });
            for (std::size_t i = 1; i < protections.size(); ++i)
                if (protections[i].begin < protections[i - 1].end)
                    return Error{ErrorCode::malformed, "Minidump memory information ranges overlap"};
            budget += count * sizeof(Protection);
        }

        if (auto list = stream(stream_module_list)) {
            if (list->size < 4) return Error{ErrorCode::malformed, "Minidump ModuleList stream is truncated"};
            auto count_bytes = read(*storage, list->rva, 4);
            if (!count_bytes) return count_bytes.error();
            const auto count = u(count_bytes.value().bytes, 0, 4);
            constexpr std::size_t record_size = 108;
            if (count > max_modules || count > (list->size - 4) / record_size)
                return Error{ErrorCode::resource_limit, "Minidump module count exceeds stream bounds"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(4 + count * record_size));
            if (!bytes) return bytes.error();
            metadata.modules.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
                const auto at = static_cast<std::size_t>(4 + i * record_size);
                MinidumpModule module;
                module.image_base = u(bytes.value().bytes, at, 8);
                module.image_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 8, 4));
                module.checksum = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 12, 4));
                module.timestamp = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 16, 4));
                auto name = utf8(static_cast<std::uint32_t>(u(bytes.value().bytes, at + 20, 4)), *storage, budget);
                if (!name) return name.error();
                module.name = std::move(name.value());
                module.cv_record_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 76, 4));
                module.cv_record_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 80, 4));
                if (module.image_size && module.image_base > UINT64_MAX - module.image_size)
                    return Error{ErrorCode::overflow, "Minidump module image range overflows"};
                if (module.cv_record_size && !extent(module.cv_record_rva, module.cv_record_size, storage->size()))
                    return Error{ErrorCode::malformed, "Minidump module CodeView record is outside the input"};
                metadata.modules.push_back(std::move(module));
            }
            budget += count * sizeof(MinidumpModule);
        }

        if (auto list = stream(stream_unloaded_module_list)) {
            if (list->size < 12)
                return Error{ErrorCode::malformed, "Minidump UnloadedModuleList stream header is truncated"};
            auto header = read(*storage, list->rva, 12);
            if (!header) return header.error();
            const auto header_size = u(header.value().bytes, 0, 4);
            const auto entry_size = u(header.value().bytes, 4, 4);
            const auto count = u(header.value().bytes, 8, 4);
            if (header_size < 12 || header_size > 4096 || entry_size < 24 || entry_size > 4096 ||
                header_size > list->size || count > max_modules ||
                count > (list->size - header_size) / entry_size)
                return Error{ErrorCode::malformed, "Minidump UnloadedModuleList header or entries are invalid"};
            const auto table_size = header_size + count * entry_size;
            if (table_size > max_metadata_bytes || budget > max_metadata_bytes ||
                count > (max_metadata_bytes - budget) / sizeof(MinidumpUnloadedModule))
                return Error{ErrorCode::resource_limit, "Minidump unloaded-module metadata exceeds its byte budget"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(table_size));
            if (!bytes) return bytes.error();
            metadata.unloaded_modules.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump unloaded-module parsing canceled"};
                const auto at = static_cast<std::size_t>(header_size + i * entry_size);
                MinidumpUnloadedModule module;
                module.record_file_offset = {std::uint64_t{list->rva} + at};
                module.image_base = u(bytes.value().bytes, at, 8);
                module.image_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 8, 4));
                module.checksum = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 12, 4));
                module.timestamp = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 16, 4));
                const auto name_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 20, 4));
                if (!name_rva || (module.image_size && module.image_base > UINT64_MAX - module.image_size))
                    return Error{ErrorCode::malformed, "Minidump unloaded-module record has an invalid name or image range"};
                auto name = utf8(name_rva, *storage, budget);
                if (!name) return name.error();
                module.name_file_offset = {name_rva};
                module.name = std::move(name.value());
                metadata.unloaded_modules.push_back(std::move(module));
            }
            budget += count * sizeof(MinidumpUnloadedModule);
        }

        if (auto list = stream(stream_thread_list)) {
            if (list->size < 4) return Error{ErrorCode::malformed, "Minidump ThreadList stream is truncated"};
            auto count_bytes = read(*storage, list->rva, 4);
            if (!count_bytes) return count_bytes.error();
            const auto count = u(count_bytes.value().bytes, 0, 4);
            constexpr std::size_t record_size = 48;
            if (count > max_threads || count > (list->size - 4) / record_size)
                return Error{ErrorCode::resource_limit, "Minidump thread count exceeds stream bounds"};
            auto bytes = read(*storage, list->rva, static_cast<std::size_t>(4 + count * record_size));
            if (!bytes) return bytes.error();
            constexpr auto thread_cost = sizeof(MinidumpThread) + sizeof(std::uint32_t);
            if (budget > max_metadata_bytes || count > (max_metadata_bytes - budget) / thread_cost)
                return Error{ErrorCode::resource_limit, "Minidump thread metadata exceeds its byte budget"};
            budget += count * thread_cost;
            metadata.threads.reserve(static_cast<std::size_t>(count));
            std::vector<std::uint32_t> thread_ids;
            thread_ids.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump thread-context decoding canceled"};
                const auto at = static_cast<std::size_t>(4 + i * record_size);
                MinidumpThread thread;
                thread.record_file_offset = {std::uint64_t{list->rva} + at};
                thread.id = static_cast<std::uint32_t>(u(bytes.value().bytes, at, 4));
                if (!thread.id)
                    return Error{ErrorCode::malformed, "Minidump ThreadList has a zero thread ID"};
                thread_ids.push_back(thread.id);
                thread.suspend_count = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 4, 4));
                thread.priority_class = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 8, 4));
                thread.priority = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 12, 4));
                thread.teb = u(bytes.value().bytes, at + 16, 8);
                thread.stack_address = u(bytes.value().bytes, at + 24, 8);
                thread.stack_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 32, 4));
                thread.stack_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 36, 4));
                thread.context_size = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 40, 4));
                thread.context_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, at + 44, 4));
                if ((thread.stack_size && (thread.stack_address > UINT64_MAX - thread.stack_size ||
                                           !extent(thread.stack_rva, thread.stack_size, storage->size()))) ||
                    (thread.context_size && !extent(thread.context_rva, thread.context_size, storage->size())))
                    return Error{ErrorCode::malformed, "Minidump thread stack/context data is outside the input"};
                auto context = context_at(thread.context_size, thread.context_rva);
                if (!context) return context.error();
                thread.context = std::move(context.value());
                metadata.threads.push_back(std::move(thread));
            }
            std::sort(thread_ids.begin(), thread_ids.end());
            if (std::adjacent_find(thread_ids.begin(), thread_ids.end()) != thread_ids.end())
                return Error{ErrorCode::malformed, "Minidump ThreadList has duplicate thread IDs"};
        }

        if (auto exception = stream(stream_exception)) {
            if (exception->size < 168) return Error{ErrorCode::malformed, "Minidump Exception stream is truncated"};
            auto bytes = read(*storage, exception->rva, 168);
            if (!bytes) return bytes.error();
            MinidumpException row;
            row.record_file_offset = {exception->rva};
            row.thread_id = static_cast<std::uint32_t>(u(bytes.value().bytes, 0, 4));
            row.code = static_cast<std::uint32_t>(u(bytes.value().bytes, 8, 4));
            row.flags = static_cast<std::uint32_t>(u(bytes.value().bytes, 12, 4));
            row.record = u(bytes.value().bytes, 16, 8);
            row.address = u(bytes.value().bytes, 24, 8);
            row.parameter_count = static_cast<std::uint32_t>(u(bytes.value().bytes, 32, 4));
            if (row.parameter_count > 15)
                return Error{ErrorCode::malformed, "Minidump Exception parameter count exceeds the format limit"};
            row.parameters.reserve(row.parameter_count);
            for (std::uint32_t i = 0; i < row.parameter_count; ++i)
                row.parameters.push_back(u(bytes.value().bytes, 40 + i * 8, 8));
            row.context_size = static_cast<std::uint32_t>(u(bytes.value().bytes, 160, 4));
            row.context_rva = static_cast<std::uint32_t>(u(bytes.value().bytes, 164, 4));
            if (row.context_size && !extent(row.context_rva, row.context_size, storage->size()))
                return Error{ErrorCode::malformed, "Minidump exception context is outside the input"};
            auto context = context_at(row.context_size, row.context_rva);
            if (!context) return context.error();
            row.context = std::move(context.value());
            metadata.exception = std::move(row);
        }

        if (auto names = stream(stream_thread_names)) {
            if (names->size < 4)
                return Error{ErrorCode::malformed, "Minidump ThreadNames stream is truncated"};
            auto count_bytes = read(*storage, names->rva, 4);
            if (!count_bytes) return count_bytes.error();
            const auto count = u(count_bytes.value().bytes, 0, 4);
            constexpr std::size_t record_size = 12;
            if (count > max_threads || count > (names->size - 4) / record_size)
                return Error{ErrorCode::resource_limit, "Minidump thread-name count exceeds stream bounds"};
            auto bytes = read(*storage, names->rva, static_cast<std::size_t>(4 + count * record_size));
            if (!bytes) return bytes.error();
            constexpr std::size_t row_cost = sizeof(MinidumpThreadName) + sizeof(std::uint32_t);
            if (budget > max_metadata_bytes || count > (max_metadata_bytes - budget) / row_cost)
                return Error{ErrorCode::resource_limit, "Minidump thread-name metadata exceeds its byte budget"};
            metadata.thread_names.reserve(static_cast<std::size_t>(count));
            std::vector<std::uint32_t> thread_ids;
            thread_ids.reserve(static_cast<std::size_t>(count));
            for (std::uint64_t i = 0; i < count; ++i) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump thread-name decoding canceled"};
                const auto at = static_cast<std::size_t>(4 + i * record_size);
                const auto thread_id = static_cast<std::uint32_t>(u(bytes.value().bytes, at, 4));
                const auto name_rva = u(bytes.value().bytes, at + 4, 8);
                if (!thread_id || !name_rva)
                    return Error{ErrorCode::malformed, "Minidump thread-name row has a zero thread ID or string RVA"};
                auto name = utf8(name_rva, *storage, budget);
                if (!name) return name.error();
                if (budget > max_metadata_bytes || name.value().size() > max_metadata_bytes - budget)
                    return Error{ErrorCode::resource_limit, "Minidump thread names exceed the metadata byte budget"};
                budget += name.value().size();
                MinidumpThreadName row;
                row.thread_id = thread_id;
                row.name = std::move(name.value());
                row.record_file_offset = {std::uint64_t{names->rva} + at};
                row.string_file_offset = {name_rva};
                thread_ids.push_back(thread_id);
                metadata.thread_names.push_back(std::move(row));
            }
            std::sort(thread_ids.begin(), thread_ids.end());
            if (std::adjacent_find(thread_ids.begin(), thread_ids.end()) != thread_ids.end())
                return Error{ErrorCode::malformed, "Minidump ThreadNames stream has duplicate thread IDs"};
            std::sort(metadata.thread_names.begin(), metadata.thread_names.end(), [](const auto &left, const auto &right) {
                return left.thread_id < right.thread_id;
            });
            budget += count * row_cost;
        }

        if (context_issue_count)
            metadata.diagnostics.emplace_back(std::to_string(context_issue_count) + " Minidump context records are partial, malformed, unsupported or have no captured groups");
        if (regions.empty()) metadata.diagnostics.emplace_back("Minidump contains no mapped memory-list regions");
        std::sort(regions.begin(), regions.end(), [](const auto &a, const auto &b) { return a.begin < b.begin; });
        for (std::size_t i = 1; i < regions.size(); ++i)
            if (regions[i].begin < regions[i - 1].begin + regions[i - 1].size)
                return Error{ErrorCode::malformed, "Minidump memory descriptors overlap"};

        Architecture arch = Architecture::unknown;
        ExecutionMode mode = ExecutionMode::unknown;
        std::uint8_t width = 64;
        switch (metadata.processor_architecture) {
        case 0: arch = Architecture::x86; mode = ExecutionMode::x86_32; width = 32; break;
        case 5: arch = Architecture::arm; width = 32; break;
        case 9: arch = Architecture::x86_64; mode = ExecutionMode::x86_64; break;
        case 12: arch = Architecture::arm64; mode = ExecutionMode::a64; break;
        case 0x8003: arch = Architecture::arm64; mode = ExecutionMode::a64; break;
        default:
            if (!regions.empty() && regions.back().begin + regions.back().size <= (UINT64_C(1) << 32)) width = 32;
            metadata.diagnostics.emplace_back("Minidump processor architecture is not supported for instruction decoding");
            break;
        }
        ImageLayout layout{{{0}, width, 1, ByteOrder::little}, arch, mode, {}, {}};
        LoadedImage loaded;
        loaded.metadata.format = "minidump";
        if (!regions.empty()) {
            loaded.metadata.preferred_base = regions.front().begin;
            const auto last_end = regions.back().begin + regions.back().size;
            loaded.metadata.image_size = last_end - regions.front().begin;
        }
        switch (metadata.processor_architecture) {
        case 0: loaded.metadata.machine = 0x014c; break;
        case 5: loaded.metadata.machine = 0x01c0; break;
        case 9: loaded.metadata.machine = 0x8664; break;
        case 12: loaded.metadata.machine = 0xaa64; break;
        case 0x8003: loaded.metadata.machine = 0xaa64; break;
        default: break;
        }
        loaded.metadata.minidump = std::move(metadata);
        loaded.metadata_complete = loaded.metadata.minidump->diagnostics.empty();
        auto &minidump = *loaded.metadata.minidump;
        if (protections.empty() && !regions.empty()) {
            minidump.diagnostics.emplace_back("Minidump has no MemoryInfoList; mapped bytes use provisional RWX permissions");
            loaded.metadata_complete = false;
        }
        bool protection_gap = false;
        auto append = [&](std::uint64_t begin, std::uint64_t size, std::uint64_t file,
                                std::uint32_t protect, std::uint32_t state, std::uint32_t type,
                                bool permission_known) {
            if (!size) return;
            if (!permission_known) protection_gap = true;
            bool read_access = true, write_access = false, execute = !permission_known;
            if (permission_known) {
                const auto access = protect & 0xff;
                const bool committed = state == 0x1000; // MEM_COMMIT
                read_access = committed && (access == 0x02 || access == 0x04 || access == 0x08 ||
                                             access == 0x20 || access == 0x40 || access == 0x80);
                write_access = committed && (access == 0x04 || access == 0x08 || access == 0x40 || access == 0x80);
                execute = committed && (access == 0x10 || access == 0x20 || access == 0x40 || access == 0x80);
                if (access == 0x01 || (protect & 0x100)) read_access = write_access = execute = false;
            } else write_access = true;
            const auto index = minidump.memory.size();
            layout.segments.push_back({"memory" + std::to_string(index), {{0}, begin}, size, {file}, size,
                                       read_access, write_access, execute});
            minidump.memory.push_back({{{0}, begin}, size, {file}, protect, state, type,
                                       read_access, write_access, execute});
            budget += sizeof(Segment) + sizeof(MinidumpMemoryRegion) + 24;
        };
        for (const auto &region : regions) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "Minidump loading canceled"};
            const auto end = region.begin + region.size;
            if (width < 64 && end > (UINT64_C(1) << width))
                return Error{ErrorCode::overflow, "Minidump address exceeds the declared processor width"};
            if (protections.empty()) {
                append(region.begin, region.size, region.file, 0, 0, 0, false);
                continue;
            }
            std::uint64_t cursor = region.begin;
            auto protection = std::lower_bound(protections.begin(), protections.end(), cursor,
                [](const auto &row, std::uint64_t value) { return row.end <= value; });
            for (; protection != protections.end() && protection->begin < end; ++protection) {
                if (protection->begin > cursor)
                    append(cursor, protection->begin - cursor, region.file + (cursor - region.begin), 0, 0, 0, false);
                const auto piece_begin = std::max(cursor, protection->begin);
                const auto piece_end = std::min(end, protection->end);
                if (piece_end > piece_begin)
                    append(piece_begin, piece_end - piece_begin, region.file + (piece_begin - region.begin),
                           protection->protect, protection->state, protection->type, true);
                cursor = std::max(cursor, piece_end);
                if (cursor >= end) break;
            }
            if (cursor < end)
                append(cursor, end - cursor, region.file + (cursor - region.begin), 0, 0, 0, false);
        }
        if (protection_gap && !protections.empty()) {
            minidump.diagnostics.emplace_back("Some captured memory ranges have no MemoryInfoList protection record; permissions are provisional");
            loaded.metadata_complete = false;
        }
        if (budget > max_metadata_bytes)
            return Error{ErrorCode::resource_limit, "Minidump metadata exceeds its byte budget"};
        if (minidump.exception) {
            const Address at{{0}, minidump.exception->address};
            if (std::any_of(layout.segments.begin(), layout.segments.end(), [&](const auto &segment) {
                    return at.offset >= segment.begin.offset && at.offset - segment.begin.offset < segment.size;
                })) layout.entries.push_back(at);
        }
        auto image = Image::create(storage, std::move(layout));
        if (!image) return image.error();
        loaded.image = std::move(image.value());
        loaded.metadata_reads = tracking.value()->reads();
        loaded.metadata_reads_complete = true;
        if (minidump.streams.empty())
            return Error{ErrorCode::malformed, "Minidump has no stream directory entries"};
        if (!minidump.diagnostics.empty()) {
            for (const auto &message : minidump.diagnostics)
                loaded.diagnostics.push_back({DiagnosticSeverity::warning, message, {}});
            loaded.metadata_complete = false;
        }
        return loaded;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Minidump metadata"};
    } catch (...) {
        return Error{ErrorCode::malformed, "Minidump parsing failed"};
    }
}
} // namespace hexlab
