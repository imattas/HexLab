#include "hexlab/loaders/pe_messages.hpp"
#include "pe_internal.hpp"
#include <algorithm>
#include <new>

namespace hexlab {
Result<PeMessageTable> inspect_pe_message_table(const LoadedImage &loaded,
    std::size_t resource_index, std::stop_token stop, PeMessageTableLimits limits) try {
    using namespace pe_detail;
    canceled(stop);
    require(loaded.image && loaded.metadata.pe && resource_index < loaded.metadata.pe->resources.size(),
            "PE message-table resource index is invalid", ErrorCode::invalid_argument);
    require(limits.max_blocks && limits.max_messages && limits.max_payload_bytes && limits.max_metadata_bytes,
            "PE message-table limits must be positive", ErrorCode::invalid_argument);
    const auto &resource = loaded.metadata.pe->resources[resource_index];
    require(resource.type.id && *resource.type.id == 11 && !resource.type.name,
            "Selected PE resource is not numeric RT_MESSAGETABLE", ErrorCode::invalid_argument);
    require(resource.size >= 4, "Truncated PE message-table header");
    require(resource.size <= limits.max_payload_bytes && resource.size <= limits.max_metadata_bytes,
            "PE message-table payload exceeds configured limit", ErrorCode::resource_limit);
    ImageReader reader(*loaded.image, loaded.metadata, stop);
    const auto bytes = reader.bytes(resource.data_rva, resource.size);
    std::uint64_t budget = bytes.size();
    const auto charge = [&](std::uint64_t amount) {
        require(budget <= limits.max_metadata_bytes && amount <= limits.max_metadata_bytes - budget,
                "PE message-table metadata exceeds configured limit", ErrorCode::resource_limit);
        budget += amount;
    };
    charge(0);
    const auto u16 = [&](std::size_t at) -> std::uint16_t {
        require(at <= bytes.size() && bytes.size() - at >= 2, "Truncated PE message-table word");
        return std::to_integer<std::uint8_t>(bytes[at]) |
            (std::uint16_t{std::to_integer<std::uint8_t>(bytes[at + 1])} << 8);
    };
    const auto u32 = [&](std::size_t at) -> std::uint32_t {
        return std::uint32_t{u16(at)} | (std::uint32_t{u16(at + 2)} << 16);
    };
    const auto count = u32(0);
    require(count <= limits.max_blocks, "PE message-table block count exceeds limit", ErrorCode::resource_limit);
    const auto header_size = 4ULL + std::uint64_t{count} * 12;
    require(header_size <= bytes.size(), "PE message-table block array exceeds payload");
    charge(std::uint64_t{count} * (sizeof(PeMessageBlock) + 2 * sizeof(std::pair<std::uint64_t, std::uint64_t>)));
    PeMessageTable result;
    result.resource_index = resource_index;
    result.code_page = resource.code_page;
    // Copy only identifier values: their existing provenance stays on the resource.
    const auto identifier = [&](const PeResourceIdentifier &from) {
        if (from.name) charge(from.name->size());
        PeResourceIdentifier to; to.id = from.id; to.name = from.name; return to;
    };
    result.name = identifier(resource.name);
    result.language = identifier(resource.language);
    result.blocks.reserve(count);
    std::vector<std::pair<std::uint64_t, std::uint64_t>> id_ranges, byte_ranges;
    id_ranges.reserve(count); byte_ranges.reserve(count);
    const auto source = [&](std::uint64_t offset, std::uint64_t size, std::uint32_t index) {
        auto spans = reader.sources(std::uint64_t{resource.data_rva} + offset, size);
        charge(std::uint64_t{spans.size()} * sizeof(PeSourceSpan));
        return PeRecordSource{index, std::move(spans)};
    };
    std::uint64_t total = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        canceled(stop);
        const auto at = std::size_t{4} + std::size_t{i} * 12;
        PeMessageBlock block;
        block.low_id = u32(at); block.high_id = u32(at + 4); block.entries_offset = u32(at + 8);
        require(block.low_id <= block.high_id, "PE message block has a reversed ID range");
        const auto entries = std::uint64_t{block.high_id} - block.low_id + 1;
        require(entries <= limits.max_messages - total,
                "PE message count exceeds configured limit", ErrorCode::resource_limit);
        total += entries;
        require(block.entries_offset >= header_size && block.entries_offset < bytes.size(),
                "PE message block entries offset is outside the payload or overlaps headers");
        block.source = source(at, 12, i);
        id_ranges.emplace_back(block.low_id, block.high_id);
        result.blocks.push_back(std::move(block));
    }
    std::sort(id_ranges.begin(), id_ranges.end());
    for (std::size_t i = 1; i < id_ranges.size(); ++i)
        require(id_ranges[i - 1].second < id_ranges[i].first, "PE message block ID ranges overlap");
    charge(total * sizeof(PeMessageEntry));
    require(total <= result.messages.max_size(), "PE message count exceeds host capacity", ErrorCode::resource_limit);
    result.messages.reserve(static_cast<std::size_t>(total));
    const auto append_utf8 = [](std::string &text, std::uint32_t cp) {
        if (cp < 0x80) text.push_back(static_cast<char>(cp));
        else if (cp < 0x800) {
            text.push_back(static_cast<char>(0xc0 | (cp >> 6)));
            text.push_back(static_cast<char>(0x80 | (cp & 63)));
        } else {
            if (cp >= 0x10000) text.push_back(static_cast<char>(0xf0 | (cp >> 18)));
            text.push_back(static_cast<char>((cp >= 0x10000 ? 0x80 : 0xe0) | ((cp >> 12) & 63)));
            text.push_back(static_cast<char>(0x80 | ((cp >> 6) & 63)));
            text.push_back(static_cast<char>(0x80 | (cp & 63)));
        }
    };
    for (std::uint32_t bi = 0; bi < count; ++bi) {
        const auto &block = result.blocks[bi];
        std::size_t cursor = block.entries_offset;
        for (std::uint64_t id = block.low_id; id <= block.high_id; ++id) {
            canceled(stop);
            PeMessageEntry entry;
            entry.id = static_cast<std::uint32_t>(id); entry.block_index = bi;
            entry.resource_offset = static_cast<std::uint32_t>(cursor);
            entry.length = u16(cursor); entry.flags = u16(cursor + 2);
            require(entry.length >= 5 && entry.length <= bytes.size() - cursor,
                    "PE message entry has an invalid length");
            require(entry.flags <= 1, "Unsupported PE message entry flags", ErrorCode::unsupported);
            const auto end = cursor + entry.length;
            auto p = cursor + 4;
            if (entry.flags == 1) {
                require((entry.length & 1u) == 0, "PE Unicode message has an odd byte length");
                charge(std::uint64_t{entry.length - 4u} * 3 / 2);
                entry.text.emplace();
                entry.text->reserve(std::size_t{entry.length - 4u} * 3 / 2);
                bool terminated = false;
                while (p < end) {
                    auto cp = std::uint32_t{u16(p)}; p += 2;
                    if (!cp) { terminated = true; break; }
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        require(p + 2 <= end, "Truncated PE message UTF-16 surrogate pair");
                        const auto low = u16(p); p += 2;
                        require(low >= 0xdc00 && low <= 0xdfff, "Invalid PE message UTF-16 surrogate pair");
                        cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                    } else require(cp < 0xdc00 || cp > 0xdfff, "Unpaired PE message UTF-16 low surrogate");
                    append_utf8(*entry.text, cp);
                }
                require(terminated, "Unterminated PE Unicode message");
            } else {
                const auto begin = p;
                while (p < end && bytes[p] != std::byte{0}) ++p;
                require(p < end, "Unterminated PE ANSI message");
                charge(p - begin);
                entry.ansi_bytes.assign(bytes.begin() + begin, bytes.begin() + p);
                ++p;
            }
            // Entry length includes producer padding; preserve it through source.
            entry.source = source(cursor, entry.length, static_cast<std::uint32_t>(result.messages.size()));
            result.messages.push_back(std::move(entry));
            cursor = end;
        }
        byte_ranges.emplace_back(block.entries_offset, cursor);
    }
    std::sort(byte_ranges.begin(), byte_ranges.end());
    for (std::size_t i = 1; i < byte_ranges.size(); ++i)
        require(byte_ranges[i - 1].second <= byte_ranges[i].first, "PE message entry blocks overlap");
    canceled(stop);
    return result;
} catch (const pe_detail::Failure &failure) { return failure.error; }
  catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "Cannot allocate PE message-table metadata"}; }
  catch (const std::length_error &) { return Error{ErrorCode::resource_limit, "PE message-table metadata exceeds host capacity"}; }

const PeMessageEntry *find_pe_message(const PeMessageTable &table, std::uint32_t id) {
    const auto it = std::find_if(table.messages.begin(), table.messages.end(),
        [id](const auto &entry) { return entry.id == id; });
    return it == table.messages.end() ? nullptr : &*it;
}
} // namespace hexlab
