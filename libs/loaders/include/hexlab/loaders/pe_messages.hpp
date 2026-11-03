#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace hexlab {
struct PeMessageTableLimits {
    std::uint32_t max_blocks = 4096;
    std::uint32_t max_messages = 100'000;
    std::uint64_t max_payload_bytes = 16ULL * 1024 * 1024;
    std::uint64_t max_metadata_bytes = 64ULL * 1024 * 1024;
};
struct PeMessageEntry {
    std::uint32_t id = 0, block_index = 0, resource_offset = 0;
    std::uint16_t length = 0, flags = 0;
    // Unicode entries are strict UTF-16LE decoded to UTF-8. ANSI entries
    // retain their pre-terminator bytes; the resource code page is not guessed.
    std::optional<std::string> text;
    std::vector<std::byte> ansi_bytes;
    PeRecordSource source;
};
struct PeMessageBlock {
    std::uint32_t low_id = 0, high_id = 0, entries_offset = 0;
    PeRecordSource source;
};
struct PeMessageTable {
    std::size_t resource_index = 0;
    std::uint32_t code_page = 0;
    PeResourceIdentifier name, language;
    std::vector<PeMessageBlock> blocks;
    // File block order, then increasing message ID within each block.
    std::vector<PeMessageEntry> messages;
};
// Explicit resource selection avoids implicit Windows language fallback.
// Requires a numeric RT_MESSAGETABLE (11) resource already inventoried by load_pe.
// Malformed, overlapping, unknown-flag and over-budget tables fail atomically.
HEXLAB_LOADERS_EXPORT Result<PeMessageTable> inspect_pe_message_table(
    const LoadedImage &, std::size_t resource_index, std::stop_token = {}, PeMessageTableLimits = {});
// Returns a pointer owned by table, or nullptr when absent. No FormatMessage
// insert expansion or host code-page conversion is performed.
HEXLAB_LOADERS_EXPORT const PeMessageEntry *find_pe_message(const PeMessageTable &, std::uint32_t id);
} // namespace hexlab
