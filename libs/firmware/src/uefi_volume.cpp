#include "hexlab/firmware/uefi_volume.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <utility>

namespace hexlab::firmware {
namespace {
constexpr std::array<std::uint8_t, 4> fv_signature{'_', 'F', 'V', 'H'};
constexpr std::array<std::uint8_t, 16> ffs2_guid{
    0x78,0xe5,0x8c,0x8c,0x3d,0x8a,0x1c,0x4f,0x99,0x35,0x89,0x61,0x85,0xc3,0x2d,0xd3};
constexpr std::array<std::uint8_t, 16> ffs3_guid{
    0x7a,0xc0,0x73,0x54,0xcb,0x3d,0xca,0x4d,0xbd,0x6f,0x1e,0x96,0x89,0xe7,0x34,0x9a};
constexpr std::uint64_t max_header_bytes = 16ull * 1024 * 1024;
constexpr std::size_t max_fv_extension_entries = 65536;
constexpr std::uint32_t section_compression = 0x01;
constexpr std::uint32_t section_guid_defined = 0x02;
constexpr std::uint32_t section_disposable = 0x03;
constexpr std::uint32_t section_version = 0x14;
constexpr std::uint32_t section_user_interface = 0x15;
constexpr std::uint32_t section_freeform_subtype_guid = 0x18;
constexpr std::uint16_t guid_processing_required = 0x0001;
constexpr std::size_t max_section_text_units = 4096;
constexpr std::uint8_t ffs_attribute_checksum = 0x40;
constexpr std::uint8_t ffs_fixed_checksum = 0xaa;
constexpr std::uint8_t ffs_state_header_construction = 0x01;
constexpr std::uint8_t ffs_state_header_valid = 0x02;
constexpr std::uint8_t ffs_state_data_valid = 0x04;
constexpr std::uint8_t ffs_state_marked_for_update = 0x08;
constexpr std::uint8_t ffs_state_deleted = 0x10;
constexpr std::uint8_t ffs_state_header_invalid = 0x20;

std::uint8_t u8(std::span<const std::byte> b, std::size_t at) {
    return std::to_integer<std::uint8_t>(b[at]);
}
std::uint16_t u16(std::span<const std::byte> b, std::size_t at) {
    return std::uint16_t(u8(b, at)) | (std::uint16_t(u8(b, at + 1)) << 8);
}
std::uint32_t u24(std::span<const std::byte> b, std::size_t at) {
    return std::uint32_t(u8(b, at)) | (std::uint32_t(u8(b, at + 1)) << 8) |
           (std::uint32_t(u8(b, at + 2)) << 16);
}
std::uint32_t u32(std::span<const std::byte> b, std::size_t at) {
    return std::uint32_t(u16(b, at)) | (std::uint32_t(u16(b, at + 2)) << 16);
}
std::uint64_t u64(std::span<const std::byte> b, std::size_t at) {
    return std::uint64_t(u32(b, at)) | (std::uint64_t(u32(b, at + 4)) << 32);
}
bool all_value(std::span<const std::byte> b, std::uint8_t v) {
    return std::all_of(b.begin(), b.end(), [v](std::byte x) { return std::to_integer<std::uint8_t>(x) == v; });
}
bool all_padding(std::span<const std::byte> bytes, std::uint8_t erased) {
    return all_value(bytes, erased) || all_value(bytes, 0x00) || all_value(bytes, 0xff);
}

UefiFfsFileDisposition classify_ffs_state(std::uint8_t state) {
    if (state & ffs_state_header_invalid) return UefiFfsFileDisposition::header_invalid;
    if (state & ffs_state_deleted) return UefiFfsFileDisposition::deleted;
    if (state & ffs_state_marked_for_update) return UefiFfsFileDisposition::marked_for_update;
    if (state & ffs_state_data_valid) return UefiFfsFileDisposition::data_valid;
    if (state & ffs_state_header_valid) return UefiFfsFileDisposition::header_valid;
    if (state & ffs_state_header_construction) return UefiFfsFileDisposition::construction;
    return UefiFfsFileDisposition::unrecognized_state;
}

bool parse_section_utf16(std::span<const std::byte> bytes, std::u16string &text,
                         std::string &reason) {
    if ((bytes.size() & 1u) != 0) {
        reason = "UEFI section UTF-16 text has an odd byte length";
        return false;
    }
    const auto available_units = bytes.size() / 2;
    const auto units_to_read = std::min(available_units, max_section_text_units + 1);
    bool terminated = false;
    std::size_t terminator_offset = 0;
    text.clear();
    for (std::size_t i = 0; i < units_to_read; ++i) {
        const auto value = u16(bytes, i * 2);
        if (value == 0) {
            terminated = true;
            terminator_offset = i * 2 + 2;
            break;
        }
        if (text.size() == max_section_text_units) {
            reason = "UEFI section UTF-16 text exceeds its 4096-code-unit limit";
            return false;
        }
        text.push_back(static_cast<char16_t>(value));
    }
    if (!terminated) {
        reason = available_units > max_section_text_units
            ? "UEFI section UTF-16 text exceeds its 4096-code-unit limit"
            : "UEFI section UTF-16 text is not null-terminated";
        return false;
    }
    if (terminator_offset < bytes.size() && !all_padding(bytes.subspan(terminator_offset), 0)) {
        reason = "UEFI section UTF-16 text has non-padding bytes after its terminator";
        return false;
    }
    for (std::size_t i = 0; i < text.size(); ++i) {
        const auto unit = static_cast<std::uint16_t>(text[i]);
        if (unit >= 0xd800 && unit <= 0xdbff) {
            if (i + 1 >= text.size()) {
                reason = "UEFI section UTF-16 text has an unpaired high surrogate";
                return false;
            }
            const auto low = static_cast<std::uint16_t>(text[i + 1]);
            if (low < 0xdc00 || low > 0xdfff) {
                reason = "UEFI section UTF-16 text has an invalid surrogate pair";
                return false;
            }
            ++i;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) {
            reason = "UEFI section UTF-16 text has an unpaired low surrogate";
            return false;
        }
    }
    return true;
}

// Decoder structure adapted from TianoCore EDK II BaseTools/Source/C/Common/Decompress.c.
// Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.
// SPDX-License-Identifier: BSD-2-Clause-Patent
// The BSD-2-Clause-Patent terms are retained in libs/firmware/EDK2-LICENSE.txt.
constexpr std::size_t efi_code_bits = 16;
constexpr std::size_t efi_max_match = 256;
constexpr std::size_t efi_match_threshold = 3;
constexpr std::size_t efi_nc = 0xff + efi_max_match + 2 - efi_match_threshold;
constexpr std::size_t efi_nt = efi_code_bits + 3;
constexpr std::size_t efi_max_pbit = 5;
constexpr std::size_t efi_position_bits = 4;
constexpr std::size_t tiano_position_bits = efi_max_pbit;
constexpr std::size_t efi_max_np = (1u << efi_max_pbit) - 1;
constexpr std::size_t efi_npt = efi_nt > efi_max_np ? efi_nt : efi_max_np;

struct EfiDecodeBudget {
    const UefiVolumeParseOptions &limits;
    std::uint64_t work_remaining = 0;
    std::uint64_t total_output = 0;
    std::uint64_t active_output = 0;
    std::stop_token stop;
};

struct ActiveDecodeBuffer {
    EfiDecodeBudget &budget;
    std::uint64_t size;
    ~ActiveDecodeBuffer() { budget.active_output -= size; }
};

class EfiBitReader {
public:
    EfiBitReader(std::span<const std::byte> bytes, EfiDecodeBudget &budget)
        : bytes_(bytes), budget_(budget) {}

    bool read(std::size_t count, std::uint32_t &value) {
        if (count > 32 || bit_offset_ > bytes_.size() * 8 || count > bytes_.size() * 8 - bit_offset_ ||
            !charge(count)) return false;
        value = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto at = bit_offset_++;
            const auto byte = std::to_integer<std::uint8_t>(bytes_[at / 8]);
            value = (value << 1) | ((byte >> (7 - (at & 7u))) & 1u);
        }
        return true;
    }

    bool peek(std::size_t count, std::uint32_t &value) const {
        if (count > 32 || bit_offset_ > bytes_.size() * 8 || count > bytes_.size() * 8 - bit_offset_) return false;
        value = 0;
        for (std::size_t i = 0; i < count; ++i) {
            const auto at = bit_offset_ + i;
            const auto byte = std::to_integer<std::uint8_t>(bytes_[at / 8]);
            value = (value << 1) | ((byte >> (7 - (at & 7u))) & 1u);
        }
        return true;
    }

    bool consume_work(std::uint64_t amount = 1) { return charge(amount); }

private:
    bool charge(std::uint64_t amount) {
        if (budget_.stop.stop_requested() || amount > budget_.work_remaining) return false;
        budget_.work_remaining -= amount;
        return true;
    }

    std::span<const std::byte> bytes_;
    EfiDecodeBudget &budget_;
    std::size_t bit_offset_ = 0;
};

class EfiHuffman {
public:
    bool build(std::span<const std::uint8_t> lengths) {
        counts_.fill(0);
        first_code_.fill(0);
        first_symbol_.fill(0);
        symbols_.clear();
        bool all_zero = true;
        for (auto length : lengths) {
            if (length > efi_code_bits) return false;
            if (length != 0) {
                all_zero = false;
                ++counts_[length];
            }
        }
        if (all_zero) {
            constant_ = true;
            constant_symbol_ = 0;
            return true;
        }

        std::uint32_t code = 0;
        std::uint32_t first_symbol = 0;
        for (std::size_t length = 1; length <= efi_code_bits; ++length) {
            code = (code + counts_[length - 1]) << 1;
            const auto capacity = std::uint32_t{1} << length;
            if (code + counts_[length] > capacity) return false;
            first_code_[length] = code;
            first_symbol_[length] = first_symbol;
            first_symbol += counts_[length];
        }
        if (code + counts_[efi_code_bits] != (std::uint32_t{1} << efi_code_bits)) return false;

        symbols_.resize(first_symbol);
        auto next_symbol = first_symbol_;
        for (std::size_t symbol = 0; symbol < lengths.size(); ++symbol) {
            const auto length = lengths[symbol];
            if (length != 0) symbols_[next_symbol[length]++] = static_cast<std::uint16_t>(symbol);
        }
        constant_ = false;
        return true;
    }

    bool constant(std::uint16_t symbol) {
        counts_.fill(0);
        first_code_.fill(0);
        first_symbol_.fill(0);
        symbols_.clear();
        constant_ = true;
        constant_symbol_ = symbol;
        return true;
    }

    bool decode(EfiBitReader &reader, std::uint16_t &symbol) const {
        if (constant_) {
            symbol = constant_symbol_;
            return reader.consume_work();
        }
        std::uint32_t code = 0;
        for (std::size_t length = 1; length <= efi_code_bits; ++length) {
            std::uint32_t bit = 0;
            if (!reader.read(1, bit)) return false;
            code = (code << 1) | bit;
            const auto first = first_code_[length];
            if (code >= first && code - first < counts_[length]) {
                const auto index = first_symbol_[length] + code - first;
                if (index >= symbols_.size()) return false;
                symbol = symbols_[index];
                return true;
            }
        }
        return false;
    }

private:
    std::array<std::uint16_t, efi_code_bits + 1> counts_{};
    std::array<std::uint32_t, efi_code_bits + 1> first_code_{};
    std::array<std::uint32_t, efi_code_bits + 1> first_symbol_{};
    std::vector<std::uint16_t> symbols_;
    bool constant_ = false;
    std::uint16_t constant_symbol_ = 0;
};

class EfiLzhDecoder {
public:
    EfiLzhDecoder(std::span<const std::byte> compressed, std::size_t expected,
                  std::size_t position_bits, EfiDecodeBudget &budget, std::vector<std::byte> &output)
        : reader_(compressed, budget), output_(output), expected_(expected), position_bits_(position_bits) {}

    bool decode() {
        output_.resize(expected_);
        while (output_offset_ < expected_) {
            std::uint16_t character = 0;
            if (!decode_character(character)) return false;
            if (character < 256) {
                if (!emit(static_cast<std::uint8_t>(character))) return false;
                continue;
            }
            const auto match_length = std::size_t(character) - (0xffu + 1u - efi_match_threshold);
            std::uint32_t position = 0;
            if (match_length == 0 || match_length > efi_max_match || !decode_position(position)) return false;
            const auto distance = std::uint64_t(position) + 1;
            if (distance > output_offset_ || match_length > expected_ - output_offset_) return false;
            for (std::size_t i = 0; i < match_length; ++i) {
                if (!reader_.consume_work()) return false;
                output_[output_offset_] = output_[output_offset_ - static_cast<std::size_t>(distance)];
                ++output_offset_;
            }
        }
        return true;
    }

private:
    bool read_bits(std::size_t count, std::uint32_t &value) { return reader_.read(count, value); }

    bool read_position_lengths(std::size_t count, std::size_t bit_count,
                               std::optional<std::size_t> special) {
        if (count == 0 || count > efi_npt || bit_count == 0 || bit_count > 5) return false;
        std::uint32_t number = 0;
        if (!read_bits(bit_count, number) || number > count) return false;
        std::vector<std::uint8_t> lengths(count, 0);
        if (number == 0) {
            std::uint32_t constant = 0;
            if (!read_bits(bit_count, constant) || constant >= count) return false;
            position_tree_.constant(static_cast<std::uint16_t>(constant));
            return true;
        }
        std::size_t index = 0;
        while (index < number) {
            if (!reader_.consume_work()) return false;
            std::uint32_t peek = 0;
            if (!reader_.peek(3, peek)) return false;
            std::uint32_t length = peek;
            if (length == 7) {
                std::size_t consumed = 3;
                for (;;) {
                    std::uint32_t remaining = 0;
                    if (!reader_.peek(consumed + 1, remaining)) return false;
                    const auto bit = remaining & 1u;
                    if (!bit) break;
                    ++consumed;
                    if (++length > 16) return false;
                }
                ++consumed; // Include the terminating zero after the run of ones.
                std::uint32_t ignored = 0;
                if (!read_bits(consumed, ignored)) return false;
                lengths[index++] = static_cast<std::uint8_t>(length);
                if (special && index == *special) {
                    std::uint32_t zero_count = 0;
                    if (!read_bits(2, zero_count) || zero_count > count - index) return false;
                    index += zero_count;
                }
                continue;
            }
            std::uint32_t ignored = 0;
            if (!read_bits(3, ignored)) return false;
            lengths[index++] = static_cast<std::uint8_t>(length);
            if (special && index == *special) {
                std::uint32_t zero_count_minus_one = 0;
                if (!read_bits(2, zero_count_minus_one)) return false;
                const auto zero_count = zero_count_minus_one;
                if (zero_count > count - index) return false;
                index += zero_count;
            }
        }
        return reader_.consume_work(count) && position_tree_.build(lengths);
    }

    bool read_character_lengths() {
        std::uint32_t number = 0;
        if (!read_bits(9, number) || number > efi_nc) return false;
        std::vector<std::uint8_t> lengths(efi_nc, 0);
        if (number == 0) {
            std::uint32_t constant = 0;
            if (!read_bits(9, constant) || constant >= efi_nc) return false;
            character_tree_.constant(static_cast<std::uint16_t>(constant));
            return true;
        }

        std::size_t index = 0;
        while (index < number) {
            if (!reader_.consume_work()) return false;
            std::uint16_t character = 0;
            if (!position_tree_.decode(reader_, character) || character >= efi_nt) return false;
            if (character <= 2) {
                std::uint32_t run_minus_one = 0;
                std::size_t run = 1;
                if (character == 1) {
                    if (!read_bits(4, run_minus_one)) return false;
                    run += run_minus_one + 2;
                } else if (character == 2) {
                    if (!read_bits(9, run_minus_one)) return false;
                    run += run_minus_one + 19;
                }
                if (run > efi_nc - index) return false;
                index += run;
            } else {
                if (index >= number || character - 2 > efi_code_bits) return false;
                lengths[index++] = static_cast<std::uint8_t>(character - 2);
            }
        }
        return reader_.consume_work(efi_nc) && character_tree_.build(lengths);
    }

    bool decode_character(std::uint16_t &character) {
        if (block_size_ == 0) {
            std::uint32_t block = 0;
            if (!read_bits(16, block) || block == 0) return false;
            if (++block_count_ > max_blocks_) return false;
            block_size_ = block;
            if (!read_position_lengths(efi_nt, 5, 3) || !read_character_lengths() ||
                !read_position_lengths(efi_max_np, position_bits_, std::nullopt)) return false;
        }
        --block_size_;
        return character_tree_.decode(reader_, character);
    }

    bool decode_position(std::uint32_t &position) {
        std::uint16_t symbol = 0;
        if (!position_tree_.decode(reader_, symbol) || symbol >= efi_max_np) return false;
        position = symbol;
        if (symbol <= 1) return true;
        std::uint32_t extra = 0;
        if (!read_bits(symbol - 1, extra)) return false;
        position = (std::uint32_t{1} << (symbol - 1)) + extra;
        return true;
    }

    bool emit(std::uint8_t value) {
        if (output_offset_ >= expected_ || !reader_.consume_work()) return false;
        output_[output_offset_++] = static_cast<std::byte>(value);
        return true;
    }

    EfiBitReader reader_;
    std::vector<std::byte> &output_;
    std::size_t expected_ = 0;
    std::size_t position_bits_ = 4;
    std::size_t output_offset_ = 0;
    std::uint32_t block_size_ = 0;
    std::size_t block_count_ = 0;
    static constexpr std::size_t max_blocks_ = 65536;
    EfiHuffman position_tree_;
    EfiHuffman character_tree_;
};

bool decompress_efi_payload(std::span<const std::byte> payload, std::uint32_t section_output_size,
                            std::uint8_t compression_type,
                            EfiDecodeBudget &budget, std::vector<std::byte> &output,
                            std::string &reason) {
    if (compression_type != 1 && compression_type != 2) {
        reason = "unsupported EFI compression type";
        return false;
    }
    if (payload.size() < 8) {
        reason = "EFI-compressed payload has a truncated size preamble";
        return false;
    }
    const auto compressed_size = u32(payload, 0);
    const auto declared_output_size = u32(payload, 4);
    if (declared_output_size != section_output_size) {
        reason = "EFI-compressed payload output size disagrees with its section header";
        return false;
    }
    if (compressed_size != payload.size() - 8) {
        reason = "EFI-compressed payload extent does not match its preamble";
        return false;
    }
    if (payload.size() > budget.limits.max_compressed_section_bytes) {
        reason = "EFI-compressed source exceeds the per-section byte limit";
        return false;
    }
    if (declared_output_size > budget.limits.max_decompressed_section_bytes) {
        reason = "EFI-compressed output exceeds the per-section byte limit";
        return false;
    }
    if (declared_output_size > budget.limits.max_total_decompressed_bytes -
            std::min(budget.limits.max_total_decompressed_bytes, budget.total_output)) {
        reason = "UEFI cumulative decompressed-byte limit exceeded";
        return false;
    }
    if (declared_output_size > budget.limits.max_active_decompressed_bytes -
            std::min(budget.limits.max_active_decompressed_bytes, budget.active_output)) {
        reason = "UEFI active decompressed-byte limit exceeded";
        return false;
    }
    if (budget.stop.stop_requested()) {
        reason = "EFI decompression canceled";
        return false;
    }
    budget.active_output += declared_output_size;
    bool keep_active = false;
    struct ActiveOutputRollback {
        EfiDecodeBudget &budget;
        std::uint64_t size;
        bool &keep;
        ~ActiveOutputRollback() { if (!keep) budget.active_output -= size; }
    } rollback{budget, declared_output_size, keep_active};

    try {
        output.clear();
        if (declared_output_size == 0) {
            if (compressed_size != 0) {
                reason = "empty EFI-compressed output has a nonempty stream";
                return false;
            }
        } else {
            // Tiano's Huffman position alphabet has a 5-bit code-count field;
            // standard EFI uses 4 bits. The LZHUF block format is otherwise shared.
            const auto position_bits = compression_type == 2 ? tiano_position_bits : efi_position_bits;
            EfiLzhDecoder decoder(payload.subspan(8), declared_output_size, position_bits, budget, output);
            if (!decoder.decode()) {
                reason = budget.stop.stop_requested() ? "EFI decompression canceled" :
                    budget.work_remaining == 0 ? "EFI decompression work limit exceeded" :
                    "EFI-compressed bitstream or Huffman table is malformed or truncated";
                output.clear();
                return false;
            }
        }
    } catch (const std::bad_alloc &) {
        reason = "EFI decompression output allocation failed";
        output.clear();
        return false;
    }
    budget.total_output += declared_output_size;
    keep_active = true;
    return true;
}

bool parse_section_stream(std::span<const std::byte> bytes, std::uint64_t source_offset,
                          std::uint8_t erased, std::size_t max_sections,
                          std::size_t max_depth, std::size_t &section_count,
                          std::vector<UefiFfsSection> &sections, std::uint32_t depth,
                          std::optional<std::size_t> parent, std::string &reason,
                          EfiDecodeBudget &decode_budget,
                          UefiSectionOffsetSpace offset_space = UefiSectionOffsetSpace::file) {
    if (depth > max_depth) {
        reason = "UEFI nested section depth limit exceeded";
        return false;
    }
    std::size_t cursor = 0;
    while (cursor < bytes.size()) {
        if (all_padding(bytes.subspan(cursor), erased)) return true;
        if (bytes.size() - cursor < 4) {
            reason = "truncated UEFI section header or non-padding tail";
            return false;
        }
        if (section_count >= max_sections) {
            reason = "UEFI firmware section-count limit exceeded";
            return false;
        }
        std::uint64_t section_size = u24(bytes, cursor);
        const auto type = u8(bytes, cursor + 3);
        std::uint64_t common_header_size = 4;
        if (section_size == 0x00ffffffu) {
            if (bytes.size() - cursor < 8) {
                reason = "truncated extended UEFI section header";
                return false;
            }
            section_size = u32(bytes, cursor + 4);
            common_header_size = 8;
        }
        if (section_size < common_header_size || section_size > bytes.size() - cursor) {
            reason = "UEFI section size is smaller than its header or exceeds its enclosing file";
            return false;
        }
        UefiFfsSection row;
        row.file_offset = source_offset + cursor;
        row.size = section_size;
        row.header_size = common_header_size;
        row.payload_offset = row.file_offset + common_header_size;
        row.payload_size = section_size - common_header_size;
        row.type = type;
        row.depth = depth;
        row.parent_index = parent;
        row.offset_space = offset_space;
        const auto row_index = sections.size();
        sections.push_back(std::move(row));
        ++section_count;
        const auto section_bytes = bytes.subspan(cursor, static_cast<std::size_t>(section_size));

        bool contains_sections = false;
        std::size_t nested_offset = static_cast<std::size_t>(common_header_size);
        if (type == section_compression) {
            if (section_size < common_header_size + 5) {
                reason = "UEFI compression section header is truncated";
                return false;
            }
            sections[row_index].uncompressed_size = u32(section_bytes, static_cast<std::size_t>(common_header_size));
            sections[row_index].compression_type = u8(section_bytes, static_cast<std::size_t>(common_header_size + 4));
            nested_offset += 5;
            sections[row_index].header_size = nested_offset;
            sections[row_index].payload_offset = sections[row_index].file_offset + nested_offset;
            sections[row_index].payload_size = section_size - nested_offset;
            if (*sections[row_index].compression_type == 0) {
                if (*sections[row_index].uncompressed_size != sections[row_index].payload_size) {
                    reason = "UEFI uncompressed section length does not match its payload";
                    return false;
                }
                sections[row_index].disposition = UefiSectionDisposition::nested_sections;
                contains_sections = true;
            } else if (*sections[row_index].compression_type == 1 ||
                       *sections[row_index].compression_type == 2) {
                std::vector<std::byte> decompressed;
                std::string decompression_reason;
                const auto compressed_payload = section_bytes.subspan(nested_offset);
                if (!decompress_efi_payload(compressed_payload, *sections[row_index].uncompressed_size,
                                            *sections[row_index].compression_type, decode_budget,
                                            decompressed, decompression_reason)) {
                    sections[row_index].disposition = UefiSectionDisposition::opaque_compressed;
                    sections[row_index].diagnostic = std::move(decompression_reason);
                } else {
                    sections[row_index].decompression_succeeded = true;
                    const auto decoded_size = static_cast<std::uint64_t>(decompressed.size());
                    ActiveDecodeBuffer active_buffer{decode_budget, decoded_size};
                    std::string nested_reason;
                    const auto first_child = sections.size();
                    const auto section_count_before_children = section_count;
                    const bool nested_ok = parse_section_stream(decompressed, 0, erased, max_sections,
                        max_depth, section_count, sections, depth + 1, row_index, nested_reason,
                        decode_budget, UefiSectionOffsetSpace::decompressed);
                    if (nested_ok) {
                        sections[row_index].disposition = UefiSectionDisposition::decompressed_sections;
                    } else {
                        sections.resize(first_child);
                        section_count = section_count_before_children;
                        sections[row_index].disposition = UefiSectionDisposition::opaque_compressed;
                        sections[row_index].diagnostic = "EFI stream decoded, but its nested section stream is invalid: " + nested_reason;
                    }
                }
            } else {
                sections[row_index].disposition = UefiSectionDisposition::opaque_compressed;
                sections[row_index].diagnostic = "unknown UEFI compression type is retained without interpretation";
            }
        } else if (type == section_guid_defined) {
            if (section_size < common_header_size + 20) {
                reason = "UEFI GUID-defined section header is truncated";
                return false;
            }
            std::array<std::uint8_t, 16> guid{};
            for (std::size_t i = 0; i < guid.size(); ++i)
                guid[i] = u8(section_bytes, static_cast<std::size_t>(common_header_size) + i);
            const auto data_offset = u16(section_bytes, static_cast<std::size_t>(common_header_size) + 16);
            const auto attributes = u16(section_bytes, static_cast<std::size_t>(common_header_size) + 18);
            if (data_offset < common_header_size + 20 || data_offset > section_size) {
                reason = "UEFI GUID-defined section data offset is outside its section";
                return false;
            }
            sections[row_index].definition_guid = guid;
            sections[row_index].definition_data_offset = data_offset;
            sections[row_index].definition_attributes = attributes;
            sections[row_index].header_size = data_offset;
            sections[row_index].payload_offset = sections[row_index].file_offset + data_offset;
            sections[row_index].payload_size = section_size - data_offset;
            if (attributes & guid_processing_required) {
                sections[row_index].disposition = UefiSectionDisposition::processing_required;
                sections[row_index].diagnostic = "GUID-defined payload requires an unavailable processor and is retained opaque";
            } else {
                // PI permits consumers to use the bytes at DataOffset directly
                // when no extraction processor is required. In that case they
                // are an ordinary nested section stream, irrespective of GUID.
                sections[row_index].disposition = UefiSectionDisposition::nested_sections;
                contains_sections = true;
                nested_offset = data_offset;
            }
        } else if (type == section_disposable) {
            sections[row_index].disposition = UefiSectionDisposition::nested_sections;
            contains_sections = true;
        } else if (type == section_user_interface) {
            std::u16string name;
            std::string text_reason;
            if (!parse_section_utf16(section_bytes.subspan(static_cast<std::size_t>(common_header_size)),
                                     name, text_reason)) {
                reason = "invalid UEFI user-interface section: " + text_reason;
                return false;
            }
            sections[row_index].ui_name = std::move(name);
        } else if (type == section_version) {
            if (section_size < common_header_size + 4) {
                reason = "UEFI version section is truncated";
                return false;
            }
            std::u16string version;
            std::string text_reason;
            if (!parse_section_utf16(section_bytes.subspan(static_cast<std::size_t>(common_header_size + 2)),
                                     version, text_reason)) {
                reason = "invalid UEFI version section: " + text_reason;
                return false;
            }
            sections[row_index].version_build = u16(section_bytes, static_cast<std::size_t>(common_header_size));
            sections[row_index].version_text = std::move(version);
            sections[row_index].header_size = common_header_size + 2;
            sections[row_index].payload_offset = sections[row_index].file_offset + common_header_size + 2;
            sections[row_index].payload_size = section_size - common_header_size - 2;
        } else if (type == section_freeform_subtype_guid) {
            if (section_size < common_header_size + 16) {
                reason = "UEFI freeform subtype-GUID section is truncated";
                return false;
            }
            std::array<std::uint8_t, 16> subtype_guid{};
            for (std::size_t i = 0; i < subtype_guid.size(); ++i)
                subtype_guid[i] = u8(section_bytes, static_cast<std::size_t>(common_header_size) + i);
            sections[row_index].freeform_subtype_guid = subtype_guid;
            sections[row_index].header_size = common_header_size + subtype_guid.size();
            sections[row_index].payload_offset = sections[row_index].file_offset + sections[row_index].header_size;
            sections[row_index].payload_size = section_size - sections[row_index].header_size;
        }

        if (contains_sections) {
            std::string nested_reason;
            const auto first_child = sections.size();
            const auto section_count_before_children = section_count;
            const bool nested_ok = parse_section_stream(section_bytes.subspan(nested_offset),
                sections[row_index].file_offset + nested_offset, erased, max_sections, max_depth,
                section_count, sections, depth + 1, row_index, nested_reason,
                decode_budget, offset_space);
            if (!nested_ok) {
                sections.resize(first_child);
                section_count = section_count_before_children;
                // A disposable section may contain implementation-specific
                // descriptive data. Failed nested parsing leaves it visible.
                if (type == section_disposable) {
                    sections[row_index].disposition = UefiSectionDisposition::malformed_nested_payload;
                    sections[row_index].diagnostic = std::move(nested_reason);
                } else {
                    reason = std::move(nested_reason);
                    return false;
                }
            }
        }

        const auto section_end = cursor + static_cast<std::size_t>(section_size);
        const auto aligned_end = (section_end + 3u) & ~std::size_t{3};
        if (aligned_end > bytes.size()) {
            if (section_end == bytes.size()) return true;
            reason = "UEFI section alignment exceeds its enclosing file";
            return false;
        }
        if (aligned_end > section_end && !all_padding(bytes.subspan(section_end, aligned_end - section_end), erased)) {
            reason = "UEFI section alignment bytes are not padding";
            return false;
        }
        cursor = aligned_end;
    }
    return true;
}

Result<UefiFirmwareVolume> parse_volume(std::span<const std::byte> bytes, std::size_t start,
                                        std::size_t max_files, std::size_t max_sections,
                                        std::size_t max_section_depth, std::size_t &section_count,
                                        EfiDecodeBudget &decode_budget, std::stop_token stop) {
    constexpr std::size_t fixed = 56;
    if (start > bytes.size() || bytes.size() - start < fixed + 8)
        return Error{ErrorCode::malformed, "UEFI firmware volume header is truncated"};
    if (!std::equal(fv_signature.begin(), fv_signature.end(),
                    bytes.begin() + static_cast<std::ptrdiff_t>(start + 40),
                    [](std::uint8_t expected, std::byte actual) { return expected == std::to_integer<std::uint8_t>(actual); }))
        return Error{ErrorCode::malformed, "UEFI firmware volume signature is invalid"};

    const auto fv_length = u64(bytes, start + 32);
    const auto header_length = u16(bytes, start + 48);
    if (fv_length < fixed + 8 || fv_length > bytes.size() - start)
        return Error{ErrorCode::out_of_bounds, "UEFI firmware volume length is outside the input"};
    if (header_length < fixed + 8 || header_length > fv_length || (header_length & 1u) != 0 ||
        header_length > max_header_bytes)
        return Error{ErrorCode::malformed, "UEFI firmware volume header length is invalid"};
    const auto revision = u8(bytes, start + 55);
    if (revision != 2)
        return Error{ErrorCode::unsupported, "UEFI firmware volume revision is unsupported"};
    if (u8(bytes, start + 54) != 0)
        return Error{ErrorCode::malformed, "UEFI firmware volume reserved header byte is nonzero"};
    unsigned header_sum = 0;
    for (std::size_t i = 0; i < header_length; i += 2)
        header_sum = (header_sum + u16(bytes, start + i)) & 0xffffu;
    if (header_sum != 0)
        return Error{ErrorCode::integrity, "UEFI firmware volume header checksum is invalid"};

    UefiFirmwareVolume volume;
    volume.file_offset = start;
    volume.length = fv_length;
    volume.attributes = u32(bytes, start + 44);
    volume.header_length = header_length;
    volume.revision = revision;
    volume.header_checksum_valid = true;
    for (std::size_t i = 0; i < volume.file_system_guid.size(); ++i)
        volume.file_system_guid[i] = u8(bytes, start + 16 + i);
    const bool ffs2 = volume.file_system_guid == ffs2_guid;
    const bool ffs3 = volume.file_system_guid == ffs3_guid;
    if (!ffs2 && !ffs3)
        return Error{ErrorCode::unsupported, "UEFI volume uses an unrecognized file-system GUID"};

    std::uint64_t mapped_bytes = 0;
    bool map_terminated = false;
    std::size_t block_map_end = 0;
    for (std::size_t p = fixed; p + 8 <= header_length; p += 8) {
        const auto count = u32(bytes, start + p);
        const auto block_size = u32(bytes, start + p + 4);
        if (count == 0 || block_size == 0) {
            if (count != 0 || block_size != 0)
                return Error{ErrorCode::malformed, "UEFI firmware volume block map has a partial terminator"};
            map_terminated = true;
            block_map_end = p + 8;
            break;
        }
        if (std::uint64_t(count) > (UINT64_MAX - mapped_bytes) / block_size)
            return Error{ErrorCode::overflow, "UEFI firmware volume block map overflows"};
        mapped_bytes += std::uint64_t(count) * block_size;
    }
    if (!map_terminated || mapped_bytes != fv_length)
        return Error{ErrorCode::malformed, "UEFI firmware volume block map does not match its declared length"};

    const auto extended_header_offset = u16(bytes, start + 52);
    if (extended_header_offset != 0) {
        const auto ext = static_cast<std::size_t>(extended_header_offset);
        constexpr std::size_t ext_header_fixed = 20;
        if ((ext & 3u) != 0 || ext < block_map_end || ext > header_length ||
            header_length - ext < ext_header_fixed)
            return Error{ErrorCode::malformed, "UEFI firmware-volume extended-header offset is invalid"};
        const auto ext_size = u32(bytes, start + ext + 16);
        if (ext_size < ext_header_fixed || ext_size > header_length - ext)
            return Error{ErrorCode::malformed, "UEFI firmware-volume extended-header size is invalid"};
        std::array<std::uint8_t, 16> name_guid{};
        for (std::size_t i = 0; i < name_guid.size(); ++i)
            name_guid[i] = u8(bytes, start + ext + i);
        volume.extended_header_name_guid = name_guid;
        volume.extended_header_size = ext_size;

        std::size_t entry = ext + ext_size;
        while (entry < header_length) {
            const auto remaining = header_length - entry;
            const auto tail = bytes.subspan(start + entry, remaining);
            if (all_value(tail, 0)) break; // zero-filled header alignment padding
            if (remaining < 4)
                return Error{ErrorCode::malformed, "UEFI firmware-volume extension entry header is truncated"};
            const auto entry_size = u16(bytes, start + entry);
            const auto entry_type = u16(bytes, start + entry + 2);
            if (entry_size < 4 || entry_size > remaining)
                return Error{ErrorCode::malformed, "UEFI firmware-volume extension entry size is invalid"};
            if (volume.extension_entries.size() >= max_fv_extension_entries)
                return Error{ErrorCode::resource_limit, "UEFI firmware-volume extension-entry limit exceeded"};
            volume.extension_entries.push_back({entry_type, entry_size, entry,
                                                entry + 4, static_cast<std::uint64_t>(entry_size - 4u)});
            entry += entry_size;
        }
    }

    const std::uint8_t erased = (volume.attributes & 0x800u) ? 0xff : 0x00;
    std::uint64_t cursor = (std::uint64_t(header_length) + 7u) & ~std::uint64_t{7};
    while (cursor <= fv_length && fv_length - cursor >= 24) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI firmware volume parsing canceled"};
        const auto remaining = bytes.subspan(start + static_cast<std::size_t>(cursor),
                                             static_cast<std::size_t>(fv_length - cursor));
        if ((remaining.size() < 24 && all_value(remaining, erased)) ||
            (remaining.size() >= 24 && all_value(remaining.first(8), erased))) break;
        const auto file_start = start + static_cast<std::size_t>(cursor);
        const auto attributes = u8(bytes, file_start + 19);
        const bool large_file = (attributes & 0x01u) != 0;
        const std::uint64_t header_size = large_file ? 32 : 24;
        if (fv_length - cursor < header_size)
            return Error{ErrorCode::malformed, "UEFI FFS file header is truncated"};
        std::uint64_t file_size = u24(bytes, file_start + 20);
        if (large_file) {
            if (!ffs3 || file_size != 0)
                return Error{ErrorCode::malformed, "UEFI large FFS file is invalid for this volume"};
            file_size = u64(bytes, file_start + 24);
            if (file_size < header_size)
                return Error{ErrorCode::malformed, "UEFI large FFS file size is smaller than its header"};
        } else if (file_size < header_size) {
            return Error{ErrorCode::malformed, "UEFI FFS file size is smaller than its header"};
        }
        if (file_size > fv_length - cursor)
            return Error{ErrorCode::out_of_bounds, "UEFI FFS file extends beyond its firmware volume"};
        if (volume.files.size() >= max_files)
            return Error{ErrorCode::resource_limit, "UEFI firmware volume file-count limit exceeded"};

        // A valid FFS header checksum treats the file checksum and state fields as zero.
        unsigned file_header_sum = 0;
        for (std::size_t i = 0; i < header_size; ++i) {
            auto value = u8(bytes, file_start + i);
            if (i == 17 || i == 23) value = 0;
            file_header_sum = (file_header_sum + value) & 0xffu;
        }
        const auto physical_state = u8(bytes, file_start + 23);
        const auto state = static_cast<std::uint8_t>(physical_state ^ erased);
        if (state & 0xc0u)
            return Error{ErrorCode::malformed, "UEFI FFS reserved state bits do not match erase polarity"};
        const bool header_checksum_valid = file_header_sum == 0;
        if ((state & 0x02u) != 0 && !header_checksum_valid)
            return Error{ErrorCode::integrity, "UEFI FFS header checksum is invalid"};

        UefiFfsFile file;
        for (std::size_t i = 0; i < file.name_guid.size(); ++i)
            file.name_guid[i] = u8(bytes, file_start + i);
        file.volume_offset = cursor;
        file.size = file_size;
        file.data_offset = cursor + header_size;
        file.data_size = file_size - header_size;
        file.type = u8(bytes, file_start + 18);
        file.attributes = attributes;
        file.state = state;
        file.disposition = classify_ffs_state(state);
        file.header_size = static_cast<std::uint8_t>(header_size);
        file.header_checksum_valid = header_checksum_valid;
        std::string section_error;
        const auto file_data_begin = file_start + static_cast<std::size_t>(header_size);
        const auto file_data = bytes.subspan(file_data_begin, static_cast<std::size_t>(file.data_size));
        const bool file_data_valid = (state & ffs_state_data_valid) != 0 &&
            (state & (ffs_state_deleted | ffs_state_header_invalid)) == 0;
        if (file_data_valid) {
            std::uint8_t expected_checksum = ffs_fixed_checksum;
            if ((attributes & ffs_attribute_checksum) != 0) {
                std::uint8_t sum = 0;
                for (const auto byte : file_data)
                    sum = static_cast<std::uint8_t>(sum + std::to_integer<std::uint8_t>(byte));
                expected_checksum = static_cast<std::uint8_t>(0u - sum);
            }
            file.data_checksum_valid = u8(bytes, file_start + 17) == expected_checksum;
        }
        if (file_data_valid) {
            if (!parse_section_stream(file_data, file_data_begin, erased, max_sections, max_section_depth,
                                      section_count, file.sections, 0, {}, section_error, decode_budget))
                file.section_diagnostic = std::move(section_error);
        } else {
            file.section_diagnostic = "file data is not in the EFI_FILE_DATA_VALID state; sections were not parsed";
        }
        volume.files.push_back(std::move(file));

        if (file_size > UINT64_MAX - cursor - 7u)
            return Error{ErrorCode::overflow, "UEFI FFS next-header offset overflows"};
        cursor = (cursor + file_size + 7u) & ~std::uint64_t{7};
    }
    return volume;
}
} // namespace

Result<std::vector<UefiFirmwareVolume>> parse_uefi_firmware_volumes(
    std::span<const std::byte> bytes, UefiVolumeParseOptions options, std::stop_token stop) try {
    if (bytes.empty() || options.max_input_bytes == 0 || options.max_volumes == 0 || options.max_files == 0 ||
        options.max_sections == 0 || options.max_section_depth == 0 ||
        options.max_compressed_section_bytes == 0 || options.max_decompressed_section_bytes == 0 ||
        options.max_total_decompressed_bytes == 0 || options.max_active_decompressed_bytes == 0 ||
        options.max_decompression_work == 0)
        return Error{ErrorCode::invalid_argument, "UEFI firmware volume input and limits must be nonzero"};
    if (bytes.size() > options.max_input_bytes)
        return Error{ErrorCode::resource_limit, "UEFI firmware image exceeds the configured input limit"};
    if (bytes.size() < 44)
        return Error{ErrorCode::malformed, "Input is too short to contain a UEFI firmware volume"};
    std::vector<UefiFirmwareVolume> result;
    std::size_t cursor = 0, total_files = 0, total_sections = 0;
    EfiDecodeBudget decode_budget{options, options.max_decompression_work, 0, 0, stop};
    while (cursor <= bytes.size() - 44) {
        if ((cursor & 0xffffu) == 0 && stop.stop_requested())
            return Error{ErrorCode::canceled, "UEFI firmware volume scanning canceled"};
        const bool match = std::equal(fv_signature.begin(), fv_signature.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(cursor + 40),
            [](std::uint8_t expected, std::byte actual) { return expected == std::to_integer<std::uint8_t>(actual); });
        if (!match) { ++cursor; continue; }
        auto parsed = parse_volume(bytes, cursor, options.max_files,
                                   options.max_sections - std::min(options.max_sections, total_sections),
                                   options.max_section_depth, total_sections, decode_budget, stop);
        if (!parsed) { ++cursor; continue; }
        if (result.size() >= options.max_volumes)
            return Error{ErrorCode::resource_limit, "UEFI firmware volume-count limit exceeded"};
        if (parsed.value().files.size() > options.max_files - std::min(options.max_files, total_files))
            return Error{ErrorCode::resource_limit, "UEFI firmware image file-count limit exceeded"};
        total_files += parsed.value().files.size();
        result.push_back(std::move(parsed.value()));
        // Continue scanning within a valid volume as well. PI firmware-volume
        // image sections can contain another complete FV, and the full header,
        // checksum, block-map, and filesystem-GUID validation above keeps
        // arbitrary signature bytes from being reported as nested volumes.
        // Global volume/file/section/decompression budgets still apply.
        ++cursor;
    }
    if (result.empty())
        return Error{ErrorCode::unsupported, "No valid PI firmware volume with FFS2 or FFS3 was found"};
    return result;
} catch (const std::bad_alloc &) {
    return Error{ErrorCode::resource_limit, "Cannot allocate UEFI firmware volume metadata"};
}

std::string uefi_guid_string(const std::array<std::uint8_t, 16> &g) {
    constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    auto byte = [&](std::size_t i) {
        out.push_back(hex[g[i] >> 4]); out.push_back(hex[g[i] & 0x0f]);
    };
    // EFI_GUID's first three fields are little-endian in firmware storage.
    byte(3); byte(2); byte(1); byte(0); out.push_back('-');
    byte(5); byte(4); out.push_back('-'); byte(7); byte(6); out.push_back('-');
    byte(8); byte(9); out.push_back('-');
    for (std::size_t i = 10; i < 16; ++i) byte(i);
    return out;
}
} // namespace hexlab::firmware
