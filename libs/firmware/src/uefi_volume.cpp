#include "hexlab/firmware/uefi_volume.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <utility>

extern "C" {
#include "Bra.h"
#include "LzmaDec.h"
#include <brotli/decode.h>
}

namespace hexlab::firmware {
namespace {
constexpr std::array<std::uint8_t, 4> fv_signature{'_', 'F', 'V', 'H'};
constexpr std::array<std::uint8_t, 16> ffs2_guid{
    0x78,0xe5,0x8c,0x8c,0x3d,0x8a,0x1c,0x4f,0x99,0x35,0x89,0x61,0x85,0xc3,0x2d,0xd3};
constexpr std::array<std::uint8_t, 16> ffs3_guid{
    0x7a,0xc0,0x73,0x54,0xcb,0x3d,0xca,0x4d,0xbd,0x6f,0x1e,0x96,0x89,0xe7,0x34,0x9a};
// EFI CRC32 guided-section extraction GUID, stored in EFI_GUID wire order.
constexpr std::array<std::uint8_t, 16> crc32_guid{
    0xb0,0xcd,0x1b,0xfc,0x31,0x7d,0xaa,0x49,0x93,0x6a,0xa4,0x60,0x0d,0x9d,0xd0,0x83};
// Tiano custom decompression GUID, in EFI_GUID wire order.
constexpr std::array<std::uint8_t, 16> tiano_decompress_guid{
    0xad,0x80,0x12,0xa3,0x1e,0x48,0xb6,0x41,0x95,0xe8,0x12,0x7f,0x4c,0x98,0x47,0x79};
// LZMA custom decompression GUID from EDK II MdeModulePkg/Include/Guid/LzmaDecompress.h.
constexpr std::array<std::uint8_t, 16> lzma_decompress_guid{
    0x98,0x58,0x4e,0xee,0x14,0x39,0x59,0x42,0x9d,0x6e,0xdc,0x7b,0xd7,0x94,0x03,0xcf};
// LZMAF86 custom decompression GUID from EDK II, in EFI wire order.
constexpr std::array<std::uint8_t, 16> lzmaf86_decompress_guid{
    0xbd,0xe6,0x2a,0xd4,0x52,0x13,0xfb,0x4b,0x90,0x9a,0xca,0x72,0xa6,0xea,0xe8,0x89};
// EDK II Brotli custom decompression GUID, in EFI_GUID wire order.
constexpr std::array<std::uint8_t, 16> brotli_decompress_guid{
    0x50,0x20,0x53,0x3d,0xda,0x5c,0xd0,0x4f,0x87,0x9e,0x0f,0x7f,0x63,0x0d,0x5a,0xfb};
// EFI_APRIORI_GUID from EDK II MdePkg/Include/Guid/Apriori.h, in EFI wire order.
constexpr std::array<std::uint8_t, 16> dxe_apriori_file_guid{
    0xe7,0x0e,0x51,0xfc,0xdc,0xff,0xd4,0x11,0xbd,0x41,0x00,0x80,0xc7,0x3c,0x88,0x81};
// PEI_APRIORI_FILE_NAME_GUID from PI Vol. 1, in EFI_GUID wire order.
constexpr std::array<std::uint8_t, 16> pei_apriori_file_guid{
    0x0a,0xcc,0x45,0x1b,0x6a,0x15,0x8a,0x42,0xaf,0x62,0x49,0x86,0x4d,0xa0,0xe6,0xe6};
constexpr std::uint64_t max_header_bytes = 16ull * 1024 * 1024;
constexpr std::size_t max_fv_extension_entries = 65536;
constexpr std::uint32_t section_compression = 0x01;
constexpr std::uint32_t section_guid_defined = 0x02;
constexpr std::uint32_t section_disposable = 0x03;
constexpr std::uint32_t section_version = 0x14;
constexpr std::uint32_t section_user_interface = 0x15;
constexpr std::uint32_t section_firmware_volume_image = 0x17;
constexpr std::uint32_t section_freeform_subtype_guid = 0x18;
constexpr std::uint32_t section_raw = 0x19;
constexpr std::uint8_t section_dxe_depex = 0x13, section_pei_depex = 0x1b, section_mm_depex = 0x1c;
constexpr std::uint16_t guid_processing_required = 0x0001;
constexpr std::size_t max_section_text_units = 4096;
constexpr std::size_t max_depex_instructions = 4096;
constexpr std::size_t max_apriori_file_guids = 4096;
constexpr std::uint8_t ffs_attribute_checksum = 0x40;
constexpr std::uint8_t ffs_fixed_checksum = 0xaa;
constexpr std::uint8_t ffs_state_header_construction = 0x01;
constexpr std::uint8_t ffs_state_header_valid = 0x02;
constexpr std::uint8_t ffs_state_data_valid = 0x04;
constexpr std::uint8_t ffs_state_marked_for_update = 0x08;
constexpr std::uint8_t ffs_state_deleted = 0x10;
constexpr std::uint8_t ffs_state_header_invalid = 0x20;
constexpr std::uint8_t ffs_file_type_pad = 0xf0;
constexpr std::uint64_t max_lzma_dictionary_bytes = 16ull * 1024 * 1024;
constexpr std::size_t lzma_output_chunk_bytes = 64 * 1024;
constexpr std::size_t brotli_io_chunk_bytes = 64 * 1024;

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

struct DepexSummary {
    bool valid = false;
    std::uint32_t instruction_count = 0, guid_operand_count = 0, max_stack_depth = 0;
    std::string diagnostic;
};

DepexSummary inspect_depex(std::span<const std::byte> bytes, std::uint8_t section_type) {
    DepexSummary result;
    const bool dxe = section_type == section_dxe_depex;
    const bool pei = section_type == section_pei_depex;
    if (!dxe && !pei && section_type != section_mm_depex) {
        result.diagnostic = "unsupported dependency-expression section type";
        return result;
    }
    const bool dxe_or_mm = dxe || section_type == section_mm_depex;
    // PI defines an empty DXE dependency expression as a distinct valid form.
    if (bytes.empty()) {
        result.valid = true;
        return result;
    }
    std::size_t cursor = 0;
    std::uint32_t stack_depth = 0;
    bool saw_sor = false;
    const auto invalid = [&](const char *message) {
        result.valid = false;
        result.diagnostic = message;
        return result;
    };
    while (cursor < bytes.size()) {
        if (result.instruction_count >= max_depex_instructions)
            return invalid("dependency-expression instruction limit exceeded");
        const auto opcode_offset = cursor;
        const auto opcode = u8(bytes, cursor++);
        ++result.instruction_count;
        if (opcode == 0x00 || opcode == 0x01 || opcode == 0x02) {
            if ((opcode <= 0x01 && (!dxe_or_mm || opcode_offset != 0)) || bytes.size() - cursor < 16)
                return invalid("dependency-expression GUID operand is invalid or truncated");
            cursor += 16;
            ++result.guid_operand_count;
            if (opcode <= 0x01) {
                // BEFORE/AFTER is a standalone ordering expression followed only by END.
                if (cursor >= bytes.size() || u8(bytes, cursor) != 0x08 || cursor + 1 != bytes.size())
                    return invalid("BEFORE/AFTER must be followed immediately by the final END opcode");
                ++cursor;
                ++result.instruction_count;
                result.valid = true;
                return result;
            }
            ++stack_depth;
        } else if (opcode == 0x03 || opcode == 0x04) {
            if (stack_depth < 2) return invalid("dependency-expression binary operator underflows its stack");
            --stack_depth;
        } else if (opcode == 0x05) {
            if (stack_depth < 1) return invalid("dependency-expression NOT operator underflows its stack");
        } else if (opcode == 0x06 || opcode == 0x07) {
            ++stack_depth;
        } else if (opcode == 0x08) {
            if (cursor != bytes.size() || stack_depth != 1)
                return invalid("dependency-expression END is not final or leaves an invalid stack");
            result.valid = true;
            return result;
        } else if (opcode == 0x09) {
            if ((dxe || section_type == section_mm_depex) && opcode_offset == 0 && !saw_sor) {
                saw_sor = true;
            } else return invalid("dependency-expression SOR must be the first DXE/MM opcode");
        } else return invalid("dependency-expression contains an unsupported opcode");
        result.max_stack_depth = std::max(result.max_stack_depth, stack_depth);
    }
    return invalid(saw_sor ? "SOR has no terminating dependency expression" :
                             "dependency expression has no final END opcode");
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
    std::uint64_t guided_crc_bytes = 0;
    std::stop_token stop;
};

bool calculate_guided_crc32(std::span<const std::byte> bytes, EfiDecodeBudget &budget,
                            std::uint32_t &value, std::string &reason) {
    const auto limit = budget.limits.max_guided_crc_bytes;
    if (bytes.size() > limit - std::min(limit, budget.guided_crc_bytes)) {
        reason = "UEFI GUID-defined CRC32 byte-work limit exceeded";
        return false;
    }
    budget.guided_crc_bytes += bytes.size();
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if ((i & 0xfffu) == 0 && budget.stop.stop_requested()) {
            reason = "UEFI GUID-defined CRC32 calculation canceled";
            return false;
        }
        crc ^= std::to_integer<std::uint8_t>(bytes[i]);
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    if (budget.stop.stop_requested()) {
        reason = "UEFI GUID-defined CRC32 calculation canceled";
        return false;
    }
    value = ~crc;
    return true;
}

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

struct LzmaAllocationHeader { std::max_align_t alignment; std::size_t size; };
struct LzmaAllocator {
    ISzAlloc api{};
    std::uint64_t bytes = 0;
    std::uint64_t limit = 0;
};

void *lzma_allocate(ISzAllocPtr allocator, size_t size) {
    auto &state = *reinterpret_cast<LzmaAllocator *>(const_cast<ISzAlloc *>(allocator));
    if (size > state.limit - std::min(state.limit, state.bytes) ||
        size > std::numeric_limits<std::size_t>::max() - sizeof(LzmaAllocationHeader)) return nullptr;
    auto *header = static_cast<LzmaAllocationHeader *>(std::malloc(sizeof(LzmaAllocationHeader) + size));
    if (!header) return nullptr;
    header->size = size;
    state.bytes += size;
    return header + 1;
}

void lzma_free(ISzAllocPtr allocator, void *address) {
    if (!address) return;
    auto &state = *reinterpret_cast<LzmaAllocator *>(const_cast<ISzAlloc *>(allocator));
    auto *header = static_cast<LzmaAllocationHeader *>(address) - 1;
    state.bytes -= header->size;
    std::free(header);
}

bool decompress_lzma_guided(std::span<const std::byte> payload, EfiDecodeBudget &budget,
                            std::vector<std::byte> &output, std::uint32_t &decoded_size,
                            bool x86_filter, std::string &reason) {
    constexpr std::size_t lzma_header_bytes = 13; // 5 properties + UINT64 output size.
    constexpr std::uint64_t max_decoder_memory_bytes = 32ull * 1024 * 1024;
    if (payload.size() < lzma_header_bytes) {
        reason = "LZMA guided payload has a truncated properties/size header";
        return false;
    }
    if (payload.size() > budget.limits.max_compressed_section_bytes) {
        reason = "LZMA guided source exceeds the per-section byte limit";
        return false;
    }
    const auto declared = u64(payload, 5);
    if (declared > std::numeric_limits<std::uint32_t>::max() ||
        declared > budget.limits.max_decompressed_section_bytes) {
        reason = "LZMA guided output exceeds the per-section byte limit";
        return false;
    }
    const auto expected = static_cast<std::uint32_t>(declared);
    const auto compressed = payload.subspan(lzma_header_bytes);
    if (expected > budget.limits.max_total_decompressed_bytes -
            std::min(budget.limits.max_total_decompressed_bytes, budget.total_output)) {
        reason = "UEFI cumulative decompressed-byte limit exceeded";
        return false;
    }
    if (expected > budget.limits.max_active_decompressed_bytes -
            std::min(budget.limits.max_active_decompressed_bytes, budget.active_output)) {
        reason = "UEFI active decompressed-byte limit exceeded";
        return false;
    }
    CLzmaProps properties{};
    if (LzmaProps_Decode(&properties, reinterpret_cast<const Byte *>(payload.data()), LZMA_PROPS_SIZE) != SZ_OK) {
        reason = "LZMA guided properties are invalid";
        return false;
    }
    if (properties.dicSize > max_lzma_dictionary_bytes) {
        reason = "LZMA dictionary exceeds its 16 MiB limit";
        return false;
    }
    const auto work = std::uint64_t(compressed.size()) + std::uint64_t(expected) * (x86_filter ? 9 : 8);
    if (work < expected || work > budget.work_remaining) {
        reason = "LZMA guided decode work limit exceeded";
        return false;
    }
    if (budget.stop.stop_requested()) {
        reason = "LZMA guided decompression canceled";
        return false;
    }
    budget.work_remaining -= work;
    budget.active_output += expected;
    struct ActiveOutputGuard {
        EfiDecodeBudget &budget;
        std::uint64_t size;
        bool keep = false;
        ~ActiveOutputGuard() { if (!keep) budget.active_output -= size; }
    } active{budget, expected};

    LzmaAllocator allocator;
    allocator.api.Alloc = lzma_allocate;
    allocator.api.Free = lzma_free;
    allocator.limit = max_decoder_memory_bytes;
    CLzmaDec decoder;
    LzmaDec_Construct(&decoder);
    if (LzmaDec_Allocate(&decoder, reinterpret_cast<const Byte *>(payload.data()),
                         LZMA_PROPS_SIZE, &allocator.api) != SZ_OK) {
        reason = "LZMA decoder allocation failed or exceeded its memory limit";
        return false;
    }
    struct DecoderGuard {
        CLzmaDec &decoder;
        LzmaAllocator &allocator;
        ~DecoderGuard() { LzmaDec_Free(&decoder, &allocator.api); }
    } decoder_guard{decoder, allocator};
    LzmaDec_Init(&decoder);
    try {
        output.resize(expected);
    } catch (const std::bad_alloc &) {
        reason = "LZMA guided output allocation failed";
        return false;
    }
    std::size_t input_offset = 0;
    std::size_t output_offset = 0;
    while (output_offset < output.size()) {
        if (budget.stop.stop_requested()) {
            reason = "LZMA guided decompression canceled";
            output.clear();
            return false;
        }
        const auto out_capacity = std::min(lzma_output_chunk_bytes, output.size() - output_offset);
        SizeT out_length = out_capacity;
        SizeT in_length = compressed.size() - input_offset;
        ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
        const auto finish = output_offset + out_capacity == output.size() ? LZMA_FINISH_END : LZMA_FINISH_ANY;
        const auto result = LzmaDec_DecodeToBuf(&decoder,
            reinterpret_cast<Byte *>(output.data() + output_offset), &out_length,
            reinterpret_cast<const Byte *>(compressed.data() + input_offset), &in_length, finish, &status);
        input_offset += in_length;
        output_offset += out_length;
        if (result != SZ_OK || (out_length == 0 && in_length == 0) ||
            (status == LZMA_STATUS_FINISHED_WITH_MARK && output_offset != output.size())) {
            reason = "LZMA guided bitstream is malformed, truncated or does not match its declared output size";
            output.clear();
            return false;
        }
    }
    if (x86_filter) {
        std::size_t filter_offset = 0;
        UInt32 filter_state = 0;
        while (filter_offset < output.size()) {
            if (budget.stop.stop_requested()) {
                reason = "LZMAF86 conversion canceled";
                output.clear();
                return false;
            }
            const auto chunk_size = std::min(lzma_output_chunk_bytes, output.size() - filter_offset);
            auto *chunk = reinterpret_cast<Byte *>(output.data() + filter_offset);
            const auto processed = x86_Convert(chunk, chunk_size, static_cast<UInt32>(filter_offset),
                                               &filter_state, 0);
            if (processed == 0) {
                // The converter keeps up to four look-ahead bytes for the next
                // chunk; a final short tail has no possible complete branch.
                if (chunk_size >= 5) {
                    reason = "LZMAF86 converter made no progress on a full chunk";
                    output.clear();
                    return false;
                }
                break;
            }
            filter_offset += processed;
        }
    }
    if (input_offset != compressed.size()) {
        reason = "LZMA guided stream has trailing compressed bytes";
        output.clear();
        return false;
    }
    budget.total_output += expected;
    active.keep = true;
    decoded_size = expected;
    return true;
}

struct BrotliAllocationHeader { std::max_align_t alignment; std::size_t size; };
struct BrotliAllocator {
    std::uint64_t bytes = 0;
    std::uint64_t limit = 0;
};

void *brotli_allocate(void *opaque, std::size_t size) {
    auto &state = *static_cast<BrotliAllocator *>(opaque);
    if (size > state.limit - std::min(state.limit, state.bytes) ||
        size > std::numeric_limits<std::size_t>::max() - sizeof(BrotliAllocationHeader)) return nullptr;
    auto *header = static_cast<BrotliAllocationHeader *>(std::malloc(sizeof(BrotliAllocationHeader) + size));
    if (!header) return nullptr;
    header->size = size;
    state.bytes += size;
    return header + 1;
}

void brotli_free(void *opaque, void *address) {
    if (!address) return;
    auto &state = *static_cast<BrotliAllocator *>(opaque);
    auto *header = static_cast<BrotliAllocationHeader *>(address) - 1;
    state.bytes -= header->size;
    std::free(header);
}

bool decompress_brotli_guided(std::span<const std::byte> payload, EfiDecodeBudget &budget,
                              std::vector<std::byte> &output, std::uint32_t &decoded_size,
                              std::string &reason) {
    constexpr std::size_t wrapper_size = 16;
    constexpr std::uint64_t max_brotli_scratch_bytes = 32ull * 1024 * 1024;
    if (payload.size() < wrapper_size) {
        reason = "Brotli guided payload has a truncated size preamble";
        return false;
    }
    if (payload.size() > budget.limits.max_compressed_section_bytes) {
        reason = "Brotli guided source exceeds the per-section byte limit";
        return false;
    }
    const auto declared = u64(payload, 0);
    const auto scratch = u64(payload, 8);
    if (declared > std::numeric_limits<std::uint32_t>::max() ||
        declared > budget.limits.max_decompressed_section_bytes) {
        reason = "Brotli guided output exceeds the per-section byte limit";
        return false;
    }
    if (scratch == 0 || scratch > max_brotli_scratch_bytes) {
        reason = "Brotli guided scratch size is zero or exceeds its 32 MiB limit";
        return false;
    }
    const auto expected = static_cast<std::size_t>(declared);
    const auto compressed = payload.subspan(wrapper_size);
    if (compressed.empty()) {
        reason = "Brotli guided payload has no compressed stream";
        return false;
    }
    if (declared > budget.limits.max_total_decompressed_bytes -
            std::min(budget.limits.max_total_decompressed_bytes, budget.total_output)) {
        reason = "UEFI cumulative decompressed-byte limit exceeded";
        return false;
    }
    const auto active_limit = budget.limits.max_active_decompressed_bytes;
    const auto active_base = std::min(active_limit, budget.active_output);
    constexpr std::uint64_t output_probe_bytes = 1;
    if (declared > active_limit - active_base ||
        output_probe_bytes > active_limit - active_base - declared ||
        scratch > active_limit - active_base - declared - output_probe_bytes) {
        reason = "Brotli output and scratch exceed the active decompression memory limit";
        return false;
    }
    if (expected == std::numeric_limits<std::size_t>::max()) {
        reason = "Brotli output size cannot be represented safely";
        return false;
    }
    if (declared > (std::numeric_limits<std::uint64_t>::max() - compressed.size()) / 8) {
        reason = "Brotli guided decode work estimate overflowed";
        return false;
    }
    const auto work = static_cast<std::uint64_t>(compressed.size()) + declared * 8;
    if (work > budget.work_remaining) {
        reason = "Brotli guided decode work limit exceeded";
        return false;
    }
    if (budget.stop.stop_requested()) {
        reason = "Brotli guided decompression canceled";
        return false;
    }
    budget.work_remaining -= work;
    budget.active_output += declared;
    struct ActiveOutputGuard {
        EfiDecodeBudget &budget;
        std::uint64_t size;
        bool keep = false;
        ~ActiveOutputGuard() { if (!keep) budget.active_output -= size; }
    } active{budget, declared};

    BrotliAllocator allocator{0, std::min<std::uint64_t>(scratch, max_brotli_scratch_bytes)};
    auto *decoder = BrotliDecoderCreateInstance(brotli_allocate, brotli_free, &allocator);
    if (!decoder) {
        reason = "Brotli decoder allocation failed or exceeded its scratch limit";
        return false;
    }
    struct DecoderGuard {
        BrotliDecoderState *decoder;
        ~DecoderGuard() { BrotliDecoderDestroyInstance(decoder); }
    } decoder_guard{decoder};
    try {
        output.resize(expected + 1);
    } catch (const std::bad_alloc &) {
        reason = "Brotli guided output allocation failed";
        return false;
    }
    std::size_t input_offset = 0;
    std::size_t output_offset = 0;
    BrotliDecoderResult result = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
    while (result != BROTLI_DECODER_RESULT_SUCCESS) {
        if (budget.stop.stop_requested()) {
            reason = "Brotli guided decompression canceled";
            output.clear();
            return false;
        }
        const auto input_capacity = std::min(brotli_io_chunk_bytes, compressed.size() - input_offset);
        const auto output_capacity = std::min(brotli_io_chunk_bytes, output.size() - output_offset);
        auto available_input = input_capacity;
        auto available_output = output_capacity;
        const auto *next_input = reinterpret_cast<const std::uint8_t *>(compressed.data() + input_offset);
        auto *next_output = reinterpret_cast<std::uint8_t *>(output.data() + output_offset);
        result = BrotliDecoderDecompressStream(decoder, &available_input, &next_input,
                                               &available_output, &next_output, nullptr);
        input_offset += input_capacity - available_input;
        output_offset += output_capacity - available_output;
        if (result == BROTLI_DECODER_RESULT_ERROR ||
            (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && input_offset == compressed.size()) ||
            (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT && output_offset == output.size()) ||
            ((input_capacity == available_input) && (output_capacity == available_output) &&
             result != BROTLI_DECODER_RESULT_SUCCESS)) {
            reason = "Brotli guided bitstream is malformed, truncated or exceeds its declared output size";
            output.clear();
            return false;
        }
    }
    if (input_offset != compressed.size() || output_offset != expected) {
        reason = "Brotli guided stream has trailing bytes or disagrees with its declared output size";
        output.clear();
        return false;
    }
    output.resize(expected);
    budget.total_output += declared;
    active.keep = true;
    decoded_size = static_cast<std::uint32_t>(declared);
    return true;
}

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
            if (guid == crc32_guid) {
                // GenSec's CRC32 guided-section header appends a UINT32 CRC
                // after the standard GUID/DataOffset/Attributes fields.
                constexpr std::size_t crc_header_size = 24;
                if (common_header_size + crc_header_size > data_offset ||
                    common_header_size + crc_header_size > section_size) {
                    reason = "UEFI CRC32 GUID-defined section header is truncated";
                    return false;
                }
                const auto stored_crc = u32(section_bytes, static_cast<std::size_t>(common_header_size + 20));
                sections[row_index].guided_crc32 = stored_crc;
                std::uint32_t actual_crc = 0;
                std::string crc_reason;
                const auto guided_payload = section_bytes.subspan(data_offset);
                if (!calculate_guided_crc32(guided_payload, decode_budget, actual_crc, crc_reason)) {
                    sections[row_index].disposition = UefiSectionDisposition::opaque_guid_defined;
                    sections[row_index].diagnostic = std::move(crc_reason);
                } else {
                    sections[row_index].guided_crc32_valid = actual_crc == stored_crc;
                    if (!*sections[row_index].guided_crc32_valid) {
                        sections[row_index].disposition = UefiSectionDisposition::opaque_guid_defined;
                        sections[row_index].diagnostic = "CRC32 guided-section payload checksum mismatch; payload retained opaque";
                    } else if (attributes & guid_processing_required) {
                        sections[row_index].disposition = UefiSectionDisposition::processing_required;
                        sections[row_index].diagnostic = "CRC32 verified; GUID-defined attributes still require processing";
                    } else {
                        sections[row_index].disposition = UefiSectionDisposition::nested_sections;
                        contains_sections = true;
                        nested_offset = data_offset;
                    }
                }
            } else if ((attributes & guid_processing_required) && guid == brotli_decompress_guid) {
                const auto guided_payload = section_bytes.subspan(data_offset);
                std::vector<std::byte> decompressed;
                std::string decompression_reason;
                std::uint32_t expected_size = 0;
                if (guided_payload.size() >= 8) {
                    const auto declared = u64(guided_payload, 0);
                    if (declared <= std::numeric_limits<std::uint32_t>::max()) {
                        expected_size = static_cast<std::uint32_t>(declared);
                        sections[row_index].uncompressed_size = expected_size;
                    }
                }
                if (!decompress_brotli_guided(guided_payload, decode_budget, decompressed,
                                              expected_size, decompression_reason)) {
                    // Keep the processor-required disposition and retain the specific failure.
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
                        decompression_reason = "Brotli guided stream decoded, but its nested section stream is invalid: " + nested_reason;
                    }
                }
                if (sections[row_index].disposition != UefiSectionDisposition::decompressed_sections) {
                    sections[row_index].disposition = UefiSectionDisposition::processing_required;
                    sections[row_index].diagnostic = std::move(decompression_reason);
                }
            } else if ((attributes & guid_processing_required) &&
                       (guid == lzma_decompress_guid || guid == lzmaf86_decompress_guid)) {
                const auto guided_payload = section_bytes.subspan(data_offset);
                std::vector<std::byte> decompressed;
                std::string decompression_reason;
                std::uint32_t expected_size = 0;
                if (guided_payload.size() >= 13) {
                    const auto declared = u64(guided_payload, 5);
                    if (declared <= std::numeric_limits<std::uint32_t>::max()) {
                        expected_size = static_cast<std::uint32_t>(declared);
                        sections[row_index].uncompressed_size = expected_size;
                    }
                }
                const bool x86_filter = guid == lzmaf86_decompress_guid;
                if (!decompress_lzma_guided(guided_payload, decode_budget, decompressed,
                                            expected_size, x86_filter, decompression_reason)) {
                    // Keep the processor-required disposition and retain the specific failure.
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
                        decompression_reason = std::string(x86_filter ? "LZMAF86" : "LZMA") +
                            " guided stream decoded, but its nested section stream is invalid: " + nested_reason;
                    }
                }
                if (sections[row_index].disposition != UefiSectionDisposition::decompressed_sections) {
                    sections[row_index].disposition = UefiSectionDisposition::processing_required;
                    sections[row_index].diagnostic = std::move(decompression_reason);
                }
            } else if ((attributes & guid_processing_required) && guid == tiano_decompress_guid) {
                const auto guided_payload = section_bytes.subspan(data_offset);
                std::vector<std::byte> decompressed;
                std::string decompression_reason;
                if (guided_payload.size() < 8) {
                    decompression_reason = "Tiano guided payload has a truncated size preamble";
                } else {
                    const auto expected_size = u32(guided_payload, 4);
                    sections[row_index].compression_type = 2;
                    sections[row_index].uncompressed_size = expected_size;
                    if (!decompress_efi_payload(guided_payload, expected_size, 2, decode_budget,
                                                decompressed, decompression_reason)) {
                        // Keep the processor-required disposition for unsupported or
                        // malformed encodings, but retain the specific failure.
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
                            decompression_reason = "Tiano guided stream decoded, but its nested section stream is invalid: " + nested_reason;
                        }
                    }
                }
                if (sections[row_index].disposition != UefiSectionDisposition::decompressed_sections) {
                    sections[row_index].disposition = UefiSectionDisposition::processing_required;
                    sections[row_index].diagnostic = std::move(decompression_reason);
                }
            } else if (attributes & guid_processing_required) {
                sections[row_index].disposition = UefiSectionDisposition::processing_required;
                sections[row_index].diagnostic = "GUID-defined payload requires an unavailable processor and is retained opaque";
            } else {
                // PI 1.10 permits direct retrieval of the nested section
                // stream at DataOffset when processing is not required,
                // regardless of whether this inspector knows the GUID.
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
        } else if (type == section_dxe_depex || type == section_pei_depex || type == section_mm_depex) {
            const auto depex = section_bytes.subspan(static_cast<std::size_t>(common_header_size));
            const auto summary = inspect_depex(depex, type);
            sections[row_index].depex_valid = summary.valid;
            sections[row_index].depex_instruction_count = summary.instruction_count;
            sections[row_index].depex_guid_operand_count = summary.guid_operand_count;
            sections[row_index].depex_max_stack_depth = summary.max_stack_depth;
            sections[row_index].depex_diagnostic = summary.diagnostic;
            if (summary.valid) sections[row_index].depex_expression.assign(depex.begin(), depex.end());
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
        volume.block_map.push_back({count, block_size});
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
    if (cursor > header_length && header_length < fv_length) {
        const auto header_gap_end = std::min(cursor, fv_length);
        const auto header_gap = bytes.subspan(start + header_length,
            static_cast<std::size_t>(header_gap_end - header_length));
        const bool gap_valid = all_value(header_gap, erased);
        volume.free_space_regions.push_back({header_length, header_gap_end - header_length, gap_valid});
        if (!gap_valid)
            volume.layout_diagnostics.push_back("FV header-to-file alignment bytes do not match FV erase polarity");
    }
    while (cursor < fv_length) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI firmware volume parsing canceled"};
        const auto remaining = bytes.subspan(start + static_cast<std::size_t>(cursor),
                                             static_cast<std::size_t>(fv_length - cursor));
        if (remaining.size() < 24) {
            const bool free_valid = all_value(remaining, erased);
            volume.free_space_regions.push_back({cursor, remaining.size(), free_valid});
            if (!free_valid)
                volume.layout_diagnostics.push_back("trailing FV bytes shorter than an FFS header are not erase-polarity free space");
            break;
        }
        if (all_value(remaining.first(8), erased)) {
            const bool free_valid = all_value(remaining, erased);
            volume.free_space_regions.push_back({cursor, remaining.size(), free_valid});
            if (!free_valid)
                volume.layout_diagnostics.push_back("FV trailing free-space region contains bytes that do not match erase polarity");
            break;
        }
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
        file.pad_file = file.type == ffs_file_type_pad;
        constexpr std::array<std::uint32_t, 16> ffs_data_alignments = {
            1u, 16u, 128u, 512u, 1024u, 4096u, 32768u, 65536u,
            131072u, 262144u, 524288u, 1048576u, 2097152u, 4194304u, 8388608u, 16777216u};
        const auto alignment_code = static_cast<std::size_t>(((attributes >> 3u) & 7u) |
            ((attributes & 0x02u) ? 8u : 0u));
        file.data_alignment = ffs_data_alignments[alignment_code];
        file.data_alignment_valid = ((cursor + header_size) % file.data_alignment) == 0;
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
            if (file.pad_file) {
                file.pad_data_erase_polarity_valid = all_value(file_data, erased);
                if (!*file.pad_data_erase_polarity_valid)
                    file.section_diagnostic = "valid FFS_PAD file data contains non-erased bytes";
            } else if (!parse_section_stream(file_data, file_data_begin, erased, max_sections, max_section_depth,
                                      section_count, file.sections, 0, {}, section_error, decode_budget))
                file.section_diagnostic = std::move(section_error);
        } else {
            file.section_diagnostic = "file data is not in the EFI_FILE_DATA_VALID state; sections were not parsed";
        }
        if (!file.data_alignment_valid) {
            if (!file.section_diagnostic.empty()) file.section_diagnostic += "; ";
            file.section_diagnostic += "FFS file data offset does not satisfy its FV-relative alignment attribute";
        }
        if (file.name_guid == dxe_apriori_file_guid) {
            if (volume.dxe_apriori_file_present) {
                volume.dxe_apriori_file_guids.clear();
                volume.dxe_apriori_diagnostic = "multiple DXE APRIORI files are present in one firmware volume";
            } else {
                volume.dxe_apriori_file_present = true;
                if (file.type != 0x02) {
                    volume.dxe_apriori_diagnostic = "DXE APRIORI file is not an FFS freeform file";
                } else if (file.disposition != UefiFfsFileDisposition::data_valid &&
                           file.disposition != UefiFfsFileDisposition::marked_for_update) {
                    volume.dxe_apriori_diagnostic = "DXE APRIORI file data is not in a dispatchable state";
                } else if (file.data_checksum_valid == false) {
                    volume.dxe_apriori_diagnostic = "DXE APRIORI file data checksum is invalid";
                } else if (file.sections.size() != 1 || file.sections.front().type != section_raw ||
                           file.sections.front().depth != 0 || file.sections.front().parent_index ||
                           file.sections.front().offset_space != UefiSectionOffsetSpace::file) {
                    volume.dxe_apriori_diagnostic = "DXE APRIORI file must contain exactly one top-level RAW section";
                } else {
                    const auto &raw = file.sections.front();
                    if ((raw.payload_size % 16u) != 0 || raw.payload_size / 16u > max_apriori_file_guids) {
                        volume.dxe_apriori_diagnostic = "DXE APRIORI RAW payload is not a bounded GUID array";
                    } else if (raw.payload_offset > bytes.size() ||
                               raw.payload_size > bytes.size() - static_cast<std::size_t>(raw.payload_offset)) {
                        volume.dxe_apriori_diagnostic = "DXE APRIORI RAW payload range is outside the input";
                    } else {
                        std::set<std::array<std::uint8_t, 16>> seen_guids;
                        const auto payload = static_cast<std::size_t>(raw.payload_offset);
                        for (std::size_t at = 0; at < raw.payload_size; at += 16) {
                            std::array<std::uint8_t, 16> guid{};
                            for (std::size_t n = 0; n < guid.size(); ++n)
                                guid[n] = u8(bytes, payload + at + n);
                            if (!seen_guids.insert(guid).second) {
                                volume.dxe_apriori_file_guids.clear();
                                volume.dxe_apriori_diagnostic = "DXE APRIORI RAW payload contains a duplicate file GUID";
                                break;
                            }
                            volume.dxe_apriori_file_guids.push_back(guid);
                        }
                    }
                }
            }
        }
        if (file.name_guid == pei_apriori_file_guid) {
            if (volume.pei_apriori_file_present) {
                volume.pei_apriori_file_guids.clear();
                volume.pei_apriori_diagnostic = "multiple PEI APRIORI files are present in one firmware volume";
            } else {
                volume.pei_apriori_file_present = true;
                if (file.type != 0x02) {
                    volume.pei_apriori_diagnostic = "PEI APRIORI file is not an FFS freeform file";
                } else if (file.disposition != UefiFfsFileDisposition::data_valid &&
                           file.disposition != UefiFfsFileDisposition::marked_for_update) {
                    volume.pei_apriori_diagnostic = "PEI APRIORI file data is not in a dispatchable state";
                } else if (file.data_checksum_valid == false) {
                    volume.pei_apriori_diagnostic = "PEI APRIORI file data checksum is invalid";
                } else if (file.sections.size() != 1 || file.sections.front().type != section_raw ||
                           file.sections.front().depth != 0 || file.sections.front().parent_index ||
                           file.sections.front().offset_space != UefiSectionOffsetSpace::file) {
                    volume.pei_apriori_diagnostic = "PEI APRIORI file must contain exactly one top-level RAW section";
                } else {
                    const auto &raw = file.sections.front();
                    if ((raw.payload_size % 16u) != 0 || raw.payload_size / 16u > max_apriori_file_guids) {
                        volume.pei_apriori_diagnostic = "PEI APRIORI RAW payload is not a bounded GUID array";
                    } else if (raw.payload_offset > bytes.size() ||
                               raw.payload_size > bytes.size() - static_cast<std::size_t>(raw.payload_offset)) {
                        volume.pei_apriori_diagnostic = "PEI APRIORI RAW payload range is outside the input";
                    } else {
                        std::set<std::array<std::uint8_t, 16>> seen_guids;
                        const auto payload = static_cast<std::size_t>(raw.payload_offset);
                        for (std::size_t at = 0; at < raw.payload_size; at += 16) {
                            std::array<std::uint8_t, 16> guid{};
                            for (std::size_t n = 0; n < guid.size(); ++n)
                                guid[n] = u8(bytes, payload + at + n);
                            if (!seen_guids.insert(guid).second) {
                                volume.pei_apriori_file_guids.clear();
                                volume.pei_apriori_diagnostic = "PEI APRIORI RAW payload contains a duplicate file GUID";
                                break;
                            }
                            volume.pei_apriori_file_guids.push_back(guid);
                        }
                    }
                }
            }
        }
        volume.files.push_back(std::move(file));

        if (file_size > UINT64_MAX - cursor - 7u)
            return Error{ErrorCode::overflow, "UEFI FFS next-header offset overflows"};
        const auto file_end = cursor + file_size;
        const auto next_cursor = (file_end + 7u) & ~std::uint64_t{7};
        if (next_cursor > file_end && file_end < fv_length) {
            const auto gap_size = std::min(next_cursor, fv_length) - file_end;
            const bool gap_valid = all_value(bytes.subspan(start + static_cast<std::size_t>(file_end),
                static_cast<std::size_t>(gap_size)), erased);
            volume.free_space_regions.push_back({file_end, gap_size, gap_valid});
            if (!gap_valid)
                volume.layout_diagnostics.push_back("FFS inter-file alignment bytes do not match FV erase polarity");
        }
        cursor = next_cursor;
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
        options.max_decompression_work == 0 || options.max_guided_crc_bytes == 0)
        return Error{ErrorCode::invalid_argument, "UEFI firmware volume input and limits must be nonzero"};
    if (bytes.size() > options.max_input_bytes)
        return Error{ErrorCode::resource_limit, "UEFI firmware image exceeds the configured input limit"};
    if (bytes.size() < 44)
        return Error{ErrorCode::malformed, "Input is too short to contain a UEFI firmware volume"};
    std::vector<UefiFirmwareVolume> result;
    std::size_t cursor = 0, total_files = 0, total_sections = 0;
    EfiDecodeBudget decode_budget{options, options.max_decompression_work, 0, 0, 0, stop};
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

    // Preserve the standard FV_IMAGE containment relation in the public
    // inventory. The scanner already validates every candidate independently;
    // this pass only links validated file-space children back to their owning
    // section and never treats arbitrary embedded signatures as volumes.
    // Volumes are appended in source-offset order, so lower_bound keeps this
    // bounded by the number of actual contained candidates rather than doing a
    // full volume cross-product for every section.
    constexpr std::size_t max_embedded_volume_links = 1'000'000;
    std::size_t embedded_volume_links = 0;
    for (std::size_t parent_index = 0; parent_index < result.size(); ++parent_index) {
        auto &parent = result[parent_index];
        for (auto &file : parent.files) {
            for (auto &section : file.sections) {
                if (section.type != section_firmware_volume_image ||
                    section.offset_space != UefiSectionOffsetSpace::file ||
                    section.payload_size == 0 ||
                    section.payload_offset > std::numeric_limits<std::uint64_t>::max() - section.payload_size)
                    continue;
                const auto payload_end = section.payload_offset + section.payload_size;
                auto child = std::lower_bound(result.begin(), result.end(), section.payload_offset,
                    [](const UefiFirmwareVolume &candidate, std::uint64_t offset) {
                        return candidate.file_offset < offset;
                    });
                for (; child != result.end() && child->file_offset < payload_end; ++child) {
                    if (child->length > std::numeric_limits<std::uint64_t>::max() - child->file_offset ||
                        child->file_offset + child->length > payload_end)
                        continue;
                    if (embedded_volume_links == max_embedded_volume_links)
                        return Error{ErrorCode::resource_limit,
                            "UEFI embedded firmware-volume relationship limit exceeded"};
                    section.embedded_volume_indices.push_back(
                        static_cast<std::size_t>(std::distance(result.begin(), child)));
                    ++embedded_volume_links;
                }
            }
        }
    }
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
UefiDepexEvaluation evaluate_uefi_depex(
    std::span<const std::byte> expression, std::uint8_t section_type,
    std::span<const std::array<std::uint8_t, 16>> available_guids) {
    UefiDepexEvaluation result;
    constexpr std::size_t max_available_guids = 4096;
    if (available_guids.size() > max_available_guids) {
        result.status = UefiDepexEvaluationStatus::input_limit_exceeded;
        result.diagnostic = "dependency-expression availability set exceeds 4096 GUIDs";
        return result;
    }
    const auto validation = inspect_depex(expression, section_type);
    if (!validation.valid) {
        result.status = UefiDepexEvaluationStatus::invalid_expression;
        result.diagnostic = validation.diagnostic;
        return result;
    }
    std::array<std::array<std::uint8_t, 16>, max_available_guids> sorted_guids{};
    std::copy(available_guids.begin(), available_guids.end(), sorted_guids.begin());
    std::sort(sorted_guids.begin(), sorted_guids.begin() + static_cast<std::ptrdiff_t>(available_guids.size()));
    if (expression.empty()) {
        result.status = UefiDepexEvaluationStatus::evaluated;
        result.satisfied = true;
        return result;
    }
    std::array<bool, max_depex_instructions> stack{};
    std::size_t depth = 0;
    std::size_t cursor = 0;
    while (cursor < expression.size() && result.instructions_evaluated < max_depex_instructions) {
        const auto opcode = u8(expression, cursor++);
        ++result.instructions_evaluated;
        if (opcode == 0x00 || opcode == 0x01) {
            result.status = UefiDepexEvaluationStatus::ordering_required;
            result.diagnostic = opcode == 0x00 ? "BEFORE requires firmware driver-order context" :
                                                 "AFTER requires firmware driver-order context";
            return result;
        }
        if (opcode == 0x09) {
            // PI defines SOR as a no-op during boolean evaluation; retain the
            // scheduling requirement separately for callers with dispatch state.
            result.schedule_on_request = true;
            continue;
        }
        if (opcode == 0x02) {
            std::array<std::uint8_t, 16> guid{};
            for (std::size_t i = 0; i < guid.size(); ++i)
                guid[i] = u8(expression, cursor + i);
            cursor += guid.size();
            stack[depth++] = std::binary_search(sorted_guids.begin(),
                sorted_guids.begin() + static_cast<std::ptrdiff_t>(available_guids.size()), guid);
        } else if (opcode == 0x06 || opcode == 0x07) {
            stack[depth++] = opcode == 0x06;
        } else if (opcode == 0x05) {
            stack[depth - 1] = !stack[depth - 1];
        } else if (opcode == 0x03 || opcode == 0x04) {
            const bool right = stack[--depth];
            const bool left = stack[depth - 1];
            stack[depth - 1] = opcode == 0x03 ? left && right : left || right;
        } else if (opcode == 0x08) {
            result.status = result.schedule_on_request
                ? UefiDepexEvaluationStatus::sor_requires_dispatch_context
                : UefiDepexEvaluationStatus::evaluated;
            result.satisfied = stack[0];
            if (result.schedule_on_request)
                result.diagnostic = "boolean result is available; SOR scheduling requires DXE/MM dispatch context";
            return result;
        } else {
            // inspect_depex has already rejected every other opcode.
            result.status = UefiDepexEvaluationStatus::invalid_expression;
            result.diagnostic = "unsupported dependency-expression opcode";
            return result;
        }
    }
    result.status = UefiDepexEvaluationStatus::invalid_expression;
    result.diagnostic = "dependency expression did not terminate within its validated instruction limit";
    return result;
}

UefiDriverDispatchPlan plan_uefi_driver_dispatch(
    const UefiFirmwareVolume &volume,
    std::span<const std::array<std::uint8_t, 16>> available_guids) {
    UefiDriverDispatchPlan plan;
    plan.apriori_file_present = volume.dxe_apriori_file_present;
    plan.apriori_diagnostic = volume.dxe_apriori_diagnostic;
    const auto is_driver = [](std::uint8_t type) { return type >= 0x05 && type <= 0x07; };
    std::vector<std::size_t> file_to_entry(volume.files.size(), std::numeric_limits<std::size_t>::max());
    for (std::size_t i = 0; i < volume.files.size(); ++i) {
        UefiDriverDispatchEntry entry;
        entry.file_index = i;
        entry.disposition = is_driver(volume.files[i].type)
            ? UefiDriverDispatchDisposition::ordered_ready
            : UefiDriverDispatchDisposition::non_driver;
        file_to_entry[i] = plan.entries.size();
        plan.entries.push_back(std::move(entry));
    }
    if (available_guids.size() > 4096) {
        for (auto &entry : plan.entries) if (entry.disposition == UefiDriverDispatchDisposition::ordered_ready) {
            entry.disposition = UefiDriverDispatchDisposition::invalid_dependency;
            entry.diagnostic = "dependency-expression availability set exceeds 4096 GUIDs";
        }
        return plan;
    }
    std::vector<std::pair<std::size_t, std::size_t>> edges;
    const auto guid_present = [&](const std::array<std::uint8_t, 16> &guid) {
        return std::find(available_guids.begin(), available_guids.end(), guid) != available_guids.end();
    };
    for (std::size_t fi = 0; fi < volume.files.size(); ++fi) {
        const auto &file = volume.files[fi];
        auto &entry = plan.entries[file_to_entry[fi]];
        if (!is_driver(file.type)) continue;
        if (file.disposition != UefiFfsFileDisposition::data_valid &&
            file.disposition != UefiFfsFileDisposition::marked_for_update) {
            entry.disposition = UefiDriverDispatchDisposition::blocked;
            entry.diagnostic = "FFS file data is not in a dispatchable data-valid state";
            continue;
        }
        for (std::size_t si = 0; si < file.sections.size(); ++si) {
            const auto &section = file.sections[si];
            if (section.type != section_dxe_depex) continue;
            entry.dependency_section_indices.push_back(si);
            if (!section.depex_valid.value_or(false)) {
                entry.disposition = UefiDriverDispatchDisposition::invalid_dependency;
                entry.diagnostic = section.depex_diagnostic.empty() ? "invalid DXE dependency expression" : section.depex_diagnostic;
                continue;
            }
            const auto code = std::span<const std::byte>(section.depex_expression);
            if (!code.empty() && (u8(code, 0) == 0x00 || u8(code, 0) == 0x01)) {
                std::array<std::uint8_t, 16> target{};
                for (std::size_t n = 0; n < target.size(); ++n) target[n] = u8(code, 1 + n);
                std::optional<std::size_t> target_file;
                for (std::size_t j = 0; j < volume.files.size(); ++j)
                    if (is_driver(volume.files[j].type) && volume.files[j].name_guid == target) { target_file = j; break; }
                if (!target_file) {
                    entry.disposition = UefiDriverDispatchDisposition::ordering_unresolved;
                    entry.missing_guids.push_back(target);
                    entry.diagnostic = "BEFORE/AFTER target driver GUID is absent from this firmware volume";
                } else {
                    const auto from = u8(code, 0) == 0x00 ? fi : *target_file;
                    const auto to = u8(code, 0) == 0x00 ? *target_file : fi;
                    if (from != to) edges.emplace_back(from, to);
                }
                continue;
            }
            for (std::size_t cursor = 0; cursor < code.size();) {
                const auto op = u8(code, cursor++);
                if (op == 0x02 && code.size() - cursor >= 16) {
                    std::array<std::uint8_t, 16> guid{};
                    for (std::size_t n = 0; n < guid.size(); ++n) guid[n] = u8(code, cursor + n);
                    if (!guid_present(guid) && std::find(entry.missing_guids.begin(), entry.missing_guids.end(), guid) == entry.missing_guids.end())
                        entry.missing_guids.push_back(guid);
                    cursor += 16;
                }
            }
            const auto evaluation = evaluate_uefi_depex(code, section.type, available_guids);
            if (!evaluation.satisfied) {
                entry.disposition = evaluation.status == UefiDepexEvaluationStatus::invalid_expression ||
                    evaluation.status == UefiDepexEvaluationStatus::input_limit_exceeded
                    ? UefiDriverDispatchDisposition::invalid_dependency
                    : UefiDriverDispatchDisposition::blocked;
                if (!evaluation.diagnostic.empty()) entry.diagnostic = evaluation.diagnostic;
            } else if (!*evaluation.satisfied && entry.disposition == UefiDriverDispatchDisposition::ordered_ready) {
                entry.disposition = UefiDriverDispatchDisposition::blocked;
                entry.diagnostic = "DXE dependency expression is false for the supplied installed-protocol set";
            }
        }
    }
    const auto count = volume.files.size();
    std::vector<std::size_t> indegree(count, 0);
    std::vector<std::vector<std::size_t>> outgoing(count);
    for (const auto &[from, to] : edges) {
        if (plan.entries[file_to_entry[from]].disposition != UefiDriverDispatchDisposition::ordered_ready ||
            plan.entries[file_to_entry[to]].disposition != UefiDriverDispatchDisposition::ordered_ready) continue;
        if (std::find(outgoing[from].begin(), outgoing[from].end(), to) == outgoing[from].end()) {
            outgoing[from].push_back(to);
            ++indegree[to];
        }
    }
    std::map<std::array<std::uint8_t, 16>, std::size_t> apriori_rank;
    const auto add_apriori_note = [&](std::string note) {
        constexpr std::size_t diagnostic_limit = 4096;
        if (plan.apriori_diagnostic.size() >= diagnostic_limit) return;
        if (!plan.apriori_diagnostic.empty()) plan.apriori_diagnostic += "; ";
        const auto remaining = diagnostic_limit - plan.apriori_diagnostic.size();
        if (note.size() > remaining) note.resize(remaining);
        plan.apriori_diagnostic += note;
    };
    const bool apriori_count_bounded = volume.dxe_apriori_file_guids.size() <= max_apriori_file_guids;
    if (!apriori_count_bounded)
        add_apriori_note("DXE APRIORI GUID list exceeds the 4096-entry planning limit");
    if (apriori_count_bounded) {
        for (std::size_t rank = 0; rank < volume.dxe_apriori_file_guids.size(); ++rank)
            apriori_rank.emplace(volume.dxe_apriori_file_guids[rank], rank);
    }
    for (const auto &guid : volume.dxe_apriori_file_guids) {
        if (!apriori_count_bounded) break;
        const auto found = std::find_if(volume.files.begin(), volume.files.end(), [&](const auto &file) {
            return file.name_guid == guid && is_driver(file.type);
        });
        if (found == volume.files.end()) {
            add_apriori_note("APRIORI GUID " + uefi_guid_string(guid) + " does not name a DXE/UEFI driver in this volume");
        } else {
            const auto file_index = static_cast<std::size_t>(found - volume.files.begin());
            if (plan.entries[file_to_entry[file_index]].disposition != UefiDriverDispatchDisposition::ordered_ready)
                add_apriori_note("APRIORI driver " + uefi_guid_string(guid) + " is not ready under the supplied dependency snapshot");
        }
    }
    std::vector<bool> emitted(count, false);
    for (;;) {
        std::optional<std::size_t> next;
        std::size_t best_apriori_rank = std::numeric_limits<std::size_t>::max();
        for (std::size_t i = 0; i < count; ++i) {
            if (emitted[i] || !is_driver(volume.files[i].type) ||
                plan.entries[file_to_entry[i]].disposition != UefiDriverDispatchDisposition::ordered_ready || indegree[i] != 0)
                continue;
            const auto rank = apriori_rank.find(volume.files[i].name_guid);
            const auto candidate_rank = rank == apriori_rank.end()
                ? std::numeric_limits<std::size_t>::max() : rank->second;
            if (!next || candidate_rank < best_apriori_rank) {
                next = i;
                best_apriori_rank = candidate_rank;
            }
        }
        if (!next) break;
        emitted[*next] = true;
        plan.ordered_file_indices.push_back(*next);
        for (const auto target : outgoing[*next]) --indegree[target];
    }
    for (std::size_t i = 0; i < count; ++i) {
        auto &entry = plan.entries[file_to_entry[i]];
        if (is_driver(volume.files[i].type) && entry.disposition == UefiDriverDispatchDisposition::ordered_ready && !emitted[i]) {
            entry.disposition = UefiDriverDispatchDisposition::ordering_unresolved;
            entry.diagnostic = "BEFORE/AFTER constraints contain a cycle";
        }
    }
    return plan;
}
UefiDriverDispatchPlan plan_uefi_pei_dispatch(
    const UefiFirmwareVolume &volume,
    std::span<const std::array<std::uint8_t, 16>> available_ppi_guids) {
    UefiDriverDispatchPlan plan;
    plan.apriori_file_present = volume.pei_apriori_file_present;
    plan.apriori_diagnostic = volume.pei_apriori_diagnostic;
    const auto is_peim = [](std::uint8_t type) { return type == 0x06 || type == 0x08; };
    const auto append_missing_guids = [&](UefiDriverDispatchEntry &entry,
                                          std::span<const std::byte> expression) {
        for (std::size_t cursor = 0; cursor < expression.size();) {
            const auto opcode = u8(expression, cursor++);
            if (opcode != 0x02) continue;
            if (expression.size() - cursor < 16) break; // Validation reports malformed operands below.
            std::array<std::uint8_t, 16> guid{};
            for (std::size_t n = 0; n < guid.size(); ++n) guid[n] = u8(expression, cursor + n);
            if (std::find(available_ppi_guids.begin(), available_ppi_guids.end(), guid) == available_ppi_guids.end() &&
                std::find(entry.missing_guids.begin(), entry.missing_guids.end(), guid) == entry.missing_guids.end())
                entry.missing_guids.push_back(guid);
            cursor += guid.size();
        }
    };
    std::vector<std::size_t> file_to_entry(volume.files.size(), std::numeric_limits<std::size_t>::max());
    for (std::size_t i = 0; i < volume.files.size(); ++i) {
        UefiDriverDispatchEntry entry;
        entry.file_index = i;
        entry.disposition = is_peim(volume.files[i].type)
            ? UefiDriverDispatchDisposition::ordered_ready
            : UefiDriverDispatchDisposition::non_driver;
        file_to_entry[i] = plan.entries.size();
        plan.entries.push_back(std::move(entry));
    }
    if (available_ppi_guids.size() > 4096) {
        for (auto &entry : plan.entries) if (entry.disposition == UefiDriverDispatchDisposition::ordered_ready) {
            entry.disposition = UefiDriverDispatchDisposition::invalid_dependency;
            entry.diagnostic = "PEI dependency availability set exceeds 4096 PPI GUIDs";
        }
        return plan;
    }
    for (std::size_t fi = 0; fi < volume.files.size(); ++fi) {
        const auto &file = volume.files[fi];
        auto &entry = plan.entries[file_to_entry[fi]];
        if (!is_peim(file.type)) continue;
        if (file.disposition != UefiFfsFileDisposition::data_valid &&
            file.disposition != UefiFfsFileDisposition::marked_for_update) {
            entry.disposition = UefiDriverDispatchDisposition::blocked;
            entry.diagnostic = "FFS PEIM data is not in a dispatchable data-valid state";
            continue;
        }
        std::size_t dependencies = 0;
        for (std::size_t si = 0; si < file.sections.size(); ++si) {
            const auto &section = file.sections[si];
            if (section.type != section_pei_depex) continue;
            entry.dependency_section_indices.push_back(si);
            if (++dependencies > 1) {
                entry.disposition = UefiDriverDispatchDisposition::invalid_dependency;
                entry.diagnostic = "multiple PEI dependency expressions make the PEIM readiness ambiguous";
                continue;
            }
            if (!section.depex_valid.value_or(false)) {
                entry.disposition = UefiDriverDispatchDisposition::invalid_dependency;
                entry.diagnostic = section.depex_diagnostic.empty()
                    ? "invalid PEI dependency expression" : section.depex_diagnostic;
                continue;
            }
            const auto code = std::span<const std::byte>(section.depex_expression);
            append_missing_guids(entry, code);
            const auto evaluation = evaluate_uefi_depex(code, section.type, available_ppi_guids);
            if (!evaluation.satisfied) {
                entry.disposition = evaluation.status == UefiDepexEvaluationStatus::invalid_expression ||
                    evaluation.status == UefiDepexEvaluationStatus::input_limit_exceeded
                    ? UefiDriverDispatchDisposition::invalid_dependency
                    : UefiDriverDispatchDisposition::blocked;
                if (!evaluation.diagnostic.empty()) entry.diagnostic = evaluation.diagnostic;
            } else if (!*evaluation.satisfied && entry.disposition == UefiDriverDispatchDisposition::ordered_ready) {
                entry.disposition = UefiDriverDispatchDisposition::blocked;
                entry.diagnostic = "PEI dependency expression is false for the supplied installed-PPI set";
            }
        }
    }
    // PI PEI APRIORI GUIDs take precedence in their listed order; other ready
    // PEIMs retain physical FFS order. This remains only a recommendation and
    // does not model dispatcher retries or execute a module.
    std::vector<bool> emitted(volume.files.size(), false);
    std::size_t unresolved_apriori = 0;
    if (volume.pei_apriori_file_present && volume.pei_apriori_diagnostic.empty()) {
        for (const auto &guid : volume.pei_apriori_file_guids) {
            const auto found = std::find_if(volume.files.begin(), volume.files.end(),
                [&](const auto &file) { return file.name_guid == guid && is_peim(file.type); });
            if (found == volume.files.end()) {
                ++unresolved_apriori;
                continue;
            }
            const auto index = static_cast<std::size_t>(found - volume.files.begin());
            if (plan.entries[file_to_entry[index]].disposition == UefiDriverDispatchDisposition::ordered_ready &&
                !emitted[index]) {
                emitted[index] = true;
                plan.ordered_file_indices.push_back(index);
            }
        }
    }
    for (std::size_t i = 0; i < volume.files.size(); ++i)
        if (is_peim(volume.files[i].type) && !emitted[i] &&
            plan.entries[file_to_entry[i]].disposition == UefiDriverDispatchDisposition::ordered_ready)
            plan.ordered_file_indices.push_back(i);
    if (unresolved_apriori) {
        if (!plan.apriori_diagnostic.empty()) plan.apriori_diagnostic += "; ";
        plan.apriori_diagnostic += std::to_string(unresolved_apriori) +
            " PEI APRIORI GUID(s) do not identify PEIMs in this volume";
    }
    return plan;
}
UefiDriverDispatchPlan plan_uefi_mm_dispatch(
    const UefiFirmwareVolume &volume,
    std::span<const std::array<std::uint8_t, 16>> available_protocol_guids) {
    UefiDriverDispatchPlan plan;
    const auto is_mm_driver = [](std::uint8_t type) {
        return type == 0x0a || type == 0x0c || type == 0x0e;
    };
    const auto append_missing_guids = [&](UefiDriverDispatchEntry &entry,
                                          std::span<const std::byte> expression) {
        for (std::size_t cursor = 0; cursor < expression.size();) {
            const auto opcode = u8(expression, cursor++);
            if (opcode != 0x02) continue;
            if (expression.size() - cursor < 16) break; // The validated expression parser reports malformed operands.
            std::array<std::uint8_t, 16> guid{};
            for (std::size_t n = 0; n < guid.size(); ++n) guid[n] = u8(expression, cursor + n);
            if (std::find(available_protocol_guids.begin(), available_protocol_guids.end(), guid) ==
                    available_protocol_guids.end() &&
                std::find(entry.missing_guids.begin(), entry.missing_guids.end(), guid) == entry.missing_guids.end())
                entry.missing_guids.push_back(guid);
            cursor += guid.size();
        }
    };
    std::vector<std::size_t> file_to_entry(volume.files.size(), std::numeric_limits<std::size_t>::max());
    for (std::size_t i = 0; i < volume.files.size(); ++i) {
        UefiDriverDispatchEntry entry;
        entry.file_index = i;
        entry.disposition = is_mm_driver(volume.files[i].type)
            ? UefiDriverDispatchDisposition::ordered_ready
            : UefiDriverDispatchDisposition::non_driver;
        file_to_entry[i] = plan.entries.size();
        plan.entries.push_back(std::move(entry));
    }
    if (available_protocol_guids.size() > 4096) {
        for (auto &entry : plan.entries) if (entry.disposition == UefiDriverDispatchDisposition::ordered_ready) {
            entry.disposition = UefiDriverDispatchDisposition::invalid_dependency;
            entry.diagnostic = "MM dependency availability set exceeds 4096 protocol GUIDs";
        }
        return plan;
    }
    for (std::size_t fi = 0; fi < volume.files.size(); ++fi) {
        const auto &file = volume.files[fi];
        auto &entry = plan.entries[file_to_entry[fi]];
        if (!is_mm_driver(file.type)) continue;
        if (file.disposition != UefiFfsFileDisposition::data_valid &&
            file.disposition != UefiFfsFileDisposition::marked_for_update) {
            entry.disposition = UefiDriverDispatchDisposition::blocked;
            entry.diagnostic = "FFS MM driver data is not in a dispatchable data-valid state";
            continue;
        }
        std::size_t dependencies = 0;
        for (std::size_t si = 0; si < file.sections.size(); ++si) {
            const auto &section = file.sections[si];
            if (section.type != section_mm_depex) continue;
            entry.dependency_section_indices.push_back(si);
            if (++dependencies > 1) {
                entry.disposition = UefiDriverDispatchDisposition::invalid_dependency;
                entry.diagnostic = "multiple MM dependency expressions make readiness ambiguous";
                continue;
            }
            if (!section.depex_valid.value_or(false)) {
                entry.disposition = UefiDriverDispatchDisposition::invalid_dependency;
                entry.diagnostic = section.depex_diagnostic.empty()
                    ? "invalid MM dependency expression" : section.depex_diagnostic;
                continue;
            }
            const auto code = std::span<const std::byte>(section.depex_expression);
            append_missing_guids(entry, code);
            const auto evaluation = evaluate_uefi_depex(code, section.type, available_protocol_guids);
            if (!evaluation.satisfied) {
                entry.disposition = evaluation.status == UefiDepexEvaluationStatus::invalid_expression ||
                    evaluation.status == UefiDepexEvaluationStatus::input_limit_exceeded
                    ? UefiDriverDispatchDisposition::invalid_dependency
                    : evaluation.status == UefiDepexEvaluationStatus::ordering_required ||
                      evaluation.status == UefiDepexEvaluationStatus::sor_requires_dispatch_context
                    ? UefiDriverDispatchDisposition::ordering_unresolved
                    : UefiDriverDispatchDisposition::blocked;
                if (!evaluation.diagnostic.empty()) entry.diagnostic = evaluation.diagnostic;
            } else if (!*evaluation.satisfied && entry.disposition == UefiDriverDispatchDisposition::ordered_ready) {
                entry.disposition = UefiDriverDispatchDisposition::blocked;
                entry.diagnostic = "MM dependency expression is false for the supplied installed-protocol set";
            }
        }
    }
    for (std::size_t i = 0; i < volume.files.size(); ++i)
        if (is_mm_driver(volume.files[i].type) &&
            plan.entries[file_to_entry[i]].disposition == UefiDriverDispatchDisposition::ordered_ready)
            plan.ordered_file_indices.push_back(i);
    return plan;
}
Result<UefiProtocolDiscoveryPlan> plan_uefi_protocol_discovery(
    const UefiFirmwareVolume &volume, std::span<const std::array<std::uint8_t, 16>> initially_available,
    std::span<const UefiDriverProtocolEffect> effects, UefiProtocolDiscoveryOptions options, std::stop_token stop) {
    using Guid = std::array<std::uint8_t, 16>;
    if (volume.files.size() > 4096 || initially_available.size() > 4096 || effects.size() > 4096 ||
        !options.max_rounds || options.max_rounds > 4096 || !options.max_work || options.max_work > 256ull*1024*1024)
        return Error{ErrorCode::resource_limit,"UEFI protocol plan exceeds file/GUID/effect/round/work limits"};
    if (volume.file_offset > UINT64_MAX - volume.length)
        return Error{ErrorCode::invalid_argument,"UEFI protocol plan volume source extent overflows"};
    try {
        UefiProtocolDiscoveryPlan result;
        std::uint64_t remaining_work = options.max_work;
        const auto charge = [&](std::uint64_t amount) {
            if (amount > remaining_work) return false;
            remaining_work -= amount; return true;
        };
        const auto is_driver = [](const UefiFfsFile &file) { return file.type >= 0x05 && file.type <= 0x07; };
        const auto count = volume.files.size();
        std::map<Guid,std::vector<std::size_t>> drivers;
        std::vector<std::vector<std::size_t>> predecessors(count);
        std::vector<std::optional<std::size_t>> before_target(count);
        std::vector<std::string> order_errors(count);
        std::vector<bool> request_context(count,false);
        std::vector<const UefiDriverProtocolEffect *> by_file(count,nullptr);
        std::vector<bool> selected(count,false);
        std::set<Guid> available;
        for (const auto &guid : initially_available)
            if (available.insert(guid).second) result.assumed_available_guids.push_back(guid);
        std::size_t protocol_rows = 0, provenance_bytes = 0, section_rows = 0, diagnostic_bytes = 0, valid_depex_count = 0;
        std::uint64_t depex_bytes = 0, base_expression_work = 0, guid_operands = 0;
        if (!charge(count+effects.size()+initially_available.size()))
            return Error{ErrorCode::resource_limit,"UEFI protocol-plan validation exceeds its work budget"};
        for (const auto &effect : effects) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled,"UEFI protocol planning canceled"};
            if (effect.file_index >= count || !is_driver(volume.files[effect.file_index]) || by_file[effect.file_index])
                return Error{ErrorCode::invalid_argument,"UEFI protocol effect has an invalid, non-driver or duplicate file index"};
            if (effect.installed_guids.size() > 4096 - protocol_rows || effect.provenance.size() > 4096 ||
                effect.provenance.size() > 1024*1024 - provenance_bytes)
                return Error{ErrorCode::resource_limit,"UEFI protocol effects exceed GUID/provenance limits"};
            protocol_rows += effect.installed_guids.size(); provenance_bytes += effect.provenance.size();
            by_file[effect.file_index] = &effect;
        }
        for (std::size_t i = 0; i < count; ++i) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled,"UEFI protocol planning canceled"};
            const auto &file = volume.files[i];
            if (file.volume_offset > volume.length || file.size > volume.length - file.volume_offset)
                return Error{ErrorCode::invalid_argument,"UEFI protocol plan file source extent exceeds its volume"};
            if (file.sections.size() > 65536 - section_rows)
                return Error{ErrorCode::resource_limit,"UEFI protocol plan exceeds 65536 section rows"};
            section_rows += file.sections.size();
            if (!charge(file.sections.size()+1))
                return Error{ErrorCode::resource_limit,"UEFI protocol-plan validation exceeds its work budget"};
            if (is_driver(file)) drivers[file.name_guid].push_back(i);
            std::size_t dependencies = 0;
            for (const auto &section : file.sections) {
                if (!is_driver(file) || section.type != section_dxe_depex) continue;
                if (++dependencies > 1)
                    return Error{ErrorCode::unsupported,"UEFI iterative protocol plan requires one unambiguous DXE DEPEX per driver"};
                if (section.depex_diagnostic.size()>4096 || section.depex_diagnostic.size()>1024*1024-diagnostic_bytes)
                    return Error{ErrorCode::resource_limit,"UEFI protocol plan exceeds dependency diagnostic byte limits"};
                diagnostic_bytes+=section.depex_diagnostic.size();
                if (section.depex_expression.size() > 4ull*1024*1024 - depex_bytes)
                    return Error{ErrorCode::resource_limit,"UEFI protocol plan exceeds 4 MiB of dependency bytes"};
                depex_bytes += section.depex_expression.size();
                if (!section.depex_valid.value_or(false)) continue;
                if (!charge(section.depex_expression.size()))
                    return Error{ErrorCode::resource_limit,"UEFI protocol-plan validation exceeds its work budget"};
                const auto validation = inspect_depex(section.depex_expression,section.type);
                if (!validation.valid)
                    return Error{ErrorCode::invalid_argument,"UEFI protocol plan contains falsely marked valid DEPEX metadata"};
                ++valid_depex_count;
                request_context[i]=!section.depex_expression.empty()&&u8(section.depex_expression,0)==0x09;
                base_expression_work += section.depex_expression.size() + validation.instruction_count +
                    std::uint64_t(validation.guid_operand_count) * (validation.guid_operand_count + 1);
                guid_operands += validation.guid_operand_count;
            }
        }
        for (std::size_t i = 0; i < count; ++i) {
            for (const auto &section : volume.files[i].sections) {
                if (!is_driver(volume.files[i]) || section.type != section_dxe_depex ||
                    !section.depex_valid.value_or(false) || section.depex_expression.empty()) continue;
                const auto code = std::span<const std::byte>(section.depex_expression);
                const auto opcode = u8(code,0);
                if (opcode != 0x00 && opcode != 0x01) continue;
                Guid target{};for (std::size_t n=0;n<16;++n) target[n]=u8(code,n+1);
                const auto found=drivers.find(target);
                if (found==drivers.end() || found->second.size()!=1) {
                    order_errors[i]="BEFORE/AFTER target GUID is absent or ambiguous in this volume"; continue;
                }
                const auto target_file=found->second.front();
                if (opcode==0x00) { predecessors[target_file].push_back(i);before_target[i]=target_file; }
                else predecessors[i].push_back(target_file);
            }
        }
        std::size_t rounds = 0;
        while (result.status != UefiProtocolDiscoveryStatus::work_limit) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled,"UEFI protocol planning canceled"};
            if (rounds == options.max_rounds) { result.status=UefiProtocolDiscoveryStatus::round_limit; break; }
            const auto round_work=3ull*count*count + section_rows + base_expression_work +
                guid_operands*available.size() + 16ull*valid_depex_count*available.size() + 1;
            if (!charge(round_work)) { result.status=UefiProtocolDiscoveryStatus::work_limit; break; }
            auto snapshot=plan_uefi_driver_dispatch(volume,result.assumed_available_guids);
            std::optional<std::size_t> chosen;
            for (const auto file : snapshot.ordered_file_indices) {
                if (selected[file] || !order_errors[file].empty() || request_context[file]) continue;
                if (before_target[file] && snapshot.entries[*before_target[file]].disposition != UefiDriverDispatchDisposition::ordered_ready)
                    continue;
                if (std::all_of(predecessors[file].begin(),predecessors[file].end(),[&](auto prior){return selected[prior];})) {
                    chosen=file;break;
                }
            }
            if (!chosen) {
                for (auto &entry : snapshot.entries) if (is_driver(volume.files[entry.file_index]) && !selected[entry.file_index]) {
                    if (request_context[entry.file_index]) {
                        entry.disposition=UefiDriverDispatchDisposition::blocked;entry.diagnostic="SOR requires caller dispatch-request context";
                    } else if (!order_errors[entry.file_index].empty()) {
                        entry.disposition=UefiDriverDispatchDisposition::ordering_unresolved;entry.diagnostic=order_errors[entry.file_index];
                    } else if (entry.disposition==UefiDriverDispatchDisposition::ordered_ready) {
                        entry.disposition=UefiDriverDispatchDisposition::ordering_unresolved;
                        entry.diagnostic="BEFORE/AFTER readiness or predecessor is blocked, cyclic or not yet assumed dispatched";
                    }
                    result.blocked_entries.push_back(std::move(entry));
                }
                break;
            }
            ++rounds;const auto file=*chosen;selected[file]=true;
            UefiProtocolDiscoveryStep step;
            step.round=rounds;step.file_index=file;step.file_guid=volume.files[file].name_guid;
            step.file_header_offset=volume.file_offset+volume.files[file].volume_offset;
            step.dependency_section_indices=std::move(snapshot.entries[file].dependency_section_indices);
            if (const auto *effect=by_file[file]) {
                step.effect_provenance=effect->provenance;
                for (const auto &guid : effect->installed_guids) if (available.insert(guid).second) {
                    if (available.size()>4096)return Error{ErrorCode::resource_limit,"UEFI assumed protocol set exceeds 4096 GUIDs"};
                    result.assumed_available_guids.push_back(guid);step.assumed_new_guids.push_back(guid);
                }
            }
            result.assumed_steps.push_back(std::move(step));
            bool all_selected=true;
            for (std::size_t i=0;i<count;++i) if (is_driver(volume.files[i])&&!selected[i]) {all_selected=false;break;}
            if (all_selected) break;
        }
        for (std::size_t i=0;i<count;++i) if (is_driver(volume.files[i])&&!selected[i]) result.remaining_file_indices.push_back(i);
        result.work_used=options.max_work-remaining_work;
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit,"Cannot allocate bounded UEFI protocol-discovery plan"};
    }
}

Result<UefiProtocolDiscoveryPlan> plan_uefi_pei_protocol_discovery(
    const UefiFirmwareVolume &volume,
    std::span<const std::array<std::uint8_t, 16>> initially_available_ppis,
    std::span<const UefiDriverProtocolEffect> effects,
    UefiProtocolDiscoveryOptions options, std::stop_token stop) {
    using Guid = std::array<std::uint8_t, 16>;
    const auto is_peim = [](const UefiFfsFile &file) { return file.type == 0x06 || file.type == 0x08; };
    if (volume.files.size() > 4096 || initially_available_ppis.size() > 4096 || effects.size() > 4096 ||
        !options.max_rounds || options.max_rounds > 4096 || !options.max_work || options.max_work > 256ull*1024*1024)
        return Error{ErrorCode::resource_limit,"UEFI PEI protocol plan exceeds file/PPI/effect/round/work limits"};
    if (volume.file_offset > UINT64_MAX - volume.length)
        return Error{ErrorCode::invalid_argument,"UEFI PEI protocol plan volume source extent overflows"};
    try {
        UefiProtocolDiscoveryPlan result;
        std::uint64_t remaining_work = options.max_work;
        const auto charge = [&](std::uint64_t amount) {
            if (amount > remaining_work) return false;
            remaining_work -= amount; return true;
        };
        const auto count = volume.files.size();
        std::vector<const UefiDriverProtocolEffect *> by_file(count, nullptr);
        std::vector<bool> selected(count, false);
        std::set<Guid> available;
        for (const auto &guid : initially_available_ppis)
            if (available.insert(guid).second) result.assumed_available_guids.push_back(guid);
        std::size_t effect_rows = 0, provenance_bytes = 0, section_rows = 0, depex_bytes = 0, diagnostic_bytes = 0;
        if (!charge(count + effects.size() + initially_available_ppis.size()))
            return Error{ErrorCode::resource_limit,"UEFI PEI protocol-plan validation exceeds its work budget"};
        for (const auto &effect : effects) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled,"UEFI PEI protocol planning canceled"};
            if (effect.file_index >= count || !is_peim(volume.files[effect.file_index]) || by_file[effect.file_index])
                return Error{ErrorCode::invalid_argument,"UEFI PPI effect has an invalid, non-PEIM or duplicate file index"};
            if (effect.installed_guids.size() > 4096 - effect_rows || effect.provenance.size() > 4096 ||
                effect.provenance.size() > 1024*1024 - provenance_bytes)
                return Error{ErrorCode::resource_limit,"UEFI PPI effects exceed GUID/provenance limits"};
            effect_rows += effect.installed_guids.size(); provenance_bytes += effect.provenance.size();
            by_file[effect.file_index] = &effect;
        }
        for (const auto &file : volume.files) {
            if (file.volume_offset > volume.length || file.size > volume.length - file.volume_offset)
                return Error{ErrorCode::invalid_argument,"UEFI PEI protocol plan file extent exceeds its volume"};
            if (file.sections.size() > 65536 - section_rows)
                return Error{ErrorCode::resource_limit,"UEFI PEI protocol plan exceeds 65536 section rows"};
            section_rows += file.sections.size();
            for (const auto &section : file.sections) if (section.type == section_pei_depex) {
                if (section.depex_diagnostic.size() > 4096 ||
                    section.depex_diagnostic.size() > 1024*1024 - diagnostic_bytes)
                    return Error{ErrorCode::resource_limit,"UEFI PEI protocol plan exceeds dependency diagnostic limits"};
                diagnostic_bytes += section.depex_diagnostic.size();
                if (section.depex_expression.size() > 4ull*1024*1024 - depex_bytes)
                    return Error{ErrorCode::resource_limit,"UEFI PEI protocol plan exceeds 4 MiB of dependency metadata"};
                depex_bytes += section.depex_expression.size();
            }
        }
        std::size_t rounds = 0;
        for (;;) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled,"UEFI PEI protocol planning canceled"};
            const auto round_work = 2ull*count*count + section_rows + depex_bytes +
                std::uint64_t(available.size())*count + 1;
            if (!charge(round_work)) { result.status = UefiProtocolDiscoveryStatus::work_limit; break; }
            const auto snapshot = plan_uefi_pei_dispatch(volume, result.assumed_available_guids);
            std::optional<std::size_t> chosen;
            for (const auto file : snapshot.ordered_file_indices)
                if (!selected[file]) { chosen = file; break; }
            if (!chosen) {
                for (auto entry : snapshot.entries) if (is_peim(volume.files[entry.file_index]) && !selected[entry.file_index])
                    result.blocked_entries.push_back(std::move(entry));
                break;
            }
            if (rounds == options.max_rounds) {
                result.status = UefiProtocolDiscoveryStatus::round_limit;
                result.blocked_entries.clear();
                break;
            }
            ++rounds;
            const auto file = *chosen;
            selected[file] = true;
            UefiProtocolDiscoveryStep step;
            step.round = rounds; step.file_index = file;
            step.file_guid = volume.files[file].name_guid;
            step.file_header_offset = volume.file_offset + volume.files[file].volume_offset;
            step.dependency_section_indices = snapshot.entries[file].dependency_section_indices;
            if (const auto *effect = by_file[file]) {
                step.effect_provenance = effect->provenance;
                for (const auto &guid : effect->installed_guids) if (available.insert(guid).second) {
                    if (available.size() > 4096)
                        return Error{ErrorCode::resource_limit,"UEFI assumed PPI set exceeds 4096 GUIDs"};
                    result.assumed_available_guids.push_back(guid);
                    step.assumed_new_guids.push_back(guid);
                }
            }
            result.assumed_steps.push_back(std::move(step));
            bool all_selected = true;
            for (std::size_t i = 0; i < count; ++i)
                if (is_peim(volume.files[i]) && !selected[i]) { all_selected = false; break; }
            if (all_selected) break;
        }
        for (std::size_t i = 0; i < count; ++i)
            if (is_peim(volume.files[i]) && !selected[i]) result.remaining_file_indices.push_back(i);
        result.work_used = options.max_work - remaining_work;
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit,"Cannot allocate bounded UEFI PEI protocol-discovery plan"};
    }
}
} // namespace hexlab::firmware
