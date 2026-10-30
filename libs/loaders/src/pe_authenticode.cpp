#include "pe_internal.hpp"
#include <array>
#include <new>

namespace hexlab {
namespace {
struct PeHashRange { std::uint64_t begin = 0, end = 0; };

class PeSha1 {
public:
    void update(std::span<const std::byte> input) noexcept {
        total_ += input.size();
        for (const auto byte : input) {
            tail_[used_++] = byte;
            if (used_ == tail_.size()) { compress(tail_.data()); used_ = 0; }
        }
    }
    std::array<std::byte, 20> digest() const noexcept {
        auto copy = *this;
        const auto bit_count = copy.total_ * 8;
        copy.tail_[copy.used_++] = std::byte{0x80};
        if (copy.used_ > 56) {
            std::fill(copy.tail_.begin() + static_cast<std::ptrdiff_t>(copy.used_), copy.tail_.end(), std::byte{});
            copy.compress(copy.tail_.data()); copy.used_ = 0;
        }
        std::fill(copy.tail_.begin() + static_cast<std::ptrdiff_t>(copy.used_), copy.tail_.begin() + 56, std::byte{});
        for (unsigned i = 0; i < 8; ++i) copy.tail_[63 - i] = std::byte((bit_count >> (8 * i)) & 0xff);
        copy.compress(copy.tail_.data());
        std::array<std::byte, 20> result{};
        for (std::size_t i = 0; i < copy.state_.size(); ++i)
            for (unsigned j = 0; j < 4; ++j)
                result[i * 4 + j] = std::byte((copy.state_[i] >> (24 - 8 * j)) & 0xff);
        return result;
    }
private:
    static std::uint32_t rol(std::uint32_t value, unsigned count) noexcept {
        return (value << count) | (value >> (32 - count));
    }
    void compress(const std::byte *block) noexcept {
        std::uint32_t w[80]{};
        for (unsigned i = 0; i < 16; ++i)
            for (unsigned j = 0; j < 4; ++j)
                w[i] = (w[i] << 8) | std::to_integer<std::uint8_t>(block[i * 4 + j]);
        for (unsigned i = 16; i < 80; ++i)
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        auto a = state_[0], b = state_[1], c = state_[2], d = state_[3], e = state_[4];
        for (unsigned i = 0; i < 80; ++i) {
            std::uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else { f = b ^ c ^ d; k = 0xca62c1d6; }
            const auto t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d; state_[4] += e;
    }
    std::array<std::uint32_t,5> state_{0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
    std::array<std::byte,64> tail_{};
    std::size_t used_=0;
    std::uint64_t total_=0;
};

std::uint64_t read_le(const ByteStorage &storage, std::uint64_t at, unsigned width,
                      const char *field) {
    auto view = storage.read_at({at}, width);
    if (!view) throw pe_detail::Failure{{ErrorCode::malformed,
        std::string("Truncated PE ") + field + " at file offset " + std::to_string(at)}};
    std::uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i)
        value |= std::to_integer<std::uint64_t>(view.value().bytes[i]) << (8 * i);
    return value;
}

void hash_file_range(const ByteStorage &storage, PeHashRange range,
                     std::span<const PeHashRange> exclusions, Sha256 &hash,
                     PeSha1 &sha1, std::uint64_t &hashed_bytes, std::stop_token stop) {
    constexpr std::size_t chunk_size = 64 * 1024;
    std::array<std::byte, chunk_size> buffer{};
    auto hash_part = [&](std::uint64_t begin, std::uint64_t end) {
        while (begin < end) {
            pe_detail::canceled(stop);
            const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(end - begin, buffer.size()));
            auto view = storage.read_at({begin}, count);
            if (!view) throw pe_detail::Failure{{ErrorCode::malformed,
                "Truncated PE image bytes while computing Authenticode digest"}};
            const auto updated = hash.update(view.value().bytes);
            if (!updated) throw pe_detail::Failure{updated.error()};
            sha1.update(view.value().bytes);
            if (count > UINT64_MAX - hashed_bytes)
                throw pe_detail::Failure{{ErrorCode::overflow, "Authenticode hashed-byte count overflows"}};
            hashed_bytes += count;
            begin += count;
        }
    };
    auto cursor = range.begin;
    for (const auto excluded : exclusions) {
        if (excluded.end <= cursor || excluded.begin >= range.end) continue;
        if (excluded.begin > cursor) hash_part(cursor, std::min(excluded.begin, range.end));
        cursor = std::max(cursor, std::min(excluded.end, range.end));
        if (cursor == range.end) break;
    }
    if (cursor < range.end) hash_part(cursor, range.end);
}
}

Result<PeAuthenticodeImageDigest> compute_pe_authenticode_sha256(
    const Image &image, const ImageMetadata &metadata, std::stop_token stop) {
    using namespace pe_detail;
    try {
        require(metadata.pe.has_value(),
                "Authenticode image digest requires a loaded PE image", ErrorCode::invalid_argument);
        const auto &storage = *image.storage();
        canceled(stop);
        const auto nt = read_le(storage, 0x3c, 4, "DOS e_lfanew");
        require(read_le(storage, nt, 4, "signature") == 0x00004550,
                "Missing PE signature");
        const auto optional = add(nt, 24, "optional-header position");
        const auto optional_size = read_le(storage, add(nt, 20, "optional-header size"), 2,
                                           "optional-header size");
        require(optional_size >= 68, "PE optional header is too short for checksum");
        const auto magic = read_le(storage, optional, 2, "optional-header magic");
        require(magic == 0x10b || magic == 0x20b,
                "PE optional-header magic is unsupported", ErrorCode::unsupported);
        const auto directory_base = magic == 0x10b ? 96u : 112u;
        const auto count_offset = magic == 0x10b ? 92u : 108u;
        const auto header_size = read_le(storage, add(optional, 60, "SizeOfHeaders"), 4, "SizeOfHeaders");
        require(header_size <= storage.size() && header_size >= add(optional, optional_size, "header extent"),
                "PE SizeOfHeaders is inconsistent with its optional header");
        std::vector<PeHashRange> exclusions;
        exclusions.push_back({add(optional, 64, "checksum offset"), add(optional, 68, "checksum end")});
        std::optional<PeHashRange> certificates;
        if (optional_size >= count_offset + 4) {
            const auto directory_count = read_le(storage, add(optional, count_offset, "directory count"), 4,
                                                 "directory count");
            if (directory_count > 4) {
                require(optional_size >= directory_base + 5 * 8,
                        "PE optional header truncates the security directory");
                const auto security = add(optional, directory_base + 4 * 8, "security directory");
                exclusions.push_back({security, add(security, 8, "security directory end")});
                const auto file_offset = read_le(storage, security, 4, "certificate file offset");
                const auto certificate_size = read_le(storage, security + 4, 4, "certificate size");
                require((file_offset == 0) == (certificate_size == 0),
                        "PE certificate offset and size are inconsistent");
                if (certificate_size) {
                    require((file_offset & 7u) == 0 && (certificate_size & 7u) == 0,
                            "PE certificate table is not 8-byte aligned");
                    require(file_offset <= storage.size() && certificate_size <= storage.size() - file_offset,
                            "PE certificate table exceeds input");
                    certificates = PeHashRange{file_offset, file_offset + certificate_size};
                    exclusions.push_back(*certificates);
                }
            }
        }
        std::sort(exclusions.begin(), exclusions.end(), [](const auto &a, const auto &b) {
            return a.begin < b.begin || (a.begin == b.begin && a.end < b.end);
        });
        for (std::size_t i = 1; i < exclusions.size(); ++i)
            if (exclusions[i].begin < exclusions[i - 1].end)
                exclusions[i].begin = exclusions[i - 1].end;

        PeAuthenticodeImageDigest result;
        Sha256 hash;
        PeSha1 sha1;
        hash_file_range(storage, {0, header_size}, exclusions, hash, sha1, result.hashed_byte_count, stop);
        auto sections = metadata.sections;
        auto raw_order = sections;
        std::sort(raw_order.begin(), raw_order.end(), [](const auto &a, const auto &b) {
            return a.raw_position.value < b.raw_position.value;
        });
        if (certificates) {
            require(certificates->begin >= header_size,
                    "PE certificate table overlaps the image headers");
            for (const auto &section : raw_order) {
                if (section.raw_size == 0) continue;
                const auto section_begin = std::uint64_t{section.raw_position.value};
                const auto section_end = section_begin + section.raw_size;
                require(certificates->end <= section_begin || certificates->begin >= section_end,
                        "PE certificate table overlaps section bytes");
            }
        }
        std::uint64_t previous_raw_end = header_size;
        for (const auto &section : raw_order) {
            if (section.raw_size == 0) continue;
            const auto raw_begin = section.raw_position.value;
            require(raw_begin >= header_size && raw_begin >= previous_raw_end,
                    "PE section raw ranges overlap headers or another section");
            require(raw_begin <= storage.size() && section.raw_size <= storage.size() - raw_begin,
                    "PE section raw data exceeds input");
            previous_raw_end = raw_begin + section.raw_size;
        }
        std::sort(sections.begin(), sections.end(), [](const auto &a, const auto &b) {
            return a.rva.value < b.rva.value || (a.rva.value == b.rva.value &&
                   a.raw_position.value < b.raw_position.value);
        });
        std::uint64_t previous_rva_end = 0;
        for (const auto &section : sections) {
            canceled(stop);
            if (section.raw_size == 0) continue;
            const auto raw_begin = section.raw_position.value;
            const auto rva_size = std::max(section.virtual_size, section.raw_size);
            const auto rva_end = std::uint64_t{section.rva.value} + rva_size;
            require(rva_end <= UINT32_MAX + std::uint64_t{1}, "PE section virtual extent overflows");
            require(section.rva.value >= previous_rva_end,
                    "PE sections overlap or are not ordered by virtual address");
            previous_rva_end = rva_end;
            hash_file_range(storage, {raw_begin, raw_begin + section.raw_size}, exclusions,
                            hash, sha1, result.hashed_byte_count, stop);
        }
        result.sha256 = hash.digest();
        result.sha1 = sha1.digest();
        return result;
    } catch (const Failure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate Authenticode digest state"};
    }
}
}
