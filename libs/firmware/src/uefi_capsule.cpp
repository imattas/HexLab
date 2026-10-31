#include "hexlab/firmware/uefi_capsule.hpp"
#include "hexlab/firmware/uefi_volume.hpp"
#include <algorithm>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <utility>

namespace hexlab::firmware {
namespace {
std::uint8_t u8(std::span<const std::byte> b, std::size_t at) { return std::to_integer<std::uint8_t>(b[at]); }
std::uint16_t u16(std::span<const std::byte> b, std::size_t at) {
    return static_cast<std::uint16_t>(u8(b, at) | (std::uint16_t(u8(b, at + 1)) << 8));
}
std::uint32_t u32(std::span<const std::byte> b, std::size_t at) {
    return std::uint32_t(u16(b, at)) | (std::uint32_t(u16(b, at + 2)) << 16);
}
std::uint64_t u64(std::span<const std::byte> b, std::size_t at) {
    return std::uint64_t(u32(b, at)) | (std::uint64_t(u32(b, at + 4)) << 32);
}
constexpr std::array<std::uint8_t, 16> fmp_guid{
    0xed,0xd5,0xcb,0x6d,0x2d,0xe8,0x44,0x4c,0xbd,0xa1,0x71,0x94,0x19,0x9a,0xd9,0x2a};
constexpr std::array<std::uint8_t, 16> json_guid{
    0xcd,0xf4,0xd6,0x67,0xb8,0xd6,0x73,0x45,0xbf,0x4a,0xde,0x5e,0x25,0x2d,0x61,0xae};
// EFI_CERT_TYPE_PKCS7_GUID as it appears in the little-endian UEFI structure.
constexpr std::array<std::uint8_t, 16> pkcs7_guid{
    0x9d,0xd2,0xaf,0x4a,0xdf,0x68,0xee,0x49,0x8a,0xa9,0x34,0x7d,0x37,0x56,0x65,0xa7};
constexpr std::uint32_t fmp_payload_signature = 0x3153534d; // "MSS1"
constexpr std::uint32_t capsule_reserved_spec_flags = 0xfff80000u;
constexpr std::uint64_t capsule_support_authentication = 0x1;
constexpr std::uint64_t capsule_support_dependency = 0x2;
constexpr std::uint64_t capsule_support_known_bits =
    capsule_support_authentication | capsule_support_dependency;
constexpr std::size_t max_dependency_expression_bytes = 1024 * 1024;
Error malformed(const char *message) { return {ErrorCode::malformed, message}; }

struct DependencyInstruction {
    std::uint8_t opcode = 0;
    std::array<std::uint8_t, 16> guid{};
    std::uint32_t version = 0;
};
struct ParsedDependency {
    std::size_t size = 0;
    std::vector<DependencyInstruction> instructions;
};
struct DependencyStackValue {
    bool is_boolean = false;
    bool known = true;
    bool missing_guid = false;
    bool boolean = false;
    std::uint32_t version = 0;
};

Result<ParsedDependency> parse_dependency_expression(std::span<const std::byte> bytes,
                                                     bool allow_trailing, std::stop_token stop) {
    if (bytes.empty()) return malformed("FMP dependency expression is empty");
    if (!allow_trailing && bytes.size() > max_dependency_expression_bytes)
        return Error{ErrorCode::resource_limit, "FMP dependency expression exceeds 1 MiB limit"};
    const auto input = bytes.first(std::min(bytes.size(), max_dependency_expression_bytes));
    std::size_t position = 0;
    std::size_t expression_end = input.size();
    const bool has_declared_length = u8(input, 0) == 0x0e;
    if (has_declared_length) {
        if (input.size() < 5) return malformed("FMP dependency DECLARE_LENGTH is truncated");
        const auto declared = u32(input, 1);
        if (declared > max_dependency_expression_bytes)
            return Error{ErrorCode::resource_limit, "FMP dependency expression exceeds 1 MiB limit"};
        if (declared < 6 || declared > bytes.size())
            return malformed("FMP dependency DECLARE_LENGTH is outside the image payload");
        expression_end = declared;
    }

    ParsedDependency parsed;
    std::vector<bool> boolean_stack;
    bool ended = false;
    while (position < expression_end) {
        if ((position & 4095u) == 0 && stop.stop_requested())
            return Error{ErrorCode::canceled, "FMP dependency parsing canceled"};
        const auto at = position;
        const auto opcode = u8(input, position++);
        DependencyInstruction instruction;
        instruction.opcode = opcode;
        const auto require_bytes = [&](std::size_t count) {
            return count <= expression_end - position;
        };
        const auto pop_type = [&](bool is_boolean) {
            if (boolean_stack.empty() || boolean_stack.back() != is_boolean) return false;
            boolean_stack.pop_back();
            return true;
        };
        switch (opcode) {
        case 0x00:
            if (!require_bytes(16)) return malformed("FMP dependency PUSH_GUID operand is truncated");
            for (std::size_t i = 0; i < 16; ++i) instruction.guid[i] = u8(input, position + i);
            position += 16;
            boolean_stack.push_back(false);
            break;
        case 0x01:
            if (!require_bytes(4)) return malformed("FMP dependency PUSH_VERSION operand is truncated");
            instruction.version = u32(input, position);
            position += 4;
            boolean_stack.push_back(false);
            break;
        case 0x02: {
            // Version names are CHAR16 strings and do not participate in comparisons.
            bool terminated = false;
            bool pending_high_surrogate = false;
            while (require_bytes(2)) {
                const auto code_unit = u16(input, position);
                position += 2;
                if (code_unit == 0) {
                    if (pending_high_surrogate) return malformed("FMP dependency version name has an unpaired surrogate");
                    terminated = true;
                    break;
                }
                if (pending_high_surrogate) {
                    if (code_unit < 0xdc00 || code_unit > 0xdfff)
                        return malformed("FMP dependency version name has an unpaired surrogate");
                    pending_high_surrogate = false;
                } else if (code_unit >= 0xd800 && code_unit <= 0xdbff) {
                    pending_high_surrogate = true;
                } else if (code_unit >= 0xdc00 && code_unit <= 0xdfff) {
                    return malformed("FMP dependency version name has an unpaired surrogate");
                }
            }
            if (!terminated) return malformed("FMP dependency version name is not null-terminated UTF-16");
            break;
        }
        case 0x03: case 0x04:
            if (!pop_type(true) || !pop_type(true))
                return malformed("FMP dependency boolean operator has invalid operands");
            boolean_stack.push_back(true);
            break;
        case 0x05:
            if (!pop_type(true)) return malformed("FMP dependency NOT has an invalid operand");
            boolean_stack.push_back(true);
            break;
        case 0x06: case 0x07:
            boolean_stack.push_back(true);
            break;
        case 0x08: case 0x09: case 0x0a: case 0x0b: case 0x0c:
            if (!pop_type(false) || !pop_type(false))
                return malformed("FMP dependency comparison has invalid operands");
            boolean_stack.push_back(true);
            break;
        case 0x0d:
            if ((has_declared_length && position != expression_end) ||
                (!allow_trailing && position != input.size()) || boolean_stack.size() != 1 || !boolean_stack.back())
                return malformed("FMP dependency END is not final or does not leave one boolean result");
            ended = true;
            parsed.size = position;
            if (parsed.instructions.size() >= 65536)
                return Error{ErrorCode::resource_limit, "FMP dependency instruction limit reached"};
            parsed.instructions.push_back(instruction);
            break;
        case 0x0e:
            if (at != 0 || (!allow_trailing && expression_end != input.size()) || position != 1 || !require_bytes(4))
                return malformed("FMP dependency DECLARE_LENGTH is not the first opcode");
            position = 1;
            // The length includes this opcode and its four-byte operand.
            (void)u32(input, position);
            position += 4;
            break;
        default:
            return malformed("FMP dependency expression contains an unsupported opcode");
        }
        if (opcode != 0x0e) {
            if (parsed.instructions.size() >= 65536)
                return Error{ErrorCode::resource_limit, "FMP dependency instruction limit reached"};
            parsed.instructions.push_back(instruction);
        }
        if (ended) break;
    }
    if (!ended && allow_trailing && bytes.size() > input.size())
        return Error{ErrorCode::resource_limit, "FMP dependency expression scan reached 1 MiB without END"};
    if (!ended) return malformed("FMP dependency expression has no final END opcode");
    if (!allow_trailing && parsed.size != input.size())
        return malformed("FMP dependency expression has trailing bytes");
    if (has_declared_length && parsed.size != expression_end)
        return malformed("FMP dependency expression length does not end at END");
    return parsed;
}
class JsonSyntaxParser {
public:
    JsonSyntaxParser(std::span<const std::byte> bytes, std::size_t depth_limit, std::stop_token stop)
        : bytes_(bytes), depth_limit_(depth_limit), stop_(stop) {}

    Result<bool> parse() {
        skip_space();
        if (auto error = checkpoint()) return *error;
        if (!parse_value(0)) {
            if (auto error = checkpoint()) return *error;
            return malformed("EFI JSON capsule payload is not valid JSON");
        }
        skip_space();
        if (auto error = checkpoint()) return *error;
        if (position_ != bytes_.size()) return malformed("EFI JSON capsule payload has trailing non-whitespace bytes");
        return true;
    }

private:
    std::span<const std::byte> bytes_;
    std::size_t depth_limit_;
    std::stop_token stop_;
    std::size_t position_ = 0;

    std::uint8_t peek() const { return position_ < bytes_.size() ? u8(bytes_, position_) : 0; }
    bool take(std::uint8_t c) {
        if (position_ >= bytes_.size() || u8(bytes_, position_) != c) return false;
        ++position_;
        return true;
    }
    void skip_space() {
        while (position_ < bytes_.size()) {
            const auto c = peek();
            if (c != 0x20 && c != 0x09 && c != 0x0a && c != 0x0d) break;
            ++position_;
        }
    }
    std::optional<Error> checkpoint() const {
        if (stop_.stop_requested()) return Error{ErrorCode::canceled, "EFI JSON payload validation canceled"};
        return {};
    }
    bool hex4(std::uint32_t &value) {
        if (bytes_.size() - position_ < 4) return false;
        value = 0;
        for (unsigned i = 0; i < 4; ++i) {
            const auto c = u8(bytes_, position_++);
            unsigned digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else return false;
            value = (value << 4) | digit;
        }
        return true;
    }
    bool parse_string() {
        if (!take('"')) return false;
        while (position_ < bytes_.size()) {
            if ((position_ & 4095u) == 0 && stop_.stop_requested()) return false;
            const auto c = u8(bytes_, position_++);
            if (c == '"') return true;
            if (c == '\\') {
                if (position_ == bytes_.size()) return false;
                const auto escaped = u8(bytes_, position_++);
                if (escaped == '"' || escaped == '\\' || escaped == '/' || escaped == 'b' || escaped == 'f' ||
                    escaped == 'n' || escaped == 'r' || escaped == 't') continue;
                if (escaped != 'u') return false;
                std::uint32_t codepoint;
                if (!hex4(codepoint)) return false;
                if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                    if (!take('\\') || !take('u')) return false;
                    std::uint32_t low;
                    if (!hex4(low) || low < 0xdc00 || low > 0xdfff) return false;
                } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) return false;
                continue;
            }
            if (c < 0x20) return false;
            if (c < 0x80) continue;
            unsigned continuation_count;
            std::uint32_t codepoint;
            if (c >= 0xc2 && c <= 0xdf) { continuation_count = 1; codepoint = c & 0x1f; }
            else if (c >= 0xe0 && c <= 0xef) { continuation_count = 2; codepoint = c & 0x0f; }
            else if (c >= 0xf0 && c <= 0xf4) { continuation_count = 3; codepoint = c & 0x07; }
            else return false;
            if (bytes_.size() - position_ < continuation_count) return false;
            for (unsigned i = 0; i < continuation_count; ++i) {
                const auto next = u8(bytes_, position_++);
                if ((next & 0xc0) != 0x80) return false;
                codepoint = (codepoint << 6) | (next & 0x3f);
            }
            if ((continuation_count == 1 && codepoint < 0x80) ||
                (continuation_count == 2 && codepoint < 0x800) ||
                (continuation_count == 3 && codepoint < 0x10000) ||
                (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff) return false;
        }
        return false;
    }
    bool parse_number() {
        take('-');
        if (!take('0')) {
            if (peek() < '1' || peek() > '9') return false;
            do { ++position_; } while (peek() >= '0' && peek() <= '9');
        }
        if (take('.')) {
            if (peek() < '0' || peek() > '9') return false;
            do { ++position_; } while (peek() >= '0' && peek() <= '9');
        }
        if (take('e') || take('E')) {
            if (!take('+')) take('-');
            if (peek() < '0' || peek() > '9') return false;
            do { ++position_; } while (peek() >= '0' && peek() <= '9');
        }
        return true;
    }
    bool literal(std::string_view expected) {
        if (bytes_.size() - position_ < expected.size()) return false;
        for (char c : expected) if (u8(bytes_, position_++) != static_cast<std::uint8_t>(c)) return false;
        return true;
    }
    bool parse_value(std::size_t depth) {
        if (position_ >= bytes_.size() || ((position_ & 4095u) == 0 && stop_.stop_requested())) return false;
        skip_space();
        const auto c = peek();
        if (c == '"') return parse_string();
        if (c == 'n') return literal("null");
        if (c == 't') return literal("true");
        if (c == 'f') return literal("false");
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
        if (c != '[' && c != '{') return false;
        if (depth >= depth_limit_) return false;
        const bool object = c == '{';
        ++position_;
        skip_space();
        const auto close = object ? '}' : ']';
        if (take(close)) return true;
        for (;;) {
            if (object) {
                if (!parse_string()) return false;
                skip_space();
                if (!take(':')) return false;
            }
            if (!parse_value(depth + 1)) return false;
            skip_space();
            if (take(close)) return true;
            if (!take(',')) return false;
            skip_space();
        }
    }
};
struct NestedBudget {
    std::size_t capsules = 0;
    std::uint64_t bytes = 0;
};
Result<UefiCapsule> parse_fmp_impl(std::span<const std::byte>, UefiCapsuleParseOptions,
                                   std::stop_token, bool, std::size_t, NestedBudget &);
Result<bool> inspect_nested_capsules(UefiCapsuleItem &, std::span<const std::byte>, std::uint64_t, std::uint64_t,
                                    UefiCapsuleParseOptions, std::stop_token, std::size_t, NestedBudget &);
}

namespace {
Result<UefiCapsule> parse_fmp_impl(std::span<const std::byte> bytes, UefiCapsuleParseOptions options,
                                   std::stop_token stop, bool scan_embedded_volumes,
                                   std::size_t nested_depth, NestedBudget &nested_budget) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule parsing canceled"};
    if (bytes.size() > options.max_input_bytes) return Error{ErrorCode::resource_limit, "UEFI capsule exceeds input-size limit"};
    if (bytes.size() < 28) return malformed("EFI capsule header is truncated");
    UefiCapsule result;
    for (std::size_t i = 0; i < 16; ++i) result.capsule_guid[i] = u8(bytes, i);
    if (result.capsule_guid != fmp_guid) return Error{ErrorCode::unsupported, "capsule GUID is not EFI FMP"};
    result.header_size = u32(bytes, 16);
    result.flags = u32(bytes, 20);
    result.image_size = u32(bytes, 24);
    if (result.header_size < 28 || result.header_size > result.image_size || result.image_size > bytes.size())
        return malformed("EFI capsule header or declared image size is inconsistent with the input");
    if (result.flags & capsule_reserved_spec_flags)
        return malformed("EFI capsule sets reserved specification flag bits");
    result.header_extension_size = result.header_size - 28;
    result.trailing_size = bytes.size() - result.image_size;
    // UEFI 2.10 §23.3.3 requires POPULATE_SYSTEM_TABLE to be clear for FMP
    // capsules. Keep the other capsule flags intact for metadata presentation.
    if (result.flags & 0x00020000u)
        return malformed("FMP capsule sets CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE");
    constexpr std::uint32_t capsule_persist_across_reset = 0x00010000u;
    constexpr std::uint32_t capsule_initiate_reset = 0x00040000u;
    if ((result.flags & capsule_initiate_reset) && !(result.flags & capsule_persist_across_reset))
        return malformed("CAPSULE_FLAGS_INITIATE_RESET requires CAPSULE_FLAGS_PERSIST_ACROSS_RESET");
    const std::size_t base = result.header_size;
    if (result.image_size - base < 8) return malformed("FMP capsule header is truncated");
    result.fmp_version = u32(bytes, base);
    result.embedded_driver_count = u16(bytes, base + 4);
    result.payload_count = u16(bytes, base + 6);
    if (result.fmp_version != 1) return Error{ErrorCode::unsupported, "unsupported FMP capsule header version"};
    const std::size_t count = std::size_t(result.embedded_driver_count) + result.payload_count;
    if (count > options.max_items) return Error{ErrorCode::resource_limit, "FMP capsule item count exceeds limit"};
    if (count > (std::numeric_limits<std::size_t>::max)() / 8 || 8 + count * 8 > result.image_size - base)
        return malformed("FMP item-offset list is truncated");
    const std::size_t data_start = 8 + count * 8;
    std::vector<std::uint64_t> offsets;
    offsets.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule parsing canceled"};
        const auto offset = u64(bytes, base + 8 + i * 8);
        if (offset < data_start || offset >= result.image_size - base || (!offsets.empty() && offset <= offsets.back()))
            return malformed("FMP item offsets are out of range or not strictly ascending");
        offsets.push_back(offset);
    }
    result.items.reserve(count);
    std::size_t embedded_volumes_used = 0;
    std::size_t embedded_files_used = 0;
    std::size_t embedded_sections_used = 0;
    std::size_t embedded_scans_used = 0;
    std::uint64_t embedded_decompressed_used = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule parsing canceled"};
        const std::uint64_t item_start = offsets[i];
        const std::uint64_t item_end = i + 1 < count ? offsets[i + 1] : result.image_size - base;
        UefiCapsuleItem item;
        item.file_offset = base + item_start;
        item.size = item_end - item_start;
        if (i < result.embedded_driver_count) {
            item.kind = UefiCapsuleItemKind::embedded_driver;
        } else {
            item.kind = UefiCapsuleItemKind::fmp_payload;
            if (item.size < 32) return malformed("FMP image header is truncated");
            const auto p = static_cast<std::size_t>(item.file_offset);
            item.image_header_version = u32(bytes, p);
            if (item.image_header_version < 1 || item.image_header_version > 3)
                return Error{ErrorCode::unsupported, "unsupported FMP image header version"};
            item.image_header_size = item.image_header_version == 1 ? 32 : item.image_header_version == 2 ? 40 : 48;
            if (item.size < item.image_header_size) return malformed("versioned FMP image header is truncated");
            for (std::size_t j = 0; j < 16; ++j) item.image_type_guid[j] = u8(bytes, p + 4 + j);
            item.image_index = u8(bytes, p + 20);
            if (u8(bytes, p + 21) != 0 || u8(bytes, p + 22) != 0 || u8(bytes, p + 23) != 0)
                return malformed("FMP image header reserved bytes are nonzero");
            item.update_image_size = u32(bytes, p + 24);
            item.vendor_code_size = u32(bytes, p + 28);
            if (item.image_header_version >= 2) item.hardware_instance = u64(bytes, p + 32);
            if (item.image_header_version >= 3) {
                item.image_capsule_support_offset = p + 40;
                item.image_capsule_support = u64(bytes, p + 40);
                item.capsule_support_authentication_advertised =
                    (item.image_capsule_support & capsule_support_authentication) != 0;
                item.capsule_support_dependency_advertised =
                    (item.image_capsule_support & capsule_support_dependency) != 0;
                item.capsule_support_unrecognized_bits = item.image_capsule_support & ~capsule_support_known_bits;
            }
            const std::uint64_t content_size = item.image_header_size + item.update_image_size + item.vendor_code_size;
            if (content_size != item.size) return malformed("FMP image and vendor-code sizes do not match item extent");
            item.payload_offset = item.file_offset + item.image_header_size;
            item.vendor_code_offset = item.payload_offset + item.update_image_size;

            // IMAGE_AUTHENTICATION_REQUIRED images start UpdateImage with
            // EFI_FIRMWARE_IMAGE_AUTHENTICATION (UINT64 count + a 24-byte
            // WIN_CERTIFICATE_UEFI_GUID header + PKCS#7 bytes). Recognize only
            // the specified certificate kind; other payloads stay opaque.
            if (item.update_image_size >= 32) {
                const auto auth = static_cast<std::size_t>(item.payload_offset);
                const auto certificate_size = u32(bytes, auth + 8);
                const bool is_pkcs7_auth = u16(bytes, auth + 12) == 0x0200 &&
                    u16(bytes, auth + 14) == 0x0ef1 &&
                    std::equal(pkcs7_guid.begin(), pkcs7_guid.end(),
                               reinterpret_cast<const std::uint8_t *>(bytes.data() + auth + 16));
                if (is_pkcs7_auth) {
                    if (certificate_size < 24 || certificate_size > item.update_image_size - 8)
                        return malformed("FMP authentication certificate extent is invalid");
                    item.authentication_present = true;
                    item.authentication_monotonic_count = u64(bytes, auth);
                    item.authentication_certificate_size = certificate_size;
                    std::copy_n(pkcs7_guid.begin(), pkcs7_guid.size(), item.authentication_certificate_guid.begin());
                    item.authentication_certificate_offset = item.payload_offset + 8;
                    item.authentication_certificate_data_offset = item.payload_offset + 32;
                    item.authentication_certificate_data_size = certificate_size - 24;
                    item.authentication_header_size = 8 + certificate_size;
                    item.payload_offset += item.authentication_header_size;
                }
            }
            if (item.image_header_version >= 3 &&
                item.capsule_support_authentication_advertised != item.authentication_present) {
                item.capsule_support_authentication_mismatch = true;
                item.capsule_support_authentication_diagnostic = item.capsule_support_authentication_advertised
                    ? "CAPSULE_SUPPORT_AUTHENTICATION is set but the PKCS#7 authentication prefix was not recognized"
                    : "PKCS#7 authentication prefix is present while CAPSULE_SUPPORT_AUTHENTICATION is clear";
            }

            item.firmware_image_offset = item.payload_offset;
            const auto authenticated_image_size = std::uint64_t(item.update_image_size) - item.authentication_header_size;
            std::uint64_t dependency_size = 0;
            if ((item.image_capsule_support & capsule_support_dependency) != 0) {
                const auto dependency_bytes = bytes.subspan(static_cast<std::size_t>(item.payload_offset),
                                                              static_cast<std::size_t>(authenticated_image_size));
                auto dependency = parse_dependency_expression(dependency_bytes, true, stop);
                if (!dependency) return dependency.error();
                dependency_size = dependency.value().size;
                item.dependency_expression_present = true;
                item.dependency_expression_offset = item.payload_offset;
                item.dependency_expression_size = dependency_size;
                item.firmware_image_offset += dependency_size;
            }
            const auto image_data_size = authenticated_image_size - dependency_size;
            if (item.authentication_present) {
                // UEFI signs the monotonic count, any dependency expression,
                // and the image bytes. The latter are a single span following
                // the optional dependency prefix; vendor code is outside the
                // UpdateImage extent and is not included here.
                item.authentication_signed_image_offset = item.payload_offset + dependency_size;
                item.authentication_signed_image_size = image_data_size;
            }
            if (image_data_size >= 4 && u32(bytes, static_cast<std::size_t>(item.firmware_image_offset)) == fmp_payload_signature) {
                if (image_data_size < 16) return malformed("FMP payload header is truncated");
                const auto header = static_cast<std::size_t>(item.firmware_image_offset);
                const auto header_size = u32(bytes, header + 4);
                if (header_size < 16 || header_size > image_data_size)
                    return malformed("FMP payload header has an invalid declared size");
                item.fmp_payload_header_present = true;
                item.fmp_payload_header_offset = item.firmware_image_offset;
                item.fmp_payload_header_size = header_size;
                item.firmware_version = u32(bytes, header + 8);
                item.lowest_supported_firmware_version = u32(bytes, header + 12);
                if (item.lowest_supported_firmware_version > item.firmware_version)
                    return malformed("FMP payload lowest-supported version exceeds its firmware version");
                item.firmware_image_offset += header_size;
            }

            const auto image_payload_size = image_data_size - item.fmp_payload_header_size;
            if (scan_embedded_volumes && image_payload_size >= 56 && embedded_scans_used < options.max_embedded_payload_scans &&
                embedded_volumes_used < options.max_embedded_volumes &&
                embedded_files_used < options.max_embedded_files &&
                embedded_sections_used < options.max_embedded_sections &&
                embedded_decompressed_used < options.max_embedded_decompressed_bytes) {
                const auto scan_limit = options.max_embedded_decompressed_bytes / options.max_embedded_payload_scans;
                const auto payload = bytes.subspan(static_cast<std::size_t>(item.firmware_image_offset),
                                                   static_cast<std::size_t>(image_payload_size));
                UefiVolumeParseOptions volume_options;
                volume_options.max_input_bytes = options.max_input_bytes;
                volume_options.max_volumes = options.max_embedded_volumes - embedded_volumes_used;
                volume_options.max_files = options.max_embedded_files - embedded_files_used;
                volume_options.max_sections = options.max_embedded_sections - embedded_sections_used;
                volume_options.max_total_decompressed_bytes = std::min(
                    scan_limit, options.max_embedded_decompressed_bytes - embedded_decompressed_used);
                ++embedded_scans_used;
                item.embedded_volume_scan_attempted = true;
                auto volumes = parse_uefi_firmware_volumes(payload, volume_options, stop);
                if (!volumes) {
                    if (volumes.error().code == ErrorCode::canceled) return volumes.error();
                    if (volumes.error().code != ErrorCode::unsupported) {
                        item.embedded_volume_scan_complete = false;
                        item.embedded_volume_diagnostic = volumes.error().message;
                    }
                } else {
                    for (const auto &volume : volumes.value()) {
                        std::size_t sections = 0;
                        std::uint64_t decompressed_bytes = 0;
                        for (const auto &file : volume.files) {
                            sections += file.sections.size();
                            for (const auto &section : file.sections) {
                                if (section.decompression_succeeded && section.uncompressed_size)
                                    decompressed_bytes += *section.uncompressed_size;
                            }
                        }
                        if (embedded_volumes_used == options.max_embedded_volumes ||
                            volume.files.size() > options.max_embedded_files - embedded_files_used ||
                            sections > options.max_embedded_sections - embedded_sections_used ||
                            decompressed_bytes > options.max_embedded_decompressed_bytes - embedded_decompressed_used) {
                            item.embedded_volume_scan_complete = false;
                            item.embedded_volume_diagnostic = "embedded firmware-volume inventory budget exceeded";
                            break;
                        }
                        UefiCapsuleEmbeddedVolume embedded;
                        embedded.file_offset = item.firmware_image_offset + volume.file_offset;
                        embedded.size = volume.length;
                        embedded.file_system_guid = volume.file_system_guid;
                        embedded.revision = volume.revision;
                        embedded.file_count = volume.files.size();
                        embedded.section_count = sections;
                        embedded.decompressed_bytes = decompressed_bytes;
                        embedded.header_checksum_valid = volume.header_checksum_valid;
                        item.embedded_volumes.push_back(embedded);
                        ++embedded_volumes_used;
                        embedded_files_used += volume.files.size();
                        embedded_sections_used += sections;
                        embedded_decompressed_used += decompressed_bytes;
                    }
                }
            } else if (scan_embedded_volumes && image_payload_size >= 56) {
                item.embedded_volume_scan_complete = false;
                item.embedded_volume_diagnostic = embedded_scans_used >= options.max_embedded_payload_scans
                    ? "embedded firmware-volume payload scan count limit reached"
                    : "embedded firmware-volume inventory budget exhausted";
            }
        }
        const auto nested_offset = item.kind == UefiCapsuleItemKind::fmp_payload
            ? item.firmware_image_offset - item.file_offset : 0;
        const auto nested_size = item.kind == UefiCapsuleItemKind::fmp_payload
            ? std::uint64_t(item.update_image_size) - item.authentication_header_size -
                item.dependency_expression_size - item.fmp_payload_header_size
            : item.size;
        const auto nested = inspect_nested_capsules(item, bytes, item.file_offset + nested_offset,
                                                    nested_size, options, stop, nested_depth, nested_budget);
        if (!nested) return nested.error();
        result.items.push_back(std::move(item));
    }
    return result;
}
} // namespace

namespace {
Result<bool> inspect_nested_capsules(UefiCapsuleItem &item, std::span<const std::byte> parent_bytes,
                                     std::uint64_t candidate_offset, std::uint64_t candidate_size,
                                     UefiCapsuleParseOptions options, std::stop_token stop,
                                     std::size_t depth, NestedBudget &budget) {
    if (candidate_size < 16 || candidate_offset > parent_bytes.size() ||
        candidate_size > parent_bytes.size() - candidate_offset)
        return true;
    item.nested_capsule_scan_attempted = true;
    const auto candidate = parent_bytes.subspan(static_cast<std::size_t>(candidate_offset),
                                                static_cast<std::size_t>(candidate_size));
    const auto guid_matches = [&](const auto &guid) {
        return std::equal(guid.begin(), guid.end(), reinterpret_cast<const std::uint8_t *>(candidate.data()));
    };
    const bool is_fmp = guid_matches(fmp_guid);
    const bool is_json = guid_matches(json_guid);
    if (!is_fmp && !is_json) return true;
    const auto incomplete = [&](std::string reason) -> Result<bool> {
        item.nested_capsule_scan_complete = false;
        item.nested_capsule_diagnostic = std::move(reason);
        return true;
    };
    if (depth >= options.max_nested_depth)
        return incomplete("nested EFI capsule depth limit reached");
    if (budget.capsules >= options.max_nested_capsules)
        return incomplete("nested EFI capsule count limit reached");
    if (candidate_size > options.max_nested_bytes - budget.bytes)
        return incomplete("nested EFI capsule byte limit reached");
    if (candidate_size > options.max_input_bytes)
        return incomplete("nested EFI capsule exceeds the input-size limit");
    ++budget.capsules;
    budget.bytes += candidate_size;

    UefiNestedCapsule nested;
    nested.kind = is_fmp ? UefiNestedCapsuleKind::fmp : UefiNestedCapsuleKind::json;
    nested.item_relative_offset = candidate_offset - item.file_offset;
    nested.candidate_size = candidate_size;
    if (is_fmp) {
        auto parsed = parse_fmp_impl(candidate, options, stop, false, depth + 1, budget);
        if (!parsed) {
            if (parsed.error().code == ErrorCode::canceled) return parsed.error();
            return incomplete("nested FMP capsule is malformed or unsupported: " + parsed.error().message);
        }
        nested.capsule_guid = parsed.value().capsule_guid;
        nested.header_size = parsed.value().header_size;
        nested.image_size = parsed.value().image_size;
        nested.size = parsed.value().image_size;
        nested.trailing_size = parsed.value().trailing_size;
        nested.flags = parsed.value().flags;
        nested.fmp_version = parsed.value().fmp_version;
        nested.items = std::move(parsed.value().items);
    } else {
        auto parsed = parse_uefi_json_capsule(candidate, options, stop);
        if (!parsed) {
            if (parsed.error().code == ErrorCode::canceled) return parsed.error();
            return incomplete("nested JSON capsule is malformed or unsupported: " + parsed.error().message);
        }
        nested.capsule_guid = parsed.value().capsule_guid;
        nested.header_size = parsed.value().header_size;
        nested.image_size = parsed.value().image_size;
        nested.size = parsed.value().image_size;
        nested.trailing_size = parsed.value().trailing_size;
        nested.flags = parsed.value().flags;
        nested.json_header_version = parsed.value().json_header_version;
        nested.json_capsule_id = parsed.value().capsule_id;
    }
    item.nested_capsules.push_back(std::move(nested));
    return true;
}
} // namespace

Result<UefiFmpDependencyResult> evaluate_uefi_fmp_dependency_expression(
    std::span<const std::byte> expression, std::span<const UefiFmpImageVersion> versions,
    bool version_inventory_complete, std::stop_token stop) {
    if (versions.size() > 65536)
        return Error{ErrorCode::resource_limit, "FMP dependency version inventory exceeds 65,536 records"};
    auto parsed = parse_dependency_expression(expression, false, stop);
    if (!parsed) return parsed.error();
    std::map<std::array<std::uint8_t, 16>, std::pair<std::uint32_t, bool>> version_index;
    std::size_t version_indexed = 0;
    for (const auto &entry : versions) {
        if ((version_indexed++ & 4095u) == 0 && stop.stop_requested())
            return Error{ErrorCode::canceled, "FMP dependency evaluation canceled"};
        const auto [it, inserted] = version_index.emplace(entry.image_type_guid, std::pair{entry.version, false});
        if (!inserted && it->second.first != entry.version) it->second.second = true;
    }
    std::vector<DependencyStackValue> stack;
    stack.reserve(std::min<std::size_t>(parsed.value().instructions.size(), 65536));
    for (const auto &instruction : parsed.value().instructions) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "FMP dependency evaluation canceled"};
        switch (instruction.opcode) {
        case 0x00: {
            DependencyStackValue value;
            const auto match = version_index.find(instruction.guid);
            if (match != version_index.end() && !match->second.second) value.version = match->second.first;
            else if (match == version_index.end() && version_inventory_complete) value.missing_guid = true;
            else value.known = false;
            stack.push_back(value);
            break;
        }
        case 0x01:
            stack.push_back(DependencyStackValue{false, true, false, false, instruction.version});
            break;
        case 0x02:
            // Optional display string; UEFI does not compare its contents.
            break;
        case 0x06: case 0x07:
            stack.push_back(DependencyStackValue{true, true, false, instruction.opcode == 0x06, 0});
            break;
        case 0x05: {
            auto value = stack.back(); stack.pop_back();
            value.boolean = !value.boolean;
            stack.push_back(value);
            break;
        }
        case 0x03: case 0x04: {
            const auto first = stack.back(); stack.pop_back();
            const auto second = stack.back(); stack.pop_back();
            DependencyStackValue value;
            value.is_boolean = true;
            if (instruction.opcode == 0x03) {
                value.known = (first.known && !first.boolean) || (second.known && !second.boolean) ||
                              (first.known && second.known);
                value.boolean = first.boolean && second.boolean;
            } else {
                value.known = (first.known && first.boolean) || (second.known && second.boolean) ||
                              (first.known && second.known);
                value.boolean = first.boolean || second.boolean;
            }
            stack.push_back(value);
            break;
        }
        case 0x08: case 0x09: case 0x0a: case 0x0b: case 0x0c: {
            const auto first = stack.back(); stack.pop_back();
            const auto second = stack.back(); stack.pop_back();
            DependencyStackValue value;
            value.is_boolean = true;
            if (first.missing_guid || second.missing_guid) {
                value.boolean = false;
            } else if (!first.known || !second.known) {
                value.known = false;
            } else {
                switch (instruction.opcode) {
                case 0x08: value.boolean = first.version == second.version; break;
                case 0x09: value.boolean = first.version > second.version; break;
                case 0x0a: value.boolean = first.version >= second.version; break;
                case 0x0b: value.boolean = first.version < second.version; break;
                default: value.boolean = first.version <= second.version; break;
                }
            }
            stack.push_back(value);
            break;
        }
        case 0x0d:
            if (stack.back().known)
                return stack.back().boolean ? UefiFmpDependencyResult::satisfied
                                            : UefiFmpDependencyResult::unsatisfied;
            return UefiFmpDependencyResult::indeterminate;
        default:
            return malformed("FMP dependency expression contains an unsupported opcode");
        }
    }
    return malformed("FMP dependency expression has no END result");
}

Result<UefiFmpAntiRollbackResult> evaluate_uefi_fmp_anti_rollback(
    const UefiCapsuleItem &update, std::span<const UefiFmpInstalledImage> installed_images,
    bool inventory_complete, std::stop_token stop) {
    if (update.kind != UefiCapsuleItemKind::fmp_payload)
        return Error{ErrorCode::invalid_argument, "Anti-rollback evaluation requires an FMP payload item"};
    if (!update.fmp_payload_header_present)
        return UefiFmpAntiRollbackResult::indeterminate;
    if (update.lowest_supported_firmware_version > update.firmware_version)
        return Error{ErrorCode::malformed, "FMP update lowest-supported version exceeds its firmware version"};
    if (installed_images.size() > 65536)
        return Error{ErrorCode::resource_limit, "FMP installed-image inventory exceeds 65,536 records"};
    const UefiFmpInstalledImage *match = nullptr;
    for (std::size_t index = 0; index < installed_images.size(); ++index) {
        if ((index & 4095u) == 0 && stop.stop_requested())
            return Error{ErrorCode::canceled, "FMP anti-rollback evaluation canceled"};
        const auto &candidate = installed_images[index];
        if (candidate.image_type_guid != update.image_type_guid) continue;
        if (match && (match->version != candidate.version ||
                      match->lowest_supported_version != candidate.lowest_supported_version))
            return UefiFmpAntiRollbackResult::indeterminate;
        match = &candidate;
    }
    if (!match)
        return inventory_complete ? UefiFmpAntiRollbackResult::not_installed
                                  : UefiFmpAntiRollbackResult::indeterminate;
    if (!match->lowest_supported_version)
        return UefiFmpAntiRollbackResult::indeterminate;
    return update.firmware_version < *match->lowest_supported_version
        ? UefiFmpAntiRollbackResult::prevented
        : UefiFmpAntiRollbackResult::permitted;
}

Result<UefiCapsule> parse_uefi_fmp_capsule(std::span<const std::byte> bytes,
                                           UefiCapsuleParseOptions options, std::stop_token stop) {
    NestedBudget budget;
    return parse_fmp_impl(bytes, options, stop, true, 0, budget);
}

namespace {
struct GatheredCapsuleStream {
    std::uint64_t capture_physical_base = 0, descriptor_head = 0, payload_bytes = 0;
    std::vector<std::uint64_t> capture_region_bases;
    std::vector<UefiCapsuleBlock> blocks;
    std::vector<std::byte> bytes;
};
Result<GatheredCapsuleStream> gather_capsule_stream(std::span<const UefiCapsuleCaptureRegion> regions,
    std::uint64_t descriptor_head,
    UefiCapsuleScatterGatherOptions options, std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI scatter/gather parsing canceled"};
    if (!options.max_descriptors || options.max_descriptors > 4096 || !options.max_payload_bytes ||
        options.max_payload_bytes > 128ull * 1024 * 1024 || regions.empty() || regions.size() > 256)
        return Error{ErrorCode::resource_limit, "UEFI scatter/gather limits exceed 256 regions, 4096 descriptors, 128 MiB payload, or 512 MiB capture"};
    struct RegionRange { std::uint64_t begin, end; std::size_t index; };
    std::vector<RegionRange> ranges;
    try { ranges.reserve(regions.size()); }
    catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded UEFI capture-region map"};
    }
    std::uint64_t capture_bytes = 0;
    for (std::size_t index = 0; index < regions.size(); ++index) {
        const auto &region = regions[index];
        if (region.bytes.empty() || region.bytes.size() > UINT64_MAX - region.physical_base)
            return malformed("UEFI physical capture region is empty or its address range overflows");
        const auto region_size = static_cast<std::uint64_t>(region.bytes.size());
        if (region_size > 512ull * 1024 * 1024 ||
            capture_bytes > 512ull * 1024 * 1024 - region_size ||
            region_size > options.capsule.max_input_bytes ||
            capture_bytes > options.capsule.max_input_bytes - region_size)
            return Error{ErrorCode::resource_limit, "UEFI physical captures exceed cumulative 512 MiB or capsule-input limit"};
        capture_bytes += region.bytes.size();
        ranges.push_back({region.physical_base, region.physical_base + region.bytes.size(), index});
    }
    std::sort(ranges.begin(), ranges.end(), [](const auto &a, const auto &b) { return a.begin < b.begin; });
    for (std::size_t i = 1; i < ranges.size(); ++i)
        if (ranges[i].begin < ranges[i - 1].end)
            return malformed("UEFI physical capture regions overlap");
    if (!descriptor_head || descriptor_head % 8)
        return malformed("UEFI scatter/gather head must be nonzero and 8-byte aligned");
    struct CaptureAddress { std::size_t region_index; std::size_t offset; };
    const auto offset_for = [&](std::uint64_t address, std::uint64_t length) -> std::optional<CaptureAddress> {
        const auto it = std::upper_bound(ranges.begin(), ranges.end(), address,
            [](std::uint64_t value, const RegionRange &range) { return value < range.begin; });
        if (it == ranges.begin()) return {};
        const auto &range = *std::prev(it);
        if (address < range.begin || address > range.end || length > range.end - address) return {};
        return CaptureAddress{range.index, static_cast<std::size_t>(address - range.begin)};
    };
    try {
        GatheredCapsuleStream result;
        result.capture_physical_base = regions.front().physical_base;
        for (const auto &region : regions) result.capture_region_bases.push_back(region.physical_base);
        result.descriptor_head = descriptor_head;
        std::set<std::uint64_t> visited;
        auto cursor = descriptor_head;
        for (;;) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI scatter/gather parsing canceled"};
            if (result.blocks.size() == options.max_descriptors)
                return Error{ErrorCode::resource_limit, "UEFI scatter/gather descriptor budget exhausted before termination"};
            if (!visited.insert(cursor).second) return malformed("UEFI scatter/gather descriptor cycle");
            const auto offset = offset_for(cursor, 16);
            if (!offset) return malformed("UEFI scatter/gather descriptor is outside the physical capture");
            UefiCapsuleBlock block;
            block.descriptor_physical_address = cursor;
            block.descriptor_region_index = offset->region_index;
            block.data_region_index = offset->region_index;
            block.descriptor_capture_offset = offset->offset;
            const auto descriptor_bytes = regions[offset->region_index].bytes;
            block.length = u64(descriptor_bytes, offset->offset);
            block.target_physical_address = u64(descriptor_bytes, offset->offset + 8);
            block.logical_offset = result.payload_bytes;
            if (block.length) {
                if (block.length > options.max_payload_bytes - result.payload_bytes)
                    return Error{ErrorCode::resource_limit, "UEFI gathered capsule exceeds payload-byte budget"};
                const auto data = offset_for(block.target_physical_address, block.length);
                if (!data) return malformed("UEFI scatter/gather data range is outside the physical capture");
                block.data_region_index = data->region_index;
                block.data_capture_offset = data->offset;
                result.payload_bytes += block.length;
                result.blocks.push_back(block);
                if (cursor > UINT64_MAX - 16) return malformed("UEFI scatter/gather next descriptor address overflows");
                cursor += 16;
            } else if (block.target_physical_address) {
                if (block.target_physical_address % 8)
                    return malformed("UEFI scatter/gather continuation is not 8-byte aligned");
                block.kind = UefiCapsuleBlockKind::continuation;
                result.blocks.push_back(block);
                cursor = block.target_physical_address;
            } else {
                block.kind = UefiCapsuleBlockKind::terminator;
                result.blocks.push_back(block);
                break;
            }
        }
        if (!result.payload_bytes) return malformed("UEFI scatter/gather chain contains no capsule data");
        std::vector<std::byte> gathered(static_cast<std::size_t>(result.payload_bytes));
        for (const auto &block : result.blocks) {
            if (block.kind != UefiCapsuleBlockKind::data) continue;
            for (std::uint64_t copied = 0; copied < block.length;) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule gathering canceled"};
                const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(1024u * 1024u, block.length - copied));
                const auto capture = regions[block.data_region_index].bytes;
                std::copy_n(capture.begin() + static_cast<std::size_t>(block.data_capture_offset + copied), count,
                    gathered.begin() + static_cast<std::size_t>(block.logical_offset + copied));
                copied += count;
            }
        }
        result.bytes = std::move(gathered);
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded UEFI scatter/gather inventory"};
    }
}
Result<GatheredCapsuleStream> gather_capsule_stream(std::span<const std::byte> capture,
    std::uint64_t physical_base, std::uint64_t descriptor_head,
    UefiCapsuleScatterGatherOptions options, std::stop_token stop) {
    const std::array<UefiCapsuleCaptureRegion, 1> region{{{physical_base, capture}}};
    return gather_capsule_stream(region, descriptor_head, options, stop);
}
} // namespace

Result<UefiScatterGatherCapsule> parse_uefi_fmp_scatter_gather(std::span<const std::byte> capture,
    std::uint64_t physical_base, std::uint64_t descriptor_head,
    UefiCapsuleScatterGatherOptions options, std::stop_token stop) {
    try {
        auto gathered = gather_capsule_stream(capture, physical_base, descriptor_head, options, stop);
        if (!gathered) return gathered.error();
        auto parsed = parse_uefi_fmp_capsule(gathered.value().bytes, options.capsule, stop);
        if (!parsed) return parsed.error();
        if (parsed.value().image_size != gathered.value().payload_bytes)
            return malformed("UEFI scatter/gather form requires exactly one FMP capsule with no trailing data");
        if (!(parsed.value().flags & 0x00010000u))
            return malformed("UEFI scatter/gather FMP capsule must persist across reset");
        UefiScatterGatherCapsule result;
        result.capture_physical_base = physical_base; result.descriptor_head = descriptor_head;
        result.capture_region_bases = gathered.value().capture_region_bases;
        result.payload_bytes = gathered.value().payload_bytes;
        result.blocks = std::move(gathered.value().blocks); result.capsule = std::move(parsed.value());
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded UEFI scatter/gather inventory"};
    }
}

Result<UefiScatterGatherCapsuleList> parse_uefi_fmp_scatter_gather_list(std::span<const std::byte> capture,
    std::uint64_t physical_base, std::uint64_t descriptor_head,
    UefiCapsuleScatterGatherOptions options, std::stop_token stop) {
    const std::array<UefiCapsuleCaptureRegion, 1> region{{{physical_base, capture}}};
    return parse_uefi_fmp_scatter_gather_regions(region, descriptor_head, options, stop);
}

Result<UefiScatterGatherCapsuleList> parse_uefi_fmp_scatter_gather_regions(
    std::span<const UefiCapsuleCaptureRegion> regions, std::uint64_t descriptor_head,
    UefiCapsuleScatterGatherOptions options, std::stop_token stop) {
    auto gathered = gather_capsule_stream(regions, descriptor_head, options, stop);
    if (!gathered) return gathered.error();
    try {
        UefiScatterGatherCapsuleList result;
        result.capture_physical_base = gathered.value().capture_physical_base;
        result.capture_region_bases = gathered.value().capture_region_bases;
        result.descriptor_head = descriptor_head;
        result.payload_bytes = gathered.value().payload_bytes;
        const auto bytes = std::span<const std::byte>(gathered.value().bytes);
        std::vector<std::span<const std::byte>> capsules;
        std::set<std::uint64_t> continuation_offsets, data_offsets;
        for (const auto &block : gathered.value().blocks) {
            if (block.kind == UefiCapsuleBlockKind::continuation) continuation_offsets.insert(block.logical_offset);
            if (block.kind == UefiCapsuleBlockKind::data) data_offsets.insert(block.logical_offset);
        }
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI multi-region capsule-list parsing canceled"};
            if (capsules.size() >= std::min<std::size_t>(256, options.capsule.max_capsules))
                return Error{ErrorCode::resource_limit, "UEFI gathered capsule count exceeds limit"};
            if (offset && (!continuation_offsets.contains(offset) || !data_offsets.contains(offset)))
                return malformed("UEFI gathered capsule boundary lacks a continuation to a new data descriptor");
            if (bytes.size() - offset < 28) return malformed("UEFI gathered stream ends with a truncated capsule header");
            const auto header_size = u32(bytes, offset + 16), image_size = u32(bytes, offset + 24);
            if (header_size < 28 || image_size < header_size || image_size > bytes.size() - offset)
                return malformed("UEFI gathered capsule size is invalid or crosses the logical stream extent");
            if (!(u32(bytes, offset + 20) & 0x00010000u))
                return malformed("Every UEFI scatter/gather FMP capsule must persist across reset");
            result.capsule_logical_offsets.push_back(offset);
            capsules.push_back(bytes.subspan(offset, image_size));
            offset += image_size;
        }
        auto parsed = parse_uefi_fmp_capsule_list(capsules, options.capsule, stop);
        if (!parsed) return parsed.error();
        result.inventory = std::move(parsed.value()); result.blocks = std::move(gathered.value().blocks);
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate bounded UEFI multi-region scatter/gather inventory"};
    }
}

Result<UefiCapsuleList> parse_uefi_fmp_capsule_list(
    std::span<const std::span<const std::byte>> capsules,
    UefiCapsuleParseOptions options, std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule-list parsing canceled"};
    if (capsules.empty()) return malformed("FMP capsule list is empty");
    if (capsules.size() > options.max_capsules)
        return Error{ErrorCode::resource_limit, "FMP capsule count exceeds limit"};

    UefiCapsuleList result;
    result.capsules.reserve(capsules.size());
    std::size_t embedded_volumes_used = 0;
    std::size_t embedded_files_used = 0;
    std::size_t embedded_sections_used = 0;
    std::size_t embedded_scans_used = 0;
    std::uint64_t embedded_decompressed_used = 0;
    NestedBudget nested_budget;
    for (const auto capsule_bytes : capsules) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule-list parsing canceled"};
        if (result.total_input_bytes > options.max_input_bytes ||
            capsule_bytes.size() > options.max_input_bytes - result.total_input_bytes)
            return Error{ErrorCode::resource_limit, "FMP capsule list exceeds cumulative input-size limit"};
        if (result.total_item_count > options.max_items)
            return Error{ErrorCode::resource_limit, "FMP capsule list exceeds cumulative item limit"};

        auto capsule_options = options;
        capsule_options.max_input_bytes = options.max_input_bytes - result.total_input_bytes;
        capsule_options.max_items = options.max_items - result.total_item_count;
        capsule_options.max_embedded_volumes = options.max_embedded_volumes - embedded_volumes_used;
        capsule_options.max_embedded_files = options.max_embedded_files - embedded_files_used;
        capsule_options.max_embedded_sections = options.max_embedded_sections - embedded_sections_used;
        capsule_options.max_embedded_payload_scans = options.max_embedded_payload_scans - embedded_scans_used;
        capsule_options.max_embedded_decompressed_bytes = options.max_embedded_decompressed_bytes - embedded_decompressed_used;
        auto parsed = parse_fmp_impl(capsule_bytes, capsule_options, stop, true, 0, nested_budget);
        if (!parsed) return parsed.error();
        if (result.capsules.empty()) {
            result.capsule_guid = parsed.value().capsule_guid;
        } else if (parsed.value().capsule_guid != result.capsule_guid) {
            return malformed("FMP capsule list contains differing capsule GUIDs");
        }
        result.total_input_bytes += capsule_bytes.size();
        result.total_item_count += parsed.value().items.size();
        for (const auto &item : parsed.value().items) {
            embedded_volumes_used += item.embedded_volumes.size();
            if (item.embedded_volume_scan_attempted) ++embedded_scans_used;
            for (const auto &volume : item.embedded_volumes) {
                embedded_files_used += volume.file_count;
                embedded_sections_used += volume.section_count;
                embedded_decompressed_used += volume.decompressed_bytes;
            }
        }
        result.capsules.push_back(std::move(parsed.value()));
    }
    result.total_capsule_count = result.capsules.size();
    return result;
}

Result<UefiCapsuleList> parse_uefi_capsule_list(
    std::span<const std::span<const std::byte>> capsules,
    UefiCapsuleParseOptions options, std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule-list parsing canceled"};
    if (capsules.empty()) return malformed("capsule list is empty");
    if (capsules.size() > options.max_capsules)
        return Error{ErrorCode::resource_limit, "capsule count exceeds limit"};
    if (capsules.front().size() < 16) return malformed("capsule-list entry GUID is truncated");

    const bool is_fmp = std::equal(fmp_guid.begin(), fmp_guid.end(), capsules.front().begin(),
        [](std::uint8_t expected, std::byte actual) { return expected == std::to_integer<std::uint8_t>(actual); });
    const bool is_json = std::equal(json_guid.begin(), json_guid.end(), capsules.front().begin(),
        [](std::uint8_t expected, std::byte actual) { return expected == std::to_integer<std::uint8_t>(actual); });
    if (is_fmp) return parse_uefi_fmp_capsule_list(capsules, options, stop);
    if (!is_json) return Error{ErrorCode::unsupported, "capsule-list GUID is not a supported FMP or JSON capsule"};

    UefiCapsuleList result;
    result.kind = UefiCapsuleListKind::json;
    result.capsule_guid = json_guid;
    result.total_capsule_count = capsules.size();
    result.json_capsules.reserve(capsules.size());
    std::uint64_t total_json_payload_bytes = 0;
    for (const auto capsule_bytes : capsules) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule-list parsing canceled"};
        if (result.total_input_bytes > options.max_input_bytes ||
            capsule_bytes.size() > options.max_input_bytes - result.total_input_bytes)
            return Error{ErrorCode::resource_limit, "JSON capsule list exceeds cumulative input-size limit"};
        if (capsule_bytes.size() < json_guid.size() ||
            !std::equal(json_guid.begin(), json_guid.end(), capsule_bytes.begin(),
                [](std::uint8_t expected, std::byte actual) {
                    return expected == std::to_integer<std::uint8_t>(actual);
                }))
            return malformed("capsule list contains differing capsule GUIDs");
        if (total_json_payload_bytes > options.max_json_payload_bytes)
            return Error{ErrorCode::resource_limit, "JSON capsule list exceeds cumulative JSON payload limit"};
        auto capsule_options = options;
        capsule_options.max_input_bytes = options.max_input_bytes - result.total_input_bytes;
        capsule_options.max_json_payload_bytes = options.max_json_payload_bytes - total_json_payload_bytes;
        auto parsed = parse_uefi_json_capsule(capsule_bytes, capsule_options, stop);
        if (!parsed) return parsed.error();
        total_json_payload_bytes += parsed.value().payload_size;
        result.total_input_bytes += capsule_bytes.size();
        result.json_capsules.push_back(std::move(parsed.value()));
    }
    return result;
}

Result<UefiJsonCapsule> parse_uefi_json_capsule(std::span<const std::byte> bytes,
                                               UefiCapsuleParseOptions options, std::stop_token stop) {
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "UEFI capsule parsing canceled"};
    if (bytes.size() > options.max_input_bytes) return Error{ErrorCode::resource_limit, "UEFI capsule exceeds input-size limit"};
    if (bytes.size() < 40) return malformed("EFI JSON capsule header is truncated");
    UefiJsonCapsule result;
    for (std::size_t i = 0; i < 16; ++i) result.capsule_guid[i] = u8(bytes, i);
    if (result.capsule_guid != json_guid) return Error{ErrorCode::unsupported, "capsule GUID is not EFI JSON"};
    result.header_size = u32(bytes, 16);
    result.flags = u32(bytes, 20);
    result.image_size = u32(bytes, 24);
    if (result.header_size < 28 || result.header_size > result.image_size || result.image_size > bytes.size())
        return malformed("EFI JSON capsule header or declared image size is inconsistent with the input");
    if (result.flags & capsule_reserved_spec_flags)
        return malformed("EFI JSON capsule sets reserved specification flag bits");
    result.header_extension_size = result.header_size - 28;
    result.trailing_size = bytes.size() - result.image_size;
    if (result.flags & 0x00020000u)
        return malformed("JSON capsule sets CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE");
    if (std::uint64_t(result.header_size) + 12 > result.image_size)
        return malformed("EFI JSON capsule body header is truncated");
    const auto body = static_cast<std::size_t>(result.header_size);
    result.json_header_version = u32(bytes, body);
    result.capsule_id = u32(bytes, body + 4);
    result.payload_size = u32(bytes, body + 8);
    if (result.json_header_version != 1)
        return Error{ErrorCode::unsupported, "unsupported EFI JSON capsule header version"};
    if (result.payload_size == 0 || std::uint64_t(body) + 12 + result.payload_size != result.image_size)
        return malformed("EFI JSON capsule payload length does not match the declared capsule extent");
    result.payload_offset = body + 12;
    if (result.payload_size > options.max_json_payload_bytes)
        return Error{ErrorCode::resource_limit, "EFI JSON capsule payload exceeds the JSON validation limit"};
    const auto payload = bytes.subspan(static_cast<std::size_t>(result.payload_offset), result.payload_size);
    auto json = JsonSyntaxParser(payload, options.max_json_depth, stop).parse();
    if (!json) return json.error();
    return result;
}
} // namespace hexlab::firmware
