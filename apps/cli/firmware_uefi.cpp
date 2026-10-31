#include "commands.hpp"
#include "argument_text.hpp"
#include "project_arguments.hpp"
#include "hexlab/firmware/uefi_volume.hpp"
#include "hexlab/firmware/uefi_capsule.hpp"
#include "hexlab/image/image.hpp"
#include "hexlab/image/file_publication.hpp"
#include "hexlab/workspace/navigation.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <ostream>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace hexlab::cli {
namespace {
std::string hex_value(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << value;
    return out.str();
}
std::string json_string(std::string_view value) {
    std::string result = "\"";
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 0x20) {
                constexpr char digits[] = "0123456789abcdef";
                result += "\\u00";
                result += digits[ch >> 4];
                result += digits[ch & 0x0f];
            } else result += static_cast<char>(ch);
        }
    }
    result += '"';
    return result;
}
std::string capsule_flag_names(std::uint32_t flags) {
    std::string names;
    const auto add = [&](std::string_view name) {
        if (!names.empty()) names += ',';
        names += name;
    };
    if (flags & 0x00010000u) add("persist-across-reset");
    if (flags & 0x00020000u) add("populate-system-table");
    if (flags & 0x00040000u) add("initiate-reset");
    return names.empty() ? "none" : names;
}
std::optional<firmware::UefiFmpInstalledImage> parse_installed_image(std::wstring_view argument) {
    const auto text = wide_to_utf8(argument);
    const auto equal = text.find('=');
    const auto comma = text.find(',', equal == std::string::npos ? 0 : equal + 1);
    if (equal == std::string::npos || comma == std::string::npos) return {};
    std::string guid;
    for (const char ch : text.substr(0, equal)) if (ch != '-') guid.push_back(ch);
    if (guid.size() != 32) return {};
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::array<std::uint8_t, 16> canonical{};
    for (std::size_t i = 0; i < canonical.size(); ++i) {
        const auto high = nibble(guid[i * 2]), low = nibble(guid[i * 2 + 1]);
        if (high < 0 || low < 0) return {};
        canonical[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    firmware::UefiFmpInstalledImage result;
    result.image_type_guid = {canonical[3], canonical[2], canonical[1], canonical[0],
        canonical[5], canonical[4], canonical[7], canonical[6], canonical[8], canonical[9],
        canonical[10], canonical[11], canonical[12], canonical[13], canonical[14], canonical[15]};
    const auto parse_version = [](std::string_view value) -> std::optional<std::uint32_t> {
        if (value.empty()) return {};
        std::uint32_t parsed = 0;
        const int base = value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') ? 16 : 10;
        if (base == 16) value.remove_prefix(2);
        const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed, base);
        if (error != std::errc{} || end != value.data() + value.size()) return {};
        return parsed;
    };
    const auto version = parse_version(std::string_view(text).substr(equal + 1, comma - equal - 1));
    if (!version) return {};
    result.version = *version;
    const auto lowest = std::string_view(text).substr(comma + 1);
    if (lowest != "-") {
        const auto parsed_lowest = parse_version(lowest);
        if (!parsed_lowest) return {};
        result.lowest_supported_version = *parsed_lowest;
    }
    return result;
}
std::optional<firmware::UefiFmpImageVersion> parse_image_version(std::wstring_view argument) {
    if (argument.size() > 256) return {};
    std::wstring with_empty_floor(argument);
    with_empty_floor += L",-";
    const auto parsed = parse_installed_image(with_empty_floor);
    if (!parsed) return {};
    return firmware::UefiFmpImageVersion{parsed->image_type_guid, parsed->version};
}
void write_embedded_volumes(std::ostream &out, const firmware::UefiCapsuleItem &item, std::string_view indent,
                            bool logical = false) {
    for (std::size_t i = 0; i < item.embedded_volumes.size(); ++i) {
        const auto &volume = item.embedded_volumes[i];
        out << indent << "EmbeddedFV[" << i << (logical ? "] logical-capsule-offset=" : "] file-offset=") << hex_value(volume.file_offset)
            << " size=" << hex_value(volume.size)
            << " fs-guid=" << firmware::uefi_guid_string(volume.file_system_guid)
            << " revision=" << static_cast<unsigned>(volume.revision)
            << " header-checksum=" << (volume.header_checksum_valid ? "valid" : "not-valid")
            << " files=" << volume.file_count << " sections=" << volume.section_count << '\n';
    }
    if (!item.embedded_volume_scan_complete)
        out << indent << "Embedded firmware-volume scan incomplete: " << item.embedded_volume_diagnostic << '\n';
}
constexpr std::size_t capsule_output_limit = 320;
constexpr std::size_t capsule_item_output_limit = 4096;
struct CapsuleOutputBudget {
    std::size_t capsules = 0, items = 0, omitted_capsules = 0, omitted_items = 0;
};
std::size_t bounded_count_add(std::size_t a, std::size_t b) {
    return b > (std::numeric_limits<std::size_t>::max)() - a
        ? (std::numeric_limits<std::size_t>::max)() : a + b;
}
std::size_t nested_capsule_count(const firmware::UefiNestedCapsule &capsule);
std::size_t nested_item_count(const firmware::UefiNestedCapsule &capsule);
std::size_t nested_capsule_count(const firmware::UefiCapsuleItem &item) {
    std::size_t total = 0;
    for (const auto &nested : item.nested_capsules)
        total = bounded_count_add(total, nested_capsule_count(nested));
    return total;
}
std::size_t nested_item_count(const firmware::UefiCapsuleItem &item) {
    std::size_t total = 1;
    for (const auto &nested : item.nested_capsules)
        total = bounded_count_add(total, nested_item_count(nested));
    return total;
}
std::size_t nested_capsule_count(const firmware::UefiNestedCapsule &capsule) {
    std::size_t total = 1;
    for (const auto &item : capsule.items)
        total = bounded_count_add(total, nested_capsule_count(item));
    return total;
}
std::size_t nested_item_count(const firmware::UefiNestedCapsule &capsule) {
    std::size_t total = 0;
    for (const auto &item : capsule.items)
        total = bounded_count_add(total, nested_item_count(item));
    return total;
}
void write_capsule_item(std::ostream &, const firmware::UefiCapsuleItem &, std::string_view,
                        std::string_view, bool, CapsuleOutputBudget &, bool logical = false);
void write_nested_capsule(std::ostream &out, const firmware::UefiNestedCapsule &capsule,
                          std::string_view indent, std::string_view label,
                          CapsuleOutputBudget &budget) {
    if (budget.capsules >= capsule_output_limit) {
        budget.omitted_capsules = bounded_count_add(budget.omitted_capsules, nested_capsule_count(capsule));
        budget.omitted_items = bounded_count_add(budget.omitted_items, nested_item_count(capsule));
        return;
    }
    ++budget.capsules;
    out << indent << label << " kind="
        << (capsule.kind == firmware::UefiNestedCapsuleKind::fmp ? "FMP" : "JSON")
        << " guid=" << firmware::uefi_guid_string(capsule.capsule_guid)
        << " item-relative-offset=" << hex_value(capsule.item_relative_offset)
        << " image-size=" << hex_value(capsule.size)
        << " candidate-span=" << hex_value(capsule.candidate_size)
        << " header-size=" << hex_value(capsule.header_size)
        << " flags=" << hex_value(capsule.flags)
        << " flag-names=" << capsule_flag_names(capsule.flags);
    if (capsule.trailing_size) out << " trailing-size=" << hex_value(capsule.trailing_size);
    if (capsule.kind == firmware::UefiNestedCapsuleKind::fmp)
        out << " fmp-version=" << capsule.fmp_version << " items=" << capsule.items.size();
    else
        out << " json-version=" << capsule.json_header_version << " capsule-id=" << capsule.json_capsule_id;
    out << '\n';
    for (std::size_t i = 0; i < capsule.items.size(); ++i)
        write_capsule_item(out, capsule.items[i], std::string(indent) + "  ",
                           std::string(label) + " Item[" + std::to_string(i) + "]", true, budget);
}
void write_capsule_item(std::ostream &out, const firmware::UefiCapsuleItem &item,
                        std::string_view indent, std::string_view label, bool nested,
                        CapsuleOutputBudget &budget, bool logical) {
    if (budget.items >= capsule_item_output_limit) {
        budget.omitted_items = bounded_count_add(budget.omitted_items, nested_item_count(item));
        budget.omitted_capsules = bounded_count_add(budget.omitted_capsules, nested_capsule_count(item));
        return;
    }
    ++budget.items;
    out << indent << label << " kind="
        << (item.kind == firmware::UefiCapsuleItemKind::embedded_driver ? "embedded-driver" : "fmp-payload")
        << (logical ? " logical-capsule-offset=" : nested ? " capsule-relative-file-offset=" : " file-offset=")
        << hex_value(item.file_offset) << " size=" << hex_value(item.size);
    if (item.kind == firmware::UefiCapsuleItemKind::fmp_payload) {
        out << " image-header-version=" << item.image_header_version
            << " image-type-guid=" << firmware::uefi_guid_string(item.image_type_guid)
            << " image-index=" << static_cast<unsigned>(item.image_index)
            << " image-size=" << hex_value(item.update_image_size)
            << " payload-offset=" << hex_value(item.payload_offset)
            << " firmware-image-offset=" << hex_value(item.firmware_image_offset)
            << " vendor-code-size=" << hex_value(item.vendor_code_size)
            << " vendor-code-offset=" << hex_value(item.vendor_code_offset);
        if (item.image_header_version >= 2) out << " hardware-instance=" << hex_value(item.hardware_instance);
        if (item.image_header_version >= 3) {
            out << " image-capsule-support=" << hex_value(item.image_capsule_support)
                << " image-capsule-support-offset=" << hex_value(item.image_capsule_support_offset)
                << " support-authentication=" << (item.capsule_support_authentication_advertised ? "yes" : "no")
                << " support-dependency=" << (item.capsule_support_dependency_advertised ? "yes" : "no");
            if (item.capsule_support_unrecognized_bits)
                out << " support-unrecognized-bits=" << hex_value(item.capsule_support_unrecognized_bits);
        }
        if (item.authentication_present)
            out << " authentication=pkcs7 monotonic-count=" << hex_value(item.authentication_monotonic_count)
                << " certificate-offset=" << hex_value(item.authentication_certificate_offset)
                << " certificate-size=" << hex_value(item.authentication_certificate_size)
                << " certificate-data-offset=" << hex_value(item.authentication_certificate_data_offset)
                << " certificate-data-size=" << hex_value(item.authentication_certificate_data_size)
                << " signed-image-offset=" << hex_value(item.authentication_signed_image_offset)
                << " signed-image-size=" << hex_value(item.authentication_signed_image_size);
        if (item.dependency_expression_present)
            out << " dependency-expression-offset=" << hex_value(item.dependency_expression_offset)
                << " dependency-expression-size=" << hex_value(item.dependency_expression_size);
        if (item.fmp_payload_header_present)
            out << " fmp-payload-header=mss1"
                << " fmp-payload-header-offset=" << hex_value(item.fmp_payload_header_offset)
                << " fmp-payload-header-size=" << hex_value(item.fmp_payload_header_size)
                << " firmware-version=" << hex_value(item.firmware_version)
                << " lowest-supported-firmware-version=" << hex_value(item.lowest_supported_firmware_version);
    }
    out << '\n';
    if (item.capsule_support_authentication_mismatch)
        out << indent << "  Image capsule support warning at "
            << hex_value(item.image_capsule_support_offset) << ": "
            << item.capsule_support_authentication_diagnostic << '\n';
    write_embedded_volumes(out, item, std::string(indent) + "  ", logical);
    if (!item.nested_capsule_scan_complete)
        out << indent << "  Nested capsule scan incomplete: " << item.nested_capsule_diagnostic << '\n';
    for (std::size_t i = 0; i < item.nested_capsules.size(); ++i)
        write_nested_capsule(out, item.nested_capsules[i], std::string(indent) + "  ",
                             std::string(label) + " Nested[" + std::to_string(i) + "]", budget);
}
void write_capsule_output_limits(std::ostream &out, const CapsuleOutputBudget &budget) {
    if (budget.omitted_capsules)
        out << "Nested capsules omitted from output: " << budget.omitted_capsules
            << " (capsule output limit " << capsule_output_limit << ")\n";
    if (budget.omitted_items)
        out << "Capsule items omitted from output: " << budget.omitted_items
            << " (item output limit " << capsule_item_output_limit << ")\n";
}
void write_anti_rollback(std::ostream &out, const firmware::UefiCapsuleItem &item,
                         std::span<const firmware::UefiFmpInstalledImage> inventory,
                         bool inventory_complete, std::string_view label) {
    if (item.kind != firmware::UefiCapsuleItemKind::fmp_payload || !item.fmp_payload_header_present) return;
    auto result = firmware::evaluate_uefi_fmp_anti_rollback(item, inventory, inventory_complete);
    out << "Anti-rollback " << label << ": ";
    if (!result) { out << "indeterminate (" << result.error().message << ")\n"; return; }
    switch (result.value()) {
    case firmware::UefiFmpAntiRollbackResult::permitted: out << "permitted by supplied inventory\n"; break;
    case firmware::UefiFmpAntiRollbackResult::prevented: out << "prevented by installed rollback floor\n"; break;
    case firmware::UefiFmpAntiRollbackResult::not_installed: out << "matching image not installed\n"; break;
    case firmware::UefiFmpAntiRollbackResult::indeterminate: out << "indeterminate\n"; break;
    }
}
void write_dependency_status(std::ostream &out, const firmware::UefiCapsuleItem &item,
        std::span<const std::byte> capsule_bytes,
        std::span<const firmware::UefiFmpImageVersion> versions, bool inventory_complete,
        std::string_view label, std::size_t &shown, std::size_t &omitted) {
    if (item.kind != firmware::UefiCapsuleItemKind::fmp_payload || !item.dependency_expression_present) return;
    constexpr std::size_t evaluation_limit = 4096;
    if (shown >= evaluation_limit) { ++omitted; return; }
    ++shown;
    out << "FMP dependency " << label << ": ";
    if (item.dependency_expression_offset > capsule_bytes.size() ||
        item.dependency_expression_size > capsule_bytes.size() - item.dependency_expression_offset) {
        out << "indeterminate (expression range is outside the capsule bytes)\n";
        return;
    }
    const auto expression = capsule_bytes.subspan(
        static_cast<std::size_t>(item.dependency_expression_offset),
        static_cast<std::size_t>(item.dependency_expression_size));
    const auto result = firmware::evaluate_uefi_fmp_dependency_expression(expression, versions, inventory_complete);
    if (!result) { out << "unavailable (" << result.error().message << ")\n"; return; }
    switch (result.value()) {
    case firmware::UefiFmpDependencyResult::satisfied: out << "satisfied by supplied image versions\n"; break;
    case firmware::UefiFmpDependencyResult::unsatisfied: out << "unsatisfied by supplied image versions\n"; break;
    case firmware::UefiFmpDependencyResult::indeterminate: out << "indeterminate (version facts incomplete or conflicting)\n"; break;
    }
}
void write_authentication_status(std::ostream &out, const firmware::UefiCapsuleItem &item,
                                std::span<const std::byte> source, std::string_view label,
                                std::size_t &verification_count) {
    if (!item.authentication_present) return;
    constexpr std::size_t verification_limit = 64;
    if (verification_count >= verification_limit) {
        out << "FMP authentication " << label << ": verification skipped (CLI limit "
            << verification_limit << " authenticated items)\n";
        return;
    }
    ++verification_count;
    const auto verification = firmware::verify_uefi_fmp_authentication(source, item);
    out << "FMP authentication " << label << ": ";
    if (!verification) {
        out << "unavailable (" << verification.error().message << ")\n";
        return;
    }
    out << "Crypt32 detached CMS signers=" << verification.value().signers.size()
        << " (certificate trust and freshness not checked)\n";
    constexpr std::size_t signer_limit = 32;
    const auto shown = std::min(signer_limit, verification.value().signers.size());
    for (std::size_t i = 0; i < shown; ++i) {
        const auto &signer = verification.value().signers[i];
        out << "  signer=" << i << " signature=" << (signer.signature_valid ? "verified" : "failed");
        if (!signer.signature_valid) out << " provider-error=" << signer.provider_error;
        out << '\n';
    }
    if (shown < verification.value().signers.size())
        out << "  signer rows omitted=" << verification.value().signers.size() - shown
            << " (limit " << signer_limit << ")\n";
}
const char *section_type_name(std::uint8_t value) {
    switch (value) {
    case 0x01: return "compression";
    case 0x02: return "guid-defined";
    case 0x03: return "disposable";
    case 0x10: return "pe32";
    case 0x11: return "pic";
    case 0x12: return "te";
    case 0x13: return "dxe-depex";
    case 0x14: return "version";
    case 0x15: return "user-interface";
    case 0x16: return "compatibility16";
    case 0x17: return "firmware-volume-image";
    case 0x18: return "freeform-subtype-guid";
    case 0x19: return "raw";
    case 0x1b: return "pei-depex";
    case 0x1c: return "mm-depex";
    default: return "unknown";
    }
}
const char *ffs_disposition_name(firmware::UefiFfsFileDisposition value) {
    switch (value) {
    case firmware::UefiFfsFileDisposition::construction: return "construction";
    case firmware::UefiFfsFileDisposition::header_valid: return "header-valid";
    case firmware::UefiFfsFileDisposition::data_valid: return "data-valid";
    case firmware::UefiFfsFileDisposition::marked_for_update: return "marked-for-update";
    case firmware::UefiFfsFileDisposition::deleted: return "deleted";
    case firmware::UefiFfsFileDisposition::header_invalid: return "header-invalid";
    case firmware::UefiFfsFileDisposition::unrecognized_state: return "unrecognized";
    }
    return "unrecognized";
}
void append_utf8(std::string &out, std::uint32_t codepoint) {
    if (codepoint <= 0x7f) {
        out.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
        out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else if (codepoint <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
        out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
        out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    }
}
void append_escaped_unit(std::string &out, std::uint16_t value) {
    constexpr char digits[] = "0123456789ABCDEF";
    out += "\\u";
    for (int shift = 12; shift >= 0; shift -= 4)
        out.push_back(digits[(value >> shift) & 0xf]);
}
std::string quoted_utf16(std::u16string_view text) {
    std::string out = "\"";
    for (std::size_t i = 0; i < text.size(); ++i) {
        std::uint32_t codepoint = static_cast<std::uint16_t>(text[i]);
        if (codepoint >= 0xd800 && codepoint <= 0xdbff && i + 1 < text.size()) {
            const auto low = static_cast<std::uint16_t>(text[i + 1]);
            if (low >= 0xdc00 && low <= 0xdfff) {
                codepoint = 0x10000u + ((codepoint - 0xd800u) << 10) + (low - 0xdc00u);
                ++i;
            } else {
                append_escaped_unit(out, codepoint);
                continue;
            }
        } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
            append_escaped_unit(out, codepoint);
            continue;
        }
        if (codepoint == '\\' || codepoint == '"') {
            out.push_back('\\');
            out.push_back(static_cast<char>(codepoint));
        } else if (codepoint < 0x20 || codepoint == 0x7f || codepoint == 0x2028 || codepoint == 0x2029 ||
                   (codepoint >= 0x202a && codepoint <= 0x202e) || (codepoint >= 0x2066 && codepoint <= 0x2069)) {
            append_escaped_unit(out, static_cast<std::uint16_t>(codepoint));
        } else {
            append_utf8(out, codepoint);
        }
    }
    out.push_back('"');
    return out;
}
const char *section_disposition(firmware::UefiSectionDisposition value) {
    switch (value) {
    case firmware::UefiSectionDisposition::leaf: return "leaf";
    case firmware::UefiSectionDisposition::nested_sections: return "nested-sections";
    case firmware::UefiSectionDisposition::decompressed_sections: return "decompressed-sections";
    case firmware::UefiSectionDisposition::opaque_compressed: return "opaque-compressed";
    case firmware::UefiSectionDisposition::opaque_guid_defined: return "opaque-guid-defined";
    case firmware::UefiSectionDisposition::processing_required: return "processing-required";
    case firmware::UefiSectionDisposition::malformed_nested_payload: return "opaque-nested-payload";
    }
    return "unknown";
}
}

int run_uefi_firmware_cli(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.size() != 4 || args[0] != L"inspect" || args[2] != L"--format" || args[3] != L"uefi")
        return -1;
    try {
        auto opened = FileStorage::open(path_from_wide(args[1]));
        if (!opened) {
            err << "UEFI firmware: " << opened.error().message << '\n';
            return 1;
        }
        const auto &file = opened.value();
        if (file->size() > 512ull * 1024 * 1024 || file->size() > (std::numeric_limits<std::size_t>::max)()) {
            err << "UEFI firmware: input exceeds 512 MiB inspection limit\n";
            return 1;
        }
        auto read = file->read_at({0}, static_cast<std::size_t>(file->size()));
        if (!read) {
            err << "UEFI firmware: " << read.error().message << '\n';
            return 1;
        }
        const auto view = std::move(read.value());
        auto volumes = firmware::parse_uefi_firmware_volumes(view.bytes);
        if (!volumes) {
            err << "UEFI firmware: " << volumes.error().message << '\n';
            return 1;
        }
        std::size_t total_files = 0, total_sections = 0, total_extensions = 0, total_apriori_guids = 0;
        for (const auto &volume : volumes.value()) {
            total_files += volume.files.size();
            total_extensions += volume.extension_entries.size();
            total_apriori_guids += volume.dxe_apriori_file_guids.size();
            for (const auto &entry : volume.files) total_sections += entry.sections.size();
        }
        out << "Format: UEFI PI Firmware Volume / FFS2-FFS3\n"
            << "Volumes: " << volumes.value().size() << " Files: " << total_files
            << " Sections: " << total_sections << " Extended-header entries: " << total_extensions << '\n';
        std::size_t listed_files = 0, listed_sections = 0, listed_extensions = 0,
                    listed_apriori_guids = 0, listed_free_space = 0, listed_layout_diagnostics = 0;
        constexpr std::size_t file_output_limit = 4096;
        constexpr std::size_t section_output_limit = 16384;
        constexpr std::size_t extension_output_limit = 8192;
        constexpr std::size_t free_space_output_limit = 8192;
        constexpr std::size_t layout_diagnostic_output_limit = 4096;
        constexpr std::size_t apriori_guid_output_limit = 512;
        for (std::size_t i = 0; i < volumes.value().size(); ++i) {
            const auto &volume = volumes.value()[i];
            out << "Volume[" << i << "] file-offset=" << hex_value(volume.file_offset)
                << " size=" << hex_value(volume.length)
                << " fs-guid=" << firmware::uefi_guid_string(volume.file_system_guid)
                << " revision=" << static_cast<unsigned>(volume.revision)
                << " header-checksum=valid files=" << volume.files.size() << '\n';
            if (volume.dxe_apriori_file_present) {
                out << "  DXE-APRIORI entries=" << volume.dxe_apriori_file_guids.size();
                if (!volume.dxe_apriori_diagnostic.empty())
                    out << " diagnostic=" << volume.dxe_apriori_diagnostic;
                out << '\n';
                for (const auto &guid : volume.dxe_apriori_file_guids) {
                    if (listed_apriori_guids >= apriori_guid_output_limit) break;
                    out << "    DXE-APRIORI-GUID " << firmware::uefi_guid_string(guid) << '\n';
                    ++listed_apriori_guids;
                }
            }
            if (volume.extended_header_name_guid)
                out << "  ExtendedHeader name-guid="
                    << firmware::uefi_guid_string(*volume.extended_header_name_guid)
                    << " size=" << hex_value(volume.extended_header_size.value_or(0)) << '\n';
            for (const auto &extension : volume.extension_entries) {
                if (listed_extensions >= extension_output_limit) break;
                out << "  ExtendedHeaderEntry type=" << hex_value(extension.type)
                    << " size=" << hex_value(extension.size)
                    << " volume-offset=" << hex_value(extension.volume_offset)
                    << " payload-offset=" << hex_value(extension.payload_offset)
                    << "+" << hex_value(extension.payload_size) << '\n';
                ++listed_extensions;
            }
            for (std::size_t block_index = 0; block_index < volume.block_map.size(); ++block_index) {
                const auto &block = volume.block_map[block_index];
                out << "  BlockMap[" << block_index << "] blocks=" << block.block_count
                    << " block-size=" << hex_value(block.block_size)
                    << " mapped-size=" << hex_value(std::uint64_t(block.block_count) * block.block_size) << '\n';
            }
            std::size_t listed_volume_free_space = 0;
            for (std::size_t free_index = 0; free_index < volume.free_space_regions.size() &&
                 listed_free_space < free_space_output_limit; ++free_index, ++listed_free_space, ++listed_volume_free_space) {
                const auto &region = volume.free_space_regions[free_index];
                out << "  FreeSpace[" << free_index << "] offset=" << hex_value(region.volume_offset)
                    << " size=" << hex_value(region.size)
                    << " erase-polarity=" << (region.erase_polarity_valid ? "valid" : "not-valid") << '\n';
            }
            std::size_t listed_volume_layout_diagnostics = 0;
            for (const auto &diagnostic : volume.layout_diagnostics) {
                if (listed_layout_diagnostics >= layout_diagnostic_output_limit) break;
                out << "  layout=" << diagnostic << '\n';
                ++listed_layout_diagnostics;
                ++listed_volume_layout_diagnostics;
            }
            if (volume.layout_diagnostics.size() > listed_volume_layout_diagnostics)
                out << "  layout-diagnostics-omitted="
                    << volume.layout_diagnostics.size() - listed_volume_layout_diagnostics << '\n';
            if (volume.free_space_regions.size() > listed_volume_free_space)
                out << "  free-space-entries-omitted=" << volume.free_space_regions.size() - listed_volume_free_space << '\n';
            for (const auto &entry : volume.files) {
                if (listed_files >= file_output_limit) break;
                out << "  " << firmware::uefi_guid_string(entry.name_guid)
                    << " type=" << hex_value(entry.type)
                    << " size=" << hex_value(entry.size)
                    << " header=" << hex_value(entry.header_size)
                    << " state=" << hex_value(entry.state)
                    << " disposition=" << ffs_disposition_name(entry.disposition)
                    << " data-offset=" << hex_value(volume.file_offset + entry.data_offset)
                    << " data-size=" << hex_value(entry.data_size)
                    << " data-alignment=" << hex_value(entry.data_alignment)
                    << " alignment=" << (entry.data_alignment_valid ? "valid" : "not-valid")
                    << " pad-file=" << (entry.pad_file ? "yes" : "no")
                    << " pad-data=" << (!entry.pad_data_erase_polarity_valid ? "not-applicable"
                        : *entry.pad_data_erase_polarity_valid ? "erase-polarity-valid" : "not-valid")
                    << " header-checksum=" << (entry.header_checksum_valid ? "valid" : "not-valid")
                    << " data-checksum=" << (!entry.data_checksum_valid ? "not-applicable"
                        : *entry.data_checksum_valid ? "valid" : "not-valid")
                    << " sections=" << entry.sections.size() << '\n';
                if (!entry.section_diagnostic.empty())
                    out << "    section-parse=" << entry.section_diagnostic << '\n';
                for (std::size_t section_index = 0; section_index < entry.sections.size(); ++section_index) {
                    if (listed_sections >= section_output_limit) break;
                    const auto &section = entry.sections[section_index];
                    out << "    Section[" << section_index << "] type=" << hex_value(section.type)
                        << " (" << section_type_name(section.type) << ")"
                        << " size=" << hex_value(section.size)
                        << " offset-space=" << (section.offset_space == firmware::UefiSectionOffsetSpace::file
                            ? "file" : "decompressed")
                        << (section.offset_space == firmware::UefiSectionOffsetSpace::file ? " file-offset=" : " decoded-offset=")
                        << hex_value(section.file_offset)
                        << " header=" << hex_value(section.header_size)
                        << (section.offset_space == firmware::UefiSectionOffsetSpace::file ? " payload=" : " decoded-payload=")
                        << hex_value(section.payload_offset)
                        << "+" << hex_value(section.payload_size)
                        << " depth=" << section.depth
                        << " disposition=" << section_disposition(section.disposition);
                    if (section.parent_index) out << " parent=" << *section.parent_index;
                    if (section.uncompressed_size) out << " uncompressed-size=" << hex_value(*section.uncompressed_size);
                    if (section.compression_type) out << " compression=" << hex_value(*section.compression_type);
                    if (section.decompression_succeeded) out << " decompression=decoded";
                    if (section.definition_guid)
                        out << " guid=" << firmware::uefi_guid_string(*section.definition_guid)
                            << " data-offset=" << hex_value(*section.definition_data_offset)
                            << " attributes=" << hex_value(*section.definition_attributes);
                    if (section.guided_crc32)
                        out << " guided-crc32=" << hex_value(*section.guided_crc32)
                            << " crc-status=" << (!section.guided_crc32_valid ? "not-checked"
                                : *section.guided_crc32_valid ? "valid" : "mismatch");
                    if (section.freeform_subtype_guid)
                        out << " subtype-guid=" << firmware::uefi_guid_string(*section.freeform_subtype_guid);
                    if (section.version_build) out << " build=" << *section.version_build;
                    if (section.ui_name) out << " ui-name=" << quoted_utf16(*section.ui_name);
                    if (section.version_text) out << " version-text=" << quoted_utf16(*section.version_text);
                    if (section.depex_valid)
                        out << " depex=" << (*section.depex_valid ? "valid" : "invalid")
                            << " instructions=" << section.depex_instruction_count
                            << " guid-operands=" << section.depex_guid_operand_count
                            << " max-stack=" << section.depex_max_stack_depth;
                    if (!section.depex_diagnostic.empty()) out << " depex-note=" << section.depex_diagnostic;
                    if (!section.diagnostic.empty()) out << " note=" << section.diagnostic;
                    out << '\n';
                    ++listed_sections;
                }
                ++listed_files;
            }
        }
        if (listed_files < total_files)
            out << "Files omitted from output: " << (total_files - listed_files) << " (output limit " << file_output_limit << ")\n";
        if (listed_sections < total_sections)
            out << "Sections omitted from output: " << (total_sections - listed_sections)
                << " (output limit " << section_output_limit << ")\n";
        if (listed_extensions < total_extensions)
            out << "Extended-header entries omitted from output: " << (total_extensions - listed_extensions)
                << " (output limit " << extension_output_limit << ")\n";
        if (listed_apriori_guids < total_apriori_guids)
            out << "DXE APRIORI GUIDs omitted from output: " << (total_apriori_guids - listed_apriori_guids)
                << " (output limit " << apriori_guid_output_limit << ")\n";
        return 0;
    } catch (const std::exception &error) {
        err << "UEFI firmware: " << error.what() << '\n';
        return 1;
    }
}

int run_uefi_capsule_cli(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.size() < 4 || args[0] != L"inspect" || args[args.size() - 2] != L"--format" || args.back() != L"uefi-capsule")
        return -1;
    try {
        std::vector<std::wstring_view> inputs;
        std::vector<std::pair<std::uint64_t, std::wstring_view>> sparse_region_args;
        std::optional<std::uint64_t> scatter_base, scatter_head;
        bool json_output = false;
        std::vector<firmware::UefiFmpInstalledImage> installed_images;
        std::vector<firmware::UefiFmpImageVersion> dependency_versions;
        std::optional<std::size_t> extract_item;
        std::filesystem::path extract_output;
        bool replace_output = false;
        bool inventory_complete = false;
        bool report_anti_rollback = false;
        bool report_dependencies = false, dependency_inventory_complete = false;
        for (std::size_t index = 1; index < args.size() - 2; ++index) {
            if (args[index] == L"--extract-item") {
                if (extract_item || index + 1 >= args.size() - 2) {
                    err << "UEFI capsule: --extract-item requires one item index\n"; return 1;
                }
                auto parsed_index = parse_address(args[++index]);
                if (!parsed_index || parsed_index.value() > 4095) {
                    err << "UEFI capsule: item index must be in the range 0..4095\n"; return 1;
                }
                extract_item = static_cast<std::size_t>(parsed_index.value());
            } else if (args[index] == L"--output") {
                if (!extract_output.empty() || index + 1 >= args.size() - 2) {
                    err << "UEFI capsule: --output requires one path\n"; return 1;
                }
                extract_output = path_from_wide(args[++index]);
            } else if (args[index] == L"--replace") {
                if (replace_output) { err << "UEFI capsule: duplicate --replace\n"; return 1; }
                replace_output = true;
            } else if (args[index] == L"--fmp-installed-image") {
                if (index + 1 >= args.size() - 2 || installed_images.size() >= 65536) {
                    err << "UEFI capsule: --fmp-installed-image requires GUID=VERSION,LOWEST (max 65,536)\n"; return 1;
                }
                auto image = parse_installed_image(args[++index]);
                if (!image) { err << "UEFI capsule: invalid installed image; expected GUID=VERSION,LOWEST\n"; return 1; }
                installed_images.push_back(*image);
                report_anti_rollback = true;
            } else if (args[index] == L"--fmp-image-version") {
                if (index + 1 >= args.size() - 2 || dependency_versions.size() >= 65536) {
                    err << "UEFI capsule: --fmp-image-version requires GUID=VERSION (max 65,536)\n"; return 1;
                }
                auto version = parse_image_version(args[++index]);
                if (!version) { err << "UEFI capsule: invalid image version; expected GUID=VERSION\n"; return 1; }
                dependency_versions.push_back(*version);
            } else if (args[index] == L"--fmp-evaluate-dependencies") {
                report_dependencies = true;
            } else if (args[index] == L"--fmp-dependency-inventory-complete") {
                dependency_inventory_complete = true;
            } else if (args[index] == L"--fmp-inventory-complete") {
                inventory_complete = true;
                report_anti_rollback = true;
            } else if (args[index] == L"--capsule-sg-region") {
                if (index + 1 >= args.size() - 2) {
                    err << "UEFI capsule: --capsule-sg-region requires BASE=FILE\n"; return 1;
                }
                const auto specification = args[++index];
                const auto equal = specification.find(L'=');
                if (equal == std::wstring_view::npos || equal == 0 || equal + 1 >= specification.size()) {
                    err << "UEFI capsule: --capsule-sg-region requires BASE=FILE\n"; return 1;
                }
                auto base = parse_address(specification.substr(0, equal));
                if (!base) { err << "UEFI capsule: invalid sparse-region base: " << base.error().message << '\n'; return 1; }
                sparse_region_args.emplace_back(base.value(), specification.substr(equal + 1));
                if (sparse_region_args.size() > 255) {
                    err << "UEFI capsule: sparse region count exceeds 256 total regions\n"; return 1;
                }
            } else if (args[index] == L"--json") {
                json_output = true;
            } else
            if (args[index] == L"--capsule-sg-base" || args[index] == L"--capsule-sg-head") {
                auto &option = args[index] == L"--capsule-sg-base" ? scatter_base : scatter_head;
                if (option || index + 1 >= args.size() - 2) {
                    err << "UEFI capsule: missing or duplicate scatter/gather address option\n"; return 1;
                }
                auto value = parse_address(args[++index]);
                if (!value) { err << "UEFI capsule: " << value.error().message << '\n'; return 1; }
                option = value.value();
            } else {
                if (inputs.size() == 256) {
                    err << "UEFI capsule: input count exceeds 256 capsule limit\n"; return 1;
                }
                inputs.push_back(args[index]);
            }
        }
        const auto input_count = inputs.size();
        if (input_count == 0 || scatter_base.has_value() != scatter_head.has_value() ||
            ((scatter_head || !sparse_region_args.empty()) && input_count != 1) ||
            (!sparse_region_args.empty() && !scatter_head)) {
            err << "UEFI capsule: scatter/gather requires one primary capture, --capsule-sg-base and --capsule-sg-head; sparse regions require scatter/gather\n"; return 1;
        }
        if (sparse_region_args.size() + 1 > 256) { err << "UEFI capsule: sparse region count exceeds 256 total regions\n"; return 1; }
        if (json_output && sparse_region_args.empty()) { err << "UEFI capsule: --json is supported only with multi-region scatter/gather inventory\n"; return 1; }
        if (input_count > 256) {
            err << "UEFI capsule: input count exceeds 256 capsule limit\n"; return 1;
        }
        if (!report_dependencies && (!dependency_versions.empty() || dependency_inventory_complete)) {
            err << "UEFI capsule: --fmp-image-version and --fmp-dependency-inventory-complete require --fmp-evaluate-dependencies\n";
            return 1;
        }
        if (report_dependencies && scatter_head) {
            err << "UEFI capsule: dependency evaluation currently requires contiguous FMP capsule inputs\n";
            return 1;
        }
        if (report_dependencies && extract_item) {
            err << "UEFI capsule: dependency evaluation cannot be combined with item extraction\n";
            return 1;
        }
        if (extract_item.has_value() != !extract_output.empty() ||
            (replace_output && !extract_item)) {
            err << "UEFI capsule: extraction requires both --extract-item and --output; --replace applies only to extraction\n";
            return 1;
        }
        if (extract_item && (input_count != 1 || scatter_head)) {
            err << "UEFI capsule: item extraction requires one contiguous capsule input\n";
            return 1;
        }
        std::vector<std::shared_ptr<const FileStorage>> files;
        std::vector<ByteView> views;
        std::vector<std::span<const std::byte>> buffers;
        files.reserve(input_count + sparse_region_args.size());
        views.reserve(input_count + sparse_region_args.size());
        buffers.reserve(input_count + sparse_region_args.size());
        std::uint64_t total_size = 0;
        for (std::size_t i = 0; i < input_count; ++i) {
            auto opened = FileStorage::open(path_from_wide(inputs[i]));
            if (!opened) { err << "UEFI capsule: " << opened.error().message << '\n'; return 1; }
            auto file = opened.value();
            if (file->size() > 512ull * 1024 * 1024 - total_size ||
                file->size() > (std::numeric_limits<std::size_t>::max)()) {
                err << "UEFI capsule: inputs exceed cumulative 512 MiB inspection limit\n"; return 1;
            }
            total_size += file->size();
            auto read = file->read_at({0}, static_cast<std::size_t>(file->size()));
            if (!read) { err << "UEFI capsule: " << read.error().message << '\n'; return 1; }
            files.push_back(std::move(file));
            views.push_back(std::move(read.value()));
            buffers.push_back(views.back().bytes);
        }
        std::vector<std::uint64_t> loaded_region_bases;
        std::vector<std::wstring_view> loaded_region_paths;
        if (scatter_head) {
            loaded_region_bases.push_back(*scatter_base);
            loaded_region_paths.push_back(inputs.front());
            for (const auto &[base, path] : sparse_region_args) {
                if (std::find(loaded_region_bases.begin(), loaded_region_bases.end(), base) != loaded_region_bases.end()) {
                    err << "UEFI capsule: duplicate sparse-region physical base " << hex_value(base) << '\n'; return 1;
                }
                auto opened = FileStorage::open(path_from_wide(path));
                if (!opened) { err << "UEFI capsule: sparse region " << wide_to_utf8(path) << ": " << opened.error().message << '\n'; return 1; }
                auto file = opened.value();
                if (file->size() > 512ull * 1024 * 1024 - total_size ||
                    file->size() > (std::numeric_limits<std::size_t>::max)()) {
                    err << "UEFI capsule: captures exceed cumulative 512 MiB inspection limit\n"; return 1;
                }
                total_size += file->size();
                auto read = file->read_at({0}, static_cast<std::size_t>(file->size()));
                if (!read) { err << "UEFI capsule: " << read.error().message << '\n'; return 1; }
                loaded_region_bases.push_back(base);
                loaded_region_paths.push_back(path);
                files.push_back(std::move(file));
                views.push_back(std::move(read.value()));
                buffers.push_back(views.back().bytes);
            }
        }
        if (scatter_head) {
            std::vector<firmware::UefiCapsuleCaptureRegion> capture_regions;
            capture_regions.reserve(loaded_region_bases.size());
            for (std::size_t i = 0; i < loaded_region_bases.size(); ++i)
                capture_regions.push_back({loaded_region_bases[i], buffers[i]});
            auto parsed = firmware::parse_uefi_fmp_scatter_gather_regions(capture_regions, *scatter_head);
            if (!parsed) { err << "UEFI capsule: " << parsed.error().message << '\n'; return 1; }
            const auto &gathered = parsed.value();
            if (!sparse_region_args.empty()) {
                if (json_output) {
                    out << "{\"schema\":\"hexlab.uefi-capsule-sg.v1\",\"status\":\"complete\",\"physical_base\":"
                        << json_string(hex_value(gathered.capture_physical_base)) << ",\"descriptor_head\":"
                        << json_string(hex_value(gathered.descriptor_head)) << ",\"gathered_bytes\":"
                        << gathered.payload_bytes << ",\"capsule_count\":" << gathered.inventory.capsules.size()
                        << ",\"regions\":[";
                    const auto region_limit = std::min<std::size_t>(loaded_region_bases.size(), 256);
                    for (std::size_t i = 0; i < region_limit; ++i) {
                        if (i) out << ',';
                        out << "{\"base\":" << json_string(hex_value(loaded_region_bases[i]))
                            << ",\"path\":" << json_string(wide_to_utf8(loaded_region_paths[i]))
                            << ",\"size\":" << buffers[i].size() << '}';
                    }
                    out << "],\"omitted_regions\":" << loaded_region_bases.size() - region_limit << ",\"capsules\":[";
                    for (std::size_t i = 0; i < gathered.inventory.capsules.size(); ++i) {
                        if (i) out << ',';
                        out << "{\"stream_offset\":" << json_string(hex_value(gathered.capsule_logical_offsets[i]))
                            << ",\"image_size\":" << gathered.inventory.capsules[i].image_size << '}';
                    }
                    out << "]}\n";
                    return 0;
                }
                out << "Format: UEFI FMP scatter/gather capsule list (sparse physical captures)\n"
                    << "Capture: descriptor-head=" << hex_value(gathered.descriptor_head)
                    << " descriptors=" << gathered.blocks.size() << " gathered-bytes=" << gathered.payload_bytes
                    << " capsules=" << gathered.inventory.capsules.size() << '\n';
                constexpr std::size_t region_output_limit = 256;
                for (std::size_t i = 0; i < std::min(loaded_region_bases.size(), region_output_limit); ++i)
                    out << "Region[" << i << "]: physical-base=" << hex_value(loaded_region_bases[i])
                        << " path=" << wide_to_utf8(loaded_region_paths[i]) << " size=" << buffers[i].size() << '\n';
                if (loaded_region_bases.size() > region_output_limit)
                    out << "Regions omitted: " << loaded_region_bases.size() - region_output_limit << '\n';
                constexpr std::size_t descriptor_output_limit = 256;
                for (std::size_t i = 0; i < std::min(gathered.blocks.size(), descriptor_output_limit); ++i) {
                    const auto &block = gathered.blocks[i];
                    out << "Block[" << i << "]: kind="
                        << (block.kind == firmware::UefiCapsuleBlockKind::data ? "data" :
                            block.kind == firmware::UefiCapsuleBlockKind::continuation ? "continuation" : "terminator")
                        << " descriptor-region=" << block.descriptor_region_index
                        << " descriptor-offset=" << hex_value(block.descriptor_capture_offset)
                        << " physical=" << hex_value(block.descriptor_physical_address)
                        << " target=" << hex_value(block.target_physical_address)
                        << " length=" << hex_value(block.length);
                    if (block.kind == firmware::UefiCapsuleBlockKind::data)
                        out << " data-region=" << block.data_region_index
                            << " data-offset=" << hex_value(block.data_capture_offset)
                            << " logical-offset=" << hex_value(block.logical_offset);
                    out << '\n';
                }
                if (gathered.blocks.size() > descriptor_output_limit)
                    out << "Descriptor rows omitted: " << gathered.blocks.size() - descriptor_output_limit << '\n';
                CapsuleOutputBudget sparse_budget;
                for (std::size_t i = 0; i < gathered.inventory.capsules.size(); ++i) {
                    const auto &capsule = gathered.inventory.capsules[i];
                    ++sparse_budget.capsules;
                    out << "Capsule[" << i << "]: logical-stream-offset=" << hex_value(gathered.capsule_logical_offsets[i])
                        << " guid=" << firmware::uefi_guid_string(capsule.capsule_guid)
                        << " image-size=" << hex_value(capsule.image_size) << " payloads=" << capsule.payload_count << '\n';
                    for (std::size_t j = 0; j < capsule.items.size(); ++j)
                        write_capsule_item(out, capsule.items[j], "  ",
                            "Capsule[" + std::to_string(i) + "] Item[" + std::to_string(j) + "]",
                            false, sparse_budget, true);
                    if (report_anti_rollback)
                        for (std::size_t j = 0; j < capsule.items.size(); ++j)
                            write_anti_rollback(out, capsule.items[j], installed_images, inventory_complete,
                                "Capsule[" + std::to_string(i) + "] Item[" + std::to_string(j) + "]");
                }
                write_capsule_output_limits(out, sparse_budget);
                out << "Physical addresses were resolved only inside supplied regions; no firmware was updated.\n";
                return 0;
            }
            out << "Format: UEFI FMP scatter/gather capsule list (offline little-endian physical capture)\n"
                << "Capture: physical-base=" << hex_value(gathered.capture_physical_base)
                << " descriptor-head=" << hex_value(gathered.descriptor_head)
                << " descriptors=" << gathered.blocks.size() << " gathered-bytes=" << gathered.payload_bytes
                << " capsules=" << gathered.inventory.capsules.size() << '\n';
            constexpr std::size_t descriptor_output_limit = 256;
            for (std::size_t index = 0; index < std::min(gathered.blocks.size(), descriptor_output_limit); ++index) {
                const auto &block = gathered.blocks[index];
                out << "Block[" << index << "] kind="
                    << (block.kind == firmware::UefiCapsuleBlockKind::data ? "data" :
                        block.kind == firmware::UefiCapsuleBlockKind::continuation ? "continuation" : "terminator")
                    << " descriptor-physical=" << hex_value(block.descriptor_physical_address)
                    << " descriptor-capture-offset=" << hex_value(block.descriptor_capture_offset)
                    << " target-physical=" << hex_value(block.target_physical_address)
                    << " length=" << hex_value(block.length);
                if (block.kind == firmware::UefiCapsuleBlockKind::data)
                    out << " logical-capsule-offset=" << hex_value(block.logical_offset)
                        << " data-capture-offset=" << hex_value(block.data_capture_offset);
                out << '\n';
            }
            if (gathered.blocks.size() > descriptor_output_limit)
                out << "Descriptor rows omitted: " << gathered.blocks.size() - descriptor_output_limit << '\n';
            CapsuleOutputBudget output_budget;
            for (std::size_t capsule_index = 0; capsule_index < gathered.inventory.capsules.size(); ++capsule_index) {
                const auto &capsule = gathered.inventory.capsules[capsule_index];
                ++output_budget.capsules;
                out << "Capsule[" << capsule_index << "]: logical-stream-offset="
                    << hex_value(gathered.capsule_logical_offsets[capsule_index])
                    << " guid=" << firmware::uefi_guid_string(capsule.capsule_guid)
                    << " header-size=" << hex_value(capsule.header_size)
                    << " header-extension-offset=" << hex_value(capsule.header_extension_offset)
                    << " header-extension-size=" << hex_value(capsule.header_extension_size)
                    << " flags=" << hex_value(capsule.flags)
                    << " flag-names=" << capsule_flag_names(capsule.flags)
                    << " image-size=" << hex_value(capsule.image_size)
                    << " fmp-version=" << capsule.fmp_version << " embedded-drivers=" << capsule.embedded_driver_count
                    << " payloads=" << capsule.payload_count << '\n'
                    << "Item/FV offsets are local to this logical capsule; add its logical-stream-offset before capture translation.\n";
                for (std::size_t index = 0; index < capsule.items.size(); ++index)
                    write_capsule_item(out, capsule.items[index], "  ", "Item[" + std::to_string(index) + "]",
                                       false, output_budget, true);
                if (report_anti_rollback)
                    for (std::size_t index = 0; index < capsule.items.size(); ++index)
                        write_anti_rollback(out, capsule.items[index], installed_images, inventory_complete,
                                            "Item[" + std::to_string(index) + "]");
            }
            write_capsule_output_limits(out, output_budget);
            out << "Physical addresses were resolved only inside the supplied capture; no firmware was updated.\n";
            return 0;
        }
        if (input_count == 1) {
            static constexpr std::array<std::uint8_t, 16> json_guid{
                0xcd,0xf4,0xd6,0x67,0xb8,0xd6,0x73,0x45,0xbf,0x4a,0xde,0x5e,0x25,0x2d,0x61,0xae};
            bool is_json = buffers.front().size() >= json_guid.size();
            for (std::size_t i = 0; is_json && i < json_guid.size(); ++i)
                is_json = std::to_integer<std::uint8_t>(buffers.front()[i]) == json_guid[i];
            if (is_json) {
                if (report_dependencies) {
                    err << "UEFI capsule: FMP dependency evaluation cannot be used with a JSON capsule\n"; return 1;
                }
                if (extract_item) { err << "UEFI capsule: JSON capsule payload extraction is unsupported\n"; return 1; }
                auto parsed = firmware::parse_uefi_json_capsule(buffers.front());
                if (!parsed) { err << "UEFI capsule: " << parsed.error().message << '\n'; return 1; }
                const auto &capsule = parsed.value();
                out << "Format: UEFI JSON Capsule\n"
                    << "Capsule: guid=" << firmware::uefi_guid_string(capsule.capsule_guid)
                    << " header-size=" << hex_value(capsule.header_size)
                    << " header-extension-offset=" << hex_value(capsule.header_extension_offset)
                    << " header-extension-size=" << hex_value(capsule.header_extension_size)
                    << " flags=" << hex_value(capsule.flags)
                    << " flag-names=" << capsule_flag_names(capsule.flags)
                    << " image-size=" << hex_value(capsule.image_size) << '\n'
                    << "JSON: version=" << capsule.json_header_version
                    << " capsule-id=" << capsule.capsule_id
                    << " payload-size=" << capsule.payload_size
                    << " payload-offset=" << hex_value(capsule.payload_offset) << '\n';
                if (capsule.trailing_size != 0)
                    out << "Trailing bytes: " << capsule.trailing_size << '\n';
                out << "JSON payload contents were not parsed or executed.\n";
                return 0;
            }
            auto parsed = firmware::parse_uefi_fmp_capsule(buffers.front());
            if (!parsed) { err << "UEFI capsule: " << parsed.error().message << '\n'; return 1; }
            const auto &capsule = parsed.value();
            if (extract_item) {
                if (*extract_item >= capsule.items.size()) {
                    err << "UEFI capsule: item index is outside the capsule item table\n"; return 1;
                }
                const auto &item = capsule.items[*extract_item];
                if (item.kind != firmware::UefiCapsuleItemKind::fmp_payload) {
                    err << "UEFI capsule: selected item is an embedded driver, not an FMP image payload\n"; return 1;
                }
                const auto image_size = std::uint64_t(item.update_image_size) - item.authentication_header_size -
                    item.dependency_expression_size - item.fmp_payload_header_size;
                if (item.firmware_image_offset > buffers.front().size() ||
                    image_size > buffers.front().size() - item.firmware_image_offset) {
                    err << "UEFI capsule: validated firmware image extent is outside input buffer\n"; return 1;
                }
                const std::array protected_paths{path_from_wide(inputs.front())};
                auto publication = FilePublication::create(extract_output,
                    replace_output ? ExistingFilePolicy::replace : ExistingFilePolicy::reject, protected_paths, {});
                if (!publication) { err << "UEFI capsule: " << publication.error().message << '\n'; return 1; }
                auto appended = publication.value()->append(buffers.front().subspan(
                    static_cast<std::size_t>(item.firmware_image_offset), static_cast<std::size_t>(image_size)));
                if (!appended) { err << "UEFI capsule: " << appended.error().message << '\n'; return 1; }
                auto published = publication.value()->publish();
                if (!published) { err << "UEFI capsule: " << published.error().message << '\n'; return 1; }
                if (!published.value()) { err << "UEFI capsule: output publication was canceled\n"; return 1; }
                out << "Extracted FMP firmware image payload Item[" << *extract_item << "]: bytes="
                    << image_size << " offset=" << hex_value(item.firmware_image_offset)
                    << " output=" << extract_output.string() << '\n';
            }
            out << "Format: UEFI FMP Capsule\n"
                << "Capsule: guid=" << firmware::uefi_guid_string(capsule.capsule_guid)
                << " header-size=" << hex_value(capsule.header_size)
                << " header-extension-offset=" << hex_value(capsule.header_extension_offset)
                << " header-extension-size=" << hex_value(capsule.header_extension_size)
                << " flags=" << hex_value(capsule.flags)
                << " flag-names=" << capsule_flag_names(capsule.flags)
                << " image-size=" << hex_value(capsule.image_size) << '\n'
                << "FMP: version=" << capsule.fmp_version
                << " embedded-drivers=" << capsule.embedded_driver_count
                << " payloads=" << capsule.payload_count << '\n';
            CapsuleOutputBudget output_budget;
            output_budget.capsules = 1;
            std::size_t authentication_checks = 0;
            std::size_t dependency_checks = 0, dependency_checks_omitted = 0;
            if (report_dependencies)
                out << "FMP dependency facts: supplied-image-versions=" << dependency_versions.size()
                    << " inventory-complete=" << (dependency_inventory_complete ? "true" : "false") << '\n';
            for (std::size_t i = 0; i < capsule.items.size(); ++i) {
                write_capsule_item(out, capsule.items[i], "  ", "Item[" + std::to_string(i) + "]",
                                   false, output_budget);
                write_authentication_status(out, capsule.items[i], buffers.front(),
                                            "Item[" + std::to_string(i) + "]", authentication_checks);
                if (report_anti_rollback)
                    write_anti_rollback(out, capsule.items[i], installed_images, inventory_complete,
                                        "Item[" + std::to_string(i) + "]");
                if (report_dependencies)
                    write_dependency_status(out, capsule.items[i], buffers.front(), dependency_versions,
                        dependency_inventory_complete, "Item[" + std::to_string(i) + "]",
                        dependency_checks, dependency_checks_omitted);
            }
            if (dependency_checks_omitted)
                out << "FMP dependency evaluations omitted: " << dependency_checks_omitted << " (CLI limit 4096)\n";
            write_capsule_output_limits(out, output_budget);
            if (capsule.trailing_size != 0)
                out << "Trailing bytes: " << capsule.trailing_size << '\n';
        } else {
            auto parsed = firmware::parse_uefi_capsule_list(buffers);
            if (!parsed) { err << "UEFI capsule: " << parsed.error().message << '\n'; return 1; }
            const auto &list = parsed.value();
            if (list.kind == firmware::UefiCapsuleListKind::json) {
                if (report_dependencies) {
                    err << "UEFI capsule: FMP dependency evaluation cannot be used with JSON capsules\n"; return 1;
                }
                out << "Format: UEFI JSON Capsule List (" << list.total_capsule_count << ")\n";
                for (std::size_t i = 0; i < list.json_capsules.size(); ++i) {
                    const auto &capsule = list.json_capsules[i];
                    out << "Capsule[" << i << "]: guid=" << firmware::uefi_guid_string(capsule.capsule_guid)
                        << " header-size=" << hex_value(capsule.header_size)
                        << " header-extension-offset=" << hex_value(capsule.header_extension_offset)
                        << " header-extension-size=" << hex_value(capsule.header_extension_size)
                        << " flags=" << hex_value(capsule.flags)
                        << " flag-names=" << capsule_flag_names(capsule.flags)
                        << " image-size=" << hex_value(capsule.image_size)
                        << " json-version=" << capsule.json_header_version
                        << " capsule-id=" << capsule.capsule_id
                        << " payload-size=" << capsule.payload_size
                        << " payload-offset=" << hex_value(capsule.payload_offset) << '\n';
                    if (capsule.trailing_size != 0)
                        out << "  Trailing bytes: " << capsule.trailing_size << '\n';
                }
                out << "Total input bytes: " << list.total_input_bytes
                    << " total capsules: " << list.total_capsule_count << '\n'
                    << "JSON payload contents were not decoded or executed.\n";
                return 0;
            }
            out << "Format: UEFI FMP Capsule List (" << list.total_capsule_count << ")\n";
            CapsuleOutputBudget output_budget;
            std::size_t authentication_checks = 0;
            std::size_t dependency_checks = 0, dependency_checks_omitted = 0;
            if (report_dependencies)
                out << "FMP dependency facts: supplied-image-versions=" << dependency_versions.size()
                    << " inventory-complete=" << (dependency_inventory_complete ? "true" : "false") << '\n';
            for (std::size_t i = 0; i < list.capsules.size(); ++i) {
                const auto &capsule = list.capsules[i];
                if (output_budget.capsules < capsule_output_limit) ++output_budget.capsules;
                out << "Capsule[" << i << "]: guid=" << firmware::uefi_guid_string(capsule.capsule_guid)
                    << " header-size=" << hex_value(capsule.header_size)
                    << " header-extension-offset=" << hex_value(capsule.header_extension_offset)
                    << " header-extension-size=" << hex_value(capsule.header_extension_size)
                    << " flags=" << hex_value(capsule.flags)
                    << " flag-names=" << capsule_flag_names(capsule.flags)
                    << " image-size=" << hex_value(capsule.image_size)
                    << " fmp-version=" << capsule.fmp_version
                    << " embedded-drivers=" << capsule.embedded_driver_count
                    << " payloads=" << capsule.payload_count << '\n';
                for (std::size_t j = 0; j < capsule.items.size(); ++j) {
                    write_capsule_item(out, capsule.items[j], "  ",
                                       "Capsule[" + std::to_string(i) + "] Item[" + std::to_string(j) + "]",
                                       false, output_budget);
                    if (i < buffers.size())
                        write_authentication_status(out, capsule.items[j], buffers[i],
                            "Capsule[" + std::to_string(i) + "] Item[" + std::to_string(j) + "]",
                            authentication_checks);
                    if (report_anti_rollback)
                        write_anti_rollback(out, capsule.items[j], installed_images, inventory_complete,
                                            "Capsule[" + std::to_string(i) + "] Item[" + std::to_string(j) + "]");
                    if (report_dependencies && i < buffers.size())
                        write_dependency_status(out, capsule.items[j], buffers[i], dependency_versions,
                            dependency_inventory_complete,
                            "Capsule[" + std::to_string(i) + "] Item[" + std::to_string(j) + "]",
                            dependency_checks, dependency_checks_omitted);
                }
                if (capsule.trailing_size != 0)
                    out << "  Trailing bytes: " << capsule.trailing_size << '\n';
            }
            if (dependency_checks_omitted)
                out << "FMP dependency evaluations omitted: " << dependency_checks_omitted << " (CLI limit 4096)\n";
            write_capsule_output_limits(out, output_budget);
            out << "Total input bytes: " << list.total_input_bytes << " total items: " << list.total_item_count << '\n';
        }
        out << "Payload contents were not extracted or executed.\n";
        return 0;
    } catch (const std::exception &error) {
        err << "UEFI capsule: " << error.what() << '\n'; return 1;
    }
}
} // namespace hexlab::cli
