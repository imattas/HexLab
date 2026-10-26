#include "commands.hpp"
#include "argument_text.hpp"
#include "project_arguments.hpp"
#include "hexlab/firmware/uefi_volume.hpp"
#include "hexlab/firmware/uefi_capsule.hpp"
#include "hexlab/image/image.hpp"
#include <iomanip>
#include <limits>
#include <ostream>
#include <sstream>
#include <string_view>

namespace hexlab::cli {
namespace {
std::string hex_value(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << value;
    return out.str();
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
    default: return "unknown";
    }
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
        auto codepoint = static_cast<std::uint16_t>(text[i]);
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
        std::size_t total_files = 0, total_sections = 0;
        for (const auto &volume : volumes.value()) {
            total_files += volume.files.size();
            for (const auto &entry : volume.files) total_sections += entry.sections.size();
        }
        out << "Format: UEFI PI Firmware Volume / FFS2-FFS3\n"
            << "Volumes: " << volumes.value().size() << " Files: " << total_files
            << " Sections: " << total_sections << '\n';
        std::size_t listed_files = 0, listed_sections = 0;
        constexpr std::size_t file_output_limit = 4096;
        constexpr std::size_t section_output_limit = 16384;
        for (std::size_t i = 0; i < volumes.value().size(); ++i) {
            const auto &volume = volumes.value()[i];
            out << "Volume[" << i << "] file-offset=" << hex_value(volume.file_offset)
                << " size=" << hex_value(volume.length)
                << " fs-guid=" << firmware::uefi_guid_string(volume.file_system_guid)
                << " revision=" << static_cast<unsigned>(volume.revision)
                << " header-checksum=valid files=" << volume.files.size() << '\n';
            for (const auto &entry : volume.files) {
                if (listed_files >= file_output_limit) break;
                out << "  " << firmware::uefi_guid_string(entry.name_guid)
                    << " type=" << hex_value(entry.type)
                    << " size=" << hex_value(entry.size)
                    << " header=" << hex_value(entry.header_size)
                    << " state=" << hex_value(entry.state)
                    << " data-offset=" << hex_value(volume.file_offset + entry.data_offset)
                    << " data-size=" << hex_value(entry.data_size)
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
                    if (section.freeform_subtype_guid)
                        out << " subtype-guid=" << firmware::uefi_guid_string(*section.freeform_subtype_guid);
                    if (section.version_build) out << " build=" << *section.version_build;
                    if (section.ui_name) out << " ui-name=" << quoted_utf16(*section.ui_name);
                    if (section.version_text) out << " version-text=" << quoted_utf16(*section.version_text);
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
        return 0;
    } catch (const std::exception &error) {
        err << "UEFI firmware: " << error.what() << '\n';
        return 1;
    }
}

int run_uefi_capsule_cli(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.size() != 4 || args[0] != L"inspect" || args[2] != L"--format" || args[3] != L"uefi-capsule")
        return -1;
    try {
        auto opened = FileStorage::open(path_from_wide(args[1]));
        if (!opened) { err << "UEFI capsule: " << opened.error().message << '\n'; return 1; }
        const auto &file = opened.value();
        if (file->size() > 512ull * 1024 * 1024 || file->size() > (std::numeric_limits<std::size_t>::max)()) {
            err << "UEFI capsule: input exceeds 512 MiB inspection limit\n"; return 1;
        }
        auto read = file->read_at({0}, static_cast<std::size_t>(file->size()));
        if (!read) { err << "UEFI capsule: " << read.error().message << '\n'; return 1; }
        const auto view = std::move(read.value());
        auto parsed = firmware::parse_uefi_fmp_capsule(view.bytes);
        if (!parsed) { err << "UEFI capsule: " << parsed.error().message << '\n'; return 1; }
        const auto &capsule = parsed.value();
        out << "Format: UEFI FMP Capsule\n"
            << "Capsule: guid=" << firmware::uefi_guid_string(capsule.capsule_guid)
            << " header-size=" << hex_value(capsule.header_size)
            << " flags=" << hex_value(capsule.flags)
            << " image-size=" << hex_value(capsule.image_size) << '\n'
            << "FMP: version=" << capsule.fmp_version
            << " embedded-drivers=" << capsule.embedded_driver_count
            << " payloads=" << capsule.payload_count << '\n';
        for (std::size_t i = 0; i < capsule.items.size(); ++i) {
            const auto &item = capsule.items[i];
            out << "  Item[" << i << "] kind="
                << (item.kind == firmware::UefiCapsuleItemKind::embedded_driver ? "embedded-driver" : "fmp-payload")
                << " file-offset=" << hex_value(item.file_offset) << " size=" << hex_value(item.size);
            if (item.kind == firmware::UefiCapsuleItemKind::fmp_payload) {
                out << " image-header-version=" << item.image_header_version
                    << " image-type-guid=" << firmware::uefi_guid_string(item.image_type_guid)
                    << " image-index=" << static_cast<unsigned>(item.image_index)
                    << " image-size=" << hex_value(item.update_image_size)
                    << " payload-offset=" << hex_value(item.payload_offset)
                    << " vendor-code-size=" << hex_value(item.vendor_code_size)
                    << " vendor-code-offset=" << hex_value(item.vendor_code_offset);
                if (item.image_header_version >= 2) out << " hardware-instance=" << hex_value(item.hardware_instance);
                if (item.image_header_version >= 3) out << " image-capsule-support=" << hex_value(item.image_capsule_support);
            }
            out << '\n';
        }
        if (capsule.image_size < view.bytes.size())
            out << "Trailing bytes: " << (view.bytes.size() - capsule.image_size) << '\n';
        out << "Payload contents were not extracted or executed.\n";
        return 0;
    } catch (const std::exception &error) {
        err << "UEFI capsule: " << error.what() << '\n'; return 1;
    }
}
} // namespace hexlab::cli
