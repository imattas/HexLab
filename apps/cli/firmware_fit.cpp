#include "commands.hpp"
#include "argument_text.hpp"
#include "project_arguments.hpp"
#include "hexlab/firmware/intel_fit.hpp"
#include "hexlab/image/byte_storage.hpp"
#include <algorithm>
#include <charconv>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>

namespace hexlab::cli {
namespace {
std::optional<std::uint64_t> parse_fit_offset(std::wstring_view argument) {
    auto text = wide_to_utf8(argument);
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.erase(0, 2);
        base = 16;
    }
    if (text.empty()) return {};
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (error != std::errc{} || end != text.data() + text.size()) return {};
    return value;
}
std::string fit_hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << value;
    return out.str();
}
const char *fit_type(std::uint8_t type) {
    switch (type) {
    case 0x00: return "header";
    case 0x01: return "microcode";
    case 0x02: return "startup-acm";
    case 0x03: return "diagnostic-acm";
    case 0x07: return "bios-startup-module";
    case 0x08: return "tpm-policy";
    case 0x09: return "bios-policy";
    case 0x0a: return "txt-policy";
    case 0x0b: return "key-manifest";
    case 0x0c: return "boot-policy-manifest";
    case 0x7f: return "empty";
    default: return "other";
    }
}
}

int run_intel_fit_cli(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.size() != 6 || args[0] != L"inspect" || args[2] != L"--fit-offset" ||
        args[4] != L"--format" || args[5] != L"fit") {
        err << "Usage: hexlab_cli firmware inspect <path> --fit-offset <file-offset> --format fit\n";
        return 2;
    }
    const auto offset = parse_fit_offset(args[3]);
    if (!offset) {
        err << "Intel FIT: invalid file offset\n";
        return 2;
    }
    auto opened = FileStorage::open(path_from_wide(args[1]));
    if (!opened) {
        err << "Intel FIT: " << opened.error().message << '\n';
        return 1;
    }
    const auto &file = *opened.value();
    constexpr std::uint64_t max_input_bytes = 512ULL * 1024 * 1024;
    if (file.size() > max_input_bytes || file.size() > std::numeric_limits<std::size_t>::max()) {
        err << "Intel FIT: input exceeds 512 MiB inspection limit\n";
        return 1;
    }
    auto read = file.read_at({0}, static_cast<std::size_t>(file.size()));
    if (!read) {
        err << "Intel FIT: " << read.error().message << '\n';
        return 1;
    }
    const auto parsed = firmware::parse_intel_fit(read.value().bytes, *offset);
    if (!parsed) {
        err << "Intel FIT: " << parsed.error().message << '\n';
        return 1;
    }
    const auto &table = parsed.value();
    out << "Format: Intel Firmware Interface Table\n"
        << "File offset: " << fit_hex(table.file_offset) << " bytes=" << fit_hex(table.size_bytes)
        << " version=" << fit_hex(table.version) << " entries=" << table.entries.size()
        << " types-ordered=" << (table.entry_types_ordered ? "true" : "false") << '\n';
    if (table.table_checksum_valid)
        out << "Table checksum: " << (*table.table_checksum_valid ? "valid" : "mismatch") << '\n';
    else
        out << "Table checksum: not-requested\n";
    constexpr std::size_t max_rows = 4096;
    const auto shown = std::min(table.entries.size(), max_rows);
    for (std::size_t index = 0; index < shown; ++index) {
        const auto &entry = table.entries[index];
        out << "  entry=" << entry.index << " type=" << fit_type(entry.type) << '(' << unsigned(entry.type)
            << ") address=" << fit_hex(entry.address) << " size-units=" << fit_hex(entry.size_units)
            << " version=" << fit_hex(entry.version) << " c_v=" << (entry.checksum_valid ? "true" : "false")
            << " checksum=" << fit_hex(entry.checksum) << " reserved=" << fit_hex(entry.reserved)
            << " file=" << fit_hex(entry.file_offset) << '\n';
    }
    if (shown < table.entries.size())
        out << "  entries omitted=" << table.entries.size() - shown << " (limit " << max_rows << ")\n";
    out << "Component address mapping and per-component checksums were not evaluated.\n";
    return 0;
}
} // namespace hexlab::cli
