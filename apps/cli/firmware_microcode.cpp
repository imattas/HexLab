#include "commands.hpp"
#include "argument_text.hpp"
#include "project_arguments.hpp"
#include "hexlab/firmware/intel_microcode.hpp"
#include "hexlab/image/byte_storage.hpp"
#include <algorithm>
#include <charconv>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>

namespace hexlab::cli {
namespace {
std::optional<std::uint64_t> parse_microcode_offset(std::wstring_view argument) {
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
std::string microcode_hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << value;
    return out.str();
}
}

int run_intel_microcode_cli(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.size() != 6 || args[0] != L"inspect" || args[2] != L"--microcode-offset" ||
        args[4] != L"--format" || args[5] != L"intel-microcode") {
        err << "Usage: hexlab_cli firmware inspect <path> --microcode-offset <file-offset> --format intel-microcode\n";
        return 2;
    }
    const auto offset = parse_microcode_offset(args[3]);
    if (!offset) {
        err << "Intel microcode: invalid file offset\n";
        return 2;
    }
    auto opened = FileStorage::open(path_from_wide(args[1]));
    if (!opened) {
        err << "Intel microcode: " << opened.error().message << '\n';
        return 1;
    }
    const auto &file = *opened.value();
    constexpr std::uint64_t max_input_bytes = 512ULL * 1024 * 1024;
    if (file.size() > max_input_bytes || file.size() > std::numeric_limits<std::size_t>::max()) {
        err << "Intel microcode: input exceeds 512 MiB inspection limit\n";
        return 1;
    }
    auto read = file.read_at({0}, static_cast<std::size_t>(file.size()));
    if (!read) {
        err << "Intel microcode: " << read.error().message << '\n';
        return 1;
    }
    const auto parsed = firmware::parse_intel_microcode_update(read.value().bytes, *offset);
    if (!parsed) {
        err << "Intel microcode: " << parsed.error().message << '\n';
        return 1;
    }
    const auto &update = parsed.value();
    out << "Format: Intel microcode update\n"
        << "File offset: " << microcode_hex(update.file_offset)
        << " size=" << microcode_hex(update.effective_total_size)
        << " revision=" << microcode_hex(update.update_revision)
        << " date-raw=" << microcode_hex(update.date) << '\n'
        << "Processor signature: " << microcode_hex(update.processor_signature)
        << " flags=" << microcode_hex(update.processor_flags)
        << " loader-revision=" << microcode_hex(update.loader_revision) << '\n'
        << "Data bytes: " << update.effective_data_size
        << " reserved-zero=" << (update.reserved_fields_zero ? "true" : "false")
        << " base-checksum=" << (update.base_checksum_valid ? "valid" : "mismatch") << '\n'
        << "Extension table: " << (update.extension_table_present ? "present" : "absent");
    if (update.extension_table_present)
        out << " checksum=" << (update.extension_table_checksum_valid ? "valid" : "mismatch")
            << " reserved-zero=" << (update.extension_reserved_fields_zero ? "true" : "false")
            << " signatures=" << update.extended_signatures.size();
    out << '\n';
    constexpr std::size_t max_rows = 4096;
    const auto shown = std::min(update.extended_signatures.size(), max_rows);
    for (std::size_t index = 0; index < shown; ++index) {
        const auto &signature = update.extended_signatures[index];
        out << "  signature=" << microcode_hex(signature.processor_signature)
            << " flags=" << microcode_hex(signature.processor_flags)
            << " checksum=" << (signature.checksum_valid ? "valid" : "mismatch")
            << " file=" << microcode_hex(signature.file_offset) << '\n';
    }
    if (shown < update.extended_signatures.size())
        out << "  signatures omitted=" << update.extended_signatures.size() - shown << " (limit " << max_rows << ")\n";
    out << "Encrypted update data is opaque; applicability and authenticity were not evaluated.\n";
    return 0;
}
} // namespace hexlab::cli
