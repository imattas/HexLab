#include "commands.hpp"
#include "argument_text.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/loaders/elf_debug_companions.hpp"
#include <sstream>

namespace hexlab::cli {
namespace {
std::string path_text(const std::filesystem::path &path) {
    const auto value = path.u8string();
    std::string result(reinterpret_cast<const char *>(value.data()), value.size());
    (void)utf8_to_wide(result); // Reject native names that cannot be emitted as UTF-8.
    return result;
}
std::string quote(std::string_view text) {
    (void)utf8_to_wide(text);
    constexpr char digits[] = "0123456789abcdef";
    std::string result = "\"";
    for (const unsigned char value : text) {
        if (value == '"' || value == '\\') { result.push_back('\\'); result.push_back(char(value)); }
        else if (value < 0x20) {
            result += "\\u00"; result.push_back(digits[value >> 4]); result.push_back(digits[value & 15]);
        } else result.push_back(char(value));
    }
    result.push_back('"');
    return result;
}
const char *source_name(ElfDebugCompanionSource source) {
    switch (source) {
    case ElfDebugCompanionSource::explicit_path: return "explicit";
    case ElfDebugCompanionSource::adjacent: return "adjacent";
    case ElfDebugCompanionSource::adjacent_debug_directory: return "adjacent-.debug";
    case ElfDebugCompanionSource::debug_directory: return "debug-directory";
    case ElfDebugCompanionSource::build_id_directory: return "build-id-directory";
    }
    return "unknown";
}
const char *status_name(ElfDebugCompanionStatus state) {
    switch (state) {
    case ElfDebugCompanionStatus::missing: return "missing";
    case ElfDebugCompanionStatus::not_regular: return "not-regular";
    case ElfDebugCompanionStatus::outside_directory: return "outside-directory";
    case ElfDebugCompanionStatus::same_as_primary: return "same-as-primary";
    case ElfDebugCompanionStatus::io_error: return "io-error";
    case ElfDebugCompanionStatus::too_large: return "too-large";
    case ElfDebugCompanionStatus::invalid_elf: return "invalid-elf";
    case ElfDebugCompanionStatus::incompatible_elf: return "incompatible-elf";
    case ElfDebugCompanionStatus::no_debug_metadata: return "no-debug-metadata";
    case ElfDebugCompanionStatus::missing_build_id: return "missing-build-id";
    case ElfDebugCompanionStatus::build_id_mismatch: return "build-id-mismatch";
    case ElfDebugCompanionStatus::checksum_mismatch: return "checksum-mismatch";
    case ElfDebugCompanionStatus::changed_during_read: return "changed-during-read";
    case ElfDebugCompanionStatus::matched: return "matched";
    }
    return "unknown";
}
std::string bytes_hex(std::span<const std::byte> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : bytes) {
        const auto value = std::to_integer<unsigned>(byte);
        result.push_back(digits[value >> 4]); result.push_back(digits[value & 15]);
    }
    return result;
}
void usage(std::ostream &out) {
    out << "Usage: hexlab_cli elf debug-companions <primary> [--candidate <file> ...]\n"
           "       [--debug-dir <directory> ...] [--sysroot <root>] [--json]\n"
           "Checks adjacent GNU debuglink files and explicit roots with mirrored/debug-ID paths.\n"
           "Exit 0 selects one local identity match; exit 3 means missing, ambiguous, or incomplete.\n";
}
} // namespace

int run_elf_debug_companion_cli(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.empty() || (args.size() == 1 && args[0] == L"--help") ||
        (args.size() == 2 && args[0] == L"debug-companions" && args[1] == L"--help")) {
        usage(out); return 0;
    }
    if (args.size() < 2 || args[0] != L"debug-companions") { usage(err); return 2; }
    try {
        const auto input = path_from_wide(args[1]);
        ElfDebugCompanionSearch search;
        bool json = false;
        for (std::size_t at = 2; at < args.size(); ++at) {
            if (args[at] == L"--json") {
                if (json) { err << "Duplicate --json option\n"; return 2; }
                json = true; continue;
            }
            const auto option = args[at];
            if (option != L"--candidate" && option != L"--debug-dir" && option != L"--sysroot") {
                err << "Unknown ELF debug-companion option\n"; return 2;
            }
            if (++at == args.size() || args[at].starts_with(L"--")) {
                err << "ELF debug-companion option requires a path\n"; return 2;
            }
            const auto path = path_from_wide(args[at]);
            if (option == L"--candidate") search.candidates.push_back(path);
            else if (option == L"--debug-dir") search.debug_directories.push_back(path);
            else {
                if (search.sysroot) { err << "Duplicate --sysroot option\n"; return 2; }
                search.sysroot = path;
            }
            if (search.candidates.size() > search.max_candidates || search.debug_directories.size() > search.max_directories) {
                err << "ELF debug-companion option count exceeds its limit\n"; return 2;
            }
        }
        const auto storage = FileStorage::open(input);
        if (!storage) { err << storage.error().message << '\n'; return 2; }
        const auto loaded = load_elf(storage.value(), {});
        if (!loaded) { err << loaded.error().message << '\n'; return 2; }
        if (!loaded.value().metadata.elf) { err << "Input has no ELF metadata\n"; return 2; }
        const auto found = discover_elf_debug_companions(*loaded.value().metadata.elf, input, search);
        if (!found) { err << found.error().message << '\n'; return 2; }
        const auto &report = found.value();
        std::ostringstream rendered;
        if (json) {
            rendered << "{\"schema\":\"hexlab.elf.debug-companions.v1\",\"primary\":" << quote(path_text(input))
                     << ",\"complete\":" << (report.complete ? "true" : "false") << ",\"selected\":";
            if (report.selected) rendered << *report.selected; else rendered << "null";
            rendered << ",\"inspected_file_bytes\":" << report.inspected_file_bytes << ",\"candidates\":[";
            for (std::size_t index = 0; index < report.candidates.size(); ++index) {
                if (index) rendered << ',';
                const auto &row = report.candidates[index];
                rendered << "{\"path\":" << quote(path_text(row.path)) << ",\"canonical_path\":";
                if (row.canonical_path) rendered << quote(path_text(*row.canonical_path)); else rendered << "null";
                rendered << ",\"source\":" << quote(source_name(row.source)) << ",\"status\":" << quote(status_name(row.status))
                         << ",\"file_size\":";
                if (row.file_size) rendered << *row.file_size; else rendered << "null";
                rendered << ",\"sha256\":";
                if (row.content_sha256) rendered << quote(digest_hex(*row.content_sha256)); else rendered << "null";
                rendered << ",\"build_id\":" << quote(bytes_hex(row.build_id))
                         << ",\"has_debug_info_sections\":" << (row.has_debug_info_sections ? "true" : "false")
                         << ",\"has_source_line_sections\":" << (row.has_source_line_sections ? "true" : "false")
                         << ",\"has_static_symbol_tables\":" << (row.has_static_symbol_tables ? "true" : "false")
                         << ",\"diagnostic\":" << quote(row.diagnostic) << '}';
            }
            rendered << "],\"diagnostics\":[";
            for (std::size_t i = 0; i < report.diagnostics.size(); ++i) {
                if (i) rendered << ',';
                rendered << quote(report.diagnostics[i]);
            }
            rendered << "]}\n";
        } else {
            rendered << "ELF local debug companions: complete=" << (report.complete ? "yes" : "no")
                     << " candidates=" << report.candidates.size() << " inspected-file-bytes=" << report.inspected_file_bytes << '\n';
            if (report.selected) rendered << "Selected [" << *report.selected << "] "
                << quote(path_text(*report.candidates[*report.selected].canonical_path)) << '\n';
            else rendered << "Selected: unavailable\n";
            for (std::size_t index = 0; index < report.candidates.size(); ++index) {
                const auto &row = report.candidates[index];
                rendered << "  [" << index << "] " << status_name(row.status) << " (" << source_name(row.source) << ") "
                         << quote(path_text(row.path));
                if (row.content_sha256) rendered << " sha256=" << digest_hex(*row.content_sha256);
                if (row.has_debug_info_sections) rendered << " info-sections";
                if (row.has_source_line_sections) rendered << " line-sections";
                if (row.has_static_symbol_tables) rendered << " static-symbol-table";
                rendered << '\n';
                if (!row.diagnostic.empty()) rendered << "      " << quote(row.diagnostic) << '\n';
            }
            for (const auto &message : report.diagnostics) rendered << "  " << quote(message) << '\n';
        }
        out << rendered.str();
        return report.selected ? 0 : 3;
    } catch (const std::exception &error) { err << "ELF debug-companion command: " << error.what() << '\n'; return 2; }
}
} // namespace hexlab::cli
