#include "commands.hpp"
#include "argument_text.hpp"
#include "hexlab/compare/compare.hpp"
#include "project_commands.hpp"
#include "project_arguments.hpp"
#include "profile_output.hpp"
#include "elf_output.hpp"
#include "macho_output.hpp"
#include "pe_output.hpp"
#include "jvm_output.hpp"
#include "wasm_output.hpp"
#include "dex_output.hpp"
#include "minidump_output.hpp"
#include "module_symbol_resolution.hpp"
#include "demangle_output.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "hexlab/core/version.hpp"
#include "hexlab/workspace/workspace.hpp"
#include "hexlab/workspace/project_actor.hpp"
#include "hexlab/database/project_state.hpp"
#include "hexlab/loaders/ar.hpp"
#include "hexlab/loaders/jar.hpp"
#include "hexlab/loaders/firmware.hpp"
#include "hexlab/loaders/elf.hpp"
#include "hexlab/loaders/elf_link.hpp"
#include "hexlab/loaders/coff_link.hpp"
#include "hexlab/loaders/macho_link.hpp"
#include "hexlab/loaders/loader.hpp"
#include "hexlab/processors/format.hpp"
#include "hexlab/plugins/runtime.hpp"
#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/decompiler/optimizer.hpp"
#include "hexlab/decompiler/type_recovery.hpp"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <system_error>
#include <cerrno>
#include <utility>
#ifdef _WIN32
#include <Windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace hexlab::cli {
namespace {
struct ArgumentError {
    std::string message;
};
[[noreturn]] void argument_error(std::string message) { throw ArgumentError{std::move(message)}; }
std::string hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}
decompiler::AbiDescription cli_decompiler_abi(const Image &image, const ImageMetadata &metadata) {
    switch (image.layout().architecture) {
    case Architecture::x86:
        if (image.layout().mode == ExecutionMode::x86_32) return decompiler::x86_32_cdecl_abi();
        return {};
    case Architecture::x86_64:
        return metadata.pe ? decompiler::x86_64_windows_abi() : decompiler::x86_64_system_v_abi();
    case Architecture::arm:
        return decompiler::arm32_aapcs_abi();
    case Architecture::arm64:
        return decompiler::aarch64_abi();
    case Architecture::riscv32:
        return decompiler::riscv32_ilp32_abi();
    case Architecture::riscv64:
        return decompiler::riscv64_lp64_abi();
    case Architecture::mips32:
        return decompiler::mips32_o32_abi();
    case Architecture::mips64:
        return image.layout().space.width_bits == 32 ? decompiler::mips_n32_abi()
                                                       : decompiler::mips64_n64_abi();
    case Architecture::powerpc:
        if (image.layout().mode == ExecutionMode::ppc64 && metadata.elf &&
            metadata.elf->header.is_64 && metadata.elf->header.machine == 21 &&
            metadata.elf->header.order == ByteOrder::little &&
            (metadata.elf->header.flags & 3u) == 2u)
            return decompiler::ppc64le_elfv2_abi();
        return {};
    default:
        return {};
    }
}
std::string safe_text(std::string_view text) {
    std::ostringstream out;
    for (const unsigned char ch : text) {
        if (ch >= 32 && ch < 127)
            out << static_cast<char>(ch);
        else
            out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(ch);
    }
    return out.str();
}
std::string path_text(const std::filesystem::path &path) {
    const auto utf8 = path.u8string();
    return {reinterpret_cast<const char *>(utf8.data()), utf8.size()};
}
std::string json_quote(std::string_view value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() + 2);
    result.push_back('"');
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 0x20) {
                result += "\\u00";
                result.push_back(digits[ch >> 4]);
                result.push_back(digits[ch & 0x0f]);
            } else result.push_back(static_cast<char>(ch));
        }
    }
    result.push_back('"');
    return result;
}
std::filesystem::path reserve_temporary_file() {
    const auto directory = std::filesystem::temp_directory_path();
#ifdef _WIN32
    wchar_t name[MAX_PATH]{};
    if (!GetTempFileNameW(directory.c_str(), L"hxar", 0, name))
        throw std::runtime_error("Cannot reserve a temporary file for the selected archive member");
    return std::filesystem::path(name);
#else
    auto pattern = (directory / "hexlab-ar-member-XXXXXX").string();
    std::vector<char> name(pattern.begin(), pattern.end());
    name.push_back('\0');
    const int descriptor = mkstemp(name.data());
    if (descriptor < 0)
        throw std::runtime_error("Cannot reserve a temporary file for the selected archive member");
    if (close(descriptor) != 0) {
        std::error_code ignored;
        std::filesystem::remove(std::filesystem::path(name.data()), ignored);
        throw std::runtime_error("Cannot close the reserved temporary file");
    }
    return std::filesystem::path(name.data());
#endif
}
void write_archive_output(const std::filesystem::path &path, std::span<const std::byte> bytes, bool replace) {
#ifdef _WIN32
    const auto handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                    replace ? CREATE_ALWAYS : CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const auto code = GetLastError();
        if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS)
            throw std::runtime_error("Output file already exists (use --replace to overwrite it)");
        throw std::runtime_error("Cannot create archive member output file (Windows error " + std::to_string(code) + ")");
    }
    bool success = true;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto count = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, MAXDWORD));
        DWORD written = 0;
        if (!WriteFile(handle, bytes.data() + offset, count, &written, nullptr) || written != count) {
            success = false;
            break;
        }
        offset += written;
    }
    if (!CloseHandle(handle)) success = false;
    if (!success) throw std::runtime_error("Cannot finish writing archive member output file");
#else
    const int flags = O_WRONLY | O_CREAT | (replace ? O_TRUNC : O_EXCL);
    const int descriptor = ::open(path.c_str(), flags, 0666);
    if (descriptor < 0) {
        if (!replace && errno == EEXIST)
            throw std::runtime_error("Output file already exists (use --replace to overwrite it)");
        throw std::runtime_error("Cannot create archive member output file");
    }
    bool success = true;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const auto written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { success = false; break; }
        offset += static_cast<std::size_t>(written);
    }
    if (::close(descriptor) != 0) success = false;
    if (!success) throw std::runtime_error("Cannot finish writing archive member output file");
#endif
}
void usage(std::ostream &out) {
    out << "Usage: hexlab_cli [--help | --version]\n"
           "       hexlab_cli inspect <path> [options]\n"
           "       hexlab_cli disassemble <path> [options]\n\n"
           "       hexlab_cli decompile <path> [options]\n\n"
           "       hexlab_cli compare <old-image> <new-image> [--window <bytes>] [--anchor <bytes>] [--limit <runs>] [--functions]\n\n"
           "       hexlab_cli modules [--graph] <binary>...  (graph mode traverses dependencies from the first file)\n\n"
           "       hexlab_cli project --help  (persistent projects and editing)\n\n"
           "       hexlab_cli plugins scan <directory> [--json]  (data-only native plugin discovery)\n\n"
           "       hexlab_cli archive list <archive>\n"
           "       hexlab_cli archive link-select <archive> --root-object <ET_REL>\n"
           "       hexlab_cli archive link-exec <archive> --root-object <ET_REL> --entry <symbol> --output <ET_EXEC>\n"
           "       hexlab_cli archive link-pe <archive> --root-object <COFF .obj> --entry <symbol> --output <PE .exe>\n"
           "       hexlab_cli archive link-macho <archive> --root-object <Mach-O .o> --entry <symbol> --output <Mach-O executable>\n"
           "       hexlab_cli archive extract <archive> --member <index> --output <path> [--replace]\n"
           "       hexlab_cli archive open <archive> --member <index> --project <project.hxproj> [--replace]\n\n"
           "       hexlab_cli jar list <package.jar>\n"
           "       hexlab_cli jar inspect <package.jar> --member <index>\n\n"
           "       hexlab_cli firmware inspect <path> --format ihex|srec|uefi\n\n"
           "Input options:\n  --format auto|pe|elf|raw|macho|wasm|dex|jvm\n"
           "  --pe-runtime arm64|x64-compatible  (select an ARM64X PE process view)\n"
           "  --slice <index>  (Mach-O universal slice; zero-based, auto or macho format)\n"
           "  --arch x86-32|x86-64|a64|6502|rv32|rv64|mips64|ppc32le|ppc32be|ppc64le|ppc64be --base <address> [--entry <address>]  (raw only)\n"
           "  --profile <file>  (segmented raw x86-16/32; replaces arch/base/entry)\n"
           "  --arm-profile <file>  (raw ARM/Thumb/data declarations; replaces arch/base/entry)\n"
           "  --plugin <module>  (load a native plugin for detection and display decoding; repeatable)\n"
           "  --pdb <file> --pdb-search <directory>  (local PE PDB binding; no network lookup)\n"
           "  --dwarf-supplementary-package <file>  (explicit ELF DWARF v5 supplementary DWP; no filename lookup)\n"
           "Analysis options:\n  --instruction-budget <count> --string-budget <count>\n"
           "  --min-string-length <count>\n"
           "Addresses use decimal or 0x-prefixed hexadecimal. Use -- before an option-like path.\n";
}

int modules_command(std::span<const std::wstring_view> arguments, std::ostream &out, std::ostream &err) {
    const bool graph_mode = !arguments.empty() && arguments.front() == L"--graph";
    const auto inputs = graph_mode ? arguments.subspan(1) : arguments;
    if ((graph_mode && inputs.empty()) || (!graph_mode && inputs.size() < 2)) {
        err << "Usage: hexlab_cli modules [--graph] <binary>...\n"
               "       In graph mode the first binary is the root; later files are supplied candidates.\n";
        return 2;
    }
    constexpr std::size_t max_graph_modules = 4096;
    constexpr std::size_t max_graph_edges = 100000;
    constexpr std::size_t max_graph_depth = 64;
    constexpr std::size_t max_graph_name_bytes = 16 * 1024 * 1024;
    if (graph_mode && inputs.size() > max_graph_modules) {
        err << "Dependency graph accepts at most " << max_graph_modules << " supplied files.\n";
        return 2;
    }
    struct Module { std::filesystem::path path; std::shared_ptr<const DocumentSnapshot> document; };
    std::vector<Module> modules;
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        OpenRequest request;
        request.path = std::filesystem::path(inputs[i]);
        request.run_analysis = false;
        auto loaded = load_document(request, {{i}, 1}, {});
        if (!loaded) { err << path_text(request.path) << ": " << loaded.error().message << '\n'; return 1; }
        modules.push_back({request.path, loaded.value()});
    }
    auto leaf = [](std::string value) {
        const auto slash = value.find_last_of("/\\");
        if (slash != std::string::npos) value.erase(0, slash + 1);
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return value;
    };
    auto path_key = [](const std::filesystem::path &path) {
        auto value = path.lexically_normal().generic_string();
#ifdef _WIN32
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
#endif
        return value;
    };
    auto dependencies_for = [](const ImageMetadata &metadata, std::size_t row_limit, std::size_t byte_limit,
                               bool include_macho_id)
        -> std::optional<std::vector<std::string>> {
        std::vector<std::string> deps;
        std::size_t bytes = 0;
        bool exceeded = false;
        auto add = [&](const std::string &name) {
            if (name.empty()) return;
            if (deps.size() >= row_limit || name.size() > byte_limit - bytes) {
                exceeded = true;
                return;
            }
            bytes += name.size();
            deps.push_back(name);
        };
        for (const auto &imp : metadata.imports)
            add(imp.library);
        if (metadata.elf)
            for (const auto &table : metadata.elf->dynamic_tables)
                for (const auto &entry : table.entries)
                    if (entry.tag == 1 && entry.string_value) add(*entry.string_value);
        if (metadata.macho)
            for (const auto &library : metadata.macho->libraries)
                if (include_macho_id || library.ordinal) add(library.name);
        if (exceeded) return std::nullopt;
        return deps;
    };
    auto sort_dependencies = [&leaf](std::vector<std::string> &deps) {
        std::sort(deps.begin(), deps.end(), [&leaf](const auto &a, const auto &b) {
            const auto left = leaf(a), right = leaf(b);
            return left == right ? a < b : left < right;
        });
        deps.erase(std::unique(deps.begin(), deps.end()), deps.end());
    };
    if (!graph_mode) {
        for (const auto &module : modules) {
            auto deps_result = dependencies_for(module.document->metadata,
                (std::numeric_limits<std::size_t>::max)(),
                (std::numeric_limits<std::size_t>::max)(), true);
            auto deps = std::move(*deps_result);
            sort_dependencies(deps);
            out << path_text(module.path) << "\n";
            if (deps.empty()) { out << "  (no dependency names in parsed metadata)\n"; continue; }
            for (const auto &dep : deps) {
                std::vector<std::string> providers;
                for (const auto &candidate : modules)
                    if (&candidate != &module && leaf(path_text(candidate.path)) == leaf(dep))
                        providers.push_back(path_text(candidate.path));
                out << "  " << dep << " -> ";
                if (providers.empty()) out << "unresolved (not supplied)";
                else if (providers.size() == 1) out << "resolved: " << providers.front();
                else { out << "ambiguous:"; for (const auto &p : providers) out << " " << p; }
                out << '\n';
            }
        }
    } else {
        struct Edge {
            std::string name;
            const std::vector<std::size_t> *providers = nullptr;
        };
        std::vector<std::vector<Edge>> graph(modules.size());
        std::size_t edge_count = 0;
        std::size_t raw_dependency_rows = 0;
        std::size_t dependency_name_bytes = 0;
        std::map<std::string, std::vector<std::size_t>> providers_by_basename;
        std::map<std::string, std::set<std::string>> provider_paths_by_basename;
        for (std::size_t candidate = 0; candidate < modules.size(); ++candidate) {
            const auto basename = leaf(path_text(modules[candidate].path));
            const auto normalized_path = path_key(modules[candidate].path);
            if (provider_paths_by_basename[basename].insert(normalized_path).second)
                providers_by_basename[basename].push_back(candidate);
        }
        for (std::size_t source = 0; source < modules.size(); ++source) {
            auto deps_result = dependencies_for(modules[source].document->metadata,
                max_graph_edges - raw_dependency_rows, max_graph_name_bytes - dependency_name_bytes, false);
            if (!deps_result) {
                err << "Dependency graph exceeds " << max_graph_edges << " dependency rows or "
                    << max_graph_name_bytes << " dependency-name bytes.\n";
                return 2;
            }
            auto deps = std::move(*deps_result);
            raw_dependency_rows += deps.size();
            for (const auto &dep : deps) dependency_name_bytes += dep.size();
            sort_dependencies(deps);
            if (deps.size() > max_graph_edges - edge_count) {
                err << "Dependency graph exceeds " << max_graph_edges << " unique dependency rows.\n";
                return 2;
            }
            edge_count += deps.size();
            graph[source].reserve(deps.size());
            for (auto &dep : deps) {
                Edge edge{std::move(dep), {}};
                const auto providers = providers_by_basename.find(leaf(edge.name));
                if (providers != providers_by_basename.end()) edge.providers = &providers->second;
                graph[source].push_back(std::move(edge));
            }
        }

        out << "Recursive dependency graph (only supplied files; maximum depth " << max_graph_depth << ")\n";
        out << "Supplied node identities (input order):\n";
        std::map<std::string, std::size_t> first_path;
        std::map<std::string, std::size_t> first_basename;
        for (std::size_t index = 0; index < modules.size(); ++index) {
            const auto key = path_key(modules[index].path);
            const auto basename = leaf(path_text(modules[index].path));
            out << "  [" << index << "] " << path_text(modules[index].path);
            if (const auto same_path = first_path.find(key); same_path != first_path.end())
                out << " (duplicate supplied path of [" << same_path->second << "])";
            else if (const auto same_basename = first_basename.find(basename);
                     same_basename != first_basename.end())
                out << " (duplicate basename of [" << same_basename->second << "])";
            out << '\n';
            first_path.try_emplace(key, index);
            first_basename.try_emplace(basename, index);
        }
        out << "Root: [0] " << path_text(modules.front().path) << "\n";
        std::vector<std::uint8_t> color(modules.size(), 0);
        std::size_t expanded = 0;
        std::size_t provider_ids_reported = 0;
        constexpr std::size_t max_reported_provider_ids = 100000;
        bool depth_limited = false;
        std::function<void(std::size_t, std::size_t)> visit = [&](std::size_t current, std::size_t depth) {
            color[current] = 1;
            ++expanded;
            if (graph[current].empty())
                out << std::string((depth + 1) * 2, ' ') << "(no dependency names in parsed metadata)\n";
            for (const auto &edge : graph[current]) {
                out << std::string((depth + 1) * 2, ' ') << edge.name << " -> ";
                if (!edge.providers || edge.providers->empty()) {
                    out << "unresolved (not supplied)\n";
                    continue;
                }
                if (edge.providers->size() != 1) {
                    out << "ambiguous:";
                    const auto remaining = max_reported_provider_ids - provider_ids_reported;
                    const auto count = (std::min)(edge.providers->size(), remaining);
                    for (std::size_t index = 0; index < count; ++index)
                        out << " [" << (*edge.providers)[index] << "]";
                    provider_ids_reported += count;
                    if (count < edge.providers->size())
                        out << " ... " << edge.providers->size() - count << " provider IDs omitted";
                    out << '\n';
                    continue;
                }
                const auto provider = edge.providers->front();
                out << "[" << provider << "] " << path_text(modules[provider].path);
                if (color[provider] == 1) {
                    out << " (cycle)\n";
                    continue;
                }
                if (color[provider] == 2) {
                    out << " (already expanded)\n";
                    continue;
                }
                if (depth + 1 >= max_graph_depth) {
                    out << " (depth limit reached)\n";
                    depth_limited = true;
                    continue;
                }
                out << '\n';
                visit(provider, depth + 1);
            }
            color[current] = 2;
        };
        visit(0, 0);
        out << "Expanded " << expanded << " of " << modules.size() << " supplied modules; "
            << edge_count << " dependency rows.\n";
        if (expanded < modules.size()) {
            out << "Some supplied modules were not expanded because they are unreachable from the root";
            if (depth_limited) out << " or beyond the depth limit";
            out << ".\n";
        }
    }
    std::vector<SuppliedModule> supplied;
    supplied.reserve(modules.size());
    for (const auto &module : modules)
        supplied.push_back({path_text(module.path), &module.document->metadata});
    print_pe_import_resolutions(supplied, out);
    print_elf_import_resolutions(supplied, out);
    print_macho_import_resolutions(supplied, out);
    return 0;
}
int plugin_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.size() == 1 && args[0] == L"--help") {
        out << "Usage: hexlab_cli plugins scan <directory> [--json]\n"
               "       hexlab_cli plugins dependencies <directory> [--json]\n"
               "Scans direct native plugin candidates and bounded .hexlab-plugin sidecars without loading modules.\n"
               "dependencies also reports advisory host/candidate/missing/ambiguous requirement providers.\n";
        return 0;
    }
    const bool dependency_report = !args.empty() && args[0] == L"dependencies";
    if (args.size() < 2 || (args[0] != L"scan" && !dependency_report) || args.size() > 3 ||
        (args.size() == 3 && args[2] != L"--json")) {
        err << "Usage: hexlab_cli plugins scan|dependencies <directory> [--json]\n";
        return 2;
    }
    try {
        const auto directory = path_from_wide(args[1]);
        plugins::PluginManager manager(plugins::make_native_module_provider());
        auto scanned = manager.scan_directory(path_text(directory), 4096);
        if (!scanned) {
            err << "Plugin scan: " << scanned.error().message << '\n';
            return 1;
        }
        const bool json = args.size() == 3;
        if (dependency_report) {
            struct RequirementRow {
                plugins::PluginInfo::VersionedCapability capability;
                std::string resolution;
                std::vector<std::pair<std::string, std::string>> providers;
            };
            struct CandidateRow {
                const plugins::PluginCandidate *candidate = nullptr;
                std::vector<RequirementRow> requirements;
            };
            std::vector<CandidateRow> report;
            report.reserve(scanned.value().size());
            for (const auto &candidate : scanned.value()) {
                CandidateRow row{&candidate, {}};
                if (candidate.manifest) {
                    const auto &manifest = *candidate.manifest;
                    row.requirements.reserve(manifest.required_capabilities.size());
                    for (const auto &required : manifest.required_capabilities) {
                        RequirementRow item{required, "unavailable", {}};
                        const auto host = std::find_if(candidate.requirement_preflight.begin(),
                            candidate.requirement_preflight.end(), [&](const auto &preflight) {
                                return preflight.capability.id == required.id &&
                                       preflight.capability.major_version == required.major_version &&
                                       preflight.capability.minor_version == required.minor_version &&
                                       preflight.resolution == plugins::PluginRequirementResolution::host;
                            });
                        if (host != candidate.requirement_preflight.end()) {
                            item.resolution = "host";
                        } else {
                            for (const auto &provider : scanned.value()) {
                                if (!provider.manifest || provider.path == candidate.path) continue;
                                const auto &provider_manifest = *provider.manifest;
                                const auto capability = std::find_if(provider_manifest.capabilities.begin(),
                                    provider_manifest.capabilities.end(), [&](const auto &declared) {
                                        return declared.id == required.id &&
                                               declared.major_version == required.major_version &&
                                               declared.minor_version >= required.minor_version;
                                    });
                                if (capability != provider_manifest.capabilities.end())
                                    item.providers.emplace_back(provider_manifest.id, provider.path);
                            }
                            if (item.providers.size() == 1) item.resolution = "candidate";
                            else if (item.providers.size() > 1) item.resolution = "ambiguous";
                        }
                        row.requirements.push_back(std::move(item));
                    }
                }
                report.push_back(std::move(row));
            }
            if (json) {
                out << "{\"directory\":" << json_quote(path_text(directory))
                    << ",\"loaded\":false,\"advisory\":true,\"count\":" << report.size()
                    << ",\"candidates\":[";
                for (std::size_t i = 0; i < report.size(); ++i) {
                    const auto &row = report[i];
                    if (i) out << ',';
                    out << "{\"path\":" << json_quote(row.candidate->path) << ",\"manifest\":";
                    if (row.candidate->manifest) out << json_quote(row.candidate->manifest->id);
                    else out << "null";
                    out << ",\"manifest_error\":" << json_quote(row.candidate->manifest_error)
                        << ",\"requirements\":[";
                    for (std::size_t r = 0; r < row.requirements.size(); ++r) {
                        const auto &requirement = row.requirements[r];
                        if (r) out << ',';
                        out << "{\"id\":" << json_quote(requirement.capability.id)
                            << ",\"major\":" << requirement.capability.major_version
                            << ",\"minimum_minor\":" << requirement.capability.minor_version
                            << ",\"resolution\":" << json_quote(requirement.resolution)
                            << ",\"providers\":[";
                        for (std::size_t p = 0; p < requirement.providers.size(); ++p) {
                            if (p) out << ',';
                            out << "{\"id\":" << json_quote(requirement.providers[p].first)
                                << ",\"path\":" << json_quote(requirement.providers[p].second) << '}';
                        }
                        out << "]}";
                    }
                    out << "]}";
                }
                out << "]}\n";
                return 0;
            }
            out << "Dependency preflight for " << path_text(directory) << " (advisory; no modules loaded)\n";
            for (const auto &row : report) {
                out << row.candidate->path;
                if (!row.candidate->manifest) {
                    out << (row.candidate->manifest_error.empty() ? "\n  no manifest; requirements unknown\n"
                                                                  : "\n  invalid manifest: " + safe_text(row.candidate->manifest_error) + "\n");
                    continue;
                }
                out << "\n  " << row.candidate->manifest->id;
                if (row.requirements.empty()) out << "\n  no declared requirements";
                for (const auto &requirement : row.requirements) {
                    const auto &capability = requirement.capability;
                    out << "\n  " << capability.id << '@' << capability.major_version << '.'
                        << capability.minor_version << ": " << requirement.resolution;
                    for (const auto &[provider, path] : requirement.providers)
                        out << " " << provider << " (" << path << ')';
                }
                out << '\n';
            }
            return 0;
        }
        if (json) {
            out << "{\"directory\":" << json_quote(path_text(directory))
                << ",\"loaded\":false,\"count\":" << scanned.value().size() << ",\"candidates\":[";
            for (std::size_t i = 0; i < scanned.value().size(); ++i) {
                const auto &candidate = scanned.value()[i];
                if (i) out << ',';
                out << "{\"path\":" << json_quote(candidate.path) << ",\"manifest\":";
                if (!candidate.manifest) out << "null";
                else {
                    const auto &manifest = *candidate.manifest;
                    auto capabilities = [&](const auto &items) {
                        out << '[';
                        for (std::size_t n = 0; n < items.size(); ++n) {
                            if (n) out << ',';
                            const auto &item = items[n];
                            out << "{\"id\":" << json_quote(item.id)
                                << ",\"major\":" << item.major_version
                                << ",\"minor\":" << item.minor_version
                                << ",\"flags\":" << item.flags << '}';
                        }
                        out << ']';
                    };
                    out << "{\"id\":" << json_quote(manifest.id)
                        << ",\"name\":" << json_quote(manifest.name)
                        << ",\"version\":" << json_quote(manifest.version)
                        << ",\"capabilities\":";
                    capabilities(manifest.capabilities);
                    out << ",\"required_capabilities\":";
                    capabilities(manifest.required_capabilities);
                    out << '}';
                }
                out << ",\"manifest_error\":" << json_quote(candidate.manifest_error) << '}';
            }
            out << "]}\n";
            return 0;
        }
        out << "Scanned " << scanned.value().size() << " candidate(s) in " << path_text(directory)
            << ". No plugin modules were loaded.\n";
        for (const auto &candidate : scanned.value()) {
            out << candidate.path;
            if (candidate.manifest) {
                const auto &manifest = *candidate.manifest;
                out << "\n  " << manifest.id << " | " << manifest.name << " | " << manifest.version;
                if (!manifest.capabilities.empty()) {
                    out << "\n  capabilities:";
                    for (const auto &capability : manifest.capabilities)
                        out << ' ' << capability.id << '@' << capability.major_version << '.' << capability.minor_version;
                }
                if (!manifest.required_capabilities.empty()) {
                    out << "\n  requires:";
                    for (const auto &capability : manifest.required_capabilities)
                        out << ' ' << capability.id << '@' << capability.major_version << '.' << capability.minor_version;
                }
            } else if (!candidate.manifest_error.empty())
                out << "\n  Invalid manifest: " << safe_text(candidate.manifest_error);
            else out << "\n  No manifest";
            out << '\n';
        }
        return 0;
    } catch (const std::exception &error) {
        err << "Plugin scan: " << error.what() << '\n';
        return 1;
    }
}
int firmware_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.size() == 2 && args[1] == L"--help") {
        out << "Usage: hexlab_cli firmware inspect <path> --format ihex|srec|uefi\n";
        return 0;
    }
    if (args.size() == 4 && args[0] == L"inspect" && args[2] == L"--format" && args[3] == L"uefi")
        return run_uefi_firmware_cli(args, out, err);
    try {
        if (args.size() != 4 || args[0] != L"inspect" || args[2] != L"--format")
            argument_error("firmware inspect requires a path and --format ihex|srec");
        firmware::Format format;
        if (args[3] == L"ihex") format = firmware::Format::intel_hex;
        else if (args[3] == L"srec") format = firmware::Format::motorola_s_record;
        else argument_error("Firmware format must be ihex or srec");
        auto opened = FileStorage::open(path_from_wide(args[1]));
        if (!opened) throw std::runtime_error(opened.error().message);
        auto file = opened.value();
        if (file->size() > (std::numeric_limits<std::size_t>::max)())
            throw std::runtime_error("Firmware file exceeds addressable memory");
        auto read = file->read_at({0}, static_cast<std::size_t>(file->size()));
        if (!read) throw std::runtime_error(read.error().message);
        auto view = std::move(read.value());
        std::string_view text(reinterpret_cast<const char *>(view.bytes.data()), view.bytes.size());
        auto parsed_image = load_firmware(text, FirmwareLoadOptions{format});
        if (!parsed_image) throw std::runtime_error(parsed_image.error().message);
        auto loaded = std::move(parsed_image.value());
        const auto &data = *loaded.metadata.firmware;
        out << "Format: " << loaded.metadata.format << '\n'
            << "Data bytes: " << loaded.metadata.image_size << '\n'
            << "Records: " << data.records.size() << '\n';
        if (data.has_start_address) out << "Start address: " << hex(data.start_address) << '\n';
        out << "Segments:\n";
        for (const auto &record : data.records)
            out << "  " << hex(record.address.offset) << " Size=" << hex(record.size)
                << " SourceLine=" << record.source_line << " Record=" << record.record_index
                << " Backing=" << hex(record.packed_file_offset.value) << '\n';
        for (const auto &diagnostic : loaded.diagnostics)
            out << "warning: " << safe_text(diagnostic.message) << '\n';
        return 0;
    } catch (const ArgumentError &error) { err << error.message << '\n'; return 2; }
      catch (const project_detail::Failure &error) { err << "Firmware: " << error.error.message << '\n'; return 1; }
      catch (const std::exception &error) { err << "Firmware: " << error.what() << '\n'; return 1; }
}
int archive_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    using project_detail::Failure;
    using project_detail::take;
    if (args.size() < 2 || (args.size() == 2 && args[1] == L"--help")) {
        out << "Usage: hexlab_cli archive list <archive>\n"
               "       hexlab_cli archive link-select <archive> --root-object <ET_REL>\n"
               "       hexlab_cli archive link-audit <archive> --root-object <ET_REL>\n"
               "       hexlab_cli archive link <archive> --root-object <ET_REL> --output <ET_REL>\n"
               "       hexlab_cli archive link-exec <archive> --root-object <ET_REL> --entry <symbol> --output <ET_EXEC>\n"
               "       hexlab_cli archive link-pe <archive> --root-object <COFF .obj> --entry <symbol> --output <PE .exe>\n"
               "       hexlab_cli archive link-macho <archive> --root-object <Mach-O .o> --entry <symbol> --output <Mach-O executable>\n"
               "       hexlab_cli archive extract <archive> --member <index> --output <path> [--replace]\n"
               "       hexlab_cli archive open <archive> --member <index> --project <project.hxproj> [--replace]\n";
        return 0;
    }
    try {
        const auto action = args[0];
        const auto archive_path = path_from_wide(args[1]);
        auto storage = take(FileStorage::open(archive_path));
        auto archive = take(read_ar_archive(*storage));
        if (action == L"link-pe") {
            if (args.size() != 8 || args[2] != L"--root-object" || args[4] != L"--entry" || args[6] != L"--output")
                argument_error("archive link-pe requires --root-object <COFF .obj> --entry <symbol> --output <PE .exe>");
            auto root_storage = take(FileStorage::open(path_from_wide(args[3])));
            const auto root = take(summarize_coff_ar_member(*root_storage, 0));
            const auto machine_from_prefix = [](std::span<const std::byte> bytes) -> std::uint16_t {
                if (bytes.size() < 2) return 0;
                const bool anonymous = bytes.size() >= 4 && bytes[0] == std::byte{0} && bytes[1] == std::byte{0} &&
                    bytes[2] == std::byte{0xff} && bytes[3] == std::byte{0xff};
                const auto offset = anonymous ? 6u : 0u;
                if (bytes.size() < offset + 2) return 0;
                return static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(bytes[offset]) |
                    (std::to_integer<std::uint16_t>(bytes[offset + 1]) << 8));
            };
            const auto root_prefix = take(root_storage->read_at({0}, static_cast<std::size_t>(std::min<std::uint64_t>(root_storage->size(), 8))));
            const auto root_machine = machine_from_prefix(root_prefix.bytes);
            if (root_machine != 0x8664 && root_machine != 0xaa64)
                throw std::runtime_error("COFF PE link root must use AMD64 or ARM64 machine architecture");
            std::vector<ArMemberSymbols> summaries;
            summaries.reserve(archive.members.size());
            for (std::size_t i = 0; i < archive.members.size(); ++i) {
                const auto &member = archive.members[i];
                if (member.kind != ArMemberKind::regular) continue;
                auto member_storage = take(open_ar_member(storage, member));
                if (member_storage->size() < 2) continue;
                const auto prefix_size = static_cast<std::size_t>(std::min<std::uint64_t>(member_storage->size(), 8));
                auto prefix = take(member_storage->read_at({0}, prefix_size));
                if (machine_from_prefix(prefix.bytes) == root_machine)
                    summaries.push_back(take(summarize_coff_ar_member(*member_storage, i)));
            }
            std::vector<std::string_view> roots, definitions;
            for (const auto &name : root.undefined) roots.emplace_back(name);
            for (const auto &name : root.definitions) definitions.emplace_back(name);
            const auto selected = take(select_ar_members_fixed_point(archive, summaries, roots, definitions));
            if (!selected.unresolved_symbols.empty())
                throw std::runtime_error("Unresolved strong COFF symbol " + selected.unresolved_symbols.front());
            std::vector<std::shared_ptr<const ByteStorage>> objects{root_storage};
            for (const auto &item : selected.members)
                objects.push_back(take(open_ar_member(storage, archive.members[item.member_index])));
            const auto linked = take(link_coff_executable(objects, wide_to_utf8(args[5])));
            write_archive_output(path_from_wide(args[7]), linked, false);
            out << "Linked PE32+ " << (root_machine == 0xaa64 ? "ARM64" : "AMD64") << ": objects=" << objects.size() << " bytes=" << linked.size()
                << " relocations-applied=true\n";
            return 0;
        }
        if (action == L"link-macho") {
            if (args.size() != 8 || args[2] != L"--root-object" || args[4] != L"--entry" || args[6] != L"--output")
                argument_error("archive link-macho requires --root-object <Mach-O .o> --entry <symbol> --output <executable>");
            auto root_storage = take(FileStorage::open(path_from_wide(args[3])));
            const auto root = take(summarize_macho_ar_member(*root_storage, 0));
            std::vector<ArMemberSymbols> summaries;
            summaries.reserve(archive.members.size());
            for (std::size_t i = 0; i < archive.members.size(); ++i) {
                const auto &member = archive.members[i];
                if (member.kind != ArMemberKind::regular) continue;
                auto member_storage = take(open_ar_member(storage, member));
                if (take(detect_format(*member_storage)) != DetectedFormat::macho_candidate) continue;
                summaries.push_back(take(summarize_macho_ar_member(*member_storage, i)));
            }
            std::vector<std::string_view> roots, definitions;
            for (const auto &name : root.undefined) roots.emplace_back(name);
            for (const auto &name : root.definitions) definitions.emplace_back(name);
            const auto selected = take(select_ar_members_fixed_point(archive, summaries, roots, definitions));
            if (!selected.unresolved_symbols.empty())
                throw std::runtime_error("Unresolved strong Mach-O symbol " + selected.unresolved_symbols.front());
            std::vector<std::shared_ptr<const ByteStorage>> objects{root_storage};
            for (const auto &item : selected.members)
                objects.push_back(take(open_ar_member(storage, archive.members[item.member_index])));
            const auto linked = take(link_macho64_executable(objects, wide_to_utf8(args[5])));
            write_archive_output(path_from_wide(args[7]), linked, false);
            out << "Linked static Mach-O: objects=" << objects.size() << " bytes=" << linked.size()
                << " relocations-applied=true\n";
            return 0;
        }
        if (action == L"link-select" || action == L"link-audit" || action == L"link" || action == L"link-exec") {
            const bool linking = action == L"link";
            const bool executable = action == L"link-exec";
            if ((!linking && !executable && (args.size() != 4 || args[2] != L"--root-object")) ||
                (linking && (args.size() != 6 || args[2] != L"--root-object" || args[4] != L"--output")))
                argument_error("archive link action requires --root-object <ET_REL> [--output <ET_REL>]");
            if (executable && (args.size() != 8 || args[2] != L"--root-object" || args[4] != L"--entry" ||
                               args[6] != L"--output"))
                argument_error("archive link-exec requires --root-object <ET_REL> --entry <symbol> --output <ET_EXEC>");
            auto root_storage = take(FileStorage::open(path_from_wide(args[3])));
            const auto root = take(summarize_elf_ar_member(*root_storage, 0));
            std::vector<ArMemberSymbols> summaries;
            summaries.reserve(archive.members.size());
            for (std::size_t i = 0; i < archive.members.size(); ++i) {
                const auto &member = archive.members[i];
                if (member.kind != ArMemberKind::regular) continue;
                auto member_storage = take(open_ar_member(storage, member));
                auto detected = take(detect_format(*member_storage));
                if (detected != DetectedFormat::elf_candidate) continue;
                summaries.push_back(take(summarize_elf_ar_member(*member_storage, i)));
            }
            std::vector<std::string_view> roots, definitions;
            roots.reserve(root.undefined.size());
            definitions.reserve(root.definitions.size());
            for (const auto &name : root.undefined) roots.emplace_back(name);
            for (const auto &name : root.definitions) definitions.emplace_back(name);
            const auto selected = take(select_ar_members_fixed_point(archive, summaries, roots, definitions));
            if (linking || executable) {
                if (!selected.unresolved_symbols.empty())
                    throw std::runtime_error("Unresolved strong ELF symbol " + selected.unresolved_symbols.front());
                std::vector<std::shared_ptr<const ByteStorage>> objects;
                objects.reserve(selected.members.size() + 1);
                objects.push_back(root_storage);
                for (const auto &entry : selected.members)
                    objects.push_back(take(open_ar_member(storage, archive.members[entry.member_index])));
                const auto root_elf = take(read_elf_header(*root_storage, {}));
                const bool aarch64 = root_elf.machine == 183;
                const auto linked = !executable && !root_elf.is_64 && root_elf.machine == 3
                    ? take(link_elf32_i386_text(objects))
                    : executable
                        ? (aarch64 ? take(link_elf64_aarch64_executable(objects, wide_to_utf8(args[5])))
                                   : take(link_elf64_x86_64_executable(objects, wide_to_utf8(args[5]))))
                        : (aarch64 ? take(link_elf64_aarch64_text(objects)) : take(link_elf64_x86_64_text(objects)));
                const auto output_path = path_from_wide(args[executable ? 7 : 5]);
                write_archive_output(output_path, linked, false);
                out << (executable ? "Linked ELF ET_EXEC: objects=" : "Linked ELF ET_REL: objects=")
                    << objects.size() << " bytes=" << linked.size()
                    << " relocations-applied=true\n";
                return 0;
            }
            for (const auto &entry : selected.members) {
                out << "Selected: member=" << entry.member_index << " name="
                    << safe_text(archive.members[entry.member_index].name) << " triggered-by=";
                for (std::size_t i = 0; i < entry.selected_for.size(); ++i) {
                    if (i) out << ',';
                    out << safe_text(entry.selected_for[i]);
                }
                out << '\n';
            }
            for (const auto &name : selected.unresolved_symbols)
                out << "Unresolved: " << safe_text(name) << '\n';
            if (action == L"link-audit") {
                struct Object { std::string name; std::shared_ptr<const ByteStorage> bytes; LoadedImage loaded; };
                std::vector<Object> objects;
                objects.push_back({"<root>", root_storage, take(load_elf(root_storage, {}))});
                for (const auto &entry : selected.members) {
                    auto bytes = take(open_ar_member(storage, archive.members[entry.member_index]));
                    objects.push_back({archive.members[entry.member_index].name, bytes, take(load_elf(bytes, {}))});
                }
                std::map<std::string, std::string> providers;
                for (const auto &object : objects) {
                    if (!object.loaded.metadata.elf) continue;
                    for (const auto &symbol : object.loaded.metadata.elf->symbols) {
                        if ((symbol.binding == 1 || symbol.binding == 10) &&
                            (symbol.state == ElfSymbolState::defined || symbol.state == ElfSymbolState::absolute) &&
                            !symbol.name.empty())
                            providers.try_emplace(symbol.name, object.name);
                    }
                }
                std::size_t unsupported = 0, unresolved = 0;
                for (const auto &object : objects) {
                    if (!object.loaded.metadata.elf) continue;
                    const auto &elf = *object.loaded.metadata.elf;
                    for (const auto &relocation : elf.relocations) {
                        std::string symbol_name = "<symbol-index-unavailable>";
                        if (relocation.symbol_table) {
                            const auto table = std::find_if(elf.symbol_tables.begin(), elf.symbol_tables.end(), [&](const auto &candidate) {
                                return candidate.source == *relocation.symbol_table;
                            });
                            if (table != elf.symbol_tables.end() && table->symbol_begin && relocation.symbol_index_validated &&
                                *table->symbol_begin + relocation.symbol_index < elf.symbols.size())
                                symbol_name = elf.symbols[static_cast<std::size_t>(*table->symbol_begin + relocation.symbol_index)].name;
                        }
                        const auto type = relocation.type;
                        const bool supported = (elf.header.machine == 62 &&
                            (type == 0 || type == 1 || type == 2 || type == 4 || type == 10 || type == 11 || type == 24)) ||
                            (elf.header.machine == 183 && (type == 0 || type == 257 || type == 258 || type == 260 ||
                             type == 261 || type == 275 || type == 277 || type == 282 || type == 283 || type == 286));
                        if (!supported) ++unsupported;
                        const auto provider = providers.find(symbol_name);
                        const bool needs_symbol = relocation.symbol_index != 0;
                        if (needs_symbol && provider == providers.end()) ++unresolved;
                        out << (supported ? "Relocation: " : "Unsupported relocation: ") << "object=" << safe_text(object.name)
                            << " type=" << type << " symbol=" << safe_text(symbol_name);
                        if (provider != providers.end()) out << " provider=" << safe_text(provider->second);
                        else if (needs_symbol) out << " unresolved=true";
                        out << '\n';
                    }
                }
                out << "Link audit: objects=" << objects.size() << " unresolved-relocations=" << unresolved
                    << " unsupported-relocations=" << unsupported << " output=none\n";
            }
            return 0;
        }
        if (action == L"list") {
            if (args.size() != 2) argument_error("archive list takes one path");
            for (std::size_t i = 0; i < archive.members.size(); ++i) {
                const auto &member = archive.members[i];
                out << "Member: " << i << " name=" << safe_text(member.name) << " size=" << member.size
                    << " kind=" << (member.kind == ArMemberKind::regular ? "regular"
                                    : member.kind == ArMemberKind::symbol_index ? "symbol-index" : "long-name-table") << '\n';
            }
            for (const auto &symbol : archive.symbols) {
                const auto &member = archive.members[symbol.member_index];
                out << "Symbol: name=" << safe_text(symbol.name) << " member=" << symbol.member_index
                    << " member-name=" << safe_text(member.name) << '\n';
            }
            for (const auto &diagnostic : archive.diagnostics) out << "Diagnostic: " << safe_text(diagnostic) << '\n';
            return 0;
        }
        if (action != L"open" && action != L"extract") argument_error("Unknown archive action");
        std::optional<std::uint64_t> selected;
        std::filesystem::path project_path;
        std::filesystem::path output_path;
        bool replace = false;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == L"--replace") { replace = true; continue; }
            if ((args[i] == L"--member" || args[i] == L"--project" || args[i] == L"--output") && i + 1 < args.size()) {
                const auto value = args[++i];
                if (args[i - 1] == L"--member") selected = project_detail::take(parse_address(value));
                else if (args[i - 1] == L"--project") project_path = path_from_wide(value);
                else output_path = path_from_wide(value);
                continue;
            }
            argument_error("Unknown or incomplete archive option");
        }
        if (!selected) argument_error("archive action requires --member");
        if (action == L"open" && (project_path.empty() || !output_path.empty()))
            argument_error("archive open requires --project and does not accept --output");
        if (action == L"extract" && (output_path.empty() || !project_path.empty()))
            argument_error("archive extract requires --output and does not accept --project");
        if (*selected >= archive.members.size()) argument_error("Archive member index is out of range");
        const auto &member = archive.members[static_cast<std::size_t>(*selected)];
        if (member.kind != ArMemberKind::regular) argument_error("Selected archive member is not a regular file");
        auto bytes = take(extract_ar_member(*storage, member));
        if (action == L"extract") {
            write_archive_output(output_path, bytes, replace);
            out << "Extracted archive member " << *selected << " (" << safe_text(member.name) << ")\nOutput: "
                << path_text(output_path) << '\n';
            return 0;
        }
        const auto temporary = reserve_temporary_file();
        struct TempFile { std::filesystem::path path; ~TempFile() { std::error_code ec; std::filesystem::remove(path, ec); } } cleanup{temporary};
        {
            std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
            if (!file || (!bytes.empty() && !file.write(reinterpret_cast<const char *>(bytes.data()), std::streamsize(bytes.size()))))
                throw std::runtime_error("Cannot stage selected archive member");
        }
        auto pool = std::make_shared<AnalysisPool>();
        auto actor = take(ProjectActor::create({{1}, 1}, pool));
        auto reply = [&](Result<ProjectSubmission> submitted) {
            auto operation = take(std::move(submitted));
            return take(operation.result.get());
        };
        struct Close { std::shared_ptr<ProjectActor> actor; ~Close() { auto closing=actor->close(); if(closing) closing.value().result.wait(); } } close{actor};
        OpenRequest request; request.path = temporary; request.run_analysis = false;
        reply(actor->import_binary(std::move(request)));
        auto saved = reply(actor->save_as(project_path, replace ? database::ReplacePolicy::replace_existing
                                                               : database::ReplacePolicy::fail_if_exists));
        if (!saved.adopted) throw Failure{saved.adoption_error.value_or(Error{ErrorCode::io, "Project adoption failed"})};
        out << "Opened archive member " << *selected << " (" << safe_text(member.name) << ")\nSaved: "
            << path_text(saved.saved->path) << '\n';
        return 0;
    } catch (const Failure &failure) {
        err << "Archive: " << failure.error.message << '\n';
        return failure.error.code == ErrorCode::invalid_argument ? 2 : 1;
    } catch (const ArgumentError &error) { err << error.message << '\n'; return 2; }
      catch (const std::exception &error) { err << "Archive: " << error.what() << '\n'; return 1; }
}
int jar_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    using project_detail::Failure;
    using project_detail::take;
    if (args.size() < 2 || (args.size() == 2 && args[1] == L"--help")) {
        out << "Usage: hexlab_cli jar list <package.jar>\n"
               "       hexlab_cli jar inspect <package.jar> --member <index>\n";
        return 0;
    }
    try {
        const auto action = args[0];
        auto storage = take(FileStorage::open(path_from_wide(args[1])));
        auto archive = take(read_jar_archive(*storage));
        if (action == L"list") {
            if (args.size() != 2) argument_error("jar list accepts one package path");
            out << "JAR members: " << archive.members.size() << '\n';
            for (std::size_t i = 0; i < archive.members.size(); ++i) {
                const auto &member = archive.members[i];
                out << i << "  " << (member.directory ? "directory" : member.name.ends_with(".class") ? "class" : "resource")
                    << "  method=" << member.compression_method
                    << "  compressed=" << member.compressed_size
                    << "  size=" << member.uncompressed_size
                    << "  crc32=" << hex(member.crc32)
                    << "  " << safe_text(member.name);
                if (member.encrypted) out << "  encrypted";
                else if (!member.supported) out << "  unsupported-compression";
                out << '\n';
            }
            return 0;
        }
        if (action != L"inspect" || args.size() != 4 || args[2] != L"--member")
            argument_error("jar inspect requires --member <index>");
        auto parsed = parse_address(args[3]);
        if (!parsed) argument_error(parsed.error().message);
        if (parsed.value() > (std::numeric_limits<std::size_t>::max)())
            argument_error("JAR member index is too large");
        const auto index = static_cast<std::size_t>(parsed.value());
        if (index >= archive.members.size()) argument_error("JAR member index is out of range");
        out << "Class member " << index << ": " << safe_text(archive.members[index].name) << '\n';
        const auto loaded = take(load_jvm_jar_class(archive, index));
        jvm_description(out, loaded.metadata);
        return 0;
    } catch (const Failure &failure) {
        err << "JAR: " << failure.error.message << '\n';
        return failure.error.code == ErrorCode::invalid_argument ? 2 : 1;
    } catch (const ArgumentError &error) { err << error.message << '\n'; return 2; }
      catch (const std::exception &error) { err << "JAR: " << error.what() << '\n'; return 1; }
}
template <class T> void option(std::optional<T> &destination, T value) {
    if (destination && *destination != value)
        argument_error("Option has conflicting duplicate values");
    destination = std::move(value);
}
std::uint64_t number(std::wstring_view text) {
    auto value = parse_address(text);
    if (!value)
        argument_error(value.error().message);
    return value.value();
}
OpenRequest parse(std::span<const std::wstring_view> args, bool disassemble,
                  std::vector<std::filesystem::path>& plugin_paths) {
    OpenRequest request;
    request.run_analysis = disassemble;
    std::optional<Format> format;
    std::optional<Architecture> architecture;
    std::optional<ExecutionMode> raw_mode;
    std::optional<ByteOrder> raw_order;
    std::optional<std::uint64_t> base, entry, instructions, strings, minimum, slice;
    std::optional<std::filesystem::path> profile;
    std::optional<std::filesystem::path> arm_profile;
    std::optional<std::filesystem::path> pdb_path, pdb_search_path, dwarf_supplementary_package_path;
    std::optional<PeRuntimeArchitecture> pe_runtime_architecture;
    bool end_options = false;
    for (std::size_t n = 0; n < args.size(); ++n) {
        const auto item = args[n];
        if (!end_options && item == L"--") {
            end_options = true;
            continue;
        }
        if (!end_options && item.starts_with(L"--")) {
            if (n + 1 >= args.size() || args[n + 1].starts_with(L"--"))
                argument_error("Option requires a value");
            const auto value = args[++n];
            if (item == L"--plugin")
                plugin_paths.push_back(path_from_wide(value));
            else if (item == L"--format") {
                if (value == L"auto")
                    option(format, Format::automatic);
                else if (value == L"pe")
                    option(format, Format::pe);
                else if (value == L"elf")
                    option(format, Format::elf);
                else if (value == L"raw")
                    option(format, Format::raw);
                else if (value == L"macho")
                    option(format, Format::macho);
                else if (value == L"wasm")
                    option(format, Format::wasm);
                else if (value == L"dex")
                    option(format, Format::dex);
                else if (value == L"jvm")
                    option(format, Format::jvm);
                else
                    argument_error("Unknown format value");
            } else if (item == L"--arch") {
                if (value != L"x86-64" && value != L"x86-32" && value != L"a64" && value != L"6502" &&
                    value != L"rv32" && value != L"rv64" && value != L"mips64" && value != L"ppc32le" &&
                    value != L"ppc32be" && value != L"ppc64le" && value != L"ppc64be")
                    argument_error("Raw architecture must be x86-32, x86-64, a64, 6502, rv32, rv64, mips64, ppc32le/be or ppc64le/be");
                option(architecture, value == L"a64"      ? Architecture::arm64
                                     : value == L"x86-32" ? Architecture::x86
                                     : value == L"6502"   ? Architecture::mos6502
                                     : value == L"rv32"   ? Architecture::riscv32
                                     : value == L"rv64"   ? Architecture::riscv64
                                     : value == L"mips64" ? Architecture::mips64
                                     : value.starts_with(L"ppc") ? Architecture::powerpc
                                                          : Architecture::x86_64);
                if (value.starts_with(L"ppc")) {
                    option(raw_mode, value.starts_with(L"ppc32") ? ExecutionMode::ppc32 : ExecutionMode::ppc64);
                    option(raw_order, value.ends_with(L"be") ? ByteOrder::big : ByteOrder::little);
                }
            } else if (item == L"--profile")
                option(profile, path_from_wide(value));
            else if (item == L"--arm-profile")
                option(arm_profile, path_from_wide(value));
            else if (item == L"--pdb")
                option(pdb_path, path_from_wide(value));
            else if (item == L"--pdb-search")
                option(pdb_search_path, path_from_wide(value));
            else if (item == L"--dwarf-supplementary-package")
                option(dwarf_supplementary_package_path, path_from_wide(value));
            else if (item == L"--pe-runtime") {
                if (value == L"arm64")
                    option(pe_runtime_architecture, PeRuntimeArchitecture::arm64);
                else if (value == L"x64-compatible")
                    option(pe_runtime_architecture, PeRuntimeArchitecture::x64_compatible);
                else
                    argument_error("PE runtime architecture must be arm64 or x64-compatible");
            }
            else if (item == L"--base")
                option(base, number(value));
            else if (item == L"--entry")
                option(entry, number(value));
            else if (item == L"--slice")
                option(slice, number(value));
            else if (item == L"--instruction-budget")
                option(instructions, number(value));
            else if (item == L"--string-budget")
                option(strings, number(value));
            else if (item == L"--min-string-length")
                option(minimum, number(value));
            else
                argument_error("Invalid arguments: unknown option");
        } else {
            if (!request.path.empty())
                argument_error("Exactly one input path is required");
            request.path = path_from_wide(item);
        }
    }
    if (request.path.empty())
        argument_error("An input path is required");
    request.format = format.value_or(Format::automatic);
    request.pe_runtime_architecture = pe_runtime_architecture;
    request.pdb_path = pdb_path;
    request.dwarf_supplementary_package_path = dwarf_supplementary_package_path;
    if (pdb_search_path) request.pdb_search_paths.push_back(*pdb_search_path);
    if (slice) {
        if (*slice > UINT32_MAX || (request.format != Format::automatic && request.format != Format::macho))
            argument_error("Slice requires auto or macho format and a 32-bit unsigned index");
        request.macho = MachOOptions{static_cast<std::uint32_t>(*slice)};
    }
    if (request.format == Format::raw) {
        if (profile || arm_profile) {
            if (architecture || base || entry || (profile && arm_profile))
                argument_error("A raw profile replaces architecture/base/entry options");
            request.x86_profile_path = std::move(profile);
            request.arm_profile_path = std::move(arm_profile);
        } else {
            if (!architecture || !base)
                argument_error("Raw format requires --arch x86-32|x86-64|a64|6502|rv32|rv64|mips64|ppc32le|ppc32be|ppc64le|ppc64be and --base");
            request.raw = RawOptions{*architecture,
                                     raw_mode.value_or(*architecture == Architecture::arm64 ? ExecutionMode::a64
                                     : *architecture == Architecture::x86 ? ExecutionMode::x86_32
                                     : *architecture == Architecture::mos6502 ? ExecutionMode::m6502
                                     : *architecture == Architecture::riscv32 ? ExecutionMode::rv32
                                     : *architecture == Architecture::riscv64 ? ExecutionMode::rv64
                                     : *architecture == Architecture::mips64 ? ExecutionMode::mips64
                                                                          : ExecutionMode::x86_64),
                                     {{0}, *base},
                                     true,
                                     false,
                                     true,
                                     {}};
            request.raw->order = raw_order.value_or(ByteOrder::little);
            if (entry)
                request.raw->entry = Address{{0}, *entry};
            auto valid = validate_raw_coordinates(*request.raw);
            if (!valid)
                argument_error(valid.error().message);
        }
    } else if (architecture || base || entry || profile || arm_profile)
        argument_error("Raw profile/architecture/base/entry options require --format raw");
    if (pe_runtime_architecture && request.format != Format::pe && request.format != Format::automatic)
        argument_error("--pe-runtime requires --format pe or auto");
    if (!disassemble && (instructions || strings || minimum))
        argument_error("Analysis options require disassemble");
    if (minimum && *minimum == 0)
        argument_error("Minimum string length must be positive");
    if (instructions)
        request.analysis_options.instruction_budget = static_cast<std::size_t>(*instructions);
    if (strings)
        request.analysis_options.string_budget = static_cast<std::size_t>(*strings);
    if (minimum)
        request.analysis_options.min_string_characters = static_cast<std::size_t>(*minimum);
    return request;
}
void diagnostics(std::ostream &err, const std::vector<Diagnostic> &messages, const Image *image) {
    for (const auto &diagnostic : messages) {
        err << (diagnostic.severity == DiagnosticSeverity::error     ? "error: "
                : diagnostic.severity == DiagnosticSeverity::warning ? "warning: "
                                                                     : "info: ");
        if (diagnostic.location)
            err << (image && image->layout().x86_profile ? format_location(*diagnostic.location, image)
                                                         : hex(diagnostic.location->offset))
                << ": ";
        err << safe_text(diagnostic.message) << '\n';
    }
}
void metadata(std::ostream &out, const DocumentSnapshot &document) {
    const auto &m = document.metadata;
    out << "Format: " << m.format << '\n';
    if (!m.macho)
        out << "Machine: " << hex(m.machine) << '\n';
    out << "Image base: " << hex(m.preferred_base) << '\n';
    profile_description(out, *document.image);
    for (auto entry : document.image->layout().entries) {
        out << "Entry: "
            << (entry.space.value && !document.image->layout().x86_profile
                    ? format_location(entry, document.image.get())
                    : hex(entry.offset));
        profile_coordinate(out, *document.image, entry);
        out << '\n';
    }
    out << "Sections:\n";
    for (const auto &section : document.image->layout().segments) {
        out << "  " << safe_text(section.name) << " VA="
            << (section.begin.space.value && !document.image->layout().x86_profile
                    ? format_location(section.begin, document.image.get())
                    : hex(section.begin.offset))
            << " File=" << hex(section.file_begin.value) << " Size=" << hex(section.size)
            << " Initialized=" << hex(section.file_size);
        profile_coordinate(out, *document.image, section.begin);
        out << '\n';
    }
    out << "Imports:\n";
    for (const auto &symbol : m.imports) {
        const auto raw_name = symbol.name ? *symbol.name : std::string{};
        const auto rendered = demangled_name(raw_name);
        out << "  " << safe_text(symbol.library) << '!'
            << (symbol.name ? safe_text(*symbol.name) : "#" + std::to_string(symbol.ordinal.value_or(0)));
        if (!rendered.empty()) out << " [" << safe_text(rendered) << ']';
        out << " IAT=" << hex(symbol.iat.offset) << " Thunk=" << hex(symbol.thunk.offset) << '\n';
    }
    out << "Exports:\n";
    for (const auto &symbol : m.exports) {
        out << "  #" << symbol.ordinal;
        if (symbol.name)
            out << ' ' << safe_text(*symbol.name);
        if (symbol.forwarder)
            out << " -> " << safe_text(*symbol.forwarder);
        else if (symbol.address)
            out << " VA=" << hex(symbol.address->offset);
        out << '\n';
    }
    out << "Relocations:\n";
    for (const auto &relocation : m.relocations)
        out << "  type=" << relocation.type << " VA=" << hex(relocation.address.offset) << '\n';
    out << "Metadata: " << (document.metadata_complete ? "complete" : "partial") << '\n';
    elf_description(out, m, document.image.get());
    macho_description(out, m, document.image.get());
    pe_description(out, m);
    jvm_description(out, m);
    wasm_description(out, m);
    dex_description(out, m);
    minidump_description(out, m);
}
} // namespace
int run_cli(std::span<const std::wstring_view> arguments, std::ostream &out, std::ostream &err) {
    if (arguments.empty() || (arguments.size() == 1 && arguments[0] == L"--help")) {
        usage(out);
        return 0;
    }
    if (arguments.size() == 1 && arguments[0] == L"--version") {
        out << "HexLab " << build_version() << '\n';
        return 0;
    }
    if (arguments[0] == L"project")
        return run_project_cli(arguments.subspan(1), out, err);
    if (arguments[0] == L"plugins")
        return plugin_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"archive")
        return archive_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"jar")
        return jar_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"firmware")
        return firmware_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"compare")
        return run_compare_cli(arguments.subspan(1), out, err);
    if (arguments[0] == L"modules")
        return modules_command(arguments.subspan(1), out, err);
    if (arguments[0] != L"inspect" && arguments[0] != L"disassemble" && arguments[0] != L"decompile") {
        err << "Invalid arguments. Use --help for usage.\n";
        return 2;
    }
    if (arguments.size() == 2 && arguments[1] == L"--help") {
        usage(out);
        return 0;
    }
    try {
        const bool decompile = arguments[0] == L"decompile";
        const bool disassemble = arguments[0] == L"disassemble" || decompile;
        std::vector<std::filesystem::path> plugin_paths;
        auto request = parse(arguments.subspan(1), disassemble, plugin_paths);
        plugins::PluginManager plugin_manager(plugins::make_native_module_provider());
        for (const auto& plugin_path : plugin_paths) {
            auto loaded = plugin_manager.load(path_text(plugin_path));
            if (!loaded) {
                err << "Plugin: " << loaded.error().message << '\n';
                return 1;
            }
        }
        if (disassemble && !plugin_paths.empty())
            request.analysis_options = plugin_manager.analysis_options(request.analysis_options);
        if (request.format == Format::automatic && !plugin_paths.empty()) {
            auto source = FileStorage::open(request.path);
            if (!source) {
                err << path_text(request.path) << ": " << source.error().message << '\n';
                return 1;
            }
            auto prefix_view = source.value()->read_at({0}, static_cast<std::size_t>(
                std::min<std::uint64_t>(source.value()->size(), HEXLAB_PLUGIN_MAX_LOADER_PROBE_BYTES)));
            if (!prefix_view) {
                err << path_text(request.path) << ": " << prefix_view.error().message << '\n';
                return 1;
            }
            const auto prefix = std::span(reinterpret_cast<const std::uint8_t*>(prefix_view.value().bytes.data()),
                                          prefix_view.value().bytes.size());
            auto selected = plugins::detect_with_extensions(plugin_manager, *source.value(), prefix);
            if (!selected) {
                err << path_text(request.path) << ": " << selected.error().message << '\n';
                return 1;
            }
            if (const auto* extension = std::get_if<plugins::LoaderProbeResult>(&selected.value())) {
                auto image_recipe = plugin_manager.image_recipe(extension->plugin_id, extension->extension_id);
                if (image_recipe) {
                    // Keep automatic format selection: the loader registry will
                    // persist the exact winning provider identity in the recipe.
                } else if (extension->format_id == "pe") request.format = Format::pe;
                else if (extension->format_id == "elf") request.format = Format::elf;
                else if (extension->format_id == "macho") request.format = Format::macho;
                else {
                    err << "Unsupported plugin loader format: " << extension->format_id
                        << " (no image construction service is registered)\n";
                    return 1;
                }
            }
        }
        auto result = load_document(request, {{1}, 1}, {});
        if (!result) {
            err << path_text(request.path) << ": " << result.error().message << '\n';
            return result.error().code == ErrorCode::invalid_argument ? 2 : 1;
        }
        const auto &document = *result.value();
        if (decompile && document.image->decode_context().architecture == Architecture::wasm) {
            err << "Unsupported decompilation: WebAssembly stack and structured-control lifting is not implemented\n";
            return 1;
        }
        auto analysis = document.analysis;
        if (disassemble && analysis && !plugin_paths.empty()) {
            for (auto& instruction : analysis->instructions) {
                auto applied = plugins::apply_display_extension(plugin_manager, instruction);
                if (!applied) {
                    err << "Plugin decode: " << applied.error().message << '\n';
                    return 1;
                }
            }
        }
        for (const auto& failure : plugin_manager.extension_failures())
            err << "Plugin extension disabled: " << failure.plugin_id << "/" << failure.extension_id
                << " (" << failure.kind << "): " << failure.reason << '\n';
        if (disassemble && !analysis) {
            err << "Unsupported analysis: this CPU/mode has no enabled decoder\n";
            return 1;
        }
        metadata(out, document);
        diagnostics(err, document.diagnostics, document.image.get());
        if (!disassemble)
            return 0;
        if (decompile) {
            auto functions = recover_functions(*document.image, document.metadata, {}, request.analysis_options, {});
            if (!functions) {
                err << "Function recovery: " << functions.error().message << '\n';
                return 1;
            }
            if (functions.value()->functions.empty()) {
                err << "No functions recovered from this image\n";
                return 3;
            }
            bool complete = functions.value()->complete;
            const decompiler::CallSummaryOptions summary_options{};
            // Preflight the whole candidate set before retaining lifted bodies.
            // Large inputs use the original streaming path instead of keeping
            // an unbounded number of IR bodies alive at once.
            std::map<BlockId, const BasicBlock *> blocks_by_id;
            for (const auto &block : functions.value()->blocks)
                if (block) blocks_by_id.emplace(block->id, block.get());
            bool within_summary_limits = functions.value()->functions.size() <= summary_options.max_functions;
            std::size_t summary_block_count = 0;
            std::size_t summary_instruction_count = 0;
            for (const auto &function : functions.value()->functions) {
                if (!function || summary_block_count > summary_options.max_blocks ||
                    function->blocks.size() > summary_options.max_blocks - summary_block_count) {
                    within_summary_limits = false;
                    break;
                }
                summary_block_count += function->blocks.size();
                for (const auto id : function->blocks) {
                    const auto found = blocks_by_id.find(id);
                    if (found == blocks_by_id.end() ||
                        summary_instruction_count > summary_options.max_instructions ||
                        found->second->instructions.size() >
                            summary_options.max_instructions - summary_instruction_count) {
                        within_summary_limits = false;
                        break;
                    }
                    summary_instruction_count += found->second->instructions.size();
                }
                if (!within_summary_limits) break;
            }
            const auto emit_pseudocode = [&](const FunctionRecord &function,
                                             const decompiler::LiftedFunction &body,
                                             const decompiler::AbiDescription &abi,
                                             types::TypePtr prototype) {
                auto constants = decompiler::simplify_constants(body);
                auto identities = constants ? decompiler::simplify_identities(constants.value())
                                             : Result<decompiler::LiftedFunction>(constants.error());
                auto dead = identities ? decompiler::eliminate_dead_code(identities.value())
                                       : Result<decompiler::LiftedFunction>(identities.error());
                if (!dead) {
                    err << "Simplification at " << hex(function.entry.offset) << ": "
                        << dead.error().message << '\n';
                    complete = false;
                    return;
                }
                out << "Function at " << hex(function.entry.offset) << ":\n";
                auto typed = decompiler::format_pseudocode_with_types(dead.value(), abi, std::move(prototype));
                if (typed) out << typed.value();
                else {
                    err << "Typed pseudocode at " << hex(function.entry.offset) << ": "
                        << typed.error().message << "; using structured IR output\n";
                    out << decompiler::format_structured_pseudocode(dead.value()).text;
                }
                if (!function.complete)
                    complete = false;
            };
            if (!within_summary_limits)
                err << "Call summaries skipped: recovered input set exceeds summary preparation limits; "
                       "continuing with streaming local simplification\n";

            // Build the complete candidate set before summarization so direct
            // calls resolve independent of recovered-function order. Unknown
            // ABI boundary effects remain explicit and therefore cannot be
            // mistaken for preserved registers or pure memory behavior.
            std::vector<decompiler::LiftedFunction> summary_bodies;
            std::vector<decompiler::CallSummaryInput> summary_inputs;
            std::vector<decompiler::AbiDescription> summary_abis;
            std::vector<std::optional<std::size_t>> summary_indices(functions.value()->functions.size());
            bool interprocedural_types_eligible = true;
            if (within_summary_limits) {
                summary_bodies.reserve(functions.value()->functions.size());
                summary_inputs.reserve(functions.value()->functions.size());
                summary_abis.reserve(functions.value()->functions.size());
                for (std::size_t index = 0; index < functions.value()->functions.size(); ++index) {
                    const auto &function = functions.value()->functions[index];
                    const auto *jvm_metadata = document.metadata.jvm ? &*document.metadata.jvm : nullptr;
                    const auto *wasm_metadata = document.metadata.wasm ? &*document.metadata.wasm : nullptr;
                    auto lifted = decompiler::lift_function(*function, *functions.value(), jvm_metadata, wasm_metadata);
                    if (!lifted) {
                        err << "Decompilation at " << hex(function->entry.offset) << ": "
                            << lifted.error().message << '\n';
                        complete = false;
                        interprocedural_types_eligible = false;
                        continue;
                    }
                    const auto abi = cli_decompiler_abi(*document.image, document.metadata);
                    auto call_effects = decompiler::prepare_call_effects(lifted.value(), abi);
                    auto call_arguments = abi.integer_argument_registers;
                    call_arguments.insert(call_arguments.end(), abi.floating_argument_registers.begin(), abi.floating_argument_registers.end());
                    call_arguments.insert(call_arguments.end(), abi.vector_argument_registers.begin(), abi.vector_argument_registers.end());
                    auto ssa = call_effects ? decompiler::to_ssa(call_effects.value(), call_arguments)
                                            : Result<decompiler::LiftedFunction>{call_effects.error()};
                    if (!ssa) {
                        err << "SSA at " << hex(function->entry.offset) << ": " << ssa.error().message << '\n';
                        complete = false;
                        interprocedural_types_eligible = false;
                        continue;
                    }
                    summary_bodies.push_back(std::move(ssa.value()));
                    summary_indices[index] = summary_bodies.size() - 1;
                    summary_abis.push_back(cli_decompiler_abi(*document.image, document.metadata));
                    bool externally_bound = std::any_of(document.metadata.exports.begin(), document.metadata.exports.end(),
                        [&](const auto &symbol) { return symbol.address && *symbol.address == function->entry; });
                    // ELF and Mach-O keep format-specific symbol/export tables
                    // alongside the generic metadata list. Treat any defined
                    // symbol at this entry as externally bound; this is
                    // intentionally conservative for local and static cases.
                    if (document.metadata.elf)
                        externally_bound |= std::any_of(document.metadata.elf->symbols.begin(),
                            document.metadata.elf->symbols.end(), [&](const auto &symbol) {
                                return symbol.state == ElfSymbolState::defined && symbol.address &&
                                       *symbol.address == function->entry;
                            });
                    if (document.metadata.macho) {
                        externally_bound |= std::any_of(document.metadata.macho->symbols.begin(),
                            document.metadata.macho->symbols.end(), [&](const auto &symbol) {
                                return symbol.state == MachOSymbolState::defined && symbol.address &&
                                       *symbol.address == function->entry;
                            });
                        externally_bound |= std::any_of(document.metadata.macho->dyld_exports.begin(),
                            document.metadata.macho->dyld_exports.end(), [&](const auto &symbol) {
                                return symbol.is_definition() && symbol.address &&
                                       *symbol.address == function->entry;
                            });
                    }
                    interprocedural_types_eligible &= function->complete && !externally_bound;
                    summary_inputs.push_back({&summary_bodies.back(), function->complete, externally_bound, false, {},
                                              decompiler::IntrinsicMemoryEffect::unknown});
                }
            }
            std::optional<decompiler::CallSummaryOptimization> summarized;
            if (within_summary_limits) {
                auto summary_result = decompiler::optimize_with_call_summaries(summary_inputs, summary_options);
                if (summary_result) {
                    summarized.emplace(std::move(summary_result.value()));
                } else {
                    err << "Call summaries unavailable: " << summary_result.error().message
                        << "; continuing with local simplification\n";
                }
            }
            std::optional<std::vector<decompiler::TypeRecoveryResult>> interprocedural_types;
            if (within_summary_limits && !summary_bodies.empty() && interprocedural_types_eligible) {
                const auto &type_inputs = summarized ? summarized->functions : summary_bodies;
                auto recovered = decompiler::recover_interprocedural_types(type_inputs, summary_abis);
                if (recovered)
                    interprocedural_types.emplace(std::move(recovered.value()));
                else
                    err << "Interprocedural type recovery unavailable: " << recovered.error().message
                        << "; using per-function type recovery\n";
            } else if (within_summary_limits && !summary_bodies.empty()) {
                err << "Interprocedural type recovery skipped: candidate set includes incomplete or externally bound functions; "
                       "using per-function type recovery\n";
            }
            for (std::size_t index = 0; index < functions.value()->functions.size(); ++index) {
                const auto &function = functions.value()->functions[index];
                if (within_summary_limits) {
                    if (!summary_indices[index])
                        continue;
                    const auto body_index = *summary_indices[index];
                    const auto &body = summarized ? summarized->functions[body_index] : summary_bodies[body_index];
                    const auto prototype = interprocedural_types && body_index < interprocedural_types->size()
                        ? (*interprocedural_types)[body_index].inferred_prototype : types::TypePtr{};
                    emit_pseudocode(*function, body, summary_abis[body_index], prototype);
                    continue;
                }
                const auto *jvm_metadata = document.metadata.jvm ? &*document.metadata.jvm : nullptr;
                const auto *wasm_metadata = document.metadata.wasm ? &*document.metadata.wasm : nullptr;
                auto lifted = decompiler::lift_function(*function, *functions.value(), jvm_metadata, wasm_metadata);
                if (!lifted) {
                    err << "Decompilation at " << hex(function->entry.offset) << ": "
                        << lifted.error().message << '\n';
                    complete = false;
                    continue;
                }
                const auto abi = cli_decompiler_abi(*document.image, document.metadata);
                auto call_effects = decompiler::prepare_call_effects(lifted.value(), abi);
                auto call_arguments = abi.integer_argument_registers;
                call_arguments.insert(call_arguments.end(), abi.floating_argument_registers.begin(), abi.floating_argument_registers.end());
                call_arguments.insert(call_arguments.end(), abi.vector_argument_registers.begin(), abi.vector_argument_registers.end());
                auto ssa = call_effects ? decompiler::to_ssa(call_effects.value(), call_arguments)
                                        : Result<decompiler::LiftedFunction>{call_effects.error()};
                if (!ssa) {
                    err << "SSA at " << hex(function->entry.offset) << ": " << ssa.error().message << '\n';
                    complete = false;
                    continue;
                }
                emit_pseudocode(*function, ssa.value(),
                                cli_decompiler_abi(*document.image, document.metadata), {});
            }
            diagnostics(err, analysis->diagnostics, document.image.get());
            return complete ? 0 : 3;
        }
        out << "Disassembly:\n";
        auto resolutions = RelocationResolver::create(*document.image, document.metadata, {});
        if (!resolutions) {
            err << resolutions.error().message << '\n';
            return 1;
        }
        for (const auto &instruction : analysis->instructions) {
            if (document.image->layout().x86_profile || instruction.address.space.value)
                out << format_location(instruction.address, document.image.get()) << " ["
                    << mode_label(instruction.context.mode) << "]  ";
            else
                out << hex(instruction.address.offset) << "  ";
            std::ostringstream encoded;
            for (const auto byte : instruction.encoded_bytes())
                encoded << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                        << std::to_integer<unsigned>(byte) << ' ';
            out << encoded.str() << " " << format_instruction(instruction);
            if (!instruction.operands.empty() &&
                (instruction.flow == FlowKind::call || instruction.flow == FlowKind::jump ||
                 instruction.flow == FlowKind::conditional_branch)) {
                auto operand = resolutions.value().operand(instruction, control_operand_index(instruction), {});
                if (!operand) {
                    err << operand.error().message << '\n';
                    return 1;
                }
                if (operand.value().relocated()) {
                    auto target = resolutions.value().control_target(*document.image, instruction, {});
                    if (!target) {
                        err << target.error().message << '\n';
                        return 1;
                    }
                    out << " ; target="
                        << (target.value() ? format_location(*target.value(), document.image.get()) : "unresolved");
                }
            }
            out << '\n';
        }
        diagnostics(err, analysis->diagnostics, document.image.get());
        diagnostics(err, analysis->strings.diagnostics, document.image.get());
        out << "Analysis: " << (analysis->complete ? "complete" : "incomplete") << '\n';
        return analysis->complete ? 0 : 3;
    } catch (const ArgumentError &error) {
        err << error.message << '\n';
        return 2;
    }
}
} // namespace hexlab::cli
