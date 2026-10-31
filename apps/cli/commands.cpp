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
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/strings.hpp"
#include "hexlab/analysis/module_dependencies.hpp"
#include "hexlab/analysis/pe_module_dependencies.hpp"
#include "hexlab/core/version.hpp"
#include "hexlab/workspace/workspace.hpp"
#include "hexlab/workspace/project_actor.hpp"
#include "hexlab/database/project_state.hpp"
#include "hexlab/loaders/ar.hpp"
#include "hexlab/loaders/xcoff64.hpp"
#include "hexlab/loaders/jar.hpp"
#include "hexlab/loaders/jvm_module_path.hpp"
#include "hexlab/loaders/firmware.hpp"
#include "hexlab/loaders/elf.hpp"
#include "hexlab/loaders/elf_link.hpp"
#include "hexlab/loaders/macho.hpp"
#include "hexlab/loaders/coff_link.hpp"
#include "hexlab/loaders/macho_link.hpp"
#include "hexlab/loaders/loader.hpp"
#include "hexlab/loaders/dex_container.hpp"
#include "hexlab/loaders/dex_archive.hpp"
#include "hexlab/loaders/vdex.hpp"
#include "hexlab/loaders/dex.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/processors/format.hpp"
#include "hexlab/processors/decoder.hpp"
#include "hexlab/plugins/runtime.hpp"
#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/decompiler/optimizer.hpp"
#include "hexlab/decompiler/type_recovery.hpp"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
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
std::string_view processor_architecture_label(Architecture architecture) {
    switch (architecture) {
    case Architecture::x86: return "x86";
    case Architecture::x86_64: return "x86-64";
    case Architecture::arm: return "ARM";
    case Architecture::arm64: return "AArch64";
    case Architecture::riscv32: return "RISC-V 32";
    case Architecture::riscv64: return "RISC-V 64";
    case Architecture::mips32: return "MIPS 32";
    case Architecture::mips64: return "MIPS 64";
    case Architecture::powerpc: return "PowerPC";
    case Architecture::mos6502: return "MOS 6502";
    case Architecture::wasm: return "WebAssembly";
    case Architecture::dex: return "Dalvik";
    case Architecture::jvm: return "JVM";
    case Architecture::unknown: return "unknown";
    }
    return "unknown";
}

std::string_view processor_mode_label(ExecutionMode mode) {
    switch (mode) {
    case ExecutionMode::x86_16: return "16-bit";
    case ExecutionMode::x86_32: return "32-bit";
    case ExecutionMode::x86_64: return "64-bit";
    case ExecutionMode::a32: return "A32";
    case ExecutionMode::thumb: return "Thumb/Thumb-2";
    case ExecutionMode::a64: return "A64";
    case ExecutionMode::rv32: return "RV32";
    case ExecutionMode::rv64: return "RV64";
    case ExecutionMode::rv64c: return "RV64C";
    case ExecutionMode::mips32: return "MIPS32";
    case ExecutionMode::mips64: return "MIPS64";
    case ExecutionMode::ppc32: return "32-bit";
    case ExecutionMode::ppc64: return "64-bit";
    case ExecutionMode::m6502: return "6502";
    case ExecutionMode::wasm32: return "wasm32";
    case ExecutionMode::dex: return "DEX";
    case ExecutionMode::jvm: return "JVM bytecode";
    case ExecutionMode::unknown: return "unknown";
    }
    return "unknown";
}

std::string processor_inventory_json_string(std::string_view value) {
    std::ostringstream out;
    out << '"';
    constexpr char hex_digits[] = "0123456789abcdef";
    for (const unsigned char byte : value) {
        switch (byte) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (byte < 0x20) {
                out << "\\u00" << hex_digits[byte >> 4] << hex_digits[byte & 0xf];
            } else {
                out << static_cast<char>(byte);
            }
        }
    }
    out << '"';
    return out.str();
}

int processors_command(std::span<const std::wstring_view> arguments, std::ostream &out, std::ostream &err) {
    const bool json = arguments.size() == 1 && arguments.front() == L"--json";
    if (!arguments.empty() && !json) {
        err << "Usage: hexlab_cli processors [--json]\n";
        return 2;
    }
    if (json) {
        out << "{\"schema\":\"hexlab.processor-inventory.v2\",\"scope\":\"decoder-and-selected-downstream\",\"variants\":[";
        bool first = true;
        for (const auto &variant : processor_variant_inventory()) {
            if (!first) out << ',';
            first = false;
            const auto &capability = variant.capabilities;
            out << "{\"id\":" << processor_inventory_json_string(variant.id)
                << ",\"architecture\":" << processor_inventory_json_string(
                    processor_architecture_label(variant.context.architecture))
                << ",\"mode\":" << processor_inventory_json_string(processor_mode_label(variant.context.mode))
                << ",\"byte_order\":";
            if (variant.byte_order_applicable)
                out << processor_inventory_json_string(variant.context.order == ByteOrder::little ? "little" : "big");
            else
                out << "null";
            out << ",\"can_decode\":" << (capability.can_decode ? "true" : "false")
                << ",\"max_instruction_bytes\":";
            if (capability.can_decode)
                out << static_cast<unsigned>(capability.max_instruction_bytes);
            else
                out << "null";
            out << ",\"display_name\":";
            if (capability.can_decode)
                out << processor_inventory_json_string(capability.display_name);
            else
                out << "null";
            out << ",\"reason\":";
            if (!capability.can_decode && !capability.reason.empty())
                out << processor_inventory_json_string(capability.reason);
            else
                out << "null";
            const auto write_labels = [&](std::string_view name, std::span<const std::string_view> labels) {
                out << "," << processor_inventory_json_string(name) << ":[";
                for (std::size_t index = 0; index < labels.size(); ++index) {
                    if (index) out << ',';
                    out << processor_inventory_json_string(labels[index]);
                }
                out << ']';
            };
            out << ",\"coverage\":{";
            write_labels("instruction_families", variant.coverage.instruction_families);
            write_labels("analysis", variant.coverage.analysis);
            write_labels("decompiler", variant.coverage.decompiler);
            write_labels("debugger", variant.coverage.debugger);
            out << '}';
            out << '}';
        }
        out << "]}\n";
        return 0;
    }
    out << "Decoder variants (bounded subsets; later-layer coverage varies):\n";
    for (const auto &variant : processor_variant_inventory()) {
        const auto &capability = variant.capabilities;
        out << "  " << variant.id << "  " << processor_architecture_label(variant.context.architecture)
            << " / " << processor_mode_label(variant.context.mode) << " / ";
        if (variant.byte_order_applicable)
            out << (variant.context.order == ByteOrder::little ? "little-endian" : "big-endian");
        else
            out << "byte order n/a";
        out << "  " << (capability.can_decode ? "enabled" : "disabled");
        if (capability.can_decode)
            out << ", max " << static_cast<unsigned>(capability.max_instruction_bytes) << " bytes, "
                << capability.display_name;
        else if (!capability.reason.empty())
            out << ": " << capability.reason;
        out << '\n';
    }
    return 0;
}

void usage(std::ostream &out) {
    out << "Usage: hexlab_cli [--help | --version]\n"
           "       hexlab_cli inspect <path> [options]\n"
           "       hexlab_cli disassemble <path> [options] [--json]\n\n"
           "       hexlab_cli functions <path> [options] [--limit <count>] [--json]\n\n"
           "       hexlab_cli decompile <path> [options]\n\n"
           "       hexlab_cli compare <old-image> <new-image> [--window <bytes>] [--anchor <bytes>] [--limit <runs>] [--functions]\n\n"
           "       hexlab_cli modules [--sysroot <dir>] [--discover] [--search-dir <dir>] [--target-cwd <dir>] [--lib-token <value>] [--platform-token <value>] [--graph] <binary>...\n\n"
           "       hexlab_cli pe-deps --sysroot <dir> [--search-dir <dir>] [--windows-defaults] <PE image>\n\n"
           "       hexlab_cli project --help  (persistent projects and editing)\n\n"
           "       hexlab_cli plugins scan|dependencies <directory> [--json] [--strict]  (data-only native plugin discovery)\n\n"
           "       hexlab_cli processors [--json]  (supported decoder variants)\n\n"
           "       hexlab_cli archive list <archive> [--thin-root <directory>]\n"
           "       hexlab_cli archive index-audit <archive> [--thin-root <directory>]\n"
           "       hexlab_cli archive link-select <archive> --root-object <ET_REL|XCOFF64>\n"
           "       hexlab_cli archive link-audit <archive> --root-object <ET_REL|XCOFF64>\n"
           "       hexlab_cli archive link-exec <archive> --root-object <ET_REL> --entry <symbol> --output <ET_EXEC>\n"
           "       hexlab_cli archive link-pe <archive> --root-object <COFF .obj> --entry <symbol> --output <PE .exe>\n"
           "       hexlab_cli archive link-macho <archive> --root-object <Mach-O .o> --entry <symbol> --output <Mach-O executable>\n"
           "       hexlab_cli archive extract <archive> --member <index> --output <path> [--replace]\n"
           "       hexlab_cli archive open <archive> --member <index> --project <project.hxproj> [--replace]\n"
           "       Thin archive reads/link actions require --thin-root <directory>\n\n"
           "       hexlab_cli jar list <package.jar>\n"
           "       hexlab_cli jar inspect <package.jar> --member <index>\n"
           "       hexlab_cli jar list --volume <path> --volume <path> ...\n"
           "       hexlab_cli jar inspect --volume <path> --volume <path> ... --member <index>\n\n"
           "       hexlab_cli dex container <path> [--json]  (inventory DEX 041 logical members)\n"
           "       hexlab_cli dex load-container <path> [--json]  (parse every DEX 041 member)\n\n"
           "       hexlab_cli dex apk <path> [--json]  (load Android APK multidex entries)\n\n"
           "       hexlab_cli dex vdex <path> [--json]  (inventory Android VDEX 027 sections and DEX members)\n\n"
           "       hexlab_cli jvm module-path [--release <feature>] [--archive-volume <path>]... [--module-path <dir-or-jar>]... [--class-path <dir-or-jar>]...\n\n"
           "       hexlab_cli macho chained-targets <image> [--shared-cache-base <address>] [--cache-level-base <0..3> <address>]...\n"
           "       hexlab_cli firmware inspect <path> --format ihex|srec|uefi|uefi-capsule\n"
           "       hexlab_cli firmware inspect <path> --fit-offset <file-offset> --format fit\n\n"
           "       hexlab_cli firmware inspect <path> --microcode-offset <file-offset> --format intel-microcode\n\n"
           "Input options:\n  --format auto|pe|elf|raw|macho|wasm|dex|jvm\n"
           "  --pe-runtime arm64|x64-compatible  (select an ARM64X PE process view)\n"
           "  --slice <index>  (Mach-O universal slice; zero-based, auto or macho format)\n"
           "  --arch x86-32|x86-64|a64|6502|rv32|rv64|mips64|ppc32le|ppc32be|ppc64le|ppc64be --base <address> [--entry <address>]  (raw only)\n"
           "  --profile <file>  (segmented raw x86-16/32; replaces arch/base/entry)\n"
           "  --arm-profile <file>  (raw ARM/Thumb/data declarations; replaces arch/base/entry)\n"
           "  --plugin <module>  (load a native plugin for detection and display decoding; repeatable)\n"
           "  --pdb <file> --pdb-search <directory>  (local PE PDB binding; no network lookup)\n"
           "  --dwarf-supplementary-package <file>  (explicit supplementary ELF/DWP; otherwise a safe local .debug_sup hint may be used)\n"
           "Analysis options:\n  --instruction-budget <count> --string-budget <count> --show-strings\n"
           "  --min-string-length <count>\n"
           "Function inventory options (with `functions`): --limit <count> (default 10000, max 100000)\n"
           "Addresses use decimal or 0x-prefixed hexadecimal. Use -- before an option-like path.\n";
}

std::string_view function_seed_name(FunctionSeedKind kind) {
    switch (kind) {
    case FunctionSeedKind::entry: return "entry";
    case FunctionSeedKind::export_symbol: return "export-symbol";
    case FunctionSeedKind::direct_call: return "direct-call";
    case FunctionSeedKind::user_function: return "user-function";
    case FunctionSeedKind::user_code: return "user-code";
    case FunctionSeedKind::symbol: return "symbol";
    case FunctionSeedKind::unwind: return "unwind";
    case FunctionSeedKind::arm_context_root: return "arm-context-root";
    case FunctionSeedKind::tls_callback: return "tls-callback";
    case FunctionSeedKind::initializer: return "initializer";
    case FunctionSeedKind::guard_cf: return "guard-cf";
    case FunctionSeedKind::dex_method: return "dex-method";
    case FunctionSeedKind::safe_seh: return "safe-seh";
    case FunctionSeedKind::pogo: return "pogo";
    case FunctionSeedKind::wasm_export: return "wasm-export";
    case FunctionSeedKind::wasm_start: return "wasm-start";
    case FunctionSeedKind::wasm_element: return "wasm-element";
    case FunctionSeedKind::wasm_defined: return "wasm-defined";
    case FunctionSeedKind::dwarf_subprogram: return "dwarf-subprogram";
    case FunctionSeedKind::m6502_nmi_vector: return "m6502-nmi-vector";
    case FunctionSeedKind::m6502_reset_vector: return "m6502-reset-vector";
    case FunctionSeedKind::m6502_irq_vector: return "m6502-irq-vector";
    case FunctionSeedKind::dwarf_entry_point: return "dwarf-entry-point";
    }
    return "unknown";
}

std::string_view function_stop_name(FunctionStopReason reason) {
    switch (reason) {
    case FunctionStopReason::ret: return "return";
    case FunctionStopReason::trap: return "trap";
    case FunctionStopReason::unsupported: return "unsupported";
    case FunctionStopReason::invalid: return "invalid";
    case FunctionStopReason::truncated: return "truncated";
    case FunctionStopReason::unmapped: return "unmapped";
    case FunctionStopReason::uninitialized: return "uninitialized";
    case FunctionStopReason::non_executable: return "non-executable";
    case FunctionStopReason::manual_data: return "manual-data";
    case FunctionStopReason::overlap: return "overlap";
    case FunctionStopReason::indirect: return "indirect";
    case FunctionStopReason::budget: return "budget";
    case FunctionStopReason::target_overflow: return "target-overflow";
    case FunctionStopReason::chunk_boundary: return "chunk-boundary";
    case FunctionStopReason::tail_candidate: return "tail-candidate";
    case FunctionStopReason::elf_relocation: return "elf-relocation";
    case FunctionStopReason::macho_relocation: return "macho-relocation";
    case FunctionStopReason::macho_dyld: return "macho-dyld";
    case FunctionStopReason::image_exclusion: return "image-exclusion";
    }
    return "unknown";
}

int functions_report(const DocumentSnapshot &document, const std::filesystem::path &input,
                     const AnalysisOptions &options, std::size_t limit, bool json,
                     std::ostream &out, std::ostream &err) {
    auto recovered = recover_functions(*document.image, document.metadata, {}, options, {});
    if (!recovered) {
        err << "Function recovery: " << recovered.error().message << '\n';
        return 1;
    }
    const auto &snapshot = *recovered.value();
    const auto count = (std::min)(limit, snapshot.functions.size());
    std::map<std::uint64_t, const BasicBlock *> blocks;
    for (const auto &block : snapshot.blocks)
        if (block) blocks.emplace(block->id.value, block.get());
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::vector<std::string>> names;
    for (const auto &symbol : document.metadata.exports)
        if (symbol.address && symbol.name)
            names[{symbol.address->space.value, symbol.address->offset}].push_back(*symbol.name);
    std::map<std::uint64_t, std::vector<const FunctionCall *>> calls;
    for (const auto &call : snapshot.calls)
        calls[call.owner.value].push_back(&call);
    constexpr std::size_t per_function_detail_limit = 256;
    constexpr std::size_t call_detail_budget = 100000;
    std::size_t emitted_call_details = 0;
    if (json) {
        out << "{\"schema\":\"hexlab.function-inventory.v1\",\"input\":"
            << processor_inventory_json_string(path_text(input))
            << ",\"complete\":" << (snapshot.complete ? "true" : "false")
            << ",\"function_count\":" << snapshot.functions.size()
            << ",\"returned_count\":" << count
            << ",\"truncated\":" << (count < snapshot.functions.size() ? "true" : "false")
            << ",\"functions\":[";
    } else {
        out << "Functions: " << snapshot.functions.size()
            << (snapshot.complete ? " recovered" : " recovered (analysis partial)")
            << "; showing " << count << "\n";
    }
    for (std::size_t index = 0; index < count; ++index) {
        const auto &function = *snapshot.functions[index];
        std::uint64_t instruction_count = 0;
        for (const auto id : function.blocks) {
            const auto found = blocks.find(id.value);
            if (found != blocks.end()) instruction_count += found->second->instructions.size();
        }
        const auto function_name = names.find({function.entry.space.value, function.entry.offset});
        const auto call_group = calls.find(function.id.value);
        const std::size_t call_count = call_group == calls.end() ? 0 : call_group->second.size();
        if (json) {
            if (index) out << ',';
            out << "{\"id\":" << function.id.value << ",\"entry\":"
                << processor_inventory_json_string(format_location(function.entry, document.image.get()))
                << ",\"name\":";
            if (function_name == names.end() || function_name->second.empty()) out << "null";
            else out << processor_inventory_json_string(safe_text(function_name->second.front()));
            out << ",\"complete\":" << (function.complete ? "true" : "false")
                << ",\"thunk\":" << (function.thunk ? "true" : "false")
                << ",\"block_count\":" << function.blocks.size()
                << ",\"instruction_count\":" << instruction_count << ",\"chunks\":[";
            const auto chunk_count = (std::min)(per_function_detail_limit, function.chunks.size());
            for (std::size_t chunk_index = 0; chunk_index < chunk_count; ++chunk_index) {
                if (chunk_index) out << ',';
                const auto &chunk = function.chunks[chunk_index];
                out << "{\"begin\":" << processor_inventory_json_string(format_location(chunk.begin, document.image.get()))
                    << ",\"size\":" << chunk.size << ",\"block_count\":" << chunk.blocks.size() << '}';
            }
            out << "],\"chunks_total\":" << function.chunks.size()
                << ",\"chunks_omitted\":" << function.chunks.size() - chunk_count << ",\"seeds\":[";
            const auto seed_count = (std::min)(per_function_detail_limit, function.seeds.size());
            for (std::size_t seed_index = 0; seed_index < seed_count; ++seed_index) {
                if (seed_index) out << ',';
                out << processor_inventory_json_string(function_seed_name(function.seeds[seed_index].kind));
            }
            out << "],\"seeds_total\":" << function.seeds.size()
                << ",\"seeds_omitted\":" << function.seeds.size() - seed_count << ",\"stops\":[";
            const auto stop_count = (std::min)(per_function_detail_limit, function.stops.size());
            for (std::size_t stop_index = 0; stop_index < stop_count; ++stop_index) {
                if (stop_index) out << ',';
                const auto &stop = function.stops[stop_index];
                out << "{\"address\":" << processor_inventory_json_string(format_location(stop.address, document.image.get()))
                    << ",\"reason\":" << processor_inventory_json_string(function_stop_name(stop.reason))
                    << ",\"detail\":" << processor_inventory_json_string(safe_text(stop.detail)) << '}';
            }
            out << "],\"stops_total\":" << function.stops.size()
                << ",\"stops_omitted\":" << function.stops.size() - stop_count << ",\"calls\":[";
            const auto call_detail_count = (std::min)(call_count, call_detail_budget - emitted_call_details);
            if (call_group != calls.end()) {
                for (std::size_t call_index = 0; call_index < call_detail_count; ++call_index) {
                    if (call_index) out << ',';
                    const auto &call = *call_group->second[call_index];
                    out << "{\"source\":" << processor_inventory_json_string(format_location(call.source, document.image.get()))
                        << ",\"target\":";
                    if (call.target) out << processor_inventory_json_string(format_location(*call.target, document.image.get()));
                    else out << "null";
                    out << ",\"callee_id\":";
                    if (call.callee) out << call.callee->value;
                    else out << "null";
                    out << ",\"tail_candidate\":" << (call.tail_candidate ? "true" : "false")
                        << ",\"external\":";
                    if (call.external_target) {
                        out << "{\"library\":" << processor_inventory_json_string(safe_text(call.external_target->library))
                            << ",\"name\":";
                        if (call.external_target->name)
                            out << processor_inventory_json_string(safe_text(*call.external_target->name));
                        else out << "null";
                        out << ",\"ordinal\":";
                        if (call.external_target->ordinal) out << *call.external_target->ordinal;
                        else out << "null";
                        out << ",\"wasm_function_index\":";
                        if (call.external_target->wasm_function_index) out << *call.external_target->wasm_function_index;
                        else out << "null";
                        out << ",\"host_binding\":";
                        if (call.external_target->host_binding)
                            out << processor_inventory_json_string(safe_text(*call.external_target->host_binding));
                        else out << "null";
                        out << '}';
                    } else out << "null";
                    out << '}';
                }
            }
            emitted_call_details += call_detail_count;
            out << "],\"calls_total\":" << call_count
                << ",\"calls_omitted\":" << call_count - call_detail_count << "}";
        } else {
            out << "  " << format_location(function.entry, document.image.get());
            if (function_name != names.end() && !function_name->second.empty())
                out << "  " << safe_text(function_name->second.front());
            out << "  blocks=" << function.blocks.size() << " instructions=" << instruction_count
                << " chunks=" << function.chunks.size() << " calls=" << call_count
                << (function.thunk ? " thunk" : "") << (function.complete ? " complete" : " partial") << '\n';
        }
    }
    if (json) {
        out << "]}\n";
    } else if (count < snapshot.functions.size()) {
        out << "  " << snapshot.functions.size() - count << " function(s) omitted by --limit\n";
    }
    return snapshot.complete && count == snapshot.functions.size() && !snapshot.functions.empty() ? 0 : 3;
}

int modules_command(std::span<const std::wstring_view> arguments, std::ostream &out, std::ostream &err) {
    std::optional<std::filesystem::path> sysroot;
    std::optional<std::filesystem::path> target_working_directory;
    std::string lib_token, platform_token;
    std::vector<std::filesystem::path> discovery_directories;
    bool graph_mode = false, discover = false;
    std::size_t option_count = 0;
    while (option_count < arguments.size()) {
        const auto option = arguments[option_count];
        if (option == L"--") { ++option_count; break; }
        if (option == L"--graph") graph_mode = true;
        else if (option == L"--discover") discover = true;
        else if (option == L"--sysroot" || option == L"--search-dir" || option == L"--target-cwd" ||
                 option == L"--lib-token" || option == L"--platform-token") {
            if (++option_count == arguments.size()) {
                err << "Missing module discovery option value.\n"; return 2;
            }
            if (option == L"--sysroot") sysroot = std::filesystem::path(arguments[option_count]);
            else if (option == L"--target-cwd") target_working_directory = std::filesystem::path(arguments[option_count]);
            else if (option == L"--lib-token" || option == L"--platform-token") {
                std::string value;
                for (const auto c : arguments[option_count]) {
                    if (c < 0 || c > 0x7f) {
                        err << "ELF loader token values must contain ASCII path characters.\n"; return 2;
                    }
                    value.push_back(static_cast<char>(c));
                }
                (option == L"--lib-token" ? lib_token : platform_token) = std::move(value);
            } else {
                if (discovery_directories.size() >= 128) {
                    err << "Module discovery accepts at most 128 explicit search directories.\n"; return 2;
                }
                discovery_directories.emplace_back(arguments[option_count]);
            }
        } else break;
        ++option_count;
    }
    const auto inputs = arguments.subspan(option_count);
    if ((graph_mode && inputs.empty()) || (!graph_mode && inputs.size() < 2)) {
        err << "Usage: hexlab_cli modules [--sysroot <directory>] [--discover] [--search-dir <directory>] [--target-cwd <directory>] [--lib-token <value>] [--platform-token <value>] [--graph] <binary>...\n"
               "       Graph mode starts at the first binary. Discovery requires --graph and --sysroot.\n";
        return 2;
    }
    if ((sysroot && !graph_mode) || (discover && (!graph_mode || !sysroot)) ||
        (!discovery_directories.empty() && !discover) ||
        ((target_working_directory || !lib_token.empty() || !platform_token.empty()) && !discover)) {
        err << "--discover requires --graph and --sysroot; --search-dir and target path substitutions require --discover.\n";
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
    const auto elf_soname_alias = [&](const Module &module) -> std::optional<std::string> {
        const auto &metadata = module.document->metadata.elf;
        if (!metadata) return {};
        bool conflicting_sonames = false;
        std::optional<std::string> alias;
        for (const auto &table : metadata->dynamic_tables) {
            for (const auto &entry : table.entries) {
                if (entry.tag != 14 || !entry.string_value || entry.string_value->empty() ||
                    entry.string_value->size() > 32768 ||
                    entry.string_value->find_first_of("/\\:") != std::string::npos ||
                    entry.string_value->find('\0') != std::string::npos)
                    continue;
                auto candidate = leaf(*entry.string_value);
                if (candidate.empty()) continue;
                if (alias && *alias != candidate) {
                    conflicting_sonames = true;
                    break;
                }
                alias = std::move(candidate);
            }
            if (conflicting_sonames) break;
        }
        return conflicting_sonames ? std::optional<std::string>{} : alias;
    };
    std::vector<std::optional<std::string>> elf_soname_aliases;
    elf_soname_aliases.reserve(modules.size());
    for (const auto &module : modules) elf_soname_aliases.push_back(elf_soname_alias(module));
    auto path_key = [](const std::filesystem::path &path) {
        auto value = path.lexically_normal().generic_string();
#ifdef _WIN32
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
#endif
        return value;
    };
    std::optional<std::filesystem::path> canonical_sysroot;
    if (sysroot) {
        std::error_code ec;
        canonical_sysroot = std::filesystem::canonical(*sysroot, ec);
        if (ec || !std::filesystem::is_directory(*canonical_sysroot)) {
            err << "Invalid --sysroot directory: " << path_text(*sysroot) << '\n';
            return 2;
        }
    }
    ElfDependencyPathContext path_context;
    path_context.target_working_directory = target_working_directory;
    path_context.lib_token = lib_token;
    path_context.platform_token = platform_token;
    auto is_under_root = [](const std::filesystem::path &candidate, const std::filesystem::path &root) {
        auto c = candidate.begin(), r = root.begin();
        for (; r != root.end(); ++r, ++c) {
            if (c == candidate.end()) return false;
#ifdef _WIN32
            auto left = c->wstring(), right = r->wstring();
            std::transform(left.begin(), left.end(), left.begin(), ::towlower);
            std::transform(right.begin(), right.end(), right.begin(), ::towlower);
            if (left != right) return false;
#else
            if (*c != *r) return false;
#endif
        }
        return true;
    };
    struct DiscoveredDependency {
        std::vector<std::size_t> providers;
        std::size_t unsupported_paths = 0, escaped_paths = 0, incompatible_files = 0, filesystem_errors = 0;
        bool depth_limited = false;
        bool inherited_path_context_conflict = false;
        bool weak_dependency = false;
        std::string dependency_kind;
    };
    std::map<std::size_t, std::map<std::string, DiscoveredDependency>> discovered_dependencies;
    const auto supplied_count = modules.size();
    if (discover && !modules.front().document->metadata.elf && !modules.front().document->metadata.macho) {
        err << "Filesystem dependency discovery currently requires an ELF or Mach-O root.\n";
        return 2;
    }
    if (discover && modules.front().document->metadata.elf) {
        std::map<std::string, std::size_t> module_ids;
        std::map<std::string, std::shared_ptr<const DocumentSnapshot>> loaded_files;
        for (std::size_t index = 0; index < modules.size(); ++index) {
            std::error_code ec;
            const auto canonical = std::filesystem::canonical(modules[index].path, ec);
            if (!ec) {
                const auto key = path_key(canonical);
                module_ids.try_emplace(key, index);
                loaded_files.try_emplace(key, modules[index].document);
            }
        }
        ElfDependencyDiscoveryLimits remaining;
        struct PendingModule {
            std::size_t index = 0, depth = 0;
            std::vector<ElfDependencyFileCandidate> inherited_rpath;
            std::size_t inherited_unsupported_rpath = 0;
        };
        std::vector<PendingModule> pending{{0, 0, {}, 0}};
        std::set<std::size_t> queued{0};
        std::map<std::size_t, std::vector<ElfDependencyFileCandidate>> inherited_contexts{{0, {}}};
        std::map<std::size_t, std::size_t> inherited_unsupported_contexts{{0, 0}};
        std::set<std::size_t> inherited_context_conflicts;
        const auto same_inherited_context = [&](const auto &left, const auto &right,
                                                std::size_t left_unsupported,
                                                std::size_t right_unsupported) {
            if (left_unsupported != right_unsupported) return false;
            if (left.size() != right.size()) return false;
            for (std::size_t i = 0; i < left.size(); ++i)
                if (path_key(left[i].path) != path_key(right[i].path) ||
                    left[i].search_entry_file_offset != right[i].search_entry_file_offset)
                    return false;
            return true;
        };
        out << "ELF sysroot file discovery (all compatible candidates retained):\n";
        for (std::size_t cursor = 0; cursor < pending.size(); ++cursor) {
            const auto current = pending[cursor];
            const auto source = current.index;
            const auto depth = current.depth;
            const auto source_document = modules[source].document;
            const auto &metadata = source_document->metadata.elf;
            if (!metadata) continue;
            auto current_path_context = path_context;
            current_path_context.inherited_rpath = current.inherited_rpath;
            current_path_context.inherited_unsupported_rpath = current.inherited_unsupported_rpath;
            auto found = discover_elf_dependency_files(*metadata, modules[source].path,
                *canonical_sysroot, discovery_directories, remaining, {}, current_path_context);
            if (!found) { err << path_text(modules[source].path) << ": " << found.error().message << '\n'; return 1; }
            const auto &report = found.value();
            remaining.dependency_rows -= report.raw_dependency_rows;
            remaining.metadata_entries -= report.metadata_entries;
            remaining.name_bytes -= report.name_bytes;
            remaining.path_bytes -= report.path_bytes;
            remaining.probes -= report.probes;
            remaining.candidates -= report.candidates;
            for (const auto &row : report.rows) {
                const auto tag_name = row.kind == ElfDependencyFileRow::Kind::auxiliary ? "DT_AUXILIARY"
                    : row.kind == ElfDependencyFileRow::Kind::filter ? "DT_FILTER" : "DT_NEEDED";
                out << "  [" << source << "] " << row.name << ' ' << tag_name << " @file:"
                    << hex(row.dynamic_entry_file_offset) << '\n';
                if (row.kind != ElfDependencyFileRow::Kind::needed) {
                    for (const auto &candidate : row.candidates)
                        out << "    inventory candidate " << path_text(candidate.path) << '\n';
                    if (row.candidates.empty())
                        out << "    no sysroot candidate (unsupported=" << row.unsupported_paths
                            << ", escaped=" << row.escaped_paths << ", filesystem-errors="
                            << row.filesystem_errors << ")\n";
                    continue;
                }
                auto &resolution = discovered_dependencies[source][row.name];
                resolution.unsupported_paths = row.unsupported_paths;
                resolution.escaped_paths = row.escaped_paths;
                resolution.filesystem_errors = row.filesystem_errors;
                for (const auto &candidate : row.candidates) {
                    const auto key = path_key(candidate.path);
                    auto loaded = loaded_files.find(key);
                    if (loaded == loaded_files.end()) {
                        if (depth + 1 >= max_graph_depth) { resolution.depth_limited = true; continue; }
                        if (loaded_files.size() >= max_graph_modules) {
                            err << "Dependency discovery exceeds 4096 distinct inspected files.\n"; return 2;
                        }
                        OpenRequest request;
                        request.path = candidate.path;
                        request.run_analysis = false;
                        auto document = load_document(request, {{loaded_files.size()}, 1}, {});
                        if (!document) { err << path_text(candidate.path) << ": " << document.error().message << '\n'; return 1; }
                        loaded = loaded_files.emplace(key, document.value()).first;
                    }
                    const auto &provider = loaded->second->metadata.elf;
                    const auto incompatibility = provider ? elf_abi_incompatibility(metadata->header, provider->header)
                        : std::optional<std::string>{"candidate is not ELF"};
                    if (incompatibility) {
                        ++resolution.incompatible_files;
                        out << "    rejected " << path_text(candidate.path) << ": " << *incompatibility << '\n';
                        continue;
                    }
                    auto id = module_ids.find(key);
                    if (id == module_ids.end()) {
                        if (depth + 1 >= max_graph_depth) { resolution.depth_limited = true; continue; }
                        if (modules.size() >= max_graph_modules) {
                            err << "Dependency discovery exceeds 4096 graph modules.\n"; return 2;
                        }
                        id = module_ids.emplace(key, modules.size()).first;
                        modules.push_back({candidate.path, loaded->second});
                    }
                    resolution.providers.push_back(id->second);
                    const char *via = candidate.source == ElfDependencyPathSource::needed_path ? "DT_NEEDED path" :
                        candidate.source == ElfDependencyPathSource::runpath ? "DT_RUNPATH" :
                        candidate.source == ElfDependencyPathSource::rpath ? "DT_RPATH" :
                        candidate.source == ElfDependencyPathSource::inherited_rpath ? "inherited DT_RPATH" :
                        "--search-dir";
                    out << "    [" << id->second << "] " << path_text(candidate.path) << " via " << via;
                    if (candidate.search_entry_file_offset) out << " @file:" << hex(*candidate.search_entry_file_offset);
                    out << '\n';
                }
                std::sort(resolution.providers.begin(), resolution.providers.end());
                resolution.providers.erase(std::unique(resolution.providers.begin(), resolution.providers.end()),
                    resolution.providers.end());
                // Expand only an unambiguous edge; selecting among competing
                // providers would invent a link map. All candidates remain visible.
                if (resolution.providers.size() == 1 && depth + 1 < max_graph_depth) {
                    const auto provider_id = resolution.providers.front();
                    auto child_context = current.inherited_rpath;
                    for (const auto &directory : report.inherited_rpath) {
                        const bool duplicate = std::any_of(child_context.begin(), child_context.end(),
                            [&](const auto &prior) {
                                return path_key(prior.path) == path_key(directory.path) &&
                                       prior.search_entry_file_offset == directory.search_entry_file_offset;
                            });
                        if (!duplicate) child_context.push_back(directory);
                    }
                    const auto child_unsupported_rpath = report.inherited_unsupported_rpath;
                    if (queued.insert(provider_id).second) {
                        inherited_contexts.emplace(provider_id, child_context);
                        inherited_unsupported_contexts.emplace(provider_id, child_unsupported_rpath);
                        pending.push_back({provider_id, depth + 1, std::move(child_context),
                                           child_unsupported_rpath});
                    } else if (const auto prior = inherited_contexts.find(provider_id);
                               prior != inherited_contexts.end() &&
                               !same_inherited_context(prior->second, child_context,
                                   inherited_unsupported_contexts.at(provider_id), child_unsupported_rpath)) {
                        inherited_context_conflicts.insert(provider_id);
                    }
                }
            }
        }
        for (const auto source : inherited_context_conflicts)
            for (auto &[name, resolution] : discovered_dependencies[source]) {
                (void)name;
                resolution.inherited_path_context_conflict = true;
            }
        out << "Discovered " << modules.size() - supplied_count << " additional ELF modules; "
            << 100000 - remaining.probes << " exact file probes; "
            << inherited_context_conflicts.size() << " modules had distinct inherited RPATH contexts.\n";
    }
    if (discover && modules.front().document->metadata.macho) {
        std::map<std::string, std::size_t> module_ids;
        std::map<std::string, std::shared_ptr<const DocumentSnapshot>> loaded_files;
        for (std::size_t index = 0; index < modules.size(); ++index) {
            std::error_code ec;
            const auto canonical = std::filesystem::canonical(modules[index].path, ec);
            if (!ec) {
                const auto key = path_key(canonical);
                module_ids.try_emplace(key, index);
                loaded_files.try_emplace(key, modules[index].document);
            }
        }
        const auto root_macho = modules.front().document->metadata.macho;
        if (!root_macho || root_macho->selected_slice >= root_macho->container.slices.size()) {
            err << "Mach-O root has no selected architecture slice.\n"; return 2;
        }
        const auto root_header = root_macho->container.slices[root_macho->selected_slice].header;
        MachODependencyDiscoveryLimits remaining;
        struct PendingMachO { std::size_t index = 0, depth = 0; MachODependencyPathContext context; };
        MachODependencyPathContext root_context;
        if (root_header.file_type == 2) root_context.executable_path = modules.front().path;
        std::vector<PendingMachO> pending{{0, 0, root_context}};
        std::set<std::size_t> queued{0};
        std::map<std::size_t, MachODependencyPathContext> prior_contexts{{0, root_context}};
        std::set<std::size_t> context_conflicts;
        out << "Mach-O sysroot file discovery (all compatible candidates retained):\n";
        constexpr std::uint32_t lc_load_weak_dylib = 0x80000018;
        constexpr std::uint32_t lc_reexport_dylib = 0x8000001f;
        constexpr std::uint32_t lc_load_upward_dylib = 0x80000023;
        auto same_context = [&](const MachODependencyPathContext &a, const MachODependencyPathContext &b) {
            if (a.executable_path != b.executable_path || a.inherited_unsupported_rpaths != b.inherited_unsupported_rpaths ||
                a.inherited_rpaths.size() != b.inherited_rpaths.size()) return false;
            for (std::size_t i = 0; i < a.inherited_rpaths.size(); ++i)
                if (path_key(a.inherited_rpaths[i].path) != path_key(b.inherited_rpaths[i].path) ||
                    a.inherited_rpaths[i].command_file_offset != b.inherited_rpaths[i].command_file_offset) return false;
            return true;
        };
        for (std::size_t cursor = 0; cursor < pending.size(); ++cursor) {
            const auto current = pending[cursor];
            const auto source = current.index;
            const auto source_macho = modules[source].document->metadata.macho;
            if (!source_macho) continue;
            auto found = discover_macho_dependency_files(*source_macho, modules[source].path,
                *canonical_sysroot, current.context, remaining);
            if (!found) { err << path_text(modules[source].path) << ": " << found.error().message << '\n'; return 1; }
            const auto &report = found.value();
            remaining.dependency_rows -= report.rows.size();
            remaining.metadata_entries -= report.metadata_entries;
            remaining.name_bytes -= report.name_bytes;
            remaining.path_bytes -= report.path_bytes;
            remaining.probes -= report.probes;
            remaining.candidates -= report.candidates;
            remaining.rpaths -= report.inherited_rpaths.size() - current.context.inherited_rpaths.size();
            for (const auto &row : report.rows) {
                auto &resolution = discovered_dependencies[source][row.name];
                resolution.unsupported_paths = row.unsupported_paths;
                resolution.escaped_paths = row.escaped_paths;
                resolution.filesystem_errors = row.filesystem_errors;
                resolution.weak_dependency = row.load_command == lc_load_weak_dylib;
                resolution.dependency_kind = row.load_command == lc_load_weak_dylib ? "LC_LOAD_WEAK_DYLIB" :
                    row.load_command == lc_reexport_dylib ? "LC_REEXPORT_DYLIB" :
                    row.load_command == lc_load_upward_dylib ? "LC_LOAD_UPWARD_DYLIB" : "LC_LOAD_DYLIB";
                out << "  [" << source << "] " << row.name << " " << resolution.dependency_kind
                    << " command[" << row.load_command_index << "] @file:" << hex(row.load_command_file_offset) << '\n';
                for (const auto &candidate : row.candidates) {
                    const auto key = path_key(candidate.path);
                    auto loaded = loaded_files.find(key);
                    if (loaded == loaded_files.end()) {
                        if (current.depth + 1 >= max_graph_depth) { resolution.depth_limited = true; continue; }
                        if (loaded_files.size() >= max_graph_modules) { err << "Dependency discovery exceeds 4096 distinct inspected files.\n"; return 2; }
                        OpenRequest request; request.path = candidate.path; request.run_analysis = false;
                        auto document = load_document(request, {{loaded_files.size()}, 1}, {});
                        if (!document) { err << path_text(candidate.path) << ": " << document.error().message << '\n'; return 1; }
                        loaded = loaded_files.emplace(key, document.value()).first;
                    }
                    const auto &provider = loaded->second->metadata.macho;
                    if (!provider || provider->selected_slice >= provider->container.slices.size()) {
                        ++resolution.incompatible_files; out << "    rejected " << path_text(candidate.path) << ": not a selected Mach-O slice\n"; continue;
                    }
                    auto selected_provider = loaded->second;
                    const auto &provider_header = provider->container.slices[provider->selected_slice].header;
                    if (provider_header.cpu_type != root_header.cpu_type || provider_header.cpu_subtype != root_header.cpu_subtype) {
                        std::optional<std::uint32_t> compatible_slice;
                        for (const auto &slice : provider->container.slices)
                            if (slice.header.cpu_type == root_header.cpu_type && slice.header.cpu_subtype == root_header.cpu_subtype) {
                                compatible_slice = slice.index; break;
                            }
                        if (!compatible_slice) {
                            ++resolution.incompatible_files; out << "    rejected " << path_text(candidate.path) << ": CPU type/subtype mismatch\n"; continue;
                        }
                        OpenRequest request; request.path = candidate.path; request.run_analysis = false;
                        request.macho = MachOOptions{*compatible_slice};
                        auto document = load_document(request, {{loaded_files.size()}, 1}, {});
                        if (!document || !document.value()->metadata.macho) {
                            ++resolution.incompatible_files; out << "    rejected " << path_text(candidate.path) << ": matching slice could not be loaded\n"; continue;
                        }
                        selected_provider = document.value();
                        loaded->second = selected_provider;
                    }
                    auto id = module_ids.find(key);
                    if (id == module_ids.end()) {
                        if (current.depth + 1 >= max_graph_depth) { resolution.depth_limited = true; continue; }
                        if (modules.size() >= max_graph_modules) { err << "Dependency discovery exceeds 4096 graph modules.\n"; return 2; }
                        id = module_ids.emplace(key, modules.size()).first;
                        modules.push_back({candidate.path, selected_provider});
                    } else if (id->second < modules.size()) {
                        // A supplied universal file may have been opened with a
                        // different default slice. Keep the graph node aligned
                        // with the root architecture selected above.
                        modules[id->second].document = selected_provider;
                    }
                    resolution.providers.push_back(id->second);
                    const auto via = candidate.source == MachODependencyPathSource::rpath ? "LC_RPATH" :
                        candidate.source == MachODependencyPathSource::loader_path ? "@loader_path" :
                        candidate.source == MachODependencyPathSource::executable_path ? "@executable_path" : "install name";
                    out << "    [" << id->second << "] " << path_text(candidate.path) << " via " << via;
                    if (candidate.rpath_command_file_offset) out << " rpath@file:" << hex(*candidate.rpath_command_file_offset);
                    out << '\n';
                }
                std::sort(resolution.providers.begin(), resolution.providers.end());
                resolution.providers.erase(std::unique(resolution.providers.begin(), resolution.providers.end()), resolution.providers.end());
                if (resolution.providers.size() == 1 && current.depth + 1 < max_graph_depth) {
                    const auto child = resolution.providers.front();
                    auto child_context = current.context;
                    child_context.inherited_rpaths = report.inherited_rpaths;
                    child_context.inherited_unsupported_rpaths = report.inherited_unsupported_rpaths;
                    if (queued.insert(child).second) {
                        prior_contexts.emplace(child, child_context);
                        pending.push_back({child, current.depth + 1, std::move(child_context)});
                    } else if (const auto previous = prior_contexts.find(child); previous != prior_contexts.end() &&
                               !same_context(previous->second, child_context)) context_conflicts.insert(child);
                }
            }
        }
        for (const auto source : context_conflicts)
            for (auto &[name, resolution] : discovered_dependencies[source]) { (void)name; resolution.inherited_path_context_conflict = true; }
        out << "Discovered " << modules.size() - supplied_count << " additional Mach-O modules; "
            << 100000 - remaining.probes << " exact file probes; " << context_conflicts.size()
            << " modules had distinct inherited LC_RPATH contexts.\n";
    }
    while (elf_soname_aliases.size() < modules.size())
        elf_soname_aliases.push_back(elf_soname_alias(modules[elf_soname_aliases.size()]));
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
    auto elf_search_paths = [](const ImageMetadata &metadata, bool &has_runpath) {
        std::vector<std::string> paths;
        has_runpath = false;
        if (!metadata.elf) return paths;
        std::vector<std::string> rpath, runpath;
        for (const auto &table : metadata.elf->dynamic_tables)
            for (const auto &entry : table.entries) {
                if (entry.tag == 15 && entry.string_value) rpath.push_back(*entry.string_value);
                if (entry.tag == 29 && entry.string_value) runpath.push_back(*entry.string_value);
            }
        has_runpath = !runpath.empty();
        const auto &selected = has_runpath ? runpath : rpath;
        for (const auto &item : selected) {
            std::size_t begin = 0;
            while (begin <= item.size()) {
                const auto end = item.find(':', begin);
                const auto length = (end == std::string::npos ? item.size() : end) - begin;
                if (length) paths.emplace_back(item.substr(begin, length));
                if (end == std::string::npos) break;
                begin = end + 1;
            }
        }
        return paths;
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
                for (std::size_t candidate_index = 0; candidate_index < modules.size(); ++candidate_index) {
                    const auto &candidate = modules[candidate_index];
                    if (&candidate == &module) continue;
                    const auto requested = leaf(dep);
                    const auto candidate_name = leaf(path_text(candidate.path));
                    const bool soname_match = candidate_name != requested && elf_soname_aliases[candidate_index] &&
                        *elf_soname_aliases[candidate_index] == requested;
                    if (candidate_name == requested || soname_match)
                        providers.push_back(path_text(candidate.path) +
                            (soname_match ? " (DT_SONAME alias)" : ""));
                }
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
            const DiscoveredDependency *discovery = nullptr;
            std::size_t incompatible_pe_providers = 0;
            bool soname_alias_match = false;
        };
        std::vector<std::vector<Edge>> graph(modules.size());
        std::size_t edge_count = 0;
        std::size_t raw_dependency_rows = 0;
        std::size_t dependency_name_bytes = 0;
        std::map<std::string, std::vector<std::size_t>> providers_by_basename;
        std::map<std::string, std::set<std::string>> provider_paths_by_basename;
        std::map<std::string, std::size_t> supplied_by_canonical_path;
        std::vector<std::unique_ptr<std::vector<std::size_t>>> path_buckets;
        for (std::size_t candidate = 0; candidate < modules.size(); ++candidate) {
            const auto normalized_path = path_key(modules[candidate].path);
            const auto add_provider_alias = [&](const std::string &alias) {
                if (provider_paths_by_basename[alias].insert(normalized_path).second)
                    providers_by_basename[alias].push_back(candidate);
            };
            add_provider_alias(leaf(path_text(modules[candidate].path)));
            if (elf_soname_aliases[candidate]) add_provider_alias(*elf_soname_aliases[candidate]);
            if (canonical_sysroot) {
                std::error_code ec;
                auto canonical = std::filesystem::canonical(modules[candidate].path, ec);
                if (!ec && is_under_root(canonical, *canonical_sysroot))
                    supplied_by_canonical_path[path_key(canonical)] = candidate;
            }
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
                bool path_resolution_authoritative = false;
                if (discover && (modules[source].document->metadata.elf || modules[source].document->metadata.macho)) {
                    path_resolution_authoritative = true;
                    const auto importer = discovered_dependencies.find(source);
                    if (importer != discovered_dependencies.end()) {
                        const auto found = importer->second.find(edge.name);
                        if (found != importer->second.end()) {
                            edge.discovery = &found->second;
                            edge.providers = &found->second.providers;
                        }
                    }
                }
                if (!discover && canonical_sysroot && modules[source].document->metadata.elf) {
                    bool has_runpath = false;
                    const auto search_paths = elf_search_paths(modules[source].document->metadata, has_runpath);
                    std::vector<std::size_t> path_matches;
                    std::error_code ec;
                    const auto importer_path = std::filesystem::canonical(modules[source].path, ec);
                    if (!ec && is_under_root(importer_path, *canonical_sysroot)) {
                        path_resolution_authoritative = !search_paths.empty();
                        for (auto directory : search_paths) {
                            constexpr std::string_view origin1 = "${ORIGIN}", origin2 = "$ORIGIN";
                            const auto origin = importer_path.parent_path();
                            for (std::size_t at = 0; (at = directory.find(origin1, at)) != std::string::npos;)
                                directory.replace(at, origin1.size(), origin.generic_string());
                            for (std::size_t at = 0; (at = directory.find(origin2, at)) != std::string::npos;)
                                directory.replace(at, origin2.size(), origin.generic_string());
                            // Only origin-relative entries are currently interpreted; other loader tokens
                            // and ambient paths are deliberately not searched.
                            if (directory.find('$') != std::string::npos) continue;
                            auto path = std::filesystem::path(directory);
                            if (path.is_relative()) path = origin / path;
                            auto candidate_path = std::filesystem::canonical(path / std::filesystem::path(dep), ec);
                            if (ec) { ec.clear(); continue; }
                            if (!is_under_root(candidate_path, *canonical_sysroot)) continue;
                            const auto found = supplied_by_canonical_path.find(path_key(candidate_path));
                            if (found != supplied_by_canonical_path.end()) path_matches.push_back(found->second);
                        }
                    }
                    if (!path_matches.empty()) {
                        std::sort(path_matches.begin(), path_matches.end());
                        path_matches.erase(std::unique(path_matches.begin(), path_matches.end()), path_matches.end());
                        // A path match is authoritative; ambiguity is retained in the graph.
                        path_buckets.push_back(std::make_unique<std::vector<std::size_t>>(std::move(path_matches)));
                        edge.providers = path_buckets.back().get();
                    } else if (path_resolution_authoritative) {
                        // A declared bounded search path takes precedence over basename matching.
                        edge.providers = nullptr;
                    }
                }
                const auto providers = providers_by_basename.find(leaf(edge.name));
                if (!edge.providers && providers != providers_by_basename.end() &&
                    !path_resolution_authoritative) {
                    for (const auto candidate : providers->second)
                        if (leaf(path_text(modules[candidate].path)) != leaf(edge.name) &&
                            elf_soname_aliases[candidate] && *elf_soname_aliases[candidate] == leaf(edge.name))
                            edge.soname_alias_match = true;
                    if (is_pe_module(modules[source].document->metadata)) {
                        std::vector<std::size_t> compatible;
                        for (const auto candidate : providers->second) {
                            const auto compatibility = classify_pe_module_compatibility(
                                modules[source].document->metadata, modules[candidate].document->metadata);
                            if (compatibility == PeModuleCompatibility::compatible)
                                compatible.push_back(candidate);
                            else
                                ++edge.incompatible_pe_providers;
                        }
                        if (!compatible.empty()) {
                            path_buckets.push_back(std::make_unique<std::vector<std::size_t>>(std::move(compatible)));
                            edge.providers = path_buckets.back().get();
                        }
                    } else {
                        edge.providers = &providers->second;
                    }
                }
                graph[source].push_back(std::move(edge));
            }
        }

        out << "Recursive dependency graph (" << (discover ? "supplied and discovered files" : "only supplied files")
            << "; maximum depth " << max_graph_depth << ")\n";
        out << (discover ? "Node identities (supplied input order, then discovery order):\n"
                         : "Supplied node identities (input order):\n");
        std::map<std::string, std::size_t> first_path;
        std::map<std::string, std::size_t> first_basename;
        for (std::size_t index = 0; index < modules.size(); ++index) {
            const auto key = path_key(modules[index].path);
            const auto basename = leaf(path_text(modules[index].path));
            out << "  [" << index << "] " << path_text(modules[index].path);
            if (index >= supplied_count) out << " (discovered)";
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
        struct GraphDiagnostics {
            std::size_t unresolved = 0, weak_unresolved = 0, ambiguous = 0;
            std::size_t partial_search = 0, unsupported_paths = 0, escaped_paths = 0;
            std::size_t filesystem_errors = 0, incompatible_providers = 0;
            std::size_t depth_limited_rows = 0, cycles = 0, already_expanded = 0;
        } diagnostics;
        std::function<void(std::size_t, std::size_t)> visit = [&](std::size_t current, std::size_t depth) {
            color[current] = 1;
            ++expanded;
            if (graph[current].empty())
                out << std::string((depth + 1) * 2, ' ') << "(no dependency names in parsed metadata)\n";
            for (const auto &edge : graph[current]) {
                const bool partial_search = edge.discovery &&
                    (edge.discovery->unsupported_paths || edge.discovery->escaped_paths ||
                     edge.discovery->filesystem_errors || edge.discovery->inherited_path_context_conflict);
                if (partial_search) ++diagnostics.partial_search;
                if (edge.discovery) {
                    diagnostics.unsupported_paths += edge.discovery->unsupported_paths;
                    diagnostics.escaped_paths += edge.discovery->escaped_paths;
                    diagnostics.filesystem_errors += edge.discovery->filesystem_errors;
                }
                diagnostics.incompatible_providers += edge.incompatible_pe_providers;
                if (edge.discovery) diagnostics.incompatible_providers += edge.discovery->incompatible_files;
                if ((edge.discovery && edge.discovery->depth_limited) ||
                    (edge.providers && edge.providers->size() == 1 && depth + 1 >= max_graph_depth))
                    ++diagnostics.depth_limited_rows;
                out << std::string((depth + 1) * 2, ' ') << edge.name;
                if (edge.soname_alias_match) out << " (DT_SONAME alias)";
                if (edge.discovery && (edge.discovery->unsupported_paths || edge.discovery->escaped_paths ||
                                       edge.discovery->filesystem_errors ||
                                       edge.discovery->inherited_path_context_conflict))
                    out << " (partial search" << (edge.discovery->dependency_kind.empty() ? "" : ", " + edge.discovery->dependency_kind)
                        << ": " << edge.discovery->unsupported_paths << " unsupported paths, "
                        << edge.discovery->filesystem_errors << " filesystem errors"
                        << (edge.discovery->inherited_path_context_conflict
                                ? (modules[current].document->metadata.macho ? ", distinct inherited LC_RPATH contexts; first path retained" :
                                   ", distinct inherited DT_RPATH contexts; first path retained") : "")
                        << ")";
                out << " -> ";
                if (!edge.providers || edge.providers->empty()) {
                    ++diagnostics.unresolved;
                    if (discover && edge.discovery && edge.discovery->weak_dependency)
                        ++diagnostics.weak_unresolved;
                    out << (discover ? (edge.discovery && edge.discovery->weak_dependency
                        ? "unresolved weak dependency (no discovered provider)" : "unresolved (no discovered provider)")
                        : "unresolved (not supplied)");
                    if (edge.discovery) {
                        if (edge.discovery->unsupported_paths) out << "; unsupported search/path forms: " << edge.discovery->unsupported_paths;
                        if (edge.discovery->escaped_paths) out << "; sysroot escapes rejected: " << edge.discovery->escaped_paths;
                        if (edge.discovery->incompatible_files) out << "; incompatible files: " << edge.discovery->incompatible_files;
                        if (edge.discovery->filesystem_errors) out << "; filesystem errors: " << edge.discovery->filesystem_errors;
                        if (edge.discovery->depth_limited) out << "; discovery depth limit reached";
                        if (edge.discovery->inherited_path_context_conflict)
                            out << "; distinct inherited DT_RPATH contexts; first path retained";
                    } else if (discover) out << "; importer was not expanded";
                    if (edge.incompatible_pe_providers)
                        out << "; rejected incompatible PE providers: " << edge.incompatible_pe_providers;
                    out << '\n';
                    continue;
                }
                if (edge.providers->size() != 1) {
                    ++diagnostics.ambiguous;
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
                    ++diagnostics.cycles;
                    out << " (cycle)\n";
                    continue;
                }
                if (color[provider] == 2) {
                    ++diagnostics.already_expanded;
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
        out << "Expanded " << expanded << " of " << modules.size()
            << (discover ? " graph modules; " : " supplied modules; ")
            << edge_count << " dependency rows.\n";
        out << "Graph edge diagnostics (bounded by " << max_graph_edges << " rows): unresolved "
            << diagnostics.unresolved << " (weak " << diagnostics.weak_unresolved << "), ambiguous "
            << diagnostics.ambiguous << ", partial-search " << diagnostics.partial_search
            << " (unsupported paths " << diagnostics.unsupported_paths << ", sysroot escapes "
            << diagnostics.escaped_paths << ", filesystem errors " << diagnostics.filesystem_errors
            << "), incompatible providers " << diagnostics.incompatible_providers
            << ", depth-limited rows " << diagnostics.depth_limited_rows
            << ", cycles " << diagnostics.cycles << ", already expanded "
            << diagnostics.already_expanded << ".\n";
        if (expanded < modules.size()) {
            out << (discover ? "Some graph modules were not expanded because they are unreachable or ambiguous from the root"
                             : "Some supplied modules were not expanded because they are unreachable from the root");
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
int pe_dependency_files_command(std::span<const std::wstring_view> arguments,
                                std::ostream &out, std::ostream &err) {
    std::optional<std::filesystem::path> sysroot;
    std::vector<std::filesystem::path> search_directories;
    std::optional<std::filesystem::path> input;
    bool windows_defaults = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const auto argument = arguments[index];
        if (argument == L"--windows-defaults") {
            windows_defaults = true;
        } else if (argument == L"--sysroot" || argument == L"--search-dir") {
            if (++index == arguments.size()) {
                err << "Missing PE dependency option value.\n";
                return 2;
            }
            const std::filesystem::path value(arguments[index]);
            if (argument == L"--sysroot") {
                if (sysroot) { err << "--sysroot may be specified once.\n"; return 2; }
                sysroot = value;
            } else {
                if (search_directories.size() >= 128) {
                    err << "PE dependency discovery accepts at most 128 search directories.\n";
                    return 2;
                }
                search_directories.push_back(value);
            }
        } else if (argument.starts_with(L"--")) {
            err << "Unknown PE dependency option: " << wide_to_utf8(argument) << '\n';
            return 2;
        } else if (input) {
            err << "PE dependency discovery accepts one input image.\n";
            return 2;
        } else {
            input = std::filesystem::path(argument);
        }
    }
    if (!input || !sysroot) {
        err << "Usage: hexlab_cli pe-deps --sysroot <directory> [--search-dir <directory>] [--windows-defaults] <PE image>\n";
        return 2;
    }

    OpenRequest request;
    request.path = *input;
    request.format = Format::pe;
    request.run_analysis = false;
    auto document = load_document(request, {{0}, 1}, {});
    if (!document) {
        err << path_text(*input) << ": " << document.error().message << '\n';
        return 1;
    }
    if (!document.value()->metadata.pe) {
        err << path_text(*input) << ": PE metadata is unavailable.\n";
        return 1;
    }

    const auto target_bitness = document.value()->metadata.format == "PE32"
        ? PeDependencyTargetBitness::pe32
        : document.value()->metadata.format == "PE32+"
            ? PeDependencyTargetBitness::pe32_plus : PeDependencyTargetBitness::unspecified;
    auto report = discover_pe_dependency_files(document.value()->metadata.imports, *input, *sysroot, search_directories,
                                                {}, {}, windows_defaults, target_bitness);
    if (!report) {
        err << path_text(*input) << ": " << report.error().message << '\n';
        return 1;
    }
    for (const auto &row : report.value().rows) {
        out << row.name << " [" << (row.eager_load ? "eager" : "")
            << (row.eager_load && row.delay_load ? "," : "")
            << (row.delay_load ? "delay-load" : "") << "]:\n";
        if (row.candidates.empty()) out << "  unresolved\n";
        for (const auto &candidate : row.candidates) {
            out << "  [search rank " << candidate.precedence << "] " << path_text(candidate.path) << " via "
                << (candidate.source == PeDependencyPathSource::importer_directory
                        ? "importer directory" :
                    candidate.source == PeDependencyPathSource::explicit_directory ? "explicit search directory" :
                    candidate.source == PeDependencyPathSource::windows_system_directory ? "sysroot Windows/System32" :
                    candidate.source == PeDependencyPathSource::windows_wow64_system_directory ? "sysroot Windows/SysWOW64" :
                        "sysroot Windows directory");
            if (row.effective_precedence && candidate.precedence == *row.effective_precedence)
                out << " (effective rank)";
            else out << " (shadowed by an earlier rank)";
            out << '\n';
        }
        if (row.escaped_paths) out << "  rejected escaped paths: " << row.escaped_paths << '\n';
        if (row.filesystem_errors) out << "  filesystem errors: " << row.filesystem_errors << '\n';
    }
    out << "Scanned " << report.value().directory_entries << " entries; retained "
        << report.value().candidates << " candidate files.\n";
    return 0;
}

int plugin_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (args.size() == 1 && args[0] == L"--help") {
        out << "Usage: hexlab_cli plugins scan <directory> [--json] [--strict]\n"
               "       hexlab_cli plugins dependencies <directory> [--json] [--strict]\n"
               "Scans direct native plugin candidates and bounded .hexlab-plugin sidecars without loading modules.\n"
               "dependencies also reports advisory host/candidate/missing/ambiguous requirement providers.\n"
               "scan also reports duplicate manifest plugin IDs; --strict returns status 3 for duplicate IDs,\n"
               "malformed manifests, integrity failures, or unresolved requirements.\n";
        return 0;
    }
    const bool dependency_report = !args.empty() && args[0] == L"dependencies";
    if (args.size() < 2 || (args[0] != L"scan" && !dependency_report) || args.size() > 4) {
        err << "Usage: hexlab_cli plugins scan|dependencies <directory> [--json] [--strict]\n";
        return 2;
    }
    bool json = false;
    bool strict = false;
    for (std::size_t index = 2; index < args.size(); ++index) {
        if (args[index] == L"--json" && !json) json = true;
        else if (args[index] == L"--strict" && !strict) strict = true;
        else {
            err << "Plugin scan: unknown or duplicate option\n";
            return 2;
        }
    }
    try {
        const auto directory = path_from_wide(args[1]);
        plugins::PluginManager manager(plugins::make_native_module_provider());
        auto scanned = manager.scan_directory(path_text(directory), 4096);
        if (!scanned) {
            err << "Plugin scan: " << scanned.error().message << '\n';
            return 1;
        }
        std::map<std::string, std::vector<std::string>> duplicate_identity_paths;
        for (const auto &candidate : scanned.value())
            if (candidate.manifest)
                duplicate_identity_paths[candidate.manifest->id].push_back(candidate.path);
        for (auto it = duplicate_identity_paths.begin(); it != duplicate_identity_paths.end();) {
            if (it->second.size() < 2) it = duplicate_identity_paths.erase(it);
            else ++it;
        }
        auto write_duplicate_identities_json = [&]() {
            out << "\"duplicate_identities\":[";
            bool first_identity = true;
            for (const auto &[id, paths] : duplicate_identity_paths) {
                if (!first_identity) out << ',';
                first_identity = false;
                out << "{\"id\":" << json_quote(id) << ",\"paths\":[";
                for (std::size_t i = 0; i < paths.size(); ++i) {
                    if (i) out << ',';
                    out << json_quote(paths[i]);
                }
                out << "]}";
            }
            out << ']';
        };
        auto write_duplicate_identities_text = [&]() {
            for (const auto &[id, paths] : duplicate_identity_paths) {
                out << "Duplicate plugin identity " << id << ':';
                for (const auto &path : paths) out << " " << path;
                out << '\n';
            }
        };
        if (dependency_report) {
            struct RequirementRow {
                plugins::PluginInfo::VersionedCapability capability;
                std::string resolution;
                std::vector<std::pair<std::string, std::string>> providers;
                std::optional<std::size_t> candidate_provider;
                std::string provider_status = "not-applicable";
            };
            struct CandidateRow {
                const plugins::PluginCandidate *candidate = nullptr;
                std::vector<RequirementRow> requirements;
                std::string dependency_status = "ready";
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
                            for (std::size_t provider_index = 0; provider_index < scanned.value().size(); ++provider_index) {
                                const auto &provider = scanned.value()[provider_index];
                                if (!provider.manifest || provider.path == candidate.path) continue;
                                const auto &provider_manifest = *provider.manifest;
                                const auto capability = std::find_if(provider_manifest.capabilities.begin(),
                                    provider_manifest.capabilities.end(), [&](const auto &declared) {
                                        return declared.id == required.id &&
                                               declared.major_version == required.major_version &&
                                               declared.minor_version >= required.minor_version;
                                    });
                                if (capability != provider_manifest.capabilities.end()) {
                                    item.providers.emplace_back(provider_manifest.id, provider.path);
                                }
                            }
                            if (item.providers.size() == 1) {
                                item.resolution = "candidate";
                                item.candidate_provider = static_cast<std::size_t>(std::find_if(
                                    scanned.value().begin(), scanned.value().end(), [&](const auto &provider) {
                                        return provider.path == item.providers.front().second;
                                    }) - scanned.value().begin());
                            }
                            else if (item.providers.size() > 1) item.resolution = "ambiguous";
                        }
                        row.requirements.push_back(std::move(item));
                    }
                }
                report.push_back(std::move(row));
            }

            enum class DependencyState { ready, manifest_unavailable, unavailable, ambiguous, cycle, depth_limit };
            auto state_name = [](DependencyState state) -> const char * {
                switch (state) {
                case DependencyState::ready: return "ready";
                case DependencyState::manifest_unavailable: return "manifest_unavailable";
                case DependencyState::unavailable: return "unavailable";
                case DependencyState::ambiguous: return "ambiguous";
                case DependencyState::cycle: return "cycle";
                case DependencyState::depth_limit: return "depth_limit";
                }
                return "manifest_unavailable";
            };
            std::vector<std::uint8_t> visit_state(report.size(), 0);
            std::vector<DependencyState> dependency_states(report.size(), DependencyState::ready);
            std::function<DependencyState(std::size_t, std::size_t)> resolve_candidate;
            resolve_candidate = [&](std::size_t index, std::size_t depth) -> DependencyState {
                if (visit_state[index] == 1) return DependencyState::cycle;
                if (visit_state[index] == 2) return dependency_states[index];
                if (!report[index].candidate->manifest) {
                    visit_state[index] = 2;
                    return dependency_states[index] = DependencyState::manifest_unavailable;
                }
                if (depth >= 256) {
                    visit_state[index] = 2;
                    return dependency_states[index] = DependencyState::depth_limit;
                }
                visit_state[index] = 1;
                auto state = DependencyState::ready;
                for (auto &requirement : report[index].requirements) {
                    if (requirement.resolution == "host") continue;
                    if (requirement.resolution == "unavailable") { state = DependencyState::unavailable; break; }
                    if (requirement.resolution == "ambiguous") { state = DependencyState::ambiguous; break; }
                    if (!requirement.candidate_provider) { state = DependencyState::manifest_unavailable; break; }
                    const auto provider_state = resolve_candidate(*requirement.candidate_provider, depth + 1);
                    requirement.provider_status = state_name(provider_state);
                    if (provider_state != DependencyState::ready) { state = provider_state; break; }
                }
                visit_state[index] = 2;
                return dependency_states[index] = state;
            };
            for (std::size_t index = 0; index < report.size(); ++index)
                report[index].dependency_status = state_name(resolve_candidate(index, 0));
            for (auto &row : report)
                for (auto &requirement : row.requirements)
                    if (requirement.candidate_provider)
                        requirement.provider_status = state_name(resolve_candidate(*requirement.candidate_provider, 0));

            std::size_t failure_count = 0;
            for (const auto &row : report)
                if (row.dependency_status != "ready") ++failure_count;
            if (json) {
                out << "{\"directory\":" << json_quote(path_text(directory))
                    << ",\"loaded\":false,\"advisory\":true,\"strict\":" << (strict ? "true" : "false")
                    << ",\"failure_count\":" << failure_count << ",\"count\":" << report.size() << ',';
                write_duplicate_identities_json();
                out << ",\"candidates\":[";
                for (std::size_t i = 0; i < report.size(); ++i) {
                    const auto &row = report[i];
                    if (i) out << ',';
                    out << "{\"path\":" << json_quote(row.candidate->path) << ",\"manifest\":";
                    if (row.candidate->manifest) out << json_quote(row.candidate->manifest->id);
                    else out << "null";
                    out << ",\"manifest_error\":" << json_quote(row.candidate->manifest_error)
                        << ",\"dependency_status\":" << json_quote(row.dependency_status)
                        << ",\"requirements\":[";
                    for (std::size_t r = 0; r < row.requirements.size(); ++r) {
                        const auto &requirement = row.requirements[r];
                        if (r) out << ',';
                        out << "{\"id\":" << json_quote(requirement.capability.id)
                            << ",\"major\":" << requirement.capability.major_version
                            << ",\"minimum_minor\":" << requirement.capability.minor_version
                            << ",\"resolution\":" << json_quote(requirement.resolution)
                            << ",\"provider_dependency_status\":" << json_quote(requirement.provider_status)
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
                return strict && (failure_count || !duplicate_identity_paths.empty()) ? 3 : 0;
            }
            out << "Dependency preflight for " << path_text(directory) << " (advisory; no modules loaded)\n";
            for (const auto &row : report) {
                out << row.candidate->path;
                if (!row.candidate->manifest) {
                    out << (row.candidate->manifest_error.empty() ? "\n  no manifest; requirements unknown\n"
                                                                  : "\n  rejected or invalid manifest: " + safe_text(row.candidate->manifest_error) + "\n");
                    continue;
                }
                out << "\n  " << row.candidate->manifest->id
                    << "\n  manifest dependency graph: " << row.dependency_status;
                if (row.requirements.empty()) out << "\n  no declared requirements";
                for (const auto &requirement : row.requirements) {
                    const auto &capability = requirement.capability;
                    out << "\n  " << capability.id << '@' << capability.major_version << '.'
                        << capability.minor_version << ": " << requirement.resolution;
                    if (requirement.candidate_provider)
                        out << " (provider graph: " << requirement.provider_status << ')';
                    for (const auto &[provider, path] : requirement.providers)
                        out << " " << provider << " (" << path << ')';
                }
                out << '\n';
            }
            write_duplicate_identities_text();
            if (strict) out << "Strict failures (candidate dependency graphs): " << failure_count << '\n';
            if (strict && !duplicate_identity_paths.empty())
                out << "Duplicate plugin identities: " << duplicate_identity_paths.size() << '\n';
            return strict && (failure_count || !duplicate_identity_paths.empty()) ? 3 : 0;
        }
        const auto invalid_manifest_count = static_cast<std::size_t>(std::count_if(
            scanned.value().begin(), scanned.value().end(), [](const auto &candidate) {
                return !candidate.manifest && !candidate.manifest_error.empty();
            }));
        const auto integrity_failure_count = static_cast<std::size_t>(std::count_if(
            scanned.value().begin(), scanned.value().end(), [](const auto &candidate) {
                return !candidate.integrity_error.empty();
            }));
        if (json) {
            out << "{\"directory\":" << json_quote(path_text(directory))
                << ",\"loaded\":false,\"strict\":" << (strict ? "true" : "false")
                << ",\"invalid_manifest_count\":" << invalid_manifest_count
                << ",\"integrity_failure_count\":" << integrity_failure_count
                << ",\"duplicate_identity_count\":" << duplicate_identity_paths.size() << ',';
            write_duplicate_identities_json();
            out << ",\"count\":" << scanned.value().size() << ",\"candidates\":[";
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
                        << ",\"sha256\":" << (manifest.sha256.empty() ? "null" : json_quote(manifest.sha256))
                        << ",\"capabilities\":";
                    capabilities(manifest.capabilities);
                    out << ",\"required_capabilities\":";
                    capabilities(manifest.required_capabilities);
                    out << '}';
                }
                out << ",\"manifest_error\":" << json_quote(candidate.manifest_error)
                    << ",\"module_sha256\":" << (candidate.module_sha256.empty() ? "null" : json_quote(candidate.module_sha256))
                    << ",\"integrity_error\":" << json_quote(candidate.integrity_error) << '}';
            }
            out << "]}\n";
            return strict && (invalid_manifest_count || integrity_failure_count || !duplicate_identity_paths.empty()) ? 3 : 0;
        }
        out << "Scanned " << scanned.value().size() << " candidate(s) in " << path_text(directory)
            << ". No plugin modules were loaded.\n";
        if (strict) out << "Invalid manifests: " << invalid_manifest_count << '\n';
        if (strict) out << "Integrity failures: " << integrity_failure_count << '\n';
        for (const auto &candidate : scanned.value()) {
            out << candidate.path;
            if (candidate.manifest) {
                const auto &manifest = *candidate.manifest;
                out << "\n  " << manifest.id << " | " << manifest.name << " | " << manifest.version;
                if (!manifest.sha256.empty()) out << "\n  declared SHA-256: " << manifest.sha256;
                if (!candidate.module_sha256.empty()) out << "\n  actual SHA-256:   " << candidate.module_sha256;
                if (!candidate.integrity_error.empty()) out << "\n  integrity error: " << safe_text(candidate.integrity_error);
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
                out << "\n  Rejected or invalid manifest: " << safe_text(candidate.manifest_error);
            else out << "\n  No manifest";
            out << '\n';
        }
        write_duplicate_identities_text();
        if (strict && !duplicate_identity_paths.empty())
            out << "Duplicate plugin identities: " << duplicate_identity_paths.size() << '\n';
        return strict && (invalid_manifest_count || integrity_failure_count || !duplicate_identity_paths.empty()) ? 3 : 0;
    } catch (const std::exception &error) {
        err << "Plugin scan: " << error.what() << '\n';
        return 1;
    }
}
int firmware_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    const bool has_capsule_sg_option = std::find(args.begin(), args.end(), L"--capsule-sg-base") != args.end() ||
        std::find(args.begin(), args.end(), L"--capsule-sg-head") != args.end() ||
        std::find(args.begin(), args.end(), L"--capsule-sg-region") != args.end();
    const bool is_capsule_format = args.size() >= 2 && args[args.size() - 2] == L"--format" && args.back() == L"uefi-capsule";
    if (has_capsule_sg_option && !is_capsule_format) {
        err << "Firmware: --capsule-sg-* options require --format uefi-capsule\n";
        return 1;
    }
    if (args.size() == 2 && args[1] == L"--help") {
        out << "Usage: hexlab_cli firmware inspect <path> --format ihex|srec|uefi|uefi-capsule\n"
            << "       Intel FIT: hexlab_cli firmware inspect <path> --fit-offset <file-offset> --format fit\n"
            << "       Intel microcode: hexlab_cli firmware inspect <path> --microcode-offset <file-offset> --format intel-microcode\n"
            << "       UEFI capsule lists: hexlab_cli firmware inspect <path> [<path> ...] --format uefi-capsule\n"
            << "       Extract FMP image: hexlab_cli firmware inspect <path> --extract-item <index> --output <file> [--replace] --format uefi-capsule\n"
            << "       FMP scatter/gather: hexlab_cli firmware inspect <capture> --capsule-sg-base <physical-base> --capsule-sg-head <physical-address> [--capsule-sg-region <base=file> ...] [--json] --format uefi-capsule\n";
        return 0;
    }
    if (args.size() == 6 && args[0] == L"inspect" && args[2] == L"--fit-offset" &&
        args[4] == L"--format" && args[5] == L"fit")
        return run_intel_fit_cli(args, out, err);
    if (args.size() == 6 && args[0] == L"inspect" && args[2] == L"--microcode-offset" &&
        args[4] == L"--format" && args[5] == L"intel-microcode")
        return run_intel_microcode_cli(args, out, err);
    if (args.size() == 4 && args[0] == L"inspect" && args[2] == L"--format" && args[3] == L"uefi")
        return run_uefi_firmware_cli(args, out, err);
    if (args.size() >= 4 && args[0] == L"inspect" && args[args.size() - 2] == L"--format" && args.back() == L"uefi-capsule")
        return run_uefi_capsule_cli(args, out, err);
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
        auto loaded = load_firmware(text, FirmwareLoadOptions{format});
        if (!loaded) throw std::runtime_error(loaded.error().message);
        const auto &data = *loaded.value().metadata.firmware;
        out << "Format: " << loaded.value().metadata.format << '\n'
            << "Data bytes: " << loaded.value().metadata.image_size << '\n'
            << "Records: " << data.records.size() << '\n';
        if (data.has_start_address) out << "Start address: " << hex(data.start_address) << '\n';
        if (format == firmware::Format::motorola_s_record) {
            auto parsed_srec = firmware::parse_s_record(text);
            if (!parsed_srec) throw std::runtime_error(parsed_srec.error().message);
            if (parsed_srec.value().has_s_record_header) {
                out << "S0 header: SourceLine=" << parsed_srec.value().s_record_header_provenance.line
                    << " Record=" << parsed_srec.value().s_record_header_provenance.record_index << " Bytes=";
                for (const auto byte : parsed_srec.value().s_record_header)
                    out << std::hex << std::setw(2) << std::setfill('0') << std::to_integer<unsigned>(byte);
                out << std::dec << std::setfill(' ') << '\n';
            }
        }
        out << "Segments:\n";
        for (const auto &record : data.records)
            out << "  " << hex(record.address.offset) << " Size=" << hex(record.size)
                << " SourceLine=" << record.source_line << " Record=" << record.record_index
                << " Backing=" << hex(record.packed_file_offset.value) << '\n';
        for (const auto &diagnostic : loaded.value().diagnostics)
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
        out << "Usage: hexlab_cli archive list <archive> [--thin-root <directory>]\n"
               "       hexlab_cli archive index-audit <archive> [--thin-root <directory>]\n"
               "       hexlab_cli archive link-select <archive> --root-object <ET_REL|XCOFF64>\n"
               "       hexlab_cli archive link-audit <archive> --root-object <ET_REL|XCOFF64>\n"
               "       hexlab_cli archive link <archive> --root-object <ET_REL> --output <ET_REL>\n"
               "       hexlab_cli archive link-exec <archive> --root-object <ET_REL> --entry <symbol> --output <ET_EXEC>\n"
               "       hexlab_cli archive link-pe <archive> --root-object <COFF .obj> --entry <symbol> --output <PE .exe>\n"
               "       hexlab_cli archive link-macho <archive> --root-object <Mach-O .o> --entry <symbol> --output <Mach-O executable>\n"
               "       hexlab_cli archive extract <archive> --member <index> --output <path> [--replace]\n"
               "       hexlab_cli archive open <archive> --member <index> --project <project.hxproj> [--replace]\n"
               "Thin archive reads/link actions require --thin-root <directory>; member paths stay under that explicit root.\n";
        return 0;
    }
    try {
        std::vector<std::wstring_view> archive_arguments{args[0],args[1]};
        std::optional<std::filesystem::path> thin_root;
        for(std::size_t i=2;i<args.size();++i){
            if(args[i]!=L"--thin-root"){archive_arguments.push_back(args[i]);continue;}
            if(thin_root||i+1==args.size())argument_error("archive --thin-root requires one explicit directory");
            thin_root=std::filesystem::absolute(path_from_wide(args[++i]));
            if(!std::filesystem::is_directory(*thin_root))argument_error("archive --thin-root is not a directory");
        }
        args=archive_arguments;
        const auto action = args[0];
        const auto archive_path = path_from_wide(args[1]);
        auto storage = take(FileStorage::open(archive_path));
        auto archive = take(read_ar_archive(*storage));
        ArThinMemberResolver resolver;
        if(thin_root){
            resolver=take(make_ar_thin_member_resolver(*thin_root));
        }
        if(archive.thin&&action!=L"list"&&!resolver)
            argument_error("Thin archive reads/link actions require --thin-root <directory>");
        const auto open_member=[&](const ArMember& member){return open_ar_member(storage,member,resolver);};
        if (action == L"index-audit") {
            if (args.size() != 2) argument_error("archive index-audit takes one archive path");
            constexpr std::size_t max_members = 4096;
            constexpr std::size_t max_index_rows = 1'000'000;
            constexpr std::uint64_t max_name_bytes = 64ULL * 1024 * 1024;
            constexpr std::uint64_t max_member_bytes = 256ULL * 1024 * 1024;
            if (archive.members.size() > max_members)
                argument_error("Archive index audit exceeds 4096 members");
            if (archive.symbols.size() > max_index_rows)
                argument_error("Archive index audit exceeds one million index rows");
            std::map<std::string, std::set<std::size_t>> expected;
            std::set<std::size_t> audited_members;
            std::uint64_t total_bytes = 0, total_symbols = 0, total_name_bytes = 0;
            std::size_t skipped_members = 0;
            for (std::size_t i = 0; i < archive.members.size(); ++i) {
                const auto &member = archive.members[i];
                if (member.kind != ArMemberKind::regular && member.kind != ArMemberKind::thin_external) continue;
                auto member_storage = take(open_member(member));
                const auto format = take(detect_format(*member_storage));
                if (format != DetectedFormat::elf_candidate) { ++skipped_members; continue; }
                if (member_storage->size() > max_member_bytes - total_bytes)
                    argument_error("Archive index audit exceeds 256 MiB of ELF member data");
                total_bytes += member_storage->size();
                auto summary = take(summarize_elf_ar_member(*member_storage, i));
                audited_members.insert(i);
                total_symbols += summary.definitions.size();
                if (total_symbols > 1'000'000)
                    argument_error("Archive index audit exceeds one million defined symbols");
                for (const auto &name : summary.definitions) {
                    if (name.size() > max_name_bytes - total_name_bytes)
                        argument_error("Archive index audit exceeds 64 MiB of decoded ELF symbol names");
                    total_name_bytes += name.size();
                    expected[name].insert(i);
                }
            }
            std::set<std::pair<std::string, std::size_t>> actual;
            std::size_t stale = 0, unverifiable = 0;
            for (const auto &symbol : archive.symbols) {
                if (symbol.name.size() > max_name_bytes - total_name_bytes)
                    argument_error("Archive index audit exceeds 64 MiB of decoded symbol names");
                total_name_bytes += symbol.name.size();
                if (!audited_members.contains(symbol.member_index)) {
                    ++unverifiable;
                    out << "Unverifiable index row: symbol=" << safe_text(symbol.name)
                        << " member=" << symbol.member_index << " reason=non-ELF-or-unsupported-member\n";
                    continue;
                }
                actual.emplace(symbol.name, symbol.member_index);
                const auto found = expected.find(symbol.name);
                if (found == expected.end() || !found->second.contains(symbol.member_index)) {
                    ++stale;
                    out << "Stale index row: symbol=" << safe_text(symbol.name)
                        << " member=" << symbol.member_index << " member-name="
                        << safe_text(archive.members[symbol.member_index].name) << '\n';
                }
            }
            std::size_t missing = 0;
            for (const auto &[name, providers] : expected) {
                for (const auto member_index : providers) {
                    if (actual.contains({name, member_index})) continue;
                    ++missing;
                    out << "Missing index row: symbol=" << safe_text(name)
                        << " member=" << member_index << " member-name="
                        << safe_text(archive.members[member_index].name) << '\n';
                }
            }
            out << "Archive index audit: format=ELF members=" << audited_members.size()
                << " skipped-members=" << skipped_members << " defined-symbols=" << total_symbols
                << " index-rows=" << archive.symbols.size() << " missing=" << missing
                << " stale=" << stale << " unverifiable=" << unverifiable
                << " index-present=" << (archive.has_symbol_index ? "true" : "false")
                << " index-complete=" << (archive.symbol_index_complete ? "true" : "false") << '\n';
            for (const auto &diagnostic : archive.diagnostics)
                out << "Archive diagnostic: " << safe_text(diagnostic) << '\n';
            return missing == 0 && stale == 0 && archive.has_symbol_index && archive.symbol_index_complete ? 0 : 1;
        }
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
                if (member.kind != ArMemberKind::regular && member.kind != ArMemberKind::thin_external) continue;
                auto member_storage = take(open_member(member));
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
                objects.push_back(take(open_member(archive.members[item.member_index])));
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
                if (member.kind != ArMemberKind::regular && member.kind != ArMemberKind::thin_external) continue;
                auto member_storage = take(open_member(member));
                if (take(detect_format(*member_storage)) != DetectedFormat::macho_candidate) continue;
                summaries.push_back(take(summarize_macho_ar_member(*member_storage, i)));
            }
            const auto entry_symbol = wide_to_utf8(args[5]);
            std::vector<std::string_view> roots, definitions;
            for (const auto &name : root.undefined) roots.emplace_back(name);
            roots.emplace_back(entry_symbol); // The entry may be defined only by an archive member.
            for (const auto &name : root.definitions) definitions.emplace_back(name);
            const auto selected = take(select_ar_members_fixed_point(archive, summaries, roots, definitions));
            if (!selected.unresolved_symbols.empty())
                throw std::runtime_error("Unresolved strong Mach-O symbol " + selected.unresolved_symbols.front());
            std::vector<std::shared_ptr<const ByteStorage>> objects{root_storage};
            for (const auto &item : selected.members)
                objects.push_back(take(open_member(archive.members[item.member_index])));
            const auto linked = take(link_macho64_executable(objects, entry_symbol));
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
            const auto is_xcoff64 = [&](const ByteStorage &object) {
                if (object.size() < 2) return false;
                const auto prefix = take(object.read_at({0}, 2));
                return prefix.bytes.size() == 2 && prefix.bytes[0] == std::byte{0x01} &&
                    prefix.bytes[1] == std::byte{0xf7};
            };
            if ((action == L"link-select" || action == L"link-audit") && is_xcoff64(*root_storage)) {
                const auto root = take(summarize_xcoff64_ar_member(*root_storage, 0));
                std::vector<ArMemberSymbols> summaries;
                summaries.reserve(archive.members.size());
                for (std::size_t i = 0; i < archive.members.size(); ++i) {
                    const auto &member = archive.members[i];
                    if (member.kind != ArMemberKind::regular && member.kind != ArMemberKind::thin_external) continue;
                    auto member_storage = take(open_member(member));
                    if (!is_xcoff64(*member_storage)) continue;
                    summaries.push_back(take(summarize_xcoff64_ar_member(*member_storage, i)));
                }
                std::vector<std::string_view> roots, definitions;
                roots.reserve(root.undefined.size());
                definitions.reserve(root.definitions.size());
                for (const auto &name : root.undefined) roots.emplace_back(name);
                for (const auto &name : root.definitions) definitions.emplace_back(name);
                const auto selected = take(select_ar_members_fixed_point(archive, summaries, roots, definitions));
                out << "Archive object format: XCOFF64 (selection and structural relocation audit)\n";
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
                    struct Object { std::string name; Xcoff64Object metadata; };
                    std::vector<Object> objects;
                    std::uint64_t total_bytes = 0, total_symbols = 0, total_relocations = 0, total_name_bytes = 0;
                    const auto append = [&](std::string name, const ByteStorage &bytes) {
                        constexpr std::uint64_t byte_limit = 256ULL * 1024 * 1024;
                        if (objects.size() >= 4096 || bytes.size() > byte_limit - total_bytes)
                            argument_error("XCOFF64 audit exceeds 4096 objects or 256 MiB aggregate input limit");
                        total_bytes += bytes.size();
                        auto metadata = take(inspect_xcoff64_object(bytes));
                        for (const auto &symbol : metadata.symbols) {
                            if (symbol.name.size() > byte_limit - total_name_bytes)
                                argument_error("XCOFF64 audit exceeds 256 MiB aggregate decoded symbol name limit");
                            total_name_bytes += symbol.name.size();
                        }
                        total_symbols += metadata.symbol_count;
                        for (const auto &section : metadata.sections) total_relocations += section.relocation_count;
                        if (total_symbols > 1'000'000 || total_relocations > 1'000'000)
                            argument_error("XCOFF64 audit exceeds aggregate symbol or relocation limit");
                        objects.push_back({std::move(name), std::move(metadata)});
                    };
                    append("<root>", *root_storage);
                    for (const auto &entry : selected.members) {
                        auto bytes = take(open_member(archive.members[entry.member_index]));
                        append(archive.members[entry.member_index].name, *bytes);
                    }
                    // Only strong, concrete C_EXT definitions are unique providers.
                    // Common and weak definitions require binder policy beyond this audit.
                    std::map<std::string, std::vector<std::string>> providers;
                    std::set<std::string> deferred_providers;
                    for (const auto &object : objects)
                        for (const auto &symbol : object.metadata.symbols) {
                            if (symbol.storage_class == 2 && symbol.csect_type != 3 &&
                                (symbol.section_number > 0 || symbol.section_number == -1) &&
                                !symbol.name.empty())
                                providers[symbol.name].push_back(object.name);
                            if (!symbol.name.empty() && ((symbol.storage_class == 111 &&
                                (symbol.section_number > 0 || symbol.section_number == -1)) ||
                                (symbol.storage_class == 2 && (symbol.csect_type == 3 ||
                                 (symbol.section_number == 0 && symbol.value != 0)))))
                                deferred_providers.insert(symbol.name);
                        }
                    for (const auto &[name, candidates] : providers)
                        if (candidates.size() > 1)
                            out << "Conflicting strong definitions: symbol=" << safe_text(name)
                                << " providers=" << candidates.size() << '\n';
                    std::size_t unknown = 0, unresolved = 0, ambiguous = 0, deferred = 0, loader_rows = 0;
                    for (const auto &object : objects) {
                        if (object.metadata.file_flags & 0x0001u)
                            out << "Relocation information stripped: object=" << safe_text(object.name)
                                << " flag=F_RELFLG completeness=unknown\n";
                        for (const auto &section : object.metadata.sections) {
                            if (section.loader_relocation_encoding) {
                                loader_rows += section.relocation_count;
                                out << "Unsupported loader section: object=" << safe_text(object.name)
                                    << " section=" << section.index << " relocation-count=" << section.relocation_count
                                    << " encoding=loader16 decoded=false\n";
                            }
                            for (const auto &relocation : section.relocations) {
                                const auto symbol = std::lower_bound(object.metadata.symbols.begin(), object.metadata.symbols.end(),
                                    relocation.symbol_index, [](const auto &row, auto index) { return row.index < index; });
                                const auto type_name = xcoff64_relocation_type_name(relocation.type);
                                const bool recognized = type_name != "unknown";
                                if (!recognized) ++unknown;
                                out << (recognized ? "Relocation: " : "Unsupported relocation: ")
                                    << "object=" << safe_text(object.name) << " section=" << section.index
                                    << " address=" << hex(relocation.virtual_address)
                                    << " record-offset=" << hex(relocation.file_offset) << " type=" << unsigned(relocation.type)
                                    << " name=" << type_name << " bits=" << ((relocation.size_info & 0x3fu) + 1)
                                    << " signed=" << ((relocation.size_info & 0x80u) ? "true" : "false")
                                    << " instruction-modified=" << ((relocation.size_info & 0x40u) ? "true" : "false")
                                    << " symbol-index=" << relocation.symbol_index << " symbol=" << safe_text(symbol->name)
                                    << " symbol-section=" << symbol->section_number << " symbol-value=" << hex(symbol->value)
                                    << " symbol-class=" << unsigned(symbol->storage_class);
                                if (symbol->csect_type != 0xff)
                                    out << " csect-type=" << unsigned(symbol->csect_type)
                                        << " storage-mapping-class=" << unsigned(symbol->storage_mapping_class);
                                if ((symbol->storage_class == 2 || symbol->storage_class == 107 || symbol->storage_class == 111 ||
                                     symbol->storage_class == 3) && symbol->csect_type != 3 &&
                                    (symbol->section_number > 0 || symbol->section_number == -1)) {
                                    out << " resolution=object-definition provider=" << safe_text(object.name);
                                } else if (symbol->storage_class == 2 && symbol->section_number == 0 && symbol->value == 0 &&
                                           !symbol->name.empty()) {
                                    const auto found = providers.find(symbol->name);
                                    if (found == providers.end() && deferred_providers.contains(symbol->name)) {
                                        ++deferred; out << " resolution=deferred-common-or-weak-provider";
                                    }
                                    else if (found == providers.end()) { ++unresolved; out << " resolution=unresolved-strong"; }
                                    else if (found->second.size() != 1) { ++ambiguous; out << " resolution=ambiguous-strong providers=" << found->second.size(); }
                                    else out << " resolution=unique-strong-provider provider=" << safe_text(found->second.front());
                                } else { ++deferred; out << " resolution=deferred-common-weak-or-special"; }
                                out << " applied=false\n";
                            }
                        }
                    }
                    out << "Link audit: objects=" << objects.size() << " relocations=" << total_relocations
                        << " unresolved-strong-relocations=" << unresolved << " ambiguous-strong-relocations=" << ambiguous
                        << " deferred-symbol-relocations=" << deferred << " unsupported-relocations=" << unknown
                        << " undecoded-loader-relocations=" << loader_rows
                        << " applied=0 output=none link-readiness=not-established\n";
                }
                out << "XCOFF64 link output is unsupported; no output was written.\n";
                return 0;
            }
            if (is_xcoff64(*root_storage))
                argument_error("XCOFF64 archive link output is unsupported; use link-select or link-audit");
            const auto root = take(summarize_elf_ar_member(*root_storage, 0));
            std::vector<ArMemberSymbols> summaries;
            summaries.reserve(archive.members.size());
            for (std::size_t i = 0; i < archive.members.size(); ++i) {
                const auto &member = archive.members[i];
                if (member.kind != ArMemberKind::regular && member.kind != ArMemberKind::thin_external) continue;
                auto member_storage = take(open_member(member));
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
                    objects.push_back(take(open_member(archive.members[entry.member_index])));
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
                    auto bytes = take(open_member(archive.members[entry.member_index]));
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
            out << "Archive format: " << (archive.thin ? (resolver ? "GNU thin ar (external members resolved on request)" : "GNU thin ar (external member contents not resolved)")
                                                       : archive.aix_big ? "AIX big ar" : "ar") << '\n';
            for (std::size_t i = 0; i < archive.members.size(); ++i) {
                const auto &member = archive.members[i];
                out << "Member: " << i << " name=" << safe_text(member.name) << " size=" << member.size
                    << " timestamp=" << member.timestamp << " uid=" << member.uid << " gid=" << member.gid
                    << " mode=0" << std::oct << member.mode << std::dec
                    << " kind=" << (member.kind == ArMemberKind::regular ? "regular"
                                    : member.kind == ArMemberKind::thin_external ? "thin-external"
                                    : member.kind == ArMemberKind::symbol_index ? "symbol-index"
                                    : member.kind == ArMemberKind::member_table ? "member-table" : "long-name-table") << '\n';
                if (member.kind == ArMemberKind::thin_external && resolver) {
                    auto member_storage = take(open_member(member));
                    const auto digest = take(hash_source(*member_storage, {}));
                    out << "Thin provenance: member=" << i << " declared-path=" << safe_text(member.name)
                        << " resolved-by=--thin-root bytes=" << member_storage->size()
                        << " sha256=" << digest_hex(digest) << '\n';
                }
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
        if (member.kind != ArMemberKind::regular && member.kind != ArMemberKind::thin_external)
            argument_error("Selected archive member is not a regular file");
        if (action == L"extract") {
            auto bytes = take(extract_ar_member(storage, member, resolver));
            write_archive_output(output_path, bytes, replace);
            out << "Extracted archive member " << *selected << " (" << safe_text(member.name) << ")\nOutput: "
                << path_text(output_path) << '\n';
            return 0;
        }
        auto member_storage=take(open_member(member));
        auto pool = std::make_shared<AnalysisPool>();
        auto actor = take(ProjectActor::create({{1}, 1}, pool));
        auto reply = [&](Result<ProjectSubmission> submitted) {
            auto operation = take(std::move(submitted));
            return take(operation.result.get());
        };
        struct Close { std::shared_ptr<ProjectActor> actor; ~Close() { auto closing=actor->close(); if(closing) closing.value().result.wait(); } } close{actor};
        OpenRequest request; request.path = archive_path; request.input_storage=std::move(member_storage);
        request.source_path=path_from_wide(utf8_to_wide(path_text(archive_path)+"!"+member.name));
        request.run_analysis = false;
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
namespace {
std::vector<std::filesystem::path> discover_jar_volumes(const std::filesystem::path &input) {
    auto extension = input.extension().wstring();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](wchar_t ch) { return std::towlower(ch); });
    std::wstring base;
    if (extension == L".zip") base = input.stem().wstring();
    else if (extension.size() >= 3 && extension[0] == L'.' && extension[1] == L'z' &&
             std::all_of(extension.begin() + 2, extension.end(), [](wchar_t ch) { return ch >= L'0' && ch <= L'9'; }))
        base = input.stem().wstring();
    else return {input};

    auto parent = input.parent_path();
    std::vector<std::filesystem::path> volumes;
    std::uint32_t missing_at = 0;
    for (std::uint32_t index = 1; index <= 65536; ++index) {
        std::wstring suffix = std::to_wstring(index);
        if (suffix.size() < 2) suffix.insert(suffix.begin(), 2 - suffix.size(), L'0');
        auto candidate = parent / (base + L".z" + suffix);
        std::error_code error;
        if (!std::filesystem::is_regular_file(candidate, error)) { missing_at = index; break; }
        volumes.push_back(std::move(candidate));
    }
    if (missing_at != 0) {
        for (std::uint32_t index = missing_at + 1; index <= 65536; ++index) {
            std::wstring suffix = std::to_wstring(index);
            if (suffix.size() < 2) suffix.insert(suffix.begin(), 2 - suffix.size(), L'0');
            std::error_code error;
            if (std::filesystem::exists(parent / (base + L".z" + suffix), error))
                argument_error("Split JAR volumes must be contiguous starting at .z01");
        }
    }
    auto terminal = parent / (base + L".zip");
    std::error_code error;
    if (std::filesystem::is_regular_file(terminal, error)) volumes.push_back(std::move(terminal));
    if (volumes.empty()) return {input};
    return volumes;
}
}
int jar_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    using project_detail::Failure;
    using project_detail::take;
    if (args.size() < 2 || (args.size() == 2 && args[1] == L"--help")) {
        out << "Usage: hexlab_cli jar list <package.jar>\n"
               "       hexlab_cli jar inspect <package.jar> --member <index>\n"
               "       hexlab_cli jar list --volume <path> --volume <path> ...\n"
               "       hexlab_cli jar inspect --volume <path> --volume <path> ... --member <index>\n";
        return 0;
    }
    try {
        const auto action = args[0];
        std::optional<std::filesystem::path> input_path;
        std::vector<std::filesystem::path> explicit_volumes;
        std::optional<std::wstring_view> member_argument;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == L"--volume") {
                if (++i >= args.size()) argument_error("--volume requires a path");
                explicit_volumes.push_back(path_from_wide(args[i]));
            } else if (args[i] == L"--member") {
                if (++i >= args.size()) argument_error("--member requires an index");
                member_argument = args[i];
            } else if (!input_path) input_path = path_from_wide(args[i]);
            else argument_error("Unexpected JAR argument");
        }
        const bool explicit_volume_mode = !explicit_volumes.empty();
        auto volume_paths = !explicit_volume_mode
            ? (input_path ? discover_jar_volumes(*input_path) : std::vector<std::filesystem::path>{})
            : std::move(explicit_volumes);
        if (explicit_volume_mode && input_path)
            argument_error("Use either a package path or ordered --volume paths, not both");
        if (volume_paths.empty()) argument_error("JAR command requires a package path or one or more --volume paths");
        if (volume_paths.size() > 65536) argument_error("JAR volume count exceeds 65,536");
        std::vector<std::shared_ptr<const ByteStorage>> storages;
        storages.reserve(volume_paths.size());
        for (const auto &path : volume_paths) storages.push_back(take(FileStorage::open(path)));
        auto archive = take(read_jar_archive(storages));
        if (action == L"list") {
            if (member_argument || (!explicit_volume_mode && (!input_path || args.size() != 2)))
                argument_error("jar list accepts a package path or ordered --volume paths");
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
        if (action != L"inspect" || !member_argument)
            argument_error("jar inspect requires --member <index>");
        auto parsed = parse_address(*member_argument);
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

int jvm_module_path_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    using project_detail::Failure;
    using project_detail::take;
    if (args.empty() || (args.size() == 1 && args[0] == L"--help")) {
        out << "Usage: hexlab_cli jvm module-path [--release <feature>] [--archive-volume <path>]... [--module-path <dir-or-jar>]... [--class-path <dir-or-jar>]...\n"
               "       hexlab_cli jvm module-path [roots...] [--root-module <name>]... [--lookup-class <binary-name>]\n"
               "Roots are processed in option order; manifest Class-Path references use only supplied roots.\n";
        return 0;
    }
    try {
        if (args[0] != L"module-path") argument_error("Expected jvm module-path");
        std::vector<JvmPathRoot> roots;
        std::vector<std::string> lookup_classes;
        std::vector<std::string> configuration_roots;
        std::vector<std::filesystem::path> pending_archive_volumes;
        std::optional<std::uint16_t> target_release;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == L"--release") {
                if (target_release || ++i >= args.size()) argument_error("--release requires one Java feature version");
                std::string digits;
                for (const wchar_t c : args[i]) {
                    if (c < L'0' || c > L'9') argument_error("--release requires a decimal Java feature version");
                    digits.push_back(static_cast<char>(c));
                }
                unsigned value = 0;
                const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
                if (error != std::errc{} || end != digits.data() + digits.size() || value < 9 || value > UINT16_MAX)
                    argument_error("--release must be a decimal Java feature version from 9 through 65535");
                target_release = static_cast<std::uint16_t>(value);
                continue;
            }
            if (args[i] == L"--lookup-class") {
                if (++i >= args.size()) argument_error("--lookup-class requires a binary class name");
                if (lookup_classes.size() >= 64) argument_error("At most 64 --lookup-class queries are accepted");
                lookup_classes.push_back(wide_to_utf8(args[i]));
                continue;
            }
            if (args[i] == L"--root-module") {
                if (++i >= args.size()) argument_error("--root-module requires a module name");
                if (configuration_roots.size() >= 256) argument_error("At most 256 --root-module names are accepted");
                configuration_roots.push_back(wide_to_utf8(args[i]));
                continue;
            }
            if (args[i] == L"--archive-volume") {
                if (++i >= args.size()) argument_error("--archive-volume requires one earlier split archive volume path");
                if (pending_archive_volumes.size() >= 255) argument_error("At most 255 earlier split archive volumes are accepted per root");
                pending_archive_volumes.push_back(path_from_wide(args[i]));
                continue;
            }
            JvmPathRootKind kind;
            if (args[i] == L"--module-path") kind = JvmPathRootKind::module_path;
            else if (args[i] == L"--class-path") kind = JvmPathRootKind::class_path;
            else argument_error("Expected --module-path or --class-path followed by a directory or JAR");
            if (++i >= args.size()) argument_error("JVM path option requires a directory or archive path");
            roots.push_back({path_from_wide(args[i]), kind});
            if (!pending_archive_volumes.empty()) {
                roots.back().archive_volumes = std::move(pending_archive_volumes);
                roots.back().archive_volumes.push_back(roots.back().path);
                pending_archive_volumes.clear();
            }
        }
        if (!pending_archive_volumes.empty()) argument_error("--archive-volume paths must be followed by the final --module-path or --class-path archive root");
        if (roots.empty()) argument_error("jvm module-path requires at least one ordered root");
        JvmModulePathLimits limits;
        limits.target_release = target_release;
        auto workspace = take(link_jvm_path_workspace(roots, {}, limits));
        std::optional<JvmModuleConfiguration> configuration;
        if (!configuration_roots.empty()) {
            std::vector<std::string_view> names;
            names.reserve(configuration_roots.size());
            for (const auto &name : configuration_roots) names.push_back(name);
            configuration = take(resolve_jvm_module_configuration(workspace, names));
        }
        const auto status = [](JvmModuleLinkStatus value) -> std::string_view {
            switch (value) {
            case JvmModuleLinkStatus::resolved: return "resolved";
            case JvmModuleLinkStatus::missing: return "missing";
            case JvmModuleLinkStatus::missing_optional: return "missing-optional";
            case JvmModuleLinkStatus::duplicate_definition: return "duplicate-definition";
            case JvmModuleLinkStatus::unresolved_ownership: return "unresolved-ownership";
            case JvmModuleLinkStatus::ambiguous_ownership: return "ambiguous-ownership";
            }
            return "unknown";
        };
        const auto bounded_rows = [&](std::string_view label, const auto &rows, std::size_t cap, const auto &print) {
            const auto count = std::min<std::size_t>(rows.size(), cap);
            for (std::size_t i = 0; i < count; ++i) print(i, rows[i]);
            if (rows.size() > count) out << "  ... " << rows.size() - count << " more " << label << " rows omitted\n";
        };
        const auto &graph = workspace.graph;
        out << "JVM module-path workspace: roots=" << workspace.roots.size()
            << " modules=" << graph.module_graph.modules.size() << " edges=" << graph.module_graph.edges.size()
            << " classes=" << graph.class_ownership.size() << " packages=" << graph.packages.size()
            << " services=" << graph.services.size() << " readability=" << graph.module_graph.readability.size()
            << " requires-cycles=" << graph.module_graph.requires_cycles.size()
            << " class-path-definitions=" << workspace.class_path_classes.size();
        if (target_release) out << " target-release=" << *target_release;
        out << " versioned-classes=" << workspace.versioned_classes.size() << '\n';
        const auto nest_kind = [](JvmNestRelationKind value) -> std::string_view {
            return value == JvmNestRelationKind::member_declares_host ? "member-host" : "host-member";
        };
        const auto nest_status = [](JvmNestRelationStatus value) -> std::string_view {
            switch (value) {
            case JvmNestRelationStatus::resolved: return "resolved";
            case JvmNestRelationStatus::missing: return "missing";
            case JvmNestRelationStatus::ambiguous: return "ambiguous";
            case JvmNestRelationStatus::not_reciprocal: return "not-reciprocal";
            case JvmNestRelationStatus::cross_package: return "cross-package";
            }
            return "unknown";
        };
        out << "Nest metadata relations: " << workspace.nest_relations.size() << '\n';
        bounded_rows("nest relation", workspace.nest_relations, 256,
            [&](std::size_t, const JvmNestRelation &row) {
                out << "  " << nest_kind(row.kind) << " " << safe_text(row.source_class)
                    << " -> " << safe_text(row.target_class) << " status=" << nest_status(row.status)
                    << " source=class[" << row.source_metadata_index << "]+0x"
                    << std::hex << row.source_file_offset.value << std::dec;
                if (row.target_metadata_index) out << " target=class[" << *row.target_metadata_index << "]";
                out << '\n';
            });
        const auto permitted_status = [](JvmPermittedClassStatus value) -> std::string_view {
            switch (value) {
            case JvmPermittedClassStatus::resolved: return "resolved";
            case JvmPermittedClassStatus::missing: return "missing";
            case JvmPermittedClassStatus::ambiguous: return "ambiguous";
            case JvmPermittedClassStatus::not_direct_subtype: return "not-direct-subtype";
            }
            return "unknown";
        };
        out << "Permitted subclass links: " << graph.permitted_classes.size() << '\n';
        bounded_rows("permitted subclass", graph.permitted_classes, 256,
            [&](std::size_t, const JvmPermittedClassLink &row) {
                out << "  " << safe_text(row.source_class) << " permits " << safe_text(row.target_class)
                    << " status=" << permitted_status(row.status)
                    << " source=class[" << row.source_metadata_index << "]+0x"
                    << std::hex << row.source_file_offset.value << std::dec;
                if (row.target_metadata_index) out << " target=class[" << *row.target_metadata_index << "]";
                out << '\n';
            });
        if (configuration) {
            out << "Module configuration: complete=" << (configuration->complete ? "true" : "false")
                << " roots=" << configuration->roots.size() << " resolved-modules="
                << configuration->resolved_modules.size() << " unresolved-required="
                << configuration->unresolved_required_edges.size() << " omitted-optional="
                << configuration->omitted_optional_edges.size() << '\n';
            for (std::size_t i = 0; i < configuration->roots.size(); ++i) {
                const auto &root = configuration->roots[i];
                out << "  Module root: name=" << safe_text(root.name) << " status=" << status(root.status);
                if (root.module_definition) out << " definition=" << *root.module_definition;
                out << '\n';
            }
            for (std::size_t i = 0; i < configuration->resolved_modules.size(); ++i) {
                const auto index = configuration->resolved_modules[i];
                out << "  Resolved module[" << i << "]: definition=" << index
                    << " name=" << safe_text(graph.module_graph.modules[index].name) << '\n';
            }
            for (const auto edge_index : configuration->unresolved_required_edges)
                out << "  Unresolved required edge: " << edge_index << '\n';
            for (const auto edge_index : configuration->omitted_optional_edges)
                out << "  Omitted requires-static edge: " << edge_index << '\n';
        }
        out << "Roots:\n";
        bounded_rows("root", workspace.roots, 256, [&](std::size_t i, const JvmPathRootResult &row) {
            out << "  [" << i << "] " << (row.kind == JvmPathRootKind::module_path ? "module-path" : "class-path")
                << " status=" << (row.status == JvmPathRootStatus::linked ? "linked" : "missing-module-descriptor")
                << " files=" << row.files << " classes=" << row.classes;
            if (target_release) out << " multi-release=" << (row.multi_release_active ? "enabled" : "inactive")
                                    << " selected-overlays=" << row.selected_versioned_classes;
            if (row.module_name) out << " module=" << safe_text(*row.module_name);
            out << " path=" << safe_text(path_text(row.path)) << '\n';
        });
        out << "Effective class-path search order (manifest entries follow their declaring JAR):\n";
        bounded_rows("class-path order", workspace.class_path_search_order, 256,
            [&](std::size_t position, std::size_t root_index) {
                out << "  [" << position << "] root=" << root_index;
                if (root_index < workspace.roots.size()) out << " path=" << safe_text(path_text(workspace.roots[root_index].path));
                out << '\n';
            });
        const auto class_path_status = [](JvmClassPathReferenceStatus value) -> std::string_view {
            switch (value) {
            case JvmClassPathReferenceStatus::resolved: return "resolved";
            case JvmClassPathReferenceStatus::not_supplied: return "not-supplied";
            case JvmClassPathReferenceStatus::ambiguous: return "ambiguous";
            case JvmClassPathReferenceStatus::malformed_uri: return "malformed-uri";
            case JvmClassPathReferenceStatus::unsupported_uri: return "unsupported-uri";
            case JvmClassPathReferenceStatus::cycle: return "cycle";
            }
            return "unknown";
        };
        out << "Manifest Class-Path references (only caller-supplied roots are resolved):\n";
        bounded_rows("manifest Class-Path", workspace.class_path_references, 256,
            [&](std::size_t, const JvmClassPathReference &row) {
                out << "  source-root=" << row.declaring_root_index << " uri=" << safe_text(row.uri)
                    << " status=" << class_path_status(row.status);
                if (row.target_root_index) out << " target-root=" << *row.target_root_index;
                out << '\n';
            });
        out << "Selected versioned classes:\n";
        bounded_rows("versioned class", workspace.versioned_classes, 128,
            [&](std::size_t, const JvmPathVersionedClassSelection &row) {
                out << "  root=" << row.root_index << " release=" << row.release
                    << " logical=" << safe_text(row.logical_path) << " archive-entry=" << safe_text(row.archive_path)
                    << " data-file=0x" << std::hex << row.data_file_offset << std::dec
                    << " bytes=" << row.uncompressed_size << '\n';
            });
        out << "Modules:\n";
        bounded_rows("module", graph.module_graph.modules, 256, [&](std::size_t i, const JvmModuleLinkNode &row) {
            out << "  [" << i << "] " << safe_text(row.name) << (row.duplicate_definition ? " duplicate-definition" : "") << '\n';
        });
        out << "Module edges:\n";
        bounded_rows("edge", graph.module_graph.edges, 256, [&](std::size_t, const JvmModuleLinkEdge &row) {
            out << "  source=" << row.source_definition << " target=" << safe_text(row.target_name)
                << " kind=" << (row.kind == JvmModuleLinkEdgeKind::requires_module ? "requires" :
                    row.kind == JvmModuleLinkEdgeKind::qualified_export ? "qualified-export" : "qualified-open")
                << " status=" << status(row.status);
            if (row.kind == JvmModuleLinkEdgeKind::requires_module && row.transitive) out << " transitive=true";
            out << '\n';
        });
        out << "Module readability (descriptor-derived; self edges omitted):\n";
        bounded_rows("readability", graph.module_graph.readability, 512,
            [&](std::size_t, const JvmModuleReadability &row) {
                const std::string_view source = row.source_definition < graph.module_graph.modules.size()
                    ? std::string_view(graph.module_graph.modules[row.source_definition].name) : "<invalid-index>";
                const std::string_view target = row.target_definition < graph.module_graph.modules.size()
                    ? std::string_view(graph.module_graph.modules[row.target_definition].name) : "<invalid-index>";
                out << "  " << safe_text(source) << " reads " << safe_text(target)
                    << (row.direct ? " direct" : " via-transitive-requires") << '\n';
            });
        out << "Class ownership:\n";
        bounded_rows("class", graph.class_ownership, 128, [&](std::size_t, const JvmModuleClassOwnership &row) {
            out << "  " << safe_text(row.class_name) << " module=" << safe_text(row.module_name)
                << " status=" << status(row.status) << '\n';
        });
        out << "Packages:\n";
        bounded_rows("package", graph.packages, 128, [&](std::size_t, const JvmPackageOwnership &row) {
            out << "  " << (row.package_name.empty() ? "<default>" : safe_text(row.package_name))
                << " owners=";
            const auto owner_count = std::min<std::size_t>(row.module_definitions.size(), 8);
            for (std::size_t i = 0; i < owner_count; ++i) {
                if (i) out << ',';
                const auto definition = row.module_definitions[i];
                if (definition < graph.module_graph.modules.size()) out << safe_text(graph.module_graph.modules[definition].name);
                else out << "<invalid-index>";
            }
            if (row.module_definitions.size() > owner_count) out << ",...+" << row.module_definitions.size() - owner_count;
            out << (row.split_package ? " split" : "") << '\n';
        });
        out << "Services:\n";
        bounded_rows("service", graph.services, 256, [&](std::size_t, const JvmServiceLink &row) {
            const auto kind = row.kind == JvmServiceLinkKind::uses_service ? "uses" :
                row.kind == JvmServiceLinkKind::provides_service ? "provides" : "provider";
            out << "  source=" << row.source_definition << " kind=" << kind << " class=" << safe_text(row.class_name)
                << " status=" << status(row.status) << '\n';
        });
        out << "Requires cycles:\n";
        bounded_rows("cycle", graph.module_graph.requires_cycles, 64, [&](std::size_t, const std::vector<std::string> &cycle) {
            out << "  ";
            for (std::size_t i = 0; i < cycle.size(); ++i) out << (i ? " -> " : "") << safe_text(cycle[i]);
            out << '\n';
        });
        if (workspace.unnamed_classpath_module) out << "Unnamed classpath module index: " << *workspace.unnamed_classpath_module << '\n';
        for (const auto &requested : lookup_classes) {
            const auto lookup = take(resolve_jvm_class_path_class(workspace, requested));
            const auto lookup_status = lookup.status == JvmClassPathLookupStatus::resolved ? "resolved" :
                lookup.status == JvmClassPathLookupStatus::class_name_mismatch ? "class-name-mismatch" : "not-found";
            out << "Class-path lookup " << safe_text(lookup.requested_binary_name) << ": " << lookup_status;
            if (lookup.selected_definition) {
                const auto index = *lookup.selected_definition;
                if (index >= workspace.class_path_classes.size())
                    throw Failure{{ErrorCode::invalid_argument, "JVM class-path lookup returned an invalid definition index"}};
                const auto &definition = workspace.class_path_classes[index];
                out << " definition=" << index << " root=" << definition.root_index
                    << " class=" << safe_text(definition.class_name)
                    << " resource=" << safe_text(definition.resource_path);
                if (definition.root_index < workspace.roots.size())
                    out << " root-path=" << safe_text(path_text(workspace.roots[definition.root_index].path));
                if (definition.archive_path)
                    out << " archive-entry=" << safe_text(*definition.archive_path)
                        << " data-file=0x" << std::hex << definition.data_file_offset << std::dec
                        << " bytes=" << definition.uncompressed_size;
                if (lookup.module_definition && *lookup.module_definition < graph.module_graph.modules.size())
                    out << " module=" << safe_text(graph.module_graph.modules[*lookup.module_definition].name);
                out << " shadowed=" << lookup.shadowed_definitions.size();
                const auto shadow_preview = std::min<std::size_t>(lookup.shadowed_definitions.size(), 16);
                for (std::size_t i = 0; i < shadow_preview; ++i) {
                    const auto shadow = lookup.shadowed_definitions[i];
                    if (shadow < workspace.class_path_classes.size())
                        out << (i ? "," : " shadowed-definitions=") << shadow
                            << "@root" << workspace.class_path_classes[shadow].root_index;
                }
                if (lookup.shadowed_definitions.size() > shadow_preview)
                    out << " shadowed-omitted=" << lookup.shadowed_definitions.size() - shadow_preview;
            }
            out << '\n';
        }
        out << "Note: Class-Path order resolves only explicitly supplied local roots; runtime JPMS resolution and access enforcement are not performed.\n";
        return 0;
    } catch (const Failure &failure) {
        err << "JVM module path: " << failure.error.message << '\n';
        return failure.error.code == ErrorCode::invalid_argument ? 2 : 1;
    } catch (const ArgumentError &error) { err << error.message << '\n'; return 2; }
      catch (const std::exception &error) { err << "JVM module path: " << error.what() << '\n'; return 1; }
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
std::string_view string_encoding_label(StringEncoding encoding) {
    switch (encoding) {
    case StringEncoding::ascii: return "ASCII";
    case StringEncoding::utf16le: return "UTF-16LE";
    case StringEncoding::utf8: return "UTF-8";
    case StringEncoding::utf16be: return "UTF-16BE";
    case StringEncoding::utf32le: return "UTF-32LE";
    case StringEncoding::utf32be: return "UTF-32BE";
    case StringEncoding::windows1252: return "Windows-1252";
    case StringEncoding::windows1251: return "Windows-1251";
    case StringEncoding::windows1250: return "Windows-1250";
    case StringEncoding::windows1254: return "Windows-1254";
    case StringEncoding::windows1253: return "Windows-1253";
    case StringEncoding::windows1255: return "Windows-1255";
    case StringEncoding::windows1256: return "Windows-1256";
    case StringEncoding::windows1257: return "Windows-1257";
    case StringEncoding::windows1258: return "Windows-1258";
    case StringEncoding::iso8859_2: return "ISO-8859-2";
    case StringEncoding::iso8859_5: return "ISO-8859-5";
    case StringEncoding::dos437: return "DOS-437";
    case StringEncoding::dos850: return "DOS-850";
    case StringEncoding::iso8859_15: return "ISO-8859-15";
    case StringEncoding::iso8859_9: return "ISO-8859-9";
    case StringEncoding::dos866: return "DOS-866";
    case StringEncoding::dos852: return "DOS-852";
    case StringEncoding::koi8_r: return "KOI8-R";
    case StringEncoding::koi8_u: return "KOI8-U";
    case StringEncoding::mac_roman: return "Mac Roman";
    case StringEncoding::iso8859_1: return "ISO-8859-1";
    case StringEncoding::iso8859_3: return "ISO-8859-3";
    case StringEncoding::iso8859_4: return "ISO-8859-4";
    case StringEncoding::iso8859_6: return "ISO-8859-6";
    case StringEncoding::iso8859_7: return "ISO-8859-7";
    case StringEncoding::iso8859_10: return "ISO-8859-10";
    case StringEncoding::iso8859_13: return "ISO-8859-13";
    case StringEncoding::iso8859_14: return "ISO-8859-14";
    case StringEncoding::iso8859_16: return "ISO-8859-16";
    case StringEncoding::iso8859_8: return "ISO-8859-8";
    case StringEncoding::iso8859_11: return "ISO-8859-11";
    case StringEncoding::windows874: return "Windows-874";
    case StringEncoding::mac_cyrillic: return "Mac Cyrillic";
    case StringEncoding::ebcdic_cp037: return "EBCDIC CP037";
    case StringEncoding::ebcdic_cp500: return "EBCDIC CP500";
    case StringEncoding::ebcdic_cp1047: return "EBCDIC CP1047";
    case StringEncoding::windows932: return "Windows-932";
    case StringEncoding::windows936: return "Windows-936 (GBK)";
    case StringEncoding::windows949: return "Windows-949 (UHC)";
    case StringEncoding::windows950: return "Windows-950 (Big5)";
    }
    return "unknown";
}
OpenRequest parse(std::span<const std::wstring_view> args, bool disassemble,
                  std::vector<std::filesystem::path>& plugin_paths, bool &show_strings, bool &json_output) {
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
        if (!end_options && item == L"--show-strings") {
            show_strings = true;
            continue;
        }
        if (!end_options && item == L"--json") {
            json_output = true;
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
    if (!disassemble && (instructions || strings || minimum || show_strings || json_output))
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
    pe_description(out, m, document.image.get());
    jvm_description(out, m);
    wasm_description(out, m);
    dex_description(out, m);
    minidump_description(out, m);
}

int dex_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    if (!args.empty() && args[0] == L"vdex") {
        if (args.size() < 2 || args.size() > 3 || (args.size() == 3 && args[2] != L"--json")) {
            err << "Usage: hexlab_cli dex vdex <path> [--json]\n";
            return 2;
        }
        auto storage = FileStorage::open(path_from_wide(args[1]));
        if (!storage) { err << storage.error().message << '\n'; return 2; }
        auto inventory = inspect_android_vdex_027(*storage.value());
        if (!inventory) { err << inventory.error().message << '\n'; return 2; }
        const auto &vdex = inventory.value();
        if (args.size() == 3) {
            out << "{\"format\":\"Android VDEX 027\",\"file_size\":" << vdex.file_size.value
                << ",\"checksum_count\":" << vdex.dex_checksum_count << ",\"dex_section_present\":"
                << (vdex.dex_section_present ? "true" : "false") << ",\"sections\":[";
            for (std::size_t i = 0; i < vdex.sections.size(); ++i) {
                if (i) out << ',';
                const auto &section = vdex.sections[i];
                out << "{\"kind\":" << section.kind << ",\"offset\":" << section.file_offset.value
                    << ",\"size\":" << section.size << '}';
            }
            out << "],\"dex_members\":[";
            for (std::size_t i = 0; i < vdex.dex_members.size(); ++i) {
                if (i) out << ',';
                const auto &member = vdex.dex_members[i];
                out << "{\"index\":" << member.index << ",\"offset\":" << member.header_file_offset.value
                    << ",\"size\":" << member.file_size << ",\"version\":" << member.version
                    << ",\"header_checksum\":" << member.header_checksum
                    << ",\"vdex_checksum\":" << member.vdex_checksum
                    << ",\"checksum_fields_match\":" << (member.checksum_fields_match ? "true" : "false") << '}';
            }
            out << "]}\n";
        } else {
            out << "Android VDEX 027: " << vdex.file_size.value << " bytes sections=" << vdex.sections.size()
                << " checksums=" << vdex.dex_checksum_count << " dex-members=" << vdex.dex_members.size()
                << " dex-section=" << (vdex.dex_section_present ? "present" : "absent") << '\n';
            for (const auto &section : vdex.sections)
                out << "  section-kind=" << section.kind << " offset=0x" << std::hex << section.file_offset.value
                    << " size=0x" << section.size << std::dec << '\n';
            for (const auto &member : vdex.dex_members)
                out << "  dex[" << member.index << "] offset=0x" << std::hex << member.header_file_offset.value
                    << " size=0x" << member.file_size << std::dec << " version=" << member.version
                    << " header-checksum=0x" << std::hex << member.header_checksum
                    << " vdex-checksum=0x" << member.vdex_checksum << std::dec
                    << " fields-match=" << (member.checksum_fields_match ? "yes" : "no") << '\n';
            out << "Verifier dependencies and type-lookup data remain opaque.\n";
        }
        return 0;
    }
    if (!args.empty() && args[0] == L"apk") {
        if (args.size() < 2 || args.size() > 3 || (args.size() == 3 && args[2] != L"--json")) {
            err << "Usage: hexlab_cli dex apk <path> [--json]\n";
            return 2;
        }
        auto storage = FileStorage::open(path_from_wide(args[1]));
        if (!storage) { err << storage.error().message << '\n'; return 2; }
        auto members = load_android_dex_archive(*storage.value());
        if (!members) { err << members.error().message << '\n'; return 2; }
        if (args.size() == 3) {
            out << "{\"format\":\"APK DEX\",\"member_count\":" << members.value().size() << ",\"members\":[";
            for (std::size_t i = 0; i < members.value().size(); ++i) {
                if (i) out << ',';
                const auto &member = members.value()[i];
                const auto &dex = *member.loaded.metadata.dex;
                out << "{\"entry\":" << json_quote(member.entry_name)
                    << ",\"entry_index\":" << member.archive_entry_index
                    << ",\"logical_index\":" << member.logical_member_index
                    << ",\"data_offset\":" << member.data_offset
                    << ",\"compressed_size\":" << member.compressed_size
                    << ",\"uncompressed_size\":" << member.uncompressed_size
                    << ",\"crc32\":" << member.crc32
                    << ",\"class_count\":" << dex.classes.size()
                    << ",\"method_count\":" << dex.method_identifiers.size()
                    << ",\"code_count\":" << dex.code.size() << '}';
            }
            out << "]}\n";
        } else {
            out << "Android APK DEX: " << members.value().size() << " logical member(s)\n";
            for (const auto &member : members.value()) {
                const auto &dex = *member.loaded.metadata.dex;
                out << "  " << member.entry_name << " logical=" << member.logical_member_index
                    << " data=0x" << std::hex << member.data_offset << std::dec
                    << " compressed=" << member.compressed_size << " uncompressed=" << member.uncompressed_size
                    << " classes=" << dex.classes.size() << " methods=" << dex.method_identifiers.size()
                    << " code_items=" << dex.code.size() << '\n';
            }
        }
        return 0;
    }
    if (!args.empty() && args[0] == L"load-container") {
        if (args.size() < 2 || args.size() > 3 || (args.size() == 3 && args[2] != L"--json")) {
            err << "Usage: hexlab_cli dex load-container <path> [--json]\n";
            return 2;
        }
        auto storage = FileStorage::open(path_from_wide(args[1]));
        if (!storage) { err << storage.error().message << '\n'; return 2; }
        auto members = load_dex041_container(storage.value(), {});
        if (!members) { err << members.error().message << '\n'; return 2; }
        if (args.size() == 3) {
            out << "{\"format\":\"DEX 041\",\"container_size\":" << storage.value()->size()
                << ",\"member_count\":" << members.value().size() << ",\"members\":[";
            for (std::size_t i = 0; i < members.value().size(); ++i) {
                if (i) out << ',';
                const auto &loaded = members.value()[i];
                const auto &dex = *loaded.metadata.dex;
                out << "{\"index\":" << i << ",\"class_count\":" << dex.classes.size()
                    << ",\"method_count\":" << dex.method_identifiers.size()
                    << ",\"code_count\":" << dex.code.size() << '}';
            }
            out << "]}\n";
        } else {
            out << "DEX 041 parsed container: " << storage.value()->size() << " bytes, "
                << members.value().size() << " logical member(s)\n";
            for (std::size_t i = 0; i < members.value().size(); ++i) {
                const auto &dex = *members.value()[i].metadata.dex;
                out << "  [" << i << "] classes=" << dex.classes.size()
                    << " methods=" << dex.method_identifiers.size()
                    << " code_items=" << dex.code.size() << '\n';
            }
        }
        return 0;
    }
    if (args.size() < 2 || args.size() > 3 || args[0] != L"container" ||
        (args.size() == 3 && args[2] != L"--json")) {
        err << "Usage: hexlab_cli dex container <path> [--json]\n"
               "       hexlab_cli dex load-container <path> [--json]\n"
               "       hexlab_cli dex apk <path> [--json]\n"
               "       hexlab_cli dex vdex <path> [--json]\n";
        return 2;
    }
    const bool json = args.size() == 3;
    auto storage = FileStorage::open(path_from_wide(args[1]));
    if (!storage) { err << storage.error().message << '\n'; return 2; }
    auto members = inspect_dex041_container(*storage.value());
    if (!members) { err << members.error().message << '\n'; return 2; }
    if (json) {
        out << "{\"format\":\"DEX 041\",\"container_size\":" << storage.value()->size()
            << ",\"member_count\":" << members.value().size() << ",\"members\":[";
        for (std::size_t index = 0; index < members.value().size(); ++index) {
            if (index) out << ',';
            const auto &member = members.value()[index];
            out << "{\"index\":" << index << ",\"header_offset\":" << member.header_offset
                << ",\"logical_file_size\":" << member.logical_file_size
                << ",\"checksum\":" << member.checksum << ",\"signature\":\"";
            for (const auto byte : member.signature)
                out << std::hex << std::setw(2) << std::setfill('0')
                    << std::to_integer<unsigned>(byte);
            out << std::dec << "\"}";
        }
        out << "]}\n";
    } else {
        out << "DEX 041 container: " << storage.value()->size() << " bytes, "
            << members.value().size() << " logical member(s)\n";
        for (std::size_t index = 0; index < members.value().size(); ++index) {
            const auto &member = members.value()[index];
            out << "  [" << index << "] header=0x" << std::hex << member.header_offset
                << " size=0x" << member.logical_file_size << " checksum=0x" << member.checksum
                << " signature=";
            for (const auto byte : member.signature)
                out << std::setw(2) << std::setfill('0') << std::to_integer<unsigned>(byte);
            out << std::dec << '\n';
        }
    }
    return 0;
}
int macho_chained_targets_command(std::span<const std::wstring_view> args, std::ostream &out, std::ostream &err) {
    const auto usage = [&] {
        out << "Usage: hexlab_cli macho chained-targets <image> [--shared-cache-base <address>] "
               "[--cache-level-base <0..3> <address>]...\n";
        return 0;
    };
    if (args.empty() || (args.size() == 1 && args[0] == L"--help")) return usage();
    if (args.size() < 2 || args[0] != L"chained-targets") {
        err << "Expected macho chained-targets <image>\n";
        return 2;
    }
    const auto parse_address = [](std::wstring_view text) -> std::optional<std::uint64_t> {
        if (text.empty()) return {};
        std::string digits;
        digits.reserve(text.size());
        for (const auto ch : text) {
            if (ch > 0x7f) return {};
            digits.push_back(static_cast<char>(ch));
        }
        int base = 10;
        if (digits.starts_with("0x") || digits.starts_with("0X")) {
            digits.erase(0, 2);
            base = 16;
        }
        if (digits.empty()) return {};
        std::uint64_t value = 0;
        const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), value, base);
        if (error != std::errc{} || end != digits.data() + digits.size()) return {};
        return value;
    };
    MachOChainedTargetBases bases;
    for (std::size_t index = 2; index < args.size();) {
        if (args[index] == L"--shared-cache-base") {
            if (index + 1 >= args.size() || bases.shared_cache_base) {
                err << "--shared-cache-base requires one address and may appear once\n";
                return 2;
            }
            bases.shared_cache_base = parse_address(args[index + 1]);
            if (!bases.shared_cache_base) { err << "Invalid shared-cache base address\n"; return 2; }
            index += 2;
        } else if (args[index] == L"--cache-level-base") {
            if (index + 2 >= args.size()) { err << "--cache-level-base requires a level and address\n"; return 2; }
            const auto level = parse_address(args[index + 1]);
            const auto address = parse_address(args[index + 2]);
            if (!level || *level >= bases.cache_level_bases.size() || !address) {
                err << "Invalid cache-level base; expected a level 0..3 and an address\n";
                return 2;
            }
            if (bases.cache_level_bases[*level]) { err << "Duplicate cache-level base\n"; return 2; }
            bases.cache_level_bases[*level] = *address;
            index += 3;
        } else {
            err << "Unexpected Mach-O chained-targets option\n";
            return 2;
        }
    }
    auto storage = FileStorage::open(path_from_wide(args[1]));
    if (!storage) { err << storage.error().message << '\n'; return 2; }
    auto loaded = load_macho(storage.value(), MachOOptions{}, {});
    if (!loaded) { err << loaded.error().message << '\n'; return 2; }
    if (!loaded.value().metadata.macho) { err << "Selected input is not a Mach-O image\n"; return 2; }
    auto targets = resolve_macho_chained_external_targets(*loaded.value().metadata.macho, bases);
    if (!targets) { err << targets.error().message << '\n'; return 2; }
    const auto status_name = [](MachOChainedExternalTargetStatus status) {
        switch (status) {
        case MachOChainedExternalTargetStatus::resolved: return "resolved";
        case MachOChainedExternalTargetStatus::missing_base: return "missing-base";
        case MachOChainedExternalTargetStatus::invalid_encoding: return "invalid-encoding";
        case MachOChainedExternalTargetStatus::overflow: return "overflow";
        }
        return "unknown";
    };
    out << "Mach-O external chained rebases: " << targets.value().size() << " row(s)\n";
    constexpr std::size_t output_limit = 1024;
    const auto count = (std::min)(targets.value().size(), output_limit);
    for (std::size_t index = 0; index < count; ++index) {
        const auto &row = targets.value()[index];
        out << "  pointer=" << row.pointer_index << " status=" << status_name(row.status);
        if (row.base_kind == MachOChainedTargetBaseKind::cache_level && row.cache_level)
            out << " cache-level=" << unsigned(*row.cache_level);
        else out << " target-base=shared-cache";
        if (row.base_address) out << " base=" << hex(*row.base_address);
        if (row.target_address) out << " pre-pac-target=" << hex(*row.target_address);
        if (row.authentication_required) out << " authentication-required=true";
        out << '\n';
    }
    if (targets.value().size() > count) out << "  ... " << targets.value().size() - count << " rows omitted\n";
    return 0;
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
    if (arguments[0] == L"processors")
        return processors_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"archive")
        return archive_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"jar")
        return jar_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"jvm")
        return jvm_module_path_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"dex")
        return dex_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"macho")
        return macho_chained_targets_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"firmware")
        return firmware_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"compare")
        return run_compare_cli(arguments.subspan(1), out, err);
    if (arguments[0] == L"modules")
        return modules_command(arguments.subspan(1), out, err);
    if (arguments[0] == L"pe-deps")
        return pe_dependency_files_command(arguments.subspan(1), out, err);
    const bool functions_only = arguments[0] == L"functions";
    if (arguments[0] != L"inspect" && arguments[0] != L"disassemble" && arguments[0] != L"decompile" &&
        !functions_only) {
        err << "Invalid arguments. Use --help for usage.\n";
        return 2;
    }
    if (arguments.size() == 2 && arguments[1] == L"--help") {
        if (functions_only)
            out << "Usage: hexlab_cli functions <path> [input/analysis options] [--limit <count>] [--json]\n"
                   "       Input options match `disassemble`; --show-strings is not supported here.\n"
                   "       --limit caps returned rows (default 10000, maximum 100000).\n";
        else usage(out);
        return 0;
    }
    try {
        const bool decompile = arguments[0] == L"decompile";
        const bool disassemble = arguments[0] == L"disassemble" || decompile || functions_only;
        std::vector<std::filesystem::path> plugin_paths;
        bool show_strings = false;
        bool json_output = false;
        std::size_t function_limit = 10000;
        std::vector<std::wstring_view> parse_arguments;
        bool end_options = false, limit_seen = false;
        for (std::size_t index = 1; index < arguments.size(); ++index) {
            const auto argument = arguments[index];
            if (!functions_only || end_options || argument != L"--limit") {
                parse_arguments.push_back(argument);
                if (functions_only && argument == L"--") end_options = true;
                continue;
            }
            if (limit_seen || index + 1 >= arguments.size() || arguments[index + 1].starts_with(L"--"))
                argument_error("--limit requires one positive count and may appear once");
            const auto parsed_limit = number(arguments[++index]);
            if (parsed_limit == 0 || parsed_limit > 100000)
                argument_error("--limit must be between 1 and 100000");
            function_limit = static_cast<std::size_t>(parsed_limit);
            limit_seen = true;
        }
        auto request = parse(parse_arguments, disassemble, plugin_paths, show_strings, json_output);
        if (functions_only && show_strings)
            argument_error("--show-strings is not supported by the functions command");
        if (functions_only)
            request.run_analysis = false;
        if (json_output && (!disassemble || decompile))
            argument_error("--json is currently supported only by disassemble or functions");
        plugins::PluginManager plugin_manager(plugins::make_native_module_provider(),
                                               plugins::default_plugin_state_path());
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
        if (disassemble && !functions_only && !analysis) {
            err << "Unsupported analysis: this CPU/mode has no enabled decoder\n";
            return 1;
        }
        if (!json_output) metadata(out, document);
        diagnostics(err, document.diagnostics, document.image.get());
        if (functions_only)
            return functions_report(document, request.path, request.analysis_options,
                                    function_limit, json_output, out, err);
        if (!disassemble)
            return 0;
        if (show_strings) {
            if (!json_output) {
                out << "Strings:\n";
                for (const auto &candidate : analysis->strings.records) {
                    out << "  " << string_encoding_label(candidate.encoding)
                        << " script=" << string_script_name(classify_string_script(candidate.preview))
                        << " file=" << hex(candidate.file_offset.value)
                        << " bytes=" << candidate.byte_length
                        << " characters=" << candidate.characters
                        << (candidate.terminated ? " terminated" : "")
                        << " preview=" << candidate.preview << '\n';
                }
            }
        }
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
                    const auto *dex_metadata = document.metadata.dex ? &*document.metadata.dex : nullptr;
                    auto lifted = decompiler::lift_function(*function, *functions.value(), jvm_metadata, wasm_metadata, dex_metadata);
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
                const auto *dex_metadata = document.metadata.dex ? &*document.metadata.dex : nullptr;
                auto lifted = decompiler::lift_function(*function, *functions.value(), jvm_metadata, wasm_metadata, dex_metadata);
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
        if (json_output) {
            const auto flow_name = [](FlowKind flow) -> const char * {
                switch (flow) {
                case FlowKind::fallthrough: return "fallthrough";
                case FlowKind::call: return "call";
                case FlowKind::conditional_branch: return "conditional_branch";
                case FlowKind::jump: return "jump";
                case FlowKind::ret: return "return";
                case FlowKind::trap: return "trap";
                case FlowKind::switch_dispatch: return "switch_dispatch";
                case FlowKind::data: return "data";
                }
                return "unknown";
            };
            const auto access_name = [](OperandAccess access) -> const char * {
                switch (access) {
                case OperandAccess::read: return "read";
                case OperandAccess::write: return "write";
                case OperandAccess::read_write: return "read_write";
                case OperandAccess::address: return "address";
                }
                return "unknown";
            };
            out << "{\"schema\":\"hexlab.disassembly.v1\",\"path\":"
                << processor_inventory_json_string(path_text(request.path))
                << ",\"analysis_status\":"
                << processor_inventory_json_string(analysis->complete ? "complete" : "partial")
                << ",\"partial\":" << (analysis->complete ? "false" : "true")
                << ",\"instructions\":[";
            bool first = true;
            for (const auto &instruction : analysis->instructions) {
                if (!first) out << ',';
                first = false;
                std::ostringstream encoded;
                for (const auto byte : instruction.encoded_bytes())
                    encoded << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                            << std::to_integer<unsigned>(byte);
                out << "{\"address\":" << processor_inventory_json_string(
                           format_location(instruction.address, document.image.get()))
                    << ",\"bytes\":" << processor_inventory_json_string(encoded.str())
                    << ",\"text\":" << processor_inventory_json_string(format_instruction(instruction))
                    << ",\"flow\":" << processor_inventory_json_string(flow_name(instruction.flow))
                    << ",\"memory_read\":" << (instruction.memory_read ? "true" : "false")
                    << ",\"memory_write\":" << (instruction.memory_write ? "true" : "false")
                    << ",\"operand_access\":[";
                for (std::size_t i = 0; i < instruction.access.size(); ++i) {
                    if (i) out << ',';
                    out << processor_inventory_json_string(access_name(instruction.access[i]));
                }
                out << "]}";
            }
            out << ']';
            if (show_strings) {
                out << ",\"strings\":[";
                for (std::size_t i = 0; i < analysis->strings.records.size(); ++i) {
                    if (i) out << ',';
                    const auto &candidate = analysis->strings.records[i];
                    out << "{\"encoding\":" << processor_inventory_json_string(string_encoding_label(candidate.encoding))
                        << ",\"script_hint\":" << processor_inventory_json_string(
                            string_script_name(classify_string_script(candidate.preview)))
                        << ",\"file_offset\":" << processor_inventory_json_string(hex(candidate.file_offset.value))
                        << ",\"byte_length\":" << candidate.byte_length
                        << ",\"characters\":" << candidate.characters
                        << ",\"terminated\":" << (candidate.terminated ? "true" : "false")
                        << ",\"preview\":" << processor_inventory_json_string(candidate.preview) << '}';
                }
                out << ']';
            }
            out << "}\n";
            return analysis->complete ? 0 : 3;
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
