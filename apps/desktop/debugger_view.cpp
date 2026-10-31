#include "debugger_view.hpp"
#include "debugger_locals.hpp"
#include "hexlab/workspace/document.hpp"
#include "hexlab/workspace/project.hpp"

#include <wx/button.h>
#include <wx/accel.h>
#include <wx/clipbrd.h>
#include <wx/choice.h>
#include <wx/checkbox.h>
#include <wx/listctrl.h>
#include <wx/menu.h>
#include <wx/msgdlg.h>
#include <wx/app.h>
#include <wx/config.h>
#include <wx/dirdlg.h>
#include <wx/filedlg.h>
#include <wx/file.h>
#include <wx/filename.h>
#include <wx/notebook.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>

#include <charconv>
#include <algorithm>
#include <bit>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <exception>
#include <iterator>
#include <limits>
#include <mutex>
#include <set>
#include <condition_variable>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_map>
#include <tuple>
#include <thread>
#include <atomic>

namespace hexlab::desktop {
namespace {
enum : int { browse_executable_id = wxID_HIGHEST + 220, browse_working_directory_id, launch_id, attach_id, detach_id, terminate_id, wait_id, continue_id, step_id, source_step_over_id, source_step_out_id, pass_id,
            add_bp_id, remove_bp_id, apply_project_bp_id, save_breakpoint_rule_id, load_breakpoint_rule_id, poll_id, read_memory_id, remote_connect_id, continue_thread_id,
            thread_context_continue_id, thread_context_step_id, thread_context_stop_id, thread_context_interrupt_id,
            continue_stopped_peers_id,
            copy_thread_id, copy_visible_threads_id,
            previous_memory_id, next_memory_id, memory_history_back_id, memory_history_forward_id, watch_memory_byte_id, read_memory_tags_id,
            breakpoint_at_memory_id,
            copy_memory_id, copy_memory_address_id, save_memory_raw_id, copy_inspection_report_id, refresh_modules_id, refresh_processes_id,
            detach_remote_process_id,
            refresh_memory_regions_id, search_memory_region_id, open_memory_region_id, copy_memory_region_id, copy_visible_memory_regions_id, write_memory_id, write_register_id, navigate_pc_id, navigate_frame_id,
            copy_registers_id, copy_selected_register_id, copy_visible_registers_id, watch_register_id, navigate_register_id, pin_register_baseline_id, copy_module_id, copy_visible_modules_id, copy_output_id, copy_matching_output_id, save_output_id, clear_output_id, output_previous_id, output_next_id,
            memory_search_id, cancel_memory_search_id, copy_memory_search_id, copy_memory_search_report_id,
            add_watch_id, update_watch_id, remove_watch_id, refresh_watches_id, copy_watch_id, move_watch_up_id, move_watch_down_id,
            navigate_breakpoint_id, toggle_breakpoint_id, copy_breakpoints_id, copy_stack_id, copy_locals_id,
            inspect_local_address_id, inspect_frame_cfa_id, breakpoint_at_frame_id,
            refresh_auxv_id, copy_auxv_id, copy_visible_auxv_id, refresh_osdata_id, copy_osdata_id, refresh_signal_info_id,
            refresh_remote_file_id, run_remote_monitor_id };

std::string narrow(const wxString &value) { return value.ToStdString(); }
std::string os_data_cell(std::string_view value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(value.size());
    for (const unsigned char byte : value) {
        if (byte == '\n') output += "\\n";
        else if (byte == '\r') output += "\\r";
        else if (byte == '\t') output += "\\t";
        else if (byte < 0x20 || byte == 0x7f) {
            output += "\\x";
            output.push_back(digits[byte >> 4]);
            output.push_back(digits[byte & 0x0f]);
        } else output.push_back(static_cast<char>(byte));
    }
    return output;
}
std::string hex(std::span<const std::byte> bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string value = "0x";
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
        const auto b = std::to_integer<unsigned>(*it);
        value.push_back(digits[b >> 4]); value.push_back(digits[b & 15]);
    }
    return value;
}
std::string register_hex(const debugger::RegisterValue &reg) {
    if (!reg.available) return "Unavailable";
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string value = "0x";
    const bool big_endian = reg.byte_order == ByteOrder::big;
    for (std::size_t i = 0; i < reg.bytes.size(); ++i) {
        const auto index = big_endian ? i : reg.bytes.size() - 1 - i;
        const auto b = std::to_integer<unsigned>(reg.bytes[index]);
        value.push_back(digits[b >> 4]); value.push_back(digits[b & 15]);
    }
    return value;
}
std::string lower_register_text(std::string_view value) {
    std::string result(value);
    for (auto &character : result)
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    return result;
}
bool numbered_register(std::string_view name, std::string_view prefix) {
    if (!name.starts_with(prefix) || name.size() == prefix.size()) return false;
    return std::all_of(name.begin() + static_cast<std::ptrdiff_t>(prefix.size()), name.end(),
                       [](char value) { return value >= '0' && value <= '9'; });
}
std::string register_architecture_label(const debugger::RegisterValue &reg) {
    const auto architecture = lower_register_text(reg.target_architecture);
    if (architecture.find("x86-64") != std::string::npos || architecture.find("x86_64") != std::string::npos ||
        architecture.find("amd64") != std::string::npos) return "x86-64";
    if (architecture.find("i386") != std::string::npos || architecture == "x86") return "x86";
    if (architecture.find("aarch64") != std::string::npos || architecture.find("arm64") != std::string::npos) return "AArch64";
    if (architecture == "arm" || architecture.find("armv") != std::string::npos) return "ARM";
    if (architecture.find("riscv64") != std::string::npos || architecture == "rv64") return "RISC-V 64";
    if (architecture.find("riscv32") != std::string::npos || architecture == "rv32") return "RISC-V 32";
    if (architecture.find("mips64") != std::string::npos) return "MIPS64";
    if (architecture.find("mips") != std::string::npos) return "MIPS";
    if (architecture.find("powerpc64") != std::string::npos || architecture.find("ppc64") != std::string::npos) return "PowerPC64";
    if (architecture.find("powerpc") != std::string::npos || architecture.find("ppc") != std::string::npos) return "PowerPC";
    const auto name = lower_register_text(reg.name);
    if (name.starts_with("xmm") || name.starts_with("ymm") || name.starts_with("zmm") ||
        name.starts_with("st") || name == "mxcsr" || name == "fcw") return "x86";
    if (name.starts_with("q") || name.starts_with("v") || name == "cpsr" || name == "fpscr" ||
        name == "fpcr" || name == "fpsr" || name == "pstate" || name == "spsr" ||
        (reg.target_architecture.empty() && (numbered_register(name, "b") || numbered_register(name, "h") ||
                                             numbered_register(name, "s") || numbered_register(name, "d"))))
        return "ARM/AArch64";
    if (name == "rip" || name == "eip" || name == "ip" || name == "rflags" || name == "eflags" ||
        name == "flags" || name == "cs" || name == "ss" || name == "ds" || name == "es" ||
        name == "fs" || name == "gs") return "x86";
    return {};
}
std::string register_bank_label(const debugger::RegisterValue &reg) {
    const auto name = lower_register_text(reg.name);
    const auto group = lower_register_text(reg.group);
    const auto architecture = register_architecture_label(reg);
    std::string category;
    if (group == "vector" || group.find(".sse") != std::string::npos || group.find(".avx") != std::string::npos ||
        group.find("neon") != std::string::npos) category = "Vector";
    else if (group == "floating-point" || group.find("fpu") != std::string::npos || group.find(".fp") != std::string::npos)
        category = "Floating-point";
    else if (group == "general" || group.find(".core") != std::string::npos) category = "General-purpose";
    else if (!reg.type.empty() && (lower_register_text(reg.type).find("ieee") != std::string::npos ||
                                    lower_register_text(reg.type).find("float") != std::string::npos))
        category = "Floating-point";
    else if (!group.empty() && group != "other") category = reg.group;
    if (category.empty()) {
        if (numbered_register(name, "xmm") || numbered_register(name, "ymm") ||
            numbered_register(name, "zmm") || numbered_register(name, "v") ||
            numbered_register(name, "q") ||
            ((architecture == "ARM" || architecture == "AArch64" || architecture == "ARM/AArch64") &&
             (numbered_register(name, "b") || numbered_register(name, "h") ||
              numbered_register(name, "s") || numbered_register(name, "d")))) category = "Vector";
        else if (numbered_register(name, "st") || numbered_register(name, "mm") ||
                 numbered_register(name, "f") || name == "fcw" || name == "fsw" ||
                 name == "ftw" || name == "fop" || name == "fip" || name == "fdp" ||
                 name == "fcs" || name == "fds" || name == "mxcsr" || name == "fpscr" ||
                 name == "fpcr" || name == "fpsr" || name == "fcsr" || name == "frm" ||
                 name == "fflags") category = "Floating-point";
        else if (name == "pc" || name == "rip" || name == "eip" || name == "ip" ||
                 name == "rflags" || name == "eflags" || name == "flags" || name == "cpsr" ||
                 name == "pstate" || name == "spsr" || name == "hi" || name == "lo" ||
                 name == "cause" || name == "status" || name == "epc" || name == "lr" ||
                 name == "ctr" || name == "xer" || name == "cr" || name == "mstatus" ||
                 name == "sstatus" || name == "mtvec" || name == "stvec" || name == "mepc" ||
                 name == "sepc" || name == "mcause" || name == "scause" || name == "satp" ||
                 name == "mhartid" || name.starts_with("cr") || name.starts_with("dr") ||
                 name.starts_with("seg")) category = "Special";
        else category = "Other";
    }
    return architecture.empty() ? category : architecture + " / " + category;
}
std::optional<std::uint64_t> register_u64(const debugger::RegisterValue &reg) {
    if (!reg.available) return {};
    if (reg.bytes.size() != 8) return {};
    std::uint64_t value = 0;
    const bool big_endian = reg.byte_order == ByteOrder::big;
    for (std::size_t i = 0; i < reg.bytes.size(); ++i) {
        const auto index = big_endian ? i : reg.bytes.size() - 1 - i;
        value = (value << 8) | std::to_integer<std::uint8_t>(reg.bytes[index]);
    }
    return value;
}
std::string register_display_value(const debugger::RegisterValue &reg, int format) {
    if (format <= 0 || !reg.available || reg.bytes.empty() || reg.bytes.size() > 8 || !reg.byte_order)
        return register_hex(reg);
    const auto bank = register_bank_label(reg);
    if (bank.find("Vector") != std::string::npos || bank.find("Floating-point") != std::string::npos)
        return register_hex(reg);
    std::uint64_t value = 0;
    const bool big_endian = *reg.byte_order == ByteOrder::big;
    for (std::size_t i = 0; i < reg.bytes.size(); ++i) {
        const auto index = big_endian ? i : reg.bytes.size() - 1 - i;
        value = (value << 8) | std::to_integer<std::uint8_t>(reg.bytes[index]);
    }
    if (format == 1) return std::to_string(value);
    if (format != 2) return register_hex(reg);
    const auto bits = static_cast<unsigned>(reg.bytes.size() * 8);
    const auto sign = std::uint64_t{1} << (bits - 1);
    if ((value & sign) == 0) return std::to_string(value);
    if (bits < 64) value |= ~std::uint64_t{0} << bits;
    const auto magnitude = (~value) + 1;
    return "-" + std::to_string(magnitude);
}
std::string_view auxiliary_vector_type_name(std::uint64_t type) {
    switch (type) {
    case 0: return "AT_NULL";
    case 1: return "AT_IGNORE";
    case 2: return "AT_EXECFD";
    case 3: return "AT_PHDR";
    case 4: return "AT_PHENT";
    case 5: return "AT_PHNUM";
    case 6: return "AT_PAGESZ";
    case 7: return "AT_BASE";
    case 8: return "AT_FLAGS";
    case 9: return "AT_ENTRY";
    case 10: return "AT_NOTELF";
    case 11: return "AT_UID";
    case 12: return "AT_EUID";
    case 13: return "AT_GID";
    case 14: return "AT_EGID";
    case 15: return "AT_PLATFORM";
    case 16: return "AT_HWCAP";
    case 17: return "AT_CLKTCK";
    case 23: return "AT_SECURE";
    case 24: return "AT_BASE_PLATFORM";
    case 25: return "AT_RANDOM";
    case 26: return "AT_HWCAP2";
    case 31: return "AT_EXECFN";
    case 32: return "AT_SYSINFO";
    case 33: return "AT_SYSINFO_EHDR";
    case 51: return "AT_MINSIGSTKSZ";
    default: return {};
    }
}
std::string event_name(debugger::EventKind kind) {
    using debugger::EventKind;
    switch (kind) {
    case EventKind::breakpoint: return "breakpoint";
    case EventKind::single_step: return "single step";
    case EventKind::exception: return "exception";
    case EventKind::thread_created: return "thread created";
    case EventKind::thread_exited: return "thread exited";
    case EventKind::module_loaded: return "module loaded";
    case EventKind::module_unloaded: return "module unloaded";
    case EventKind::process_exited: return "process exited";
    case EventKind::output: return "debug output";
    case EventKind::unknown: return "debug event";
    case EventKind::interrupted: return "debugger interrupt";
    }
    return "debug event";
}
std::string_view process_architecture_label(Architecture architecture) {
    switch (architecture) {
    case Architecture::x86: return "x86";
    case Architecture::x86_64: return "x86_64";
    case Architecture::arm: return "ARM";
    case Architecture::arm64: return "AArch64";
    case Architecture::riscv32: return "RISC-V 32";
    case Architecture::riscv64: return "RISC-V 64";
    case Architecture::mips32: return "MIPS32";
    case Architecture::mips64: return "MIPS64";
    case Architecture::powerpc: return "PowerPC";
    case Architecture::mos6502: return "MOS 6502";
    case Architecture::wasm: return "WebAssembly";
    case Architecture::dex: return "DEX";
    case Architecture::jvm: return "JVM";
    case Architecture::unknown: return "unknown";
    }
    return "unknown";
}
bool parse_unsigned(std::string_view text, std::uint64_t &value) {
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) { text.remove_prefix(2); base = 16; }
    if (text.empty()) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}
wxString watch_value_display(std::string_view value, int format) {
    if (format == 0 || !value.starts_with("0x")) return wxString::FromUTF8(value.data(), value.size());
    std::uint64_t number = 0;
    const auto digits = value.substr(2);
    const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), number, 16);
    if (digits.empty() || parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size())
        return wxString::FromUTF8(value.data(), value.size());
    if (format == 2) {
        const auto signed_number = number <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
            ? static_cast<std::int64_t>(number)
            : -1 - static_cast<std::int64_t>(std::numeric_limits<std::uint64_t>::max() - number);
        return wxString::Format("%lld", static_cast<long long>(signed_number));
    }
    return wxString::Format("%llu", static_cast<unsigned long long>(number));
}
const char *memory_search_completion(debugger::MemorySearchCompletion completion) {
    using debugger::MemorySearchCompletion;
    switch (completion) {
    case MemorySearchCompletion::completed: return "Complete";
    case MemorySearchCompletion::completed_with_read_failures: return "Complete with read failures";
    case MemorySearchCompletion::byte_budget_exhausted: return "Stopped at byte budget";
    case MemorySearchCompletion::comparison_budget_exhausted: return "Stopped at comparison budget";
    case MemorySearchCompletion::result_limit_reached: return "Stopped at result limit";
    case MemorySearchCompletion::canceled: return "Canceled";
    case MemorySearchCompletion::read_failed: return "Stopped after read failure";
    case MemorySearchCompletion::read_failure_limit_reached: return "Stopped at read-failure limit";
    case MemorySearchCompletion::backend_protocol_error: return "Backend protocol error";
    }
    return "Unknown completion";
}
const char *memory_search_completion_id(debugger::MemorySearchCompletion completion) {
    using debugger::MemorySearchCompletion;
    switch (completion) {
    case MemorySearchCompletion::completed: return "completed";
    case MemorySearchCompletion::completed_with_read_failures: return "completed_with_read_failures";
    case MemorySearchCompletion::byte_budget_exhausted: return "byte_budget_exhausted";
    case MemorySearchCompletion::comparison_budget_exhausted: return "comparison_budget_exhausted";
    case MemorySearchCompletion::result_limit_reached: return "result_limit_reached";
    case MemorySearchCompletion::canceled: return "canceled";
    case MemorySearchCompletion::read_failed: return "read_failed";
    case MemorySearchCompletion::read_failure_limit_reached: return "read_failure_limit_reached";
    case MemorySearchCompletion::backend_protocol_error: return "backend_protocol_error";
    }
    return "unknown";
}
const char *debugger_error_code_name(ErrorCode code) {
    switch (code) {
    case ErrorCode::overflow: return "overflow";
    case ErrorCode::out_of_bounds: return "out_of_bounds";
    case ErrorCode::invalid_argument: return "invalid_argument";
    case ErrorCode::io: return "io";
    case ErrorCode::unsupported: return "unsupported";
    case ErrorCode::malformed: return "malformed";
    case ErrorCode::canceled: return "canceled";
    case ErrorCode::resource_limit: return "resource_limit";
    case ErrorCode::conflict: return "conflict";
    case ErrorCode::read_only: return "read_only";
    case ErrorCode::busy: return "busy";
    case ErrorCode::integrity: return "integrity";
    }
    return "unknown";
}
std::string json_quote_utf8(std::string_view text) {
    std::string result{"\""};
    if (text.empty()) return "\"\"";
    const auto normalized = wxString::FromUTF8(text.data(), text.size()).ToUTF8();
    if (normalized) {
        constexpr char digits[] = "0123456789abcdef";
        for (const auto byte : std::string_view(normalized.data(), normalized.length())) {
            const auto value = static_cast<unsigned char>(byte);
            switch (value) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (value < 0x20) {
                    result += "\\u00";
                    result += digits[value >> 4];
                    result += digits[value & 0x0f];
                } else result.push_back(static_cast<char>(value));
            }
        }
    }
    result.push_back('"');
    return result;
}
bool parse_hex_bytes(std::string_view text, std::vector<std::byte> &bytes, std::size_t maximum,
                     bool &too_many) {
    bytes.clear();
    too_many = false;
    int high = -1;
    for (const unsigned char ch : text) {
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ',' || ch == ':') continue;
        int nibble = ch >= '0' && ch <= '9' ? ch - '0' :
                     ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 :
                     ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
        if (nibble < 0) return false;
        if (high < 0) high = nibble;
        else {
            if (bytes.size() == maximum) { too_many = true; return false; }
            bytes.push_back(static_cast<std::byte>((high << 4) | nibble)); high = -1;
        }
    }
    return high < 0 && !bytes.empty();
}
bool split_arguments(std::string_view input, std::vector<std::string> &out) {
    std::string current;
    bool quoted = false, started = false;
    for (char ch : input) {
        if (ch == '"') { quoted = !quoted; started = true; }
        else if (!quoted && (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')) {
            if (started) { out.push_back(std::move(current)); current.clear(); started = false; }
        } else { current.push_back(ch); started = true; }
    }
    if (quoted) return false;
    if (started) out.push_back(std::move(current));
    return true;
}
bool parse_remote_environment(std::string_view input,
                              std::vector<debugger::RemoteEnvironmentChange> &out,
                              std::string &error) {
    out.clear();
    if (input.size() > 256 * 1024) {
        error = "Remote environment editor exceeds the 256 KiB text limit.";
        return false;
    }
    std::set<std::string, std::less<>> names;
    std::size_t total_bytes = 0;
    std::size_t line_number = 0;
    const auto append = [&](debugger::RemoteEnvironmentChange change) {
        const auto fail = [&](std::string message) {
            error = "Remote environment line " + std::to_string(line_number) + " " + std::move(message);
            return false;
        };
        if (change.name.empty() || change.name.find('=') != std::string::npos ||
            change.name.find('\0') != std::string::npos ||
            (change.value && change.value->find('\0') != std::string::npos))
            return fail("has an empty or invalid name, or a value containing NUL.");
        if (change.name.size() > 4096) return fail("exceeds the 4 KiB variable-name limit.");
        if (change.value && change.value->size() > 16 * 1024)
            return fail("exceeds the 16 KiB value limit.");
        if (!names.insert(change.name).second)
            return fail("repeats a variable name.");
        const auto cost = change.name.size() + (change.value ? change.value->size() : 0);
        if (cost > 64 * 1024 - total_bytes) {
            error = "Remote environment settings exceed the 64 KiB combined name/value limit.";
            return false;
        }
        total_bytes += cost;
        if (out.size() == 256) {
            error = "Remote environment settings exceed the 256-change limit.";
            return false;
        }
        out.push_back(std::move(change));
        return true;
    };
    while (!input.empty()) {
        ++line_number;
        const auto newline = input.find('\n');
        auto line = input.substr(0, newline);
        if (newline == std::string_view::npos) input = {};
        else input.remove_prefix(newline + 1);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty() || line.front() == '#') continue;

        if (line.front() == '-') {
            line.remove_prefix(1);
            if (line.empty() || line.find('=') != std::string_view::npos) {
                error = "Remote environment line " + std::to_string(line_number) +
                    " must use -NAME to unset a variable.";
                return false;
            }
            if (line.size() > 4096) {
                error = "Remote environment line " + std::to_string(line_number) +
                    " exceeds the 4 KiB variable-name limit.";
                return false;
            }
            if (!append({std::string(line), std::nullopt})) return false;
            continue;
        }
        const auto separator = line.find('=');
        if (separator == std::string_view::npos || separator == 0) {
            error = "Remote environment line " + std::to_string(line_number) +
                " must use NAME=VALUE or -NAME.";
            return false;
        }
        if (separator > 4096) {
            error = "Remote environment line " + std::to_string(line_number) +
                " exceeds the 4 KiB variable-name limit.";
            return false;
        }
        auto value = line.substr(separator + 1);
        std::string decoded_value;
        if (value.starts_with("hex:")) {
            value.remove_prefix(4);
            if (value.size() % 2 != 0) {
                error = "Remote environment line " + std::to_string(line_number) +
                    " has an odd number of hexadecimal value digits.";
                return false;
            }
            if (value.size() > 32 * 1024) {
                error = "Remote environment line " + std::to_string(line_number) +
                    " exceeds the 16 KiB decoded value limit.";
                return false;
            }
            decoded_value.reserve(value.size() / 2);
            const auto hex_digit = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            for (std::size_t i = 0; i < value.size(); i += 2) {
                const auto high = hex_digit(value[i]);
                const auto low = hex_digit(value[i + 1]);
                if (high < 0 || low < 0) {
                    error = "Remote environment line " + std::to_string(line_number) +
                        " contains a non-hexadecimal value digit.";
                    return false;
                }
                decoded_value.push_back(static_cast<char>((high << 4) | low));
            }
        } else {
            if (value.size() > 16 * 1024) {
                error = "Remote environment line " + std::to_string(line_number) +
                    " exceeds the 16 KiB value limit.";
                return false;
            }
            decoded_value.assign(value);
        }
        if (!append({std::string(line.substr(0, separator)), std::move(decoded_value)})) return false;
    }
    return true;
}
wxButton *make_button(wxWindow *parent, const wxString &name, const wxString &label, int id) {
    auto *button = new wxButton(parent, id, label); button->SetName(name); return button;
}
wxTextCtrl *make_text(wxWindow *parent, const wxString &name, long style = 0) {
    auto *text = new wxTextCtrl(parent, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, style);
    text->SetName(name); return text;
}
wxListCtrl *make_list(wxWindow *parent, const wxString &name, std::initializer_list<const char *> columns) {
    auto *list = new wxListCtrl(parent, wxID_ANY, wxDefaultPosition, wxDefaultSize,
                                wxLC_REPORT | wxLC_SINGLE_SEL | wxBORDER_SIMPLE);
    list->SetName(name);
    int i = 0; for (auto *column : columns) list->InsertColumn(i++, column);
    return list;
}
wxString debugger_project_config_path(const database::ProjectUuid &uuid) {
    static constexpr char digits[] = "0123456789abcdef";
    wxString key = "/Debugger/Watches/";
    for (const auto byte : uuid) {
        const auto value = std::to_integer<unsigned>(byte);
        key += digits[value >> 4]; key += digits[value & 15];
    }
    return key;
}
wxString debugger_remote_config_path(const database::ProjectUuid &uuid) {
    auto key = debugger_project_config_path(uuid);
    key.Replace("/Debugger/Watches/", "/Debugger/Remote/");
    return key;
}
} // namespace

struct DebuggerView::TerminationState {
    std::mutex mutex;
    DebuggerView *target = nullptr;
    std::optional<debugger::Status> result;
};

struct DebuggerView::InspectionState {
    struct Task { int kind; std::function<void()> run; };
    std::mutex mutex;
    std::mutex backend_mutex;
    std::condition_variable ready;
    std::deque<Task> tasks;
    DebuggerView *target = nullptr;
    std::atomic_bool stopping{false};
    std::atomic<std::uint64_t> session_generation{1}, stop_generation{1};
    std::uint64_t session_id = 0;
};

DebuggerView::DebuggerView(wxWindow *parent, std::unique_ptr<debugger::Backend> backend,
                           std::function<std::shared_ptr<const hexlab::DocumentSnapshot>()> document,
                           std::function<void(DocumentId, Location)> navigate,
                           std::function<std::optional<std::pair<DocumentId, Location>>()> selection,
                           std::function<void(ProjectCommand)> submit,
                           std::function<bool(std::vector<database::BreakpointHitCount>)> persist_hit_counts)
    : wxPanel(parent), session_(std::make_shared<debugger::DebugSession>(backend ? std::move(backend) :
          debugger::make_backend_router(debugger::make_native_backend()))),
      termination_state_(std::make_shared<TerminationState>()), poll_timer_(this, poll_id),
      document_(std::move(document)), navigate_(std::move(navigate)), selection_(std::move(selection)), submit_(std::move(submit)),
      persist_hit_counts_(std::move(persist_hit_counts)) {
    termination_state_->target = this;
    inspection_state_ = std::make_shared<InspectionState>();
    static std::atomic<std::uint64_t> next_session_id{1};
    inspection_state_->session_id = next_session_id.fetch_add(1, std::memory_order_relaxed);
    inspection_state_->target = this;
    auto inspection = inspection_state_;
    std::thread([inspection] {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock lock(inspection->mutex);
                inspection->ready.wait(lock, [&] { return inspection->stopping || !inspection->tasks.empty(); });
                if (inspection->stopping && inspection->tasks.empty()) return;
                task = std::move(inspection->tasks.front().run);
                inspection->tasks.pop_front();
            }
            try { task(); } catch (...) { }
        }
    }).detach();
    auto *root = new wxBoxSizer(wxVERTICAL);
    auto *target = new wxFlexGridSizer(2, FromDIP(5), FromDIP(5));
    target->AddGrowableCol(1, 1);
    target->Add(new wxStaticText(this, wxID_ANY, "Executable"), 0, wxALIGN_CENTER_VERTICAL);
    executable_ = make_text(this, "debug-executable");
    auto *executable_controls = new wxBoxSizer(wxHORIZONTAL);
    executable_controls->Add(executable_, 1, wxRIGHT, FromDIP(4));
    executable_controls->Add(make_button(this, "debug-browse-executable", "Browse...", browse_executable_id), 0);
    target->Add(executable_controls, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Arguments"), 0, wxALIGN_CENTER_VERTICAL);
    arguments_ = make_text(this, "debug-arguments"); target->Add(arguments_, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Working directory"), 0, wxALIGN_CENTER_VERTICAL);
    working_directory_ = make_text(this, "debug-working-directory");
    working_directory_->SetHint("Target-side directory; empty uses the default");
    auto *working_directory_controls = new wxBoxSizer(wxHORIZONTAL);
    working_directory_controls->Add(working_directory_, 1, wxRIGHT, FromDIP(4));
    working_directory_controls->Add(make_button(this, "debug-browse-working-directory", "Browse...", browse_working_directory_id), 0);
    target->Add(working_directory_controls, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Remote environment"), 0, wxALIGN_TOP);
    remote_environment_ = make_text(this, "debug-remote-environment",
                                    wxTE_MULTILINE | wxTE_DONTWRAP);
    remote_environment_->SetMinSize(wxSize(-1, FromDIP(56)));
    remote_environment_->SetHint("NAME=VALUE, NAME=hex:HEX, or -NAME; lines beginning with # are comments");
    target->Add(remote_environment_, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, ""), 0);
    remote_environment_status_ = new wxStaticText(this, wxID_ANY,
        "Use NAME=VALUE, NAME=hex:HEX, or -NAME; # lines are comments.");
    remote_environment_status_->SetName("debug-remote-environment-status");
    target->Add(remote_environment_status_, 0, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Process"), 0, wxALIGN_CENTER_VERTICAL);
    auto *process_controls = new wxBoxSizer(wxVERTICAL);
    process_filter_ = make_text(this, "debug-process-filter");
    process_filter_->SetMaxLength(2048);
    process_filter_->SetHint("Filter process ID, name, or architecture");
    process_sort_ = new wxChoice(this, wxID_ANY);
    process_sort_->SetName("debug-process-sort");
    process_sort_->Append("PID order");
    process_sort_->Append("Name order");
    process_sort_->Append("Architecture order");
    process_sort_->SetSelection(0);
    process_filter_status_ = new wxStaticText(this, wxID_ANY, "0 of 0 processes");
    process_filter_status_->SetName("debug-process-filter-status");
    auto *process_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    process_filter_controls->Add(process_filter_, 1, wxRIGHT | wxBOTTOM, FromDIP(3));
    process_filter_controls->Add(process_sort_, 0, wxBOTTOM, FromDIP(2));
    process_controls->Add(process_filter_controls, 0, wxEXPAND);
    process_controls->Add(process_filter_status_, 0, wxEXPAND | wxBOTTOM, FromDIP(2));
    auto *process_picker = new wxBoxSizer(wxHORIZONTAL);
    processes_choice_ = new wxChoice(this, wxID_ANY); processes_choice_->SetName("debug-processes");
    process_picker->Add(processes_choice_, 1, wxRIGHT, FromDIP(4));
    process_picker->Add(make_button(this, "debug-refresh-processes", "Refresh", refresh_processes_id), 0, wxRIGHT, FromDIP(4));
    detach_remote_process_button_ = make_button(this, "debug-detach-secondary-process", "Detach secondary", detach_remote_process_id);
    detach_remote_process_button_->SetToolTip("Detach the selected listed remote process while keeping the active process attached.");
    detach_remote_process_button_->Disable();
    process_picker->Add(detach_remote_process_button_, 0, wxRIGHT, FromDIP(4));
    process_id_ = make_text(this, "debug-process-id", wxTE_PROCESS_ENTER); process_id_->SetHint("PID (decimal/hex)");
    process_picker->Add(process_id_, 0);
    process_controls->Add(process_picker, 0, wxEXPAND);
    target->Add(process_controls, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Remote host / port"), 0, wxALIGN_CENTER_VERTICAL);
    auto *remote = new wxBoxSizer(wxHORIZONTAL);
    remote_host_ = make_text(this, "debug-remote-host"); remote_host_->SetValue("127.0.0.1");
    remote_port_ = make_text(this, "debug-remote-port"); remote_port_->SetValue("1234");
    remote->Add(remote_host_, 1, wxRIGHT, FromDIP(4)); remote->Add(remote_port_, 0, wxRIGHT, FromDIP(4));
    remote_connect_button_ = make_button(this, "debug-remote-connect", "Connect RSP", remote_connect_id);
    remote->Add(remote_connect_button_, 0);
    target->Add(remote, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "RSP packet limit"), 0, wxALIGN_CENTER_VERTICAL);
    auto *remote_options = new wxBoxSizer(wxHORIZONTAL);
    remote_packet_limit_ = make_text(this, "debug-remote-packet-limit");
    remote_packet_limit_->SetValue("1048576");
    remote_packet_limit_->SetHint("128..1048576 bytes");
    remote_options->Add(remote_packet_limit_, 0, wxRIGHT, FromDIP(5));
    remote_no_ack_ = new wxCheckBox(this, wxID_ANY, "No ACK"); remote_no_ack_->SetName("debug-remote-no-ack"); remote_no_ack_->SetValue(true);
    remote_non_stop_ = new wxCheckBox(this, wxID_ANY, "Non-stop"); remote_non_stop_->SetName("debug-remote-non-stop"); remote_non_stop_->SetValue(true);
    remote_thread_events_ = new wxCheckBox(this, wxID_ANY, "Thread events"); remote_thread_events_->SetName("debug-remote-thread-events"); remote_thread_events_->SetValue(true);
    remote_options->Add(remote_no_ack_, 0, wxRIGHT, FromDIP(6));
    remote_options->Add(remote_non_stop_, 0, wxRIGHT, FromDIP(6));
    remote_options->Add(remote_thread_events_, 0);
    target->Add(remote_options, 1, wxEXPAND);
    target->Add(new wxStaticText(this, wxID_ANY, "Negotiated target"), 0, wxALIGN_TOP);
    remote_metadata_ = make_text(this, "debug-remote-target-metadata", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    remote_metadata_->SetMinSize(wxSize(-1, FromDIP(38)));
    remote_metadata_->SetHint("Architecture, pointer width, byte order, and packet size appear after connection");
    target->Add(remote_metadata_, 1, wxEXPAND);
    root->Add(target, 0, wxEXPAND | wxALL, FromDIP(6));

    auto *actions = new wxBoxSizer(wxHORIZONTAL);
    actions->Add(make_button(this, "debug-launch", "Launch", launch_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-attach", "Attach", attach_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-detach", "Detach / Disconnect", detach_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-terminate", "Terminate target", terminate_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-wait-event", "Wait Event", wait_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-continue", "Continue", continue_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-continue-thread", "Continue selected thread", continue_thread_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-step", "Step", step_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-step-over", "Step over", source_step_over_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-step-out", "Step out", source_step_out_id), 0, wxRIGHT, FromDIP(4));
    actions->Add(make_button(this, "debug-pass-event", "Pass Exception", pass_id), 0);
    actions->Add(make_button(this, "debug-show-thread-pc", "Show thread PC", navigate_pc_id), 0, wxLEFT, FromDIP(4));
    actions->Add(make_button(this, "debug-show-frame-pc", "Show frame PC", navigate_frame_id), 0, wxLEFT, FromDIP(4));
    root->Add(actions, 0, wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));

    auto *summary = new wxBoxSizer(wxHORIZONTAL);
    summary->Add(new wxStaticText(this, wxID_ANY, "State:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    state_ = make_text(this, "debug-state", wxTE_READONLY); summary->Add(state_, 1, wxRIGHT, FromDIP(8));
    summary->Add(new wxStaticText(this, wxID_ANY, "Target:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    target_identity_ = make_text(this, "debug-target-identity", wxTE_READONLY);
    summary->Add(target_identity_, 2, wxRIGHT, FromDIP(8));
    summary->Add(new wxStaticText(this, wxID_ANY, "Last event:"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    event_ = make_text(this, "debug-event", wxTE_READONLY); summary->Add(event_, 2, wxEXPAND);
    root->Add(summary, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));

    auto *details = new wxBoxSizer(wxHORIZONTAL);
    auto *thread_column = new wxBoxSizer(wxVERTICAL);
    auto *thread_heading = new wxBoxSizer(wxHORIZONTAL);
    thread_heading->Add(new wxStaticText(this, wxID_ANY, "Threads"), 1, wxALIGN_CENTER_VERTICAL);
    copy_thread_button_ = make_button(this, "debug-copy-thread", "Copy selected", copy_thread_id);
    copy_thread_button_->Disable();
    thread_heading->Add(copy_thread_button_, 0, wxRIGHT, FromDIP(4));
    thread_heading->Add(make_button(this, "debug-copy-visible-threads", "Copy visible", copy_visible_threads_id), 0, wxRIGHT, FromDIP(4));
    continue_stopped_peers_button_ = make_button(this, "debug-continue-stopped-peers", "Run stopped peers", continue_stopped_peers_id);
    continue_stopped_peers_button_->SetToolTip("Continue every known-stopped peer in one schedule while keeping the pending event owner stopped.");
    continue_stopped_peers_button_->Disable();
    thread_heading->Add(continue_stopped_peers_button_, 0, wxLEFT, FromDIP(4));
    thread_column->Add(thread_heading, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    auto *thread_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    thread_filter_ = make_text(this, "debug-thread-filter");
    thread_filter_->SetMaxLength(2048);
    thread_filter_->SetHint("Filter ID, name, state, core, kernel state, or latest event");
    thread_state_filter_ = new wxChoice(this, wxID_ANY);
    thread_state_filter_->SetName("debug-thread-state-filter");
    thread_state_filter_->Append("All states");
    thread_state_filter_->Append("Stopped");
    thread_state_filter_->Append("Running");
    thread_state_filter_->Append("Exited");
    thread_state_filter_->Append("Unknown");
    thread_state_filter_->SetSelection(0);
    thread_sort_ = new wxChoice(this, wxID_ANY);
    thread_sort_->SetName("debug-thread-sort");
    thread_sort_->Append("ID order");
    thread_sort_->Append("Name order");
    thread_sort_->Append("State order");
    thread_sort_->Append("Core order");
    thread_sort_->Append("Latest event");
    thread_sort_->SetSelection(0);
    thread_filter_status_ = new wxStaticText(this, wxID_ANY, "0 of 0 threads");
    thread_filter_status_->SetName("debug-thread-filter-status");
    thread_filter_controls->Add(thread_filter_, 1, wxRIGHT, FromDIP(4));
    thread_filter_controls->Add(thread_state_filter_, 0, wxRIGHT, FromDIP(4));
    thread_filter_controls->Add(thread_sort_, 0, wxRIGHT, FromDIP(4));
    thread_filter_controls->Add(thread_filter_status_, 0, wxALIGN_CENTER_VERTICAL);
    thread_column->Add(thread_filter_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    threads_view_ = make_list(this, "debug-threads", {"ID", "Name", "State", "Core", "Kernel state", "Latest event"});
    threads_view_->SetColumnWidth(5, FromDIP(210));
    thread_column->Add(threads_view_, 1, wxEXPAND);
    thread_selection_summary_ = new wxStaticText(this, wxID_ANY, "Select a thread to inspect its registers.");
    thread_selection_summary_->SetName("debug-thread-selection-summary");
    thread_selection_summary_->Wrap(FromDIP(360));
    thread_column->Add(thread_selection_summary_, 0, wxEXPAND | wxTOP, FromDIP(4));
    details->Add(thread_column, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *register_column = new wxBoxSizer(wxVERTICAL);
    auto *register_heading = new wxBoxSizer(wxHORIZONTAL);
    register_heading->Add(new wxStaticText(this, wxID_ANY, "Registers"), 1, wxALIGN_CENTER_VERTICAL);
    register_heading->Add(make_button(this, "debug-watch-register", "Watch selected", watch_register_id), 0, wxRIGHT, FromDIP(3));
    register_heading->Add(make_button(this, "debug-read-register-address", "Read address", navigate_register_id), 0, wxRIGHT, FromDIP(3));
    register_baseline_button_ = make_button(this, "debug-register-baseline", "Pin baseline", pin_register_baseline_id);
    register_baseline_button_->SetToolTip("Compare future register snapshots with the selected thread's current values.");
    register_heading->Add(register_baseline_button_, 0, wxRIGHT, FromDIP(3));
    register_heading->Add(make_button(this, "debug-copy-selected-register", "Copy selected", copy_selected_register_id), 0, wxRIGHT, FromDIP(3));
    register_heading->Add(make_button(this, "debug-copy-registers", "Copy snapshot", copy_registers_id), 0, wxRIGHT, FromDIP(3));
    copy_visible_registers_ = make_button(this, "debug-copy-visible-registers", "Copy visible TSV", copy_visible_registers_id);
    copy_visible_registers_->SetToolTip("Copy the currently filtered register rows and change status as TSV.");
    copy_visible_registers_->Enable(false);
    register_heading->Add(copy_visible_registers_, 0);
    register_column->Add(register_heading, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    auto *register_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    register_filter_ = make_text(this, "debug-register-filter");
    register_filter_->SetMaxLength(2048);
    register_filter_->SetHint("Filter register, bank, value, or change");
    register_changed_only_ = new wxCheckBox(this, wxID_ANY, "Changes only");
    register_changed_only_->SetName("debug-register-changed-only");
    register_value_format_ = new wxChoice(this, wxID_ANY);
    register_value_format_->SetName("debug-register-value-format");
    register_value_format_->Append("Hex");
    register_value_format_->Append("Unsigned");
    register_value_format_->Append("Signed");
    register_value_format_->SetSelection(0);
    register_value_format_->SetToolTip("Decimal applies to available scalar integer/special registers up to 64 bits; vector and floating-point values stay hexadecimal.");
    register_filter_status_ = new wxStaticText(this, wxID_ANY, "0 of 0 registers");
    register_filter_status_->SetName("debug-register-filter-status");
    register_filter_controls->Add(register_filter_, 1, wxRIGHT, FromDIP(4));
    register_filter_controls->Add(register_changed_only_, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, FromDIP(4));
    register_filter_controls->Add(register_value_format_, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, FromDIP(4));
    register_filter_controls->Add(register_filter_status_, 0, wxALIGN_CENTER_VERTICAL);
    register_column->Add(register_filter_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    registers_view_ = make_list(this, "debug-registers", {"Register", "Bank", "Value", "Change"});
    registers_view_->SetColumnWidth(0, FromDIP(100));
    registers_view_->SetColumnWidth(1, FromDIP(170));
    registers_view_->SetColumnWidth(2, FromDIP(200));
    registers_view_->SetColumnWidth(3, FromDIP(72));
    register_column->Add(registers_view_, 1, wxEXPAND);
    auto *register_controls = new wxBoxSizer(wxHORIZONTAL);
    register_value_ = make_text(this, "debug-register-value");
    register_value_->SetHint("Register value (hex, exact width)");
    register_controls->Add(register_value_, 1, wxRIGHT, FromDIP(3));
    register_controls->Add(make_button(this, "debug-write-register", "Write register", write_register_id), 0);
    register_column->Add(register_controls, 0, wxEXPAND | wxTOP, FromDIP(4));
    details->Add(register_column, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *locals_column = new wxBoxSizer(wxVERTICAL);
    locals_column->Add(new wxStaticText(this, wxID_ANY, "DWARF / PDB locals and parameters"), 0, wxBOTTOM, FromDIP(3));
    locals_frame_choice_ = new wxChoice(this, wxID_ANY);
    locals_frame_choice_->SetName("debug-locals-frame");
    auto *locals_frame_controls = new wxBoxSizer(wxHORIZONTAL);
    locals_frame_controls->Add(locals_frame_choice_, 1, wxRIGHT, FromDIP(3));
    locals_frame_controls->Add(make_button(this, "debug-copy-stack", "Copy frames", copy_stack_id), 0);
    locals_frame_controls->Add(make_button(this, "debug-copy-locals", "Copy locals", copy_locals_id), 0, wxLEFT, FromDIP(3));
    locals_frame_controls->Add(make_button(this, "debug-inspect-local-address", "Inspect address", inspect_local_address_id), 0, wxLEFT, FromDIP(3));
    locals_frame_controls->Add(make_button(this, "debug-inspect-frame-cfa", "Inspect CFA", inspect_frame_cfa_id), 0, wxLEFT, FromDIP(3));
    locals_frame_controls->Add(make_button(this, "debug-break-at-frame", "Set breakpoint", breakpoint_at_frame_id), 0, wxLEFT, FromDIP(3));
    locals_column->Add(locals_frame_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    locals_tabs_ = new wxNotebook(this, wxID_ANY);
    locals_tabs_->SetName("debug-frame-inspection-tabs");
    auto *locals_page = new wxPanel(locals_tabs_);
    auto *locals_page_box = new wxBoxSizer(wxVERTICAL);
    locals_view_ = make_list(locals_page, "debug-locals", {"Name", "Kind", "Scope / origin", "Location", "Value"});
    locals_page_box->Add(locals_view_, 1, wxEXPAND);
    locals_page->SetSizer(locals_page_box);
    locals_tabs_->AddPage(locals_page, "Locals", true);
    auto *frame_registers_page = new wxPanel(locals_tabs_);
    auto *frame_registers_box = new wxBoxSizer(wxVERTICAL);
    frame_register_status_ = new wxStaticText(frame_registers_page, wxID_ANY,
        "Recovered register values for the selected unwind frame.");
    frame_register_status_->SetName("debug-frame-register-status");
    frame_registers_box->Add(frame_register_status_, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    frame_registers_view_ = make_list(frame_registers_page, "debug-frame-registers",
        {"Register", "Bank", "Value", "Availability"});
    frame_registers_box->Add(frame_registers_view_, 1, wxEXPAND);
    frame_registers_page->SetSizer(frame_registers_box);
    locals_tabs_->AddPage(frame_registers_page, "Frame registers", false);
    locals_column->Add(locals_tabs_, 1, wxEXPAND);
    details->Add(locals_column, 2, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *bp_column = new wxBoxSizer(wxVERTICAL);
    bp_column->Add(new wxStaticText(this, wxID_ANY, "Breakpoints"), 0, wxBOTTOM, FromDIP(3));
    auto *breakpoint_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    breakpoint_filter_ = make_text(this, "debug-breakpoint-filter");
    breakpoint_filter_->SetMaxLength(2048);
    breakpoint_filter_->SetHint("Filter ID, address, kind, state, hits, or rule");
    breakpoint_filter_controls->Add(breakpoint_filter_, 2, wxRIGHT, FromDIP(3));
    breakpoint_enabled_only_ = new wxCheckBox(this, wxID_ANY, "Enabled only");
    breakpoint_enabled_only_->SetName("debug-breakpoint-enabled-only");
    breakpoint_filter_controls->Add(breakpoint_enabled_only_, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, FromDIP(4));
    breakpoint_sort_ = new wxChoice(this, wxID_ANY);
    breakpoint_sort_->SetName("debug-breakpoint-sort");
    breakpoint_sort_->Append("Creation order");
    breakpoint_sort_->Append("Address");
    breakpoint_sort_->Append("Most hits");
    breakpoint_sort_->Append("Most ignored");
    breakpoint_sort_->SetSelection(0);
    breakpoint_filter_controls->Add(breakpoint_sort_, 1);
    breakpoint_filter_status_ = new wxStaticText(this, wxID_ANY, "0 of 0 breakpoints");
    breakpoint_filter_status_->SetName("debug-breakpoint-filter-status");
    bp_column->Add(breakpoint_filter_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(2));
    bp_column->Add(breakpoint_filter_status_, 0, wxEXPAND | wxBOTTOM, FromDIP(2));
    breakpoints_view_ = make_list(this, "debug-breakpoints",
                                  {"ID", "Address", "Kind", "Enabled", "Hits", "Ignore", "Rule", "One-shot"});
    bp_column->Add(breakpoints_view_, 1, wxEXPAND);
    auto *bp_controls = new wxBoxSizer(wxHORIZONTAL);
    breakpoint_address_ = make_text(this, "debug-breakpoint-address", wxTE_PROCESS_ENTER); breakpoint_address_->SetHint("Address (hex/decimal)");
    bp_controls->Add(breakpoint_address_, 1, wxRIGHT, FromDIP(3));
    breakpoint_kind_ = new wxChoice(this, wxID_ANY);
    breakpoint_kind_->SetName("debug-breakpoint-kind");
    breakpoint_kind_->Append("Software");
    breakpoint_kind_->Append("Hardware execute");
    breakpoint_kind_->Append("Hardware read (if supported)");
    breakpoint_kind_->Append("Hardware write");
    breakpoint_kind_->Append("Hardware access");
    breakpoint_kind_->SetSelection(0);
    bp_controls->Add(breakpoint_kind_, 0, wxRIGHT, FromDIP(3));
    breakpoint_size_ = new wxChoice(this, wxID_ANY);
    breakpoint_size_->SetName("debug-breakpoint-size");
    breakpoint_size_->Append("1 byte");
    breakpoint_size_->Append("2 bytes");
    breakpoint_size_->Append("4 bytes");
    breakpoint_size_->Append("8 bytes");
    breakpoint_size_->SetSelection(0);
    breakpoint_size_->Disable();
    bp_controls->Add(breakpoint_size_, 0, wxRIGHT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-add-breakpoint", "Add", add_bp_id), 0, wxRIGHT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-remove-breakpoint", "Remove", remove_bp_id), 0);
    bp_controls->Add(make_button(this, "debug-apply-project-breakpoints", "Apply Project", apply_project_bp_id), 0, wxLEFT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-save-breakpoint-rule", "Save Rule", save_breakpoint_rule_id), 0, wxLEFT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-load-breakpoint-rule", "Load Rule", load_breakpoint_rule_id), 0, wxLEFT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-navigate-breakpoint", "Go to", navigate_breakpoint_id), 0, wxLEFT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-toggle-breakpoint", "Toggle enabled", toggle_breakpoint_id), 0, wxLEFT, FromDIP(3));
    bp_controls->Add(make_button(this, "debug-copy-breakpoints", "Copy visible", copy_breakpoints_id), 0, wxLEFT, FromDIP(3));
    bp_column->Add(bp_controls, 0, wxEXPAND | wxTOP, FromDIP(4));
    auto *condition_controls = new wxBoxSizer(wxHORIZONTAL);
    breakpoint_condition_ = make_text(this, "debug-breakpoint-condition");
    breakpoint_condition_->SetHint("Condition: registers/constants, mem8/16/32/64(address), arithmetic, comparisons, && || !");
    condition_controls->Add(breakpoint_condition_, 1, wxRIGHT, FromDIP(3));
    breakpoint_logpoint_ = new wxCheckBox(this, wxID_ANY, "Logpoint (auto-continue)");
    breakpoint_logpoint_->SetName("debug-breakpoint-logpoint");
    condition_controls->Add(breakpoint_logpoint_, 0, wxALIGN_CENTER_VERTICAL);
    breakpoint_one_shot_ = new wxCheckBox(this, wxID_ANY, "One-shot (software/execute)");
    breakpoint_one_shot_->SetName("debug-breakpoint-one-shot");
    condition_controls->Add(breakpoint_one_shot_, 0, wxLEFT | wxALIGN_CENTER_VERTICAL, FromDIP(6));
    bp_column->Add(condition_controls, 0, wxEXPAND | wxTOP, FromDIP(4)); details->Add(bp_column, 1, wxEXPAND);
    auto *rule_controls = new wxBoxSizer(wxHORIZONTAL);
    breakpoint_log_message_ = make_text(this, "debug-breakpoint-log-message");
    breakpoint_log_message_->SetHint("Logpoint output text (literal, up to 1024 bytes)");
    rule_controls->Add(breakpoint_log_message_, 1, wxRIGHT, FromDIP(3));
    breakpoint_ignore_count_ = make_text(this, "debug-breakpoint-ignore-count");
    breakpoint_ignore_count_->SetValue("0");
    breakpoint_ignore_count_->SetHint("Ignore first N hits");
    rule_controls->Add(breakpoint_ignore_count_, 0);
    bp_column->Add(rule_controls, 0, wxEXPAND | wxTOP, FromDIP(4));
    root->Add(details, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    auto *inspect = new wxBoxSizer(wxHORIZONTAL);
    auto *memory_column = new wxBoxSizer(wxVERTICAL);
    memory_tabs_ = new wxNotebook(this, wxID_ANY);
    memory_tabs_->SetName("debug-memory-tabs");
    auto *memory_page = new wxPanel(memory_tabs_);
    auto *memory_page_box = new wxBoxSizer(wxVERTICAL);
    memory_page_box->Add(new wxStaticText(memory_page, wxID_ANY, "Live process memory (bounded pages)"), 0, wxBOTTOM, FromDIP(3));
    auto *memory_controls = new wxBoxSizer(wxHORIZONTAL);
    memory_address_ = make_text(memory_page, "debug-memory-address", wxTE_PROCESS_ENTER); memory_address_->SetHint("Address (hex/decimal)");
    memory_controls->Add(memory_address_, 1, wxRIGHT, FromDIP(3));
    memory_page_size_ = new wxChoice(memory_page, wxID_ANY);
    memory_page_size_->SetName("debug-memory-page-size");
    memory_page_size_->Append("64 bytes"); memory_page_size_->Append("256 bytes"); memory_page_size_->Append("1024 bytes");
    memory_page_size_->SetSelection(1);
    memory_controls->Add(memory_page_size_, 0, wxRIGHT, FromDIP(3));
    memory_row_width_ = new wxChoice(memory_page, wxID_ANY);
    memory_row_width_->SetName("debug-memory-row-width");
    memory_row_width_->Append("8 / row");
    memory_row_width_->Append("16 / row");
    memory_row_width_->Append("32 / row");
    memory_row_width_->SetSelection(1);
    memory_controls->Add(memory_row_width_, 0, wxRIGHT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-memory-previous", "Previous", previous_memory_id), 0, wxRIGHT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-read-memory", "Read", read_memory_id), 0, wxRIGHT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-memory-next", "Next", next_memory_id), 0);
    memory_history_back_button_ = make_button(memory_page, "debug-memory-history-back", "Back", memory_history_back_id);
    memory_history_back_button_->SetToolTip("Return to the previous memory address you requested.");
    memory_history_back_button_->Disable();
    memory_controls->Add(memory_history_back_button_, 0, wxLEFT, FromDIP(3));
    memory_history_forward_button_ = make_button(memory_page, "debug-memory-history-forward", "Forward", memory_history_forward_id);
    memory_history_forward_button_->SetToolTip("Move forward in memory address history.");
    memory_history_forward_button_->Disable();
    memory_controls->Add(memory_history_forward_button_, 0, wxLEFT, FromDIP(3));
    memory_history_choice_ = new wxChoice(memory_page, wxID_ANY);
    memory_history_choice_->SetName("debug-memory-history-chooser");
    memory_history_choice_->SetMinSize(FromDIP(wxSize(104, -1)));
    memory_history_choice_->Append("History");
    memory_history_choice_->SetSelection(0);
    memory_history_choice_->Disable();
    memory_controls->Add(memory_history_choice_, 0, wxLEFT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-memory-watch-byte", "Watch byte", watch_memory_byte_id), 0, wxLEFT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-copy-memory-page", "Copy view", copy_memory_id), 0, wxLEFT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-save-memory-bytes", "Save raw", save_memory_raw_id), 0, wxLEFT, FromDIP(3));
    memory_controls->Add(make_button(memory_page, "debug-copy-memory-address", "Copy address", copy_memory_address_id), 0, wxLEFT, FromDIP(3));
    auto *breakpoint_at_memory_button = make_button(memory_page, "debug-break-at-memory-address", "Set BP", breakpoint_at_memory_id);
    breakpoint_at_memory_button->SetToolTip("Attempt to set a software breakpoint at the address field value.");
    memory_controls->Add(breakpoint_at_memory_button, 0, wxLEFT, FromDIP(3));
    memory_page_box->Add(memory_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    auto *memory_tag_controls = new wxBoxSizer(wxHORIZONTAL);
    memory_tag_type_ = make_text(memory_page, "debug-memory-tag-type");
    memory_tag_type_->SetValue("0");
    memory_tag_type_->SetMaxLength(11);
    memory_tag_type_->SetMinSize(FromDIP(wxSize(72, -1)));
    memory_tag_type_->SetToolTip("Target-specific qMemTags type selector, entered as a signed decimal integer.");
    memory_tag_controls->Add(new wxStaticText(memory_page, wxID_ANY, "Tag type"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(3));
    memory_tag_controls->Add(memory_tag_type_, 0, wxRIGHT, FromDIP(4));
    memory_tag_read_button_ = make_button(memory_page, "debug-read-memory-tags", "Read tags", read_memory_tags_id);
    memory_tag_read_button_->Disable();
    memory_tag_controls->Add(memory_tag_read_button_, 0, wxRIGHT, FromDIP(6));
    memory_tag_status_ = new wxStaticText(memory_page, wxID_ANY, "Memory tags are available when the selected stopped target supports tag reads.");
    memory_tag_status_->SetName("debug-memory-tag-status");
    memory_tag_controls->Add(memory_tag_status_, 1, wxALIGN_CENTER_VERTICAL);
    memory_page_box->Add(memory_tag_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    memory_tag_view_ = make_text(memory_page, "debug-memory-tag-view", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    memory_tag_view_->SetMinSize(FromDIP(wxSize(-1, 80)));
    memory_page_box->Add(memory_tag_view_, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    auto *memory_write_controls = new wxBoxSizer(wxHORIZONTAL);
    memory_write_bytes_ = make_text(memory_page, "debug-memory-write-bytes");
    memory_write_bytes_->SetMaxLength(3072);
    memory_write_bytes_->SetHint("Bytes to write (hex pairs, e.g. 90 C3)");
    memory_write_controls->Add(memory_write_bytes_, 1, wxRIGHT, FromDIP(3));
    memory_write_utf8_ = new wxCheckBox(memory_page, wxID_ANY, "UTF-8 text");
    memory_write_utf8_->SetName("debug-memory-write-utf8");
    memory_write_controls->Add(memory_write_utf8_, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(3));
    memory_write_controls->Add(make_button(memory_page, "debug-write-memory", "Write", write_memory_id), 0);
    memory_write_utf8_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &) {
        memory_write_bytes_->SetHint(memory_write_utf8_->GetValue()
            ? "UTF-8 text to write (no terminator)" : "Bytes to write (hex pairs, e.g. 90 C3)");
    });
    memory_page_box->Add(memory_write_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    memory_view_ = make_text(memory_page, "debug-memory-view", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    memory_page_box->Add(memory_view_, 1, wxEXPAND);
    memory_page->SetSizer(memory_page_box);
    memory_tabs_->AddPage(memory_page, "Memory", true);

    auto *search_page = new wxPanel(memory_tabs_);
    auto *search_box = new wxBoxSizer(wxVERTICAL);
    search_box->Add(new wxStaticText(search_page, wxID_ANY,
        "Search readable mapped process memory. Double-click a hit to open it in the memory view."),
        0, wxEXPAND | wxBOTTOM, FromDIP(4));
    memory_search_pattern_ = make_text(search_page, "debug-memory-search-pattern");
    memory_search_pattern_->SetHint("Hex bytes and nibble wildcards (e.g. 48 8B ?? A? ?F)");
    search_box->Add(memory_search_pattern_, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *search_scope = new wxFlexGridSizer(2, FromDIP(4), FromDIP(4));
    search_scope->AddGrowableCol(1, 1);
    search_scope->Add(new wxStaticText(search_page, wxID_ANY, "Range start (optional)"), 0, wxALIGN_CENTER_VERTICAL);
    memory_search_start_ = make_text(search_page, "debug-memory-search-start");
    memory_search_start_->SetHint("Hex/decimal; blank scans eligible maps");
    search_scope->Add(memory_search_start_, 1, wxEXPAND);
    search_scope->Add(new wxStaticText(search_page, wxID_ANY, "Range length (optional)"), 0, wxALIGN_CENTER_VERTICAL);
    memory_search_length_ = make_text(search_page, "debug-memory-search-length");
    memory_search_length_->SetHint("Bytes, hex or decimal");
    search_scope->Add(memory_search_length_, 1, wxEXPAND);
    search_scope->Add(new wxStaticText(search_page, wxID_ANY, "Absolute alignment"), 0, wxALIGN_CENTER_VERTICAL);
    memory_search_alignment_ = make_text(search_page, "debug-memory-search-alignment");
    memory_search_alignment_->SetValue("1");
    memory_search_alignment_->SetHint("1 means every byte");
    search_scope->Add(memory_search_alignment_, 1, wxEXPAND);
    search_scope->Add(new wxStaticText(search_page, wxID_ANY, "Region filter"), 0, wxALIGN_CENTER_VERTICAL);
    memory_search_permissions_ = new wxChoice(search_page, wxID_ANY);
    memory_search_permissions_->SetName("debug-memory-search-permissions");
    memory_search_permissions_->Append("All readable regions");
    memory_search_permissions_->Append("Executable");
    memory_search_permissions_->Append("Writable");
    memory_search_permissions_->Append("Non-executable");
    memory_search_permissions_->SetSelection(0);
    search_scope->Add(memory_search_permissions_, 1, wxEXPAND);
    search_box->Add(search_scope, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *search_actions = new wxBoxSizer(wxHORIZONTAL);
    memory_search_start_button_ = make_button(search_page, "debug-memory-search-start", "Search memory", memory_search_id);
    memory_search_cancel_button_ = make_button(search_page, "debug-memory-search-cancel", "Cancel", cancel_memory_search_id);
    memory_search_cancel_button_->Disable();
    memory_search_copy_button_ = make_button(search_page, "debug-memory-search-copy", "Copy matches", copy_memory_search_id);
    memory_search_copy_button_->Disable();
    memory_search_report_button_ = make_button(search_page, "debug-memory-search-copy-report", "Copy report JSON", copy_memory_search_report_id);
    memory_search_report_button_->Disable();
    search_actions->Add(memory_search_start_button_, 0, wxRIGHT, FromDIP(4));
    search_actions->Add(memory_search_cancel_button_, 0, wxRIGHT, FromDIP(4));
    search_actions->Add(memory_search_copy_button_, 0, wxRIGHT, FromDIP(4));
    search_actions->Add(memory_search_report_button_, 0);
    search_box->Add(search_actions, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    memory_search_status_ = new wxStaticText(search_page, wxID_ANY, "No memory search has run.");
    memory_search_status_->SetName("debug-memory-search-status");
    search_box->Add(memory_search_status_, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *memory_search_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    memory_search_filter_ = make_text(search_page, "debug-memory-search-filter");
    memory_search_filter_->SetMaxLength(2048);
    memory_search_filter_->SetHint("Filter hit addresses");
    memory_search_filter_controls->Add(memory_search_filter_, 1, wxRIGHT, FromDIP(4));
    memory_search_result_count_ = new wxStaticText(search_page, wxID_ANY, "0 visible / 0 hits");
    memory_search_result_count_->SetName("debug-memory-search-result-count");
    memory_search_filter_controls->Add(memory_search_result_count_, 0, wxALIGN_CENTER_VERTICAL);
    search_box->Add(memory_search_filter_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    memory_search_results_ = make_list(search_page, "debug-memory-search-results", {"Match address"});
    memory_search_results_->SetColumnWidth(0, FromDIP(180));
    search_box->Add(memory_search_results_, 1, wxEXPAND);
    search_page->SetSizer(search_box);
    memory_tabs_->AddPage(search_page, "Search", false);

    auto *watch_page = new wxPanel(memory_tabs_);
    auto *watch_box = new wxBoxSizer(wxVERTICAL);
    watch_box->Add(new wxStaticText(watch_page, wxID_ANY,
        "Evaluate bounded register and memory expressions for the selected stopped thread. Watch expressions persist per project."),
        0, wxEXPAND | wxBOTTOM, FromDIP(4));
    watch_expression_ = make_text(watch_page, "debug-watch-expression", wxTE_PROCESS_ENTER);
    watch_expression_->SetHint("Expression: register, integer, arithmetic, comparisons, mem8/16/32/64(address)");
    watch_box->Add(watch_expression_, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *watch_actions = new wxBoxSizer(wxHORIZONTAL);
    watch_actions->Add(make_button(watch_page, "debug-watch-add", "Add watch", add_watch_id), 0, wxRIGHT, FromDIP(4));
    watch_actions->Add(make_button(watch_page, "debug-watch-update", "Update selected", update_watch_id), 0, wxRIGHT, FromDIP(4));
    watch_actions->Add(make_button(watch_page, "debug-watch-remove", "Remove selected", remove_watch_id), 0, wxRIGHT, FromDIP(4));
    watch_actions->Add(make_button(watch_page, "debug-watch-refresh", "Refresh", refresh_watches_id), 0);
    watch_actions->Add(make_button(watch_page, "debug-watch-copy", "Copy selected", copy_watch_id), 0, wxLEFT, FromDIP(4));
    watch_actions->Add(make_button(watch_page, "debug-watch-move-up", "Move up", move_watch_up_id), 0, wxLEFT, FromDIP(4));
    watch_actions->Add(make_button(watch_page, "debug-watch-move-down", "Move down", move_watch_down_id), 0, wxLEFT, FromDIP(3));
    watch_value_format_ = new wxChoice(watch_page, wxID_ANY);
    watch_value_format_->SetName("debug-watch-value-format");
    watch_value_format_->Append("Hexadecimal");
    watch_value_format_->Append("Unsigned decimal");
    watch_value_format_->Append("Signed decimal");
    watch_value_format_->SetSelection(0);
    watch_actions->Add(watch_value_format_, 0, wxLEFT | wxALIGN_CENTER_VERTICAL, FromDIP(8));
    watch_box->Add(watch_actions, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    watch_view_ = make_list(watch_page, "debug-watches", {"Expression", "Value", "Change"});
    watch_view_->SetColumnWidth(0, FromDIP(240));
    watch_view_->SetColumnWidth(1, FromDIP(180));
    watch_view_->SetColumnWidth(2, FromDIP(90));
    watch_box->Add(watch_view_, 1, wxEXPAND);
    watch_page->SetSizer(watch_box);
    memory_tabs_->AddPage(watch_page, "Watches", false);

    auto *auxv_page = new wxPanel(memory_tabs_);
    auto *auxv_box = new wxBoxSizer(wxVERTICAL);
    auxv_box->Add(new wxStaticText(auxv_page, wxID_ANY,
        "Linux auxiliary vector entries from the connected remote target."), 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *auxv_controls = new wxBoxSizer(wxHORIZONTAL);
    auxv_controls->Add(make_button(auxv_page, "debug-auxv-refresh", "Refresh", refresh_auxv_id), 0, wxRIGHT, FromDIP(3));
    auxiliary_vector_copy_button_ = make_button(auxv_page, "debug-auxv-copy", "Copy TSV", copy_auxv_id);
    auxiliary_vector_copy_button_->Disable();
    auxv_controls->Add(auxiliary_vector_copy_button_, 0);
    auxv_controls->Add(make_button(auxv_page, "debug-auxv-copy-visible", "Copy visible", copy_visible_auxv_id), 0, wxLEFT, FromDIP(3));
    auxv_box->Add(auxv_controls, 0, wxBOTTOM, FromDIP(4));
    auto *auxv_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    auxiliary_vector_filter_ = make_text(auxv_page, "debug-auxv-filter");
    auxiliary_vector_filter_->SetMaxLength(2048);
    auxiliary_vector_filter_->SetHint("Filter type or value");
    auxiliary_vector_filter_->Disable();
    auxv_filter_controls->Add(auxiliary_vector_filter_, 1, wxRIGHT, FromDIP(4));
    auxiliary_vector_count_ = new wxStaticText(auxv_page, wxID_ANY, "0 of 0 entries");
    auxiliary_vector_count_->SetName("debug-auxv-filter-count");
    auxv_filter_controls->Add(auxiliary_vector_count_, 0, wxALIGN_CENTER_VERTICAL);
    auxv_box->Add(auxv_filter_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auxiliary_vector_view_ = make_list(auxv_page, "debug-auxv", {"Type", "Value"});
    auxiliary_vector_view_->SetColumnWidth(0, FromDIP(190));
    auxiliary_vector_view_->SetColumnWidth(1, FromDIP(220));
    auxv_box->Add(auxiliary_vector_view_, 1, wxEXPAND);
    auxv_page->SetSizer(auxv_box);
    memory_tabs_->AddPage(auxv_page, "Auxv", false);

    auto *os_data_page = new wxPanel(memory_tabs_);
    auto *os_data_box = new wxBoxSizer(wxVERTICAL);
    os_data_box->Add(new wxStaticText(os_data_page, wxID_ANY,
        "Read a target-provided GDB OS-data table (for example, cpus or procgroups)."),
        0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *os_data_controls = new wxBoxSizer(wxHORIZONTAL);
    os_data_type_ = make_text(os_data_page, "debug-os-data-type", wxTE_PROCESS_ENTER);
    os_data_type_->SetHint("OS-data type, such as cpus or procgroups");
    os_data_controls->Add(os_data_type_, 1, wxRIGHT, FromDIP(4));
    os_data_controls->Add(make_button(os_data_page, "debug-os-data-refresh", "Read table", refresh_osdata_id), 0);
    os_data_copy_button_ = make_button(os_data_page, "debug-os-data-copy", "Copy TSV", copy_osdata_id);
    os_data_copy_button_->Disable();
    os_data_controls->Add(os_data_copy_button_, 0, wxLEFT, FromDIP(3));
    os_data_box->Add(os_data_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *os_data_find_controls = new wxBoxSizer(wxHORIZONTAL);
    os_data_find_ = make_text(os_data_page, "debug-os-data-find", wxTE_PROCESS_ENTER);
    os_data_find_->SetMaxLength(2048);
    os_data_find_->SetHint("Find in displayed OS data");
    os_data_find_controls->Add(os_data_find_, 1, wxRIGHT, FromDIP(4));
    os_data_find_case_ = new wxCheckBox(os_data_page, wxID_ANY, "Match case");
    os_data_find_case_->SetName("debug-os-data-find-case");
    os_data_find_controls->Add(os_data_find_case_, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, FromDIP(4));
    auto *os_data_previous = new wxButton(os_data_page, wxID_ANY, "Previous");
    os_data_previous->SetName("debug-os-data-previous");
    os_data_find_controls->Add(os_data_previous, 0, wxRIGHT, FromDIP(3));
    auto *os_data_next = new wxButton(os_data_page, wxID_ANY, "Next");
    os_data_next->SetName("debug-os-data-next");
    os_data_find_controls->Add(os_data_next, 0, wxRIGHT, FromDIP(4));
    os_data_find_status_ = new wxStaticText(os_data_page, wxID_ANY, "");
    os_data_find_status_->SetName("debug-os-data-find-status");
    os_data_find_controls->Add(os_data_find_status_, 0, wxALIGN_CENTER_VERTICAL);
    os_data_box->Add(os_data_find_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    os_data_view_ = make_text(os_data_page, "debug-os-data-results", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    os_data_box->Add(os_data_view_, 1, wxEXPAND);
    os_data_page->SetSizer(os_data_box);
    memory_tabs_->AddPage(os_data_page, "OS data", false);
    auto *signal_info_page = new wxPanel(memory_tabs_);
    auto *signal_info_box = new wxBoxSizer(wxVERTICAL);
    signal_info_box->Add(new wxStaticText(signal_info_page, wxID_ANY,
        "Read signal information for the current stopped event. Linux header decoding is opt-in; the signal-specific union remains raw."),
        0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *signal_info_controls = new wxBoxSizer(wxHORIZONTAL);
    signal_info_format_ = new wxChoice(signal_info_page, wxID_ANY);
    signal_info_format_->SetName("debug-signal-info-format");
    signal_info_format_->Append("Raw target bytes");
    signal_info_format_->Append("Linux 32-bit header");
    signal_info_format_->Append("Linux 64-bit header");
    signal_info_format_->SetSelection(0);
    signal_info_controls->Add(signal_info_format_, 0, wxRIGHT, FromDIP(6));
    signal_info_read_button_ = make_button(signal_info_page, "debug-signal-info-read", "Read current event", refresh_signal_info_id);
    signal_info_read_button_->Disable();
    signal_info_controls->Add(signal_info_read_button_, 0, wxRIGHT, FromDIP(6));
    signal_info_status_ = new wxStaticText(signal_info_page, wxID_ANY, "No pending stopped event.");
    signal_info_status_->SetName("debug-signal-info-status");
    signal_info_controls->Add(signal_info_status_, 1, wxALIGN_CENTER_VERTICAL);
    signal_info_box->Add(signal_info_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    signal_info_view_ = make_text(signal_info_page, "debug-signal-info-bytes", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    signal_info_box->Add(signal_info_view_, 1, wxEXPAND);
    signal_info_page->SetSizer(signal_info_box);
    memory_tabs_->AddPage(signal_info_page, "Signal info", false);
    auto *remote_file_page = new wxPanel(memory_tabs_);
    auto *remote_file_box = new wxBoxSizer(wxVERTICAL);
    remote_file_box->Add(new wxStaticText(remote_file_page, wxID_ANY,
        "Read a bounded file from the connected remote stub filesystem using vFile. This does not read a path inside the debugged process."),
        0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *remote_file_controls = new wxBoxSizer(wxHORIZONTAL);
    remote_file_path_ = new wxTextCtrl(remote_file_page, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    remote_file_path_->SetName("debug-remote-file-path");
    remote_file_path_->SetHint("Remote stub file path");
    remote_file_controls->Add(remote_file_path_, 1, wxRIGHT, FromDIP(6));
    remote_file_read_button_ = make_button(remote_file_page, "debug-remote-file-read", "Read up to 1 MiB", refresh_remote_file_id);
    remote_file_read_button_->Disable();
    remote_file_controls->Add(remote_file_read_button_, 0, wxRIGHT, FromDIP(6));
    remote_file_status_ = new wxStaticText(remote_file_page, wxID_ANY, "Connect to an RSP target to read remote files.");
    remote_file_status_->SetName("debug-remote-file-status");
    remote_file_controls->Add(remote_file_status_, 0, wxALIGN_CENTER_VERTICAL);
    remote_file_box->Add(remote_file_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    remote_file_view_ = make_text(remote_file_page, "debug-remote-file-bytes", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    remote_file_box->Add(remote_file_view_, 1, wxEXPAND);
    remote_file_page->SetSizer(remote_file_box);
    memory_tabs_->AddPage(remote_file_page, "Remote file", false);
    auto *remote_monitor_page = new wxPanel(memory_tabs_);
    auto *remote_monitor_box = new wxBoxSizer(wxVERTICAL);
    remote_monitor_box->Add(new wxStaticText(remote_monitor_page, wxID_ANY,
        "Run a bounded GDB monitor command on the connected remote stub while stopped. Use commands that leave the current stop intact; output comes from qRcmd console packets."),
        0, wxEXPAND | wxBOTTOM, FromDIP(4));
    auto *remote_monitor_controls = new wxBoxSizer(wxHORIZONTAL);
    remote_monitor_command_ = new wxTextCtrl(remote_monitor_page, wxID_ANY, {}, wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
    remote_monitor_command_->SetName("debug-remote-monitor-command");
    remote_monitor_command_->SetMaxLength(4096);
    remote_monitor_command_->SetHint("Remote monitor command");
    remote_monitor_controls->Add(remote_monitor_command_, 1, wxRIGHT, FromDIP(6));
    remote_monitor_button_ = make_button(remote_monitor_page, "debug-remote-monitor-run", "Run", run_remote_monitor_id);
    remote_monitor_button_->Disable();
    remote_monitor_controls->Add(remote_monitor_button_, 0, wxRIGHT, FromDIP(6));
    remote_monitor_status_ = new wxStaticText(remote_monitor_page, wxID_ANY,
        "Connect to an RSP target and stop it before running monitor commands.");
    remote_monitor_status_->SetName("debug-remote-monitor-status");
    remote_monitor_controls->Add(remote_monitor_status_, 0, wxALIGN_CENTER_VERTICAL);
    remote_monitor_box->Add(remote_monitor_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(4));
    remote_monitor_output_ = make_text(remote_monitor_page, "debug-remote-monitor-output",
        wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    remote_monitor_box->Add(remote_monitor_output_, 1, wxEXPAND);
    remote_monitor_page->SetSizer(remote_monitor_box);
    memory_tabs_->AddPage(remote_monitor_page, "Remote monitor", false);
    memory_column->Add(memory_tabs_, 1, wxEXPAND);
    inspect->Add(memory_column, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *module_column = new wxBoxSizer(wxVERTICAL);
    auto *module_heading = new wxBoxSizer(wxHORIZONTAL);
    module_heading->Add(new wxStaticText(this, wxID_ANY, "Loaded modules"), 1, wxALIGN_CENTER_VERTICAL);
    module_heading->Add(make_button(this, "debug-copy-module", "Copy selected", copy_module_id), 0, wxRIGHT, FromDIP(3));
    module_heading->Add(make_button(this, "debug-copy-visible-modules", "Copy visible", copy_visible_modules_id), 0, wxRIGHT, FromDIP(3));
    module_heading->Add(make_button(this, "debug-refresh-modules", "Refresh", refresh_modules_id), 0);
    module_column->Add(module_heading, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    auto *module_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    module_filter_ = make_text(this, "debug-module-filter");
    module_filter_->SetMaxLength(2048);
    module_filter_->SetHint("Filter base, size, module name, or path");
    module_filter_controls->Add(module_filter_, 1, wxRIGHT, FromDIP(4));
    module_sort_ = new wxChoice(this, wxID_ANY);
    module_sort_->SetName("debug-module-sort");
    module_sort_->Append("Base order");
    module_sort_->Append("Name order");
    module_sort_->Append("Largest first");
    module_sort_->SetSelection(0);
    module_filter_controls->Add(module_sort_, 0);
    module_column->Add(module_filter_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(2));
    module_filter_status_ = new wxStaticText(this, wxID_ANY, "0 of 0 modules");
    module_filter_status_->SetName("debug-module-filter-status");
    module_column->Add(module_filter_status_, 0, wxEXPAND | wxBOTTOM, FromDIP(2));
    modules_view_ = make_list(this, "debug-modules", {"Base", "Size", "Name", "Path"});
    module_column->Add(modules_view_, 1, wxEXPAND); inspect->Add(module_column, 1, wxEXPAND | wxRIGHT, FromDIP(5));
    auto *region_column = new wxBoxSizer(wxVERTICAL);
    auto *region_heading = new wxBoxSizer(wxHORIZONTAL);
    region_heading->Add(new wxStaticText(this, wxID_ANY, "Memory regions"), 1, wxALIGN_CENTER_VERTICAL);
    region_heading->Add(make_button(this, "debug-open-memory-region", "Open start", open_memory_region_id), 0, wxRIGHT, FromDIP(3));
    region_heading->Add(make_button(this, "debug-search-memory-region", "Search region", search_memory_region_id), 0, wxRIGHT, FromDIP(3));
    region_heading->Add(make_button(this, "debug-copy-memory-region", "Copy selected", copy_memory_region_id), 0, wxRIGHT, FromDIP(3));
    region_heading->Add(make_button(this, "debug-copy-visible-memory-regions", "Copy visible", copy_visible_memory_regions_id), 0, wxRIGHT, FromDIP(3));
    region_heading->Add(make_button(this, "debug-refresh-memory-regions", "Refresh", refresh_memory_regions_id), 0);
    region_column->Add(region_heading, 0, wxEXPAND | wxBOTTOM, FromDIP(3));
    memory_region_filter_ = make_text(this, "debug-memory-region-filter");
    memory_region_filter_->SetMaxLength(2048);
    memory_region_filter_->SetHint("Filter address, size, permissions, type, or erase block");
    auto *region_filter_controls = new wxBoxSizer(wxHORIZONTAL);
    region_filter_controls->Add(memory_region_filter_, 1, wxRIGHT, FromDIP(4));
    memory_region_permission_filter_ = new wxChoice(this, wxID_ANY);
    memory_region_permission_filter_->SetName("debug-memory-region-permission-filter");
    memory_region_permission_filter_->Append("Any permissions");
    memory_region_permission_filter_->Append("Readable");
    memory_region_permission_filter_->Append("Writable");
    memory_region_permission_filter_->Append("Executable");
    memory_region_permission_filter_->SetSelection(0);
    region_filter_controls->Add(memory_region_permission_filter_, 0);
    memory_region_sort_ = new wxChoice(this, wxID_ANY);
    memory_region_sort_->SetName("debug-memory-region-sort");
    memory_region_sort_->Append("Start order");
    memory_region_sort_->Append("Largest first");
    memory_region_sort_->Append("Type order");
    memory_region_sort_->SetSelection(0);
    region_filter_controls->Add(memory_region_sort_, 0, wxLEFT, FromDIP(4));
    memory_region_filter_status_ = new wxStaticText(this, wxID_ANY, "0 of 0 regions");
    memory_region_filter_status_->SetName("debug-memory-region-filter-status");
    region_column->Add(region_filter_controls, 0, wxEXPAND | wxBOTTOM, FromDIP(2));
    region_column->Add(memory_region_filter_status_, 0, wxEXPAND | wxBOTTOM, FromDIP(2));
    memory_regions_view_ = make_list(this, "debug-memory-regions", {"Start", "Size", "Permissions", "Type", "Erase block"});
    region_column->Add(memory_regions_view_, 1, wxEXPAND); inspect->Add(region_column, 1, wxEXPAND);
    root->Add(inspect, 1, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    auto *output_heading = new wxBoxSizer(wxHORIZONTAL);
    output_heading->Add(new wxStaticText(this, wxID_ANY, "Debugger output"), 1, wxALIGN_CENTER_VERTICAL);
    output_heading->Add(new wxStaticText(this, wxID_ANY, "Retain"), 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(3));
    output_retention_ = new wxChoice(this, wxID_ANY);
    output_retention_->SetName("debug-output-retention");
    output_retention_->Append("32 Ki chars");
    output_retention_->Append("128 Ki chars");
    output_retention_->Append("1 Mi chars");
    output_retention_->SetSelection(0);
    output_heading->Add(output_retention_, 0, wxRIGHT, FromDIP(4));
    output_follow_ = new wxCheckBox(this, wxID_ANY, "Follow new output");
    output_follow_->SetName("debug-output-follow");
    output_follow_->SetValue(true);
    output_heading->Add(output_follow_, 0, wxALIGN_CENTER_VERTICAL | wxRIGHT, FromDIP(4));
    output_heading->Add(make_button(this, "debug-copy-output", "Copy output", copy_output_id), 0);
    output_heading->Add(make_button(this, "debug-copy-output-matches", "Copy matches", copy_matching_output_id), 0, wxLEFT, FromDIP(3));
    output_heading->Add(make_button(this, "debug-copy-inspection-report", "Copy inspection JSON", copy_inspection_report_id), 0, wxLEFT, FromDIP(3));
    output_heading->Add(make_button(this, "debug-save-output", "Save output", save_output_id), 0, wxLEFT, FromDIP(3));
    output_heading->Add(make_button(this, "debug-clear-output", "Clear", clear_output_id), 0, wxLEFT, FromDIP(3));
    root->Add(output_heading, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    auto *output_search_controls = new wxBoxSizer(wxHORIZONTAL);
    output_search_ = make_text(this, "debug-output-search", wxTE_PROCESS_ENTER);
    output_search_->SetMaxLength(2048);
    output_search_->SetHint("Find in debugger output");
    output_search_controls->Add(output_search_, 1, wxRIGHT, FromDIP(3));
    output_search_case_ = new wxCheckBox(this, wxID_ANY, "Match case");
    output_search_case_->SetName("debug-output-search-case");
    output_search_controls->Add(output_search_case_, 0, wxRIGHT | wxALIGN_CENTER_VERTICAL, FromDIP(4));
    output_search_controls->Add(make_button(this, "debug-output-previous", "Previous", output_previous_id), 0, wxRIGHT, FromDIP(3));
    output_search_controls->Add(make_button(this, "debug-output-next", "Next", output_next_id), 0, wxRIGHT, FromDIP(3));
    output_search_status_ = new wxStaticText(this, wxID_ANY, "");
    output_search_status_->SetName("debug-output-search-status");
    output_search_controls->Add(output_search_status_, 0, wxALIGN_CENTER_VERTICAL);
    root->Add(output_search_controls, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    log_ = make_text(this, "debug-output", wxTE_MULTILINE | wxTE_READONLY | wxTE_DONTWRAP);
    root->Add(log_, 0, wxEXPAND | wxLEFT | wxRIGHT | wxBOTTOM, FromDIP(6));
    SetSizer(root);
    const wxAcceleratorEntry accelerators[] = {
        wxAcceleratorEntry(wxACCEL_NORMAL, WXK_F5, continue_id),
        wxAcceleratorEntry(wxACCEL_NORMAL, WXK_F8, step_id),
        wxAcceleratorEntry(wxACCEL_NORMAL, WXK_F10, source_step_over_id),
        wxAcceleratorEntry(wxACCEL_SHIFT, WXK_F5, detach_id)};
    SetAcceleratorTable(wxAcceleratorTable(4, accelerators));

    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_pc(false); }, navigate_pc_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_pc(true); }, navigate_frame_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        const wxFileName current_executable(executable_->GetValue());
        wxFileDialog dialog(this, "Choose executable", current_executable.GetPath(), current_executable.GetFullName(),
                            "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);
        if (dialog.ShowModal() == wxID_OK) executable_->SetValue(dialog.GetPath());
    }, browse_executable_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) {
        wxDirDialog dialog(this, "Choose working directory", working_directory_->GetValue(), wxDD_DEFAULT_STYLE | wxDD_DIR_MUST_EXIST);
        if (dialog.ShowModal() == wxID_OK) working_directory_->SetValue(dialog.GetPath());
    }, browse_working_directory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { launch(); }, launch_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { attach(); }, attach_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { connect_remote(); }, remote_connect_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { detach(); }, detach_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { terminate(); }, terminate_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { poll_event(); }, wait_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { continue_event(debugger::ContinueStatus::handled); }, continue_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { continue_selected_thread(); }, continue_thread_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { continue_stopped_peers(); }, continue_stopped_peers_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { step_event(); }, step_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { step_out_event(); }, source_step_out_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { step_over_event(); }, source_step_over_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { continue_event(debugger::ContinueStatus::not_handled); }, pass_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { add_breakpoint(); }, add_bp_id);
    breakpoint_address_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { add_breakpoint(); });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { remove_breakpoint(); }, remove_bp_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { apply_project_breakpoints(); }, apply_project_bp_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { save_breakpoint_rule(); }, save_breakpoint_rule_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { load_breakpoint_rule(); }, load_breakpoint_rule_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_breakpoint(); }, navigate_breakpoint_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { toggle_breakpoint_enabled(); }, toggle_breakpoint_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_visible_breakpoints(); }, copy_breakpoints_id);
    const auto selected_breakpoint_id = [this]() -> std::optional<debugger::BreakpointId> {
        const auto row = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (row < 0 || static_cast<std::size_t>(row) >= visible_breakpoint_rows_.size()) return std::nullopt;
        return breakpoints_[visible_breakpoint_rows_[static_cast<std::size_t>(row)]].id;
    };
    breakpoint_filter_->Bind(wxEVT_TEXT, [this, selected_breakpoint_id](wxCommandEvent &) {
        render_breakpoints(selected_breakpoint_id());
    });
    breakpoint_enabled_only_->Bind(wxEVT_CHECKBOX, [this, selected_breakpoint_id](wxCommandEvent &) {
        render_breakpoints(selected_breakpoint_id());
    });
    Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= visible_breakpoint_rows_.size()) return;
        breakpoints_view_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        toggle_breakpoint_enabled();
    }, breakpoints_view_->GetId());
    Bind(wxEVT_CHOICE, [this, selected_breakpoint_id](wxCommandEvent &) {
        render_breakpoints(selected_breakpoint_id());
    }, breakpoint_sort_->GetId());
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_stack_trace(); }, copy_stack_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_locals(); }, copy_locals_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { inspect_local_address(); }, inspect_local_address_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { inspect_frame_cfa(); }, inspect_frame_cfa_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { breakpoint_at_frame(); }, breakpoint_at_frame_id);
    Bind(wxEVT_CHOICE, [this](wxCommandEvent &event) {
        const auto selection = event.GetSelection();
        const bool hardware_data = selection >= 2 && selection <= 4;
        if (!hardware_data) breakpoint_size_->SetSelection(0);
        breakpoint_size_->Enable(hardware_data);
    }, breakpoint_kind_->GetId());
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_memory(); }, read_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { read_memory_tags(); }, read_memory_tags_id);
    memory_address_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { refresh_memory(); });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { write_memory(); }, write_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { write_register(); }, write_register_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_registers(); }, copy_registers_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_selected_register(); }, copy_selected_register_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_visible_registers(); }, copy_visible_registers_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { watch_selected_register(); }, watch_register_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { toggle_register_baseline(); }, pin_register_baseline_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { read_selected_register_address(); }, navigate_register_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_output(); }, copy_output_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_matching_output_lines(); }, copy_matching_output_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { save_output_to_file(); }, save_output_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { log_->Clear(); output_search_cursor_ = 0; output_search_status_->SetLabel(""); }, clear_output_id);
    output_retention_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        output_search_cursor_ = 0;
        output_search_status_->SetLabel("");
        report(wxString("Debugger output retention set to ") + output_retention_->GetStringSelection() + ".");
    });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { search_output(-1); }, output_previous_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { search_output(1); }, output_next_id);
    output_search_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { search_output(1); });
    output_search_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { output_search_cursor_ = 0; output_search_status_->SetLabel(""); });
    output_search_case_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &) { output_search_cursor_ = 0; output_search_status_->SetLabel(""); });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { move_memory_page(-1); }, previous_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { move_memory_page(1); }, next_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_memory_history(-1); }, memory_history_back_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { navigate_memory_history(1); }, memory_history_forward_id);
    memory_history_choice_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &event) {
        if (updating_memory_history_choice_) return;
        const auto selection = event.GetSelection();
        if (selection >= 0 && static_cast<std::size_t>(selection) < memory_address_history_.size())
            navigate_memory_history_to(static_cast<std::size_t>(selection));
    });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { watch_memory_byte(); }, watch_memory_byte_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { breakpoint_at_memory_address(); }, breakpoint_at_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_memory_page(); }, copy_memory_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { save_memory_page_raw(); }, save_memory_raw_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_inspection_report(); }, copy_inspection_report_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_memory_address(); }, copy_memory_address_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { start_memory_search(); }, memory_search_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { cancel_memory_search(); }, cancel_memory_search_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_memory_search_matches(); }, copy_memory_search_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_memory_search_report(); }, copy_memory_search_report_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { add_watch_expression(); }, add_watch_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { update_watch_expression(); }, update_watch_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { remove_watch_expression(); }, remove_watch_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_watches(); }, refresh_watches_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_selected_watch(); }, copy_watch_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { move_watch_expression(-1); }, move_watch_up_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { move_watch_expression(1); }, move_watch_down_id);
    watch_value_format_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        render_watch_values();
        save_watch_value_format();
    });
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row >= 0 && static_cast<std::size_t>(row) < watch_expressions_.size())
            watch_expression_->SetValue(wxString::FromUTF8(watch_expressions_[static_cast<std::size_t>(row)]));
    }, watch_view_->GetId());
    watch_expression_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { add_watch_expression(); });
    Bind(wxEVT_LIST_ITEM_ACTIVATED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= visible_memory_search_rows_.size()) return;
        memory_tabs_->SetSelection(0);
        memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(memory_search_matches_[visible_memory_search_rows_[static_cast<std::size_t>(row)]])));
        refresh_memory();
    }, memory_search_results_->GetId());
    memory_search_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { render_memory_search_matches(); });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_modules(); }, refresh_modules_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_selected_module(); }, copy_module_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_visible_modules(); }, copy_visible_modules_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_memory_regions(); }, refresh_memory_regions_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { search_selected_memory_region(); }, search_memory_region_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { open_selected_memory_region(); }, open_memory_region_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_selected_memory_region(); }, copy_memory_region_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_visible_memory_regions(); }, copy_visible_memory_regions_id);
    module_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { render_modules(); });
    module_sort_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        const auto row = modules_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        const auto preferred = row >= 0 && static_cast<std::size_t>(row) < visible_module_rows_.size()
            ? std::optional<std::size_t>{visible_module_rows_[static_cast<std::size_t>(row)]} : std::nullopt;
        render_modules(preferred);
    });
    const auto selected_memory_region_start = [this]() -> std::optional<std::uint64_t> {
        const auto row = memory_regions_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        if (row < 0 || static_cast<std::size_t>(row) >= visible_memory_region_rows_.size()) return std::nullopt;
        const auto source_row = visible_memory_region_rows_[static_cast<std::size_t>(row)];
        return source_row < memory_regions_.size() ? std::optional<std::uint64_t>{memory_regions_[source_row].start} : std::nullopt;
    };
    memory_region_filter_->Bind(wxEVT_TEXT, [this, selected_memory_region_start](wxCommandEvent &) {
        render_memory_regions(selected_memory_region_start());
    });
    memory_region_permission_filter_->Bind(wxEVT_CHOICE, [this, selected_memory_region_start](wxCommandEvent &) {
        render_memory_regions(selected_memory_region_start());
    });
    memory_region_sort_->Bind(wxEVT_CHOICE, [this, selected_memory_region_start](wxCommandEvent &) {
        render_memory_regions(selected_memory_region_start());
    });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_auxiliary_vector(); }, refresh_auxv_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_auxiliary_vector(); }, copy_auxv_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_visible_auxiliary_vector(); }, copy_visible_auxv_id);
    auxiliary_vector_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { render_auxiliary_vector(); });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_os_data(); }, refresh_osdata_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_os_data_table(); }, copy_osdata_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { read_signal_info(); }, refresh_signal_info_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { read_remote_file(); }, refresh_remote_file_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { run_remote_monitor_command(); }, run_remote_monitor_id);
    remote_environment_->Bind(wxEVT_TEXT, [this](wxCommandEvent &event) {
        std::vector<debugger::RemoteEnvironmentChange> changes;
        std::string error;
        if (!parse_remote_environment(narrow(remote_environment_->GetValue()), changes, error)) {
            remote_environment_status_->SetLabel(wxString::FromUTF8(error));
        } else {
            const auto unsets = static_cast<std::size_t>(std::count_if(changes.begin(), changes.end(),
                [](const auto &change) { return !change.value.has_value(); }));
            remote_environment_status_->SetLabel(wxString::Format(
                "%llu changes: %llu set, %llu unset; 64 KiB total budget.",
                static_cast<unsigned long long>(changes.size()),
                static_cast<unsigned long long>(changes.size() - unsets),
                static_cast<unsigned long long>(unsets)));
        }
        event.Skip();
    });
    remote_file_path_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { read_remote_file(); });
    remote_file_path_->Bind(wxEVT_TEXT, [this](wxCommandEvent &event) {
        if (remote_file_reading_) {
            ++remote_file_request_;
            remote_file_reading_ = false;
            remote_file_read_button_->Enable(remote_session_active_ && !remote_connecting_);
            remote_file_status_->SetLabel("Path changed; start a new read.");
        }
        event.Skip();
    });
    remote_monitor_command_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { run_remote_monitor_command(); });
    remote_monitor_command_->Bind(wxEVT_TEXT, [this](wxCommandEvent &event) {
        if (remote_monitor_running_) {
            ++remote_monitor_request_;
            remote_monitor_running_ = false;
            remote_monitor_button_->Enable(remote_session_active_ && !remote_connecting_ &&
                session_->state() == debugger::SessionState::stopped && pending_event_.has_value());
            remote_monitor_status_->SetLabel("Command changed; run it again.");
        }
        event.Skip();
    });
    signal_info_format_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        ++signal_info_request_;
        signal_info_reading_ = false;
        signal_info_read_button_->Enable(session_->state() == debugger::SessionState::stopped && pending_event_.has_value());
        if (pending_event_) signal_info_status_->SetLabel("Display format changed; read the current event again.");
    });
    os_data_type_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { refresh_os_data(); });
    os_data_previous->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { search_os_data(-1); });
    os_data_next->Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { search_os_data(1); });
    os_data_find_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { search_os_data(1); });
    os_data_find_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        os_data_find_cursor_ = 0;
        os_data_find_status_->SetLabel("");
    });
    os_data_find_case_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &) {
        os_data_find_cursor_ = 0;
        os_data_find_status_->SetLabel("");
    });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { refresh_processes(); }, refresh_processes_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { detach_remote_process(); }, detach_remote_process_id);
    process_id_->Bind(wxEVT_TEXT_ENTER, [this](wxCommandEvent &) { attach(); });
    Bind(wxEVT_CHOICE, [this](wxCommandEvent &event) {
        const auto selection = event.GetSelection();
        if (selection < 0 || static_cast<std::size_t>(selection) >= visible_processes_.size()) {
            update_process_actions();
            return;
        }
        process_id_->SetValue(wxString::Format("%llu", static_cast<unsigned long long>(visible_processes_[selection].id)));
        update_process_actions();
    }, processes_choice_->GetId());
    process_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        const auto selected = processes_choice_->GetSelection();
        const auto preferred = selected >= 0 && static_cast<std::size_t>(selected) < visible_processes_.size()
            ? std::optional<debugger::ProcessId>{visible_processes_[static_cast<std::size_t>(selected)].id}
            : std::nullopt;
        render_processes(preferred);
    });
    process_sort_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        const auto selected = processes_choice_->GetSelection();
        const auto preferred = selected >= 0 && static_cast<std::size_t>(selected) < visible_processes_.size()
            ? std::optional<debugger::ProcessId>{visible_processes_[static_cast<std::size_t>(selected)].id}
            : std::nullopt;
        render_processes(preferred);
    });
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        copy_thread_button_->Enable(true);
        const auto row = event.GetIndex();
        if (row >= 0 && static_cast<std::size_t>(row) < visible_thread_rows_.size())
            refresh_registers(visible_thread_rows_[static_cast<std::size_t>(row)]);
    }, threads_view_->GetId());
    thread_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) {
        const auto selected = threads_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        const auto preferred = selected >= 0 && static_cast<std::size_t>(selected) < visible_thread_rows_.size()
            ? std::optional<debugger::ThreadId>{threads_[visible_thread_rows_[static_cast<std::size_t>(selected)]].id}
            : selected_register_thread_;
        const auto row = render_threads(preferred);
        if (!row || !selected_register_thread_ || threads_[*row].id != *selected_register_thread_)
            refresh_registers(row.value_or(threads_.size()));
    });
    thread_state_filter_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        const auto selected = threads_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        const auto preferred = selected >= 0 && static_cast<std::size_t>(selected) < visible_thread_rows_.size()
            ? std::optional<debugger::ThreadId>{threads_[visible_thread_rows_[static_cast<std::size_t>(selected)]].id}
            : selected_register_thread_;
        const auto row = render_threads(preferred);
        if (!row || !selected_register_thread_ || threads_[*row].id != *selected_register_thread_)
            refresh_registers(row.value_or(threads_.size()));
    });
    thread_sort_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) {
        const auto selected = threads_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
        const auto preferred = selected >= 0 && static_cast<std::size_t>(selected) < visible_thread_rows_.size()
            ? std::optional<debugger::ThreadId>{threads_[visible_thread_rows_[static_cast<std::size_t>(selected)]].id}
            : selected_register_thread_;
        const auto row = render_threads(preferred);
        if (!row || !selected_register_thread_ || threads_[*row].id != *selected_register_thread_)
            refresh_registers(row.value_or(threads_.size()));
    });
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_selected_thread(); }, copy_thread_id);
    Bind(wxEVT_BUTTON, [this](wxCommandEvent &) { copy_visible_threads(); }, copy_visible_threads_id);
    threads_view_->Bind(wxEVT_CONTEXT_MENU, [this](wxContextMenuEvent &event) {
        wxPoint point = event.GetPosition();
        if (point == wxDefaultPosition) point = wxPoint(4, 4);
        else point = threads_view_->ScreenToClient(point);
        int hit_flags = 0;
        const auto hit = threads_view_->HitTest(point, hit_flags);
        const auto thread_index = hit >= 0 && static_cast<std::size_t>(hit) < visible_thread_rows_.size()
            ? std::optional<std::size_t>{visible_thread_rows_[static_cast<std::size_t>(hit)]} : std::nullopt;
        if (thread_index) {
            threads_view_->SetItemState(hit, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            refresh_registers(*thread_index);
        }
        wxMenu menu;
        menu.Append(thread_context_continue_id, "Continue thread");
        menu.Append(thread_context_step_id, "Step thread");
        menu.Append(thread_context_stop_id, "Stop thread (resume event thread)");
        menu.Append(thread_context_interrupt_id, "Interrupt thread (non-stop)");
        bool can_continue = false, can_step = false, can_stop = false, can_interrupt = false;
        bool thread_interrupt_supported = false;
        {
            std::lock_guard lock(inspection_state_->backend_mutex);
            thread_interrupt_supported = session_->supports_thread_interrupt();
        }
        if (thread_index && *thread_index < threads_.size() && thread_interrupt_supported && !pending_event_) {
            can_interrupt = threads_[*thread_index].state == debugger::ThreadState::running;
        }
        if (thread_index && *thread_index < threads_.size() && thread_run_states_supported_ &&
            pending_event_ && pending_event_thread_) {
            const auto &selected_thread = threads_[*thread_index];
            const auto owner = *pending_event_thread_;
            const auto owner_row = std::find_if(threads_.begin(), threads_.end(), [&](const auto &item) { return item.id == owner; });
            const bool owner_active = owner_row != threads_.end() && owner_row->state != debugger::ThreadState::exited;
            can_continue = owner_active && selected_thread.state == debugger::ThreadState::stopped &&
                selected_thread.state != debugger::ThreadState::exited;
            can_step = can_continue;
            can_stop = owner_active && selected_thread.id != owner && selected_thread.state == debugger::ThreadState::running;
        }
        menu.Enable(thread_context_continue_id, can_continue);
        menu.Enable(thread_context_step_id, can_step);
        menu.Enable(thread_context_stop_id, can_stop);
        menu.Enable(thread_context_interrupt_id, can_interrupt);
        menu.AppendSeparator();
        menu.Append(wxID_REFRESH, "Refresh threads");
        const auto selected = threads_view_->GetPopupMenuSelectionFromUser(menu, point);
        if (selected == thread_context_continue_id) thread_context_action(debugger::ThreadResumeKind::continue_execution);
        else if (selected == thread_context_step_id) thread_context_action(debugger::ThreadResumeKind::single_step);
        else if (selected == thread_context_stop_id) thread_context_action(debugger::ThreadResumeKind::stop);
        else if (selected == thread_context_interrupt_id) interrupt_selected_thread();
        else if (selected == wxID_REFRESH) refresh_threads(selected_register_thread_);
    });
    locals_frame_choice_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &event) {
        const auto selected = event.GetSelection();
        selected_locals_frame_ = selected == wxNOT_FOUND ? 0 : static_cast<std::size_t>(selected);
        refresh_locals();
    });
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= visible_register_rows_.size()) return;
        selected_register_index_ = visible_register_rows_[static_cast<std::size_t>(row)];
        const auto &reg = registers_[*selected_register_index_];
        register_value_->SetValue(wxString::FromUTF8(register_hex(reg)));
        register_value_->Enable(reg.available);
    }, registers_view_->GetId());
    register_filter_->Bind(wxEVT_TEXT, [this](wxCommandEvent &) { render_registers(); });
    register_changed_only_->Bind(wxEVT_CHECKBOX, [this](wxCommandEvent &) { render_registers(); });
    register_value_format_->Bind(wxEVT_CHOICE, [this](wxCommandEvent &) { render_registers(); });
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= visible_module_rows_.size()) return;
        const auto source_row = visible_module_rows_[static_cast<std::size_t>(row)];
        if (source_row >= modules_.size()) return;
        const auto &module = modules_[source_row];
        memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(module.base)));
        refresh_memory();
    }, modules_view_->GetId());
    Bind(wxEVT_LIST_ITEM_SELECTED, [this](wxListEvent &event) {
        const auto row = event.GetIndex();
        if (row < 0 || static_cast<std::size_t>(row) >= visible_memory_region_rows_.size()) return;
        const auto source_row = visible_memory_region_rows_[static_cast<std::size_t>(row)];
        if (source_row >= memory_regions_.size()) return;
        const auto address = memory_regions_[source_row].start;
        memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(address)));
        refresh_memory();
    }, memory_regions_view_->GetId());
    Bind(wxEVT_TIMER, [this](wxTimerEvent &) { poll_event(); }, poll_id);
    document_changed();
    refresh_state();
}

plugins::ActiveDebuggerServices DebuggerView::active_debugger_services(
    std::function<std::int32_t(HexLabActiveDocumentInfo&)> document_query) const {
    plugins::ActiveDebuggerServices services;
    const auto session = session_;
    const auto state = inspection_state_;
    const auto token_valid = [session, state, document_query](const HexLabActiveDebuggerToken& token) {
        if (!session || !state || state->stopping.load(std::memory_order_acquire) ||
            token.session_id != state->session_id ||
            token.session_generation != state->session_generation.load(std::memory_order_acquire) ||
            token.stop_generation != state->stop_generation.load(std::memory_order_acquire)) return false;
        HexLabActiveDebuggerInfo current{}; current.struct_size = sizeof(current);
        current.token.document.struct_size = sizeof(current.token.document);
        if (!document_query) return false;
        HexLabActiveDocumentInfo document{}; document.struct_size = sizeof(document);
        document.token.struct_size = sizeof(document.token);
        if (document_query(document) != HEXLAB_ACTIVE_DOCUMENT_OK) return false;
        const auto& a = token.document; const auto& b = document.token;
        return a.document_id == b.document_id && a.open_generation == b.open_generation &&
            a.edit_revision == b.edit_revision && a.byte_revision == b.byte_revision &&
            a.decision_revision == b.decision_revision;
    };
    services.query = [session, state, document_query](HexLabActiveDebuggerInfo& out) {
        if (!session || !state || !document_query) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        HexLabActiveDocumentInfo doc{}; doc.struct_size = sizeof(doc); doc.token.struct_size = sizeof(doc.token);
        if (document_query(doc) != HEXLAB_ACTIVE_DOCUMENT_OK) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        std::lock_guard lock(state->backend_mutex);
        if (state->stopping.load(std::memory_order_acquire)) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        HexLabActiveDocumentInfo current{}; current.struct_size=sizeof(current); current.token.struct_size=sizeof(current.token);
        if (document_query(current)!=HEXLAB_ACTIVE_DOCUMENT_OK ||
            current.token.document_id!=doc.token.document_id || current.token.open_generation!=doc.token.open_generation ||
            current.token.edit_revision!=doc.token.edit_revision || current.token.byte_revision!=doc.token.byte_revision ||
            current.token.decision_revision!=doc.token.decision_revision) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        out.state = static_cast<std::uint32_t>(session->state());
        out.token.session_id = state->session_id;
        out.token.session_generation = state->session_generation.load(std::memory_order_acquire);
        out.token.stop_generation = state->stop_generation.load(std::memory_order_acquire);
        out.token.document = doc.token;
        if (const auto& process = session->process()) {
            out.has_process = 1; out.process.struct_size = sizeof(out.process);
            out.process.id = process->id; out.process.architecture = static_cast<std::uint32_t>(process->architecture);
            const auto n = std::min(process->name.size(), sizeof(out.process.name) - 1);
            std::memcpy(out.process.name, process->name.data(), n); out.process.name[n] = '\0';
        }
        return HEXLAB_ACTIVE_DEBUGGER_OK;
    };
    services.threads = [session, state, token_valid](const HexLabActiveDebuggerToken& token, std::uint64_t start,
        std::uint32_t capacity, HexLabDebugThread* output, std::uint32_t* written) {
        if (!written || (capacity && !output) || capacity > HEXLAB_ACTIVE_DEBUGGER_MAX_PAGE || !token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::lock_guard lock(state->backend_mutex);
        if (session->state() != debugger::SessionState::stopped) return HEXLAB_ACTIVE_DEBUGGER_NOT_STOPPED;
        if (!token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        auto rows = session->threads(); if (!rows) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        const auto begin = std::min<std::size_t>(static_cast<std::size_t>(start), rows.value().size());
        const auto count = std::min<std::size_t>(capacity, rows.value().size() - begin);
        std::vector<HexLabDebugThread> result(count);
        for (std::size_t i=0;i<count;++i) { auto& row=result[i]; if(output[i].struct_size<sizeof(row)) return HEXLAB_ACTIVE_DEBUGGER_INVALID;
            row.struct_size=sizeof(row);
            const auto& src=rows.value()[begin+i]; row.struct_size=sizeof(row); row.id=src.id; row.state=static_cast<std::uint32_t>(src.state);
            const auto n=std::min(src.name.size(),sizeof(row.name)-1); std::memcpy(row.name,src.name.data(),n); row.name[n]='\0'; }
        if (!token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::copy(result.begin(), result.end(), output);
        *written=static_cast<std::uint32_t>(count); return HEXLAB_ACTIVE_DEBUGGER_OK;
    };
    services.read_registers = [session, state, token_valid](const HexLabActiveDebuggerToken& token, std::uint64_t thread,
        std::uint64_t start, std::uint32_t capacity, HexLabDebugRegister* output, std::uint32_t* written) {
        if (!thread || !written || (capacity && !output) || capacity > HEXLAB_ACTIVE_DEBUGGER_MAX_PAGE || !token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::lock_guard lock(state->backend_mutex); if(session->state()!=debugger::SessionState::stopped)return HEXLAB_ACTIVE_DEBUGGER_NOT_STOPPED; if (!token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        auto rows=session->read_registers(thread); if(!rows) return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        const auto begin=std::min<std::size_t>(static_cast<std::size_t>(start),rows.value().size());
        const auto count=std::min<std::size_t>(capacity,rows.value().size()-begin);
        std::vector<HexLabDebugRegister> result(count);
        for(std::size_t i=0;i<count;++i){auto& row=result[i]; if(output[i].struct_size<sizeof(row))return HEXLAB_ACTIVE_DEBUGGER_INVALID;
            const auto& src=rows.value()[begin+i]; if(src.bytes.size()>sizeof(row.bytes))return HEXLAB_ACTIVE_DEBUGGER_FAILED;
            row={}; row.struct_size=sizeof(row); row.number=src.number; row.byte_count=static_cast<std::uint32_t>(src.bytes.size());
            row.byte_order=!src.byte_order?HEXLAB_DEBUGGER_BYTE_ORDER_UNKNOWN:*src.byte_order==ByteOrder::big?HEXLAB_DEBUGGER_BYTE_ORDER_BIG:HEXLAB_DEBUGGER_BYTE_ORDER_LITTLE;
            std::memcpy(row.bytes,src.bytes.data(),src.bytes.size());
            const auto nn=std::min(src.name.size(),sizeof(row.name)-1), gn=std::min(src.group.size(),sizeof(row.group)-1);
            std::memcpy(row.name,src.name.data(),nn); row.name[nn]='\0'; std::memcpy(row.group,src.group.data(),gn); row.group[gn]='\0'; }
        if (!token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::copy(result.begin(), result.end(), output);
        *written=static_cast<std::uint32_t>(count); return HEXLAB_ACTIVE_DEBUGGER_OK;
    };
    services.read_memory = [session, state, token_valid](const HexLabActiveDebuggerToken& token, std::uint64_t address,
        std::uint32_t size, std::uint8_t* output) {
        if (!output || !size || size>HEXLAB_ACTIVE_DEBUGGER_MAX_READ || !token_valid(token)) return HEXLAB_ACTIVE_DEBUGGER_STALE;
        std::lock_guard lock(state->backend_mutex); if(session->state()!=debugger::SessionState::stopped)return HEXLAB_ACTIVE_DEBUGGER_NOT_STOPPED; if(!token_valid(token))return HEXLAB_ACTIVE_DEBUGGER_STALE;
        auto bytes=session->read_memory(address,size); if(!bytes || bytes.value().size()!=size)return HEXLAB_ACTIVE_DEBUGGER_FAILED;
        if(!token_valid(token))return HEXLAB_ACTIVE_DEBUGGER_STALE;
        for(std::size_t i=0;i<size;++i)output[i]=std::to_integer<std::uint8_t>(bytes.value()[i]);
        return HEXLAB_ACTIVE_DEBUGGER_OK;
    };
    return services;
}

DebuggerView::~DebuggerView() {
    memory_search_stop_.request_stop();
    {
        std::lock_guard lock(termination_state_->mutex);
        termination_state_->target = nullptr;
    }
    {
        std::lock_guard lock(inspection_state_->mutex);
        inspection_state_->target = nullptr;
        inspection_state_->stopping = true;
        inspection_state_->tasks.clear();
    }
    inspection_state_->ready.notify_one();
}

void DebuggerView::enqueue_inspection(int kind, std::function<void()> task) {
    // Memory search and the target-provided OS-data annex are deliberately
    // low-priority inspections. An interactive request can make room for
    // register, memory, module, region, and frame work before these larger or
    // potentially network-bound requests run.
    constexpr int memory_search_kind = 7;
    if (kind != memory_search_kind) memory_search_stop_.request_stop();
    {
        std::lock_guard lock(inspection_state_->mutex);
        if (inspection_state_->stopping) return;
        std::erase_if(inspection_state_->tasks, [kind](const auto &pending) { return pending.kind == kind; });
        const auto position = std::find_if(inspection_state_->tasks.begin(), inspection_state_->tasks.end(),
            [kind](const auto &pending) { return pending.kind > kind; });
        inspection_state_->tasks.insert(position, {kind, std::move(task)});
    }
    inspection_state_->ready.notify_one();
}

void DebuggerView::launch() {
    debugger::Target target;
    target.executable = narrow(executable_->GetValue());
    target.working_directory = narrow(working_directory_->GetValue());
    if (!split_arguments(narrow(arguments_->GetValue()), target.arguments)) {
        report("Arguments contain an unmatched quote."); return;
    }
    if (remote_session_active_) {
        std::string environment_error;
        if (!parse_remote_environment(narrow(remote_environment_->GetValue()),
                                      target.remote_environment, environment_error)) {
            report(wxString::FromUTF8(environment_error)); return;
        }
    }
    if (target.executable.empty()) { report("Choose an executable to launch."); return; }
    save_remote_configuration();
    if (!cancel_source_step_out()) return;
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->launch(target); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    remote_session_active_ = false;
    event_->Clear(); threads_.clear(); breakpoints_.clear();
    threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems(); breakpoints_view_->DeleteAllItems(); visible_breakpoint_rows_.clear();
    clear_inspection();
    report(wxString::Format("Launched %s (PID %llu)", result.value().name,
                            static_cast<unsigned long long>(result.value().id)));
    refresh_state(); poll_timer_.Start(100);
}

void DebuggerView::attach() {
    std::uint64_t id = 0;
    const auto selected = processes_choice_->GetSelection();
    const auto entered_id = narrow(process_id_->GetValue());
    const bool selected_process_matches =
        selected >= 0 && static_cast<std::size_t>(selected) < visible_processes_.size() &&
        entered_id == std::to_string(visible_processes_[static_cast<std::size_t>(selected)].id);
    if (selected_process_matches)
        id = visible_processes_[static_cast<std::size_t>(selected)].id;
    else if (!parse_unsigned(entered_id, id)) {
        report("Enter a valid process ID (decimal or 0x-prefixed hexadecimal)."); return;
    }
    if (id == 0) {
        report("Enter a valid process ID (decimal or 0x-prefixed hexadecimal)."); return;
    }
    if (!cancel_source_step_out()) return;
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return remote_session_active_ ? session_->attach_remote_process(id) : session_->attach(id);
    }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    if (remote_session_active_) {
        pending_event_.reset(); pending_event_thread_.reset(); threads_.clear(); breakpoints_.clear();
        threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems(); breakpoints_view_->DeleteAllItems(); visible_breakpoint_rows_.clear();
    }
    event_->Clear(); threads_.clear();
    clear_inspection();
    report(wxString::Format("Attached to %s (PID %llu)", result.value().name,
                            static_cast<unsigned long long>(result.value().id)));
    if (remote_session_active_) refresh_processes();
    refresh_state(); poll_timer_.Start(100);
}

void DebuggerView::refresh_processes() {
    std::optional<debugger::ProcessId> previous_selection;
    const auto previous_row = processes_choice_->GetSelection();
    if (previous_row >= 0 && static_cast<std::size_t>(previous_row) < visible_processes_.size())
        previous_selection = visible_processes_[static_cast<std::size_t>(previous_row)].id;
    processes_.clear(); visible_processes_.clear();
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->processes(); }();
    if (!result) {
        processes_choice_->Clear();
        processes_choice_->Append("Unavailable: " + wxString::FromUTF8(result.error().message));
        process_filter_status_->SetLabel("Unavailable");
        update_process_actions();
        report(wxString::FromUTF8(result.error().message)); return;
    }
    processes_ = std::move(result.value());
    const auto active_id = session_->process() ? std::optional<debugger::ProcessId>{session_->process()->id} : std::nullopt;
    std::optional<debugger::ProcessId> desired = active_id;
    if (!desired || std::none_of(processes_.begin(), processes_.end(), [&](const auto &p) { return p.id == *desired; }))
        desired = previous_selection;
    render_processes(desired);
}

void DebuggerView::render_processes(std::optional<debugger::ProcessId> preferred) {
    const auto query = lower_register_text(narrow(process_filter_->GetValue()));
    processes_choice_->Clear();
    visible_processes_.clear();
    for (const auto &process : processes_) {
        const auto id = std::to_string(process.id);
        const auto architecture = process_architecture_label(process.architecture);
        const auto searchable = lower_register_text(id + " " + process.name + " " + std::string(architecture));
        if (!query.empty() && searchable.find(query) == std::string::npos) continue;
        visible_processes_.push_back(process);
    }
    if (process_sort_->GetSelection() == 1) {
        std::stable_sort(visible_processes_.begin(), visible_processes_.end(), [](const auto &left, const auto &right) {
            const auto left_name = lower_register_text(left.name);
            const auto right_name = lower_register_text(right.name);
            return left_name != right_name ? left_name < right_name : left.id < right.id;
        });
    } else if (process_sort_->GetSelection() == 2) {
        std::stable_sort(visible_processes_.begin(), visible_processes_.end(), [](const auto &left, const auto &right) {
            const auto left_architecture = process_architecture_label(left.architecture);
            const auto right_architecture = process_architecture_label(right.architecture);
            if ((left_architecture == "unknown") != (right_architecture == "unknown"))
                return right_architecture == "unknown";
            const auto left_label = lower_register_text(left_architecture);
            const auto right_label = lower_register_text(right_architecture);
            return left_label != right_label ? left_label < right_label : left.id < right.id;
        });
    } else {
        std::stable_sort(visible_processes_.begin(), visible_processes_.end(), [](const auto &left, const auto &right) {
            return left.id < right.id;
        });
    }
    processes_choice_->Clear();
    for (const auto &process : visible_processes_) {
        const auto architecture = process_architecture_label(process.architecture);
        processes_choice_->Append(wxString::Format("%llu  %s  [%s]",
            static_cast<unsigned long long>(process.id), wxString::FromUTF8(process.name),
            wxString::FromUTF8(architecture.data(), architecture.size())));
    }
    process_filter_status_->SetLabel(wxString::Format("%llu of %llu processes",
        static_cast<unsigned long long>(visible_processes_.size()),
        static_cast<unsigned long long>(processes_.size())));
    if (visible_processes_.empty())
        processes_choice_->Append(processes_.empty() ? "No processes found" : "No matching processes");
    if (preferred) {
        const auto row = std::find_if(visible_processes_.begin(), visible_processes_.end(),
            [&](const auto &process) { return process.id == *preferred; });
        if (row != visible_processes_.end()) {
            const auto index = static_cast<int>(std::distance(visible_processes_.begin(), row));
            processes_choice_->SetSelection(index);
            process_id_->SetValue(wxString::Format("%llu", static_cast<unsigned long long>(row->id)));
        }
    }
    update_process_actions();
}

void DebuggerView::update_process_actions() {
    if (!detach_remote_process_button_) return;
    const auto selection = processes_choice_->GetSelection();
    const auto state = session_->state();
    bool enabled = remote_session_active_ && session_->process() &&
        (state == debugger::SessionState::running || state == debugger::SessionState::stopped) &&
        selection >= 0 && static_cast<std::size_t>(selection) < visible_processes_.size();
    if (enabled)
        enabled = visible_processes_[static_cast<std::size_t>(selection)].id != session_->process()->id;
    detach_remote_process_button_->Enable(enabled);
}

void DebuggerView::detach_remote_process() {
    if (!remote_session_active_) {
        report("Secondary-process detach is available only for a connected remote target.");
        return;
    }
    const auto state = session_->state();
    if (state != debugger::SessionState::running && state != debugger::SessionState::stopped) {
        report("There is no active remote session.");
        update_process_actions();
        return;
    }
    const auto selection = processes_choice_->GetSelection();
    if (selection < 0 || static_cast<std::size_t>(selection) >= visible_processes_.size()) {
        report("Select a listed remote process to detach.");
        return;
    }
    const auto process = visible_processes_[static_cast<std::size_t>(selection)];
    const auto active = session_->process();
    if (!active) {
        report("The active remote process identity is unavailable; secondary detach is disabled.");
        update_process_actions();
        return;
    }
    if (process.id == active->id) {
        report("The selected process is active. Use Detach / Disconnect to end this session.");
        update_process_actions();
        return;
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->detach_remote_process(process.id);
    }();
    if (!result) {
        report(wxString::FromUTF8(result.error().message));
        refresh_processes();
        return;
    }
    report(wxString::Format("Detached remote process %llu; the active process remains attached.",
                            static_cast<unsigned long long>(process.id)));
    refresh_processes();
    refresh_state();
}

void DebuggerView::connect_remote() {
    if (!cancel_source_step_out()) return;
    if (remote_connecting_) return;
    const auto host = narrow(remote_host_->GetValue());
    std::uint64_t port = 0;
    if (host.empty() || host.size() > 255 || !parse_unsigned(narrow(remote_port_->GetValue()), port) || port == 0 || port > 65535) {
        report("Enter a host of at most 255 bytes and a TCP port from 1 through 65535."); return;
    }
    std::uint64_t packet_limit = 0;
    if (!parse_unsigned(narrow(remote_packet_limit_->GetValue()), packet_limit) || packet_limit < 128 || packet_limit > 1024 * 1024) {
        report("RSP packet limit must be 128 through 1048576 bytes."); return;
    }
    const debugger::RemoteConnectOptions options{static_cast<std::size_t>(packet_limit),
        remote_no_ack_->GetValue(), remote_non_stop_->GetValue(), remote_thread_events_->GetValue()};
    save_remote_configuration();
    remote_connecting_ = true;
    const auto request = ++remote_connect_request_;
    Enable(false);
    remote_connect_button_->SetLabel("Connecting...");
    report(wxString::Format("Connecting to %s:%llu...", wxString::FromUTF8(host),
                            static_cast<unsigned long long>(port)));
    auto state = inspection_state_;
    auto session = session_;
    enqueue_inspection(0, [state, session, host, port, options, request] {
        std::optional<debugger::ProcessInfo> process;
        std::vector<debugger::ProcessInfo> processes;
        std::string connect_error, process_error;
        {
            std::lock_guard lock(state->backend_mutex);
            auto connected = session->connect_remote(host, static_cast<std::uint16_t>(port), options);
            if (!connected) connect_error = connected.error().message;
            else {
                process = std::move(connected.value());
                auto listed = session->processes();
                if (listed) processes = std::move(listed.value());
                else process_error = listed.error().message;
            }
        }
        if (!wxTheApp) {
            if (process) {
                std::lock_guard lock(state->backend_mutex);
                (void)session->detach();
            }
            return;
        }
        wxTheApp->CallAfter([state, session, request, process = std::move(process),
                             processes = std::move(processes), connect_error = std::move(connect_error),
                             process_error = std::move(process_error)]() mutable {
            DebuggerView *target = nullptr;
            {
                std::lock_guard lock(state->mutex);
                target = state->target;
            }
            if (target) {
                target->finish_remote_connect(request, std::move(process), std::move(processes),
                                              std::move(connect_error), std::move(process_error));
            } else if (process) {
                std::lock_guard lock(state->backend_mutex);
                (void)session->detach();
            }
        });
    });
}

void DebuggerView::finish_remote_connect(std::uint64_t request,
                                         std::optional<debugger::ProcessInfo> process,
                                         std::vector<debugger::ProcessInfo> processes,
                                         std::string connect_error, std::string process_error) {
    if (request != remote_connect_request_) {
        if (process) {
            auto session = session_;
            auto state = inspection_state_;
            enqueue_inspection(0, [session, state] {
                std::lock_guard lock(state->backend_mutex);
                (void)session->detach();
            });
        }
        return;
    }
    remote_connecting_ = false;
    Enable(true);
    remote_connect_button_->SetLabel("Connect RSP");
    if (!process) {
        report(wxString::FromUTF8(connect_error));
        refresh_state();
        return;
    }
    remote_session_active_ = true;
    std::optional<debugger::RemoteTargetMetadata> remote_metadata;
    {
        std::lock_guard lock(inspection_state_->backend_mutex);
        remote_metadata = session_->remote_target_metadata();
    }
    save_remote_configuration(remote_metadata);
    pending_event_.reset(); pending_event_thread_.reset(); threads_.clear(); breakpoints_.clear();
    threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems(); breakpoints_view_->DeleteAllItems(); visible_breakpoint_rows_.clear();
    event_->Clear(); clear_inspection();
    report(wxString::Format("Connected to remote target %s (thread %llu)", wxString::FromUTF8(process->name),
                            static_cast<unsigned long long>(process->id)));
    process_id_->SetValue(wxString::Format("%llu", static_cast<unsigned long long>(process->id)));
    processes_ = std::move(processes);
    const auto active = std::find_if(processes_.begin(), processes_.end(),
        [&](const auto &listed) { return listed.id == process->id; });
    render_processes(active == processes_.end() ? std::nullopt : std::optional<debugger::ProcessId>{active->id});
    if (!process_error.empty()) {
        visible_processes_.clear();
        processes_choice_->Clear();
        processes_choice_->Append("Unavailable: " + wxString::FromUTF8(process_error));
        process_filter_status_->SetLabel("Unavailable");
        report("Connected, but process enumeration failed: " + wxString::FromUTF8(process_error));
    }
    update_process_actions();
    refresh_state(); poll_timer_.Start(100);
}

void DebuggerView::detach() {
    poll_timer_.Stop();
    if (!cancel_source_step_out()) return;
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->detach(); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    remote_session_active_ = false;
    pending_event_.reset(); pending_event_thread_.reset(); threads_.clear(); breakpoints_.clear();
    threads_view_->DeleteAllItems(); registers_view_->DeleteAllItems(); breakpoints_view_->DeleteAllItems(); visible_breakpoint_rows_.clear();
    clear_inspection();
    event_->Clear(); report("Detached from debug target."); refresh_state();
}

void DebuggerView::terminate() {
    if (termination_pending_) return;
    const auto current_state = session_->state();
    if (current_state != debugger::SessionState::running && current_state != debugger::SessionState::stopped) {
        report("There is no active target to terminate.");
        return;
    }
    wxString target = "the active target";
    if (session_->process() && !session_->process()->name.empty())
        target = wxString::FromUTF8(session_->process()->name);
    const auto confirmation = wxString::Format(
        "Permanently terminate %s?\n\nDetach leaves the target running.", target);
    wxMessageDialog dialog(this, confirmation, "Confirm target termination",
                           wxYES_NO | wxNO_DEFAULT | wxICON_WARNING);
    if (dialog.ShowModal() != wxID_YES) return;

    termination_pending_ = true;
    Enable(false);
    poll_timer_.Stop();
    report("Terminating debug target...");
    auto state = termination_state_;
    auto session = session_;
    auto inspection = inspection_state_;
    try {
        std::thread([state = std::move(state), session = std::move(session), inspection = std::move(inspection)]() mutable {
            auto result = [&] { std::lock_guard lock(inspection->backend_mutex); return session->terminate(); }();
            bool alive = false;
            {
                std::lock_guard lock(state->mutex);
                state->result.emplace(std::move(result));
                alive = state->target != nullptr;
            }
            if (alive && wxTheApp) wxTheApp->CallAfter([state] {
                DebuggerView *target = nullptr;
                std::optional<debugger::Status> result;
                {
                    std::lock_guard lock(state->mutex);
                    target = state->target;
                    result = std::move(state->result);
                    state->result.reset();
                }
                if (target && result) target->finish_terminate(std::move(*result));
            });
        }).detach();
    } catch (const std::exception &error) {
        termination_pending_ = false;
        Enable(true);
        if (session_->state() == debugger::SessionState::running) poll_timer_.Start(100);
        report(wxString::Format("Could not start target termination: %s", error.what()));
    }
}

void DebuggerView::finish_terminate(debugger::Status result) {
    termination_pending_ = false;
    Enable(true);
    if (!result) {
        if (result.error().code == ErrorCode::unsupported)
            report("Target termination is unsupported by this debugger backend: " +
                   wxString::FromUTF8(result.error().message));
        else
            report(wxString::FromUTF8(result.error().message));
        if (session_->state() == debugger::SessionState::running) poll_timer_.Start(100);
        return;
    }

    poll_timer_.Stop();
    pending_event_.reset(); pending_event_thread_.reset(); breakpoints_.clear();
    breakpoints_view_->DeleteAllItems(); visible_breakpoint_rows_.clear();
    clear_inspection();
    refresh_threads(selected_register_thread_);
    event_->SetValue("Target terminated.");
    report("Terminated debug target.");
    refresh_state();
}

void DebuggerView::poll_event() {
    document_changed();
    if (session_->state() != debugger::SessionState::running) return;
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->wait_event(std::chrono::milliseconds(0)); }();
    if (!result) {
        if (result.error().code == ErrorCode::busy) { persist_project_breakpoint_hit_counts(); return; }
        poll_timer_.Stop(); report(wxString::FromUTF8(result.error().message)); refresh_state(); return;
    }
    const auto &received = result.value();
    last_event_snapshot_ = received;
    if (received.thread != 0 && received.kind != debugger::EventKind::output) {
        char detail[64]{};
        std::snprintf(detail, sizeof(detail), " at 0x%llX (code 0x%X)",
            static_cast<unsigned long long>(received.address), static_cast<unsigned>(received.code));
        const auto summary = event_name(received.kind) + detail;
        thread_last_events_[received.thread] = {received.sequence, summary};
        constexpr std::size_t max_thread_event_rows = 4096;
        if (thread_last_events_.size() > max_thread_event_rows) {
            const auto oldest = std::min_element(thread_last_events_.begin(), thread_last_events_.end(),
                [](const auto &left, const auto &right) { return left.second.first < right.second.first; });
            if (oldest != thread_last_events_.end()) thread_last_events_.erase(oldest);
        }
    }
    refresh_breakpoints();
    persist_project_breakpoint_hit_counts();
    if (received.kind == debugger::EventKind::output) {
        event_->SetValue(wxString::FromUTF8(received.message));
        report(wxString::FromUTF8(received.message));
        if (session_->state() == debugger::SessionState::running) {
            refresh_state();
            return;
        }
    }
    std::optional<std::string> source_step_out_status;
    if (source_step_out_target_) {
        const auto target = *source_step_out_target_;
        const bool breakpoint_hit = received.process == target.process && received.thread == target.thread &&
            received.address == target.runtime_address &&
            std::find(received.breakpoint_ids.begin(), received.breakpoint_ids.end(), target.breakpoint) !=
                received.breakpoint_ids.end();
        bool same_process = false;
        std::optional<Error> cleanup_error;
        {
            std::lock_guard lock(inspection_state_->backend_mutex);
            const auto process = session_->process();
            same_process = process && process->id == target.process;
            if (same_process && received.kind != debugger::EventKind::process_exited) {
                const auto removed = session_->remove_breakpoint(target.breakpoint);
                if (!removed) cleanup_error = removed.error();
            }
        }
        if (!cleanup_error || !same_process || received.kind == debugger::EventKind::process_exited)
            source_step_out_target_.reset();
        if (breakpoint_hit) {
            source_step_out_status = target.source_step_over
                ? "Source step-over reached " + target.source_location + "."
                : target.instruction_step_over ? "Step over reached the instruction after the call."
                                               : "Source step-out reached " + target.source_location + ".";
        } else if (!same_process || received.kind == debugger::EventKind::process_exited) {
            source_step_out_status = target.source_step_over
                ? "Source step-over canceled because its process exited or changed."
                : target.instruction_step_over ? "Step over canceled because its process exited or changed."
                                               : "Source step-out canceled because its process exited or changed.";
        } else if (received.thread != target.thread) {
            source_step_out_status = target.source_step_over
                ? "Source step-over canceled by a stop in a different thread."
                : target.instruction_step_over ? "Step over canceled by a stop in a different thread."
                                               : "Source step-out canceled by a stop in a different thread.";
        } else {
            source_step_out_status = target.source_step_over
                ? "Source step-over canceled by an intervening target stop."
                : target.instruction_step_over ? "Step over canceled by an intervening target stop."
                                               : "Source step-out canceled by an intervening target stop.";
        }
        if (cleanup_error) *source_step_out_status += " Temporary breakpoint cleanup failed: " + cleanup_error->message;
        if (same_process && received.kind != debugger::EventKind::process_exited) refresh_breakpoints();
        const auto current_document_snapshot = document_ ? document_() : nullptr;
        if (current_document_snapshot && (current_document_snapshot->id != target.document ||
            current_document_snapshot->revision != target.document_revision))
            *source_step_out_status += " The source document changed while the target was running.";
    }
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    invalidate_frames();
    ++signal_info_request_;
    ++remote_monitor_request_;
    remote_monitor_running_ = false;
    remote_monitor_output_->Clear();
    remote_monitor_status_->SetLabel("Stop event changed; run a new monitor command if needed.");
    pending_event_ = received.sequence;
    pending_event_thread_ = received.thread ? std::optional{received.thread} : std::nullopt;
    pending_event_code_ = received.code;
    signal_info_reading_ = false;
    signal_info_view_->Clear();
    signal_info_status_->SetLabel("Pending event changed; read its signal information.");
    thread_schedule_snapshot_event_.reset();
    wxString breakpoint_ids;
    for (const auto id : received.breakpoint_ids) {
        if (!breakpoint_ids.empty()) breakpoint_ids += ", ";
        breakpoint_ids += wxString::Format("%llu", static_cast<unsigned long long>(id));
    }
    wxString owned_breakpoints;
    if (!breakpoint_ids.empty()) {
        owned_breakpoints = " (breakpoint IDs: ";
        owned_breakpoints += breakpoint_ids;
        owned_breakpoints += ")";
    }
    wxString exception_chance;
    if (received.first_chance.has_value())
        exception_chance = *received.first_chance ? " [first chance]" : " [second chance]";
    wxString exception_parameters;
    if (!received.exception_parameters.empty()) {
        exception_parameters = " [exception parameters:";
        for (const auto value : received.exception_parameters)
            exception_parameters += wxString::Format(" 0x%llX", static_cast<unsigned long long>(value));
        if (received.exception_parameters_truncated) exception_parameters += " ...truncated";
        exception_parameters += "]";
    }
    event_->SetValue(wxString::Format("%s%s at 0x%llX, thread %llu, code 0x%X: %s%s%s",
                                      event_name(received.kind), exception_chance,
                                      static_cast<unsigned long long>(received.address),
                                      static_cast<unsigned long long>(received.thread), received.code,
                                      wxString::FromUTF8(received.message), owned_breakpoints, exception_parameters));
    report(wxString::Format("Received event %llu: %s", static_cast<unsigned long long>(received.sequence),
                            event_name(received.kind)));
    refresh_state();
    refresh_threads(received.thread ? std::optional{received.thread} : std::nullopt);
    if (received.kind != debugger::EventKind::process_exited) {
        refresh_modules();
        refresh_memory_regions();
        if (received.address != 0) {
            memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(received.address)));
            refresh_memory();
        }
    }
    else poll_timer_.Stop();
    if (source_step_out_status) report(wxString::FromUTF8(*source_step_out_status));
}

void DebuggerView::continue_event(debugger::ContinueStatus status) {
    if (!pending_event_) { report("There is no pending debug event to continue."); return; }
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->continue_execution(*pending_event_, status); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    report(status == debugger::ContinueStatus::handled ? "Continued event as handled." : "Passed event to the target.");
    pending_event_.reset(); pending_event_thread_.reset(); invalidate_frames(); ++register_request_; refresh_state();
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    refresh_threads(selected_register_thread_);
}

void DebuggerView::continue_selected_thread() {
    if (!pending_event_) { report("There is no pending stop event to continue."); return; }
    if (!selected_register_thread_) { report("Select a stopped thread first."); return; }
    if (!pending_event_thread_) { report("The pending event has no identifiable thread; use Continue."); return; }
    if (*selected_register_thread_ != *pending_event_thread_) {
        report(wxString::Format("Thread %llu does not own the pending event; select thread %llu or use Continue.",
            static_cast<unsigned long long>(*selected_register_thread_),
            static_cast<unsigned long long>(*pending_event_thread_)));
        return;
    }
    const auto thread = *selected_register_thread_;
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->continue_thread_execution(*pending_event_, thread); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    pending_event_.reset(); pending_event_thread_.reset(); invalidate_frames(); ++register_request_;
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    refresh_state(); refresh_threads(thread);
    report(wxString::Format("Continued thread %llu for the pending event.",
                            static_cast<unsigned long long>(thread)));
}

void DebuggerView::continue_stopped_peers() {
    if (!pending_event_ || !pending_event_thread_) {
        report("Run stopped peers requires a pending event with an identified owner.");
        return;
    }
    if (!thread_run_states_supported_ || thread_schedule_snapshot_event_ != pending_event_) {
        report("A fresh authoritative thread-state snapshot is not available for this event.");
        return;
    }
    const auto owner = *pending_event_thread_;
    const auto owner_thread = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
        return thread.id == owner;
    });
    if (owner_thread == threads_.end() || owner_thread->state != debugger::ThreadState::stopped) {
        report("The event-owner thread is not confirmed stopped; no schedule was sent.");
        return;
    }
    std::vector<debugger::ThreadResumeAction> actions;
    actions.reserve(threads_.size());
    actions.push_back({owner, debugger::ThreadResumeKind::stop});
    std::size_t peer_count = 0;
    for (const auto &thread : threads_) {
        if (thread.id == owner || thread.state != debugger::ThreadState::stopped) continue;
        actions.push_back({thread.id, debugger::ThreadResumeKind::continue_execution});
        ++peer_count;
    }
    if (peer_count == 0) {
        report("There are no other known-stopped threads to run.");
        return;
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->resume_threads(*pending_event_, actions);
    }();
    if (!result) {
        report(wxString::FromUTF8(result.error().message));
        return;
    }
    const auto sequence = *pending_event_;
    pending_event_.reset();
    pending_event_thread_.reset();
    thread_schedule_snapshot_event_.reset();
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    invalidate_frames();
    ++register_request_;
    refresh_state();
    refresh_threads(owner);
    poll_timer_.Start(100);
    report(wxString::Format("Started %llu stopped peer thread(s); event-owner thread %llu remains stopped (event %llu).",
        static_cast<unsigned long long>(peer_count), static_cast<unsigned long long>(owner),
        static_cast<unsigned long long>(sequence)));
}

void DebuggerView::update_thread_schedule_controls() {
    if (!continue_stopped_peers_button_) return;
    bool enabled = false;
    if (pending_event_ && pending_event_thread_ && thread_run_states_supported_ &&
        thread_schedule_snapshot_event_ == pending_event_) {
        const auto owner = *pending_event_thread_;
        const auto owner_thread = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
            return thread.id == owner;
        });
        const bool owner_stopped = owner_thread != threads_.end() &&
            owner_thread->state == debugger::ThreadState::stopped;
        const bool has_stopped_peer = std::any_of(threads_.begin(), threads_.end(), [&](const auto &thread) {
            return thread.id != owner && thread.state == debugger::ThreadState::stopped;
        });
        enabled = owner_stopped && has_stopped_peer;
    }
    continue_stopped_peers_button_->Enable(enabled);
}

void DebuggerView::update_thread_selection_summary() {
    if (!thread_selection_summary_) return;
    if (!selected_register_thread_) {
        thread_selection_summary_->SetLabel("Select a thread to inspect its registers.");
        return;
    }
    const auto selected = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
        return thread.id == *selected_register_thread_;
    });
    if (selected == threads_.end()) {
        thread_selection_summary_->SetLabel(wxString::Format("Selected thread 0x%llX is no longer in the snapshot.",
            static_cast<unsigned long long>(*selected_register_thread_)));
        return;
    }
    const char *state = selected->state == debugger::ThreadState::running ? "running" :
        selected->state == debugger::ThreadState::stopped ? "stopped" :
        selected->state == debugger::ThreadState::exited ? "exited" : "unknown";
    wxString summary = wxString::Format("Selected: %s  |  ID: 0x%llX  |  State: %s",
        wxString::FromUTF8(selected->name), static_cast<unsigned long long>(selected->id), state);
    if (selected->core)
        summary += wxString::Format("  |  Core: %u", static_cast<unsigned>(*selected->core));
    if (pending_event_thread_ && *pending_event_thread_ == selected->id)
        summary += "  |  Pending stop owner";
    thread_selection_summary_->SetLabel(summary);
}

void DebuggerView::thread_context_action(debugger::ThreadResumeKind action) {
    if (!pending_event_ || !pending_event_thread_) {
        report("A thread action requires a pending event with an identified owner.");
        return;
    }
    if (!selected_register_thread_) {
        report("Select a thread first.");
        return;
    }
    const auto selected = *selected_register_thread_;
    const auto thread = std::find_if(threads_.begin(), threads_.end(), [&](const auto &item) { return item.id == selected; });
    if (thread == threads_.end()) { report("The selected thread is no longer in the refreshed snapshot."); return; }
    if (thread->state == debugger::ThreadState::unknown || thread->state == debugger::ThreadState::exited) {
        report("Run-state is unknown or exited; no thread action was sent.");
        return;
    }
    if (action == debugger::ThreadResumeKind::stop && thread->state != debugger::ThreadState::running) {
        report("Only a known running thread can be stopped from this context menu.");
        return;
    }
    if (action != debugger::ThreadResumeKind::stop && thread->state != debugger::ThreadState::stopped) {
        report("Only a known stopped thread can be continued or stepped from this context menu.");
        return;
    }
    const auto owner = *pending_event_thread_;
    std::vector<debugger::ThreadResumeAction> actions;
    if (selected == owner) {
        actions.push_back({selected, action});
    } else if (action == debugger::ThreadResumeKind::stop) {
        // RSP schedules must consume the pending event. Stopping another
        // running thread therefore resumes the stopped event owner atomically.
        actions.push_back({owner, debugger::ThreadResumeKind::continue_execution});
        actions.push_back({selected, debugger::ThreadResumeKind::stop});
    } else {
        // Keep the event owner stopped while resuming/stepping another thread.
        actions.push_back({owner, debugger::ThreadResumeKind::stop});
        actions.push_back({selected, action});
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->resume_threads(*pending_event_, actions);
    }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    const auto event_sequence = *pending_event_;
    pending_event_.reset(); pending_event_thread_.reset();
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    invalidate_frames(); ++register_request_; refresh_state(); refresh_threads(selected);
    poll_timer_.Start(100);
    if (action == debugger::ThreadResumeKind::stop) {
        report(wxString::Format("Stopped thread %llu and resumed event-owner thread %llu (event %llu).",
            static_cast<unsigned long long>(selected), static_cast<unsigned long long>(owner),
            static_cast<unsigned long long>(event_sequence)));
    } else {
        report(wxString::Format("%s thread %llu; event-owner thread %llu remains stopped until its next event.",
            action == debugger::ThreadResumeKind::single_step ? "Stepping" : "Continuing",
            static_cast<unsigned long long>(selected), static_cast<unsigned long long>(owner)));
    }
}

void DebuggerView::interrupt_selected_thread() {
    if (!selected_register_thread_) {
        report("Select a thread first.");
        return;
    }
    const auto selected = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
        return thread.id == *selected_register_thread_;
    });
    if (selected == threads_.end() || selected->state != debugger::ThreadState::running) {
        report("Select a thread reported as running in the current snapshot.");
        return;
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->request_thread_interrupt(selected->id);
    }();
    if (!result) {
        report(wxString::FromUTF8(result.error().message));
        return;
    }
    report(wxString::Format("Requested a non-stop interrupt for thread 0x%llX; waiting for its stop event.",
        static_cast<unsigned long long>(selected->id)));
    poll_timer_.Start(100);
}

void DebuggerView::step_event() {
    if (!pending_event_) { report("There is no pending debug event to single-step."); return; }
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->single_step_execution(*pending_event_); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    pending_event_.reset(); pending_event_thread_.reset(); invalidate_frames(); ++register_request_;
    refresh_state(); refresh_threads(selected_register_thread_);
    poll_timer_.Start(100);
    report("Stepped one instruction; waiting for the next target event.");
}

void DebuggerView::step_out_event() {
    if (source_step_out_target_) {
        report(source_step_out_target_->source_step_over || source_step_out_target_->instruction_step_over
            ? "A step-over is already waiting for its destination or another stop event."
            : "A source step-out is already waiting for its caller location or another stop event.");
        return;
    }
    if (!pending_event_ || !pending_event_thread_ || session_->state() != debugger::SessionState::stopped) {
        report("Source step-out requires a stopped event with an identifiable owner thread.");
        return;
    }
    if (selected_register_thread_ != pending_event_thread_) {
        report("Select the thread that owns the pending event before stepping out.");
        return;
    }
    if (!frames_stop_ || frames_stop_ != pending_event_ || locals_stack_frames_.size() < 2 ||
        !frames_mapping_ || !current_document(inspection_document_)) {
        refresh_locals();
        report("Source step-out needs current caller frames; they are being refreshed. Try again when Frame 1 appears.");
        return;
    }

    const auto document = document_ ? document_() : nullptr;
    if (!document || !current_document(document) || !document->project || !document->project->loaded ||
        !document->project->loaded->image) {
        report("Source step-out requires the same open project image used to inspect the current stop.");
        return;
    }
    const auto &loaded = *document->project->loaded;
    const auto &image = *loaded.image;
    auto target = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return std::tuple{session_->modules(), session_->process(), session_->breakpoints()};
    }();
    auto &modules = std::get<0>(target);
    const auto &process = std::get<1>(target);
    const auto &existing_breakpoints = std::get<2>(target);
    if (!process || process->id == 0 || !modules) {
        report("Source step-out cannot refresh the active process and module identity.");
        return;
    }
    if (process->architecture != Architecture::x86 && process->architecture != Architecture::x86_64 &&
        process->architecture != Architecture::arm64) {
        report("Source step-out currently requires an x86, x64, or AArch64 target with recovered caller frames.");
        return;
    }
    std::string mapping_reason;
    const auto mapping = debugger_image_mapping(*document, modules.value(), process->architecture, mapping_reason);
    if (!mapping || mapping != frames_mapping_) {
        if (mapping)
            report("Source step-out stopped because the loaded-module mapping changed; refresh caller frames.");
        else
            report(wxString::FromUTF8(mapping_reason));
        invalidate_frames();
        return;
    }
    const auto &current_frame = locals_stack_frames_[0];
    const auto &caller_frame = locals_stack_frames_[1];
    const auto current_address = mapping->to_image(image, current_frame.runtime_pc);
    const auto caller_address = mapping->to_image(image, caller_frame.runtime_pc);
    if (!current_address || !caller_address || caller_frame.runtime_pc == 0) {
        report("Source step-out cannot map both the stopped frame and caller return address into the same loaded image.");
        return;
    }
    const auto *caller_segment = image.segment_at(*caller_address);
    if (!caller_segment || !caller_segment->executable) {
        report("Source step-out caller return address is outside initialized executable image data.");
        return;
    }
    const auto current_symbol = symbolize_debugger_address(*document->project, image, current_frame.runtime_pc,
        mapping->runtime_base, mapping->size);
    const auto caller_symbol = symbolize_debugger_address(*document->project, image, caller_frame.runtime_pc,
        mapping->runtime_base, mapping->size);
    if (!current_symbol || !current_symbol->source_location ||
        !caller_symbol || !caller_symbol->source_location) {
        report("Source step-out needs unambiguous source-line records for both the current frame and caller return address.");
        return;
    }
    const auto runtime_return = mapping->to_runtime(image, *caller_address);
    if (!runtime_return || *runtime_return != caller_frame.runtime_pc) {
        report("Source step-out caller address does not round-trip through the current module mapping.");
        return;
    }
    if (std::any_of(existing_breakpoints.begin(), existing_breakpoints.end(), [&](const auto &breakpoint) {
            return breakpoint.address == caller_frame.runtime_pc;
        })) {
        report("Source step-out cannot reuse a user breakpoint at the caller return address.");
        return;
    }

    auto added = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->add_breakpoint(caller_frame.runtime_pc, debugger::BreakpointKind::software);
    }();
    if (!added) {
        report("Could not arm source step-out at the caller return address: " + wxString::FromUTF8(added.error().message));
        return;
    }
    auto one_shot = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->set_breakpoint_one_shot(added.value().id, true);
    }();
    if (!one_shot) {
        std::lock_guard lock(inspection_state_->backend_mutex);
        (void)session_->remove_breakpoint(added.value().id);
        report("Could not configure the caller breakpoint as one-shot: " + wxString::FromUTF8(one_shot.error().message));
        return;
    }
    auto continued = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->continue_thread_execution(*pending_event_, *pending_event_thread_,
            debugger::ContinueStatus::handled);
    }();
    if (!continued) {
        std::lock_guard lock(inspection_state_->backend_mutex);
        (void)session_->remove_breakpoint(added.value().id);
        report("Could not continue toward the caller return address: " + wxString::FromUTF8(continued.error().message));
        return;
    }

    source_step_out_target_ = SourceStepOutTarget{added.value().id, process->id, *pending_event_thread_,
        document->id, document->revision, caller_frame.runtime_pc, *caller_symbol->source_location};
    pending_event_.reset();
    pending_event_thread_.reset();
    invalidate_frames();
    ++register_request_;
    refresh_state();
    refresh_breakpoints();
    refresh_threads(selected_register_thread_);
    poll_timer_.Start(100);
    report("Source step-out armed for " + wxString::FromUTF8(*caller_symbol->source_location) +
        "; waiting for the caller return address. Other stop events cancel it.");
}

void DebuggerView::step_over_event() {
    if (source_step_out_target_) {
        report(source_step_out_target_->source_step_over || source_step_out_target_->instruction_step_over
            ? "A step-over is already waiting for its destination or another stop event."
            : "A source step-out is already waiting for its caller location or another stop event.");
        return;
    }
    if (!pending_event_ || !pending_event_thread_ || !last_event_snapshot_ ||
        session_->state() != debugger::SessionState::stopped) {
        report("Step over requires a stopped event with an identifiable owner thread.");
        return;
    }
    if (selected_register_thread_ != pending_event_thread_) {
        report("Select the thread that owns the pending event before stepping over.");
        return;
    }
    // For non-call instructions, instruction step-over is exactly one
    // instruction. Keep that path in the existing backend operation.
    const auto event_kind = last_event_snapshot_->kind;
    if (event_kind != debugger::EventKind::breakpoint && event_kind != debugger::EventKind::single_step) {
        step_event();
        return;
    }

    const auto document = document_ ? document_() : nullptr;
    if (!document || !current_document(document) || !document->project || !document->project->loaded ||
        !document->project->loaded->image || !document->project->functions ||
        !document->project->derived_key || document->project->functions->key != document->project->derived_key) {
        step_event();
        return;
    }
    const auto &image = *document->project->loaded->image;
    auto target = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return std::tuple{session_->modules(), session_->process(), session_->breakpoints()};
    }();
    auto &modules = std::get<0>(target);
    const auto &process = std::get<1>(target);
    const auto &existing_breakpoints = std::get<2>(target);
    if (!process || process->id != last_event_snapshot_->process || !modules ||
        (process->architecture != Architecture::x86 && process->architecture != Architecture::x86_64 &&
         process->architecture != Architecture::arm64)) {
        step_event();
        return;
    }
    std::string mapping_reason;
    const auto mapping = debugger_image_mapping(*document, modules.value(), process->architecture, mapping_reason);
    const auto image_pc = mapping ? mapping->to_image(image, last_event_snapshot_->address) : std::nullopt;
    if (!image_pc) {
        step_event();
        return;
    }
    // Prefer a source-level stop at the next distinct line in the same
    // recovered function. The scan is deliberately capped; if source facts
    // are absent, ambiguous, or too large, the instruction-level path below
    // remains available.
    const auto current_source = symbolize_debugger_address(*document->project, image,
        last_event_snapshot_->address, mapping->runtime_base, mapping->size);
    if (current_source && current_source->function_entry && current_source->source_location) {
        const auto line_key = [](std::string_view location) {
            constexpr std::string_view inline_suffix = " (inline)";
            if (location.ends_with(inline_suffix)) location.remove_suffix(inline_suffix.size());
            const auto last = location.rfind(':');
            if (last == std::string_view::npos) return std::string(location);
            std::uint64_t column = 0;
            const auto column_text = location.substr(last + 1);
            const auto column_parse = std::from_chars(column_text.data(), column_text.data() + column_text.size(), column);
            if (column_text.empty() || column_parse.ec != std::errc{} || column_parse.ptr != column_text.data() + column_text.size())
                return std::string(location);
            const auto previous = location.rfind(':', last - 1);
            if (previous == std::string_view::npos) return std::string(location);
            std::uint64_t line = 0;
            const auto line_text = location.substr(previous + 1, last - previous - 1);
            const auto line_parse = std::from_chars(line_text.data(), line_text.data() + line_text.size(), line);
            if (line_text.empty() || line_parse.ec != std::errc{} || line_parse.ptr != line_text.data() + line_text.size())
                return std::string(location);
            return std::string(location.substr(0, last));
        };
        const auto current_line = line_key(*current_source->source_location);
        const auto function = std::find_if(document->project->functions->functions.begin(),
            document->project->functions->functions.end(), [&](const auto &candidate) {
                return candidate && candidate->entry == *current_source->function_entry;
            });
        if (function != document->project->functions->functions.end() && (*function)->complete &&
            (*function)->blocks.size() <= 4096) {
            std::unordered_map<std::uint64_t, std::shared_ptr<const BasicBlock>> blocks;
            blocks.reserve(document->project->functions->blocks.size());
            for (const auto &block : document->project->functions->blocks)
                if (block) blocks.emplace(block->id.value, block);
            std::optional<std::pair<Address, std::string>> next_source;
            std::size_t inspected = 0, line_lookups = 0;
            bool exhausted = false;
            for (const auto block_id : (*function)->blocks) {
                const auto found_block = blocks.find(block_id.value);
                if (found_block == blocks.end()) continue;
                for (const auto &candidate : found_block->second->instructions) {
                    if (++inspected > 16384) { exhausted = true; break; }
                    if (!candidate || candidate->instruction.address.space != image_pc->space ||
                        candidate->instruction.address.offset <= image_pc->offset) continue;
                    if (next_source && candidate->instruction.address.offset >= next_source->first.offset) continue;
                    if (++line_lookups > 256) { exhausted = true; break; }
                    const auto runtime = mapping->to_runtime(image, candidate->instruction.address);
                    if (!runtime) continue;
                    const auto symbol = symbolize_debugger_address(*document->project, image, *runtime,
                        mapping->runtime_base, mapping->size);
                    if (!symbol || symbol->function_entry != current_source->function_entry || !symbol->source_location ||
                        line_key(*symbol->source_location) == current_line) continue;
                    next_source = std::pair{candidate->instruction.address, *symbol->source_location};
                }
                if (exhausted) break;
            }
            if (exhausted) {
                report("Source step-over stopped at its 16,384-instruction or 256-source-location lookup bound; use instruction stepping for this function.");
                return;
            }
            if (next_source) {
                const auto runtime = mapping->to_runtime(image, next_source->first);
                if (!runtime || *runtime <= last_event_snapshot_->address) {
                    report("Source step-over destination does not round-trip through the current module mapping.");
                    return;
                }
                if (std::any_of(existing_breakpoints.begin(), existing_breakpoints.end(), [&](const auto &breakpoint) {
                        return breakpoint.address == *runtime;
                    })) {
                    report("Source step-over cannot reuse a user breakpoint at the next source line.");
                    return;
                }
                auto added = [&] {
                    std::lock_guard lock(inspection_state_->backend_mutex);
                    return session_->add_breakpoint(*runtime, debugger::BreakpointKind::software);
                }();
                if (!added) {
                    report("Could not arm source step-over at the next source line: " +
                        wxString::FromUTF8(added.error().message));
                    return;
                }
                auto one_shot = [&] {
                    std::lock_guard lock(inspection_state_->backend_mutex);
                    return session_->set_breakpoint_one_shot(added.value().id, true);
                }();
                if (!one_shot) {
                    std::lock_guard lock(inspection_state_->backend_mutex);
                    (void)session_->remove_breakpoint(added.value().id);
                    report("Could not configure the next-line breakpoint as one-shot: " +
                        wxString::FromUTF8(one_shot.error().message));
                    return;
                }
                auto continued = [&] {
                    std::lock_guard lock(inspection_state_->backend_mutex);
                    return session_->continue_thread_execution(*pending_event_, *pending_event_thread_,
                        debugger::ContinueStatus::handled);
                }();
                if (!continued) {
                    std::lock_guard lock(inspection_state_->backend_mutex);
                    (void)session_->remove_breakpoint(added.value().id);
                    report("Could not continue to the next source line: " + wxString::FromUTF8(continued.error().message));
                    return;
                }
                source_step_out_target_ = SourceStepOutTarget{added.value().id, process->id, *pending_event_thread_,
                    document->id, document->revision, *runtime, next_source->second, false, true};
                pending_event_.reset();
                pending_event_thread_.reset();
                invalidate_frames();
                ++register_request_;
                refresh_state();
                refresh_breakpoints();
                refresh_threads(selected_register_thread_);
                poll_timer_.Start(100);
                report("Source step-over armed for " + wxString::FromUTF8(next_source->second) +
                    "; another stop event cancels the operation.");
                return;
            }
        }
    }
    const auto &facts = document->project->functions->instructions;
    const auto fact = std::find_if(facts.begin(), facts.end(), [&](const auto &candidate) {
        return candidate && candidate->instruction.address == *image_pc;
    });
    if (fact == facts.end() || (*fact)->instruction.flow != FlowKind::call ||
        !(*fact)->instruction.byte_length()) {
        step_event();
        return;
    }
    const auto &instruction = (*fact)->instruction;
    if (instruction.address.offset > UINT64_MAX - instruction.byte_length()) {
        report("Step over cannot represent the address after this call instruction.");
        return;
    }
    const Address return_address{instruction.address.space,
        instruction.address.offset + instruction.byte_length()};
    const auto *return_segment = image.segment_at(return_address);
    if (!return_segment || !return_segment->executable) {
        report("Step over cannot arm a return breakpoint outside initialized executable image data.");
        return;
    }
    const auto runtime_return = mapping->to_runtime(image, return_address);
    if (!runtime_return || *runtime_return <= last_event_snapshot_->address) {
        report("Step over return address does not round-trip through the current module mapping.");
        return;
    }
    if (std::any_of(existing_breakpoints.begin(), existing_breakpoints.end(), [&](const auto &breakpoint) {
            return breakpoint.address == *runtime_return;
        })) {
        report("Step over cannot reuse a user breakpoint at the instruction after the call.");
        return;
    }

    auto added = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->add_breakpoint(*runtime_return, debugger::BreakpointKind::software);
    }();
    if (!added) {
        report("Could not arm step-over at the instruction after the call: " +
            wxString::FromUTF8(added.error().message));
        return;
    }
    auto one_shot = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->set_breakpoint_one_shot(added.value().id, true);
    }();
    if (!one_shot) {
        std::lock_guard lock(inspection_state_->backend_mutex);
        (void)session_->remove_breakpoint(added.value().id);
        report("Could not configure the call-return breakpoint as one-shot: " +
            wxString::FromUTF8(one_shot.error().message));
        return;
    }
    auto continued = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->continue_thread_execution(*pending_event_, *pending_event_thread_,
            debugger::ContinueStatus::handled);
    }();
    if (!continued) {
        std::lock_guard lock(inspection_state_->backend_mutex);
        (void)session_->remove_breakpoint(added.value().id);
        report("Could not continue to the instruction after the call: " +
            wxString::FromUTF8(continued.error().message));
        return;
    }

    source_step_out_target_ = SourceStepOutTarget{added.value().id, process->id, *pending_event_thread_,
        document->id, document->revision, *runtime_return, "instruction after call", true};
    pending_event_.reset();
    pending_event_thread_.reset();
    invalidate_frames();
    ++register_request_;
    refresh_state();
    refresh_breakpoints();
    refresh_threads(selected_register_thread_);
    poll_timer_.Start(100);
    report("Step over armed at the instruction after the call; any other stop cancels the operation.");
}

bool DebuggerView::cancel_source_step_out() {
    if (!source_step_out_target_) return true;
    const auto target = *source_step_out_target_;
    std::optional<Error> cleanup_error;
    {
        std::lock_guard lock(inspection_state_->backend_mutex);
        const auto process = session_->process();
        const auto state = session_->state();
        if (process && process->id == target.process &&
            (state == debugger::SessionState::running || state == debugger::SessionState::stopped)) {
            const auto removed = session_->remove_breakpoint(target.breakpoint);
            if (!removed) cleanup_error = removed.error();
        }
    }
    if (cleanup_error) {
        report((target.source_step_over || target.instruction_step_over
            ? "Could not remove the temporary step-over breakpoint: "
            : "Could not remove the temporary source step-out breakpoint: ") +
            wxString::FromUTF8(cleanup_error->message));
        return false;
    }
    source_step_out_target_.reset();
    refresh_breakpoints();
    return true;
}

void DebuggerView::refresh_breakpoints() {
    const auto selected_row = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    const auto selected_id = selected_row >= 0 && static_cast<std::size_t>(selected_row) < visible_breakpoint_rows_.size()
        ? std::optional{breakpoints_[visible_breakpoint_rows_[static_cast<std::size_t>(selected_row)]].id} : std::nullopt;
    {
        std::lock_guard lock(inspection_state_->backend_mutex);
        breakpoints_ = session_->breakpoints();
    }
    render_breakpoints(selected_id);
}

void DebuggerView::render_breakpoints(std::optional<debugger::BreakpointId> preferred) {
    breakpoints_view_->DeleteAllItems();
    visible_breakpoint_rows_.clear();
    const auto query = breakpoint_filter_->GetValue().Lower().Trim(true).Trim(false);
    const auto document = document_ ? document_() : nullptr;
    std::optional<DebuggerImageMapping> symbol_mapping;
    const Image *symbol_image = nullptr;
    Architecture process_architecture = Architecture::unknown;
    const auto process_row = processes_choice_ ? processes_choice_->GetSelection() : wxNOT_FOUND;
    if (process_row >= 0 && static_cast<std::size_t>(process_row) < visible_processes_.size())
        process_architecture = visible_processes_[static_cast<std::size_t>(process_row)].architecture;
    if (document && document->project && document->project->loaded && document->project->loaded->image &&
        process_architecture != Architecture::unknown && !modules_.empty()) {
        symbol_image = document->project->loaded->image.get();
        std::string mapping_reason;
        symbol_mapping = debugger_image_mapping(*document, modules_, process_architecture, mapping_reason);
    }
    std::vector<std::size_t> order;
    order.reserve(breakpoints_.size());
    for (std::size_t index = 0; index < breakpoints_.size(); ++index) order.push_back(index);
    const auto sort_mode = breakpoint_sort_->GetSelection();
    if (sort_mode == 1) {
        std::stable_sort(order.begin(), order.end(), [&](std::size_t left, std::size_t right) {
            if (breakpoints_[left].address != breakpoints_[right].address)
                return breakpoints_[left].address < breakpoints_[right].address;
            return breakpoints_[left].id < breakpoints_[right].id;
        });
    } else if (sort_mode == 2) {
        std::stable_sort(order.begin(), order.end(), [&](std::size_t left, std::size_t right) {
            if (breakpoints_[left].hit_count != breakpoints_[right].hit_count)
                return breakpoints_[left].hit_count > breakpoints_[right].hit_count;
            return breakpoints_[left].id < breakpoints_[right].id;
        });
    } else if (sort_mode == 3) {
        std::stable_sort(order.begin(), order.end(), [&](std::size_t left, std::size_t right) {
            if (breakpoints_[left].ignore_count != breakpoints_[right].ignore_count)
                return breakpoints_[left].ignore_count > breakpoints_[right].ignore_count;
            return breakpoints_[left].id < breakpoints_[right].id;
        });
    }
    for (const auto index : order) {
        const auto &breakpoint = breakpoints_[index];
        if (breakpoint_enabled_only_->GetValue() && !breakpoint.enabled) continue;
        const auto row = breakpoints_view_->InsertItem(breakpoints_view_->GetItemCount(),
            wxString::Format("%llu", static_cast<unsigned long long>(breakpoint.id)));
        auto address = wxString::Format("0x%llX", static_cast<unsigned long long>(breakpoint.address));
        if (symbol_mapping && symbol_image && document->project) {
            if (const auto symbol = symbolize_debugger_address(*document->project, *symbol_image,
                    breakpoint.address, symbol_mapping->runtime_base, symbol_mapping->size); symbol && !symbol->name.empty()) {
                address += " (";
                address += wxString::FromUTF8(symbol->name);
                if (symbol->displacement)
                    address += wxString::Format("+0x%llX", static_cast<unsigned long long>(symbol->displacement));
                if (symbol->source_location) {
                    address += " @ ";
                    address += wxString::FromUTF8(*symbol->source_location);
                }
                address += ")";
            }
        }
        breakpoints_view_->SetItem(row, 1, address);
        const char *kind_name = breakpoint.kind == debugger::BreakpointKind::software ? "software" :
                                breakpoint.kind == debugger::BreakpointKind::execute ? "hardware execute" :
                                breakpoint.kind == debugger::BreakpointKind::read ? "hardware read" :
                                breakpoint.kind == debugger::BreakpointKind::write ? "hardware write" : "hardware access";
        auto description = wxString::FromUTF8(kind_name);
        if (breakpoint.kind != debugger::BreakpointKind::software)
            description += wxString::Format(" (%u byte%s)", static_cast<unsigned>(breakpoint.size),
                                             breakpoint.size == 1 ? "" : "s");
        breakpoints_view_->SetItem(row, 2, description);
        breakpoints_view_->SetItem(row, 3, breakpoint.enabled ? "yes" : "no");
        breakpoints_view_->SetItem(row, 4, wxString::Format("%llu", static_cast<unsigned long long>(breakpoint.hit_count)));
        breakpoints_view_->SetItem(row, 5, wxString::Format("%llu", static_cast<unsigned long long>(breakpoint.ignore_count)));
        wxString rule = breakpoint.condition.empty() ? wxString("always") : wxString::FromUTF8(breakpoint.condition);
        if (breakpoint.logpoint)
            rule = rule == "always" ? wxString("logpoint") : rule + " + logpoint";
        const auto enabled = breakpoint.enabled ? wxString("yes") : wxString("no");
        const auto hits = wxString::Format("%llu", static_cast<unsigned long long>(breakpoint.hit_count));
        const auto ignore = wxString::Format("%llu", static_cast<unsigned long long>(breakpoint.ignore_count));
        const auto one_shot = breakpoint.one_shot ? wxString("yes") : wxString("no");
        wxString searchable = wxString::Format("%llu", static_cast<unsigned long long>(breakpoint.id)) + " " +
            address + " " + description + " " + enabled + " " + hits + " " + ignore + " " + rule + " " + one_shot;
        if (!query.empty() && searchable.Lower().Find(query) == wxNOT_FOUND) {
            breakpoints_view_->DeleteItem(row);
            continue;
        }
        breakpoints_view_->SetItem(row, 6, rule);
        breakpoints_view_->SetItem(row, 7, one_shot);
        breakpoints_view_->SetItem(row, 3, enabled);
        breakpoints_view_->SetItem(row, 4, hits);
        breakpoints_view_->SetItem(row, 5, ignore);
        visible_breakpoint_rows_.push_back(index);
        if (preferred && breakpoint.id == *preferred)
            breakpoints_view_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    }
    breakpoint_filter_status_->SetLabel(wxString::Format("%llu of %llu breakpoints",
        static_cast<unsigned long long>(visible_breakpoint_rows_.size()),
        static_cast<unsigned long long>(breakpoints_.size())));
}

void DebuggerView::add_breakpoint() {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(breakpoint_address_->GetValue()), address)) {
        report("Enter a valid breakpoint address (decimal or 0x-prefixed hexadecimal)."); return;
    }
    const int selected_kind = breakpoint_kind_->GetSelection();
    const int selected_size = breakpoint_size_->GetSelection();
    constexpr std::uint8_t watch_sizes[] = {1, 2, 4, 8};
    const auto size = selected_size >= 0 && selected_size < 4 ? watch_sizes[selected_size] : std::uint8_t{1};
    debugger::BreakpointKind kind = debugger::BreakpointKind::software;
    switch (selected_kind) {
    case 1: kind = debugger::BreakpointKind::execute; break;
    case 2: kind = debugger::BreakpointKind::read; break;
    case 3: kind = debugger::BreakpointKind::write; break;
    case 4: kind = debugger::BreakpointKind::access; break;
    default: break;
    }
    const auto condition = narrow(breakpoint_condition_->GetValue());
    const bool logpoint = breakpoint_logpoint_->GetValue();
    const auto log_message = narrow(breakpoint_log_message_->GetValue());
    std::uint64_t ignore_count = 0;
    if (!parse_unsigned(narrow(breakpoint_ignore_count_->GetValue()), ignore_count)) {
        report("Ignore count must be an unsigned decimal or 0x-prefixed integer."); return;
    }
    if (condition.size() > 256 || log_message.size() > 1024) {
        report("Breakpoint conditions are limited to 256 bytes and log messages to 1024 bytes."); return;
    }
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        auto added = session_->add_breakpoint(address, kind, size);
        if (!added) return added;
        if (!condition.empty()) { auto configured=session_->set_breakpoint_condition(added.value().id, condition); if(!configured) { (void)session_->remove_breakpoint(added.value().id); return Result<debugger::Breakpoint>(configured.error()); } }
        if (logpoint) { auto configured=session_->set_breakpoint_logpoint(added.value().id, true, log_message); if(!configured) { (void)session_->remove_breakpoint(added.value().id); return Result<debugger::Breakpoint>(configured.error()); } }
        if (ignore_count) { auto configured=session_->set_breakpoint_ignore_count(added.value().id, ignore_count); if(!configured) { (void)session_->remove_breakpoint(added.value().id); return Result<debugger::Breakpoint>(configured.error()); } }
        if (breakpoint_one_shot_->GetValue()) { auto configured=session_->set_breakpoint_one_shot(added.value().id, true); if(!configured) { (void)session_->remove_breakpoint(added.value().id); return Result<debugger::Breakpoint>(configured.error()); } }
        const auto configured=session_->breakpoints();
        auto found=std::find_if(configured.begin(),configured.end(),[&](const auto& bp){return bp.id==added.value().id;});
        return found==configured.end()?added:Result<debugger::Breakpoint>(*found);
    }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    const auto breakpoint = result.value();
    if (submit_ && document_) {
        auto current=document_();
        std::string reason;
        if(current && current->project && current->project->loaded && current->project->loaded->image &&
           current->project->state) {
            auto target=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return std::pair{session_->modules(),session_->process()};}();
            auto mapping=target.first?debugger_image_mapping(*current,target.first.value(),target.second?target.second->architecture:Architecture::unknown,reason):std::nullopt;
            auto image_address=mapping?mapping->to_image(*current->project->loaded->image,address):std::nullopt;
            if(image_address) {
                submit_(SetProjectBreakpoint{*image_address,static_cast<database::ProjectBreakpointKind>(kind),size,true,false,condition,logpoint,log_message,ignore_count,breakpoint.one_shot});
                report(wxString::Format("Breakpoint and rule saved at project address 0x%llX.",static_cast<unsigned long long>(image_address->offset)));
            } else report("Breakpoint added to this session only; the active module mapping does not identify the project image.");
        } else report("Breakpoint added to this session only; no verified project image mapping is available.");
    }
    refresh_breakpoints();
    const char *kind_name = breakpoint.kind == debugger::BreakpointKind::software ? "software" :
                            breakpoint.kind == debugger::BreakpointKind::execute ? "hardware execute" :
                            breakpoint.kind == debugger::BreakpointKind::read ? "hardware read" :
                            breakpoint.kind == debugger::BreakpointKind::write ? "hardware write" : "hardware access";
    auto description = wxString::FromUTF8(kind_name);
    if (breakpoint.kind != debugger::BreakpointKind::software)
        description += wxString::Format(" (%u byte%s)", static_cast<unsigned>(breakpoint.size),
                                        breakpoint.size == 1 ? "" : "s");
    if (logpoint) description += " · logpoint";
    report(description + " breakpoint added.");
}

void DebuggerView::load_breakpoint_rule() {
    const auto selected = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible_breakpoint_rows_.size()) {
        report("Select a breakpoint before loading its rule.");
        return;
    }
    const auto source_row = visible_breakpoint_rows_[static_cast<std::size_t>(selected)];
    if (source_row >= breakpoints_.size()) {
        report("The selected breakpoint is no longer available; refresh the list.");
        return;
    }
    const auto &breakpoint = breakpoints_[source_row];
    breakpoint_condition_->ChangeValue(wxString::FromUTF8(breakpoint.condition));
    breakpoint_logpoint_->SetValue(breakpoint.logpoint);
    breakpoint_log_message_->ChangeValue(wxString::FromUTF8(breakpoint.log_message));
    breakpoint_ignore_count_->ChangeValue(wxString::Format("%llu",
        static_cast<unsigned long long>(breakpoint.ignore_count)));
    breakpoint_one_shot_->SetValue(breakpoint.one_shot);
    report(wxString::Format("Loaded rule settings from breakpoint %llu into the editor.",
        static_cast<unsigned long long>(breakpoint.id)));
}

void DebuggerView::save_breakpoint_rule() {
    const auto selected = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible_breakpoint_rows_.size()) {
        report("Select a breakpoint before saving its rule."); return;
    }
    const auto source_row = visible_breakpoint_rows_[static_cast<std::size_t>(selected)];
    if (source_row >= breakpoints_.size()) {
        report("The selected breakpoint is no longer available; refresh the list.");
        return;
    }
    const auto condition = narrow(breakpoint_condition_->GetValue());
    const auto message = narrow(breakpoint_log_message_->GetValue());
    std::uint64_t ignore_count = 0;
    if (condition.size() > 256 || message.size() > 1024 ||
        !parse_unsigned(narrow(breakpoint_ignore_count_->GetValue()), ignore_count)) {
        report("Rule is invalid: condition/message limits are 256/1024 bytes and ignore count must be an unsigned integer."); return;
    }
    auto breakpoint = breakpoints_[source_row];
    const bool logpoint = breakpoint_logpoint_->GetValue();
    const bool one_shot = breakpoint_one_shot_->GetValue();
    auto configured = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->configure_breakpoint_rule(breakpoint.id, condition, logpoint, message, ignore_count, one_shot);
    }();
    if (!configured) { report(wxString::FromUTF8(configured.error().message)); return; }
    refresh_breakpoints();
    if (document_ && submit_) {
        const auto current = document_();
        std::string reason;
        if (current && current->project && current->project->loaded && current->project->loaded->image && current->project->state) {
            auto target = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return std::pair{session_->modules(), session_->process()}; }();
            auto mapping = target.first ? debugger_image_mapping(*current, target.first.value(), target.second ? target.second->architecture : Architecture::unknown, reason) : std::nullopt;
            auto address = mapping ? mapping->to_image(*current->project->loaded->image, breakpoint.address) : std::nullopt;
            if (address) {
                submit_(SetProjectBreakpoint{*address, static_cast<database::ProjectBreakpointKind>(breakpoint.kind), breakpoint.size, breakpoint.enabled, false, condition, logpoint, message, ignore_count, one_shot});
                report("Breakpoint rule saved to the project. Hit counts are saved with the project outside undo history.");
                return;
            }
        }
    }
    report("Rule applied to this debug session; no verified project image mapping is available to save it.");
}

void DebuggerView::persist_project_breakpoint_hit_counts() {
    if (!persist_hit_counts_ || !document_) return;
    const auto current = document_();
    if (!current || !current->project || !current->project->loaded || !current->project->loaded->image ||
        !current->project->state || !current->project->state->user ||
        current->project->mode == database::ProjectMode::read_only ||
        current->project->state->user->breakpoints.empty()) return;

    auto target = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return std::pair{session_->modules(), session_->process()};
    }();
    if (!target.first) return;
    std::string reason;
    auto mapping = debugger_image_mapping(*current, target.first.value(),
        target.second ? target.second->architecture : Architecture::unknown, reason);
    if (!mapping) return;
    const auto runtime_breakpoints = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->breakpoints();
    }();

    std::vector<database::BreakpointHitCount> changed;
    for (const auto &saved : current->project->state->user->breakpoints) {
        const auto runtime = mapping->to_runtime(*current->project->loaded->image, saved.address);
        if (!runtime) continue;
        const auto live = std::find_if(runtime_breakpoints.begin(), runtime_breakpoints.end(), [&](const auto &item) {
            return item.address == *runtime && static_cast<unsigned>(item.kind) == static_cast<unsigned>(saved.kind);
        });
        if (live == runtime_breakpoints.end()) continue;
        const auto cached = queued_hit_counts_.find(saved.id);
        const auto previous = cached == queued_hit_counts_.end() ? saved.hit_count : cached->second;
        if (live->hit_count != previous) changed.push_back({saved.id, live->hit_count});
    }
    if (!changed.empty() && persist_hit_counts_(changed))
        for (const auto &counter : changed) queued_hit_counts_[counter.id] = counter.hit_count;
}

void DebuggerView::apply_project_breakpoints() {
    if (!document_) { report("Open a project before applying project breakpoints."); return; }
    const auto current=document_();
    if (!current || !current->project || !current->project->loaded || !current->project->loaded->image ||
        !current->project->state || !current->project->state->user) {
        report("Project breakpoints cannot be applied until the active project image is loaded."); return;
    }
    if (!pending_event_ && session_->state()!=debugger::SessionState::stopped) {
        report("Stop the target before applying project breakpoints."); return;
    }
    std::string reason;
    auto target=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return std::pair{session_->modules(),session_->process()};}();
    auto mapping=target.first?debugger_image_mapping(*current,target.first.value(),target.second?target.second->architecture:Architecture::unknown,reason):std::nullopt;
    if (!mapping) { report(wxString::FromUTF8(reason)); return; }
    std::size_t applied=0, skipped=0;
    for (const auto &saved: current->project->state->user->breakpoints) {
        const auto runtime=mapping->to_runtime(*current->project->loaded->image,saved.address);
        if (!runtime) { ++skipped; continue; }
        const auto duplicate=std::find_if(breakpoints_.begin(),breakpoints_.end(),[&](const auto& item){return item.address==*runtime && item.kind==static_cast<debugger::BreakpointKind>(saved.kind);});
        if (duplicate!=breakpoints_.end()) continue;
        auto added=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return session_->add_breakpoint(*runtime,static_cast<debugger::BreakpointKind>(saved.kind),saved.size);}();
        if (!added) { ++skipped; continue; }
        auto row=added.value();
        auto counter_status = [&] {
            std::lock_guard lock(inspection_state_->backend_mutex);
            return session_->set_breakpoint_hit_count(row.id, saved.hit_count);
        }();
        if (!counter_status) { std::lock_guard lock(inspection_state_->backend_mutex); (void)session_->remove_breakpoint(row.id); ++skipped; continue; }
        auto rule_status = [&] {
            std::lock_guard lock(inspection_state_->backend_mutex);
            return session_->configure_breakpoint_rule(row.id, saved.condition, saved.logpoint,
                saved.log_message, saved.ignore_count, saved.one_shot);
        }();
        if (!rule_status) { std::lock_guard lock(inspection_state_->backend_mutex); (void)session_->remove_breakpoint(row.id); ++skipped; continue; }
        const auto configured_rows = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->breakpoints(); }();
        if (const auto configured = std::find_if(configured_rows.begin(), configured_rows.end(), [&](const auto &bp) { return bp.id == row.id; }); configured != configured_rows.end()) row = *configured;
        if (!saved.enabled) {
            auto disabled=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return session_->set_breakpoint_enabled(row.id,false);}();
            if (!disabled) { std::lock_guard lock(inspection_state_->backend_mutex); const auto removed=session_->remove_breakpoint(row.id); (void)removed; ++skipped; continue; }
            row.enabled=false;
        }
        breakpoints_.push_back(row);
        ++applied;
    }
    refresh_breakpoints();
    report(wxString::Format("Applied %llu project breakpoint(s); %llu were skipped because they were unmapped or unsupported. Saved project addresses were not changed.",static_cast<unsigned long long>(applied),static_cast<unsigned long long>(skipped)));
}

void DebuggerView::remove_breakpoint() {
    const auto row = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_breakpoint_rows_.size()) {
        report("Select a breakpoint to remove."); return;
    }
    const auto source_row = visible_breakpoint_rows_[static_cast<std::size_t>(row)];
    const auto breakpoint = breakpoints_[source_row];
    const bool source_step_out = source_step_out_target_ && source_step_out_target_->breakpoint == breakpoint.id;
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->remove_breakpoint(breakpoint.id); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    if (source_step_out) source_step_out_target_.reset();
    breakpoints_.erase(breakpoints_.begin() + static_cast<std::ptrdiff_t>(source_row));
    render_breakpoints();
    if (!source_step_out && submit_ && document_) {
        auto current=document_();
        if(current && current->project && current->project->loaded && current->project->loaded->image && current->project->state) {
            auto target=[&]{std::lock_guard lock(inspection_state_->backend_mutex);return std::pair{session_->modules(),session_->process()};}();
            std::string reason;
            auto mapping=target.first?debugger_image_mapping(*current,target.first.value(),target.second?target.second->architecture:Architecture::unknown,reason):std::nullopt;
            auto address=mapping?mapping->to_image(*current->project->loaded->image,breakpoint.address):std::nullopt;
            if(address)submit_(SetProjectBreakpoint{*address,static_cast<database::ProjectBreakpointKind>(breakpoint.kind),breakpoint.size,true,true});
        }
    }
    report("Breakpoint removed.");
}

void DebuggerView::toggle_breakpoint_enabled() {
    const auto row = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_breakpoint_rows_.size()) {
        report("Select a breakpoint to enable or disable."); return;
    }
    auto breakpoint = breakpoints_[visible_breakpoint_rows_[static_cast<std::size_t>(row)]];
    const bool source_step_out = source_step_out_target_ && source_step_out_target_->breakpoint == breakpoint.id;
    if (source_step_out) {
        report("Remove the temporary source step-out breakpoint to cancel it; its one-shot behavior cannot be changed.");
        return;
    }
    const bool enabled = !breakpoint.enabled;
    auto result = [&] {
        std::lock_guard lock(inspection_state_->backend_mutex);
        return session_->set_breakpoint_enabled(breakpoint.id, enabled);
    }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    breakpoint.enabled = enabled;
    refresh_breakpoints();

    if (submit_ && document_) {
        const auto current = document_();
        if (current && current->project && current->project->loaded && current->project->loaded->image) {
            auto target = [&] {
                std::lock_guard lock(inspection_state_->backend_mutex);
                return std::pair{session_->modules(), session_->process()};
            }();
            std::string reason;
            auto mapping = target.first ? debugger_image_mapping(*current, target.first.value(),
                target.second ? target.second->architecture : Architecture::unknown, reason) : std::nullopt;
            const auto address = mapping ? mapping->to_image(*current->project->loaded->image, breakpoint.address) : std::nullopt;
            if (address) submit_(SetProjectBreakpoint{*address,
                static_cast<database::ProjectBreakpointKind>(breakpoint.kind), breakpoint.size, enabled, false,
                breakpoint.condition, breakpoint.logpoint, breakpoint.log_message, breakpoint.ignore_count,
                breakpoint.one_shot});
        }
    }
    report(enabled ? "Breakpoint enabled." : "Breakpoint disabled.");
}

void DebuggerView::copy_visible_breakpoints() {
    const auto count = breakpoints_view_->GetItemCount();
    if (count == 0) {
        report("There are no visible breakpoints to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    std::string text = "Id\tAddress\tKind\tEnabled\tHits\tIgnore count\tRule\tOne-shot\r\n";
    bool too_large = text.size() > max_copy_bytes;
    for (long row = 0; row < count && !too_large; ++row) {
        std::string line;
        for (int column = 0; column < 8; ++column) {
            if (column) line.push_back('\t');
            line += os_data_cell(narrow(breakpoints_view_->GetItemText(row, column)));
        }
        line += "\r\n";
        if (line.size() > max_copy_bytes - std::min(text.size(), max_copy_bytes)) {
            too_large = true;
            break;
        }
        text += line;
    }
    if (too_large) {
        report("Visible breakpoints exceed the 1 MiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(text)));
    wxTheClipboard->Close();
    report(copied ? wxString::Format("Copied %llu visible breakpoint(s) as TSV.",
        static_cast<unsigned long long>(count)) : wxString("Could not copy visible breakpoints."));
}

void DebuggerView::refresh_threads(std::optional<debugger::ThreadId> preferred) {
    if (!preferred && selected_register_thread_) preferred = selected_register_thread_;
    const auto generation = session_generation_;
    const auto stop_generation = inspection_state_->stop_generation.load(std::memory_order_acquire);
    const auto selection_generation = thread_selection_generation_;
    const auto request = ++thread_request_;
    const bool target_exited = session_->state() == debugger::SessionState::exited;
    auto session = session_;
    auto state = inspection_state_;
    enqueue_inspection(0, [session, state, generation, stop_generation, selection_generation,
                           request, preferred, target_exited] {
        auto [result, run_states] = [&] {
            std::lock_guard backend_lock(state->backend_mutex);
            return std::pair{session->threads(), session->thread_run_states()};
        }();
        std::vector<debugger::ThreadInfo> values;
        std::string error;
        if (result) values = std::move(result.value());
        else if (!run_states) error = result.error().message;
        if (run_states) {
            for (const auto &snapshot : run_states.value()) {
                const auto found = std::find_if(values.begin(), values.end(), [&](const auto &thread) {
                    return thread.id == snapshot.thread;
                });
                if (found != values.end()) found->state = snapshot.state;
                else values.push_back({snapshot.thread, "thread " + std::to_string(snapshot.thread), snapshot.state});
            }
        } else if (run_states.error().code != ErrorCode::unsupported && error.empty()) {
            error = run_states.error().message;
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, stop_generation, selection_generation,
                request, preferred, target_exited, values = std::move(values),
                run_states_supported = static_cast<bool>(run_states), error = std::move(error)]() mutable {
            std::unique_lock lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->thread_request_ != request ||
                state->stop_generation.load(std::memory_order_acquire) != stop_generation) return;
            if (view->thread_selection_generation_ != selection_generation) {
                const auto current_selection = view->selected_register_thread_;
                lock.unlock();
                view->refresh_threads(current_selection);
                return;
            }
            if (values.empty() && !target_exited) {
                // An empty or unavailable run-state snapshot cannot prove the
                // session has no threads. Keep the last usable list intact.
                if (error.empty()) view->report("Thread snapshot is empty; retained the last usable thread list.");
                else view->report(wxString::FromUTF8(error));
                return;
            }
            if (!error.empty()) view->report(wxString::FromUTF8(error));
            view->thread_run_states_supported_ = run_states_supported;
            view->threads_ = std::move(values);
            view->thread_schedule_snapshot_event_ = run_states_supported && view->pending_event_
                ? view->pending_event_ : std::nullopt;
            view->registers_view_->DeleteAllItems();
            const auto row = view->render_threads(preferred);
            view->update_thread_schedule_controls();
            lock.unlock();
            view->refresh_registers(row.value_or(view->threads_.size()));
        });
    });
}

std::optional<std::size_t> DebuggerView::render_threads(std::optional<debugger::ThreadId> preferred) {
    threads_view_->DeleteAllItems();
    visible_thread_rows_.clear();
    const auto query = lower_register_text(narrow(thread_filter_->GetValue()));
    for (std::size_t i = 0; i < threads_.size(); ++i) {
        const auto &thread = threads_[i];
        const char *thread_state = thread.state == debugger::ThreadState::running ? "running" :
            thread.state == debugger::ThreadState::stopped ? "stopped" :
            thread.state == debugger::ThreadState::exited ? "exited" : "unknown";
        const auto state_filter = thread_state_filter_->GetSelection();
        if ((state_filter == 1 && thread.state != debugger::ThreadState::stopped) ||
            (state_filter == 2 && thread.state != debugger::ThreadState::running) ||
            (state_filter == 3 && thread.state != debugger::ThreadState::exited) ||
            (state_filter == 4 && thread.state != debugger::ThreadState::unknown)) continue;
        const auto core = thread.core ? std::to_string(*thread.core) : std::string{};
        const auto last_event = thread_last_events_.find(thread.id);
        const auto event_summary = last_event == thread_last_events_.end() ? std::string{} : last_event->second.second;
        const auto searchable = lower_register_text(std::to_string(thread.id) + " " + thread.name + " " +
            thread_state + " " + core + " " + thread.native_state + " " + event_summary);
        if (!query.empty() && searchable.find(query) == std::string::npos) continue;
        visible_thread_rows_.push_back(i);
    }
    const auto sort_mode = thread_sort_->GetSelection();
    std::stable_sort(visible_thread_rows_.begin(), visible_thread_rows_.end(), [&](std::size_t left_index, std::size_t right_index) {
        const auto &left = threads_[left_index];
        const auto &right = threads_[right_index];
        if (sort_mode == 1) {
            const auto left_name = lower_register_text(left.name);
            const auto right_name = lower_register_text(right.name);
            if (left_name != right_name) return left_name < right_name;
        } else if (sort_mode == 2) {
            const auto left_state = static_cast<unsigned>(left.state);
            const auto right_state = static_cast<unsigned>(right.state);
            if (left_state != right_state) return left_state < right_state;
        } else if (sort_mode == 3 && left.core != right.core) {
            if (!left.core) return false;
            if (!right.core) return true;
            return *left.core < *right.core;
        } else if (sort_mode == 4) {
            const auto left_event = thread_last_events_.find(left.id);
            const auto right_event = thread_last_events_.find(right.id);
            const auto left_sequence = left_event == thread_last_events_.end() ? 0 : left_event->second.first;
            const auto right_sequence = right_event == thread_last_events_.end() ? 0 : right_event->second.first;
            if (left_sequence != right_sequence) return left_sequence > right_sequence;
        }
        return left.id < right.id;
    });
    for (const auto i : visible_thread_rows_) {
        const auto &thread = threads_[i];
        const char *thread_state = thread.state == debugger::ThreadState::running ? "running" :
            thread.state == debugger::ThreadState::stopped ? "stopped" :
            thread.state == debugger::ThreadState::exited ? "exited" : "unknown";
        const auto row = threads_view_->InsertItem(threads_view_->GetItemCount(),
            wxString::Format("%llu", static_cast<unsigned long long>(thread.id)));
        threads_view_->SetItem(row, 1, wxString::FromUTF8(thread.name));
        threads_view_->SetItem(row, 2, thread_state);
        threads_view_->SetItem(row, 3, thread.core
            ? wxString::Format("%u", static_cast<unsigned>(*thread.core)) : wxString{});
        threads_view_->SetItem(row, 4, wxString::FromUTF8(thread.native_state));
        const auto last_event = thread_last_events_.find(thread.id);
        if (last_event != thread_last_events_.end()) threads_view_->SetItem(row, 5, wxString::FromUTF8(last_event->second.second));
    }
    thread_filter_status_->SetLabel(wxString::Format("%llu of %llu threads",
        static_cast<unsigned long long>(visible_thread_rows_.size()), static_cast<unsigned long long>(threads_.size())));
    copy_thread_button_->Enable(!visible_thread_rows_.empty());
    auto selected = visible_thread_rows_.end();
    if (preferred) selected = std::find_if(visible_thread_rows_.begin(), visible_thread_rows_.end(), [&](std::size_t index) {
        return threads_[index].id == *preferred;
    });
    if (selected == visible_thread_rows_.end()) selected = std::find_if(visible_thread_rows_.begin(), visible_thread_rows_.end(),
        [&](std::size_t index) { return threads_[index].state != debugger::ThreadState::exited; });
    if (selected == visible_thread_rows_.end()) selected = visible_thread_rows_.begin();
    if (selected == visible_thread_rows_.end()) return {};
    const auto visible_row = static_cast<long>(std::distance(visible_thread_rows_.begin(), selected));
    threads_view_->SetItemState(visible_row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    return *selected;
}

void DebuggerView::refresh_registers(std::size_t row) {
    ++thread_selection_generation_;
    invalidate_frames();
    registers_view_->DeleteAllItems();
    registers_.clear(); register_changes_.clear(); visible_register_rows_.clear();
    register_filter_status_->SetLabel("0 of 0 registers");
    selected_register_thread_.reset(); selected_register_index_.reset();
    register_value_->Clear();
    register_value_->Disable();
    if (row >= threads_.size()) {
        update_thread_selection_summary();
        refresh_watches(); return;
    }
    const auto thread = threads_[row].id;
    selected_register_thread_ = thread;
    update_thread_selection_summary();
    if (threads_[row].state == debugger::ThreadState::running ||
        threads_[row].state == debugger::ThreadState::exited) { refresh_watches(); return; }
    const auto generation = session_generation_;
    const auto request = ++register_request_;
    auto session = session_;
    auto state = inspection_state_;
    enqueue_inspection(1, [session, state, thread, generation, request] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->read_registers(thread);
        std::vector<debugger::RegisterValue> values;
        std::string error;
        if (result) values = std::move(result.value()); else error = result.error().message;
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, thread,
                values = std::move(values), error = std::move(error)]() mutable {
            std::unique_lock lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->register_request_ != request ||
                view->selected_register_thread_ != thread) return;
            if (!error.empty()) {
                view->report(wxString::FromUTF8(error));
                lock.unlock();
                view->refresh_watches();
                return;
            }
            constexpr std::size_t max_register_rows = 1024;
            constexpr std::size_t max_register_bytes = 512;
            constexpr std::size_t max_register_display_bytes = 1024 * 1024;
            std::size_t display_bytes = 0;
            bool bounded = values.size() <= max_register_rows;
            for (const auto &reg : values) {
                if (reg.name.size() > 256 || reg.group.size() > 256 || reg.target_architecture.size() > 256 ||
                    reg.type.size() > 256 || reg.bytes.size() > max_register_bytes) {
                    bounded = false;
                    break;
                }
                const auto value_bytes = reg.available ? reg.bytes.size() * 2 + 2 : std::size_t{11};
                const auto remaining = max_register_display_bytes - display_bytes;
                if (reg.name.size() > remaining || remaining - reg.name.size() < 4 ||
                    value_bytes > remaining - reg.name.size() - 4) {
                    bounded = false;
                    break;
                }
                display_bytes += reg.name.size() + value_bytes + 4;
            }
            if (!bounded) {
                view->report("Register snapshot exceeds the 1024-row, 512-byte-per-register, or 1 MiB display limit.");
                lock.unlock();
                view->refresh_watches();
                return;
            }
            view->registers_ = std::move(values);
            const bool have_pinned_baseline = view->pinned_register_thread_ == thread;
            const auto &baseline = have_pinned_baseline ? view->pinned_registers_ : view->previous_registers_;
            const bool have_previous = have_pinned_baseline || view->previous_register_thread_ == thread;
            view->register_changes_.clear();
            view->register_changes_.reserve(view->registers_.size());
            for (const auto &reg : view->registers_) {
                const auto previous = have_previous
                    ? std::find_if(baseline.begin(), baseline.end(),
                        [&](const auto &candidate) {
                            return candidate.number == reg.number && candidate.name == reg.name &&
                                candidate.group == reg.group;
                        })
                    : baseline.end();
                const char *change = !have_previous ? "Baseline" :
                    previous == baseline.end() ? "New" :
                    previous->available != reg.available ? "Changed" :
                    !reg.available ? "Unavailable" : previous->bytes == reg.bytes ? "Same" : "Changed";
                view->register_changes_.emplace_back(change);
            }
            view->previous_register_thread_ = thread;
            view->previous_registers_ = view->registers_;
            view->selected_locals_frame_ = 0;
            view->render_registers();
            lock.unlock();
            view->refresh_locals();
            view->refresh_watches();
        });
    });
}

void DebuggerView::render_registers() {
    registers_view_->DeleteAllItems();
    visible_register_rows_.clear();
    const auto query = lower_register_text(narrow(register_filter_->GetValue()));
    const auto value_format = register_value_format_ ? register_value_format_->GetSelection() : 0;
    for (std::size_t i = 0; i < registers_.size(); ++i) {
        const auto &reg = registers_[i];
        const auto bank = register_bank_label(reg);
        const auto value = register_display_value(reg, value_format);
        const auto change = i < register_changes_.size() ? register_changes_[i] : std::string{};
        if (register_changed_only_->GetValue() && change != "Changed" && change != "New") continue;
        const auto searchable = lower_register_text(reg.name + " " + bank + " " + value + " " + change);
        if (!query.empty() && searchable.find(query) == std::string::npos) continue;
        const auto row = registers_view_->InsertItem(registers_view_->GetItemCount(), wxString::FromUTF8(reg.name));
        registers_view_->SetItem(row, 1, wxString::FromUTF8(bank));
        registers_view_->SetItem(row, 2, wxString::FromUTF8(value));
        registers_view_->SetItem(row, 3, wxString::FromUTF8(change));
        visible_register_rows_.push_back(i);
    }
    register_filter_status_->SetLabel(wxString::Format("%llu of %llu registers",
        static_cast<unsigned long long>(visible_register_rows_.size()), static_cast<unsigned long long>(registers_.size())));
    if (copy_visible_registers_)
        copy_visible_registers_->Enable(selected_register_thread_.has_value() && !visible_register_rows_.empty());
    if (selected_register_index_) {
        const auto found = std::find(visible_register_rows_.begin(), visible_register_rows_.end(), *selected_register_index_);
        if (found != visible_register_rows_.end()) {
            const auto row = static_cast<long>(std::distance(visible_register_rows_.begin(), found));
            registers_view_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            const auto &reg = registers_[*selected_register_index_];
            register_value_->SetValue(wxString::FromUTF8(register_hex(reg)));
            register_value_->Enable(reg.available);
            return;
        }
        selected_register_index_.reset();
    }
    register_value_->Clear();
    register_value_->Disable();
}

void DebuggerView::toggle_register_baseline() {
    if (pinned_register_thread_) {
        const auto cleared_thread = *pinned_register_thread_;
        pinned_register_thread_.reset();
        pinned_registers_.clear();
        register_baseline_button_->SetLabel("Pin baseline");
        register_baseline_button_->SetToolTip("Compare future register snapshots with the selected thread's current values.");
        if (selected_register_thread_) {
            const auto row = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
                return thread.id == *selected_register_thread_;
            });
            if (row != threads_.end()) refresh_registers(static_cast<std::size_t>(row - threads_.begin()));
        }
        report(wxString::Format("Cleared the pinned register baseline for thread %llu.",
            static_cast<unsigned long long>(cleared_thread)));
        return;
    }
    if (!selected_register_thread_ || registers_.empty()) {
        report("Select a thread with a completed register snapshot before pinning a baseline.");
        return;
    }
    pinned_register_thread_ = *selected_register_thread_;
    pinned_registers_ = registers_;
    register_baseline_button_->SetLabel("Clear baseline");
    register_baseline_button_->SetToolTip(wxString::Format("Clear the pinned register baseline for thread %llu.",
        static_cast<unsigned long long>(*pinned_register_thread_)));
    register_changes_.clear();
    register_changes_.reserve(registers_.size());
    for (const auto &reg : registers_) {
        register_changes_.emplace_back(reg.available ? "Same" : "Unavailable");
    }
    render_registers();
    report(wxString::Format("Pinned the current register snapshot for thread %llu.",
        static_cast<unsigned long long>(*pinned_register_thread_)));
}

void DebuggerView::copy_selected_thread() {
    const auto row = threads_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_thread_rows_.size()) {
        report("Select a thread before copying its snapshot.");
        return;
    }
    const auto &thread = threads_[visible_thread_rows_[static_cast<std::size_t>(row)]];
    const char *state = thread.state == debugger::ThreadState::running ? "running" :
        thread.state == debugger::ThreadState::stopped ? "stopped" :
        thread.state == debugger::ThreadState::exited ? "exited" : "unknown";
    const auto escape = [](wxString value) {
        value.Replace("\\", "\\\\");
        value.Replace("\t", "\\t");
        value.Replace("\r", "\\r");
        value.Replace("\n", "\\n");
        return value;
    };
    const wxString core = thread.core
        ? wxString::Format("%u", static_cast<unsigned>(*thread.core)) : wxString{};
    const auto last_event = thread_last_events_.find(thread.id);
    const wxString output = "Thread ID\tName\tState\tCore\tKernel state\tLatest event\r\n" +
        wxString::Format("%llu", static_cast<unsigned long long>(thread.id)) + "\t" +
        escape(wxString::FromUTF8(thread.name)) + "\t" + state + "\t" + core + "\t" +
        escape(wxString::FromUTF8(thread.native_state)) + "\t" +
        (last_event == thread_last_events_.end() ? wxString{} : escape(wxString::FromUTF8(last_event->second.second))) + "\r\n";
    const auto encoded = output.utf8_str();
    if (encoded.length() > 64 * 1024) {
        report("The selected thread snapshot exceeds the 64 KiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(output));
    wxTheClipboard->Close();
    report(copied ? "Copied the selected thread snapshot to the clipboard."
                  : "Could not copy the selected thread snapshot.");
}

void DebuggerView::copy_visible_threads() {
    if (visible_thread_rows_.empty()) {
        report("There are no visible threads to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    std::string output = "Thread ID\tName\tState\tCore\tKernel state\tLatest event\r\n";
    for (const auto index : visible_thread_rows_) {
        if (index >= threads_.size()) continue;
        const auto &thread = threads_[index];
        const char *state = thread.state == debugger::ThreadState::running ? "running" :
            thread.state == debugger::ThreadState::stopped ? "stopped" :
            thread.state == debugger::ThreadState::exited ? "exited" : "unknown";
        const auto core = thread.core ? std::to_string(*thread.core) : std::string{};
        const auto last_event = thread_last_events_.find(thread.id);
        const auto event_summary = last_event == thread_last_events_.end() ? std::string{} : last_event->second.second;
        const auto line = std::to_string(thread.id) + "\t" + os_data_cell(thread.name) + "\t" + state + "\t" +
            core + "\t" + os_data_cell(thread.native_state) + "\t" + os_data_cell(event_summary) + "\r\n";
        if (line.size() > max_copy_bytes - std::min(output.size(), max_copy_bytes)) {
            report("Visible thread snapshots exceed the 1 MiB clipboard limit.");
            return;
        }
        output += line;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(output)));
    wxTheClipboard->Close();
    report(copied ? "Copied visible thread snapshots as TSV." : "Could not copy visible threads.");
}

void DebuggerView::copy_stack_trace() {
    if (!selected_register_thread_ || session_->state() != debugger::SessionState::stopped ||
        !pending_event_ || frames_stop_ != pending_event_ || locals_stack_frames_.empty() ||
        !current_document(inspection_document_)) {
        report("Refresh stopped-thread inspection before copying stack frames.");
        return;
    }
    wxString output = wxString::Format("Thread %llu stack frames\r\n",
        static_cast<unsigned long long>(*selected_register_thread_));
    for (std::size_t index = 0; index < locals_stack_frames_.size(); ++index) {
        wxString label = locals_frame_choice_->GetString(index);
        label.Replace("\t", " ");
        label.Replace("\r", " ");
        label.Replace("\n", " ");
        output += label;
        if (locals_stack_frames_[index].call_frame_cfa)
            output += wxString::Format(" [CFA=0x%llX]",
                static_cast<unsigned long long>(*locals_stack_frames_[index].call_frame_cfa));
        output += "\r\n";
    }
    const auto encoded = output.utf8_str();
    if (encoded.length() > 64 * 1024) {
        report("The inspected stack trace exceeds the 64 KiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(output));
    wxTheClipboard->Close();
    report(copied ? "Copied the inspected stack frames to the clipboard."
                  : "Could not copy the inspected stack frames.");
}

void DebuggerView::copy_locals() {
    if (!selected_register_thread_ || session_->state() != debugger::SessionState::stopped ||
        !pending_event_ || frames_stop_ != pending_event_ || !current_document(inspection_document_) ||
        selected_locals_frame_ >= locals_stack_frames_.size()) {
        report("Refresh stopped-thread inspection before copying locals.");
        return;
    }
    const auto count = locals_view_->GetItemCount();
    if (count <= 0) {
        report("There are no displayed local values to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    std::string output = "Frame PC\tName\tKind\tScope / origin\tLocation\tValue\r\n";
    const auto to_utf8 = [](const wxString &value) {
        const auto encoded = value.utf8_str();
        if (encoded.length() == 0) return std::string{};
        return std::string(encoded.data(), encoded.length());
    };
    const auto frame_pc = to_utf8(wxString::Format("0x%llX",
        static_cast<unsigned long long>(locals_stack_frames_[selected_locals_frame_].runtime_pc)));
    for (long row = 0; row < count; ++row) {
        const std::vector<std::string> fields{
            frame_pc,
            to_utf8(locals_view_->GetItemText(row, 0)),
            to_utf8(locals_view_->GetItemText(row, 1)),
            to_utf8(locals_view_->GetItemText(row, 2)),
            to_utf8(locals_view_->GetItemText(row, 3)),
            to_utf8(locals_view_->GetItemText(row, 4))};
        std::string line;
        for (std::size_t column = 0; column < fields.size(); ++column) {
            if (column) line.push_back('\t');
            line += os_data_cell(fields[column]);
        }
        line += "\r\n";
        if (line.size() > max_copy_bytes - std::min(output.size(), max_copy_bytes)) {
            report("Displayed local values exceed the 1 MiB clipboard limit.");
            return;
        }
        output += line;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(output)));
    wxTheClipboard->Close();
    report(copied ? "Copied the displayed locals as TSV." : "Could not copy displayed locals.");
}

void DebuggerView::inspect_local_address() {
    const auto row = locals_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0) {
        report("Select a local before inspecting its value as an address.");
        return;
    }
    if (!pending_event_ || session_->state() != debugger::SessionState::stopped) {
        report("Local memory inspection requires a stopped target.");
        return;
    }
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(locals_view_->GetItemText(row, 4)), address)) {
        report("The selected local is not a plain decimal or 0x-prefixed address value.");
        return;
    }
    memory_tabs_->SetSelection(0);
    memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(address)));
    refresh_memory();
}

void DebuggerView::inspect_frame_cfa() {
    if (!selected_register_thread_ || session_->state() != debugger::SessionState::stopped ||
        !pending_event_ || frames_stop_ != pending_event_ || !current_document(inspection_document_) ||
        selected_locals_frame_ >= locals_stack_frames_.size()) {
        report("Refresh stopped-thread frame inspection before inspecting its CFA.");
        return;
    }
    const auto cfa = locals_stack_frames_[selected_locals_frame_].call_frame_cfa;
    if (!cfa) {
        report("The selected frame has no available CFA address.");
        return;
    }
    memory_tabs_->SetSelection(0);
    memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(*cfa)));
    refresh_memory();
}

void DebuggerView::breakpoint_at_frame() {
    document_changed();
    if (session_->state() != debugger::SessionState::stopped || !pending_event_ ||
        frames_stop_ != pending_event_ || !current_document(inspection_document_) ||
        selected_locals_frame_ >= locals_stack_frames_.size()) {
        report("Refresh stopped-thread frame inspection before setting a frame breakpoint.");
        return;
    }
    const auto previous_address = breakpoint_address_->GetValue();
    const auto previous_kind = breakpoint_kind_->GetSelection();
    const auto previous_size = breakpoint_size_->GetSelection();
    const bool previous_size_enabled = breakpoint_size_->IsEnabled();
    const auto runtime_pc = locals_stack_frames_[selected_locals_frame_].runtime_pc;
    breakpoint_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(runtime_pc)));
    breakpoint_kind_->SetSelection(0);
    breakpoint_size_->SetSelection(0);
    breakpoint_size_->Disable();
    add_breakpoint();
    breakpoint_address_->SetValue(previous_address);
    breakpoint_kind_->SetSelection(previous_kind);
    breakpoint_size_->SetSelection(previous_size);
    breakpoint_size_->Enable(previous_size_enabled);
}

void DebuggerView::breakpoint_at_memory_address() {
    const auto address = memory_address_->GetValue();
    if (address.empty()) {
        report("Enter a memory address before setting a breakpoint.");
        return;
    }
    const auto previous_address = breakpoint_address_->GetValue();
    const auto previous_kind = breakpoint_kind_->GetSelection();
    const auto previous_size = breakpoint_size_->GetSelection();
    const bool previous_size_enabled = breakpoint_size_->IsEnabled();
    breakpoint_address_->SetValue(address);
    breakpoint_kind_->SetSelection(0);
    breakpoint_size_->SetSelection(0);
    breakpoint_size_->Disable();
    add_breakpoint();
    breakpoint_address_->SetValue(previous_address);
    breakpoint_kind_->SetSelection(previous_kind);
    breakpoint_size_->SetSelection(previous_size);
    breakpoint_size_->Enable(previous_size_enabled);
}

void DebuggerView::refresh_locals() {
    invalidate_frames();
    if (!document_ || !selected_register_thread_ || session_->state() != debugger::SessionState::stopped) return;
    const auto document = document_();
    if (!document || !document->project || !document->project->loaded || !document->project->loaded->image) return;
    const auto selected_thread = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
        return thread.id == *selected_register_thread_;
    });
    if (selected_thread == threads_.end() || selected_thread->state == debugger::ThreadState::running ||
        selected_thread->state == debugger::ThreadState::exited) return;
    std::optional<std::uint64_t> runtime_pc;
    for (const auto &reg : registers_) {
        const auto name = reg.name;
        if (name == "RIP" || name == "rip" || name == "EIP" || name == "eip" || name == "PC" || name == "pc" ||
            (document->project->loaded->image->layout().architecture == Architecture::arm && (name == "R15" || name == "r15"))) {
            std::uint64_t value = 0;
            const bool big = reg.byte_order == ByteOrder::big;
            if (reg.bytes.empty() || reg.bytes.size() > 8) break;
            for (std::size_t i = 0; i < reg.bytes.size(); ++i) {
                const auto index = big ? i : reg.bytes.size() - 1 - i;
                value = (value << 8) | std::to_integer<std::uint8_t>(reg.bytes[index]);
            }
            runtime_pc = value;
            break;
        }
    }
    if (!runtime_pc) return;
    inspection_document_ = document;
    const auto stop = pending_event_;
    const auto thread = *selected_register_thread_;
    const auto generation = session_generation_;
    const auto request = ++locals_request_;
    const auto register_request = register_request_;
    const auto registers = registers_;
    const auto selected_frame = selected_locals_frame_;
    auto session = session_;
    auto state = inspection_state_;
    enqueue_inspection(5, [session, state, document, stop,
                           registers, runtime_pc = *runtime_pc, selected_frame, thread,
                           generation, request, register_request] {
        std::vector<DebuggerStackFrame> frames;
        std::vector<std::string> labels;
        std::vector<DebuggerLocalRow> rows;
        std::string mapping_reason;
        std::optional<DebuggerImageMapping> inspected_mapping;
        {
            std::lock_guard backend_lock(state->backend_mutex);
            auto modules = session->modules();
            if (modules) {
                const auto process = session->process();
                const auto mapping = debugger_image_mapping(*document, modules.value(),
                    process ? process->architecture : Architecture::unknown, mapping_reason);
                inspected_mapping = mapping;
                if (mapping && mapping->to_image(*document->project->loaded->image, runtime_pc)) {
                    const auto module_base = mapping->runtime_base;
                    const auto module_size = mapping->size;
                    const auto read_memory = [session](std::uint64_t address, std::size_t size) {
                        return session->read_memory(address, size);
                    };
                    const auto architecture = process ? process->architecture : Architecture::unknown;
                    const auto &loaded = *document->project->loaded;
                    const auto *macho = loaded.metadata.macho ? &*loaded.metadata.macho : nullptr;
                    const auto *elf = loaded.metadata.elf ? &*loaded.metadata.elf : nullptr;
                    const auto *pe = loaded.metadata.pe ? &*loaded.metadata.pe : nullptr;
                    frames = debugger_stack_frames_at(*loaded.image, runtime_pc, module_base,
                        module_size, architecture, registers, macho, read_memory, 64,
                        loaded.metadata.preferred_base, elf, pe);
                    for (std::size_t i = 0; i < frames.size(); ++i) {
                        const auto &frame = frames[i];
                        char address[32]{};
                        std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(frame.runtime_pc));
                        std::string label = "Frame " + std::to_string(i) + " - " + address;
                        if (auto symbol = symbolize_debugger_address(*document->project, *loaded.image,
                                frame.runtime_pc, module_base, module_size); symbol) {
                            if (!symbol->name.empty()) {
                                label += " - " + symbol->name;
                                if (symbol->displacement) {
                                    char displacement[24]{};
                                    std::snprintf(displacement, sizeof(displacement), "+0x%llX",
                                        static_cast<unsigned long long>(symbol->displacement));
                                    label += displacement;
                                }
                            }
                            if (symbol->source_location) label += " - " + *symbol->source_location;
                        }
                        labels.push_back(std::move(label));
                    }
                    if (!frames.empty()) {
                        const auto frame_index = std::min(selected_frame, frames.size() - 1);
                        const auto &frame = frames[frame_index];
                        std::optional<std::uint64_t> tls_thread_pointer;
                        if (architecture == Architecture::arm64) {
                            const auto tls_register = std::find_if(registers.begin(), registers.end(),
                                [](const auto &reg) { return reg.name == "tpidr_el0"; });
                            if (tls_register != registers.end()) tls_thread_pointer = register_u64(*tls_register);
                        }
                        rows = debugger_locals_at(*document->project, *loaded.image, frame.runtime_pc,
                            module_base, architecture, frame.registers, read_memory, frame.call_frame_cfa,
                            tls_thread_pointer);
                        if (pe && architecture == Architecture::x86_64) {
                            const auto rsp = std::find_if(frame.registers.begin(), frame.registers.end(),
                                [](const auto &reg) { return reg.name == "RSP" || reg.name == "rsp"; });
                            const auto establisher_frame = rsp == frame.registers.end()
                                ? std::nullopt : register_u64(*rsp);
                            if (establisher_frame) {
                                auto exception_rows = debugger_pe_exception_rows(
                                    *pe, module_base, frame.runtime_pc, *establisher_frame,
                                    [&](std::uint64_t address, std::size_t size) {
                                        return read_memory(address, size);
                                    });
                                rows.insert(rows.end(), std::make_move_iterator(exception_rows.begin()),
                                            std::make_move_iterator(exception_rows.end()));
                            }
                        }
                    }
                } else if (mapping) mapping_reason = "Static mapping unavailable: thread PC is outside mapped executable image coverage.";
            } else mapping_reason = "Static mapping unavailable: " + modules.error().message;
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, register_request, thread, document, stop, inspected_mapping, mapping_reason = std::move(mapping_reason),
                frames = std::move(frames), labels = std::move(labels), rows = std::move(rows)]() mutable {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->locals_request_ != request ||
                view->register_request_ != register_request || view->selected_register_thread_ != thread || !view->current_document(document) ||
                view->pending_event_ != stop || view->session_->state() != debugger::SessionState::stopped) return;
            if (!mapping_reason.empty()) view->report(wxString::FromUTF8(mapping_reason));
            view->frames_stop_ = stop;
            view->frames_mapping_ = inspected_mapping;
            view->locals_stack_frames_ = std::move(frames);
            if (view->locals_stack_frames_.empty()) {
                view->frame_register_status_->SetLabel("No recovered frame register snapshot is available.");
                return;
            }
            view->selected_locals_frame_ = std::min(view->selected_locals_frame_, view->locals_stack_frames_.size() - 1);
            for (const auto &label : labels) view->locals_frame_choice_->Append(wxString::FromUTF8(label));
            view->locals_frame_choice_->SetSelection(static_cast<int>(view->selected_locals_frame_));
            view->render_frame_registers();
            for (const auto &local : rows) {
                const auto row = view->locals_view_->InsertItem(view->locals_view_->GetItemCount(), wxString::FromUTF8(local.name));
                view->locals_view_->SetItem(row, 1, wxString::FromUTF8(local.kind));
                view->locals_view_->SetItem(row, 2, wxString::FromUTF8(local.scope));
                view->locals_view_->SetItem(row, 3, wxString::FromUTF8(local.location));
                view->locals_view_->SetItem(row, 4, wxString::FromUTF8(local.value));
            }
        });
    });
}

bool DebuggerView::current_document(const std::shared_ptr<const DocumentSnapshot> &expected) const {
    const auto current = document_ ? document_() : nullptr;
    return current && expected && current->id == expected->id && current->revision == expected->revision &&
        current->project == expected->project;
}

void DebuggerView::invalidate_frames() {
    ++locals_request_;
    locals_stack_frames_.clear();
    frames_stop_.reset();
    frames_mapping_.reset();
    locals_frame_choice_->Clear();
    locals_view_->DeleteAllItems();
    frame_registers_view_->DeleteAllItems();
    frame_register_status_->SetLabel("No recovered frame register snapshot is available.");
}

void DebuggerView::render_frame_registers() {
    frame_registers_view_->DeleteAllItems();
    if (session_->state() != debugger::SessionState::stopped || !pending_event_ ||
        frames_stop_ != pending_event_ || selected_locals_frame_ >= locals_stack_frames_.size()) {
        frame_register_status_->SetLabel("Frame registers require a current stopped-frame inspection.");
        return;
    }
    const auto& frame = locals_stack_frames_[selected_locals_frame_];
    constexpr std::size_t max_register_rows = 1024;
    constexpr std::size_t max_register_bytes = 512;
    constexpr std::size_t max_display_bytes = 1024 * 1024;
    std::size_t display_bytes = 0;
    bool bounded = frame.registers.size() <= max_register_rows;
    for (const auto& reg : frame.registers) {
        if (reg.name.size() > 256 || reg.group.size() > 256 || reg.bytes.size() > max_register_bytes) {
            bounded = false;
            break;
        }
        const auto value_size = reg.available ? reg.bytes.size() * 2 + 2 : std::size_t{11};
        const auto row_size = reg.name.size() + reg.group.size() + value_size + 32;
        if (row_size > max_display_bytes - std::min(display_bytes, max_display_bytes)) {
            bounded = false;
            break;
        }
        display_bytes += row_size;
    }
    if (!bounded) {
        frame_register_status_->SetLabel("Frame register snapshot exceeds the 1024-row, 512-byte-per-register, or 1 MiB display limit.");
        return;
    }
    wxString status = wxString::Format("Frame %llu at 0x%llX; %llu recovered register values",
        static_cast<unsigned long long>(frame.depth), static_cast<unsigned long long>(frame.runtime_pc),
        static_cast<unsigned long long>(frame.registers.size()));
    if (frame.call_frame_cfa)
        status += wxString::Format("; CFA 0x%llX", static_cast<unsigned long long>(*frame.call_frame_cfa));
    frame_register_status_->SetLabel(status);
    for (const auto& reg : frame.registers) {
        const auto row = frame_registers_view_->InsertItem(frame_registers_view_->GetItemCount(), wxString::FromUTF8(reg.name));
        frame_registers_view_->SetItem(row, 1, wxString::FromUTF8(register_bank_label(reg)));
        frame_registers_view_->SetItem(row, 2, wxString::FromUTF8(register_hex(reg)));
        frame_registers_view_->SetItem(row, 3, reg.available ? "Available" : "Unavailable");
    }
}

void DebuggerView::document_changed() {
    if (current_document(inspection_document_)) return;
    if (remote_config_project_uuid_) save_remote_configuration();
    queued_hit_counts_.clear();
    invalidate_frames();
    if (watch_project_uuid_) save_watch_expressions();
    if (watch_project_uuid_) save_watch_value_format();
    reset_watch_baseline();
    inspection_document_ = document_ ? document_() : nullptr;
    std::optional<database::ProjectUuid> next_uuid;
    if (inspection_document_ && inspection_document_->project && inspection_document_->project->state)
        next_uuid = inspection_document_->project->state->uuid;
    watch_expressions_.clear();
    watch_value_format_->SetSelection(0);
    watch_project_uuid_ = next_uuid;
    remote_config_project_uuid_ = next_uuid;
    load_remote_configuration();
    if (watch_project_uuid_) {
        if (auto *config = wxConfigBase::Get(false)) {
            const auto previous_path = config->GetPath();
            config->SetPath(debugger_project_config_path(*watch_project_uuid_));
            long count = 0;
            if (config->Read("Count", &count) && count >= 0 && count <= 64) {
                for (long i = 0; i < count; ++i) {
                    wxString value;
                    if (!config->Read(wxString::Format("Watch%ld", i), &value) || value.empty() || value.length() > 256) continue;
                    auto expression = value.ToStdString();
                    if (expression.size() > 256 || std::find(watch_expressions_.begin(), watch_expressions_.end(), expression) != watch_expressions_.end()) continue;
                    watch_expressions_.push_back(std::move(expression));
                }
            }
            long watch_format = 0;
            if (config->Read("WatchValueFormat", &watch_format) && watch_format >= 0 && watch_format <= 2)
                watch_value_format_->SetSelection(static_cast<int>(watch_format));
            config->SetPath(previous_path);
        }
    }
    refresh_watches();
    selected_locals_frame_ = 0;
    if (inspection_document_ && selected_register_thread_ && !registers_.empty()) refresh_locals();
}

void DebuggerView::save_watch_expressions() {
    if (!watch_project_uuid_) return;
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    const auto previous_path = config->GetPath();
    config->SetPath(debugger_project_config_path(*watch_project_uuid_));
    std::size_t count = 0;
    for (const auto &expression : watch_expressions_) {
        if (count >= 64 || expression.empty() || expression.size() > 256) continue;
        config->Write(wxString::Format("Watch%lu", static_cast<unsigned long>(count)), wxString::FromUTF8(expression));
        ++count;
    }
    config->Write("Count", static_cast<long>(count));
    config->SetPath(previous_path);
    config->Flush();
}

void DebuggerView::save_watch_value_format() {
    if (!watch_project_uuid_) return;
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    const auto previous_path = config->GetPath();
    config->SetPath(debugger_project_config_path(*watch_project_uuid_));
    config->Write("WatchValueFormat", static_cast<long>(watch_value_format_->GetSelection()));
    config->SetPath(previous_path);
    config->Flush();
}

void DebuggerView::reset_watch_baseline() {
    previous_watch_expressions_.clear();
    previous_watch_values_.clear();
    previous_watch_thread_.reset();
}

void DebuggerView::load_remote_configuration() {
    remote_metadata_->Clear();
    if (!remote_config_project_uuid_) return;
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    const auto previous_path = config->GetPath();
    config->SetPath(debugger_remote_config_path(*remote_config_project_uuid_));
    wxString host, port, directory, metadata, xml;
    long packet_limit = 1024 * 1024;
    bool no_ack = true, non_stop = true, thread_events = true;
    if (config->Read("Host", &host) && host.length() <= 255) remote_host_->SetValue(host);
    if (config->Read("Port", &port) && port.length() <= 5) remote_port_->SetValue(port);
    if (config->Read("WorkingDirectory", &directory) && directory.length() <= 16 * 1024)
        working_directory_->SetValue(directory);
    if (config->Read("PacketLimit", &packet_limit) && packet_limit >= 128 && packet_limit <= 1024 * 1024)
        remote_packet_limit_->SetValue(wxString::Format("%ld", packet_limit));
    config->Read("NoAck", &no_ack, true);
    config->Read("NonStop", &non_stop, true);
    config->Read("ThreadEvents", &thread_events, true);
    remote_no_ack_->SetValue(no_ack); remote_non_stop_->SetValue(non_stop);
    remote_thread_events_->SetValue(thread_events);
    if (config->Read("TargetMetadata", &metadata) && metadata.length() <= 4096)
        remote_metadata_->SetValue(metadata);
    // Keep the bounded XML annex as project-scoped inspection evidence. It is
    // not used to override the live server description on reconnect.
    if (config->Read("TargetXml", &xml) && !xml.empty() && metadata.empty())
        remote_metadata_->SetValue(wxString::Format("Saved root target.xml annex (%llu bytes)",
            static_cast<unsigned long long>(xml.length())));
    config->SetPath(previous_path);
}

void DebuggerView::save_remote_configuration(
    const std::optional<debugger::RemoteTargetMetadata> &metadata) {
    if (!remote_config_project_uuid_) return;
    auto *config = wxConfigBase::Get(false);
    if (!config) return;
    const auto previous_path = config->GetPath();
    config->SetPath(debugger_remote_config_path(*remote_config_project_uuid_));
    if (remote_host_->GetValue().length() <= 255) config->Write("Host", remote_host_->GetValue());
    if (remote_port_->GetValue().length() <= 5) config->Write("Port", remote_port_->GetValue());
    const auto directory = working_directory_->GetValue();
    if (directory.length() <= 16 * 1024) config->Write("WorkingDirectory", directory);
    std::uint64_t packet_limit = 1024 * 1024;
    (void)parse_unsigned(narrow(remote_packet_limit_->GetValue()), packet_limit);
    if (packet_limit >= 128 && packet_limit <= 1024 * 1024)
        config->Write("PacketLimit", static_cast<long>(packet_limit));
    config->Write("NoAck", remote_no_ack_->GetValue());
    config->Write("NonStop", remote_non_stop_->GetValue());
    config->Write("ThreadEvents", remote_thread_events_->GetValue());
    if (metadata) {
        std::string summary = metadata->architecture_name.empty() ? "architecture unavailable" : metadata->architecture_name;
        summary += "; " + std::to_string(metadata->pointer_bits) + "-bit pointers; ";
        summary += metadata->endian_declared ? (metadata->big_endian ? "big endian" : "little endian") : "byte order unspecified";
        summary += "; packet limit " + std::to_string(metadata->packet_size);
        remote_metadata_->SetValue(wxString::FromUTF8(summary));
        if (metadata->target_xml.size() <= 1024 * 1024)
            config->Write("TargetXml", wxString::FromUTF8(metadata->target_xml));
        config->Write("TargetMetadata", wxString::FromUTF8(summary));
    }
    // Environment entries are deliberately omitted: values can contain credentials.
    config->SetPath(previous_path);
    config->Flush();
}

void DebuggerView::navigate_pc(bool selected_frame) {
    document_changed();
    if (!navigate_ || !pending_event_ || session_->state() != debugger::SessionState::stopped) {
        report("Static navigation requires a stopped target and an open document."); return;
    }
    if (!current_document(inspection_document_) || frames_stop_ != pending_event_ || locals_stack_frames_.empty()) {
        report("Static navigation unavailable: refresh stopped-thread registers and wait for current frame inspection."); return;
    }
    const auto index = selected_frame ? selected_locals_frame_ : std::size_t{0};
    if (index >= locals_stack_frames_.size()) { report("Select an inspected stack frame first."); return; }
    const auto document = inspection_document_;
    std::string reason;
    std::optional<DebuggerImageMapping> mapping;
    {
        std::lock_guard lock(inspection_state_->backend_mutex);
        const auto modules = session_->modules();
        const auto process = session_->process();
        if (modules) mapping = debugger_image_mapping(*document, modules.value(),
            process ? process->architecture : Architecture::unknown, reason);
        else reason = "Static navigation unavailable: " + modules.error().message;
    }
    if (!mapping) { invalidate_frames(); report(wxString::FromUTF8(reason)); return; }
    if (mapping != frames_mapping_) {
        invalidate_frames();
        refresh_locals();
        report("Static navigation unavailable: target module mapping changed; refreshing frames."); return;
    }
    const auto address = mapping->to_image(*document->project->loaded->image, locals_stack_frames_[index].runtime_pc);
    if (!address) { report("Static navigation unavailable: PC is outside mapped executable image coverage."); return; }
    navigate_(document->id, Location{*address});
}

void DebuggerView::navigate_breakpoint() {
    document_changed();
    const auto selected = breakpoints_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible_breakpoint_rows_.size()) {
        report("Select a breakpoint to navigate to."); return;
    }
    if (!navigate_ || session_->state() != debugger::SessionState::stopped) {
        report("Breakpoint navigation requires a stopped target and an open document."); return;
    }
    const auto document = document_ ? document_() : nullptr;
    if (!document || !document->project || !document->project->loaded || !document->project->loaded->image) {
        report("Breakpoint navigation requires an open project image."); return;
    }
    const auto &breakpoint = breakpoints_[visible_breakpoint_rows_[static_cast<std::size_t>(selected)]];
    if (breakpoint.kind != debugger::BreakpointKind::software &&
        breakpoint.kind != debugger::BreakpointKind::execute) {
        report("Only software and hardware-execute breakpoints map to code addresses."); return;
    }
    std::string reason;
    std::optional<DebuggerImageMapping> mapping;
    {
        std::lock_guard lock(inspection_state_->backend_mutex);
        const auto modules = session_->modules();
        const auto process = session_->process();
        if (modules) mapping = debugger_image_mapping(*document, modules.value(),
            process ? process->architecture : Architecture::unknown, reason);
        else reason = "Breakpoint navigation unavailable: " + modules.error().message;
    }
    if (!mapping) { report(wxString::FromUTF8(reason)); return; }
    const auto address = mapping->to_image(*document->project->loaded->image, breakpoint.address);
    if (!address) {
        report("Breakpoint navigation unavailable: address is outside mapped executable image coverage."); return;
    }
    navigate_(document->id, Location{*address});
}

void DebuggerView::toggle_selection_breakpoint() {
    document_changed();
    const auto selected = selection_ ? selection_() : std::nullopt;
    const auto document = document_ ? document_() : nullptr;
    if (!selected || !document || selected->first != document->id ||
        session_->state() != debugger::SessionState::stopped) {
        report("Listing breakpoint requires a stopped target and a selection in the active document."); return;
    }
    std::string reason;
    std::optional<DebuggerImageMapping> mapping;
    {
        std::lock_guard lock(inspection_state_->backend_mutex);
        const auto modules = session_->modules();
        const auto process = session_->process();
        if (modules) mapping = debugger_image_mapping(*document, modules.value(),
            process ? process->architecture : Architecture::unknown, reason);
        else reason = "Listing breakpoint unavailable: " + modules.error().message;
    }
    if (!mapping) { report(wxString::FromUTF8(reason)); return; }
    const auto &image = *document->project->loaded->image;
    std::optional<Address> address;
    if (const auto *value = std::get_if<Address>(&selected->second)) address = *value;
    else if (const auto converted = image.to_address(std::get<FileOffset>(selected->second)); converted)
        address = converted.value();
    const auto runtime = address ? mapping->to_runtime(image, *address) : std::nullopt;
    if (!runtime) { report("Listing breakpoint unavailable: selection is outside mapped executable image coverage."); return; }
    const auto existing = std::find_if(breakpoints_.begin(), breakpoints_.end(), [&](const auto &bp) {
        return bp.kind == debugger::BreakpointKind::software && bp.address == *runtime;
    });
    if (existing != breakpoints_.end()) {
        const auto source_row = static_cast<std::size_t>(existing - breakpoints_.begin());
        auto visible = std::find(visible_breakpoint_rows_.begin(), visible_breakpoint_rows_.end(), source_row);
        if (visible == visible_breakpoint_rows_.end()) {
            breakpoint_filter_->ChangeValue("");
            render_breakpoints(existing->id);
            visible = std::find(visible_breakpoint_rows_.begin(), visible_breakpoint_rows_.end(), source_row);
        }
        if (visible == visible_breakpoint_rows_.end()) {
            report("The existing listing breakpoint is not visible in the inventory.");
            return;
        }
        const auto row = static_cast<long>(std::distance(visible_breakpoint_rows_.begin(), visible));
        breakpoints_view_->SetItemState(-1, 0, wxLIST_STATE_SELECTED);
        breakpoints_view_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
        remove_breakpoint();
    } else {
        breakpoint_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(*runtime)));
        breakpoint_kind_->SetSelection(0);
        add_breakpoint();
    }
}

void DebuggerView::write_register() {
    if (!selected_register_thread_ || !selected_register_index_ || *selected_register_index_ >= registers_.size()) {
        report("Select a register to edit."); return;
    }
    const auto &current = registers_[*selected_register_index_];
    if (!current.available) { report("This register is unavailable and cannot be edited."); return; }
    auto input = narrow(register_value_->GetValue());
    constexpr std::size_t max_register_input_chars = 512 * 3;
    if (input.size() > max_register_input_chars) {
        report("Register edit input exceeds the 512-byte register limit."); return;
    }
    std::string_view digits = input;
    if (digits.starts_with("0x") || digits.starts_with("0X")) digits.remove_prefix(2);
    std::vector<std::byte> value;
    bool too_many = false;
    if (!parse_hex_bytes(digits, value, 512, too_many)) {
        report(too_many ? "Register edits are limited to 512 bytes."
                        : "Enter the register value as hexadecimal byte pairs."); return;
    }
    if (value.size() != current.bytes.size()) {
        report(wxString::Format("Register %s requires exactly %llu bytes.", wxString::FromUTF8(current.name),
                                static_cast<unsigned long long>(current.bytes.size()))); return;
    }
    if (current.byte_order != ByteOrder::big) std::reverse(value.begin(), value.end());
    auto update = current;
    update.bytes = std::move(value);
    const auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->write_registers(*selected_register_thread_, std::span<const debugger::RegisterValue>(&update, 1)); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    const auto thread = *selected_register_thread_;
    const auto selected = *selected_register_index_;
    const auto name = current.name;
    auto thread_row = std::find_if(threads_.begin(), threads_.end(), [thread](const auto &candidate) { return candidate.id == thread; });
    if (thread_row != threads_.end()) refresh_registers(static_cast<std::size_t>(thread_row - threads_.begin()));
    if (selected < registers_.size()) {
        const auto visible = std::find(visible_register_rows_.begin(), visible_register_rows_.end(), selected);
        if (visible != visible_register_rows_.end()) {
            registers_view_->SetItemState(static_cast<long>(std::distance(visible_register_rows_.begin(), visible)),
                                          wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
            selected_register_index_ = selected;
            register_value_->SetValue(wxString::FromUTF8(register_hex(registers_[selected])));
            register_value_->Enable(registers_[selected].available);
        }
    }
    report(wxString::Format("Wrote register %s.", wxString::FromUTF8(name)));
}

void DebuggerView::copy_registers() {
    if (!selected_register_thread_ || registers_.empty()) {
        report("There is no completed register snapshot to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    std::string snapshot = "Thread " + std::to_string(*selected_register_thread_) + " register snapshot\n";
    for (const auto &reg : registers_) {
        const auto value = register_display_value(reg, register_value_format_ ? register_value_format_->GetSelection() : 0);
        const auto remaining = snapshot.size() <= max_copy_bytes ? max_copy_bytes - snapshot.size() : 0;
        if (reg.name.size() > remaining || value.size() > remaining - reg.name.size() ||
            4 > remaining - reg.name.size() - value.size()) {
            report("Register snapshot exceeds the 1 MiB clipboard limit.");
            return;
        }
        snapshot += reg.name;
        snapshot += " = ";
        snapshot += value;
        snapshot += '\n';
    }
    if (!wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(snapshot)));
    wxTheClipboard->Close();
    report(copied ? "Copied the displayed register snapshot to the clipboard." :
                    "Could not copy the displayed register snapshot.");
}

void DebuggerView::copy_visible_registers() {
    if (!selected_register_thread_ || registers_.empty() || visible_register_rows_.empty()) {
        report("There are no visible register rows to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    std::string output = "Thread\tRegister\tBank\tValue\tChange\r\n";
    std::size_t copied_rows = 0;
    bool truncated = false;
    for (const auto index : visible_register_rows_) {
        if (index >= registers_.size()) {
            truncated = true;
            break;
        }
        const auto &reg = registers_[index];
        const auto change = index < register_changes_.size() ? register_changes_[index] : std::string{};
        const std::array<std::string, 5> fields{
            std::to_string(*selected_register_thread_), reg.name, register_bank_label(reg),
            register_display_value(reg, register_value_format_ ? register_value_format_->GetSelection() : 0), change};
        std::string row;
        for (std::size_t field = 0; field < fields.size(); ++field) {
            if (field) row.push_back('\t');
            row += os_data_cell(fields[field]);
        }
        row += "\r\n";
        if (output.size() > max_copy_bytes || row.size() > max_copy_bytes - output.size()) {
            truncated = true;
            break;
        }
        output += row;
        ++copied_rows;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable; no register rows were copied.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(output)));
    wxTheClipboard->Close();
    if (!copied) {
        report("Could not copy the visible register rows.");
        return;
    }
    report(truncated
        ? wxString::Format("Copied %llu of %llu visible register rows as TSV; remaining rows omitted at the 1 MiB limit.",
              static_cast<unsigned long long>(copied_rows),
              static_cast<unsigned long long>(visible_register_rows_.size()))
        : wxString::Format("Copied %llu visible register rows as TSV.",
              static_cast<unsigned long long>(copied_rows)));
}

void DebuggerView::copy_selected_register() {
    if (!selected_register_thread_ || !selected_register_index_ ||
        *selected_register_index_ >= registers_.size() || *selected_register_index_ >= register_changes_.size()) {
        report("Select a register from a completed snapshot before copying it.");
        return;
    }
    const auto &reg = registers_[*selected_register_index_];
    const auto change = register_changes_[*selected_register_index_];
    const std::vector<std::string> fields{
        std::to_string(*selected_register_thread_), reg.name, register_bank_label(reg),
        register_display_value(reg, register_value_format_ ? register_value_format_->GetSelection() : 0), change};
    std::string text = "Thread\tRegister\tBank\tValue\tChange\r\n";
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (index) text.push_back('\t');
        text += os_data_cell(fields[index]);
    }
    text += "\r\n";
    constexpr std::size_t max_copy_bytes = 64 * 1024;
    if (text.size() > max_copy_bytes) {
        report("Selected register details exceed the 64 KiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(text)));
    wxTheClipboard->Close();
    report(copied ? "Copied the selected register as TSV." : "Could not copy the selected register.");
}

void DebuggerView::watch_selected_register() {
    if (!selected_register_index_ || *selected_register_index_ >= registers_.size()) {
        report("Select a register before adding it to Watches.");
        return;
    }
    if (session_->state() != debugger::SessionState::stopped) {
        report("Register watches can be added from a stopped target only.");
        return;
    }
    const auto &reg = registers_[*selected_register_index_];
    if (!reg.available || reg.name.empty()) {
        report("The selected register is unavailable and cannot be watched.");
        return;
    }
    if (reg.bytes.empty() || reg.bytes.size() > 8) {
        report("Only scalar registers up to 64 bits can be added to Watches.");
        return;
    }
    memory_tabs_->SetSelection(2);
    watch_expression_->SetValue(wxString::FromUTF8(reg.name));
    add_watch_expression();
}

void DebuggerView::read_selected_register_address() {
    if (!selected_register_index_ || *selected_register_index_ >= registers_.size()) {
        report("Select a register before reading its address.");
        return;
    }
    const auto &reg = registers_[*selected_register_index_];
    if (!reg.available || reg.bytes.empty() || reg.bytes.size() > sizeof(std::uint64_t)) {
        report("The selected register is unavailable or wider than 64 bits.");
        return;
    }
    std::uint64_t address = 0;
    const auto append_byte = [&address](std::byte byte) {
        address = (address << 8) | std::to_integer<std::uint8_t>(byte);
    };
    if (reg.byte_order == ByteOrder::big) {
        for (const auto byte : reg.bytes) append_byte(byte);
    } else {
        for (auto byte = reg.bytes.rbegin(); byte != reg.bytes.rend(); ++byte) append_byte(*byte);
    }
    memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(address)));
    memory_tabs_->SetSelection(0);
    refresh_memory();
}

void DebuggerView::copy_output() {
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    const auto output = log_->GetValue().ToUTF8();
    if (!output || output.length() == 0) {
        report("There is no debugger output to copy.");
        return;
    }
    if (output.length() > max_copy_bytes) {
        report("Debugger output exceeds the 1 MiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(log_->GetValue()));
    wxTheClipboard->Close();
    report(copied ? "Copied debugger output to the clipboard." :
                    "Could not copy debugger output.");
}

void DebuggerView::copy_matching_output_lines() {
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    const auto query = output_search_->GetValue();
    if (query.empty()) {
        report("Enter text in the output search field before copying matches.");
        return;
    }
    const auto output = log_->GetValue();
    const auto ascii_lower = [](wxString value) {
        for (std::size_t index = 0; index < value.length(); ++index) {
            const auto character = value[index];
            if (character >= 'A' && character <= 'Z')
                value[index] = wxUniChar(static_cast<wxUniChar::value_type>(character.GetValue() + 32u));
        }
        return value;
    };
    const auto search_query = output_search_case_->GetValue() ? query : ascii_lower(query);
    wxString matches;
    std::size_t start = 0;
    while (start < output.length()) {
        auto end = output.find('\n', start);
        if (end == wxString::npos) end = output.length();
        auto line = output.Mid(start, end - start);
        if (!line.empty() && line.Last() == '\r') line.RemoveLast();
        const auto searchable = output_search_case_->GetValue() ? line : ascii_lower(line);
        if (searchable.find(search_query) != wxString::npos) {
            matches += line;
            matches += '\n';
        }
        start = end == output.length() ? end : end + 1;
    }
    if (matches.empty()) {
        report("No output lines match the current search.");
        return;
    }
    const auto encoded = matches.ToUTF8();
    if (!encoded || encoded.length() > max_copy_bytes) {
        report("Matching debugger output exceeds the 1 MiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(matches));
    wxTheClipboard->Close();
    report(copied ? "Copied matching debugger output lines to the clipboard." :
                    "Could not copy matching debugger output lines.");
}

void DebuggerView::save_output_to_file() {
    const auto output = log_->GetValue().utf8_str();
    if (output.length() == 0) {
        report("There is no debugger output to save.");
        return;
    }
    constexpr std::size_t max_save_bytes = 4 * 1024 * 1024;
    if (output.length() > max_save_bytes) {
        report("Debugger output exceeds the 4 MiB file export limit.");
        return;
    }
    wxFileDialog dialog(this, "Save debugger output", wxEmptyString, "debugger-output.txt",
                        "Text files (*.txt)|*.txt|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK) return;
    wxFile file;
    if (!file.Open(dialog.GetPath(), wxFile::write)) {
        report("Could not open the selected debugger output file.");
        return;
    }
    const auto written = file.Write(output.data(), output.length());
    const bool closed = file.Close();
    if (written != static_cast<wxFileOffset>(output.length()) || !closed) {
        report("Could not write the complete debugger output file.");
        return;
    }
    report(wxString("Saved debugger output to ") + dialog.GetPath() + ".");
}

void DebuggerView::save_memory_page_raw() {
    if (memory_page_bytes_.empty()) {
        report("There is no completed memory page to save.");
        return;
    }
    wxFileDialog dialog(this, "Save raw memory bytes", wxEmptyString,
                        wxString::Format("memory-%016llX.bin", static_cast<unsigned long long>(memory_page_address_)),
                        "Binary files (*.bin)|*.bin|All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);
    if (dialog.ShowModal() != wxID_OK) return;
    wxFile file;
    if (!file.Open(dialog.GetPath(), wxFile::write)) {
        report("Could not open the selected memory dump file.");
        return;
    }
    const auto written = file.Write(memory_page_bytes_.data(), memory_page_bytes_.size());
    const bool closed = file.Close();
    if (written != static_cast<wxFileOffset>(memory_page_bytes_.size()) || !closed) {
        report("Could not write the complete raw memory page.");
        return;
    }
    report(wxString::Format("Saved %llu raw bytes from 0x%016llX to %s.",
        static_cast<unsigned long long>(memory_page_bytes_.size()),
        static_cast<unsigned long long>(memory_page_address_), dialog.GetPath()));
}

void DebuggerView::search_output(int direction) {
    auto query = output_search_->GetValue();
    if (query.empty()) {
        output_search_status_->SetLabel("Enter text to find.");
        return;
    }
    const auto ascii_lower = [](wxString value) {
        for (std::size_t index = 0; index < value.length(); ++index) {
            const auto character = value[index];
            if (character >= 'A' && character <= 'Z')
                value[index] = wxUniChar(static_cast<wxUniChar::value_type>(character.GetValue() + 32u));
        }
        return value;
    };
    const auto output = log_->GetValue();
    const auto search_text = output_search_case_->GetValue() ? output : ascii_lower(output);
    const auto search_query = output_search_case_->GetValue() ? query : ascii_lower(query);
    const auto cursor = std::min(output_search_cursor_, static_cast<std::size_t>(search_text.length()));
    auto found = wxString::npos;
    bool wrapped = false;
    if (direction >= 0) {
        found = search_text.find(search_query, cursor);
        if (found == wxString::npos && cursor > 0) {
            found = search_text.find(search_query, 0);
            wrapped = found != wxString::npos;
        }
    } else {
        found = search_text.rfind(search_query, cursor == 0 ? wxString::npos : cursor - 1);
        if (found == wxString::npos) {
            found = search_text.rfind(search_query);
            wrapped = found != wxString::npos;
        }
        if (cursor == 0 && found != wxString::npos) wrapped = true;
    }
    if (found == wxString::npos) {
        output_search_status_->SetLabel("No match.");
        log_->SetSelection(0, 0);
        return;
    }
    const auto end = found + search_query.length();
    log_->SetSelection(static_cast<long>(found), static_cast<long>(end));
    log_->ShowPosition(static_cast<long>(found));
    output_search_cursor_ = direction >= 0 ? end : found;
    output_search_status_->SetLabel(wxString::Format("Character %llu%s",
        static_cast<unsigned long long>(found + 1), wrapped ? " (wrapped)" : ""));
}

void DebuggerView::refresh_memory() {
    const auto request = ++memory_request_;
    memory_page_bytes_.clear();
    ++memory_tag_request_;
    memory_tag_view_->Clear();
    memory_tag_read_button_->Enable(session_->state() == debugger::SessionState::stopped &&
        session_->supports_memory_tag_read());
    memory_tag_status_->SetLabel(session_->state() == debugger::SessionState::stopped && session_->supports_memory_tag_read()
        ? "Tags apply to the current memory page; shown per 16-byte granule."
        : "Memory tags are available when the selected stopped target supports tag reads.");
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        memory_view_->SetValue("Memory read failed: invalid address.");
        report("Enter a valid memory address (decimal or 0x-prefixed hexadecimal)."); return;
    }
    if (!suppress_memory_history_record_) record_memory_address(address);
    const int page = memory_page_size_->GetSelection();
    constexpr std::size_t page_sizes[] = {64, 256, 1024};
    const auto count = page >= 0 && page < 3 ? page_sizes[page] : page_sizes[1];
    const int selected_row_width = memory_row_width_->GetSelection();
    constexpr std::size_t row_widths[] = {8, 16, 32};
    const auto row_width = selected_row_width >= 0 && selected_row_width < 3
        ? row_widths[selected_row_width] : row_widths[1];
    const auto generation = session_generation_;
    auto session = session_;
    auto state = inspection_state_;
    memory_view_->SetValue("Reading memory...");
    enqueue_inspection(2, [session, state, address, count, row_width, generation, request] {
      std::lock_guard backend_lock(state->backend_mutex);
      auto result = session->read_memory(address, count);
      std::string error, dump;
      std::vector<std::byte> raw_bytes;
      if (!result) error = result.error().message;
      else if (result.value().size() > count) error = "backend returned more bytes than requested.";
      else {
        const auto &bytes = result.value();
        raw_bytes = bytes;
        for (std::size_t offset = 0; offset < bytes.size(); offset += row_width) {
        char line[32]{};
        const auto written = std::snprintf(line, sizeof(line), "%016llX  ",
            static_cast<unsigned long long>(address + offset));
        dump.append(line, static_cast<std::size_t>(written));
        for (std::size_t i = 0; i < row_width; ++i) {
            if (offset + i < bytes.size()) {
                const auto value = std::to_integer<unsigned>(bytes[offset + i]);
                static constexpr char digits[] = "0123456789ABCDEF";
                dump.push_back(digits[value >> 4]); dump.push_back(digits[value & 15]);
            } else dump.append("  ");
            dump.push_back(' ');
        }
        dump.append(" | ");
        for (std::size_t i = 0; i < row_width && offset + i < bytes.size(); ++i) {
            const auto value = std::to_integer<unsigned char>(bytes[offset + i]);
            dump.push_back(value >= 32 && value < 127 ? static_cast<char>(value) : '.');
        }
        dump.push_back('\n');
        }
      }
      if (auto *app = wxTheApp) app->CallAfter([state, generation, request, address, error = std::move(error), dump = std::move(dump), raw_bytes = std::move(raw_bytes)] {
          std::lock_guard lock(state->mutex);
          auto *view = state->target;
          if (!view || view->session_generation_ != generation || view->memory_request_ != request) return;
          if (!error.empty()) {
              view->memory_page_bytes_.clear();
              view->memory_view_->SetValue("Memory read failed: " + wxString::FromUTF8(error));
              view->report(wxString::FromUTF8(error));
          } else {
              view->memory_page_address_ = address;
              view->memory_page_bytes_ = std::move(raw_bytes);
              view->memory_view_->SetValue(wxString::FromUTF8(dump));
          }
      });
    });
}

void DebuggerView::read_memory_tags() {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        memory_tag_status_->SetLabel("Enter a valid memory address first.");
        return;
    }
    const auto type_text = narrow(memory_tag_type_->GetValue());
    std::int32_t type = 0;
    const auto parsed_type = std::from_chars(type_text.data(), type_text.data() + type_text.size(), type, 10);
    if (type_text.empty() || parsed_type.ec != std::errc{} || parsed_type.ptr != type_text.data() + type_text.size()) {
        memory_tag_status_->SetLabel("Tag type must be a signed decimal 32-bit integer.");
        return;
    }
    const int page = memory_page_size_->GetSelection();
    constexpr std::size_t page_sizes[] = {64, 256, 1024};
    const auto count = page >= 0 && page < 3 ? page_sizes[page] : page_sizes[1];
    const auto generation = session_generation_;
    const auto request = ++memory_tag_request_;
    auto session = session_;
    auto state = inspection_state_;
    memory_tag_read_button_->Disable();
    memory_tag_status_->SetLabel("Reading allocation tags (4-bit per 16-byte granule)...");
    memory_tag_view_->Clear();
    enqueue_inspection(2, [session, state, address, count, type, generation, request] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->read_memory_tags(address, count, type, 256 * 1024);
        std::string error, rendered;
        std::size_t tag_count = 0;
        if (!result) error = result.error().message;
        else if (result.value().size() > 256 * 1024) error = "backend returned more tag bytes than the 256 KiB limit.";
        else {
            const auto& tags = result.value();
            tag_count = tags.size();
            const auto first_offset = static_cast<std::size_t>(address & 0xfu);
            const auto expected_tags = (first_offset + count + 15u) / 16u;
            if (tag_count > expected_tags) {
                error = "backend returned more allocation tags than the requested granules.";
            }
            if (error.empty()) {
                rendered = "Granule address       Offset  Allocation tag (4-bit)\n";
                const auto first_granule = address & ~std::uint64_t{0xf};
                for (std::size_t index = 0; index < tags.size(); ++index) {
                    const auto value = std::to_integer<unsigned>(tags[index]);
                    if (value > 0xfu) {
                        error = "backend returned an allocation tag wider than four bits.";
                        rendered.clear();
                        break;
                    }
                    if (index > (std::numeric_limits<std::uint64_t>::max() - first_granule) / 16u) {
                        error = "allocation tag granule address overflows the target address space.";
                        rendered.clear();
                        break;
                    }
                    char line[96]{};
                    const auto granule_address = first_granule + static_cast<std::uint64_t>(index) * 16u;
                    const auto written = std::snprintf(line, sizeof(line), "0x%016llX  +0x%04llX  0x%X\n",
                        static_cast<unsigned long long>(granule_address),
                        static_cast<unsigned long long>(index * 16u), value);
                    if (written > 0 && static_cast<std::size_t>(written) < sizeof(line)) rendered.append(line, static_cast<std::size_t>(written));
                }
            }
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, address, count, error = std::move(error),
                rendered = std::move(rendered), tag_count] {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->memory_tag_request_ != request) return;
            view->memory_tag_read_button_->Enable(view->session_->state() == debugger::SessionState::stopped &&
                view->session_->supports_memory_tag_read());
            if (!error.empty()) {
                view->memory_tag_status_->SetLabel("Tag read failed: " + wxString::FromUTF8(error));
                view->report(wxString::FromUTF8(error));
            } else {
                view->memory_tag_view_->SetValue(wxString::FromUTF8(rendered));
                const auto first_offset = static_cast<std::size_t>(address & 0xfu);
                const auto expected_tags = (first_offset + count + 15u) / 16u;
                const auto qualifier = tag_count < expected_tags ? " (short read; omitted granules are unknown)" : "";
                view->memory_tag_status_->SetLabel(wxString::Format("%llu of %llu allocation tags returned%s.",
                    static_cast<unsigned long long>(tag_count),
                    static_cast<unsigned long long>(expected_tags), qualifier));
            }
        });
    });
}

void DebuggerView::record_memory_address(std::uint64_t address) {
    if (!memory_address_history_.empty() && memory_address_history_position_ + 1 < memory_address_history_.size())
        memory_address_history_.erase(memory_address_history_.begin() +
            static_cast<std::ptrdiff_t>(memory_address_history_position_ + 1), memory_address_history_.end());
    if (!memory_address_history_.empty() && memory_address_history_.back() == address) {
        memory_address_history_position_ = memory_address_history_.size() - 1;
        update_memory_history_controls();
        return;
    }
    constexpr std::size_t max_history_entries = 64;
    if (memory_address_history_.size() == max_history_entries) {
        memory_address_history_.erase(memory_address_history_.begin());
        if (memory_address_history_position_ > 0) --memory_address_history_position_;
    }
    memory_address_history_.push_back(address);
    memory_address_history_position_ = memory_address_history_.size() - 1;
    update_memory_history_controls();
}

void DebuggerView::navigate_memory_history(int direction) {
    if (memory_address_history_.empty()) return;
    if (direction < 0) {
        if (memory_address_history_position_ == 0) return;
        --memory_address_history_position_;
    } else {
        if (memory_address_history_position_ + 1 >= memory_address_history_.size()) return;
        ++memory_address_history_position_;
    }
    navigate_memory_history_to(memory_address_history_position_);
}

void DebuggerView::navigate_memory_history_to(std::size_t position) {
    if (position >= memory_address_history_.size()) return;
    memory_address_history_position_ = position;
    memory_address_->SetValue(wxString::Format("0x%llX",
        static_cast<unsigned long long>(memory_address_history_[memory_address_history_position_])));
    suppress_memory_history_record_ = true;
    refresh_memory();
    suppress_memory_history_record_ = false;
    update_memory_history_controls();
}

void DebuggerView::update_memory_history_controls() {
    if (!memory_history_back_button_ || !memory_history_forward_button_) return;
    memory_history_back_button_->Enable(!memory_address_history_.empty() && memory_address_history_position_ > 0);
    memory_history_forward_button_->Enable(!memory_address_history_.empty() &&
        memory_address_history_position_ + 1 < memory_address_history_.size());
    updating_memory_history_choice_ = true;
    memory_history_choice_->Clear();
    for (const auto address : memory_address_history_)
        memory_history_choice_->Append(wxString::Format("0x%llX", static_cast<unsigned long long>(address)));
    if (memory_address_history_.empty()) {
        memory_history_choice_->Append("History");
        memory_history_choice_->SetSelection(0);
        memory_history_choice_->Disable();
    } else {
        memory_history_choice_->SetSelection(static_cast<int>(memory_address_history_position_));
        memory_history_choice_->Enable();
    }
    updating_memory_history_choice_ = false;
}

void DebuggerView::watch_memory_byte() {
    if (session_->state() != debugger::SessionState::stopped) {
        report("Memory address watches require a stopped target.");
        return;
    }
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        report("Enter a valid memory address before adding it to Watches.");
        return;
    }
    memory_tabs_->SetSelection(2);
    watch_expression_->SetValue(wxString::Format("mem8(0x%llX)", static_cast<unsigned long long>(address)));
    add_watch_expression();
}

void DebuggerView::copy_memory_page() {
    const auto dump = memory_view_->GetValue();
    if (dump.empty() || dump.StartsWith("Reading memory...") || dump.StartsWith("Memory read failed:")) {
        report("There is no completed memory dump to copy.");
        return;
    }
    if (!wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(dump));
    wxTheClipboard->Close();
    report(copied ? "Copied the displayed memory dump to the clipboard." :
                    "Could not copy the displayed memory dump.");
}

void DebuggerView::copy_inspection_report() {
    constexpr std::size_t limit = 4 * 1024 * 1024;
    std::string json;
    json.reserve(64 * 1024);
    bool overflow = false;
    const auto raw = [&](std::string_view value) {
        if (overflow) return;
        if (value.size() > limit - json.size()) { overflow = true; return; }
        json.append(value);
    };
    const auto string = [&](const wxString &value) {
        if (overflow) return;
        raw("\"");
        const auto bytes = value.ToUTF8();
        if (!bytes) { overflow = true; return; }
        for (const char byte : std::string_view(bytes.data(), bytes.length())) {
            switch (byte) {
            case '"': raw("\\\""); break;
            case '\\': raw("\\\\"); break;
            case '\b': raw("\\b"); break;
            case '\f': raw("\\f"); break;
            case '\n': raw("\\n"); break;
            case '\r': raw("\\r"); break;
            case '\t': raw("\\t"); break;
            default:
                if (static_cast<unsigned char>(byte) < 0x20) {
                    static constexpr char digits[] = "0123456789abcdef";
                    const char escaped[] = {'\\', 'u', '0', '0', digits[(static_cast<unsigned char>(byte) >> 4) & 15],
                                            digits[static_cast<unsigned char>(byte) & 15]};
                    raw(std::string_view(escaped, sizeof(escaped)));
                } else raw(std::string_view(&byte, 1));
            }
            if (overflow) return;
        }
        raw("\"");
    };
    const auto key = [&](std::string_view name) { raw("\""); raw(name); raw("\":"); };
    const auto text_field = [&](std::string_view name, const wxString &value) { key(name); string(value); };
    const auto number_field = [&](std::string_view name, std::uint64_t value) { key(name); raw(std::to_string(value)); };
    const auto flag_field = [&](std::string_view name, bool value) { key(name); raw(value ? "true" : "false"); };
    const auto comma = [&](std::size_t index) { if (index) raw(","); };
    const auto from_utf8 = [](std::string_view value) { return wxString::FromUTF8(value.data(), value.size()); };
    const auto thread_state = [](debugger::ThreadState value) {
        switch (value) {
        case debugger::ThreadState::running: return wxString("running");
        case debugger::ThreadState::stopped: return wxString("stopped");
        case debugger::ThreadState::exited: return wxString("exited");
        default: return wxString("unknown");
        }
    };
    const auto breakpoint_kind = [](debugger::BreakpointKind value) {
        switch (value) {
        case debugger::BreakpointKind::software: return wxString("software");
        case debugger::BreakpointKind::execute: return wxString("hardware_execute");
        case debugger::BreakpointKind::read: return wxString("hardware_read");
        case debugger::BreakpointKind::write: return wxString("hardware_write");
        default: return wxString("hardware_access");
        }
    };

    raw("{\"schema\":\"hexlab.debugger-inspection.v1\",\"consistency\":\"cached UI snapshots; not an atomic backend capture\",\"target\":{");
    text_field("state", state_->GetValue()); raw(","); text_field("identity", target_identity_->GetValue()); raw(",");
    text_field("last_event", event_->GetValue()); raw(",\"stop_sequence\":");
    if (pending_event_) raw(std::to_string(*pending_event_)); else raw("null");
    raw("},\"event\":");
    if (last_event_snapshot_) {
        const auto &snapshot = *last_event_snapshot_;
        raw("{"); text_field("kind", event_name(snapshot.kind)); raw(",");
        number_field("sequence", snapshot.sequence); raw(","); number_field("thread", snapshot.thread); raw(",");
        number_field("address", snapshot.address); raw(","); number_field("code", snapshot.code); raw(",");
        text_field("message", from_utf8(snapshot.message)); raw(",\"first_chance\":");
        if (snapshot.first_chance) raw(*snapshot.first_chance ? "true" : "false"); else raw("null");
        raw(",\"exception_parameters\":[");
        for (std::size_t i = 0; i < snapshot.exception_parameters.size() && !overflow; ++i) {
            if (i) raw(",");
            string(wxString::Format("0x%llX", static_cast<unsigned long long>(snapshot.exception_parameters[i])));
        }
        raw("],\"exception_parameters_truncated\":");
        raw(snapshot.exception_parameters_truncated ? "true" : "false");
        raw(",\"breakpoint_ids\":[");
        for (std::size_t i = 0; i < snapshot.breakpoint_ids.size() && !overflow; ++i) {
            if (i) raw(","); raw(std::to_string(snapshot.breakpoint_ids[i]));
        }
        raw("]}");
    } else raw("null");
    raw(",\"selection\":{\"thread\":");
    if (selected_register_thread_) raw(std::to_string(*selected_register_thread_)); else raw("null");
    raw(",\"memory_address\":"); string(memory_address_->GetValue()); raw("},\"threads\":{");
    number_field("visible_count", visible_thread_rows_.size()); raw(",");
    number_field("snapshot_count", threads_.size()); raw(","); text_field("filter", thread_filter_->GetValue()); raw(",");
    text_field("state_filter", thread_state_filter_->GetStringSelection()); raw(",");
    text_field("sort", thread_sort_->GetStringSelection()); raw(",\"rows\":[");
    for (std::size_t i = 0; i < visible_thread_rows_.size() && !overflow; ++i) {
        const auto index = visible_thread_rows_[i]; if (index >= threads_.size()) continue;
        const auto &thread = threads_[index]; comma(i); raw("{"); number_field("id", thread.id); raw(",");
        text_field("name", from_utf8(thread.name)); raw(","); text_field("state", thread_state(thread.state)); raw(",\"core\":");
        if (thread.core) raw(std::to_string(*thread.core)); else raw("null");
        raw(","); text_field("native_state", from_utf8(thread.native_state)); raw("}");
    }
    raw("]},\"registers\":{\"thread\":");
    if (selected_register_thread_) raw(std::to_string(*selected_register_thread_)); else raw("null");
    raw(","); number_field("visible_count", visible_register_rows_.size()); raw(",");
    number_field("snapshot_count", registers_.size()); raw(","); text_field("filter", register_filter_->GetValue()); raw(",");
    flag_field("changes_only", register_changed_only_->GetValue()); raw(",\"rows\":[");
    for (std::size_t i = 0; i < visible_register_rows_.size() && !overflow; ++i) {
        const auto index = visible_register_rows_[i]; if (index >= registers_.size()) continue;
        const auto &reg = registers_[index]; comma(i); raw("{"); number_field("number", reg.number); raw(",");
        text_field("name", from_utf8(reg.name)); raw(","); text_field("bank", from_utf8(register_bank_label(reg))); raw(",");
        text_field("value", from_utf8(register_hex(reg))); raw(",");
        text_field("change", from_utf8(index < register_changes_.size() ? register_changes_[index] : std::string{})); raw(",");
        flag_field("available", reg.available); raw(","); text_field("type", from_utf8(reg.type)); raw("}");
    }
    raw("]},\"memory_page\":{"); text_field("address", memory_address_->GetValue()); raw(",");
    text_field("display", memory_view_->GetValue()); raw(",");
    text_field("page_size", memory_page_size_->GetStringSelection()); raw(",");
    text_field("row_width", memory_row_width_->GetStringSelection()); raw(",\"raw_bytes\":");
    if (memory_page_bytes_.empty()) raw("null");
    else {
        raw("{\"address\":");
        char memory_address_hex[19]{};
        std::snprintf(memory_address_hex, sizeof(memory_address_hex), "0x%016llX",
                      static_cast<unsigned long long>(memory_page_address_));
        string(wxString::FromUTF8(memory_address_hex)); raw(",");
        number_field("byte_count", memory_page_bytes_.size()); raw(",\"hex\":\"");
        static constexpr char digits[] = "0123456789abcdef";
        for (const auto byte : memory_page_bytes_) {
            const auto value = std::to_integer<unsigned>(byte);
            const char pair[] = {digits[value >> 4], digits[value & 0x0f]};
            raw(std::string_view(pair, sizeof(pair)));
        }
        raw("\"}");
    }
    raw("},\"modules\":{");
    number_field("visible_count", visible_module_rows_.size()); raw(",");
    number_field("snapshot_count", modules_.size()); raw(","); text_field("filter", module_filter_->GetValue()); raw(",");
    text_field("sort", module_sort_->GetStringSelection()); raw(",\"rows\":[");
    for (std::size_t i = 0; i < visible_module_rows_.size() && !overflow; ++i) {
        const auto index = visible_module_rows_[i]; if (index >= modules_.size()) continue;
        const auto &module = modules_[index]; comma(i); raw("{"); number_field("base", module.base); raw(",");
        number_field("size", module.size); raw(","); text_field("name", from_utf8(module.name)); raw(",");
        text_field("path", from_utf8(module.path)); raw(",");
        text_field("diagnostic", from_utf8(module.diagnostic)); raw("}");
    }
    raw("]},\"memory_regions\":{"); number_field("visible_count", visible_memory_region_rows_.size()); raw(",");
    number_field("snapshot_count", memory_regions_.size()); raw(","); text_field("filter", memory_region_filter_->GetValue()); raw(",");
    text_field("permission_filter", memory_region_permission_filter_->GetStringSelection()); raw(",");
    text_field("sort", memory_region_sort_->GetStringSelection()); raw(",\"rows\":[");
    for (std::size_t i = 0; i < visible_memory_region_rows_.size() && !overflow; ++i) {
        const auto index = visible_memory_region_rows_[i]; if (index >= memory_regions_.size()) continue;
        const auto &region = memory_regions_[index]; comma(i); raw("{"); number_field("start", region.start); raw(",");
        number_field("length", region.length); raw(","); flag_field("readable", region.readable); raw(",");
        flag_field("writable", region.writable); raw(","); flag_field("executable", region.executable); raw(",");
        text_field("type", from_utf8(region.type)); raw(",");
        if (region.flash_block_size) number_field("flash_block_size", *region.flash_block_size);
        else raw("\"flash_block_size\":null");
        raw("}");
    }
    raw("]},\"breakpoints\":{"); number_field("visible_count", visible_breakpoint_rows_.size()); raw(",");
    number_field("snapshot_count", breakpoints_.size()); raw(","); text_field("filter", breakpoint_filter_->GetValue()); raw(",");
    flag_field("enabled_only", breakpoint_enabled_only_->GetValue()); raw(",");
    text_field("sort", breakpoint_sort_->GetStringSelection()); raw(",\"rows\":[");
    for (std::size_t i = 0; i < visible_breakpoint_rows_.size() && !overflow; ++i) {
        const auto index = visible_breakpoint_rows_[i]; if (index >= breakpoints_.size()) continue;
        const auto &bp = breakpoints_[index]; comma(i); raw("{"); number_field("id", bp.id); raw(",");
        number_field("address", bp.address); raw(","); text_field("kind", breakpoint_kind(bp.kind)); raw(",");
        number_field("size", bp.size); raw(","); flag_field("enabled", bp.enabled); raw(",");
        number_field("hits", bp.hit_count); raw(","); number_field("ignore_count", bp.ignore_count); raw(",");
        flag_field("logpoint", bp.logpoint); raw(","); flag_field("one_shot", bp.one_shot); raw(",");
        text_field("condition", from_utf8(bp.condition)); raw(","); text_field("log_message", from_utf8(bp.log_message)); raw("}");
    }
    raw("]}}");
    if (overflow || json.size() > limit) {
        report("Debugger inspection report exceeds the 4 MiB JSON clipboard limit."); return;
    }
    const auto output = wxString::FromUTF8(json.data(), json.size());
    const auto encoded = output.ToUTF8();
    if (!encoded || encoded.length() != json.size()) {
        report("Debugger inspection report could not be encoded safely as UTF-8 JSON."); return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable; no inspection report was copied."); return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(output));
    wxTheClipboard->Close();
    report(copied ? "Copied the visible debugger inspection snapshots as hexlab.debugger-inspection.v1 JSON."
                  : "Could not copy the debugger inspection report.");
}

void DebuggerView::copy_memory_address() {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        report("Enter a valid memory address before copying it.");
        return;
    }
    const auto text = wxString::Format("0x%llX", static_cast<unsigned long long>(address));
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(text));
    wxTheClipboard->Close();
    report(copied ? wxString("Copied memory address ") + text + " to the clipboard."
                  : wxString("Could not copy the memory address."));
}

void DebuggerView::copy_memory_search_matches() {
    if (memory_search_matches_.empty()) {
        report("There are no completed memory-search matches to copy.");
        return;
    }
    wxString text = "Match address\r\n";
    for (const auto address : memory_search_matches_)
        text += wxString::Format("0x%llX\r\n", static_cast<unsigned long long>(address));
    if (text.length() > 1024u * 1024u) {
        report("The memory-search result list exceeds the 1 MiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(text));
    wxTheClipboard->Close();
    report(copied
        ? wxString::Format("Copied %llu memory-search match address(es) to the clipboard.",
                           static_cast<unsigned long long>(memory_search_matches_.size()))
        : wxString("Could not copy memory-search matches."));
}

void DebuggerView::copy_memory_search_report() {
    if (!memory_search_report_) {
        report("There is no completed memory-search report to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    const auto &search = *memory_search_report_;
    const auto decimal = [](std::uint64_t value) { return json_quote_utf8(std::to_string(value)); };
    std::string json = "{\"schema\":\"hexlab.debugger-memory-search.v1\",\"completion\":" +
        json_quote_utf8(memory_search_completion_id(search.completion)) +
        std::string(",\"complete\":") + (search.complete() ? "true" : "false") +
        ",\"eligible_bytes\":" + decimal(search.eligible_bytes) +
        ",\"bytes_requested\":" + decimal(search.bytes_requested) +
        ",\"bytes_read\":" + decimal(search.bytes_read) +
        ",\"comparisons\":" + decimal(search.comparisons) +
        ",\"candidates_checked\":" + decimal(search.candidates_checked) +
        ",\"match_count\":" + decimal(static_cast<std::uint64_t>(search.matches.size())) +
        ",\"matches\":[";
    bool first = true;
    for (const auto address : search.matches) {
        if (!first) json.push_back(',');
        first = false;
        json += json_quote_utf8(wxString::Format("0x%llX",
            static_cast<unsigned long long>(address)).ToStdString());
        if (json.size() > max_copy_bytes) {
            report("Memory-search report JSON exceeds the 1 MiB clipboard limit.");
            return;
        }
    }
    json += "],\"failure_count\":" + decimal(static_cast<std::uint64_t>(search.failures.size())) +
        ",\"failures\":[";
    first = true;
    for (const auto &failure : search.failures) {
        if (!first) json.push_back(',');
        first = false;
        json += "{\"start\":" + json_quote_utf8(wxString::Format("0x%llX",
            static_cast<unsigned long long>(failure.range.start)).ToStdString()) +
            ",\"length\":" + json_quote_utf8(wxString::Format("0x%llX",
                static_cast<unsigned long long>(failure.range.length)).ToStdString()) +
            ",\"code\":" + json_quote_utf8(debugger_error_code_name(failure.error.code)) +
            ",\"message\":" + json_quote_utf8(failure.error.message) + "}";
        if (json.size() > max_copy_bytes) {
            report("Memory-search report JSON exceeds the 1 MiB clipboard limit.");
            return;
        }
    }
    json += "]}";
    if (json.size() > max_copy_bytes) {
        report("Memory-search report JSON exceeds the 1 MiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(json)));
    wxTheClipboard->Close();
    report(copied ? "Copied the memory-search report as JSON." :
                    "Could not copy the memory-search report.");
}

void DebuggerView::render_memory_search_matches() {
    memory_search_results_->DeleteAllItems();
    visible_memory_search_rows_.clear();
    const auto query = lower_register_text(narrow(memory_search_filter_->GetValue()));
    for (std::size_t index = 0; index < memory_search_matches_.size(); ++index) {
        const auto address = wxString::Format("0x%llX", static_cast<unsigned long long>(memory_search_matches_[index]));
        if (!query.empty() && lower_register_text(narrow(address)).find(query) == std::string::npos) continue;
        memory_search_results_->InsertItem(memory_search_results_->GetItemCount(), address);
        visible_memory_search_rows_.push_back(index);
    }
    memory_search_result_count_->SetLabel(wxString::Format("%llu visible / %llu hits",
        static_cast<unsigned long long>(visible_memory_search_rows_.size()),
        static_cast<unsigned long long>(memory_search_matches_.size())));
}

void DebuggerView::start_memory_search() {
    auto parsed = debugger::parse_memory_search_pattern(narrow(memory_search_pattern_->GetValue()));
    if (!parsed) {
        report("Invalid search pattern: " + wxString::FromUTF8(parsed.error().message));
        memory_search_status_->SetLabel("Invalid pattern.");
        return;
    }

    debugger::MemorySearchOptions options;
    const auto start_text = narrow(memory_search_start_->GetValue());
    const auto length_text = narrow(memory_search_length_->GetValue());
    if (start_text.empty() != length_text.empty()) {
        report("Enter both a range start and length, or leave both blank.");
        memory_search_status_->SetLabel("Range needs both a start and length.");
        return;
    }
    if (!start_text.empty()) {
        std::uint64_t start = 0, length = 0;
        if (!parse_unsigned(start_text, start) || !parse_unsigned(length_text, length) || length == 0 ||
            length > std::numeric_limits<std::uint64_t>::max() - start) {
            report("Enter a valid non-empty range that does not wrap the address space.");
            memory_search_status_->SetLabel("Invalid range.");
            return;
        }
        options.ranges.push_back({start, length});
    }
    std::uint64_t alignment = 0;
    if (!parse_unsigned(narrow(memory_search_alignment_->GetValue()), alignment) || alignment == 0) {
        report("Alignment must be a positive decimal or 0x-prefixed integer.");
        memory_search_status_->SetLabel("Invalid alignment.");
        return;
    }
    options.alignment = alignment;
    switch (memory_search_permissions_->GetSelection()) {
    case 1: options.executable = true; break;
    case 2: options.writable = true; break;
    case 3: options.executable = false; break;
    default: break;
    }

    memory_search_stop_.request_stop();
    memory_search_stop_ = std::stop_source{};
    const auto cancellation = memory_search_stop_.get_token();
    const auto generation = session_generation_;
    const auto request = ++memory_search_request_;
    auto pattern = std::move(parsed.value());
    auto session = session_;
    auto state = inspection_state_;
    memory_search_matches_.clear();
    memory_search_report_.reset();
    memory_search_filter_->ChangeValue({});
    render_memory_search_matches();
    memory_search_copy_button_->Disable();
    memory_search_report_button_->Disable();
    memory_search_status_->SetLabel("Searching mapped memory...");
    memory_search_start_button_->Disable();
    memory_search_cancel_button_->Enable();
    enqueue_inspection(7, [session, state, generation, request, cancellation,
                           pattern = std::move(pattern), options = std::move(options)]() mutable {
        std::string error;
        std::optional<debugger::MemorySearchReport> report;
        {
            std::lock_guard backend_lock(state->backend_mutex);
            auto result = session->search_memory(pattern, options, cancellation);
            if (result) report = std::move(result.value());
            else error = result.error().message;
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, error = std::move(error), report = std::move(report)]() mutable {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->memory_search_request_ != request) return;
            view->memory_search_start_button_->Enable();
            view->memory_search_cancel_button_->Disable();
            view->memory_search_matches_.clear();
            view->memory_search_report_.reset();
            view->render_memory_search_matches();
            view->memory_search_report_button_->Disable();
            if (!error.empty()) {
                view->memory_search_status_->SetLabel("Search failed: " + wxString::FromUTF8(error));
                view->report("Memory search failed: " + wxString::FromUTF8(error));
                return;
            }
            if (!report) return;
            view->memory_search_report_ = *report;
            view->memory_search_matches_ = report->matches;
            view->memory_search_copy_button_->Enable(!view->memory_search_matches_.empty());
            view->memory_search_report_button_->Enable();
            view->render_memory_search_matches();
            view->memory_search_status_->SetLabel(wxString::Format(
                "%s — %llu hit(s), %llu/%llu bytes read, %llu comparisons, %llu read failure(s).",
                memory_search_completion(report->completion),
                static_cast<unsigned long long>(report->matches.size()),
                static_cast<unsigned long long>(report->bytes_read),
                static_cast<unsigned long long>(report->bytes_requested),
                static_cast<unsigned long long>(report->comparisons),
                static_cast<unsigned long long>(report->failures.size())));
        });
    });
}

void DebuggerView::cancel_memory_search() {
    memory_search_stop_.request_stop();
    memory_search_cancel_button_->Disable();
    memory_search_status_->SetLabel("Canceling memory search...");
}

void DebuggerView::write_memory() {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        report("Enter a valid memory address before writing bytes."); return;
    }
    constexpr std::size_t max_write_bytes = 1024;
    const auto &input = memory_write_bytes_->GetValue();
    if (!memory_write_utf8_->GetValue() && input.length() > max_write_bytes * 3) {
        report("Memory write input exceeds the 1024-byte pane limit."); return;
    }
    std::vector<std::byte> bytes;
    if (memory_write_utf8_->GetValue()) {
        const auto encoded = input.ToUTF8();
        if (!encoded || encoded.length() == 0) {
            report("Enter non-empty UTF-8 text to write."); return;
        }
        if (encoded.length() > max_write_bytes) {
            report("Memory text write exceeds the 1024-byte pane limit."); return;
        }
        bytes.reserve(encoded.length());
        for (std::size_t index = 0; index < encoded.length(); ++index)
            bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(encoded.data()[index])));
    } else {
        bool too_many = false;
        if (!parse_hex_bytes(narrow(input), bytes, max_write_bytes, too_many)) {
            if (too_many) { report("Memory write input exceeds the 1024-byte pane limit."); return; }
            report("Enter non-empty hexadecimal bytes in pairs (for example: 90 C3)."); return;
        }
    }
    const int page = memory_page_size_->GetSelection();
    constexpr std::size_t page_sizes[] = {64, 256, 1024};
    const auto limit = page >= 0 && page < 3 ? page_sizes[page] : page_sizes[1];
    if (bytes.size() > limit) {
        report(wxString::Format("Write is limited to the selected %llu-byte memory page.",
                                static_cast<unsigned long long>(limit))); return;
    }
    if (address > UINT64_MAX - bytes.size()) {
        report("Memory write range would overflow the address space."); return;
    }
    auto result = [&] { std::lock_guard lock(inspection_state_->backend_mutex); return session_->write_memory(address, bytes); }();
    if (!result) { report(wxString::FromUTF8(result.error().message)); return; }
    memory_write_bytes_->Clear();
    refresh_memory();
    report(wxString::Format("Wrote %llu byte(s) at 0x%llX and refreshed memory.",
                            static_cast<unsigned long long>(bytes.size()),
                            static_cast<unsigned long long>(address)));
}

void DebuggerView::move_memory_page(int direction) {
    std::uint64_t address = 0;
    if (!parse_unsigned(narrow(memory_address_->GetValue()), address)) {
        memory_view_->SetValue("Memory paging failed: invalid address.");
        report("Enter a valid memory address (decimal or 0x-prefixed hexadecimal)."); return;
    }
    const int page = memory_page_size_->GetSelection();
    constexpr std::uint64_t page_sizes[] = {64, 256, 1024};
    const auto count = page >= 0 && page < 3 ? page_sizes[page] : page_sizes[1];
    if (direction < 0) {
        if (address < count) { report("Previous memory page would underflow the address space."); return; }
        address -= count;
    } else {
        if (address > UINT64_MAX - count) { report("Next memory page would overflow the address space."); return; }
        address += count;
    }
    memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(address)));
    refresh_memory();
}

void DebuggerView::refresh_modules() {
    invalidate_frames();
    modules_view_->DeleteAllItems();
    visible_module_rows_.clear();
    modules_.clear();
    module_filter_status_->SetLabel("Loading modules...");
    module_filter_->Disable();
    const auto generation = session_generation_;
    const auto request = ++module_request_;
    auto session = session_; auto state = inspection_state_;
    enqueue_inspection(3, [session, state, generation, request] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->modules();
        std::vector<debugger::ModuleInfo> values; std::string error;
        if (result) values = std::move(result.value()); else error = result.error().message;
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, values = std::move(values), error = std::move(error)]() mutable {
            std::unique_lock lock(state->mutex); auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->module_request_ != request) return;
            view->modules_.clear();
            view->visible_module_rows_.clear();
            if (!error.empty()) {
                view->modules_view_->InsertItem(0, "Unavailable: " + wxString::FromUTF8(error));
                view->module_filter_status_->SetLabel("Modules unavailable");
                view->module_filter_->Disable();
                view->render_breakpoints();
                view->report(wxString::FromUTF8(error)); return;
            }
            view->modules_ = std::move(values);
            view->module_filter_->Enable();
            view->render_modules();
            view->render_breakpoints();
            lock.unlock();
            view->refresh_locals();
        });
    });
}

void DebuggerView::render_modules(std::optional<std::size_t> preferred) {
    modules_view_->DeleteAllItems();
    visible_module_rows_.clear();
    wxString query = module_filter_ ? module_filter_->GetValue().Lower().Trim(true).Trim(false) : wxString{};
    const auto count = std::min<std::size_t>(modules_.size(), 4096);
    for (std::size_t index = 0; index < count; ++index) {
        const auto &module = modules_[index];
        const auto base = wxString::Format("0x%llX", static_cast<unsigned long long>(module.base));
        const auto size = wxString::Format("0x%llX", static_cast<unsigned long long>(module.size));
        const auto name = wxString::FromUTF8(module.name);
        const auto path = wxString::FromUTF8(module.path);
        if (!query.empty() && base.Lower().Find(query) == wxNOT_FOUND &&
            size.Lower().Find(query) == wxNOT_FOUND && name.Lower().Find(query) == wxNOT_FOUND &&
            path.Lower().Find(query) == wxNOT_FOUND)
            continue;
        visible_module_rows_.push_back(index);
    }
    const auto sort_mode = module_sort_->GetSelection();
    std::stable_sort(visible_module_rows_.begin(), visible_module_rows_.end(), [&](std::size_t left_index, std::size_t right_index) {
        const auto &left = modules_[left_index];
        const auto &right = modules_[right_index];
        if (sort_mode == 1) {
            const auto left_name = lower_register_text(left.name);
            const auto right_name = lower_register_text(right.name);
            if (left_name != right_name) return left_name < right_name;
        } else if (sort_mode == 2 && left.size != right.size) {
            return left.size > right.size;
        }
        return left.base < right.base;
    });
    for (const auto index : visible_module_rows_) {
        const auto &module = modules_[index];
        const auto base = wxString::Format("0x%llX", static_cast<unsigned long long>(module.base));
        const auto size = wxString::Format("0x%llX", static_cast<unsigned long long>(module.size));
        const auto name = wxString::FromUTF8(module.name);
        const auto path = wxString::FromUTF8(module.path);
        const auto row = modules_view_->InsertItem(modules_view_->GetItemCount(), base);
        modules_view_->SetItem(row, 1, size);
        modules_view_->SetItem(row, 2, name);
        modules_view_->SetItem(row, 3, path);
    }
    wxString status = wxString::Format("%llu of %llu modules",
        static_cast<unsigned long long>(visible_module_rows_.size()),
        static_cast<unsigned long long>(count));
    if (count < modules_.size()) status += wxString::Format(" shown (first 4096 of %llu)",
        static_cast<unsigned long long>(modules_.size()));
    module_filter_status_->SetLabel(status);
    if (preferred) {
        const auto selected = std::find(visible_module_rows_.begin(), visible_module_rows_.end(), *preferred);
        if (selected != visible_module_rows_.end())
            modules_view_->SetItemState(static_cast<long>(std::distance(visible_module_rows_.begin(), selected)),
                                        wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    }
}

void DebuggerView::copy_selected_module() {
    const auto row = modules_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_module_rows_.size()) {
        report("Select a loaded module before copying it.");
        return;
    }
    const auto source_row = visible_module_rows_[static_cast<std::size_t>(row)];
    if (source_row >= modules_.size()) {
        report("The selected module is no longer available; refresh the module list.");
        return;
    }
    const auto &module = modules_[source_row];
    const std::vector<std::string> fields{
        wxString::Format("0x%llX", static_cast<unsigned long long>(module.base)).ToStdString(),
        wxString::Format("0x%llX", static_cast<unsigned long long>(module.size)).ToStdString(),
        module.name, module.path, module.diagnostic};
    std::string text = "Base\tSize\tName\tPath\tDiagnostic\r\n";
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (index) text.push_back('\t');
        text += os_data_cell(fields[index]);
    }
    text += "\r\n";
    constexpr std::size_t max_copy_bytes = 64 * 1024;
    if (text.size() > max_copy_bytes) {
        report("Selected module details exceed the 64 KiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(text)));
    wxTheClipboard->Close();
    report(copied ? "Copied the selected module as TSV." : "Could not copy the selected module.");
}

void DebuggerView::copy_visible_modules() {
    if (visible_module_rows_.empty()) {
        report("There are no visible modules to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    std::string output = "Base\tSize\tName\tPath\tDiagnostic\r\n";
    for (const auto index : visible_module_rows_) {
        if (index >= modules_.size()) continue;
        const auto &module = modules_[index];
        const auto line = wxString::Format("0x%llX\t0x%llX\t",
            static_cast<unsigned long long>(module.base), static_cast<unsigned long long>(module.size)).ToStdString() +
            os_data_cell(module.name) + "\t" + os_data_cell(module.path) + "\t" +
            os_data_cell(module.diagnostic) + "\r\n";
        if (line.size() > max_copy_bytes - std::min(output.size(), max_copy_bytes)) {
            report("Visible module details exceed the 1 MiB clipboard limit.");
            return;
        }
        output += line;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(output)));
    wxTheClipboard->Close();
    report(copied ? "Copied visible modules as TSV." : "Could not copy visible modules.");
}

void DebuggerView::refresh_memory_regions() {
    memory_regions_view_->DeleteAllItems();
    visible_memory_region_rows_.clear();
    memory_regions_.clear();
    memory_region_filter_status_->SetLabel("Loading memory regions...");
    memory_region_filter_->Disable();
    memory_region_permission_filter_->Disable();
    memory_region_sort_->Disable();
    const auto generation = session_generation_;
    const auto request = ++region_request_;
    auto session = session_; auto state = inspection_state_;
    enqueue_inspection(4, [session, state, generation, request] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->memory_regions();
        std::vector<debugger::MemoryRegion> values; std::string error;
        if (result) values = std::move(result.value()); else error = result.error().message;
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, values = std::move(values), error = std::move(error)]() mutable {
            std::lock_guard lock(state->mutex); auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->region_request_ != request) return;
            view->memory_regions_.clear();
            view->visible_memory_region_rows_.clear();
            if (!error.empty()) {
                view->memory_regions_view_->InsertItem(0, "Unavailable: " + wxString::FromUTF8(error));
                view->memory_region_filter_status_->SetLabel("Memory regions unavailable");
                view->memory_region_filter_->Disable();
                view->memory_region_permission_filter_->Disable();
                view->memory_region_sort_->Disable();
                view->report(wxString::FromUTF8(error)); return;
            }
            view->memory_regions_ = std::move(values);
            view->memory_region_filter_->Enable();
            view->memory_region_permission_filter_->Enable();
            view->memory_region_sort_->Enable();
            view->render_memory_regions();
        });
    });
}

void DebuggerView::render_memory_regions(std::optional<std::uint64_t> preferred_start) {
    memory_regions_view_->DeleteAllItems();
    visible_memory_region_rows_.clear();
    wxString query = memory_region_filter_ ? memory_region_filter_->GetValue().Lower().Trim(true).Trim(false) : wxString{};
    const auto count = std::min<std::size_t>(memory_regions_.size(), 65536);
    const auto permission_filter = memory_region_permission_filter_->GetSelection();
    for (std::size_t index = 0; index < count; ++index) {
        const auto &region = memory_regions_[index];
        if ((permission_filter == 1 && !region.readable) ||
            (permission_filter == 2 && !region.writable) ||
            (permission_filter == 3 && !region.executable)) continue;
        const auto start = wxString::Format("0x%llX", static_cast<unsigned long long>(region.start));
        const auto size = wxString::Format("0x%llX", static_cast<unsigned long long>(region.length));
        const auto erase_block = region.flash_block_size
            ? wxString::Format("0x%llX", static_cast<unsigned long long>(*region.flash_block_size)) : wxString{};
        wxString permissions;
        permissions += region.readable ? "r" : "-";
        permissions += region.writable ? "w" : "-";
        permissions += region.executable ? "x" : "-";
        const auto type = wxString::FromUTF8(region.type);
        if (!query.empty() && start.Lower().Find(query) == wxNOT_FOUND &&
            size.Lower().Find(query) == wxNOT_FOUND && permissions.Find(query) == wxNOT_FOUND &&
            type.Lower().Find(query) == wxNOT_FOUND && erase_block.Lower().Find(query) == wxNOT_FOUND)
            continue;
        visible_memory_region_rows_.push_back(index);
    }
    const auto sort_mode = memory_region_sort_->GetSelection();
    std::stable_sort(visible_memory_region_rows_.begin(), visible_memory_region_rows_.end(),
        [&](std::size_t left_index, std::size_t right_index) {
            const auto &left = memory_regions_[left_index];
            const auto &right = memory_regions_[right_index];
            if (sort_mode == 1 && left.length != right.length) return left.length > right.length;
            if (sort_mode == 2) {
                const auto left_type = lower_register_text(left.type);
                const auto right_type = lower_register_text(right.type);
                if (left_type != right_type) return left_type < right_type;
            }
            return left.start < right.start;
        });
    for (const auto index : visible_memory_region_rows_) {
        const auto &region = memory_regions_[index];
        const auto start = wxString::Format("0x%llX", static_cast<unsigned long long>(region.start));
        const auto size = wxString::Format("0x%llX", static_cast<unsigned long long>(region.length));
        const auto erase_block = region.flash_block_size
            ? wxString::Format("0x%llX", static_cast<unsigned long long>(*region.flash_block_size)) : wxString("-");
        wxString permissions;
        permissions += region.readable ? "r" : "-";
        permissions += region.writable ? "w" : "-";
        permissions += region.executable ? "x" : "-";
        const auto type = wxString::FromUTF8(region.type);
        const auto row = memory_regions_view_->InsertItem(memory_regions_view_->GetItemCount(), start);
        memory_regions_view_->SetItem(row, 1, size);
        memory_regions_view_->SetItem(row, 2, permissions);
        memory_regions_view_->SetItem(row, 3, type);
        memory_regions_view_->SetItem(row, 4, erase_block);
        if (preferred_start && region.start == *preferred_start)
            memory_regions_view_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    }
    wxString status = wxString::Format("%llu of %llu regions",
        static_cast<unsigned long long>(visible_memory_region_rows_.size()),
        static_cast<unsigned long long>(count));
    if (count < memory_regions_.size()) status += wxString::Format(" shown (first 65536 of %llu)",
        static_cast<unsigned long long>(memory_regions_.size()));
    memory_region_filter_status_->SetLabel(status);
}

void DebuggerView::search_selected_memory_region() {
    const auto row = memory_regions_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_memory_region_rows_.size()) {
        report("Select a memory region before searching it."); return;
    }
    const auto source_row = visible_memory_region_rows_[static_cast<std::size_t>(row)];
    if (source_row >= memory_regions_.size()) {
        report("The selected memory region is no longer available; refresh the region list."); return;
    }
    const auto &region = memory_regions_[source_row];
    if (!region.readable) {
        report("The selected memory region is not readable and cannot be searched."); return;
    }
    if (region.length == 0 || region.length > std::numeric_limits<std::uint64_t>::max() - region.start) {
        report("The selected memory region has an invalid address range."); return;
    }
    memory_search_start_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(region.start)));
    memory_search_length_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(region.length)));
    memory_search_permissions_->SetSelection(0);
    memory_tabs_->SetSelection(1);
    start_memory_search();
}

void DebuggerView::open_selected_memory_region() {
    const auto row = memory_regions_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_memory_region_rows_.size()) {
        report("Select a memory region before opening it."); return;
    }
    const auto source_row = visible_memory_region_rows_[static_cast<std::size_t>(row)];
    if (source_row >= memory_regions_.size()) {
        report("The selected memory region is no longer available; refresh the region list."); return;
    }
    const auto &region = memory_regions_[source_row];
    memory_address_->SetValue(wxString::Format("0x%llX", static_cast<unsigned long long>(region.start)));
    memory_tabs_->SetSelection(0);
    refresh_memory();
}

void DebuggerView::copy_selected_memory_region() {
    const auto row = memory_regions_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= visible_memory_region_rows_.size()) {
        report("Select a memory region before copying it.");
        return;
    }
    const auto source_row = visible_memory_region_rows_[static_cast<std::size_t>(row)];
    if (source_row >= memory_regions_.size()) {
        report("The selected memory region is no longer available; refresh the region list.");
        return;
    }
    const auto &region = memory_regions_[source_row];
    std::string permissions;
    permissions += region.readable ? 'r' : '-';
    permissions += region.writable ? 'w' : '-';
    permissions += region.executable ? 'x' : '-';
    std::string text = "Start\tSize\tPermissions\tType\tErase block\r\n";
    text += wxString::Format("0x%llX\t0x%llX\t",
        static_cast<unsigned long long>(region.start),
        static_cast<unsigned long long>(region.length)).ToStdString();
    text += permissions + "\t" + os_data_cell(region.type) + "\t";
    text += region.flash_block_size
        ? wxString::Format("0x%llX", static_cast<unsigned long long>(*region.flash_block_size)).ToStdString()
        : std::string{};
    text += "\r\n";
    constexpr std::size_t max_copy_bytes = 64 * 1024;
    if (text.size() > max_copy_bytes) {
        report("Selected memory region details exceed the 64 KiB clipboard limit.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(text)));
    wxTheClipboard->Close();
    report(copied ? "Copied the selected memory region as TSV." :
                    "Could not copy the selected memory region.");
}

void DebuggerView::copy_visible_memory_regions() {
    if (visible_memory_region_rows_.empty()) {
        report("There are no visible memory regions to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 1024 * 1024;
    std::string output = "Start\tSize\tPermissions\tType\tErase block\r\n";
    std::size_t copied_rows = 0;
    for (const auto index : visible_memory_region_rows_) {
        if (index >= memory_regions_.size()) continue;
        const auto &region = memory_regions_[index];
        std::string permissions;
        permissions += region.readable ? 'r' : '-';
        permissions += region.writable ? 'w' : '-';
        permissions += region.executable ? 'x' : '-';
        const auto line = wxString::Format("0x%llX\t0x%llX\t",
            static_cast<unsigned long long>(region.start),
            static_cast<unsigned long long>(region.length)).ToStdString() +
            permissions + "\t" + os_data_cell(region.type) + "\t" +
            (region.flash_block_size
                ? wxString::Format("0x%llX", static_cast<unsigned long long>(*region.flash_block_size)).ToStdString()
                : std::string{}) + "\r\n";
        if (line.size() > max_copy_bytes - std::min(output.size(), max_copy_bytes)) {
            report("Visible memory-region details exceed the 1 MiB clipboard limit.");
            return;
        }
        output += line;
        ++copied_rows;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(output)));
    wxTheClipboard->Close();
    report(copied ? wxString::Format("Copied %llu visible memory region(s) as TSV.",
        static_cast<unsigned long long>(copied_rows)) :
        wxString("Could not copy visible memory regions."));
}

void DebuggerView::refresh_auxiliary_vector() {
    auxiliary_vector_view_->DeleteAllItems();
    auxiliary_vector_.clear();
    visible_auxiliary_vector_rows_.clear();
    auxiliary_vector_filter_->ChangeValue({});
    auxiliary_vector_filter_->Disable();
    auxiliary_vector_count_->SetLabel("0 of 0 entries");
    auxiliary_vector_copy_text_.clear();
    auxiliary_vector_copy_button_->Disable();
    const auto generation = session_generation_;
    const auto request = ++auxv_request_;
    auto session = session_; auto state = inspection_state_;
    enqueue_inspection(4, [session, state, generation, request] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->auxiliary_vector();
        std::vector<debugger::AuxiliaryVectorEntry> values; std::string error;
        if (result) values = std::move(result.value()); else error = result.error().message;
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, values = std::move(values), error = std::move(error)]() mutable {
            std::lock_guard lock(state->mutex); auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->auxv_request_ != request) return;
            view->auxiliary_vector_.clear();
            if (!error.empty()) {
                view->auxiliary_vector_copy_text_.clear();
                view->auxiliary_vector_copy_button_->Disable();
                view->auxiliary_vector_count_->SetLabel("Unavailable");
                view->auxiliary_vector_view_->InsertItem(0, "Unavailable");
                view->auxiliary_vector_view_->SetItem(0, 1, wxString::FromUTF8(error));
                view->report(wxString::FromUTF8(error));
                return;
            }
            view->auxiliary_vector_ = std::move(values);
            view->auxiliary_vector_filter_->Enable();
            view->render_auxiliary_vector();
            constexpr std::size_t max_copy_bytes = 4 * 1024 * 1024;
            std::string copy_text = "Type\tValue\r\n";
            bool copy_too_large = false;
            for (const auto &entry : view->auxiliary_vector_) {
                if (!copy_too_large) {
                    char value[32]{};
                    std::snprintf(value, sizeof(value), "%llX", static_cast<unsigned long long>(entry.value));
                    const auto line = std::to_string(entry.type) + "\t0x" + value + "\r\n";
                    if (line.size() > max_copy_bytes - std::min(copy_text.size(), max_copy_bytes)) {
                        copy_too_large = true;
                        copy_text.clear();
                    } else copy_text += line;
                }
            }
            view->auxiliary_vector_copy_text_ = std::move(copy_text);
            view->auxiliary_vector_copy_button_->Enable(!view->auxiliary_vector_copy_text_.empty());
            if (copy_too_large) view->report("Auxiliary vector exceeds the 4 MiB TSV clipboard limit.");
        });
    });
}

void DebuggerView::render_auxiliary_vector() {
    auxiliary_vector_view_->DeleteAllItems();
    visible_auxiliary_vector_rows_.clear();
    const auto query = lower_register_text(narrow(auxiliary_vector_filter_->GetValue()));
    std::size_t visible = 0;
    for (std::size_t index = 0; index < auxiliary_vector_.size(); ++index) {
        const auto &entry = auxiliary_vector_[index];
        const auto type_id = wxString::Format("%llu", static_cast<unsigned long long>(entry.type));
        const auto type_name = auxiliary_vector_type_name(entry.type);
        const auto type = type_name.empty() ? type_id : type_id + " " + wxString::FromUTF8(type_name.data(), type_name.size());
        const auto value = wxString::Format("0x%llX", static_cast<unsigned long long>(entry.value));
        if (!query.empty() && lower_register_text(narrow(type + " " + value)).find(query) == std::string::npos) continue;
        const auto row = auxiliary_vector_view_->InsertItem(auxiliary_vector_view_->GetItemCount(), type);
        auxiliary_vector_view_->SetItem(row, 1, value);
        visible_auxiliary_vector_rows_.push_back(index);
        ++visible;
    }
    auxiliary_vector_count_->SetLabel(wxString::Format("%llu of %llu entries",
        static_cast<unsigned long long>(visible), static_cast<unsigned long long>(auxiliary_vector_.size())));
}

void DebuggerView::copy_auxiliary_vector() {
    if (auxiliary_vector_copy_text_.empty()) {
        report("There is no complete auxiliary vector available to copy.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(auxiliary_vector_copy_text_)));
    wxTheClipboard->Close();
    report(copied ? "Copied the auxiliary vector as TSV." : "Could not copy the auxiliary vector.");
}

void DebuggerView::copy_visible_auxiliary_vector() {
    if (visible_auxiliary_vector_rows_.empty()) {
        report("There are no visible auxiliary-vector entries to copy.");
        return;
    }
    constexpr std::size_t max_copy_bytes = 4 * 1024 * 1024;
    std::string text = "Type\tValue\r\n";
    for (const auto index : visible_auxiliary_vector_rows_) {
        if (index >= auxiliary_vector_.size()) continue;
        const auto &entry = auxiliary_vector_[index];
        char value[32]{};
        std::snprintf(value, sizeof(value), "%llX", static_cast<unsigned long long>(entry.value));
        const auto line = std::to_string(entry.type) + "\t0x" + value + "\r\n";
        if (line.size() > max_copy_bytes - std::min(text.size(), max_copy_bytes)) {
            report("Visible auxiliary-vector entries exceed the 4 MiB TSV clipboard limit.");
            return;
        }
        text += line;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(text)));
    wxTheClipboard->Close();
    report(copied ? wxString::Format("Copied %llu visible auxiliary-vector entr%s as TSV.",
        static_cast<unsigned long long>(visible_auxiliary_vector_rows_.size()),
        visible_auxiliary_vector_rows_.size() == 1 ? "y" : "ies") :
        wxString("Could not copy visible auxiliary-vector entries."));
}

void DebuggerView::search_os_data(int direction) {
    const auto query = os_data_find_->GetValue();
    if (query.empty()) {
        os_data_find_status_->SetLabel("Enter text to find.");
        return;
    }
    const auto ascii_lower = [](wxString value) {
        for (std::size_t index = 0; index < value.length(); ++index) {
            const auto character = value[index];
            if (character >= 'A' && character <= 'Z')
                value[index] = wxUniChar(static_cast<wxUniChar::value_type>(character.GetValue() + 32u));
        }
        return value;
    };
    const auto output = os_data_view_->GetValue();
    const bool match_case = os_data_find_case_->GetValue();
    const auto searchable = match_case ? output : ascii_lower(output);
    const auto folded_query = match_case ? query : ascii_lower(query);
    const auto cursor = std::min(os_data_find_cursor_, static_cast<std::size_t>(searchable.length()));
    auto found = wxString::npos;
    bool wrapped = false;
    if (direction >= 0) {
        found = searchable.find(folded_query, cursor);
        if (found == wxString::npos && cursor > 0) {
            found = searchable.find(folded_query, 0);
            wrapped = found != wxString::npos;
        }
    } else {
        found = searchable.rfind(folded_query, cursor == 0 ? wxString::npos : cursor - 1);
        if (found == wxString::npos) {
            found = searchable.rfind(folded_query);
            wrapped = found != wxString::npos;
        }
        if (cursor == 0 && found != wxString::npos) wrapped = true;
    }
    if (found == wxString::npos) {
        os_data_find_status_->SetLabel("No match in displayed OS data.");
        os_data_view_->SetSelection(0, 0);
        return;
    }
    const auto end = found + folded_query.length();
    os_data_view_->SetSelection(static_cast<long>(found), static_cast<long>(end));
    os_data_view_->ShowPosition(static_cast<long>(found));
    os_data_find_cursor_ = direction >= 0 ? end : found;
    os_data_find_status_->SetLabel(wxString::Format("Character %llu%s",
        static_cast<unsigned long long>(found + 1), wrapped ? " (wrapped)" : ""));
}

void DebuggerView::refresh_os_data() {
    auto type = narrow(os_data_type_->GetValue());
    const auto first = std::find_if_not(type.begin(), type.end(), [](unsigned char c) { return std::isspace(c); });
    const auto last = std::find_if_not(type.rbegin(), type.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    if (first >= last) {
        report("Enter an OS-data table type, such as cpus or procgroups.");
        os_data_type_->SetFocus();
        return;
    }
    type = std::string(first, last);
    if (type.size() > 64 || !std::all_of(type.begin(), type.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '_';
        })) {
        report("OS-data type must use 1-64 ASCII letters, digits, '-' or '_'.");
        os_data_type_->SetFocus();
        return;
    }
    os_data_type_->SetValue(wxString::FromUTF8(type));
    os_data_view_->Clear();
    os_data_find_->ChangeValue({});
    os_data_find_cursor_ = 0;
    os_data_find_status_->SetLabel("");
    os_data_copy_text_.clear();
    os_data_copy_button_->Disable();
    const auto generation = session_generation_;
    const auto request = ++os_data_request_;
    auto session = session_;
    auto state = inspection_state_;
    os_data_view_->SetValue("Reading OS-data table...");
    enqueue_inspection(8, [session, state, generation, request, type = std::move(type)] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->os_data(type);
        std::string error;
        std::string rendered;
        std::string copy_text;
        bool copy_too_large = false;
        if (!result) {
            error = result.error().message;
        } else {
            rendered = "OS data: " + result.value().type + " (" +
                       std::to_string(result.value().rows.size()) + " rows)\n";
            constexpr std::size_t max_copy_bytes = 4 * 1024 * 1024;
            copy_text = "# OS data: " + os_data_cell(result.value().type) + "\r\nRow\tName\tValue\r\n";
            if (copy_text.size() > max_copy_bytes) {
                copy_text.clear();
                copy_too_large = true;
            }
            for (std::size_t row_index = 0; row_index < result.value().rows.size(); ++row_index) {
                if (copy_too_large) break;
                for (const auto &[name, value] : result.value().rows[row_index].columns) {
                    const auto line = std::to_string(row_index) + "\t" + os_data_cell(name) + "\t" + os_data_cell(value) + "\r\n";
                    if (line.size() > max_copy_bytes - std::min(copy_text.size(), max_copy_bytes)) {
                        copy_text.clear();
                        copy_too_large = true;
                        break;
                    }
                    copy_text += line;
                }
                if (copy_too_large) break;
            }
            constexpr std::size_t max_rendered_bytes = 4 * 1024 * 1024;
            bool truncated = false;
            for (std::size_t row_index = 0; row_index < result.value().rows.size(); ++row_index) {
                const auto heading = "\n[" + std::to_string(row_index) + "]\n";
                if (heading.size() > max_rendered_bytes - std::min(rendered.size(), max_rendered_bytes)) {
                    truncated = true;
                    break;
                }
                rendered += heading;
                for (const auto &[name, value] : result.value().rows[row_index].columns) {
                    const auto line = "  " + os_data_cell(name) + " = " + os_data_cell(value) + "\n";
                    if (line.size() > max_rendered_bytes - std::min(rendered.size(), max_rendered_bytes)) {
                        truncated = true;
                        break;
                    }
                    rendered += line;
                }
                if (truncated) break;
            }
            if (result.value().rows.empty()) rendered += "(no rows)\n";
            if (truncated) rendered += "\n[display truncated at 4 MiB]\n";
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, type, error = std::move(error),
                rendered = std::move(rendered), copy_text = std::move(copy_text), copy_too_large]() mutable {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->os_data_request_ != request ||
                narrow(view->os_data_type_->GetValue()) != type)
                return;
            if (!error.empty()) {
                view->os_data_copy_text_.clear();
                view->os_data_copy_button_->Disable();
                view->os_data_view_->SetValue(wxString("Unavailable: ") + wxString::FromUTF8(error));
                view->report(wxString::FromUTF8(error));
                return;
            }
            view->os_data_copy_text_ = std::move(copy_text);
            view->os_data_copy_button_->Enable(!view->os_data_copy_text_.empty());
            view->os_data_view_->SetValue(wxString::FromUTF8(rendered));
            if (copy_too_large) view->report("OS-data table exceeds the 4 MiB TSV clipboard limit.");
        });
    });
}

void DebuggerView::copy_os_data_table() {
    if (os_data_copy_text_.empty()) {
        report("There is no complete OS-data table available to copy.");
        return;
    }
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(wxString::FromUTF8(os_data_copy_text_)));
    wxTheClipboard->Close();
    report(copied ? "Copied the OS-data table as TSV." : "Could not copy the OS-data table.");
}

void DebuggerView::read_signal_info() {
    if (session_->state() != debugger::SessionState::stopped || !pending_event_) {
        signal_info_status_->SetLabel("Unavailable: there is no pending stopped event.");
        signal_info_view_->Clear();
        return;
    }
    const auto generation = session_generation_;
    const auto request = ++signal_info_request_;
    const auto sequence = *pending_event_;
    const auto thread = pending_event_thread_;
    const auto event_code = pending_event_code_;
    const auto siginfo_format = signal_info_format_->GetSelection();
    const auto process = session_->process();
    const auto architecture = process ? std::string(process_architecture_label(process->architecture)) : "unknown";
    auto session = session_;
    auto state = inspection_state_;
    signal_info_reading_ = true;
    signal_info_read_button_->Disable();
    signal_info_status_->SetLabel("Reading signal information for the pending event...");
    signal_info_view_->Clear();
    enqueue_inspection(2, [session, state, generation, request, sequence, thread, event_code, architecture, siginfo_format] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->signal_info();
        std::string error;
        std::string rendered;
        std::size_t byte_count = 0;
        bool unsupported = false;
        if (!result) {
            error = result.error().message;
            unsupported = result.error().code == ErrorCode::unsupported;
        } else if (result.value().size() > debugger::max_inspection_signal_info_bytes) {
            error = "backend returned more bytes than the 64 KiB signal-info limit.";
        } else {
            const auto& bytes = result.value();
            byte_count = bytes.size();
            rendered = "Raw target signal-info record (" + std::to_string(bytes.size()) + " bytes)\n";
            rendered += "Target architecture: " + architecture + "; event code: 0x";
            char code[16]{};
            const auto code_length = std::snprintf(code, sizeof(code), "%X", event_code);
            if (code_length > 0) rendered.append(code, static_cast<std::size_t>(code_length));
            rendered += ".\n";
            if (siginfo_format == 1 || siginfo_format == 2) {
                const auto pointer_bits = siginfo_format == 1 ? 32u : 64u;
                auto order = std::endian::native == std::endian::little ? ByteOrder::little : ByteOrder::big;
                if (const auto remote = session->remote_target_metadata()) {
                    if (!remote->endian_declared) {
                        error = "remote target description does not declare byte order; choose Raw target bytes.";
                    } else {
                        order = remote->big_endian ? ByteOrder::big : ByteOrder::little;
                    }
                }
                if (error.empty()) {
                    auto header = debugger::decode_linux_siginfo_header(bytes, pointer_bits, order);
                    if (!header) error = header.error().message;
                    else {
                        rendered += "Decoded Linux siginfo_t fixed header (user-selected " +
                            std::to_string(pointer_bits) + "-bit layout; union remains opaque):\n";
                        rendered += "  si_signo = " + std::to_string(header.value().signal_number) + "\n";
                        rendered += "  si_errno = " + std::to_string(header.value().error_number) + "\n";
                        rendered += "  si_code = " + std::to_string(header.value().code) + "\n";
                        rendered += "  signal-specific union bytes = " + std::to_string(header.value().union_bytes.size()) + "\n";
                    }
                }
            } else {
                rendered += "ABI fields are not decoded.\n";
            }
            rendered += "\n";
            constexpr char digits[] = "0123456789ABCDEF";
            for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
                char line[32]{};
                const auto line_length = std::snprintf(line, sizeof(line), "%08llX  ",
                    static_cast<unsigned long long>(offset));
                rendered.append(line, static_cast<std::size_t>(line_length));
                for (std::size_t i = 0; i < 16; ++i) {
                    if (offset + i < bytes.size()) {
                        const auto value = std::to_integer<unsigned>(bytes[offset + i]);
                        rendered.push_back(digits[value >> 4]);
                        rendered.push_back(digits[value & 15]);
                    } else rendered.append("  ");
                    rendered.push_back(' ');
                }
                rendered += " | ";
                for (std::size_t i = 0; i < 16 && offset + i < bytes.size(); ++i) {
                    const auto value = std::to_integer<unsigned char>(bytes[offset + i]);
                    rendered.push_back(value >= 32 && value < 127 ? static_cast<char>(value) : '.');
                }
                rendered.push_back('\n');
            }
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, sequence, thread,
                event_code, siginfo_format, error = std::move(error), rendered = std::move(rendered), byte_count, unsupported] {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->signal_info_request_ != request ||
                !view->pending_event_ || *view->pending_event_ != sequence ||
                view->pending_event_thread_ != thread || view->pending_event_code_ != event_code ||
                view->signal_info_format_->GetSelection() != siginfo_format)
                return;
            view->signal_info_reading_ = false;
            view->signal_info_read_button_->Enable(view->session_->state() == debugger::SessionState::stopped);
            if (!error.empty() && rendered.empty()) {
                view->signal_info_status_->SetLabel(wxString(unsupported ? "Unsupported: " : "Read failed: ") +
                    wxString::FromUTF8(error));
                view->signal_info_view_->SetValue(wxString::FromUTF8(error));
            } else {
                auto status = wxString::Format("%llu raw bytes for event %llu, ",
                    static_cast<unsigned long long>(byte_count), static_cast<unsigned long long>(sequence));
                status += thread ? wxString::Format("thread %llu.", static_cast<unsigned long long>(*thread))
                                 : wxString("thread unknown.");
                if (!error.empty()) status += " Linux header decode unavailable.";
                view->signal_info_status_->SetLabel(status);
                auto display = rendered;
                if (!error.empty()) display += "\nDecode unavailable: " + error + "\n";
                view->signal_info_view_->SetValue(wxString::FromUTF8(display));
            }
        });
    });
}

void DebuggerView::read_remote_file() {
    if (!remote_session_active_ || remote_connecting_ || !session_->process() ||
        session_->state() == debugger::SessionState::detached ||
        session_->state() == debugger::SessionState::faulted) {
        remote_file_status_->SetLabel("Unavailable: connect to an RSP target first.");
        remote_file_view_->Clear();
        return;
    }
    const auto path = narrow(remote_file_path_->GetValue());
    if (path.empty() || path.size() > 16 * 1024 || path.find('\0') != std::string::npos) {
        remote_file_status_->SetLabel("Path must contain 1 to 16384 non-NUL bytes.");
        remote_file_view_->Clear();
        return;
    }
    const auto generation = session_generation_;
    const auto request = ++remote_file_request_;
    auto session = session_;
    auto state = inspection_state_;
    remote_file_reading_ = true;
    remote_file_read_button_->Disable();
    remote_file_status_->SetLabel("Reading remote stub file (1 MiB limit)...");
    remote_file_view_->Clear();
    enqueue_inspection(2, [session, state, generation, request, path] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->read_remote_file(path, 1024 * 1024);
        std::string rendered;
        std::string error;
        bool unsupported = false;
        std::size_t byte_count = 0;
        if (!result) {
            error = result.error().message;
            unsupported = result.error().code == ErrorCode::unsupported;
        } else {
            const auto &bytes = result.value();
            byte_count = bytes.size();
            constexpr char digits[] = "0123456789ABCDEF";
            for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
                char line[32]{};
                const auto line_length = std::snprintf(line, sizeof(line), "%08llX  ",
                    static_cast<unsigned long long>(offset));
                rendered.append(line, static_cast<std::size_t>(line_length));
                for (std::size_t index = 0; index < 16; ++index) {
                    if (offset + index < bytes.size()) {
                        const auto value = std::to_integer<unsigned>(bytes[offset + index]);
                        rendered.push_back(digits[value >> 4]);
                        rendered.push_back(digits[value & 15]);
                    } else rendered.append("  ");
                    rendered.push_back(' ');
                }
                rendered += " | ";
                for (std::size_t index = 0; index < 16 && offset + index < bytes.size(); ++index) {
                    const auto value = std::to_integer<unsigned char>(bytes[offset + index]);
                    rendered.push_back(value >= 32 && value < 127 ? static_cast<char>(value) : '.');
                }
                rendered.push_back('\n');
            }
        }
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, path,
                error = std::move(error), rendered = std::move(rendered), byte_count, unsupported] {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->remote_file_request_ != request ||
                narrow(view->remote_file_path_->GetValue()) != path) return;
            view->remote_file_reading_ = false;
            view->remote_file_read_button_->Enable(view->remote_session_active_ && !view->remote_connecting_);
            if (!error.empty()) {
                view->remote_file_status_->SetLabel(wxString(unsupported ? "Unsupported: " : "Read failed: ") +
                    wxString::FromUTF8(error));
                view->remote_file_view_->SetValue(wxString::FromUTF8(error));
            } else {
                view->remote_file_status_->SetLabel(wxString::Format("%llu bytes read from the remote stub filesystem.",
                    static_cast<unsigned long long>(byte_count)));
                view->remote_file_view_->SetValue(wxString::FromUTF8(rendered));
            }
        });
    });
}

void DebuggerView::run_remote_monitor_command() {
    if (!remote_session_active_ || remote_connecting_ || !pending_event_ ||
        session_->state() != debugger::SessionState::stopped) {
        remote_monitor_status_->SetLabel("Unavailable: connect to an RSP target and stop it first.");
        remote_monitor_output_->Clear();
        return;
    }
    const auto command = narrow(remote_monitor_command_->GetValue());
    if (command.empty() || command.size() > 4096 || command.find('\0') != std::string::npos) {
        remote_monitor_status_->SetLabel("Command must contain 1 to 4096 non-NUL bytes.");
        remote_monitor_output_->Clear();
        return;
    }
    const auto generation = session_generation_;
    const auto request = ++remote_monitor_request_;
    const auto stop_sequence = *pending_event_;
    auto session = session_;
    auto state = inspection_state_;
    remote_monitor_running_ = true;
    remote_monitor_button_->Disable();
    remote_monitor_status_->SetLabel("Running remote qRcmd command...");
    remote_monitor_output_->Clear();
    enqueue_inspection(2, [session, state, generation, request, stop_sequence, command] {
        std::lock_guard backend_lock(state->backend_mutex);
        auto result = session->run_remote_monitor_command(command);
        std::string rendered;
        std::string error;
        bool unsupported = false;
        std::size_t byte_count = 0;
        bool truncated = false;
        if (!result) {
            error = result.error().message;
            unsupported = result.error().code == ErrorCode::unsupported;
        } else {
            constexpr char digits[] = "0123456789ABCDEF";
            const auto &bytes = result.value();
            byte_count = bytes.size();
            constexpr std::size_t display_limit = 64 * 1024;
            const auto count = std::min(bytes.size(), display_limit);
            truncated = count < bytes.size();
            rendered.reserve(count);
            for (std::size_t index = 0; index < count; ++index) {
                const auto value = std::to_integer<unsigned char>(bytes[index]);
                if (value == '\n' || value == '\r' || value == '\t' || (value >= 0x20 && value < 0x7f))
                    rendered.push_back(static_cast<char>(value));
                else {
                    rendered += "\\x";
                    rendered.push_back(digits[value >> 4]);
                    rendered.push_back(digits[value & 0x0f]);
                }
            }
        }
        if (rendered.empty() && error.empty()) rendered = "(no console output)";
        if (auto *app = wxTheApp) app->CallAfter([state, generation, request, stop_sequence, command,
                error = std::move(error), rendered = std::move(rendered), byte_count, truncated, unsupported] {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->remote_monitor_request_ != request ||
                !view->pending_event_ || *view->pending_event_ != stop_sequence ||
                narrow(view->remote_monitor_command_->GetValue()) != command) return;
            view->remote_monitor_running_ = false;
            view->remote_monitor_button_->Enable(view->remote_session_active_ && !view->remote_connecting_ &&
                view->session_->state() == debugger::SessionState::stopped && view->pending_event_.has_value());
            if (!error.empty()) {
                view->remote_monitor_status_->SetLabel(wxString(unsupported ? "Unsupported: " : "Command failed: ") +
                    wxString::FromUTF8(error));
                view->remote_monitor_output_->SetValue(wxString::FromUTF8(error));
            } else {
                auto status = wxString::Format("%llu output bytes captured", static_cast<unsigned long long>(byte_count));
                if (truncated) status += " (display limited to 64 KiB)";
                view->remote_monitor_status_->SetLabel(status);
                view->remote_monitor_output_->SetValue(wxString::FromUTF8(rendered));
            }
        });
    });
}

void DebuggerView::add_watch_expression() {
    auto expression = narrow(watch_expression_->GetValue());
    const auto first = std::find_if_not(expression.begin(), expression.end(), [](unsigned char c) { return std::isspace(c); });
    const auto last = std::find_if_not(expression.rbegin(), expression.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    if (first >= last) { report("Enter a watch expression first."); return; }
    expression = std::string(first, last);
    if (expression.size() > 256) { report("Watch expressions are limited to 256 bytes."); return; }
    if (watch_expressions_.size() >= 64) { report("The watch list is limited to 64 expressions."); return; }
    if (std::find(watch_expressions_.begin(), watch_expressions_.end(), expression) != watch_expressions_.end()) {
        report("That watch expression is already in the list."); return;
    }
    watch_expressions_.push_back(std::move(expression));
    reset_watch_baseline();
    save_watch_expressions();
    watch_expression_->Clear();
    refresh_watches();
}

void DebuggerView::update_watch_expression() {
    const auto row = watch_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= watch_expressions_.size()) {
        report("Select a watch expression to update."); return;
    }
    auto expression = narrow(watch_expression_->GetValue());
    const auto first = std::find_if_not(expression.begin(), expression.end(), [](unsigned char c) { return std::isspace(c); });
    const auto last = std::find_if_not(expression.rbegin(), expression.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    if (first >= last) { report("Enter a watch expression first."); return; }
    expression = std::string(first, last);
    if (expression.size() > 256) { report("Watch expressions are limited to 256 bytes."); return; }
    bool duplicate = false;
    for (std::size_t index = 0; index < watch_expressions_.size(); ++index)
        if (index != static_cast<std::size_t>(row) && watch_expressions_[index] == expression) duplicate = true;
    if (duplicate) {
        report("That watch expression is already in the list."); return;
    }
    watch_expressions_[static_cast<std::size_t>(row)] = std::move(expression);
    reset_watch_baseline();
    save_watch_expressions();
    refresh_watches();
    watch_view_->SetItemState(row, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    report("Updated watch expression.");
}

void DebuggerView::remove_watch_expression() {
    const auto row = watch_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= watch_expressions_.size()) {
        report("Select a watch expression to remove."); return;
    }
    watch_expressions_.erase(watch_expressions_.begin() + row);
    reset_watch_baseline();
    save_watch_expressions();
    refresh_watches();
}

void DebuggerView::refresh_watches() {
    watch_view_->DeleteAllItems();
    watch_values_.clear();
    watch_changes_.clear();
    const auto insert_rows = [&](const wxString &status) {
        for (const auto &expression : watch_expressions_) {
            const auto row = watch_view_->InsertItem(watch_view_->GetItemCount(), wxString::FromUTF8(expression));
            watch_view_->SetItem(row, 1, status);
            watch_view_->SetItem(row, 2, "");
            const auto encoded_status = status.ToUTF8();
            watch_values_.emplace_back(encoded_status.data(), encoded_status.length());
            watch_changes_.emplace_back();
        }
    };
    if (watch_expressions_.empty()) return;
    if (session_->state() != debugger::SessionState::stopped) {
        insert_rows("target is not stopped");
        return;
    }
    if (!selected_register_thread_) {
        insert_rows("select a stopped thread");
        return;
    }
    const auto selected = std::find_if(threads_.begin(), threads_.end(), [&](const auto &thread) {
        return thread.id == *selected_register_thread_;
    });
    if (selected == threads_.end() || selected->state != debugger::ThreadState::stopped) {
        insert_rows("selected thread is not stopped");
        return;
    }
    insert_rows("evaluating…");
    const auto thread = *selected_register_thread_;
    const auto generation = session_generation_;
    const auto stop = pending_event_;
    const auto request = ++watch_request_;
    const auto expressions = watch_expressions_;
    auto session = session_;
    auto state = inspection_state_;
    enqueue_inspection(6, [session, state, thread, generation, stop, request, expressions] {
        std::vector<std::string> values;
        values.reserve(expressions.size());
        {
            std::lock_guard backend_lock(state->backend_mutex);
            for (const auto &expression : expressions) {
                auto result = session->evaluate_expression(thread, expression);
                if (result) {
                    char value[32]{};
                    std::snprintf(value, sizeof(value), "0x%llX", static_cast<unsigned long long>(result.value()));
                    values.emplace_back(value);
                } else {
                    values.emplace_back("error: " + result.error().message);
                }
            }
        }
        if (auto *app = wxTheApp) app->CallAfter([state, thread, generation, stop, request,
                expressions, values = std::move(values)]() mutable {
            std::lock_guard lock(state->mutex);
            auto *view = state->target;
            if (!view || view->session_generation_ != generation || view->watch_request_ != request ||
                view->selected_register_thread_ != thread || view->pending_event_ != stop ||
                view->session_->state() != debugger::SessionState::stopped || view->watch_expressions_ != expressions)
                return;
            const bool comparable = view->previous_watch_thread_ == thread &&
                view->previous_watch_expressions_ == expressions && view->previous_watch_values_.size() == values.size();
            view->watch_changes_.clear();
            view->watch_changes_.reserve(values.size());
            for (std::size_t index = 0; index < values.size(); ++index) {
                if (values[index].starts_with("error:")) view->watch_changes_.emplace_back("Error");
                else if (!comparable) view->watch_changes_.emplace_back("Baseline");
                else view->watch_changes_.emplace_back(view->previous_watch_values_[index] == values[index] ? "Same" : "Changed");
            }
            view->previous_watch_thread_ = thread;
            view->previous_watch_expressions_ = expressions;
            view->previous_watch_values_ = values;
            view->watch_values_ = std::move(values);
            view->render_watch_values();
        });
    });
}

void DebuggerView::render_watch_values() {
    for (std::size_t index = 0; index < watch_values_.size() &&
         index < static_cast<std::size_t>(watch_view_->GetItemCount()); ++index)
    {
        watch_view_->SetItem(static_cast<long>(index), 1,
            watch_value_display(watch_values_[index], watch_value_format_->GetSelection()));
        watch_view_->SetItem(static_cast<long>(index), 2,
            index < watch_changes_.size() ? wxString::FromUTF8(watch_changes_[index]) : wxString{});
    }
}

void DebuggerView::copy_selected_watch() {
    const auto row = watch_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0) {
        report("Select a watch result to copy.");
        return;
    }
    const auto expression = watch_view_->GetItemText(row, 0);
    const auto value = watch_view_->GetItemText(row, 1);
    if (!wxTheClipboard || !wxTheClipboard->Open()) {
        report("The system clipboard is unavailable.");
        return;
    }
    const bool copied = wxTheClipboard->SetData(new wxTextDataObject(expression + "\t" + value));
    wxTheClipboard->Close();
    report(copied ? "Copied the selected watch expression and value." : "Could not copy the selected watch.");
}

void DebuggerView::move_watch_expression(int direction) {
    const auto row = watch_view_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
    if (row < 0 || static_cast<std::size_t>(row) >= watch_expressions_.size()) {
        report("Select a watch expression to move.");
        return;
    }
    const auto destination = static_cast<long>(row) + direction;
    if (destination < 0 || static_cast<std::size_t>(destination) >= watch_expressions_.size()) {
        report(direction < 0 ? "The selected watch is already first." : "The selected watch is already last.");
        return;
    }
    std::swap(watch_expressions_[static_cast<std::size_t>(row)], watch_expressions_[static_cast<std::size_t>(destination)]);
    reset_watch_baseline();
    if (watch_values_.size() == watch_expressions_.size())
        std::swap(watch_values_[static_cast<std::size_t>(row)], watch_values_[static_cast<std::size_t>(destination)]);
    if (watch_changes_.size() == watch_expressions_.size())
        std::swap(watch_changes_[static_cast<std::size_t>(row)], watch_changes_[static_cast<std::size_t>(destination)]);
    watch_view_->SetItem(row, 0, wxString::FromUTF8(watch_expressions_[static_cast<std::size_t>(row)]));
    watch_view_->SetItem(row, 1, watch_values_.size() == watch_expressions_.size()
        ? watch_value_display(watch_values_[static_cast<std::size_t>(row)], watch_value_format_->GetSelection()) : wxString{});
    watch_view_->SetItem(destination, 0, wxString::FromUTF8(watch_expressions_[static_cast<std::size_t>(destination)]));
    watch_view_->SetItem(destination, 1, watch_values_.size() == watch_expressions_.size()
        ? watch_value_display(watch_values_[static_cast<std::size_t>(destination)], watch_value_format_->GetSelection()) : wxString{});
    watch_view_->SetItem(row, 2, watch_changes_.size() == watch_expressions_.size()
        ? wxString::FromUTF8(watch_changes_[static_cast<std::size_t>(row)]) : wxString{});
    watch_view_->SetItem(destination, 2, watch_changes_.size() == watch_expressions_.size()
        ? wxString::FromUTF8(watch_changes_[static_cast<std::size_t>(destination)]) : wxString{});
    watch_view_->SetItemState(row, 0, wxLIST_STATE_SELECTED);
    watch_view_->SetItemState(destination, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
    watch_expression_->SetValue(wxString::FromUTF8(watch_expressions_[static_cast<std::size_t>(destination)]));
    save_watch_expressions();
    report("Moved watch expression.");
}

void DebuggerView::clear_inspection() {
    invalidate_frames();
    cancel_source_step_out();
    thread_schedule_snapshot_event_.reset();
    inspection_document_.reset();
    ++session_generation_;
    inspection_state_->session_generation.fetch_add(1, std::memory_order_acq_rel);
    inspection_state_->stop_generation.fetch_add(1, std::memory_order_acq_rel);
    ++register_request_; ++memory_request_; ++memory_tag_request_; ++module_request_; ++region_request_; ++auxv_request_; ++os_data_request_; ++locals_request_;
    ++signal_info_request_;
    ++memory_search_request_;
    ++watch_request_;
    memory_address_history_.clear();
    memory_address_history_position_ = 0;
    suppress_memory_history_record_ = false;
    update_memory_history_controls();
    memory_search_stop_.request_stop();
    {
        // Requests captured for the previous process cannot contribute to
        // the new inspection state. Drop them before accepting new work so
        // stale queued snapshots cannot delay the first result for a target.
        std::lock_guard lock(inspection_state_->mutex);
        inspection_state_->tasks.clear();
    }
    registers_.clear(); previous_registers_.clear(); previous_register_thread_.reset();
    pinned_registers_.clear(); pinned_register_thread_.reset();
    register_baseline_button_->SetLabel("Pin baseline");
    register_baseline_button_->SetToolTip("Compare future register snapshots with the selected thread's current values.");
    register_changes_.clear(); visible_register_rows_.clear();
    selected_register_thread_.reset(); selected_register_index_.reset();
    register_filter_->ChangeValue({});
    register_changed_only_->SetValue(false);
    register_filter_status_->SetLabel("0 of 0 registers");
    copy_thread_button_->Disable();
    thread_filter_->ChangeValue({});
    thread_state_filter_->SetSelection(0);
    visible_thread_rows_.clear();
    thread_filter_status_->SetLabel("0 of 0 threads");
    update_thread_selection_summary();
    registers_view_->DeleteAllItems(); register_value_->Clear();
    modules_.clear(); modules_view_->DeleteAllItems(); visible_module_rows_.clear();
    module_filter_->ChangeValue({}); module_filter_status_->SetLabel("0 of 0 modules");
    module_filter_->Enable();
    memory_regions_.clear(); memory_regions_view_->DeleteAllItems(); visible_memory_region_rows_.clear();
    memory_region_filter_->ChangeValue({}); memory_region_filter_status_->SetLabel("0 of 0 regions");
    memory_region_filter_->Enable();
    memory_region_permission_filter_->SetSelection(0);
    memory_region_permission_filter_->Enable();
    memory_region_sort_->SetSelection(0);
    memory_region_sort_->Enable();
    auxiliary_vector_.clear(); visible_auxiliary_vector_rows_.clear(); auxiliary_vector_view_->DeleteAllItems();
    auxiliary_vector_filter_->ChangeValue({}); auxiliary_vector_filter_->Disable();
    auxiliary_vector_count_->SetLabel("0 of 0 entries");
    auxiliary_vector_copy_text_.clear(); auxiliary_vector_copy_button_->Disable();
    os_data_view_->Clear();
    signal_info_reading_ = false;
    ++remote_file_request_;
    remote_file_reading_ = false;
    remote_file_view_->Clear();
    remote_file_status_->SetLabel("Connect to an RSP target to read remote files.");
    pending_event_code_ = 0;
    last_event_snapshot_.reset();
    thread_last_events_.clear();
    signal_info_view_->Clear();
    signal_info_status_->SetLabel("No pending stopped event.");
    os_data_find_->ChangeValue({});
    os_data_find_case_->SetValue(false);
    os_data_find_cursor_ = 0;
    os_data_find_status_->SetLabel("");
    os_data_copy_text_.clear(); os_data_copy_button_->Disable();
    locals_view_->DeleteAllItems();
    memory_view_->Clear(); memory_page_bytes_.clear(); memory_address_->Clear(); memory_tag_view_->Clear();
    memory_tag_status_->SetLabel("Memory tags are available when the selected stopped target supports tag reads.");
    memory_search_matches_.clear(); memory_search_report_.reset(); memory_search_results_->DeleteAllItems();
    memory_search_report_button_->Disable();
    memory_search_filter_->ChangeValue({}); visible_memory_search_rows_.clear();
    memory_search_result_count_->SetLabel("0 visible / 0 hits");
    memory_search_copy_button_->Disable();
    watch_values_.clear(); watch_changes_.clear(); watch_view_->DeleteAllItems();
    reset_watch_baseline();
    memory_search_status_->SetLabel("No memory search has run.");
    memory_search_start_button_->Enable(); memory_search_cancel_button_->Disable();
    update_thread_schedule_controls();
}

void DebuggerView::refresh_state() {
    using debugger::SessionState;
    const char *label = "Idle";
    switch (session_->state()) {
    case SessionState::idle: label = "Idle"; break;
    case SessionState::running: label = "Running"; break;
    case SessionState::stopped: label = "Stopped"; break;
    case SessionState::exited: label = "Exited"; break;
    case SessionState::detached: label = "Detached"; break;
    case SessionState::faulted: label = "Faulted"; break;
    }
    state_->SetValue(label);
    const bool can_read_tags = session_->state() == SessionState::stopped && session_->supports_memory_tag_read();
    memory_tag_read_button_->Enable(can_read_tags);
    if (!can_read_tags) {
        ++memory_tag_request_;
        memory_tag_view_->Clear();
        memory_tag_status_->SetLabel("Memory tags are available when the selected stopped target supports tag reads.");
    }
    const bool has_stopped_event = session_->state() == SessionState::stopped && pending_event_.has_value();
    signal_info_read_button_->Enable(has_stopped_event && !signal_info_reading_);
    if (!has_stopped_event) {
        ++signal_info_request_;
        signal_info_reading_ = false;
        signal_info_view_->Clear();
        signal_info_status_->SetLabel("No pending stopped event.");
    }
    const bool can_read_remote_file = remote_session_active_ && !remote_connecting_ &&
        session_->state() != SessionState::detached && session_->state() != SessionState::faulted;
    remote_file_read_button_->Enable(can_read_remote_file && !remote_file_reading_);
    if (!can_read_remote_file) {
        ++remote_file_request_;
        remote_file_reading_ = false;
        remote_file_view_->Clear();
        remote_file_status_->SetLabel("Connect to an RSP target to read remote files.");
    }
    const bool can_run_remote_monitor = remote_session_active_ && !remote_connecting_ &&
        session_->state() == SessionState::stopped && pending_event_.has_value();
    remote_monitor_button_->Enable(can_run_remote_monitor && !remote_monitor_running_);
    if (!can_run_remote_monitor) {
        ++remote_monitor_request_;
        remote_monitor_running_ = false;
        remote_monitor_output_->Clear();
        remote_monitor_status_->SetLabel("Connect to an RSP target and stop it before running monitor commands.");
    }
    const auto process = session_->process();
    if (process) {
        const auto name = process->name.empty() ? wxString("(unnamed)") : wxString::FromUTF8(process->name);
        target_identity_->SetValue(wxString::Format("%s (ID %llu)", name,
            static_cast<unsigned long long>(process->id)));
    } else {
        target_identity_->Clear();
    }
    update_process_actions();
    update_thread_schedule_controls();
}

void DebuggerView::report(const wxString &message) {
    const bool follow_output = !output_follow_ || output_follow_->GetValue();
    long old_insertion = log_->GetInsertionPoint();
    long old_selection_start = 0, old_selection_end = 0;
    log_->GetSelection(&old_selection_start, &old_selection_end);
    log_->AppendText(message + "\n");
    constexpr std::size_t output_limits[] = {32768, 131072, 1048576};
    const auto output_limit_index = output_retention_ ? output_retention_->GetSelection() : 0;
    const auto max_output_chars = output_limits[output_limit_index >= 0 && output_limit_index < 3
        ? static_cast<std::size_t>(output_limit_index) : 0];
    const wxString trimmed_marker = "[older debugger output trimmed]\n";
    auto output = log_->GetValue();
    std::size_t remove_to = 0;
    if (output.length() > max_output_chars) {
        const auto keep_limit = max_output_chars - trimmed_marker.length();
        const auto excess = output.length() - keep_limit;
        const auto newline = output.find('\n', excess);
        remove_to = newline == wxString::npos || newline + 1 > keep_limit ? excess : newline + 1;
        output.erase(0, remove_to);
        output.Prepend(trimmed_marker);
        log_->ChangeValue(output);
    }
    if (follow_output) {
        log_->SetInsertionPointEnd();
        return;
    }
    const auto adjust_position = [&](long position) {
        const auto old_position = static_cast<std::size_t>(std::max(0L, position));
        const auto relative = old_position > remove_to ? old_position - remove_to : 0;
        return static_cast<long>(std::min<std::size_t>(trimmed_marker.length() + relative, output.length()));
    };
    const auto insertion = adjust_position(old_insertion);
    const auto selection_start = adjust_position(old_selection_start);
    const auto selection_end = adjust_position(old_selection_end);
    log_->SetInsertionPoint(insertion);
    if (old_selection_start != old_selection_end)
        log_->SetSelection(selection_start, selection_end);
    log_->ShowPosition(insertion);
}
} // namespace hexlab::desktop
