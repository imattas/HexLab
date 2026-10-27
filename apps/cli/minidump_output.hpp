#pragma once
#include "hexlab/image/metadata.hpp"
#include <algorithm>
#include <iomanip>
#include <ostream>

namespace hexlab::cli {
inline const char *minidump_architecture_name(std::uint16_t architecture) {
    switch (architecture) {
    case 0: return "x86";
    case 9: return "AMD64";
    case 12: return "ARM64";
    case 5: return "ARM";
    default: return "unknown";
    }
}
inline void minidump_context(std::ostream &out, const MinidumpContext &context, const char *indent) {
    out << indent << "Context architecture=" << minidump_architecture_name(context.processor_architecture)
        << " flags=0x" << std::hex << context.flags << std::dec
        << " control=" << (context.control_valid ? "valid" : "unavailable")
        << " integer=" << (context.integer_valid ? "valid" : "unavailable") << '\n';
    for (const auto &reg : context.registers) {
        out << indent << "  " << reg.name << "=0x" << std::hex;
        if (reg.width > 64) {
            constexpr char digits[] = "0123456789abcdef";
            for (auto it = reg.bytes.rbegin(); it != reg.bytes.rend(); ++it) {
                const auto byte = std::to_integer<unsigned>(*it);
                out << digits[byte >> 4] << digits[byte & 15];
            }
        } else out << reg.value;
        out << std::dec << '\n';
    }
    for (const auto &diagnostic : context.diagnostics)
        out << indent << "  Context note: " << diagnostic << '\n';
}
inline void minidump_quoted_text(std::ostream &out, const std::string &value) {
    constexpr std::size_t limit = 256;
    out << '"';
    for (std::size_t i = 0; i < std::min(value.size(), limit); ++i) {
        const auto byte = static_cast<unsigned char>(value[i]);
        if (byte == '"' || byte == '\\') out << '\\' << static_cast<char>(byte);
        else if (byte < 0x20 || byte == 0x7f) out << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                                                   << static_cast<unsigned>(byte) << std::dec << std::setfill(' ');
        else out << static_cast<char>(byte);
    }
    if (value.size() > limit) out << "...";
    out << '"';
}
inline void minidump_description(std::ostream &out, const ImageMetadata &metadata) {
    if (!metadata.minidump) return;
    const auto &dump = *metadata.minidump;
    out << "Minidump: architecture=" << minidump_architecture_name(dump.processor_architecture)
        << " threads=" << dump.threads.size() << " modules=" << dump.modules.size()
        << " memory-regions=" << dump.memory.size() << '\n';
    constexpr std::size_t max_threads = 256;
    const auto count = std::min(dump.threads.size(), max_threads);
    for (std::size_t i = 0; i < count; ++i) {
        const auto &thread = dump.threads[i];
        const auto name = std::lower_bound(dump.thread_names.begin(), dump.thread_names.end(), thread.id,
            [](const auto &row, std::uint32_t id) { return row.thread_id < id; });
        out << "  Thread " << thread.id << " stack=0x" << std::hex << thread.stack_address
            << "+0x" << thread.stack_size << std::dec << " context-bytes=" << thread.context_size;
        if (name != dump.thread_names.end() && name->thread_id == thread.id) {
            out << " name=";
            minidump_quoted_text(out, name->name);
        }
        out << '\n';
        if (thread.context) minidump_context(out, *thread.context, "    ");
    }
    if (dump.threads.size() > count)
        out << "  (" << dump.threads.size() - count << " additional threads omitted from CLI summary)\n";
    constexpr std::size_t max_modules = 256;
    const auto module_count = std::min(dump.modules.size(), max_modules);
    for (std::size_t i = 0; i < module_count; ++i) {
        const auto &module = dump.modules[i];
        out << "  Module " << module.name << " base=0x" << std::hex << module.image_base
            << " size=0x" << module.image_size << std::dec;
        if (module.codeview_kind == "RSDS") {
            out << " pdb=RSDS guid=";
            constexpr char hex[] = "0123456789abcdef";
            for (const auto byte : module.pdb_guid) {
                const auto value = std::to_integer<unsigned>(byte);
                out << hex[value >> 4] << hex[value & 15];
            }
            out << " age=" << module.pdb_age;
        } else if (module.codeview_kind == "NB10") {
            out << " pdb=NB10 timestamp=0x" << std::hex << module.pdb_timestamp << std::dec
                << " age=" << module.pdb_age;
        }
        if (!module.pdb_path.empty()) {
            out << " path=";
            minidump_quoted_text(out, module.pdb_path);
        }
        out << '\n';
    }
    if (dump.modules.size() > module_count)
        out << "  (" << dump.modules.size() - module_count << " additional modules omitted from CLI summary)\n";
    if (dump.exception) {
        const auto name = std::lower_bound(dump.thread_names.begin(), dump.thread_names.end(), dump.exception->thread_id,
            [](const auto &row, std::uint32_t id) { return row.thread_id < id; });
        out << "  Exception thread=" << dump.exception->thread_id << " code=0x"
            << std::hex << dump.exception->code << " address=0x" << dump.exception->address << std::dec;
        if (name != dump.thread_names.end() && name->thread_id == dump.exception->thread_id) {
            out << " name=";
            minidump_quoted_text(out, name->name);
        }
        out << '\n';
        if (dump.exception->context) minidump_context(out, *dump.exception->context, "    ");
    }
}
} // namespace hexlab::cli
