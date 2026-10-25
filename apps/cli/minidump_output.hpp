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
        out << "  Thread " << thread.id << " stack=0x" << std::hex << thread.stack_address
            << "+0x" << thread.stack_size << std::dec << " context-bytes=" << thread.context_size << '\n';
        if (thread.context) minidump_context(out, *thread.context, "    ");
    }
    if (dump.threads.size() > count)
        out << "  (" << dump.threads.size() - count << " additional threads omitted from CLI summary)\n";
    if (dump.exception) {
        out << "  Exception thread=" << dump.exception->thread_id << " code=0x"
            << std::hex << dump.exception->code << " address=0x" << dump.exception->address << std::dec << '\n';
        if (dump.exception->context) minidump_context(out, *dump.exception->context, "    ");
    }
}
} // namespace hexlab::cli
