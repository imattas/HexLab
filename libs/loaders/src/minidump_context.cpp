#include "minidump_context.hpp"
#include <algorithm>
#include <array>

namespace hexlab::minidump_detail {
namespace {
std::uint64_t fixed(std::span<const std::byte> bytes, std::size_t at, std::size_t size) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < size; ++i) value |= std::uint64_t(std::to_integer<unsigned>(bytes[at + i])) << (i * 8);
    return value;
}
}
std::size_t context_prefix_size(std::uint16_t architecture) {
    switch (architecture) {
    case 0: return 716;  // Windows x86 CONTEXT including fixed FXSAVE storage.
    case 5: return 416;  // Windows ARM CONTEXT including trailing padding.
    case 9: return 1232; // Windows AMD64 fixed CONTEXT; no XSTATE following it.
    case 12: return 912; // Windows ARM64 fixed CONTEXT.
    default: return 64; // Retain evidence without inferring an architecture.
    }
}

MinidumpContext decode_context(std::uint16_t architecture, std::span<const std::byte> input,
                              std::uint32_t source_rva, std::uint32_t source_size) {
    MinidumpContext result;
    result.processor_architecture = architecture;
    result.source_rva = source_rva; result.source_size = source_size;
    const auto bytes = input.first(std::min({input.size(), static_cast<std::size_t>(source_size), context_prefix_size(architecture)}));
    result.captured_prefix.assign(bytes.begin(), bytes.end());
    const std::uint32_t family = architecture == 0 ? 0x10000u : architecture == 5 ? 0x200000u
        : architecture == 9 ? 0x100000u : architecture == 12 ? 0x400000u : 0;
    if (!family) {
        result.status = MinidumpContextStatus::unsupported_architecture;
        result.diagnostics.emplace_back("Context architecture is unsupported; captured prefix retained without register guesses");
        return result;
    }
    const std::size_t flags_at = architecture == 9 ? 48 : 0;
    if (flags_at > bytes.size() || bytes.size() - flags_at < 4) {
        result.status = MinidumpContextStatus::malformed;
        result.diagnostics.emplace_back("Context is truncated before ContextFlags");
        return result;
    }
    result.flags = static_cast<std::uint32_t>(fixed(bytes, flags_at, 4));
    result.requested_groups = result.flags & 0xffffu;
    if ((result.flags & 0x00ff0000u) != family) {
        result.status = MinidumpContextStatus::architecture_mismatch;
        result.diagnostics.emplace_back("ContextFlags architecture family does not match SystemInfo; registers were not decoded");
        return result;
    }
    result.architecture_valid = true;
    bool truncated = false;
    auto group = [&](std::uint32_t mask, std::size_t end, const char *name) {
        if (!(result.requested_groups & mask)) return false;
        if (bytes.size() < end) {
            truncated = true; result.diagnostics.emplace_back(std::string(name) + " context group is truncated");
            return false;
        }
        result.decoded_groups |= result.requested_groups & mask;
        return true;
    };
    auto add = [&](std::string name, std::size_t at, std::size_t size) {
        MinidumpRegister reg;
        reg.name = std::move(name); reg.width = static_cast<std::uint8_t>(size * 8);
        if (size <= 8) reg.value = fixed(bytes, at, size);
        reg.bytes.assign(bytes.begin() + static_cast<std::ptrdiff_t>(at), bytes.begin() + static_cast<std::ptrdiff_t>(at + size));
        reg.file_offset = {std::uint64_t{source_rva} + at};
        result.registers.push_back(std::move(reg));
    };
    auto debug_x86 = [&](std::size_t base, std::size_t width) {
        constexpr std::array<const char *, 6> names{"dr0", "dr1", "dr2", "dr3", "dr6", "dr7"};
        for (std::size_t i = 0; i < names.size(); ++i) add(names[i], base + i * width, width);
    };
    auto fxsave_x86 = [&]() {
        constexpr std::size_t base = 204;
        add("fcw",base,2); add("fsw",base+2,2); add("ftw",base+4,1); add("fop",base+6,2);
        add("fip",base+8,4); add("fcs",base+12,2); add("fdp",base+16,4); add("fds",base+20,2); add("mxcsr",base+24,4);
        for (std::size_t i = 0; i < 8; ++i) {
            add("st"+std::to_string(i),base+32+i*16,10);
            add("xmm"+std::to_string(i),base+160+i*16,16);
        }
    };
    if (architecture == 0) {
        if (group(2,180,"x86 integer")) {
            result.integer_valid = true;
            constexpr std::array<const char *,6> names{"edi","esi","ebx","edx","ecx","eax"};
            for (std::size_t i=0;i<names.size();++i) add(names[i],156+i*4,4);
        }
        if (group(1,204,"x86 control")) {
            result.control_valid = true;
            add("ebp",180,4); add("eip",184,4); add("cs",188,2); add("eflags",192,4); add("esp",196,4); add("ss",200,2);
        }
        if (group(4,156,"x86 segments")) {
            result.segments_valid = true;
            add("gs",140,2); add("fs",144,2); add("es",148,2); add("ds",152,2);
        }
        if (group(16,28,"x86 debug")) { result.debug_valid = true; debug_x86(4,4); }
        const bool legacy = group(8,140,"x86 x87");
        const bool extended = group(32,716,"x86 extended FXSAVE");
        if (extended) fxsave_x86();
        else if (legacy) {
            add("fcw",28,2); add("fsw",32,2); add("ftw",36,2); add("fip",40,4); add("fcs",44,2); add("fdp",48,4); add("fds",52,2);
            for (std::size_t i=0;i<8;++i) add("st"+std::to_string(i),56+i*10,10);
        }
        result.floating_valid = (legacy || extended) && (!(result.flags & 8) || legacy) && (!(result.flags & 32) || extended);
    } else if (architecture == 9) {
        if (group(2,248,"AMD64 integer")) {
            result.integer_valid = true;
            constexpr std::array<const char *,16> names{"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"};
            for (std::size_t i=0;i<names.size();++i) if (i!=4) add(names[i],120+i*8,8);
        }
        if (group(1,256,"AMD64 control")) {
            result.control_valid = true;
            add("cs",56,2); add("ss",66,2); add("eflags",68,4); add("rsp",152,8); add("rip",248,8);
        }
        if (group(4,66,"AMD64 segments")) {
            result.segments_valid = true;
            add("ds",58,2); add("es",60,2); add("fs",62,2); add("gs",64,2);
        }
        if (group(16,120,"AMD64 debug")) { result.debug_valid = true; debug_x86(72,8); }
        if (group(8,672,"AMD64 floating/XMM")) {
            result.floating_valid = true; add("mxcsr",52,4);
            add("fcw",256,2); add("fsw",258,2); add("ftw",260,1); add("fop",262,2);
            // Keep the serialized pointer fields as raw slots: their selector/
            // high-half interpretation differs between FXSAVE execution modes.
            add("fxsave_error_storage",264,8); add("fxsave_data_storage",272,8);
            add("fxsave_mxcsr",280,4);
            for (std::size_t i=0;i<8;++i) add("st"+std::to_string(i),288+i*16,10);
            for (std::size_t i=0;i<16;++i) add("xmm"+std::to_string(i),416+i*16,16);
        }
    } else if (architecture == 5) {
        if (group(2,56,"ARM integer")) {
            result.integer_valid = true;
            for (std::size_t i=0;i<13;++i) add("r"+std::to_string(i),4+i*4,4);
        }
        if (group(1,72,"ARM control")) {
            result.control_valid = true;
            add("sp",56,4); add("lr",60,4); add("pc",64,4); add("cpsr",68,4);
        }
        if (group(4,336,"ARM floating/NEON")) {
            result.floating_valid = true; add("fpscr",72,4);
            for (std::size_t i=0;i<32;++i) add("d"+std::to_string(i),80+i*8,8);
            for (std::size_t i=0;i<16;++i) add("q"+std::to_string(i),80+i*16,16);
        }
        if (group(8,408,"ARM debug")) {
            result.debug_valid = true;
            for (std::size_t i=0;i<8;++i) { add("bvr"+std::to_string(i),336+i*4,4); add("bcr"+std::to_string(i),368+i*4,4); }
            add("wvr0",400,4); add("wcr0",404,4);
        }
    } else {
        if (group(2,240,"ARM64 integer")) {
            result.integer_valid = true;
            for (std::size_t i=0;i<29;++i) if (i!=18) add("x"+std::to_string(i),8+i*8,8);
        }
        if (group(16,160,"ARM64 X18")) add("x18",152,8);
        if (group(1,272,"ARM64 control")) {
            result.control_valid = true;
            add("x29",240,8); add("x30",248,8); add("cpsr",4,4); add("sp",256,8); add("pc",264,8);
        }
        const bool full = (result.flags & 4) != 0;
        const bool low = group(full ? 4u|64u : 64u,792,"ARM64 low floating/NEON");
        const bool high = full ? low : group(128,784,"ARM64 high floating/NEON");
        if (full && low) result.decoded_groups |= result.requested_groups & 128u;
        result.floating_low_valid = low; result.floating_high_valid = high;
        result.floating_valid = (low || high) && (!(result.flags & (4u|64u)) || low) && (!(result.flags & (4u|128u)) || high);
        if (low) { add("fpcr",784,4); add("fpsr",788,4); }
        for (std::size_t i=0;i<32;++i) if ((i<16 && low) || (i>=16 && high)) add("v"+std::to_string(i),272+i*16,16);
        if (group(8,912,"ARM64 debug")) {
            result.debug_valid = true;
            for (std::size_t i=0;i<8;++i) { add("bcr"+std::to_string(i),792+i*4,4); add("bvr"+std::to_string(i),824+i*8,8); }
            for (std::size_t i=0;i<2;++i) { add("wcr"+std::to_string(i),888+i*4,4); add("wvr"+std::to_string(i),896+i*8,8); }
        }
    }
    const std::uint32_t supported = architecture == 0 ? 0x3fu : architecture == 9 ? 0x1fu : architecture == 5 ? 0xfu : 0xdfu;
    const bool extra = (result.requested_groups & ~supported) != 0;
    if (extra) result.diagnostics.emplace_back("Context requests unsupported extended/group flags; original source extent is retained");
    if (result.registers.empty() && !result.requested_groups) {
        result.status = MinidumpContextStatus::not_captured;
        result.diagnostics.emplace_back("ContextFlags declares no captured register group");
    } else if (result.registers.empty()) result.status = truncated ? MinidumpContextStatus::malformed : MinidumpContextStatus::partial;
    else result.status = truncated || extra ? MinidumpContextStatus::partial : MinidumpContextStatus::decoded;
    return result;
}
} // namespace hexlab::minidump_detail
