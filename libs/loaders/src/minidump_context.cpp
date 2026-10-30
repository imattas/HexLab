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
// Recognize only the classic AMX palettes. This is structural metadata, not
// an XRSTOR validator or a claim about the interrupted instruction's progress.
int amx_palette(std::span<const std::byte> config) {
    if (config.size() != 64) return -1;
    const auto palette = fixed(config, 0, 1);
    if (palette > 1) return -2;
    const auto zero = [&](std::size_t begin, std::size_t end) {
        return std::all_of(config.begin() + begin, config.begin() + end,
                           [](std::byte byte) { return byte == std::byte{0}; });
    };
    if (!palette) return zero(1, 64) ? 0 : -1;
    if (!zero(2, 16) || !zero(32, 48) || !zero(56, 64)) return -1;
    for (std::size_t tile = 0; tile < 8; ++tile) {
        const auto columns = fixed(config, 16 + tile * 2, 2);
        const auto rows = fixed(config, 48 + tile, 1);
        if (columns > 64 || rows > 16 || ((columns == 0) != (rows == 0))) return -1;
    }
    return 1;
}
}
std::size_t context_prefix_size(std::uint16_t architecture) {
    switch (architecture) {
    case 0: return 716;  // Windows x86 CONTEXT including fixed FXSAVE storage.
    case 5: return 416;  // Windows ARM CONTEXT including trailing padding.
    case 9: return 1232; // Windows AMD64 fixed CONTEXT; no XSTATE following it.
    case 12: return 912; // Windows ARM64 fixed CONTEXT.
    case 0x8003: return 796; // Breakpad ARM64 context (packed to four-byte alignment).
    default: return 64; // Retain evidence without inferring an architecture.
    }
}

MinidumpContext decode_context(std::uint16_t architecture, std::span<const std::byte> input,
                              std::uint32_t source_rva, std::uint32_t source_size,
                              std::uint32_t xstate_context_size,
                              std::span<const XstateFeatureInfo> xstate_features) {
    MinidumpContext result;
    result.processor_architecture = architecture;
    result.source_rva = source_rva; result.source_size = source_size;
    std::size_t decode_size = context_prefix_size(architecture);
    if (architecture == 9 && input.size() >= 52 && (fixed(input, 48, 4) & 0x40u))
        decode_size += 64u * 1024u;
    const auto bytes = input.first(std::min({input.size(), static_cast<std::size_t>(source_size), decode_size}));
    result.captured_prefix.assign(bytes.begin(), bytes.end());
    const std::uint64_t family = architecture == 0 ? 0x10000u : architecture == 5 ? 0x200000u
        : architecture == 9 ? 0x100000u : architecture == 12 ? 0x400000u
        : architecture == 0x8003 ? 0x80000000ull : 0;
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
    result.flags = fixed(bytes, flags_at, architecture == 0x8003 ? 8 : 4);
    result.requested_groups = result.flags & 0xffffu;
    const auto flags_family = architecture == 0x8003
        ? result.flags & 0xffffff00ull : result.flags & 0x00ff0000u;
    if (flags_family != family) {
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
        if (result.flags & 0x40u) {
            constexpr std::uint64_t xsave_area_in_context = 256;
            constexpr std::size_t xsave_header_in_context = 768;
            constexpr std::size_t xstate_chunk_bytes = 16;
            const bool xsave_header_valid = bytes.size() >= xsave_header_in_context + 16;
            const auto in_use = xsave_header_valid ? fixed(bytes, xsave_header_in_context, 8) : 0;
            const auto compacted = xsave_header_valid ? fixed(bytes, xsave_header_in_context + 8, 8) : 0;
            const bool compacted_format = (compacted & (std::uint64_t{1} << 63)) != 0;
            bool compacted_component_mismatch = false;
            if (compacted_format && xsave_header_valid) {
                // In compacted format every in-use non-legacy component must
                // have a slot in XCOMP_BV. Without the per-component compacted
                // alignment metadata we still cannot safely locate payloads,
                // but an impossible bitmap pair should be surfaced as partial.
                for (std::size_t index = 2; index < 63; ++index) {
                    const auto bit = std::uint64_t{1} << index;
                    if ((in_use & bit) && !(compacted & bit)) {
                        compacted_component_mismatch = true;
                        break;
                    }
                }
            }
            bool omitted = xstate_context_size == 0 || !xsave_header_valid;
            if (xsave_header_valid) {
                // These are the XSAVE header's architectural component bitmaps,
                // distinct from the OS feature map used to locate payloads.
                add("xstate_bv", xsave_header_in_context, 8);
                add("xcomp_bv", xsave_header_in_context + 8, 8);
            }
            std::uint64_t retained = 0;
            if (xsave_header_valid) {
                for (std::size_t index = 3; index < 64; ++index) {
                    if ((in_use & (std::uint64_t{1} << index)) &&
                        std::none_of(xstate_features.begin(), xstate_features.end(), [&](const auto &feature) {
                            return feature.index == index;
                        })) omitted = true;
                }
            }
            // Resolve TILECFG independently of feature table order. In addition
            // to the common source bounds below, AMX requires exact classic
            // sizes and nonoverlapping extended-component ranges. Never infer
            // this layout from an arbitrary future palette or enlarged state.
            auto amx_component = [&](std::uint8_t index, std::uint64_t required) -> std::span<const std::byte> {
                if (!xsave_header_valid || compacted_format || !(in_use & (std::uint64_t{1} << index))) return {};
                const auto feature = std::find_if(xstate_features.begin(), xstate_features.end(),
                    [&](const auto &row) { return row.index == index; });
                if (feature == xstate_features.end() || feature->size != required || feature->offset < 576 ||
                    feature->offset > xstate_context_size || required > xstate_context_size - feature->offset) return {};
                const std::uint64_t begin = xsave_area_in_context + feature->offset;
                if (begin > bytes.size() || required > bytes.size() - begin) return {};
                const std::uint64_t end = std::uint64_t{feature->offset} + required;
                for (const auto &other : xstate_features) {
                    if (&other == &*feature || other.index < 2) continue;
                    if (other.offset < end && feature->offset < std::uint64_t{other.offset} + other.size) return {};
                }
                return bytes.subspan(static_cast<std::size_t>(begin), static_cast<std::size_t>(required));
            };
            const auto tile_config = amx_component(17, 64);
            const auto tile_palette = amx_palette(tile_config);
            for (const auto &feature : xstate_features) {
                if (compacted_format) { omitted = true; continue; }
                // Features 0 and 1 (legacy FP and SSE) are represented by the
                // fixed AMD64 CONTEXT fields. Feature 2 stores the upper halves
                // of YMM0-YMM15 and is decoded separately below.
                if (feature.index < 2) continue;
                if (!(in_use & (std::uint64_t{1} << feature.index))) continue;
                const std::uint64_t offset = feature.offset;
                const std::uint64_t size = feature.size;
                if (!size || offset > xstate_context_size || size > xstate_context_size - offset ||
                    offset > UINT64_MAX - xsave_area_in_context ||
                    size > UINT64_MAX - xsave_area_in_context - offset) {
                    omitted = true;
                    result.diagnostics.emplace_back("AMD64 XSTATE feature has an invalid offset or size");
                    continue;
                }
                const std::uint64_t begin = xsave_area_in_context + offset;
                const std::uint64_t end = begin + size;
                if (end > bytes.size() || end > source_size ||
                    retained > 64u * 1024u || size > 64u * 1024u - retained) {
                    omitted = true;
                    continue;
                }
                retained += size;
                if (feature.index == 17 || feature.index == 18) {
                    const auto component = amx_component(feature.index, feature.index == 17 ? 64 : 8192);
                    if (feature.index == 17 && !component.empty() && tile_palette >= 0) {
                        // Keep the complete configuration image, including its
                        // reserved bytes, alongside the named field aliases.
                        for (std::size_t part = 0; part < 4; ++part)
                            add("amx_tilecfg_part" + std::to_string(part), static_cast<std::size_t>(begin + part * 16), 16);
                        add("amx_palette_id", static_cast<std::size_t>(begin), 1);
                        add("amx_start_row", static_cast<std::size_t>(begin + 1), 1);
                        if (tile_palette == 1) {
                            for (std::size_t tile = 0; tile < 8; ++tile) {
                                add("tmm" + std::to_string(tile) + "_colsb", static_cast<std::size_t>(begin + 16 + tile * 2), 2);
                                add("tmm" + std::to_string(tile) + "_rows", static_cast<std::size_t>(begin + 48 + tile), 1);
                            }
                        }
                        continue;
                    }
                    if (feature.index == 18 && !component.empty() && tile_palette == 1) {
                        // Retain all storage, including inactive rows/columns;
                        // no integer/float element type or zero-fill is inferred.
                        for (std::size_t tile = 0; tile < 8; ++tile)
                            for (std::size_t row = 0; row < 16; ++row)
                                for (std::size_t part = 0; part < 4; ++part)
                                    add("tmm" + std::to_string(tile) + "_row" + std::to_string(row) + "_part" + std::to_string(part),
                                        static_cast<std::size_t>(begin + tile * 1024 + row * 64 + part * 16), 16);
                        continue;
                    }
                    result.diagnostics.emplace_back(feature.index == 17
                        ? "AMD64 AMX TILECFG is not a supported, disjoint 64-byte palette 0/1 image; component retained as opaque chunks"
                        : "AMD64 AMX TILEDATA needs a disjoint 8192-byte image and captured valid palette 1 TILECFG; component retained as opaque chunks");
                }
                if (feature.index == 11) {
                    // Windows XSAVE_CET_U_FORMAT is two 64-bit values: IA32_U_CET
                    // followed by IA32_PL3_SSP. Keep any future/extended tail as
                    // opaque bytes instead of widening these architectural fields.
                    constexpr std::uint64_t cet_user_state_size = 16;
                    if (size < cet_user_state_size || end > bytes.size() || end > source_size) {
                        omitted = true;
                        result.diagnostics.emplace_back("AMD64 CET user-state component is shorter than its two 64-bit fields or outside the captured context");
                        continue;
                    }
                    add("ia32_u_cet", static_cast<std::size_t>(begin), 8);
                    add("ia32_pl3_ssp", static_cast<std::size_t>(begin + 8), 8);
                    for (std::uint64_t part = cet_user_state_size, at = begin + cet_user_state_size; at < end; ++part) {
                        const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(xstate_chunk_bytes, end - at));
                        add("xstate_feature_11_part_" + std::to_string(part / xstate_chunk_bytes),
                            static_cast<std::size_t>(at), chunk);
                        at += chunk;
                    }
                    continue;
                }
                if (feature.index == 9) {
                    // XSAVE component 9 contains a 32-bit PKRU value in an
                    // eight-byte component. Preserve the remaining bytes so
                    // reserved storage is not silently treated as zero.
                    constexpr std::uint64_t pkru_component_size = 8;
                    if (size != pkru_component_size) {
                        omitted = true;
                        result.diagnostics.emplace_back("AMD64 PKRU XSTATE component is not the supported eight-byte layout; bytes remain opaque");
                        continue;
                    }
                    const bool overlaps_another_feature = std::any_of(xstate_features.begin(), xstate_features.end(),
                        [&](const auto &other) {
                            return other.index >= 2 && other.index != feature.index &&
                                offset < std::uint64_t{other.offset} + other.size &&
                                other.offset < offset + size;
                        });
                    if (overlaps_another_feature) {
                        omitted = true;
                        result.diagnostics.emplace_back("AMD64 PKRU XSTATE component overlaps another feature-map entry; bytes remain opaque");
                        continue;
                    }
                    add("pkru", static_cast<std::size_t>(begin), 4);
                    add("pkru_reserved", static_cast<std::size_t>(begin + 4), 4);
                    continue;
                }
                if (feature.index == 2) {
                    constexpr std::uint64_t ymm_upper_size = 16u * 16u;
                    if (size < ymm_upper_size) {
                        omitted = true;
                        result.diagnostics.emplace_back("AMD64 AVX XSTATE component is shorter than the 16 YMM upper halves");
                        continue;
                    }
                    for (std::size_t reg = 0; reg < 16; ++reg)
                        add("ymm" + std::to_string(reg) + "_hi",
                            static_cast<std::size_t>(begin + reg * 16), 16);
                    for (std::uint64_t part = 0, at = begin + ymm_upper_size; at < end; ++part) {
                        const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(xstate_chunk_bytes, end - at));
                        add("xstate_feature_2_tail_" + std::to_string(part),
                            static_cast<std::size_t>(at), chunk);
                        at += chunk;
                    }
                    continue;
                }
                if (feature.index == 5) {
                    constexpr std::uint64_t opmask_state_size = 8u * 8u;
                    if (size < opmask_state_size) {
                        omitted = true;
                        result.diagnostics.emplace_back("AMD64 AVX-512 opmask component is shorter than eight 64-bit registers");
                        continue;
                    }
                    for (std::size_t reg = 0; reg < 8; ++reg)
                        add("k" + std::to_string(reg), static_cast<std::size_t>(begin + reg * 8), 8);
                    for (std::uint64_t at = begin + opmask_state_size, part = 0; at < end; ++part) {
                        const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(xstate_chunk_bytes, end - at));
                        add("xstate_feature_5_tail_" + std::to_string(part), static_cast<std::size_t>(at), chunk);
                        at += chunk;
                    }
                    continue;
                }
                if (feature.index == 6) {
                    constexpr std::uint64_t zmm_upper_state_size = 16u * 32u;
                    if (size < zmm_upper_state_size) {
                        omitted = true;
                        result.diagnostics.emplace_back("AMD64 AVX-512 ZMM_Hi256 component is shorter than the upper halves of ZMM0-ZMM15");
                        continue;
                    }
                    for (std::size_t reg = 0; reg < 16; ++reg)
                        for (std::size_t part = 0; part < 2; ++part)
                            add("zmm" + std::to_string(reg) + "_hi256_part" + std::to_string(part),
                                static_cast<std::size_t>(begin + reg * 32 + part * 16), 16);
                    for (std::uint64_t at = begin + zmm_upper_state_size, part = 0; at < end; ++part) {
                        const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(xstate_chunk_bytes, end - at));
                        add("xstate_feature_6_tail_" + std::to_string(part), static_cast<std::size_t>(at), chunk);
                        at += chunk;
                    }
                    continue;
                }
                if (feature.index == 7) {
                    constexpr std::uint64_t high_zmm_state_size = 16u * 64u;
                    if (size < high_zmm_state_size) {
                        omitted = true;
                        result.diagnostics.emplace_back("AMD64 AVX-512 Hi16_ZMM component is shorter than ZMM16-ZMM31");
                        continue;
                    }
                    for (std::size_t reg = 0; reg < 16; ++reg)
                        for (std::size_t part = 0; part < 4; ++part)
                            add("zmm" + std::to_string(reg + 16) + "_part" + std::to_string(part),
                                static_cast<std::size_t>(begin + reg * 64 + part * 16), 16);
                    for (std::uint64_t at = begin + high_zmm_state_size, part = 0; at < end; ++part) {
                        const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(xstate_chunk_bytes, end - at));
                        add("xstate_feature_7_tail_" + std::to_string(part), static_cast<std::size_t>(at), chunk);
                        at += chunk;
                    }
                    continue;
                }
                for (std::uint64_t part = 0, at = begin; at < end; ++part) {
                    const auto chunk = static_cast<std::size_t>(std::min<std::uint64_t>(xstate_chunk_bytes, end - at));
                    add("xstate_feature_" + std::to_string(feature.index) + "_part_" + std::to_string(part),
                        static_cast<std::size_t>(at), chunk);
                    at += chunk;
                }
            }
            if (xstate_context_size == 0) {
                result.diagnostics.emplace_back("AMD64 XSTATE is requested but no validated MiscInfo5 feature map is available");
            } else if (!xsave_header_valid) {
                result.diagnostics.emplace_back("AMD64 XSTATE header is truncated from the captured context");
            } else if (compacted_format) {
                omitted = true;
                result.diagnostics.emplace_back("AMD64 XSTATE header declares compacted XSAVE format; component payloads are not decoded");
                if (compacted_component_mismatch) {
                    truncated = true;
                    result.diagnostics.emplace_back("AMD64 compacted XSTATE bitmap marks an in-use non-legacy component absent from XCOMP_BV");
                }
            } else {
                result.diagnostics.emplace_back("AMD64 AVX, AVX-512, CET user and classic AMX components are decoded when supported and mapped; other XSTATE features remain opaque 16-byte chunks");
            }
            if (omitted && !compacted_format)
                result.diagnostics.emplace_back("Some AMD64 XSTATE feature bytes exceed the validated source extent or 64 KiB capture bound");
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
    } else if (architecture == 0x8003) {
        // Breakpad's packed ARM64 context predates the Microsoft CONTEXT
        // layout. Its integer group also carries the frame/link, SP, PC and CPSR.
        if (group(2,276,"legacy ARM64 integer/control")) {
            result.integer_valid = result.control_valid = true;
            for (std::size_t i=0;i<31;++i) add("x"+std::to_string(i),8+i*8,8);
            add("sp",256,8); add("pc",264,8); add("cpsr",272,4);
        }
        if (group(4,796,"legacy ARM64 floating/NEON")) {
            result.floating_valid = result.floating_low_valid = true;
            add("fpsr",276,4); add("fpcr",280,4);
            for (std::size_t i=0;i<32;++i) add("v"+std::to_string(i),284+i*16,16);
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
    const std::uint32_t supported = architecture == 0 ? 0x3fu : architecture == 9 ? 0x1fu : architecture == 5 ? 0xfu :
        architecture == 0x8003 ? 0x6u : 0xdfu;
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
