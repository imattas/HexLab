#include "debugger_locals.hpp"
#include "hexlab/workspace/document.hpp"
#include <filesystem>
#include <exception>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "hexlab/image/metadata.hpp"
#include "hexlab/image/pe_unwind.hpp"
#include "hexlab/loaders/elf_unwind.hpp"
#include "hexlab/loaders/macho_unwind.hpp"
#include "hexlab/workspace/project.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <climits>
#include <cstdio>
#include <limits>
#include <map>
#include <optional>
#include <string_view>

namespace hexlab::desktop {
std::optional<Address> DebuggerImageMapping::to_image(const Image &image, std::uint64_t pc) const {
    if (image.layout().architecture == Architecture::arm) pc &= ~UINT64_C(1);
    if (!size || pc < runtime_base || pc - runtime_base >= size) return {};
    const auto offset = pc - runtime_base;
    if (preferred_base > UINT64_MAX - offset) return {};
    Address address{image.layout().space.id, preferred_base + offset};
    const auto *segment = image.segment_at(address);
    if (!segment || !segment->executable || !image.code_window(address, 1)) return {};
    return address;
}
std::optional<std::uint64_t> DebuggerImageMapping::to_runtime(const Image &image, Address address) const {
    if (address.space != image.layout().space.id || address.offset < preferred_base) return {};
    const auto offset = address.offset - preferred_base;
    if (!size || offset >= size || runtime_base > UINT64_MAX - offset) return {};
    const auto runtime = runtime_base + offset;
    const auto mapped = to_image(image, runtime);
    return mapped && *mapped == address ? std::optional{runtime} : std::nullopt;
}
std::optional<DebuggerImageMapping> debugger_image_mapping(
    const DocumentSnapshot &document, const std::vector<debugger::ModuleInfo> &modules,
    Architecture architecture, std::string &reason) {
    const auto fail = [&](const char *message) -> std::optional<DebuggerImageMapping> {
        reason = message; return {};
    };
    try {
        if (!document.project || !document.project->loaded || !document.project->loaded->image ||
            !document.project->state || !document.project->state->provenance)
            return fail("Static mapping unavailable: open an image with source provenance.");
#ifdef _WIN32
        // Native provenance is UTF-16. ModuleInfo paths are explicitly UTF-8,
        // not strings in the current Windows ANSI code page.
        const auto normalize = [](const std::filesystem::path &path) {
            if (path.empty() || !path.is_absolute()) return std::wstring{};
            return path.lexically_normal().generic_wstring();
        };
        const auto valid_native = [](const std::wstring &value) {
            return value.size() <= static_cast<std::size_t>(INT_MAX) &&
                value.find(L'\0') == std::wstring::npos &&
                WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                    static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr) > 0;
        };
#else
        const auto normalize = [](const std::filesystem::path &path) {
            if (path.empty() || !path.is_absolute()) return std::string{};
            return path.lexically_normal().native();
        };
#endif
        const auto path = normalize(document.project->state->provenance->native_path);
        if (path.empty()) return fail("Static mapping unavailable: source path must be absolute.");
#ifdef _WIN32
        if (!valid_native(path))
            return fail("Static mapping unavailable: source path is not valid UTF-16 or exceeds the Windows comparison limit.");
#else
        if (path.find('\0') != std::string::npos)
            return fail("Static mapping unavailable: source path contains a null character.");
#endif
        const debugger::ModuleInfo *match = nullptr;
        for (const auto &module : modules) {
            if (module.path.empty()) continue;
#ifdef _WIN32
            if (module.path.size() > static_cast<std::size_t>(INT_MAX) ||
                module.path.find('\0') != std::string::npos)
                return fail("Static mapping unavailable: module path exceeds the Windows conversion limit or contains a null character.");
            const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                module.path.data(), static_cast<int>(module.path.size()), nullptr, 0);
            if (!length) return fail("Static mapping unavailable: module path is not valid UTF-8.");
            std::wstring native(static_cast<std::size_t>(length), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, module.path.data(),
                    static_cast<int>(module.path.size()), native.data(), length) != length)
                return fail("Static mapping unavailable: module path UTF-8 conversion failed.");
            const auto candidate = normalize(std::filesystem::path(native));
            if (candidate.empty()) continue;
            if (!valid_native(candidate))
                return fail("Static mapping unavailable: normalized module path is invalid or exceeds the Windows comparison limit.");
            const auto comparison = CompareStringOrdinal(path.data(), static_cast<int>(path.size()),
                candidate.data(), static_cast<int>(candidate.size()), TRUE);
            if (!comparison) return fail("Static mapping unavailable: Windows ordinal path comparison failed.");
            if (comparison != CSTR_EQUAL) continue;
#else
            if (module.path.find('\0') != std::string::npos)
                return fail("Static mapping unavailable: module path contains a null character.");
            if (normalize(std::filesystem::path(module.path)) != path) continue;
#endif
            if (match) return fail("Static mapping unavailable: multiple modules have the exact source path.");
            match = &module;
        }
        if (!match) return fail("Static mapping unavailable: no exact normalized module path match (basename matching is disabled).");
        const auto &loaded = *document.project->loaded;
        const auto &metadata = loaded.metadata;
        if (loaded.load_base && *loaded.load_base != metadata.preferred_base)
            return fail("Static mapping unavailable: explicitly rebased static images are not supported by frame inspection.");
        if (!match->size || !metadata.image_size || match->size != metadata.image_size)
            return fail("Static mapping unavailable: nonzero module and image sizes must agree.");
        if (architecture == Architecture::unknown || loaded.image->layout().architecture == Architecture::unknown ||
            architecture != loaded.image->layout().architecture)
            return fail("Static mapping unavailable: known compatible machine architecture is required.");
        if (match->base > UINT64_MAX - match->size || metadata.preferred_base > UINT64_MAX - metadata.image_size)
            return fail("Static mapping unavailable: module or preferred image extent overflows.");
        // ModuleInfo exposes no per-module machine, UUID/build ID or timestamp.
        // Use the target's known architecture; never invent a stronger identity proof.
        reason.clear();
        return DebuggerImageMapping{match->base, metadata.preferred_base, match->size};
    } catch (const std::exception &) {
        // Shared by queued inspection and direct UI actions: conversion errors
        // must become visible unavailable reasons rather than escape either path.
        return fail("Static mapping unavailable: path conversion or normalization failed.");
    }
}

namespace {
std::string lower(std::string_view text) {
    std::string value(text);
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::optional<std::uint64_t> parse_register_index(std::string_view text) {
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

std::optional<std::uint64_t> register_value(const debugger::RegisterValue &reg) {
    if (reg.bytes.empty() || reg.bytes.size() > 8) return std::nullopt;
    std::uint64_t value = 0;
    const bool big = reg.byte_order == ByteOrder::big;
    for (std::size_t i = 0; i < reg.bytes.size(); ++i) {
        const auto index = big ? i : reg.bytes.size() - 1 - i;
        value = (value << 8) | std::to_integer<std::uint8_t>(reg.bytes[index]);
    }
    return value;
}

std::optional<std::uint64_t> dwarf_register_number(Architecture architecture, std::string_view name) {
    const auto reg = lower(name);
    if (architecture == Architecture::x86_64) {
        static constexpr std::string_view names[] = {"rax","rdx","rcx","rbx","rsi","rdi","rbp","rsp",
            "r8","r9","r10","r11","r12","r13","r14","r15","rip"};
        for (std::uint64_t i = 0; i < std::size(names); ++i) if (reg == names[i]) return i;
    } else if (architecture == Architecture::x86) {
        static constexpr std::string_view names[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","eip"};
        for (std::uint64_t i = 0; i < std::size(names); ++i) if (reg == names[i]) return i;
    } else if (architecture == Architecture::arm64) {
        if (reg == "fp") return 29;
        if (reg == "lr") return 30;
        if (reg == "sp") return 31;
        if (reg == "pc") return 32;
        if (reg.size() >= 2 && reg[0] == 'x') {
            const auto index = parse_register_index(std::string_view(reg).substr(1));
            if (index && *index <= 30) return *index;
        }
        if (reg.size() >= 2 && reg[0] == 'd') {
            const auto index = parse_register_index(std::string_view(reg).substr(1));
            if (index && *index <= 31) return 64 + *index;
        }
    } else if (architecture == Architecture::arm) {
        if (reg == "fp") return 11;
        if (reg == "ip") return 12;
        if (reg == "sl") return 10;
        if (reg == "sb") return 9;
        if (reg == "sp") return 13;
        if (reg == "lr") return 14;
        if (reg == "pc") return 15;
        if (reg.size() >= 2 && reg[0] == 'r') {
            const auto index = parse_register_index(std::string_view(reg).substr(1));
            if (index && *index <= 15) return *index;
        }
    } else if (architecture == Architecture::riscv32 || architecture == Architecture::riscv64) {
        // DWARF 32 is F0, not PC. PC is carried separately by the unwinder.
        if (reg == "fp") return 8;
        static constexpr std::string_view aliases[] = {"zero","ra","sp","gp","tp","t0","t1","t2",
            "s0","s1","a0","a1","a2","a3","a4","a5","a6","a7","s2","s3","s4","s5",
            "s6","s7","s8","s9","s10","s11","t3","t4","t5","t6"};
        for (std::uint64_t i = 0; i < std::size(aliases); ++i) if (reg == aliases[i]) return i;
        if (reg.size() >= 2 && reg[0] == 'x') {
            const auto index = parse_register_index(std::string_view(reg).substr(1));
            if (index && *index <= 31) return *index;
        }
    }
    return std::nullopt;
}

const debugger::RegisterValue *dwarf_register(Architecture architecture, std::uint64_t number,
                                              const std::vector<debugger::RegisterValue> &registers) {
    for (const auto &reg : registers)
        if (dwarf_register_number(architecture, reg.name) == number) return &reg;
    return nullptr;
}

std::optional<std::uint64_t> dwarf_reg_value(Architecture architecture, std::uint64_t number,
                                              const std::vector<debugger::RegisterValue> &registers) {
    const auto *reg = dwarf_register(architecture, number, registers);
    return reg ? register_value(*reg) : std::nullopt;
}

std::string hex_value(std::uint64_t value) {
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

std::uint8_t address_size(const Image &image) {
    switch (image.layout().mode) {
    case ExecutionMode::x86_16: return 2;
    case ExecutionMode::x86_32: case ExecutionMode::a32: case ExecutionMode::thumb:
    case ExecutionMode::mips32: case ExecutionMode::rv32: case ExecutionMode::ppc32: return 4;
    default: return 8;
    }
}

constexpr std::array<std::string_view, 17> x64_register_names = {
    "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"};
constexpr std::array<std::string_view, 22> arm64_register_names = {
    "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", "X27", "X28",
    "X29", "X30", "SP", "PC", "D8", "D9", "D10", "D11", "D12", "D13", "D14", "D15"};
constexpr std::array<std::string_view, 16> arm_register_names = {
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "SP", "LR", "PC"};
constexpr std::array<std::string_view, 33> riscv_register_names = {
    "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", "X13", "X14", "X15",
    "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", "X27", "X28", "X29", "X30", "X31", "PC"};

std::optional<MachOUnwindRegister> macho_x64_register(std::string_view name) {
    const auto normalized = lower(name);
    if (normalized == "rbp") return MachOUnwindRegister::x86_64_rbp;
    if (normalized == "rsp") return MachOUnwindRegister::x86_64_rsp;
    if (normalized == "rip") return MachOUnwindRegister::x86_64_rip;
    if (normalized == "rbx") return MachOUnwindRegister::x86_64_rbx;
    if (normalized == "r12") return MachOUnwindRegister::x86_64_r12;
    if (normalized == "r13") return MachOUnwindRegister::x86_64_r13;
    if (normalized == "r14") return MachOUnwindRegister::x86_64_r14;
    if (normalized == "r15") return MachOUnwindRegister::x86_64_r15;
    return std::nullopt;
}

std::optional<MachOUnwindRegister> macho_arm64_register(std::string_view name) {
    const auto normalized = lower(name);
    if (normalized == "sp") return MachOUnwindRegister::arm64_sp;
    if (normalized == "pc") return MachOUnwindRegister::arm64_pc;
    if (normalized == "fp") return MachOUnwindRegister::arm64_x29;
    if (normalized == "lr") return MachOUnwindRegister::arm64_x30;
    if (normalized.size() >= 2 && normalized[0] == 'x') {
        const auto number = parse_register_index(std::string_view(normalized).substr(1));
        if (number && *number >= 19 && *number <= 30)
            return static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_x19) +
                                                    static_cast<unsigned>(*number - 19));
    }
    if (normalized.size() >= 2 && normalized[0] == 'd') {
        const auto number = parse_register_index(std::string_view(normalized).substr(1));
        if (number && *number >= 8 && *number <= 15)
            return static_cast<MachOUnwindRegister>(static_cast<unsigned>(MachOUnwindRegister::arm64_d8) +
                                                    static_cast<unsigned>(*number - 8));
    }
    return std::nullopt;
}

std::optional<std::size_t> variable_size(const ProjectSnapshot &project,
                                         const database::DebugVariable &variable) {
    if (!project.state || !project.state->user || !variable.type_id) return std::nullopt;
    const auto found = std::find_if(project.state->user->types.begin(), project.state->user->types.end(),
        [&](const auto &definition) { return definition.id == *variable.type_id; });
    // Keep previews bounded, but accept aggregates and scalar types wider than
    // a machine word. Those are displayed as bytes rather than truncated.
    if (found == project.state->user->types.end() || !found->type || !found->type->size() ||
        *found->type->size() == 0 || *found->type->size() > 256) return std::nullopt;
    return static_cast<std::size_t>(*found->type->size());
}

std::string byte_preview(std::span<const std::byte> bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result = "bytes[" + std::to_string(bytes.size()) + "] 0x";
    result.reserve(result.size() + bytes.size() * 2);
    for (const auto byte : bytes) {
        const auto value = std::to_integer<std::uint8_t>(byte);
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0xf]);
    }
    return result;
}

std::optional<std::uint64_t> pdb_register_number(Architecture architecture, std::uint16_t cv) {
    // CodeView register identifiers from cvconst.h. Keep this deliberately
    // narrow: an unknown identifier must never be treated as a guessed value.
    if (architecture == Architecture::x86_64) {
        static constexpr std::uint64_t dwarf_numbers[] = {0,3,2,1,4,5,6,7,8,9,10,11,12,13,14,15};
        if (cv >= 328 && cv <= 343) return dwarf_numbers[cv - 328];
    } else if (architecture == Architecture::x86) {
        static constexpr std::uint16_t ids[] = {17,18,19,20,21,22,23,24};
        for (std::uint64_t i = 0; i < std::size(ids); ++i) if (cv == ids[i]) return i;
    }
    return std::nullopt;
}

// Bind the whole extent, never just its first byte. Section ordinals belong
// to the identity-matched PDB/PE pair; overlapping declarations cannot supply
// an unambiguous code address even when the ordinal itself is valid.
std::optional<std::uint64_t> pdb_section_range(const ImageMetadata &metadata,
                                              const Image &image, std::uint64_t base,
                                              std::uint16_t section_number,
                                              std::uint32_t offset, std::uint32_t size) {
    if (!metadata.pe || !size || section_number == 0 || section_number > metadata.sections.size())
        return std::nullopt;
    const auto &section = metadata.sections[section_number - 1];
    const auto extent = std::max<std::uint64_t>(section.virtual_size, section.raw_size);
    const auto rva = std::uint64_t{section.rva.value} + offset;
    if (offset >= extent || size > extent - offset || rva >= metadata.image_size ||
        size > metadata.image_size - rva || rva > UINT64_MAX - base)
        return std::nullopt;
    const auto begin = base + rva;
    // Require a representable exclusive end as well as the address-space width.
    const auto width = image.layout().space.width_bits;
    if (size > UINT64_MAX - begin || !width || width > 64 ||
        (width < 64 && begin + size - 1 > ((UINT64_C(1) << width) - 1))) return std::nullopt;
    for (std::size_t index = 0; index < metadata.sections.size(); ++index) {
        if (index == static_cast<std::size_t>(section_number - 1)) continue;
        const auto &other = metadata.sections[index];
        const auto other_extent = std::max<std::uint64_t>(other.virtual_size, other.raw_size);
        if (other_extent && rva < std::uint64_t{other.rva.value} + other_extent &&
            other.rva.value < rva + size) return std::nullopt;
    }
    const Segment *mapped = nullptr;
    for (const auto &segment : image.layout().segments) {
        if (segment.begin.space != image.layout().space.id || !segment.size ||
            segment.begin.offset > UINT64_MAX - segment.size) continue;
        if (begin >= segment.begin.offset + segment.size || segment.begin.offset >= begin + size) continue;
        if (mapped || !segment.executable || begin < segment.begin.offset ||
            size > segment.size - (begin - segment.begin.offset)) return std::nullopt;
        mapped = &segment;
    }
    if (!mapped) return std::nullopt;
    return begin;
}

std::optional<std::size_t> pdb_type_size(const PeMetadata &metadata, std::uint32_t type_index,
                                         Architecture architecture) {
    if (type_index < 0x1000) {
        // Simple CodeView types encode the scalar kind in the low byte and
        // pointer mode in the high nibble.
        const auto mode = (type_index >> 8) & 0xf;
        if (mode != 0) return architecture == Architecture::x86_64 || architecture == Architecture::arm64 ? 8 : 4;
        switch (type_index & 0xff) {
        case 0x10: case 0x20: case 0x30: return 1;
        case 0x11: case 0x21: case 0x31: return 2;
        case 0x12: case 0x22: case 0x32: case 0x40: return 4;
        case 0x13: case 0x23: case 0x33: case 0x41: return 8;
        default: return std::nullopt;
        }
    }
    const auto type = std::find_if(metadata.pdb_types.begin(), metadata.pdb_types.end(),
        [&](const auto &candidate) { return candidate.index == type_index; });
    if (type == metadata.pdb_types.end() || !type->size || type->size > 256) return std::nullopt;
    return static_cast<std::size_t>(type->size);
}

struct SourceLocationView {
    std::string_view file;
    std::int64_t line = 0;
    std::uint64_t column = 0;
};

std::optional<std::string> source_location_at(const ImageMetadata &metadata, Address address) {
    constexpr std::size_t max_rows_per_lookup = 250'000;
    if (metadata.pe && metadata.pe->pdb_inline_sites.size() <= max_rows_per_lookup) {
        const PePdbInlineRange *best = nullptr;
        std::uint32_t depth = 0;
        bool conflict = false;
        std::size_t visited = 0;
        for (const auto &site : metadata.pe->pdb_inline_sites) for (const auto &range : site.ranges) {
            if (++visited > max_rows_per_lookup) return std::nullopt;
            if (!range.address || range.address->space != address.space || address.offset < range.address->offset ||
                address.offset - range.address->offset >= range.size || !range.line || range.source_path.empty()) continue;
            if (!best || site.depth > depth) {
                best = &range; depth = site.depth; conflict = false;
            } else if (site.depth == depth && (best->line != range.line || best->source_path != range.source_path)) {
                conflict = true;
            }
        }
        if (best) return conflict ? std::nullopt : std::optional<std::string>{
            best->source_path + ':' + std::to_string(best->line) + " (inline)"};
    }
    std::optional<SourceLocationView> result;
    bool ambiguous = false;
    const auto offer = [&](std::string_view file, std::int64_t line, std::uint64_t column) {
        if (file.empty() || line <= 0) return;
        if (result && (result->file != file || result->line != line || result->column != column)) {
            ambiguous = true;
            return;
        }
        result = SourceLocationView{file, line, column};
    };

    if (metadata.pe && metadata.pe->source_lines.size() <= max_rows_per_lookup) {
        const auto &pe = *metadata.pe;
        if (address.offset >= metadata.preferred_base) {
            const auto rva = address.offset - metadata.preferred_base;
            for (std::size_t index = 0; index < metadata.sections.size(); ++index) {
                const auto &section = metadata.sections[index];
                if (rva < section.rva.value) continue;
                const auto section_offset = rva - section.rva.value;
                const auto extent = std::max<std::uint64_t>(section.virtual_size, section.raw_size);
                if (section_offset >= extent) continue;
                const auto ordinal = static_cast<std::uint16_t>(index + 1);
                const PeSourceLine *previous = nullptr;
                const auto same_contribution = [](const PeSourceLine &left, const PeSourceLine &right) {
                    return left.section == right.section && left.reloc_offset == right.reloc_offset &&
                           left.contribution_size == right.contribution_size && left.module_index == right.module_index;
                };
                const auto flush = [&](const PeSourceLine *row, std::optional<std::uint64_t> next_offset) {
                    if (!row || row->section != ordinal || !row->contribution_size || !row->line ||
                        section_offset < row->section_offset ||
                        section_offset < row->reloc_offset ||
                        section_offset - row->reloc_offset >= row->contribution_size ||
                        (next_offset && section_offset >= *next_offset)) return;
                    offer(row->source_path, row->line, row->has_columns ? row->start_column : 0);
                };
                for (const auto &row : pe.source_lines) {
                    if (row.section != ordinal) continue;
                    if (!previous) {
                        previous = &row;
                        continue;
                    }
                    if (!same_contribution(*previous, row) || row.section_offset < previous->section_offset) {
                        flush(previous, std::nullopt);
                        previous = &row;
                        continue;
                    }
                    if (row.section_offset == previous->section_offset) {
                        if (section_offset == row.section_offset) {
                            flush(previous, row.section_offset);
                            flush(&row, std::nullopt);
                        }
                        previous = &row;
                        continue;
                    }
                    flush(previous, row.section_offset);
                    previous = &row;
                }
                flush(previous, std::nullopt);
                break;
            }
        }
    } else if (metadata.elf && metadata.elf->source_lines.size() <= max_rows_per_lookup) {
        const ElfSourceLine *previous = nullptr;
        for (const auto &row : metadata.elf->source_lines) {
            if (previous && previous->address.space == address.space && row.address.space == address.space &&
                row.address.offset > previous->address.offset && address.offset >= previous->address.offset &&
                address.offset < row.address.offset)
                offer(previous->file, previous->line, previous->column);
            if (row.end_sequence || (previous && row.address.offset < previous->address.offset))
                previous = nullptr;
            else
                previous = &row;
        }
    } else if (metadata.macho && metadata.macho->source_lines.size() <= max_rows_per_lookup) {
        const MachOSourceLine *previous = nullptr;
        for (const auto &row : metadata.macho->source_lines) {
            if (previous && previous->address && row.address &&
                previous->address->space == address.space && row.address->space == address.space &&
                row.address->offset > previous->address->offset && address.offset >= previous->address->offset &&
                address.offset < row.address->offset)
                offer(previous->file, previous->line, previous->column);
            if (row.end_sequence || !row.address ||
                (previous && row.raw_address < previous->raw_address))
                previous = nullptr;
            else
                previous = &row;
        }
    }

    if (!result || ambiguous) return std::nullopt;
    std::string formatted(result->file);
    formatted += ':';
    formatted += std::to_string(result->line);
    if (result->column) {
        formatted += ':';
        formatted += std::to_string(result->column);
    }
    return formatted;
}
}

std::optional<DebuggerSymbolizedAddress> symbolize_debugger_address(
    const ProjectSnapshot &project, const Image &image, std::uint64_t runtime_pc,
    std::uint64_t module_base, std::uint64_t module_size) {
    if (image.layout().architecture == Architecture::arm) runtime_pc &= ~UINT64_C(1);
    if (!project.loaded || runtime_pc < module_base) return std::nullopt;
    const auto displacement = runtime_pc - module_base;
    if (module_size && displacement >= module_size) return std::nullopt;
    std::uint64_t static_base = project.loaded->metadata.preferred_base;
    if (!static_base && !image.layout().segments.empty())
        static_base = std::min_element(image.layout().segments.begin(), image.layout().segments.end(),
            [](const auto &left, const auto &right) { return left.begin.offset < right.begin.offset; })->begin.offset;
    if (static_base > UINT64_MAX - displacement) return std::nullopt;
    const Address image_address{image.layout().space.id, static_base + displacement};
    const auto source_location = source_location_at(project.loaded->metadata, image_address);

    std::shared_ptr<const FunctionRecord> owner;
    std::uint64_t smallest_chunk = UINT64_MAX;
    if (project.functions) {
        for (const auto &function : project.functions->functions) {
            if (!function) continue;
            for (const auto &chunk : function->chunks) {
                if (chunk.begin.space != image_address.space || !chunk.size ||
                    image_address.offset < chunk.begin.offset ||
                    image_address.offset - chunk.begin.offset >= chunk.size)
                    continue;
                if (chunk.size < smallest_chunk ||
                    (chunk.size == smallest_chunk && function->entry == image_address)) {
                    owner = function;
                    smallest_chunk = chunk.size;
                }
            }
        }
    }
    if (owner) {
        const auto displacement_from_entry = image_address.offset >= owner->entry.offset
            ? image_address.offset - owner->entry.offset : 0;
        return DebuggerSymbolizedAddress{image_address,
            presentation_name(project, Location{owner->entry}), owner->entry,
            displacement_from_entry, source_location};
    }
    if (auto annotation = annotation_at(project, Location{image_address});
        annotation && !annotation->name.empty())
        return DebuggerSymbolizedAddress{image_address, annotation->name, {}, 0, source_location};
    auto symbol = presentation_name(project, Location{image_address});
    const auto generated_prefix = "sub_" + std::to_string(image_address.space.value) + "_";
    if (!symbol.empty() && !symbol.starts_with(generated_prefix))
        return DebuggerSymbolizedAddress{image_address, std::move(symbol), {}, 0, source_location};
    if (source_location)
        return DebuggerSymbolizedAddress{image_address, {}, {}, 0, source_location};
    return std::nullopt;
}

std::vector<DebuggerStackFrame> debugger_stack_frames_at(
    const Image &image, std::uint64_t runtime_pc, std::uint64_t module_base, std::uint64_t module_size,
    Architecture architecture, const std::vector<debugger::RegisterValue> &registers,
    const MachOMetadata *macho,
    const std::function<Result<std::vector<std::byte>>(std::uint64_t, std::size_t)> &read_memory,
    std::size_t max_frames, std::uint64_t preferred_base, const ElfMetadata *elf, const PeMetadata *pe) {
    std::vector<DebuggerStackFrame> frames;
    if (architecture == Architecture::arm) runtime_pc &= ~UINT64_C(1);
    if (!runtime_pc || !max_frames) return frames;
    max_frames = std::min<std::size_t>(max_frames, 128);
    frames.push_back({runtime_pc, {}, registers, 0});
    if (pe && read_memory && (architecture == Architecture::x86_64 || architecture == Architecture::arm64) &&
        runtime_pc >= module_base && (!module_size || runtime_pc - module_base < module_size)) {
        std::uint64_t static_base = preferred_base;
        if (!static_base && !image.layout().segments.empty())
            static_base = std::min_element(image.layout().segments.begin(), image.layout().segments.end(),
                [](const auto &left, const auto &right) { return left.begin.offset < right.begin.offset; })->begin.offset;
        const auto displacement = runtime_pc - module_base;
        if (static_base > UINT64_MAX - displacement) return frames;
        auto current_runtime_pc = runtime_pc;
        const auto pc_name = architecture == Architecture::x86_64 ? std::string_view("rip") : std::string_view("pc");
        const auto sp_name = architecture == Architecture::x86_64 ? std::string_view("rsp") : std::string_view("sp");
        PeRegisterContext context;
        for (const auto &reg : registers) {
            const auto value = register_value(reg);
            auto name = lower(reg.name);
            if (architecture == Architecture::arm64) {
                if (name == "x29") name = "fp";
                else if (name == "x30") name = "lr";
            }
            if (value) {
                auto &bytes = context.registers[name];
                bytes.resize(reg.bytes.size());
                for (std::size_t i = 0; i < bytes.size(); ++i)
                    bytes[i] = static_cast<std::byte>((*value >> (i * 8)) & 0xff);
            } else if (!reg.bytes.empty() && reg.bytes.size() <= 256) {
                auto bytes = reg.bytes;
                if (reg.byte_order == ByteOrder::big) std::reverse(bytes.begin(), bytes.end());
                context.registers[name] = std::move(bytes);
            }
        }
        std::uint64_t previous_sp = 0;
        if (const auto sp = context.registers.find(sp_name); sp != context.registers.end() && sp->second.size() == 8)
            for (unsigned i = 0; i < 8; ++i) previous_sp |= std::uint64_t(std::to_integer<std::uint8_t>(sp->second[i])) << (8 * i);
        std::vector<std::uint64_t> seen{runtime_pc};
        while (frames.size() < max_frames) {
            auto unwind = unwind_pe_frame(*pe, architecture, module_base, current_runtime_pc, context,
                [&](std::uint64_t address, std::size_t size) { return read_memory(address, size); });
            if (!unwind) break;
            const auto pc_it = unwind.value().registers.find(pc_name);
            const auto sp_it = unwind.value().registers.find(sp_name);
            if (pc_it == unwind.value().registers.end() || pc_it->second.size() != 8 ||
                sp_it == unwind.value().registers.end() || sp_it->second.size() != 8) break;
            std::uint64_t next_pc = 0, next_sp = 0;
            for (unsigned i = 0; i < 8; ++i) {
                next_pc |= std::uint64_t(std::to_integer<std::uint8_t>(pc_it->second[i])) << (8 * i);
                next_sp |= std::uint64_t(std::to_integer<std::uint8_t>(sp_it->second[i])) << (8 * i);
            }
            if (!next_pc || next_pc == current_runtime_pc || next_sp <= previous_sp ||
                std::find(seen.begin(), seen.end(), next_pc) != seen.end()) break;
            frames.back().call_frame_cfa = next_sp;
            if (next_pc < module_base || (module_size && next_pc - module_base >= module_size)) break;
            std::vector<debugger::RegisterValue> next_registers;
            for (const auto &[name, value] : unwind.value().registers) {
                debugger::RegisterValue reg;
                reg.name = name;
                std::transform(reg.name.begin(), reg.name.end(), reg.name.begin(),
                    [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
                reg.bytes = value;
                reg.byte_order = ByteOrder::little;
                next_registers.push_back(std::move(reg));
            }
            frames.push_back({next_pc, {}, std::move(next_registers), frames.size()});
            seen.push_back(next_pc);
            current_runtime_pc = next_pc;
            previous_sp = next_sp;
            context = std::move(unwind.value());
        }
        return frames;
    }
    if (elf && (architecture == Architecture::x86_64 || architecture == Architecture::arm64 ||
        architecture == Architecture::arm || architecture == Architecture::riscv32 || architecture == Architecture::riscv64) &&
        read_memory && runtime_pc >= module_base &&
        (!module_size || runtime_pc - module_base < module_size)) {
        const bool arm64 = architecture == Architecture::arm64;
        const bool arm = architecture == Architecture::arm;
        const bool riscv = architecture == Architecture::riscv32 || architecture == Architecture::riscv64;
        const std::uint64_t sp_register = arm64 ? 31 : arm ? 13 : riscv ? 2 : 7;
        const auto width = static_cast<std::uint8_t>(elf->header.is_64 ? 8 : 4);
        const bool matching_elf = (architecture == Architecture::x86_64 && elf->header.machine == 62 && width == 8) ||
            (arm64 && elf->header.machine == 183 && width == 8) || (arm && elf->header.machine == 40 && width == 4) ||
            (architecture == Architecture::riscv32 && elf->header.machine == 243 && width == 4) ||
            (architecture == Architecture::riscv64 && elf->header.machine == 243 && width == 8);
        if (!matching_elf || elf->header.order != image.layout().space.order) return frames;
        std::uint64_t static_base = preferred_base;
        if (!static_base && !image.layout().segments.empty())
            static_base = std::min_element(image.layout().segments.begin(), image.layout().segments.end(),
                [](const auto &left, const auto &right) { return left.begin.offset < right.begin.offset; })->begin.offset;
        const auto displacement = runtime_pc - module_base;
        if (static_base > UINT64_MAX - displacement) return frames;
        std::uint64_t static_pc = static_base + displacement;
        ElfUnwindContext context;
        for (const auto &reg : registers) {
            const auto number = dwarf_register_number(architecture, reg.name);
            const auto value = register_value(reg);
            if (number && value) {
                // Scalar ARM/RISC-V snapshots must have the target's full width.
                if ((arm || riscv) && (reg.bytes.size() != width || reg.byte_order != elf->header.order)) continue;
                if (const auto duplicate = context.find(*number); duplicate != context.end() && duplicate->second != *value)
                    return frames;
                context[*number] = *value;
            }
        }
        if (!context.contains(sp_register)) return frames;
        auto current_runtime_pc = runtime_pc;
        std::uint64_t previous_sp = context.contains(sp_register) ? context.at(sp_register) : 0;
        std::vector<std::uint64_t> seen{runtime_pc};
        while (frames.size() < max_frames) {
            const auto unwind = evaluate_elf_unwind(*elf, Address{{0}, static_pc}, context,
                [&](std::uint64_t address, std::uint8_t memory_width) -> std::optional<std::uint64_t> {
                    if (memory_width != width) return std::nullopt;
                    auto bytes = read_memory(address, memory_width);
                    if (!bytes || bytes.value().size() != memory_width) return std::nullopt;
                    std::uint64_t value = 0;
                    for (std::size_t i = 0; i < memory_width; ++i) {
                        const auto index = image.layout().space.order == ByteOrder::big ? i : memory_width - 1 - i;
                        value = (value << 8) | std::to_integer<std::uint8_t>(bytes.value()[index]);
                    }
                    return value;
                });
            if (!unwind) break;
            const auto next_pc = arm ? unwind.value().caller_pc & ~UINT64_C(1) : unwind.value().caller_pc;
            const auto sp = unwind.value().caller.find(sp_register);
            if (sp == unwind.value().caller.end() || !next_pc || next_pc == current_runtime_pc || sp->second <= previous_sp ||
                std::find(seen.begin(), seen.end(), next_pc) != seen.end()) break;
            frames.back().call_frame_cfa = unwind.value().cfa;
            if (next_pc < module_base || (module_size && next_pc - module_base >= module_size)) break;
            const auto next_displacement = next_pc - module_base;
            if (static_base > UINT64_MAX - next_displacement) break;
            const Address next_address{image.layout().space.id, static_base + next_displacement};
            const auto *next_segment = image.segment_at(next_address);
            if (!next_segment || !next_segment->executable || !image.code_window(next_address, 1)) break;
            std::vector<debugger::RegisterValue> next_registers;
            const auto *register_names = arm64 ? arm64_register_names.data() : arm ? arm_register_names.data() :
                riscv ? riscv_register_names.data() : x64_register_names.data();
            const auto register_count = arm64 ? arm64_register_names.size() : arm ? arm_register_names.size() :
                riscv ? riscv_register_names.size() : x64_register_names.size();
            for (std::size_t i = 0; i < register_count; ++i) {
                const auto number = dwarf_register_number(architecture, register_names[i]);
                const bool riscv_pc = riscv && register_names[i] == "PC";
                std::optional<std::uint64_t> value;
                if (riscv_pc) value = unwind.value().caller_pc;
                else if (number) {
                    const auto found = unwind.value().caller.find(*number);
                    if (found != unwind.value().caller.end()) value = found->second;
                }
                if (!value) continue;
                debugger::RegisterValue reg;
                reg.name = std::string(register_names[i]);
                reg.bytes.resize(width);
                reg.byte_order = image.layout().space.order;
                for (unsigned byte = 0; byte < width; ++byte) {
                    const auto index = reg.byte_order == ByteOrder::big ? width - 1 - byte : byte;
                    reg.bytes[index] = static_cast<std::byte>((*value >> (byte * 8)) & 0xff);
                }
                next_registers.push_back(std::move(reg));
            }
            frames.push_back({next_pc, {}, std::move(next_registers), frames.size()});
            seen.push_back(next_pc);
            current_runtime_pc = next_pc;
            previous_sp = sp->second;
            context = unwind.value().caller;
            static_pc = next_address.offset;
        }
        return frames;
    }
    if (!macho || macho->selected_slice >= macho->container.slices.size() || !read_memory ||
        runtime_pc < module_base ||
        (module_size && runtime_pc - module_base >= module_size)) return frames;
    const auto cpu = macho->container.slices[macho->selected_slice].header.cpu_type;
    const bool x64 = architecture == Architecture::x86_64 && cpu == 0x01000007u;
    const bool arm64 = architecture == Architecture::arm64 && cpu == 0x0100000cu;
    if (!x64 && !arm64) return frames;
    const auto pc_register = x64 ? MachOUnwindRegister::x86_64_rip : MachOUnwindRegister::arm64_pc;
    const auto sp_register = x64 ? MachOUnwindRegister::x86_64_rsp : MachOUnwindRegister::arm64_sp;

    std::uint64_t static_base = preferred_base;
    if (!static_base && !image.layout().segments.empty())
        static_base = std::min_element(image.layout().segments.begin(), image.layout().segments.end(),
            [](const auto &left, const auto &right) { return left.begin.offset < right.begin.offset; })->begin.offset;
    const auto displacement = runtime_pc - module_base;
    if (static_base > UINT64_MAX - displacement) return frames;
    auto static_pc = static_base + displacement;

    MachOUnwindContext context;
    for (const auto &reg : registers) {
        const auto target = x64 ? macho_x64_register(reg.name) : macho_arm64_register(reg.name);
        const auto value = register_value(reg);
        if (target && value) context[*target] = *value;
    }
    auto current_runtime_pc = runtime_pc;
    std::uint64_t previous_sp = 0;
    if (const auto sp = context.find(sp_register); sp != context.end()) previous_sp = sp->second;
    std::vector<std::uint64_t> seen{runtime_pc};
    while (frames.size() < max_frames) {
        auto unwind = evaluate_macho_unwind(*macho, Address{{0}, static_pc}, context,
            [&](std::uint64_t address, std::uint8_t width) -> std::optional<std::uint64_t> {
                if (width == 0 || width > 8) return std::nullopt;
                auto bytes = read_memory(address, width);
                if (!bytes || bytes.value().size() != width) return std::nullopt;
                std::uint64_t value = 0;
                const bool big = image.layout().space.order == ByteOrder::big;
                for (std::size_t i = 0; i < bytes.value().size(); ++i) {
                    const auto index = big ? i : bytes.value().size() - 1 - i;
                    value = (value << 8) | std::to_integer<std::uint8_t>(bytes.value()[index]);
                }
                return value;
            });
        if (!unwind) break;
        const auto pc_it = unwind.value().caller.find(pc_register);
        const auto sp_it = unwind.value().caller.find(sp_register);
        if (pc_it == unwind.value().caller.end() || sp_it == unwind.value().caller.end() ||
            !pc_it->second || pc_it->second == current_runtime_pc || sp_it->second <= previous_sp ||
            std::find(seen.begin(), seen.end(), pc_it->second) != seen.end()) break;
        const auto next_pc = pc_it->second;
        frames.back().call_frame_cfa = unwind.value().cfa;
        if (next_pc < module_base || (module_size && next_pc - module_base >= module_size)) break;
        std::vector<debugger::RegisterValue> next_registers;
        const auto *register_names = x64 ? x64_register_names.data() : arm64_register_names.data();
        const auto register_count = x64 ? x64_register_names.size() : arm64_register_names.size();
        for (std::size_t i = 0; i < register_count; ++i) {
            const auto target = x64 ? macho_x64_register(register_names[i]) : macho_arm64_register(register_names[i]);
            if (!target) continue;
            const auto value = unwind.value().caller.find(*target);
            if (value == unwind.value().caller.end()) continue;
            debugger::RegisterValue reg;
            reg.name = std::string(register_names[i]);
            reg.bytes.resize(8);
            reg.byte_order = image.layout().space.order;
            for (unsigned byte = 0; byte < 8; ++byte)
                reg.bytes[byte] = static_cast<std::byte>((value->second >> (byte * 8)) & 0xff);
            next_registers.push_back(std::move(reg));
        }
        frames.push_back({next_pc, {}, std::move(next_registers), frames.size()});
        seen.push_back(next_pc);
        current_runtime_pc = next_pc;
        previous_sp = sp_it->second;
        context = std::move(unwind.value().caller);
        const auto next_displacement = next_pc - module_base;
        if (static_base > UINT64_MAX - next_displacement) break;
        static_pc = static_base + next_displacement;
    }
    return frames;
}

std::vector<DebuggerLocalRow> debugger_locals_at(
    const ProjectSnapshot &project, const Image &image, std::uint64_t runtime_pc,
    std::uint64_t module_base, Architecture architecture,
    const std::vector<debugger::RegisterValue> &registers,
    const std::function<Result<std::vector<std::byte>>(std::uint64_t, std::size_t)> &read_memory,
    std::optional<std::uint64_t> call_frame_cfa) {
    if (architecture == Architecture::arm) runtime_pc &= ~UINT64_C(1);
    std::vector<DebuggerLocalRow> rows;
    if (!project.functions || runtime_pc < module_base) return rows;
    std::uint64_t static_base = project.loaded ? project.loaded->metadata.preferred_base : 0;
    if (static_base == 0 && !image.layout().segments.empty())
        static_base = std::min_element(image.layout().segments.begin(), image.layout().segments.end(),
            [](const auto &left, const auto &right) { return left.begin.offset < right.begin.offset; })->begin.offset;
    const auto delta = runtime_pc - module_base;
    if (static_base > UINT64_MAX - delta) return rows;
    const auto pc = static_base + delta;

    std::shared_ptr<const FunctionRecord> owner;
    for (const auto &function : project.functions->functions) {
        if (!function) continue;
        for (const auto &chunk : function->chunks) {
            if (pc >= chunk.begin.offset && pc - chunk.begin.offset < chunk.size) {
                owner = function;
                break;
            }
        }
        if (owner) break;
    }
    if (!owner) return rows;

    const auto variables = debug_variables_at(project, owner->entry, pc);
    const auto width = address_size(image);
    symbols::LocationEvaluationContext context;
    context.address_size = width;
    context.call_frame_cfa = call_frame_cfa;
    const auto frame_context = image.context_at({image.layout().space.id, pc});
    const auto arm_frame_register = frame_context && frame_context.value().mode == ExecutionMode::thumb ? 7u : 11u;
    for (const auto &reg : registers) {
        const auto name = lower(reg.name);
        const auto number = dwarf_register_number(architecture, name);
        if (name == "rbp" || name == "ebp" || name == "x29" || name == "fp" ||
            (architecture == Architecture::arm && number == arm_frame_register) ||
            ((architecture == Architecture::riscv32 || architecture == Architecture::riscv64) && number == 8))
            context.frame_base = register_value(reg);
    }
    if (call_frame_cfa) context.frame_base = call_frame_cfa;
    context.read_register = [&](std::uint64_t number) {
        return dwarf_reg_value(architecture, number, registers);
    };
    context.read_memory = [&](std::uint64_t address, std::uint8_t size) -> Result<std::uint64_t> {
        if (size == 0 || size > 8 || !read_memory)
            return Error{ErrorCode::unsupported, "DWARF memory read width is unavailable"};
        auto bytes = read_memory(address, size);
        if (!bytes) return bytes.error();
        if (bytes.value().size() != size)
            return Error{ErrorCode::io, "debugger returned a short read for a DWARF variable"};
        std::uint64_t value = 0;
        const bool big = image.layout().space.order == ByteOrder::big;
        for (std::size_t i = 0; i < bytes.value().size(); ++i) {
            const auto index = big ? i : bytes.value().size() - 1 - i;
            value = (value << 8) | std::to_integer<std::uint8_t>(bytes.value()[index]);
        }
        return value;
    };

    rows.reserve(variables.size());
    for (const auto *variable : variables) {
        if (!variable) continue;
        DebuggerLocalRow row;
        row.name = variable->name;
        row.kind = variable->is_parameter ? "parameter" : "local";
        const auto value_width = variable_size(project, *variable);
        const auto evaluated = evaluate_debug_variable_sequence(*variable, pc, context);
        if (!evaluated) {
            row.location = "unavailable";
            row.value = evaluated.error().message;
        } else if (evaluated.value().composite) {
            const auto &sequence = evaluated.value();
            row.location = "composite (" + std::to_string(sequence.pieces.size()) + " pieces)";
            constexpr std::size_t max_displayed_pieces = 24;
            constexpr std::size_t max_piece_preview_bytes = 32;
            const auto append_piece = [&](std::size_t index) {
                const auto &piece = sequence.pieces[index];
                std::string text = "piece " + std::to_string(index) + " dst-bit=" +
                    std::to_string(piece.destination_bit_offset) + " size=" +
                    std::to_string(piece.bit_size) + "b";
                if (!piece.available) return text + " <unavailable>";

                text += " src-bit=" + std::to_string(piece.source_bit_offset);
                switch (piece.kind) {
                case symbols::EvaluatedLocationKind::memory: {
                    text += " memory " + hex_value(piece.value);
                    const auto source_end = piece.source_bit_offset + piece.bit_size;
                    if (source_end < piece.source_bit_offset || source_end > UINT64_MAX - 7 || !read_memory) {
                        text += " <unreadable>";
                        break;
                    }
                    const auto first_byte = piece.source_bit_offset / 8;
                    const auto byte_count = (source_end + 7) / 8 - first_byte;
                    if (byte_count == 0) {
                        text += " <empty>";
                        break;
                    }
                    if (piece.value > UINT64_MAX - first_byte) {
                        text += " <unreadable>";
                        break;
                    }
                    const auto preview_size = static_cast<std::size_t>(
                        std::min<std::uint64_t>(byte_count, max_piece_preview_bytes));
                    auto bytes = read_memory(piece.value + first_byte, preview_size);
                    if (!bytes || bytes.value().size() != preview_size) text += " <unreadable>";
                    else {
                        text += " " + byte_preview(bytes.value());
                        if (preview_size < byte_count) text += "...";
                    }
                    break;
                }
                case symbols::EvaluatedLocationKind::register_location: {
                    text += " register " + std::to_string(piece.value);
                    const auto *reg = dwarf_register(architecture, piece.value, registers);
                    if (!reg) text += " <unavailable>";
                    else {
                        const auto preview_size = std::min(reg->bytes.size(), max_piece_preview_bytes);
                        text += " " + byte_preview(std::span<const std::byte>(reg->bytes).first(preview_size));
                        if (preview_size < reg->bytes.size()) text += "...";
                    }
                    break;
                }
                case symbols::EvaluatedLocationKind::value:
                    text += " value " + hex_value(piece.value);
                    break;
                }
                return text;
            };
            const auto displayed = std::min(sequence.pieces.size(), max_displayed_pieces);
            for (std::size_t i = 0; i < displayed; ++i) {
                if (!row.value.empty()) row.value += " | ";
                row.value += append_piece(i);
            }
            if (displayed < sequence.pieces.size())
                row.value += " | ... " + std::to_string(sequence.pieces.size() - displayed) + " more pieces";
        } else {
            const auto location = evaluated.value().location;
            switch (location.kind) {
            case symbols::EvaluatedLocationKind::memory:
                row.location = "memory " + hex_value(location.value);
                if (value_width && *value_width > 8 && read_memory) {
                    auto bytes = read_memory(location.value, *value_width);
                    row.value = bytes && bytes.value().size() == *value_width
                        ? byte_preview(bytes.value()) : "<unreadable>";
                } else if (value_width && read_memory) {
                    auto value = context.read_memory(location.value, static_cast<std::uint8_t>(*value_width));
                    row.value = value ? hex_value(value.value()) : "<unreadable>";
                } else row.value = value_width ? "<unreadable>" : "<unknown type size>";
                break;
            case symbols::EvaluatedLocationKind::register_location: {
                row.location = "DWARF register " + std::to_string(location.value);
                const auto *reg = dwarf_register(architecture, location.value, registers);
                const auto value = reg ? register_value(*reg) : std::nullopt;
                if (!reg) row.value = "<unavailable>";
                else if (!value_width) row.value = "<unknown type size>";
                else if (*value_width > 8) {
                    row.value = reg->bytes.size() >= *value_width
                        ? byte_preview(std::span<const std::byte>(reg->bytes).first(*value_width))
                        : "<register too small>";
                } else if (!value) row.value = "<unavailable>";
                else {
                    const auto bits = static_cast<unsigned>(*value_width) * 8;
                    const auto mask = bits == 64 ? UINT64_MAX : (std::uint64_t{1} << bits) - 1;
                    row.value = hex_value(*value & mask);
                }
                break;
            }
            case symbols::EvaluatedLocationKind::value:
                row.location = "constant value";
                row.value = hex_value(location.value);
                break;
            }
        }
        rows.push_back(std::move(row));
    }

    // PDB locals live on the bound PE image rather than in workspace DWARF
    // records. Lexical scope limits visibility independently of storage live
    // ranges; unresolved scope coordinates must never expose a guessed value.
    if (project.loaded && project.loaded->metadata.pe) {
        const auto &metadata = project.loaded->metadata;
        const auto &pe = *metadata.pe;
        const auto pdb_base = project.loaded->load_base.value_or(metadata.preferred_base);
        const auto pdb_pc = pc;
        std::map<std::pair<std::uint16_t, std::uint32_t>, std::string> inline_sources;
        std::size_t inline_ranges_seen = 0;
        for (const auto &site : pe.pdb_inline_sites) {
            if (inline_sources.size() >= 250'000 || inline_ranges_seen >= 250'000) break;
            std::string source;
            bool ambiguous_source = false;
            for (const auto &range : site.ranges) {
                if (++inline_ranges_seen > 250'000) { source = "inline source lookup limit"; break; }
                if (!range.address || range.address->space != image.layout().space.id ||
                    pdb_pc < range.address->offset || pdb_pc - range.address->offset >= range.size ||
                    !range.line || range.source_path.empty()) continue;
                const auto candidate = range.source_path + ':' + std::to_string(range.line);
                if (!source.empty() && source != candidate) ambiguous_source = true;
                source = candidate;
            }
            if (ambiguous_source) source = "ambiguous inline source";
            if (source.empty()) source = site.status;
            inline_sources.emplace(std::pair{site.module_index, site.record_offset}, std::move(source));
        }
        for (const auto &local : pe.pdb_locals) {
            if (local.name.empty() || !local.procedure_address ||
                local.procedure_address->space != image.layout().space.id) continue;
            const auto procedure = local.procedure_address->offset;
            if (pdb_pc < procedure || pdb_pc - procedure >= local.procedure_size) continue;
            std::optional<std::uint64_t> lexical_begin;
            if (local.has_lexical_scope) {
                const auto bound_procedure = pdb_section_range(metadata, image, pdb_base,
                    local.procedure_section, local.procedure_section_offset, local.procedure_size);
                lexical_begin = pdb_section_range(metadata, image, pdb_base,
                    local.lexical_scope_section, local.lexical_scope_offset, local.lexical_scope_size);
                // A block must agree with the bound procedure and fit entirely
                // inside it. Do not clip invalid extents to the procedure.
                if (!bound_procedure || *bound_procedure != procedure || !lexical_begin ||
                    *lexical_begin < procedure || *lexical_begin - procedure >= local.procedure_size ||
                    local.lexical_scope_size > local.procedure_size - (*lexical_begin - procedure))
                    lexical_begin.reset();
                if (lexical_begin && (pdb_pc < *lexical_begin ||
                    pdb_pc - *lexical_begin >= local.lexical_scope_size)) continue;
            }
            DebuggerLocalRow row;
            row.name = local.name;
            row.kind = local.parameter ? "parameter" : "local";
            if (local.inlinee_id && local.inline_site_record_offset)
                row.scope = "inlinee IPI " + hex_value(*local.inlinee_id) + ", site record " +
                    hex_value(*local.inline_site_record_offset) + ", local record " + hex_value(local.record_offset);
            else if (local.inlinee_id || local.inline_site_record_offset)
                row.scope = "incomplete inline-site identity; local record " + hex_value(local.record_offset);
            else row.scope = "procedure; local record " + hex_value(local.record_offset);
            if (local.inlinee_id && local.inline_site_record_offset) {
                const auto found = inline_sources.find({local.module_index, *local.inline_site_record_offset});
                if (found != inline_sources.end()) row.scope += " / " + found->second;
            }
            if (local.has_lexical_scope) {
                row.scope += " / lexical block section " + std::to_string(local.lexical_scope_section) +
                    " + " + hex_value(local.lexical_scope_offset) + " size " + hex_value(local.lexical_scope_size);
                if (!lexical_begin) {
                    row.location = "unresolved";
                    row.value = "<PDB lexical scope cannot be bound unambiguously>";
                    rows.push_back(std::move(row));
                    continue;
                }
            }
            std::vector<const PePdbLocalLiveRange *> active_ranges;
            for (const auto &range : local.live_ranges) {
                const auto begin = pdb_section_range(metadata, image, pdb_base,
                    range.section, range.section_offset, range.size);
                if (!begin || pdb_pc < *begin || pdb_pc - *begin >= range.size) continue;
                const auto relative = static_cast<std::uint64_t>(pdb_pc - *begin);
                bool in_gap = false;
                for (const auto &gap : range.gaps)
                    if (relative >= gap.offset && relative - gap.offset < gap.size) { in_gap = true; break; }
                if (!in_gap) active_ranges.push_back(&range);
            }
            if (active_ranges.empty()) continue;
            if (active_ranges.size() > 1) {
                row.location = "ambiguous";
                row.value = "<multiple overlapping PDB live ranges>";
                if (std::none_of(rows.begin(), rows.end(), [&](const auto &existing) {
                        return existing.name == row.name && existing.kind == row.kind && existing.scope == row.scope;
                    })) rows.push_back(std::move(row));
                continue;
            }
            const auto *active = active_ranges.front();
            const auto size = pdb_type_size(pe, local.type_index, architecture);
            std::optional<std::uint64_t> address;
            const auto kind = active->location_kind;
            const auto read_pdb_bytes = [&](std::uint64_t at, std::size_t count) -> std::optional<std::vector<std::byte>> {
                if (!read_memory || count == 0 || count > 256 || at > UINT64_MAX - (count - 1)) return std::nullopt;
                auto bytes = read_memory(at, count);
                if (!bytes || bytes.value().size() != count) return std::nullopt;
                return std::move(bytes.value());
            };
            const auto show_memory_value = [&](std::uint64_t at, std::size_t count) {
                auto bytes = read_pdb_bytes(at, count);
                if (!bytes) return std::string("<unreadable>");
                if (count > 8) return byte_preview(*bytes);
                std::uint64_t value = 0;
                const bool big = image.layout().space.order == ByteOrder::big;
                for (std::size_t i = 0; i < count; ++i) {
                    const auto index = big ? i : count - 1 - i;
                    value = (value << 8) | std::to_integer<std::uint8_t>((*bytes)[index]);
                }
                return hex_value(value);
            };
            const auto unique_parent_member = [&](std::uint64_t offset) -> const PePdbTypeField * {
                const auto parent = std::find_if(pe.pdb_types.begin(), pe.pdb_types.end(),
                    [&](const auto &candidate) { return candidate.index == local.type_index; });
                if (parent == pe.pdb_types.end() || !parent->field_layout_complete ||
                    parent->leaf == 0x1506 || !parent->size || parent->size > 256 ||
                    !size || parent->size != *size || parent->fields.size() > 4096) return nullptr;
                std::vector<std::pair<std::uint64_t, std::uint64_t>> extents;
                const PePdbTypeField *match = nullptr;
                for (const auto &field : parent->fields) {
                    if (field.leaf == 0x1400 || field.leaf == 0x1401 || field.leaf == 0x1402)
                        return nullptr;
                    if (field.leaf != 0x150d) continue;
                    const auto field_size = pdb_type_size(pe, field.type, architecture);
                    if (!field_size || *field_size == 0 || *field_size > 256 ||
                        field.offset > parent->size || *field_size > parent->size - field.offset)
                        return nullptr;
                    const auto end = field.offset + *field_size;
                    for (const auto &[begin, previous_end] : extents)
                        if (field.offset < previous_end && begin < end) return nullptr;
                    extents.emplace_back(field.offset, end);
                    if (field.offset == offset) {
                        if (match) return nullptr;
                        match = &field;
                    }
                }
                return match;
            };
            if (kind == PePdbLocalLocationKind::frame_relative ||
                (kind == PePdbLocalLocationKind::register_relative && !active->indirect &&
                 !active->spilled_udt_member && active->offset_in_parent == 0 && active->offset_in_udt == 0)) {
                std::optional<std::uint64_t> base;
                if (kind == PePdbLocalLocationKind::frame_relative) {
                    std::string_view fp_name;
                    if (architecture == Architecture::x86_64) fp_name = "rbp";
                    else if (architecture == Architecture::x86) fp_name = "ebp";
                    else if (architecture == Architecture::arm64) fp_name = "x29";
                    else if (architecture == Architecture::arm) fp_name = "r11";
                    for (const auto &reg : registers)
                        if (!fp_name.empty() && lower(reg.name) == fp_name) { base = register_value(reg); break; }
                } else if (const auto number = pdb_register_number(architecture, active->register_id)) {
                    base = dwarf_reg_value(architecture, *number, registers);
                }
                if (base) {
                    const auto displacement = static_cast<std::int64_t>(active->frame_offset);
                    if (displacement < 0) {
                        const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
                        if (*base >= magnitude) address = *base - magnitude;
                    } else if (*base <= UINT64_MAX - static_cast<std::uint64_t>(displacement)) {
                        address = *base + static_cast<std::uint64_t>(displacement);
                    }
                }
                row.location = address ? "memory " + hex_value(*address) : "unavailable";
                if (!address) row.value = "<base register unavailable>";
                else if (!size) row.value = "<unknown type size>";
                else row.value = show_memory_value(*address, *size);
            } else if (kind == PePdbLocalLocationKind::register_relative &&
                       (active->indirect || active->spilled_udt_member)) {
                row.location = "unavailable";
                std::size_t fragment_size = size.value_or(0);
                const bool has_member_offset = active->offset_in_parent != 0 || active->offset_in_udt != 0;
                if (active->spilled_udt_member) {
                    const auto *member = active->offset_in_udt < 0
                        ? nullptr : unique_parent_member(active->offset_in_parent);
                    if (active->offset_in_udt < 0)
                        row.value = "<negative spilled-member UDT offset>";
                    else if (!active->indirect && active->offset_in_udt != 0)
                        row.value = "<non-indirect spilled-member has an unexpected UDT offset>";
                    else if (!member) row.value = "<spilled parent member layout unavailable or ambiguous>";
                    else if (active->indirect && active->offset_in_udt != active->offset_in_parent)
                        row.value = "<indirect member offsets disagree>";
                    else if (const auto field_size = pdb_type_size(pe, member->type, architecture)) {
                        fragment_size = *field_size;
                    } else row.value = "<spilled member type size unavailable>";
                } else if (active->indirect && has_member_offset) {
                    if (active->offset_in_parent == 0 || active->offset_in_udt < 0 ||
                        static_cast<std::uint64_t>(active->offset_in_udt) != active->offset_in_parent)
                        row.value = "<indirect member offsets disagree or are invalid>";
                    else if (const auto *member = unique_parent_member(
                                 static_cast<std::uint64_t>(active->offset_in_udt))) {
                        if (const auto field_size = pdb_type_size(pe, member->type, architecture)) {
                            fragment_size = *field_size;
                        } else row.value = "<indirect member type size unavailable>";
                    } else row.value = "<indirect parent member layout unavailable or ambiguous>";
                } else if (!size) row.value = "<unknown type size>";
                else if (*size > 256) row.value = "<type extent exceeds preview limit>";
                if (fragment_size == 0 && row.value.empty()) row.value = "<empty member fragment>";
                else if (fragment_size > 256 && row.value.empty()) row.value = "<type extent exceeds preview limit>";
                if (row.value.empty()) {
                    const auto number = pdb_register_number(architecture, active->register_id);
                    const auto base = number ? dwarf_reg_value(architecture, *number, registers) : std::nullopt;
                    std::optional<std::uint64_t> slot;
                    if (base) {
                        const auto displacement = static_cast<std::int64_t>(active->frame_offset);
                        if (displacement < 0) {
                            const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
                            if (*base >= magnitude) slot = *base - magnitude;
                        } else if (*base <= UINT64_MAX - static_cast<std::uint64_t>(displacement))
                            slot = *base + static_cast<std::uint64_t>(displacement);
                    }
                    if (!base) row.value = "<base register unavailable>";
                    else if (!slot) row.value = "<address overflow>";
                    else if (active->indirect) {
                        const auto pointer_width = address_size(image);
                        const auto pointer = pointer_width <= 8 ? read_pdb_bytes(*slot, pointer_width) : std::nullopt;
                        if (!pointer) row.value = "<indirect pointer unreadable>";
                        else {
                            std::uint64_t pointee = 0;
                            const bool big = image.layout().space.order == ByteOrder::big;
                            for (std::size_t i = 0; i < pointer_width; ++i) {
                                const auto index = big ? i : pointer_width - 1 - i;
                                pointee = (pointee << 8) | std::to_integer<std::uint8_t>((*pointer)[index]);
                            }
                            const auto member_displacement = active->offset_in_udt > 0
                                ? static_cast<std::uint64_t>(active->offset_in_udt) : 0;
                            if (pointee > UINT64_MAX - member_displacement ||
                                pointee + member_displacement > UINT64_MAX - fragment_size)
                                row.value = "<address overflow>";
                            else {
                                address = pointee + member_displacement;
                                row.location = "memory " + hex_value(*address);
                                row.value = show_memory_value(*address, fragment_size);
                            }
                        }
                    } else {
                        if (fragment_size > UINT64_MAX - *slot) row.value = "<address overflow>";
                        else {
                            address = *slot;
                            row.location = "memory " + hex_value(*address);
                            row.value = show_memory_value(*address, fragment_size);
                        }
                    }
                }
            } else if (kind == PePdbLocalLocationKind::register_value && active->subfield_register) {
                row.location = "unavailable";
                if (!size) row.value = "<unknown parent type size>";
                else if (*size > 256) row.value = "<parent type exceeds preview limit>";
                else {
                    const auto parent = std::find_if(pe.pdb_types.begin(), pe.pdb_types.end(),
                        [&](const auto &candidate) { return candidate.index == local.type_index; });
                    if (parent == pe.pdb_types.end() || !parent->field_layout_complete ||
                        parent->leaf == 0x1506 || parent->size != *size) {
                        row.value = "<parent field layout unavailable>";
                    } else if (parent->fields.size() > 4096) {
                        row.value = "<parent field count exceeds evaluation limit>";
                    } else {
                        bool valid_layout = true;
                        bool inherited = false;
                        std::vector<std::pair<std::uint64_t, std::uint64_t>> extents;
                        std::vector<const PePdbTypeField *> matches;
                        for (const auto &field : parent->fields) {
                            if (field.leaf == 0x1400 || field.leaf == 0x1401 || field.leaf == 0x1402) {
                                inherited = true;
                                break;
                            }
                            if (field.leaf != 0x150d) continue; // Only LF_MEMBER occupies an instance extent.
                            const auto field_size = pdb_type_size(pe, field.type, architecture);
                            if (!field_size || *field_size == 0 || *field_size > 256 ||
                                field.offset > *size || *field_size > *size - field.offset) {
                                valid_layout = false;
                                break;
                            }
                            const auto end = field.offset + *field_size;
                            for (const auto &[begin, previous_end] : extents)
                                if (field.offset < previous_end && begin < end) valid_layout = false;
                            if (!valid_layout) break;
                            extents.emplace_back(field.offset, end);
                            if (field.offset == active->offset_in_parent) matches.push_back(&field);
                        }
                        if (inherited) row.value = "<inherited parent layout unsupported>";
                        else if (!valid_layout) row.value = "<ambiguous or unresolved parent layout>";
                        else if (matches.size() != 1) row.value = "<subfield offset is not unique>";
                        else {
                            const auto &field = *matches.front();
                            const auto field_size = pdb_type_size(pe, field.type, architecture);
                            const auto number = pdb_register_number(architecture, active->register_id);
                            const auto *reg = number ? dwarf_register(architecture, *number, registers) : nullptr;
                            if (!field_size) row.value = "<unknown subfield type size>";
                            else if (!reg) row.value = "<register unavailable>";
                            else if (reg->bytes.size() < *field_size) row.value = "<register fragment too small>";
                            else {
                                row.location = "register subfield at parent byte " +
                                    std::to_string(active->offset_in_parent);
                                const auto start = reg->byte_order == ByteOrder::big
                                    ? reg->bytes.size() - *field_size : 0;
                                const auto fragment = std::span<const std::byte>(reg->bytes).subspan(start, *field_size);
                                if (*field_size > 8) row.value = byte_preview(fragment);
                                else {
                                    std::uint64_t value = 0;
                                    const bool big = reg->byte_order == ByteOrder::big;
                                    for (std::size_t i = 0; i < *field_size; ++i) {
                                        const auto index = big ? i : *field_size - 1 - i;
                                        value = (value << 8) | std::to_integer<std::uint8_t>(fragment[index]);
                                    }
                                    row.value = hex_value(value);
                                }
                            }
                        }
                    }
                }
            } else if (kind == PePdbLocalLocationKind::register_value) {
                const auto number = pdb_register_number(architecture, active->register_id);
                const auto *reg = number ? dwarf_register(architecture, *number, registers) : nullptr;
                row.location = number ? "register " + std::to_string(*number) : "unavailable";
                if (!reg) row.value = "<register unavailable>";
                else if (!size) row.value = "<unknown type size>";
                else if (*size > 8) row.value = reg->bytes.size() >= *size
                    ? byte_preview(std::span<const std::byte>(reg->bytes).first(*size)) : "<register too small>";
                else if (const auto value = register_value(*reg)) {
                    const auto bits = static_cast<unsigned>(*size) * 8;
                    const auto mask = bits == 64 ? UINT64_MAX : (std::uint64_t{1} << bits) - 1;
                    row.value = hex_value(*value & mask);
                } else row.value = "<register unavailable>";
            } else {
                row.location = "unavailable";
                row.value = "<unsupported PDB location>";
            }
            if (std::none_of(rows.begin(), rows.end(), [&](const auto &existing) {
                    return existing.name == row.name && existing.kind == row.kind && existing.scope == row.scope;
                })) rows.push_back(std::move(row));
        }
    }
    return rows;
}
} // namespace hexlab::desktop
