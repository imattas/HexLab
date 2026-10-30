#pragma once
#include "hexlab/loaders/loader.hpp"
#include <stop_token>
#include <span>
#include <string_view>
#include <vector>

namespace hexlab {

struct ElfLinkLimits {
    std::size_t max_objects = 100'000;
    std::size_t max_symbols = 2'000'000;
    std::size_t max_relocations = 4'000'000;
    std::uint64_t max_output_bytes = 512ULL * 1024 * 1024;
};

// Produces a new ELF64 little-endian x86-64 ET_REL containing merged
// executable .text, read-only .rodata, writable .data, and zero-filled writable .bss sections. Only SHT_RELA relocations of types R_X86_64_NONE,
// 64, PC32, PLT32, 32, 32S, and PC64 are applied. Nonempty allocated sections
// other than .text, .rodata, initialized .data, and SHT_NOBITS .bss, REL relocations,
// and unresolved strong symbols are errors. SHN_COMMON symbols are coalesced
// into .bss by maximum size/alignment; strong definitions override common and
// weak definitions, and common definitions override weak definitions.
// Relocations stored inside .bss are unsupported.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_elf64_x86_64_text(
    std::span<const std::shared_ptr<const ByteStorage>>, std::stop_token = {}, ElfLinkLimits = {});

// Produces a static ELF64 x86-64 ET_EXEC from the same bounded object subset.
// The entry must resolve to a defined symbol in merged .text. The output uses
// a fixed base address and RX/R/RW PT_LOAD segments (omitting an empty R
// segment); dynamic linking is absent.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_elf64_x86_64_executable(
    std::span<const std::shared_ptr<const ByteStorage>>, std::string_view entry_symbol = "_start",
    std::uint64_t base_address = 0x400000, std::stop_token = {}, ElfLinkLimits = {});

// AArch64 variants of the same section-merging subset, requiring homogeneous
// ELF64 little-endian AArch64 objects. Supported RELA types: NONE, ABS64, ABS32,
// PREL64, PREL32, ADR_PREL_PG_HI21, ADD_ABS_LO12_NC, JUMP26, CALL26, and
// LDST64_ABS_LO12_NC. Instruction fields, alignment, and checked ranges are
// validated. Out-of-range branches are rejected; veneers are not generated.
// Executables separate RX/R/RW segments on 64KiB boundaries and require a base
// aligned to 64KiB and the input sections, supporting 4/16/64KiB host pages.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_elf64_aarch64_text(
    std::span<const std::shared_ptr<const ByteStorage>>, std::stop_token = {}, ElfLinkLimits = {});
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_elf64_aarch64_executable(
    std::span<const std::shared_ptr<const ByteStorage>>, std::string_view entry_symbol = "_start",
    std::uint64_t base_address = 0x400000, std::stop_token = {}, ElfLinkLimits = {});

// Produces a bounded ELF32 little-endian i386 ET_REL from compatible ET_REL
// inputs. Merges allocated .text/.rodata/.data/.bss and applies SHT_REL
// R_386_NONE, R_386_32, R_386_PC32, R_386_PLT32, R_386_16, R_386_PC16,
// R_386_8, and R_386_PC8 relocations. Narrow PC-relative fields are limited
// to same-output-section references with signed-range-checked displacements.
HEXLAB_LOADERS_EXPORT Result<std::vector<std::byte>> link_elf32_i386_text(
    std::span<const std::shared_ptr<const ByteStorage>>, std::stop_token = {}, ElfLinkLimits = {});

} // namespace hexlab
