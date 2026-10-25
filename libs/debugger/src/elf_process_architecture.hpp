#pragma once

#include "hexlab/core/architecture.hpp"

#include <cstddef>
#include <span>

namespace hexlab::debugger::detail {

// Read ELF identity and e_machine fields without relying on host struct
// layout. Unsupported byte orders and malformed or mismatched images are unknown.
inline Architecture elf_process_architecture(std::span<const std::byte> header) noexcept {
    constexpr std::size_t machine_offset = 18;
    if (header.size() < machine_offset + 2 ||
        header[0] != std::byte{0x7f} || header[1] != std::byte{'E'} ||
        header[2] != std::byte{'L'} || header[3] != std::byte{'F'} ||
        (header[4] != std::byte{1} && header[4] != std::byte{2}) ||
        (header[5] != std::byte{1} && header[5] != std::byte{2}) || header[6] != std::byte{1})
        return Architecture::unknown;

    const auto elf_class = std::to_integer<unsigned char>(header[4]);
    const auto byte_order = std::to_integer<unsigned char>(header[5]);
    const auto first_machine_byte = static_cast<unsigned>(std::to_integer<unsigned char>(header[machine_offset]));
    const auto second_machine_byte = static_cast<unsigned>(std::to_integer<unsigned char>(header[machine_offset + 1]));
    const auto machine = byte_order == 1 ? first_machine_byte | (second_machine_byte << 8)
                                         : (first_machine_byte << 8) | second_machine_byte;
    if (byte_order == 2 && machine != 8) return Architecture::unknown;
    switch (machine) {
    case 3: return elf_class == 1 ? Architecture::x86 : Architecture::unknown; // EM_386
    case 62: return elf_class == 2 ? Architecture::x86_64 : Architecture::unknown; // EM_X86_64
    case 40: return elf_class == 1 ? Architecture::arm : Architecture::unknown; // EM_ARM
    case 183: return elf_class == 2 ? Architecture::arm64 : Architecture::unknown; // EM_AARCH64
    case 243: return elf_class == 2 ? Architecture::riscv64 : Architecture::unknown; // EM_RISCV
    case 8: return elf_class == 1 ? Architecture::mips32 :
                   elf_class == 2 ? Architecture::mips64 : Architecture::unknown; // EM_MIPS
    default: return Architecture::unknown;
    }
}

} // namespace hexlab::debugger::detail
