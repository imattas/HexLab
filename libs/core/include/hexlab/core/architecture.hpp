#pragma once
#include "hexlab/core/byte_reader.hpp"
namespace hexlab {
// Preserve numeric values: canonical load recipes already store these enums.
enum class Architecture { unknown, x86, x86_64, arm, arm64, riscv64, mips32, mos6502, riscv32, mips64, powerpc, wasm, dex, jvm };
enum class ExecutionMode { unknown, x86_16, x86_32, x86_64, a32, thumb, a64, rv64, rv64c, mips32, m6502, rv32, mips64, ppc32, ppc64, wasm32, dex, jvm, m65c02 };
struct DecodeContext {
    Architecture architecture = Architecture::unknown;
    ExecutionMode mode = ExecutionMode::unknown;
    ByteOrder order = ByteOrder::little;
    // Zero keeps the mode default; legacy protected profiles may select SS.B
    // independently of CS.D. Long mode permits only zero or64.
    std::uint8_t stack_address_width = 0;
    // Legacy16 always retains segment dependencies. This flag also enables
    // that model for legacy32 without changing existing flat32 assumptions.
    bool segmented_memory = false;
    bool operator==(const DecodeContext &) const = default;
};
} // namespace hexlab
