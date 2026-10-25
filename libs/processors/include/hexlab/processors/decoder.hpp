#pragma once
#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <span>
#include <string_view>
namespace hexlab {
struct ProcessorCapabilities {
    bool can_decode = false;
    std::uint8_t max_instruction_bytes = 0;
    std::string_view display_name, reason;
};
// Static decoder support only, not decompiler/debugger or full-ISA coverage.
HEXLAB_PROCESSORS_EXPORT ProcessorCapabilities processor_capabilities(DecodeContext) noexcept;
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_instruction(DecodeContext, std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_x86_32(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_x86_16(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_x64(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_a64(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_a32(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_mips32(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_mips32(ByteOrder, std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_mips64(std::span<const std::byte>, Address,
                                                    ByteOrder = ByteOrder::little);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_powerpc(DecodeContext, std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_m6502(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_wasm(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_dex(std::span<const std::byte>, Address);
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_jvm(std::span<const std::byte>, Address);
// Unknown IT state is distinct from a caller-established boundary {true,0}.
HEXLAB_PROCESSORS_EXPORT DecodeResult decode_thumb(std::span<const std::byte>, Address, ThumbITState = {});
// Selects the encoded control operand; A64 compare/test branches put it after
// the tested register/bit. Indirect legacy and register branches use operand0.
HEXLAB_PROCESSORS_EXPORT std::uint32_t control_operand_index(const Instruction &) noexcept;
} // namespace hexlab
