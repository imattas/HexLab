#pragma once
#include "hexlab/processors/instruction.hpp"
#include "hexlab/processors/processors_export.hpp"
#include <span>
#include <string_view>
namespace hexlab {
struct ProcessorVariantCoverage {
    // Representative implemented families; this list is intentionally
    // non-exhaustive and does not imply whole-ISA support.
    std::span<const std::string_view> instruction_families;
    // Bounded downstream features currently wired for the variant.
    std::span<const std::string_view> analysis;
    std::span<const std::string_view> decompiler;
    std::span<const std::string_view> debugger;
};
struct ProcessorCapabilities {
    bool can_decode = false;
    std::uint32_t max_instruction_bytes = 0;
    std::string_view display_name, reason;
};
struct ProcessorVariantInfo {
    std::string_view id;
    DecodeContext context;
    ProcessorCapabilities capabilities;
    bool byte_order_applicable = true;
    ProcessorVariantCoverage coverage;
};
// Static decoder support only, not decompiler/debugger or full-ISA coverage.
HEXLAB_PROCESSORS_EXPORT ProcessorCapabilities processor_capabilities(DecodeContext) noexcept;
// Canonical architecture/mode contexts known to the decoder. Each record's
// capability value is derived from processor_capabilities at first use.
HEXLAB_PROCESSORS_EXPORT std::span<const ProcessorVariantInfo> processor_variant_inventory() noexcept;
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
