#pragma once
#include "hexlab/analysis/incremental.hpp"
namespace hexlab::source_detail {
// ELF permits 2^20 sections. Include the primary domain and keep the in-memory
// binding table within32MiB; encoded tables also share the64MiB payload budget.
inline constexpr std::size_t domain_limit = 1048577;
inline constexpr std::size_t domain_memory_limit = 32 * 1024 * 1024;
inline bool valid_context(DecodeContext value) {
    if (processor_capabilities(value).can_decode)
        return true;
    const auto arch = static_cast<unsigned>(value.architecture);
    return arch <= static_cast<unsigned>(Architecture::powerpc) && value.mode == ExecutionMode::unknown &&
           (value.order == ByteOrder::little || value.order == ByteOrder::big) && value.stack_address_width == 0 &&
           (!value.segmented_memory || value.architecture == Architecture::x86);
}
} // namespace hexlab::source_detail
