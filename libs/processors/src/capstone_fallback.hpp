#pragma once
#include "hexlab/processors/decoder.hpp"

namespace hexlab::processor_detail {
DecodeResult decode_capstone_fallback(DecodeContext, std::span<const std::byte>, Address);
}
