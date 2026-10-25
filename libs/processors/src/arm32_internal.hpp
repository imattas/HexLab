#pragma once
#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
namespace hexlab::arm32_detail {
bool data(Instruction &, std::uint32_t);
bool memory(Instruction &, std::uint32_t);
std::string mnemonic(Opcode, std::uint8_t);
std::string format(const Instruction &);
} // namespace hexlab::arm32_detail
