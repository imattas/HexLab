#pragma once

#include "hexlab/decompiler/decompiler.hpp"

namespace hexlab::decompiler {
std::optional<Statement> lift_mips64_instruction(const Instruction &instruction);
}
