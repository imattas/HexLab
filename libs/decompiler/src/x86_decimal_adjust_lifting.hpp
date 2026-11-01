#pragma once
#include "hexlab/decompiler/decompiler.hpp"

namespace hexlab::decompiler {
std::optional<Statement> lift_x86_decimal_adjust(const Instruction &instruction);
}
