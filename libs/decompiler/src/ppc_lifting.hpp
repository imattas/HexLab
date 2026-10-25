#pragma once

#include "hexlab/decompiler/decompiler.hpp"

namespace hexlab::decompiler {
// Control transfers may require bounded unconditional CTR/LR updates before
// the final statement. Without an output list, those forms stay one explicit
// effect so a caller cannot accidentally discard their register definitions.
std::optional<Statement> lift_ppc_instruction(const Instruction &instruction,
                                             std::vector<Statement> *before = nullptr);
}
