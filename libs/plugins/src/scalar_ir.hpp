#pragma once
#include "hexlab/plugins/plugin_abi.h"
#include "hexlab/decompiler/decompiler.hpp"

namespace hexlab::plugins::detail {
using ScalarRegisterConverter = std::optional<RegisterOperand> (*)(DecodeContext, const HexLabSemanticRegisterV2 &);
// The semantic record has already passed the existing V3 conversion. This
// additionally proves exact pure scalar effects and bounded expression work.
std::optional<decompiler::Intrinsic> convert_scalar_ir(const HexLabInstructionIR &, const Instruction &,
                                                      ScalarRegisterConverter);
bool same_scalar_instruction(const Instruction &, const Instruction &);
}
