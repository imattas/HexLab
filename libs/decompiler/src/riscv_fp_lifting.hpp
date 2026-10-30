#pragma once

#include "hexlab/decompiler/decompiler.hpp"

namespace hexlab::decompiler {
std::optional<Statement> lift_riscv_fp_conversion(const Instruction &instruction,
                                                std::span<const ExpressionPtr> operands);
std::optional<Statement> lift_riscv_fstatus_csr(const Instruction &instruction,
                                               std::span<const ExpressionPtr> operands);
}
