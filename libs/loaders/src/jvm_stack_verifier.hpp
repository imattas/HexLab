#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/image/jvm_metadata.hpp"
#include <cstddef>
#include <span>
#include <stop_token>

namespace hexlab::jvm_detail {
// false means this bounded stack-only analysis is partial, never a type-safety
// certificate. Class hierarchy and local initialization are deliberately absent.
Result<bool> verify_operand_stack(std::span<const std::byte>, const std::vector<bool> &,
                                 const JvmCode &, const JvmMetadata &,
                                 std::stop_token, std::size_t &class_work);
}
