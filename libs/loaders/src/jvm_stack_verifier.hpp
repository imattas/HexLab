#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/image/jvm_metadata.hpp"
#include <cstddef>
#include <span>
#include <stop_token>

namespace hexlab::jvm_detail {
// false means the bounded stack/local category analysis is partial, never a
// type-safety certificate. Reference subtyping and uninitialized-object rules
// remain deliberately coarse.
Result<bool> verify_operand_stack(std::span<const std::byte>, const std::vector<bool> &,
                                 const JvmCode &, const JvmMember &, const JvmMetadata &,
                                 std::stop_token, std::size_t &class_work);
}
