#pragma once

#include "hexlab/decompiler/type_recovery.hpp"

#include <map>
#include <tuple>

namespace hexlab::decompiler::detail {

using ExpressionRegisterKey =
    std::tuple<unsigned, unsigned, unsigned, bool, std::uint32_t, bool>;
using ExpressionRegisterTypes = std::map<ExpressionRegisterKey, types::TypePtr>;

class ExpressionTypeScope final {
  public:
    explicit ExpressionTypeScope(std::span<const RecoveredVariable>);
    ~ExpressionTypeScope();
    ExpressionTypeScope(const ExpressionTypeScope &) = delete;
    ExpressionTypeScope &operator=(const ExpressionTypeScope &) = delete;

  private:
    ExpressionRegisterTypes values_;
    const ExpressionRegisterTypes *previous_ = nullptr;
};

const types::TypePtr *expression_register_type(RegisterOperand,
                                               std::optional<std::uint32_t>) noexcept;

} // namespace hexlab::decompiler::detail
