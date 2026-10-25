#pragma once
#include "hexlab/core/address.hpp"
#include <variant>
namespace hexlab {
using Location=std::variant<Address,FileOffset>;
}
