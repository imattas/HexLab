#pragma once
#include <cstddef>
#include <cstdint>
namespace hexlab {
struct PageRequest {std::uint64_t offset=0;std::size_t limit=256;};
}
