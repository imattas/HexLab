#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include <memory>
#include <stop_token>

namespace hexlab {
// Bounded WebAssembly v1 container/function-body loader. It retains import and
// export metadata and maps each defined function's operator stream into its own
// zero-based address domain so branch depths and instruction locations remain
// function-relative. Statically reconstructible initial linear memory is
// mapped in a distinct wasm32 address space.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_wasm(std::shared_ptr<const ByteStorage>, std::stop_token);
}
