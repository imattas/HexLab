#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include "hexlab/image/jvm_metadata.hpp"
#include <memory>
#include <stop_token>
namespace hexlab {
// Bounded JVM class-file loader. Each method Code array receives a private
// byte-addressed address space so its branch offsets stay method-relative.
// JvmCode::stack_map_table retains bounded, expanded verifier frames, including
// class indices and uninitialized states; loading does not prove bytecode safety.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_jvm_class(std::shared_ptr<const ByteStorage>, std::stop_token);
}
