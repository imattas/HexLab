#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include <memory>
#include <stop_token>

namespace hexlab {
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_minidump(std::shared_ptr<const ByteStorage>, std::stop_token = {});
}
