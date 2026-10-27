#pragma once
#include "hexlab/loaders/loaded_image.hpp"
#include <memory>
#include <stop_token>

namespace hexlab {
// Bounded standard DEX reader. Defined Dalvik code items are mapped into
// method-relative address spaces so branch offsets remain local to a method.
// Loaded metadata retains class definitions and their declared members as
// identifier-table indexes with raw access flags; names remain in the DEX
// identifier/string tables and are not imported into shared symbols or types.
HEXLAB_LOADERS_EXPORT Result<LoadedImage> load_dex(std::shared_ptr<const ByteStorage>, std::stop_token);
}
