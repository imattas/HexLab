#pragma once
#ifdef HEXLAB_IMAGE_TESTING
#include "hexlab/image/image_export.hpp"
namespace hexlab::image_testing {
HEXLAB_IMAGE_EXPORT void fail_next_write();
HEXLAB_IMAGE_EXPORT void fail_next_publication();
bool take_write_failure();bool take_publication_failure();
}
#endif
