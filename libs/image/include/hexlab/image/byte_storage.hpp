#pragma once
#include "hexlab/core/address.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/image/image_export.hpp"
#include <memory>
#include <span>
#include <stop_token>

namespace hexlab {
struct ByteView {
    // The owner may be a mapped source or a buffer assembled by an overlay.
    std::shared_ptr<const void> owner;
    std::span<const std::byte> bytes;
};
class ByteStorage {
public:
    HEXLAB_IMAGE_EXPORT virtual ~ByteStorage();
    virtual std::uint64_t size() const noexcept=0;
    virtual Result<ByteView> read_at(FileOffset,std::size_t) const=0;
};
HEXLAB_IMAGE_EXPORT Result<Sha256Digest> hash_source(const ByteStorage&,std::stop_token);
}
