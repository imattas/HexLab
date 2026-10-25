#pragma once
#include "hexlab/image/byte_storage.hpp"
#include <vector>
namespace hexlab {
struct FileRange {FileOffset begin;std::uint64_t size;};
// ReadSet mutations belong to its owner. TrackingStorage synchronizes them.
class ReadSet {
public:
    HEXLAB_IMAGE_EXPORT Result<bool> include(FileOffset,std::uint64_t size);
    HEXLAB_IMAGE_EXPORT Result<bool> intersects(FileOffset,std::uint64_t size) const;
    std::span<const FileRange> ranges() const noexcept{return ranges_;}
private:
    std::vector<FileRange> ranges_;
};
class TrackingStorage final:public ByteStorage {
public:
    HEXLAB_IMAGE_EXPORT static Result<std::shared_ptr<TrackingStorage>> create(std::shared_ptr<const ByteStorage>);
    HEXLAB_IMAGE_EXPORT ~TrackingStorage() override;
    HEXLAB_IMAGE_EXPORT std::uint64_t size() const noexcept override;
    HEXLAB_IMAGE_EXPORT Result<ByteView> read_at(FileOffset,std::size_t) const override;
    HEXLAB_IMAGE_EXPORT ReadSet reads() const;
private:
    struct Impl;
    explicit TrackingStorage(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}
