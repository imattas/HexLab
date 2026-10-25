#pragma once
#include "hexlab/core/address.hpp"
#include "hexlab/image/byte_storage.hpp"
#include "hexlab/image/image_export.hpp"
#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>

namespace hexlab {
class FileStorage final : public ByteStorage, public std::enable_shared_from_this<FileStorage> {
public:
    HEXLAB_IMAGE_EXPORT static Result<std::shared_ptr<const FileStorage>> open(const std::filesystem::path& path);
    HEXLAB_IMAGE_EXPORT static Result<std::shared_ptr<const FileStorage>> open_owned(const std::filesystem::path&,std::shared_ptr<const void> backing_owner);
    HEXLAB_IMAGE_EXPORT const std::filesystem::path& backing_path() const noexcept;
    HEXLAB_IMAGE_EXPORT ~FileStorage() override;
    FileStorage(const FileStorage&) = delete;
    FileStorage& operator=(const FileStorage&) = delete;
    HEXLAB_IMAGE_EXPORT std::uint64_t size() const noexcept override;
    HEXLAB_IMAGE_EXPORT Result<ByteView> read_at(FileOffset offset, std::size_t count) const override;
private:
    struct Impl;
    explicit FileStorage(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> impl_;
};
}
