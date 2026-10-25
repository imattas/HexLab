#pragma once
#include "hexlab/image/byte_storage.hpp"
#include <filesystem>
#include <stop_token>
namespace hexlab {
enum class ExistingFilePolicy {reject,replace};
// Owns a same-directory temporary; failed/canceled writes never publish it.
class FilePublication {
public:
    HEXLAB_IMAGE_EXPORT static Result<std::unique_ptr<FilePublication>> create(const std::filesystem::path&,ExistingFilePolicy,std::span<const std::filesystem::path> protected_paths,std::stop_token);
    HEXLAB_IMAGE_EXPORT ~FilePublication();
    FilePublication(const FilePublication&)=delete;FilePublication& operator=(const FilePublication&)=delete;
    HEXLAB_IMAGE_EXPORT Result<std::uint64_t> append(std::span<const std::byte>);
    HEXLAB_IMAGE_EXPORT Result<bool> publish();
private:
    struct Impl;explicit FilePublication(std::unique_ptr<Impl>);std::unique_ptr<Impl> impl_;
};
}
