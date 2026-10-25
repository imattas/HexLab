#include "hexlab/image/file_storage.hpp"
#include <limits>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace hexlab {
struct FileStorage::Impl {
    std::filesystem::path path;
    std::shared_ptr<const void> backing_owner;
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    const std::byte* data = nullptr;
    std::uint64_t length = 0;
    ~Impl() {
        if (data) UnmapViewOfFile(data);
        if (mapping) CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
};
namespace {
Error io_error(const char* action) {
    return {ErrorCode::io, std::string(action) + " (Windows error " + std::to_string(GetLastError()) + ")"};
}
}
FileStorage::FileStorage(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
FileStorage::~FileStorage() = default;
Result<std::shared_ptr<const FileStorage>> FileStorage::open(const std::filesystem::path& path) {
    return open_owned(path,{});
}
Result<std::shared_ptr<const FileStorage>> FileStorage::open_owned(const std::filesystem::path& path,std::shared_ptr<const void> owner) {
    auto impl = std::make_unique<Impl>();
    impl->path=path;impl->backing_owner=std::move(owner);
    impl->file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (impl->file == INVALID_HANDLE_VALUE) return io_error("Cannot open input");
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(impl->file, &info)) return io_error("Cannot inspect input");
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return Error{ErrorCode::io,"Input is a directory"};
    if (GetFileType(impl->file) != FILE_TYPE_DISK)
        return Error{ErrorCode::io,"Input is not a disk file"};
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(impl->file,&length) || length.QuadPart < 0) return io_error("Cannot size input");
    impl->length = static_cast<std::uint64_t>(length.QuadPart);
    if (impl->length > std::numeric_limits<std::size_t>::max())
        return Error{ErrorCode::resource_limit,"Input cannot fit this host's address space"};
    if (impl->length != 0) {
        impl->mapping = CreateFileMappingW(impl->file,nullptr,PAGE_READONLY,0,0,nullptr);
        if (!impl->mapping) return io_error("Cannot create input mapping");
        impl->data = static_cast<const std::byte*>(MapViewOfFile(impl->mapping,FILE_MAP_READ,0,0,0));
        if (!impl->data) return io_error("Cannot map input bytes");
    }
    return std::shared_ptr<const FileStorage>(new FileStorage(std::move(impl)));
}
std::uint64_t FileStorage::size() const noexcept { return impl_->length; }
const std::filesystem::path& FileStorage::backing_path()const noexcept{return impl_->path;}
Result<ByteView> FileStorage::read_at(FileOffset offset, std::size_t count) const {
    if (offset.value > impl_->length || count > impl_->length - offset.value)
        return Error{ErrorCode::out_of_bounds,"File read outside input at offset " + std::to_string(offset.value)};
    const auto* start = impl_->data ? impl_->data + static_cast<std::size_t>(offset.value) : nullptr;
    return ByteView{shared_from_this(), std::span<const std::byte>(start,count)};
}
}
