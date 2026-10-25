#include "hexlab/image/file_storage.hpp"
#include <cerrno>
#include <limits>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace hexlab {
struct FileStorage::Impl {
    std::filesystem::path path;
    std::shared_ptr<const void> backing_owner;
    int file=-1;
    const std::byte* data=nullptr;
    std::uint64_t length=0;
    ~Impl(){if(data)::munmap(const_cast<std::byte*>(data),static_cast<std::size_t>(length));if(file>=0)::close(file);}
};
namespace {
Error io_error(const char* action){return {ErrorCode::io,std::string(action)+" (errno "+std::to_string(errno)+")"};}
}
FileStorage::FileStorage(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
FileStorage::~FileStorage()=default;
Result<std::shared_ptr<const FileStorage>> FileStorage::open(const std::filesystem::path& path){return open_owned(path,{});}
Result<std::shared_ptr<const FileStorage>> FileStorage::open_owned(const std::filesystem::path& path,std::shared_ptr<const void> owner){
    auto impl=std::make_unique<Impl>();impl->path=path;impl->backing_owner=std::move(owner);
    impl->file=::open(path.c_str(),O_RDONLY|O_CLOEXEC);
    if(impl->file<0)return io_error("Cannot open input");
    struct stat info{};if(::fstat(impl->file,&info)!=0)return io_error("Cannot inspect input");
    if(!S_ISREG(info.st_mode))return Error{ErrorCode::io,"Input is not a regular file"};
    if(info.st_size<0)return Error{ErrorCode::io,"Cannot size input"};
    impl->length=static_cast<std::uint64_t>(info.st_size);
    if(impl->length>std::numeric_limits<std::size_t>::max())return Error{ErrorCode::resource_limit,"Input cannot fit this host's address space"};
    if(impl->length){auto mapped=::mmap(nullptr,static_cast<std::size_t>(impl->length),PROT_READ,MAP_PRIVATE,impl->file,0);if(mapped==MAP_FAILED)return io_error("Cannot map input bytes");impl->data=static_cast<const std::byte*>(mapped);}
    return std::shared_ptr<const FileStorage>(new FileStorage(std::move(impl)));
}
std::uint64_t FileStorage::size()const noexcept{return impl_->length;}
const std::filesystem::path& FileStorage::backing_path()const noexcept{return impl_->path;}
Result<ByteView> FileStorage::read_at(FileOffset offset,std::size_t count)const{
    if(offset.value>impl_->length || count>impl_->length-offset.value)return Error{ErrorCode::out_of_bounds,"File read outside input at offset "+std::to_string(offset.value)};
    const auto* start=impl_->data?impl_->data+static_cast<std::size_t>(offset.value):nullptr;
    return ByteView{shared_from_this(),std::span<const std::byte>(start,count)};
}
}
