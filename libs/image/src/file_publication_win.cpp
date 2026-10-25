#include "hexlab/image/file_publication.hpp"
#include "image_testing.hpp"
#include <algorithm>
#include <optional>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
namespace hexlab {
namespace {
struct Failure {Error error;};
void require(bool value,const char* reason,ErrorCode code=ErrorCode::invalid_argument){if(!value)throw Failure{{code,reason}};}
Error native_error(const char* action){return {ErrorCode::io,std::string(action)+" (Windows error "+std::to_string(GetLastError())+")"};}
template<class F>auto guarded(F f)->decltype(f()){
    try{return f();}catch(const Failure& error){return error.error;}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate file publication"};}catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Publication exceeds allocation limits"};}catch(const std::filesystem::filesystem_error& error){return Error{ErrorCode::io,error.what()};}
}
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    Handle()=default;explicit Handle(HANDLE v):value(v){};Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
    Handle(Handle&& other)noexcept:value(other.value){other.value=INVALID_HANDLE_VALUE;}
    void close(){if(value!=INVALID_HANDLE_VALUE){CloseHandle(value);value=INVALID_HANDLE_VALUE;}}
    ~Handle(){close();}
};
struct Temporary {
    std::filesystem::path path;Handle handle;bool published=false;
    ~Temporary(){handle.close();if(!published && !path.empty())DeleteFileW(path.c_str());}
};
bool missing(DWORD error){return error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND;}
BY_HANDLE_FILE_INFORMATION information(HANDLE h){BY_HANDLE_FILE_INFORMATION value{};if(!GetFileInformationByHandle(h,&value))throw Failure{native_error("Cannot inspect file identity")};return value;}
bool same(const BY_HANDLE_FILE_INFORMATION& a,const BY_HANDLE_FILE_INFORMATION& b){return a.dwVolumeSerialNumber==b.dwVolumeSerialNumber && a.nFileIndexHigh==b.nFileIndexHigh && a.nFileIndexLow==b.nFileIndexLow;}
bool equal_path(const std::filesystem::path& a,const std::filesystem::path& b){const auto& x=a.native();const auto& y=b.native();require(x.size()<=32767 && y.size()<=32767,"Publication path exceeds native limits");return CompareStringOrdinal(x.data(),static_cast<int>(x.size()),y.data(),static_cast<int>(y.size()),TRUE)==CSTR_EQUAL;}
std::filesystem::path normalized(const std::filesystem::path& path){return std::filesystem::weakly_canonical(std::filesystem::absolute(path));}
std::unique_ptr<Temporary> reserve(const std::filesystem::path& directory,const wchar_t* prefix){
    for(unsigned attempt=0;attempt<8;++attempt){std::array<unsigned char,16> random{};require(BCryptGenRandom(nullptr,random.data(),static_cast<ULONG>(random.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)==0,"Cannot generate output temporary identity",ErrorCode::io);constexpr wchar_t hex[]=L"0123456789abcdef";std::wstring name=prefix;for(auto byte:random){name+=hex[byte>>4];name+=hex[byte&15];}name+=L".tmp";
        auto output=std::make_unique<Temporary>();output->path=directory/name;output->handle.value=CreateFileW(output->path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
        if(output->handle.value!=INVALID_HANDLE_VALUE)return output;auto error=GetLastError();output->published=true;if(error!=ERROR_FILE_EXISTS && error!=ERROR_ALREADY_EXISTS)throw Failure{native_error("Cannot reserve output temporary")};}
    throw Failure{{ErrorCode::conflict,"Cannot reserve a unique output temporary"}};
}
}
struct FilePublication::Impl {
    std::filesystem::path destination;ExistingFilePolicy policy;std::stop_token stop;std::unique_ptr<Temporary> temporary;
    std::vector<Handle> protected_handles;std::vector<BY_HANDLE_FILE_INFORMATION> protected_identities;
    bool finished=false,failed=false;uint64_t bytes=0;
    void check_stop(){require(!stop.stop_requested(),"File export canceled",ErrorCode::canceled);}
    std::optional<BY_HANDLE_FILE_INFORMATION> check_destination(){
        for(const auto* suffix:{L"-wal",L"-shm"}){auto companion=destination;companion+=suffix;require(!std::filesystem::exists(companion),"Export destination has database journal companions",ErrorCode::busy);}
        Handle target{CreateFileW(destination.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
        if(target.value==INVALID_HANDLE_VALUE){if(missing(GetLastError()))return {};throw Failure{native_error("Cannot inspect export destination")};}
        auto identity=information(target.value);require(!(identity.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY),"Export destination is a directory");for(auto& protected_identity:protected_identities)require(!same(identity,protected_identity),"Export destination aliases a protected input or project");require(policy==ExistingFilePolicy::replace,"Export destination already exists",ErrorCode::conflict);return identity;
    }
};
FilePublication::FilePublication(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
FilePublication::~FilePublication()=default;
Result<std::unique_ptr<FilePublication>> FilePublication::create(const std::filesystem::path& destination,ExistingFilePolicy policy,std::span<const std::filesystem::path> paths,std::stop_token stop){return guarded([&]()->Result<std::unique_ptr<FilePublication>>{
    require(!destination.empty() && destination.native().find(wchar_t{})==std::wstring::npos && destination.native().size()<=32767,"Invalid export destination");require(policy==ExistingFilePolicy::reject || policy==ExistingFilePolicy::replace,"Unknown file replacement policy");require(paths.size()<=1000,"Too many protected export paths");auto impl=std::make_unique<Impl>();impl->stop=stop;impl->check_stop();impl->destination=normalized(destination);impl->policy=policy;
    for(auto& path:paths){if(path.empty())continue;impl->check_stop();require(path.native().find(wchar_t{})==std::wstring::npos,"Invalid protected path");require(!equal_path(normalized(path),impl->destination),"Export destination is a protected input or project path");Handle guard{CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
        if(guard.value==INVALID_HANDLE_VALUE){if(missing(GetLastError()))continue;throw Failure{native_error("Cannot protect input or project identity")};}impl->protected_identities.push_back(information(guard.value));impl->protected_handles.push_back(std::move(guard));}
    impl->check_destination();impl->temporary=reserve(impl->destination.parent_path(),L".hexlab-export-");return std::unique_ptr<FilePublication>(new FilePublication(std::move(impl)));
});}
Result<uint64_t> FilePublication::append(std::span<const std::byte> data){auto result=guarded([&]()->Result<uint64_t>{
    require(!impl_->finished && !impl_->failed,"Output publication is no longer writable");impl_->check_stop();require(data.size()<=UINT64_MAX-impl_->bytes,"Export byte count overflow",ErrorCode::overflow);
#ifdef HEXLAB_IMAGE_TESTING
    require(!image_testing::take_write_failure(),"Injected output write failure",ErrorCode::io);
#endif
    size_t cursor=0;while(cursor<data.size()){impl_->check_stop();DWORD written=0;auto amount=static_cast<DWORD>(std::min<size_t>(65536,data.size()-cursor));if(!WriteFile(impl_->temporary->handle.value,data.data()+cursor,amount,&written,nullptr))throw Failure{native_error("Cannot write output temporary")};require(written==amount,"Output temporary returned a short write",ErrorCode::io);cursor+=written;}impl_->bytes+=data.size();return impl_->bytes;
});if(!result)impl_->failed=true;return result;}
Result<bool> FilePublication::publish(){auto result=guarded([&]()->Result<bool>{
    require(!impl_->finished && !impl_->failed,"Output publication is no longer available");impl_->check_stop();if(!FlushFileBuffers(impl_->temporary->handle.value))throw Failure{native_error("Cannot flush complete output")};impl_->temporary->handle.close();auto expected=impl_->check_destination();impl_->check_stop();
#ifdef HEXLAB_IMAGE_TESTING
    require(!image_testing::take_publication_failure(),"Injected output publication failure",ErrorCode::io);
#endif
    if(expected){
        Handle old{CreateFileW(impl_->destination.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};if(old.value==INVALID_HANDLE_VALUE){auto code=GetLastError();if(code==ERROR_SHARING_VIOLATION || code==ERROR_LOCK_VIOLATION)throw Failure{{ErrorCode::busy,"Export destination is still open in another reader or writer"}};throw Failure{native_error("Cannot reserve export destination")};}
        auto identity=information(old.value);require(same(identity,*expected),"Export destination changed during publication",ErrorCode::conflict);for(auto& protected_identity:impl_->protected_identities)require(!same(identity,protected_identity),"Export destination aliases a protected input or project");auto backup=reserve(impl_->destination.parent_path(),L".hexlab-export-previous-");backup->handle.close();impl_->check_stop();
        if(!ReplaceFileW(impl_->destination.c_str(),impl_->temporary->path.c_str(),backup->path.c_str(),0,nullptr,nullptr)){
            auto error=GetLastError();old.close();Handle retained{CreateFileW(backup->path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};BY_HANDLE_FILE_INFORMATION retained_info{};bool inspected=retained.value!=INVALID_HANDLE_VALUE && GetFileInformationByHandle(retained.value,&retained_info);bool has_old=inspected && same(retained_info,identity);retained.close();
            if(!inspected){backup->published=true;auto native=backup->path.u8string();throw Failure{{ErrorCode::io,"Output publication failed; recovery file retained at "+std::string(reinterpret_cast<const char*>(native.data()),native.size())}};}
            if(has_old && !MoveFileExW(backup->path.c_str(),impl_->destination.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){backup->published=true;auto native=backup->path.u8string();throw Failure{{ErrorCode::io,"Output publication failed; preceding file retained at "+std::string(reinterpret_cast<const char*>(native.data()),native.size())}};}
            throw Failure{{ErrorCode::io,"Cannot replace complete output (Windows error "+std::to_string(error)+")"}};
        }
    }else if(!MoveFileExW(impl_->temporary->path.c_str(),impl_->destination.c_str(),MOVEFILE_WRITE_THROUGH)){
        auto error=GetLastError();if(error==ERROR_FILE_EXISTS || error==ERROR_ALREADY_EXISTS)throw Failure{{ErrorCode::conflict,"Export destination appeared during publication"}};throw Failure{native_error("Cannot publish complete output")};
    }
    impl_->temporary->published=true;impl_->finished=true;return true;
});if(!result)impl_->failed=true;return result;}
}
