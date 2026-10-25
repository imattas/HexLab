#pragma once
#include "project_internal.hpp"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
namespace hexlab::database::detail {
struct OwnedFile {
    std::filesystem::path path;bool journals=false,released=false;
    ~OwnedFile();
};
struct NativeHandle {
    HANDLE value=INVALID_HANDLE_VALUE;
    NativeHandle()=default;
    explicit NativeHandle(HANDLE handle):value(handle){}
    NativeHandle(const NativeHandle&)=delete;NativeHandle& operator=(const NativeHandle&)=delete;
    ~NativeHandle(){if(value!=INVALID_HANDLE_VALUE && value!=nullptr)CloseHandle(value);}
};
Error native_error(const char* operation);
std::shared_ptr<OwnedFile> reserve_owned_file(const std::filesystem::path& directory,const wchar_t* prefix,bool journals=false);
bool same_file(const std::filesystem::path&,const std::filesystem::path&);
// Held handles deny deletion/replacement until project publication finishes.
std::vector<std::unique_ptr<NativeHandle>> protect_files(const std::filesystem::path& destination,std::span<const std::filesystem::path>);
void publish_file(OwnedFile&,const std::filesystem::path&,ReplacePolicy);
}
#else
namespace hexlab::database::detail {
struct OwnedFile { std::filesystem::path path; bool journals=false,released=false; ~OwnedFile(); };
struct NativeHandle { int value=-1; NativeHandle()=default; explicit NativeHandle(int); NativeHandle(const NativeHandle&)=delete; NativeHandle& operator=(const NativeHandle&)=delete; ~NativeHandle(); };
Error native_error(const char* operation);
std::shared_ptr<OwnedFile> reserve_owned_file(const std::filesystem::path&,const wchar_t*,bool journals=false);
bool same_file(const std::filesystem::path&,const std::filesystem::path&);
std::vector<std::unique_ptr<NativeHandle>> protect_files(const std::filesystem::path&,std::span<const std::filesystem::path>);
void publish_file(OwnedFile&,const std::filesystem::path&,ReplacePolicy);
}
#endif
