#include "native_files.hpp"
#include "testing.hpp"
namespace hexlab::database::detail {
namespace {
void publication_fault(){
#ifdef HEXLAB_DATABASE_TESTING
    if(auto error=testing::take_publication_failure())throw Failure{{*error,"Injected publication failure"}};
#endif
}
}
OwnedFile::~OwnedFile(){
    if(released)return;std::error_code ignored;std::filesystem::remove(path,ignored);
    if(journals){auto wal=path;wal+=L"-wal";std::filesystem::remove(wal,ignored);auto shm=path;shm+=L"-shm";std::filesystem::remove(shm,ignored);}
}
Error native_error(const char* operation){return {ErrorCode::io,std::string(operation)+" (Windows error "+std::to_string(GetLastError())+")"};}
std::shared_ptr<OwnedFile> reserve_owned_file(const std::filesystem::path& directory,const wchar_t* prefix,bool journals){
    for(int attempt=0;attempt<8;++attempt){
        const auto uuid=new_uuid();std::wstring name=prefix;constexpr wchar_t digits[]=L"0123456789abcdef";
        for(auto byte:uuid){const auto value=std::to_integer<unsigned>(byte);name+=digits[value>>4];name+=digits[value&15];}name+=L".tmp";
        const auto path=directory/name;NativeHandle handle{CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY,nullptr)};
        if(handle.value!=INVALID_HANDLE_VALUE){
            try{auto file=std::make_shared<OwnedFile>();file->path=path;file->journals=journals;return file;}
            catch(...){CloseHandle(handle.value);handle.value=INVALID_HANDLE_VALUE;DeleteFileW(path.c_str());throw;}
        }
        const auto error=GetLastError();if(error!=ERROR_FILE_EXISTS && error!=ERROR_ALREADY_EXISTS)throw Failure{native_error("Cannot reserve temporary file")};
    }
    throw Failure{{ErrorCode::conflict,"Cannot reserve a unique temporary file"}};
}
bool same_file(const std::filesystem::path& left,const std::filesystem::path& right){
    NativeHandle a{CreateFileW(left.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
    if(a.value==INVALID_HANDLE_VALUE)throw Failure{native_error("Cannot inspect source file identity")};
    NativeHandle b{CreateFileW(right.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
    if(b.value==INVALID_HANDLE_VALUE){if(GetLastError()==ERROR_FILE_NOT_FOUND || GetLastError()==ERROR_PATH_NOT_FOUND)return false;throw Failure{native_error("Cannot inspect destination identity")};}
    BY_HANDLE_FILE_INFORMATION x{},y{};if(!GetFileInformationByHandle(a.value,&x) || !GetFileInformationByHandle(b.value,&y))throw Failure{native_error("Cannot inspect file identity")};
    return x.dwVolumeSerialNumber==y.dwVolumeSerialNumber && x.nFileIndexHigh==y.nFileIndexHigh && x.nFileIndexLow==y.nFileIndexLow;
}
std::vector<std::unique_ptr<NativeHandle>> protect_files(const std::filesystem::path& destination,std::span<const std::filesystem::path> paths){
    auto target=std::filesystem::weakly_canonical(std::filesystem::absolute(destination));std::vector<std::unique_ptr<NativeHandle>> guards;guards.reserve(paths.size());
    for(auto& path:paths){if(path.empty())continue;auto source=std::filesystem::weakly_canonical(std::filesystem::absolute(path));const auto& left=source.native();const auto& right=target.native();if(left.size()>32767 || right.size()>32767)throw Failure{{ErrorCode::invalid_argument,"Save As path exceeds native limits"}};
        if(CompareStringOrdinal(left.data(),int(left.size()),right.data(),int(right.size()),TRUE)==CSTR_EQUAL)throw Failure{{ErrorCode::invalid_argument,"Save As destination is a protected input or project path"}};
        auto guard=std::make_unique<NativeHandle>(CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));
        if(guard->value==INVALID_HANDLE_VALUE){auto error=GetLastError();if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND)continue;throw Failure{native_error("Cannot protect Save As source")};}
        if(same_file(path,target))throw Failure{{ErrorCode::invalid_argument,"Save As destination aliases a protected input or project"}};guards.push_back(std::move(guard));
    }return guards;
}
void publish_file(OwnedFile& source,const std::filesystem::path& destination,ReplacePolicy policy){
    // An exclusive read/write handle blocks SQLite readers/writers while allowing
    // the final rename to replace this old file. Only empty WAL scratch may move.
    struct PublicationGuard {
        NativeHandle current;
        std::vector<std::pair<std::filesystem::path,std::shared_ptr<OwnedFile>>> scratch;
        bool published=false;
        ~PublicationGuard(){
            if(!published)for(auto it=scratch.rbegin();it!=scratch.rend();++it)MoveFileExW(it->second->path.c_str(),it->first.c_str(),0);
        }
    } guard;
    if(std::filesystem::exists(destination)){
        if(policy==ReplacePolicy::fail_if_exists)throw Failure{{ErrorCode::conflict,"Destination already exists"}};
        guard.current.value=CreateFileW(destination.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(guard.current.value==INVALID_HANDLE_VALUE){const auto code=GetLastError();if(code==ERROR_SHARING_VIOLATION || code==ERROR_LOCK_VIOLATION)throw Failure{{ErrorCode::busy,"Destination is still open in another reader or writer"}};throw Failure{native_error("Cannot reserve destination for publication")};}
        BY_HANDLE_FILE_INFORMATION old_identity{};if(!GetFileInformationByHandle(guard.current.value,&old_identity))throw Failure{native_error("Cannot inspect preceding destination")};
        auto wal=destination;wal+=L"-wal";
        if(std::filesystem::exists(wal) && std::filesystem::file_size(wal)!=0)throw Failure{{ErrorCode::busy,"Destination contains journal data; recover or checkpoint it before replacement"}};
        auto rollback_journal=destination;rollback_journal+=L"-journal";
        if(std::filesystem::exists(rollback_journal))throw Failure{{ErrorCode::busy,"Destination contains rollback-journal data; recover or checkpoint it before replacement"}};
        guard.scratch.reserve(2);
        for(const auto* suffix:{L"-wal",L"-shm"}){
            auto original=destination;original+=suffix;if(!std::filesystem::exists(original))continue;
            auto shadow=reserve_owned_file(destination.parent_path(),L".hexlab-journal-");
            // Record ownership before the move; failure leaves the original intact.
            guard.scratch.emplace_back(original,shadow);
            if(!MoveFileExW(original.c_str(),shadow->path.c_str(),MOVEFILE_REPLACE_EXISTING)){guard.scratch.pop_back();throw Failure{native_error("Cannot isolate destination journal scratch")};}
        }
        publication_fault();auto previous=reserve_owned_file(destination.parent_path(),L".hexlab-previous-");
        if(!ReplaceFileW(destination.c_str(),source.path.c_str(),previous->path.c_str(),0,nullptr,nullptr)){
            const auto error=GetLastError();CloseHandle(guard.current.value);guard.current.value=INVALID_HANDLE_VALUE;
            NativeHandle retained{CreateFileW(previous->path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr)};
            BY_HANDLE_FILE_INFORMATION identity{};const bool has_old=retained.value!=INVALID_HANDLE_VALUE && GetFileInformationByHandle(retained.value,&identity) && identity.dwVolumeSerialNumber==old_identity.dwVolumeSerialNumber && identity.nFileIndexHigh==old_identity.nFileIndexHigh && identity.nFileIndexLow==old_identity.nFileIndexLow;
            if(retained.value!=INVALID_HANDLE_VALUE){CloseHandle(retained.value);retained.value=INVALID_HANDLE_VALUE;}
            if(has_old && !MoveFileExW(previous->path.c_str(),destination.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){
                previous->released=true;throw Failure{{ErrorCode::io,"Publication failed; preceding project retained in a .hexlab-previous- recovery file beside the destination"}};
            }
            throw Failure{{ErrorCode::io,"Cannot replace complete project (Windows error "+std::to_string(error)+")"}};
        }
        // ReplaceFileW filled this owned path with the preceding complete
        // destination. Transfer ownership to recovery discovery on success.
        previous->released=true;
        source.released=true;guard.published=true;return;
    }else{
        auto wal=destination;wal+=L"-wal";auto shm=destination;shm+=L"-shm";
        auto rollback_journal=destination;rollback_journal+=L"-journal";
        if(std::filesystem::exists(wal) || std::filesystem::exists(shm) || std::filesystem::exists(rollback_journal))throw Failure{{ErrorCode::busy,"Destination has orphaned journal companions"}};
    }
    // A destination appearing after the existence check is a conflict, even if
    // replacement was requested: it has not passed the journal/handle checks.
    publication_fault();const auto flags=MOVEFILE_WRITE_THROUGH;
    if(!MoveFileExW(source.path.c_str(),destination.c_str(),flags)){
        const auto code=GetLastError();if(code==ERROR_FILE_EXISTS || code==ERROR_ALREADY_EXISTS)throw Failure{{ErrorCode::conflict,"Destination already exists"}};
        throw Failure{native_error("Cannot publish complete project")};
    }
    source.released=true;guard.published=true;
}
}
