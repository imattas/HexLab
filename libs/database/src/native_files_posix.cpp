#include "project_internal.hpp"
#include "native_files.hpp"
#include "testing.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <random>

namespace hexlab::database::detail {
OwnedFile::~OwnedFile() {
        if (released) return;
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        if (journals) {
            auto wal=path; wal += "-wal"; std::filesystem::remove(wal, ignored);
            auto shm=path; shm += "-shm"; std::filesystem::remove(shm, ignored);
        }
}
NativeHandle::NativeHandle(int fd):value(fd){}
NativeHandle::~NativeHandle(){if(value>=0)::close(value);}
Error native_error(const char* operation) { return {ErrorCode::io,std::string(operation)+" (errno "+std::to_string(errno)+")"}; }

std::shared_ptr<OwnedFile> reserve_owned_file(const std::filesystem::path& directory,const wchar_t* prefix,bool journals) {
    std::string prefix_utf8;
    for (auto ch:std::wstring(prefix)) prefix_utf8.push_back(ch<128?static_cast<char>(ch):'_');
    std::random_device random;
    constexpr char digits[]="0123456789abcdef";
    for(int attempt=0;attempt<8;++attempt) {
        std::string name=prefix_utf8;
        for(int i=0;i<16;++i){auto v=static_cast<unsigned>(random())&255;name+=digits[v>>4];name+=digits[v&15];}
        name += ".tmp";
        auto path=directory/name;
        int fd=::open(path.c_str(),O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(fd>=0){::close(fd);auto result=std::make_shared<OwnedFile>();result->path=std::move(path);result->journals=journals;return result;}
        if(errno!=EEXIST)throw Failure{native_error("Cannot reserve temporary file")};
    }
    throw Failure{{ErrorCode::conflict,"Cannot reserve a unique temporary file"}};
}
bool same_file(const std::filesystem::path& left,const std::filesystem::path& right) {
    struct stat a{},b{};
    if(::stat(left.c_str(),&a)!=0)throw Failure{native_error("Cannot inspect source file identity")};
    if(::stat(right.c_str(),&b)!=0){if(errno==ENOENT)return false;throw Failure{native_error("Cannot inspect destination identity")};}
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino;
}
std::vector<std::unique_ptr<NativeHandle>> protect_files(const std::filesystem::path& destination,std::span<const std::filesystem::path> paths) {
    auto target=std::filesystem::weakly_canonical(std::filesystem::absolute(destination));
    std::vector<std::unique_ptr<NativeHandle>> guards;
    for(const auto& path:paths){
        if(path.empty())continue;
        auto source=std::filesystem::weakly_canonical(std::filesystem::absolute(path));
        if(source==target)throw Failure{{ErrorCode::invalid_argument,"Save As destination is a protected input or project path"}};
        int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC);
        if(fd<0){if(errno==ENOENT)continue;throw Failure{native_error("Cannot protect Save As source")};}
        auto guard=std::make_unique<NativeHandle>(fd);
        if(same_file(path,target))throw Failure{{ErrorCode::invalid_argument,"Save As destination aliases a protected input or project"}};
        guards.push_back(std::move(guard));
    }
    return guards;
}
void publish_file(OwnedFile& source,const std::filesystem::path& destination,ReplacePolicy policy) {
#ifdef HEXLAB_DATABASE_TESTING
    if(auto error=testing::take_publication_failure())throw Failure{{*error,"Injected publication failure"}};
#endif
    // Flush the completed staging inode before making any final name durable.
    // SQLite has already checkpointed and closed it, but publication also owns
    // the ordering between file data and the directory operations below.
    int source_fd=::open(source.path.c_str(),O_RDWR|O_CLOEXEC|O_NONBLOCK
#ifdef O_NOFOLLOW
        |O_NOFOLLOW
#endif
    );
    if(source_fd<0)throw Failure{native_error("Cannot open complete project for durable publication")};
    NativeHandle staged{source_fd};
    struct stat staged_identity{},staged_path_identity{};
    if(::fstat(staged.value,&staged_identity)!=0 || ::lstat(source.path.c_str(),&staged_path_identity)!=0)
        throw Failure{native_error("Cannot inspect complete project publication identity")};
    if(!S_ISREG(staged_identity.st_mode) || !S_ISREG(staged_path_identity.st_mode) ||
       staged_identity.st_dev!=staged_path_identity.st_dev || staged_identity.st_ino!=staged_path_identity.st_ino)
        throw Failure{{ErrorCode::conflict,"Complete project staging path is not the expected regular file"}};
    if(::fsync(staged.value)!=0)throw Failure{native_error("Cannot synchronize complete project before publication")};
    struct stat destination_identity{};
    const bool exists=::lstat(destination.c_str(),&destination_identity)==0;
    if(!exists && errno!=ENOENT)throw Failure{native_error("Cannot inspect publication destination")};
    const auto check_companions=[&](bool replacing){
        for(const char* suffix:{"-journal","-wal","-shm"}){
            auto companion=destination;companion+=suffix;
            struct stat identity{};
            if(::lstat(companion.c_str(),&identity)==0){
                if(replacing && std::string(suffix)=="-wal" && S_ISREG(identity.st_mode) && identity.st_size==0)continue;
                throw Failure{{ErrorCode::busy,"Destination has live or unrecovered journal companions"}};
            }
            if(errno!=ENOENT)throw Failure{native_error("Cannot inspect destination journal companions")};
        }
    };
    if(exists && policy==ReplacePolicy::fail_if_exists)throw Failure{{ErrorCode::conflict,"Destination already exists"}};
    if(exists) {
        if(!S_ISREG(destination_identity.st_mode))
            throw Failure{{ErrorCode::invalid_argument,"Replacement destination must be a regular file, not a symlink or special file"}};
        check_companions(true);
        int fd=::open(destination.c_str(),O_RDWR|O_CLOEXEC|O_NONBLOCK
#ifdef O_NOFOLLOW
            |O_NOFOLLOW
#endif
        );
        if(fd<0)throw Failure{native_error("Cannot reserve destination for publication")};
        NativeHandle guard{fd};
        if(::flock(fd,LOCK_EX|LOCK_NB)!=0)throw Failure{{ErrorCode::busy,"Destination is still open in another reader or writer"}};
        auto parent=destination.parent_path();if(parent.empty())parent=".";
        int directory_fd=::open(parent.c_str(),O_RDONLY|O_CLOEXEC
#ifdef O_DIRECTORY
            |O_DIRECTORY
#endif
        );
        if(directory_fd<0)throw Failure{native_error("Cannot open project directory for durable publication")};
        NativeHandle directory{directory_fd};
        // Retain the old inode before replacing its final name. A hard link
        // preserves a complete recovery file without copying an entire project
        // during publication. Release the empty reservation before link(),
        // which refuses to overwrite any competing file at that random name.
        auto previous=reserve_owned_file(parent,L".hexlab-previous-");
        if(::unlink(previous->path.c_str())!=0)throw Failure{native_error("Cannot prepare preceding project recovery path")};
        previous->released=true;
        if(::link(destination.c_str(),previous->path.c_str())!=0)throw Failure{native_error("Cannot retain preceding project for recovery")};
        previous->released=false;
        struct stat old_identity{},retained_identity{};
        if(::fstat(guard.value,&old_identity)!=0 || ::lstat(previous->path.c_str(),&retained_identity)!=0)
            throw Failure{native_error("Cannot inspect preceding project recovery identity")};
        if(!S_ISREG(old_identity.st_mode) || !S_ISREG(retained_identity.st_mode) ||
           old_identity.st_dev!=destination_identity.st_dev || old_identity.st_ino!=destination_identity.st_ino ||
           old_identity.st_dev!=retained_identity.st_dev || old_identity.st_ino!=retained_identity.st_ino)
            throw Failure{{ErrorCode::conflict,"Destination changed before publication"}};
        // A durable directory entry alone does not guarantee that the inode's
        // data reached storage. Flush the retained file before its link name.
        if(::fsync(guard.value)!=0)throw Failure{native_error("Cannot synchronize preceding project recovery data")};
        if(::fsync(directory.value)!=0)throw Failure{native_error("Cannot synchronize preceding project recovery path")};
        struct stat current_destination{},current_source{};
        if(::lstat(destination.c_str(),&current_destination)!=0 || ::lstat(source.path.c_str(),&current_source)!=0)
            throw Failure{native_error("Cannot recheck project publication identities")};
        if(!S_ISREG(current_destination.st_mode) || !S_ISREG(current_source.st_mode) ||
           current_destination.st_dev!=old_identity.st_dev || current_destination.st_ino!=old_identity.st_ino ||
           current_source.st_dev!=staged_identity.st_dev || current_source.st_ino!=staged_identity.st_ino)
            throw Failure{{ErrorCode::conflict,"Project publication path changed before replacement"}};
        check_companions(true);
        // Once replacement is attempted, preserve the flushed recovery inode
        // even if the filesystem reports an ambiguous rename or sync error.
        previous->released=true;
        source.released=true;
        if(::rename(source.path.c_str(),destination.c_str())!=0){
            const auto error=errno;
            throw Failure{{ErrorCode::io,"Cannot replace complete project; recovery and any remaining staging file were retained (errno "+std::to_string(error)+")"}};
        }
        if(::fsync(directory.value)!=0)throw Failure{{ErrorCode::io,"Project was published, but its directory could not be synchronized"}};
    } else {
        check_companions(false);
        auto parent=destination.parent_path();if(parent.empty())parent=".";
        int directory_fd=::open(parent.c_str(),O_RDONLY|O_CLOEXEC
#ifdef O_DIRECTORY
            |O_DIRECTORY
#endif
        );
        if(directory_fd<0)throw Failure{native_error("Cannot open project directory for durable publication")};
        NativeHandle directory{directory_fd};
        // link() provides an atomic no-replace publication on the same filesystem.
        // A check followed by rename() could overwrite a destination created in
        // the intervening race, despite fail_if_exists being requested.
        struct stat current_source{};
        if(::lstat(source.path.c_str(),&current_source)!=0)
            throw Failure{native_error("Cannot recheck complete project publication identity")};
        if(!S_ISREG(current_source.st_mode) || current_source.st_dev!=staged_identity.st_dev || current_source.st_ino!=staged_identity.st_ino)
            throw Failure{{ErrorCode::conflict,"Complete project staging path changed before publication"}};
        check_companions(false);
        if(::link(source.path.c_str(),destination.c_str())!=0){if(errno==EEXIST)throw Failure{{ErrorCode::conflict,"Destination already exists"}};throw Failure{native_error("Cannot publish complete project")};}
        source.released=true;
        const bool removed_staging=::unlink(source.path.c_str())==0;
        // Even if cleanup fails, synchronize the successfully published name.
        if(::fsync(directory.value)!=0)throw Failure{{ErrorCode::io,"Project was published, but its directory could not be synchronized"}};
        if(!removed_staging)throw Failure{{ErrorCode::io,"Project was durably published, but its staging link could not be removed"}};
    }
    source.released=true;
}
}
