#include "hexlab/image/file_publication.hpp"
#include "image_testing.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <random>

namespace hexlab {
namespace {
struct Failure {Error error;};
void require(bool ok,const char* text,ErrorCode code=ErrorCode::invalid_argument){if(!ok)throw Failure{{code,text}};}
Error native_error(const char* action){return {ErrorCode::io,std::string(action)+" (errno "+std::to_string(errno)+")"};}
template<class F>auto guarded(F f)->decltype(f()){try{return f();}catch(const Failure& e){return e.error;}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate file publication"};}catch(const std::filesystem::filesystem_error& e){return Error{ErrorCode::io,e.what()};}}
struct Handle {int fd=-1;Handle()=default;explicit Handle(int value):fd(value){};Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;Handle(Handle&& other)noexcept:fd(other.fd){other.fd=-1;}Handle& operator=(Handle&& other)noexcept{if(this!=&other){if(fd>=0)::close(fd);fd=other.fd;other.fd=-1;}return *this;}void close(){if(fd>=0){::close(fd);fd=-1;}}~Handle(){close();}};
struct Temporary {std::filesystem::path path;Handle file;bool published=false;~Temporary(){file.close();if(!published&&!path.empty()){std::error_code ec;std::filesystem::remove(path,ec);}}};
std::filesystem::path normalized(const std::filesystem::path& path){return std::filesystem::weakly_canonical(std::filesystem::absolute(path));}
bool missing(int error){return error==ENOENT;}
struct Identity {dev_t dev{};ino_t ino{};};
Identity identity(int fd){struct stat s{};if(::fstat(fd,&s)!=0)throw Failure{native_error("Cannot inspect file identity")};return{s.st_dev,s.st_ino};}
bool same(Identity a,Identity b){return a.dev==b.dev&&a.ino==b.ino;}
std::unique_ptr<Temporary> reserve(const std::filesystem::path& directory){
    std::random_device random;constexpr char digits[]="0123456789abcdef";
    for(unsigned attempt=0;attempt<8;++attempt){std::string name=".hexlab-export-";for(int i=0;i<16;++i){auto v=static_cast<unsigned>(random())&255;name+=digits[v>>4];name+=digits[v&15];}name+=".tmp";auto temp=std::make_unique<Temporary>();temp->path=directory/name;temp->file.fd=::open(temp->path.c_str(),O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(temp->file.fd>=0)return temp;if(errno!=EEXIST)throw Failure{native_error("Cannot reserve output temporary")};}
    throw Failure{{ErrorCode::conflict,"Cannot reserve a unique output temporary"}};
}
}
struct FilePublication::Impl {
    std::filesystem::path destination;ExistingFilePolicy policy;std::stop_token stop;std::unique_ptr<Temporary> temporary;
    std::vector<Handle> protected_handles;std::vector<Identity> protected_identities;bool finished=false,failed=false;std::uint64_t bytes=0;
    void check_stop(){require(!stop.stop_requested(),"File export canceled",ErrorCode::canceled);}
    std::optional<Identity> check_destination(){
        for(const char* suffix:{"-wal","-shm"}){auto companion=destination;companion+=suffix;require(!std::filesystem::exists(companion),"Export destination has database journal companions",ErrorCode::busy);}
        int fd=::open(destination.c_str(),O_RDONLY|O_CLOEXEC);if(fd<0){if(missing(errno))return{};throw Failure{native_error("Cannot inspect export destination")};}
        Handle target{fd};auto id=identity(fd);struct stat st{};if(::fstat(fd,&st)!=0)throw Failure{native_error("Cannot inspect export destination")};require(S_ISREG(st.st_mode),"Export destination is not a regular file");
        for(auto protected_id:protected_identities)require(!same(id,protected_id),"Export destination aliases a protected input or project");require(policy==ExistingFilePolicy::replace,"Export destination already exists",ErrorCode::conflict);return id;
    }
};
FilePublication::FilePublication(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
FilePublication::~FilePublication()=default;
Result<std::unique_ptr<FilePublication>> FilePublication::create(const std::filesystem::path& destination,ExistingFilePolicy policy,std::span<const std::filesystem::path> paths,std::stop_token stop){return guarded([&]()->Result<std::unique_ptr<FilePublication>>{
    require(!destination.empty()&&destination.native().find(std::filesystem::path::value_type{})==std::filesystem::path::string_type::npos,"Invalid export destination");require(policy==ExistingFilePolicy::reject||policy==ExistingFilePolicy::replace,"Unknown file replacement policy");require(paths.size()<=1000,"Too many protected export paths");auto impl=std::make_unique<Impl>();impl->stop=stop;impl->check_stop();impl->destination=normalized(destination);impl->policy=policy;
    for(const auto& path:paths){if(path.empty())continue;impl->check_stop();require(normalized(path)!=impl->destination,"Export destination is a protected input or project path");int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC);if(fd<0){if(missing(errno))continue;throw Failure{native_error("Cannot protect input or project identity")};}Handle guard{fd};impl->protected_identities.push_back(identity(fd));impl->protected_handles.push_back(std::move(guard));}
    impl->check_destination();impl->temporary=reserve(impl->destination.parent_path());return std::unique_ptr<FilePublication>(new FilePublication(std::move(impl)));
});}
Result<std::uint64_t> FilePublication::append(std::span<const std::byte> data){auto result=guarded([&]()->Result<std::uint64_t>{require(!impl_->finished&&!impl_->failed,"Output publication is no longer writable");impl_->check_stop();require(data.size()<=UINT64_MAX-impl_->bytes,"Export byte count overflow",ErrorCode::overflow);
#ifdef HEXLAB_IMAGE_TESTING
    require(!image_testing::take_write_failure(),"Injected output write failure",ErrorCode::io);
#endif
    std::size_t cursor=0;while(cursor<data.size()){impl_->check_stop();auto written=::write(impl_->temporary->file.fd,data.data()+cursor,data.size()-cursor);if(written<0){if(errno==EINTR)continue;throw Failure{native_error("Cannot write output temporary")};}if(written==0)throw Failure{{ErrorCode::io,"Output temporary returned a short write"}};cursor+=static_cast<std::size_t>(written);}impl_->bytes+=data.size();return impl_->bytes;});if(!result)impl_->failed=true;return result;}
Result<bool> FilePublication::publish(){auto result=guarded([&]()->Result<bool>{require(!impl_->finished&&!impl_->failed,"Output publication is no longer available");impl_->check_stop();if(::fsync(impl_->temporary->file.fd)!=0)throw Failure{native_error("Cannot flush complete output")};impl_->temporary->file.close();auto expected=impl_->check_destination();impl_->check_stop();
#ifdef HEXLAB_IMAGE_TESTING
    require(!image_testing::take_publication_failure(),"Injected output publication failure",ErrorCode::io);
#endif
    if(expected){int fd=::open(impl_->destination.c_str(),O_RDWR|O_CLOEXEC);if(fd<0)throw Failure{native_error("Cannot reserve export destination")};Handle old{fd};if(::flock(fd,LOCK_EX|LOCK_NB)!=0)throw Failure{{ErrorCode::busy,"Export destination is still open in another reader or writer"}};require(same(identity(fd),*expected),"Export destination changed during publication",ErrorCode::conflict);for(auto protected_id:impl_->protected_identities)require(!same(identity(fd),protected_id),"Export destination aliases a protected input or project");}
    if(::rename(impl_->temporary->path.c_str(),impl_->destination.c_str())!=0){if(errno==EEXIST)throw Failure{{ErrorCode::conflict,"Export destination appeared during publication"}};throw Failure{native_error("Cannot publish complete output")};}
    int dir=::open(impl_->destination.parent_path().c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(dir>=0){::fsync(dir);::close(dir);}impl_->temporary->published=true;impl_->finished=true;return true;});if(!result)impl_->failed=true;return result;}
}
