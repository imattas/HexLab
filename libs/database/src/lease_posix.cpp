#include "project_internal.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

namespace hexlab::database {
struct ProjectLease::Impl { int fd=-1; ~Impl(){if(fd>=0)::close(fd);} };
ProjectLease::ProjectLease(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
ProjectLease::~ProjectLease()=default;
Result<std::shared_ptr<ProjectLease>> ProjectLease::acquire(const ProjectUuid& uuid) {
    return detail::guarded([&]()->Result<std::shared_ptr<ProjectLease>> {
        constexpr char digits[]="0123456789abcdef";
        auto path=std::filesystem::temp_directory_path()/"hexlab-project-leases";
        std::error_code ec;std::filesystem::create_directories(path,ec);
        if(ec)return Error{ErrorCode::io,"Cannot create project lease directory: "+ec.message()};
        auto dir_status=std::filesystem::status(path,ec);
        if(ec || (dir_status.permissions() & std::filesystem::perms::others_write)!=std::filesystem::perms::none)
            return Error{ErrorCode::io,"Project lease directory has unsafe permissions"};
        std::string name="project-";
        for(auto byte:uuid){auto value=std::to_integer<unsigned>(byte);name+=digits[value>>4];name+=digits[value&15];}
        path/=name;
        int fd=::open(path.c_str(),O_CREAT|O_RDWR|O_CLOEXEC,0600);
        if(fd<0)return Error{ErrorCode::io,"Cannot open project lease (errno "+std::to_string(errno)+")"};
        if(::flock(fd,LOCK_EX|LOCK_NB)!=0){::close(fd);if(errno==EWOULDBLOCK || errno==EAGAIN)return Error{ErrorCode::busy,"Project has another editable owner; opened read only"};return Error{ErrorCode::io,"Cannot acquire project process lease"};}
        auto impl=std::make_unique<Impl>();impl->fd=fd;
        return std::shared_ptr<ProjectLease>(new ProjectLease(std::move(impl)));
    });
}
}
