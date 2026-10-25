#pragma once
#include "hexlab/database/project_state.hpp"
namespace hexlab::database {
class ProjectLease {
public:
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<ProjectLease>> acquire(const ProjectUuid&);
    HEXLAB_DATABASE_EXPORT ~ProjectLease();
    ProjectLease(const ProjectLease&)=delete;ProjectLease& operator=(const ProjectLease&)=delete;
private:
    struct Impl;explicit ProjectLease(std::unique_ptr<Impl>);std::unique_ptr<Impl> impl_;
};
}
