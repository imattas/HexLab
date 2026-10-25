#pragma once
#include "hexlab/workspace/workspace.hpp"

namespace hexlab {
struct DocumentCompletion {OpenTicket ticket;Result<std::shared_ptr<const DocumentSnapshot>> result;};
// One worker and one pending replacement. Only the newest unread completion
// needs retaining for a single-document workspace; tickets still gate commits.
class DocumentJobs {
public:
    HEXLAB_WORKSPACE_EXPORT DocumentJobs();
    HEXLAB_WORKSPACE_EXPORT ~DocumentJobs();
    DocumentJobs(const DocumentJobs&)=delete;
    DocumentJobs& operator=(const DocumentJobs&)=delete;
    HEXLAB_WORKSPACE_EXPORT void submit(OpenRequest,OpenTicket);
    HEXLAB_WORKSPACE_EXPORT void cancel();
    HEXLAB_WORKSPACE_EXPORT bool busy() const;
    HEXLAB_WORKSPACE_EXPORT std::optional<DocumentCompletion> take_completed();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
