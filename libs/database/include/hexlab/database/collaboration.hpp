#pragma once
#include "hexlab/database/transaction.hpp"

namespace hexlab::database {
struct CollaborationConflict {
    std::uint64_t id = 0;
    std::uint64_t base_revision = 0;
    std::uint64_t observed_revision = 0;
    StateDelta proposal;
    bool resolved = false;
    bool accepted = false;
};
struct CollaborationSubmission {
    std::optional<CommitAck> committed;
    std::optional<CollaborationConflict> conflict;
};

// A local collaboration facade. Concurrent editable instances use the same
// SQLite file; stale deltas are retained for explicit review and rebase.
class ProjectCollaboration {
public:
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<ProjectCollaboration>> open(
        const std::filesystem::path&, std::stop_token);
    HEXLAB_DATABASE_EXPORT std::shared_ptr<ProjectStore> project() const;
    HEXLAB_DATABASE_EXPORT Result<std::shared_ptr<const ProjectState>> refresh(std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<CollaborationSubmission> submit(
        std::uint64_t base_revision, const StateDelta&, std::uint64_t group_id,
        std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<std::vector<CollaborationConflict>> conflicts(
        bool include_resolved = false, std::stop_token = {});
    // Returns the same conservative three-way rebase used during submission,
    // pinned to the caller's refreshed edit revision. An empty optional means
    // the proposal contains a conflict that needs a domain-specific decision.
    HEXLAB_DATABASE_EXPORT Result<std::optional<StateDelta>> preview_resolution(
        std::uint64_t conflict_id, std::uint64_t expected_revision, std::stop_token);
    // Apply a caller-rebased resolution delta and mark the proposal accepted
    // in one ProjectStore SQLite transaction. An empty resolution marks an
    // already-converged proposal accepted without adding a history revision.
    HEXLAB_DATABASE_EXPORT Result<CommitAck> resolve(
        std::uint64_t conflict_id, bool accept_proposal,
        std::uint64_t expected_revision, const StateDelta& resolution,
        std::uint64_t group_id, std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> dismiss(
        std::uint64_t conflict_id, std::uint64_t expected_revision,
        std::stop_token);
private:
    struct Impl;
    explicit ProjectCollaboration(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}
