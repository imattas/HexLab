#pragma once

#include "hexlab/automation/automation_export.hpp"
#include "hexlab/database/project_state.hpp"

namespace hexlab::automation {
class Project;

struct HistoricalPatch {
    FileOffset begin;
    std::uint64_t size = 0;
};
struct HistoricalFunctionDecision {
    std::uint64_t id = 0;
    Address entry{};
    bool suppressed = false;
    std::size_t chunk_count = 0;
};

// An immutable, independent projection of one exact durable history step.
// It owns its user-state and effective input, and can outlive the live Project.
// Reads use original file coordinates: no historical image mapping is inferred.
class HistoricalState {
public:
    const database::HistoryPreview& metadata() const noexcept { return preview_; }
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<database::Annotation>> annotations(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<database::Bookmark>> bookmarks(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<database::TypeDefinition>> types(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<database::TypeAssignment>> type_assignments(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<HistoricalPatch>> patches(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<RegionDecision>> regions(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<HistoricalFunctionDecision>> function_decisions(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<DecisionRange>> function_chunks(std::uint64_t decision_id, std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<UserReference>> user_references(std::size_t start=0, std::size_t count=256) const;
    HEXLAB_AUTOMATION_EXPORT Result<std::vector<std::byte>> read(FileOffset, std::size_t count) const;
    std::uint64_t input_size() const noexcept { return effective_->size(); }
private:
    friend class Project;
    HistoricalState(database::HistoryPreview preview, std::shared_ptr<const ByteStorage> effective)
        : preview_(std::move(preview)), effective_(std::move(effective)) {}
    database::HistoryPreview preview_;
    std::shared_ptr<const ByteStorage> effective_;
};
}
