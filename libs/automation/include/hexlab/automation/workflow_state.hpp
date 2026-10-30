#pragma once
#include "hexlab/database/project_state.hpp"

namespace hexlab::automation {
// Envelope and application schemas are independently versioned. Payloads are
// opaque bytes; loading never executes code or deserializes application objects.
inline constexpr std::uint32_t workflow_state_format_version = 1;
inline constexpr std::size_t maximum_workflow_state = 1024 * 1024;
inline constexpr std::size_t maximum_workflow_namespace = 128;
struct WorkflowState {
    database::ProjectUuid project_uuid{};
    std::uint64_t edit_revision = 0;
    std::string application;
    std::uint32_t schema_version = 1;
    std::vector<std::byte> payload;
};
}
