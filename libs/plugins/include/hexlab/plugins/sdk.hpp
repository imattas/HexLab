#pragma once

#include "hexlab/plugins/sdk.h"

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
#include <utility>

namespace hexlab::plugins::sdk {
inline constexpr std::uint32_t abi_major = HEXLAB_PLUGIN_ABI_MAJOR;
inline constexpr std::uint32_t abi_minor = HEXLAB_PLUGIN_ABI_MINOR;

namespace detail {
template <typename Record>
inline bool initialize_page_records(Record* records, std::uint32_t capacity,
                                    std::uint32_t maximum = HEXLAB_PROJECT_MAX_PAGE) noexcept {
    if (capacity > maximum || (capacity && !records)) return false;
    for (std::uint32_t i = 0; i < capacity; ++i)
        records[i].struct_size = static_cast<std::uint32_t>(sizeof(Record));
    return true;
}
} // namespace detail

/* Revision-checked opaque state scoped to this plugin ID. The host retains
   it across this module's unload/reload while the PluginManager is alive. */
class PluginStateClient {
public:
    PluginStateClient() = default;
    explicit PluginStateClient(const HexLabHostApi* host) noexcept {
        if (HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, plugin_state_api) && host->plugin_state_api &&
            HEXLAB_PLUGIN_HAS_FIELD(host->plugin_state_api, HexLabPluginStateApi, erase) &&
            host->plugin_state_api->api_version == HEXLAB_PLUGIN_STATE_API_VERSION &&
            host->plugin_state_api->get && host->plugin_state_api->set && host->plugin_state_api->erase)
            api_ = host->plugin_state_api;
    }
    bool available() const noexcept { return api_ != nullptr; }
    int32_t get(const char* key, uint8_t* output, uint32_t capacity,
                uint32_t& required, uint64_t& revision) const noexcept {
        required = 0; revision = 0;
        if (!api_ || (capacity && !output)) return HEXLAB_PLUGIN_STATE_INVALID;
        return api_->get(api_->host_context, key, capacity, output, &required, &revision);
    }
    int32_t set(const char* key, uint64_t expected_revision, const uint8_t* value,
                uint32_t size, uint64_t& new_revision) const noexcept {
        new_revision = 0;
        if (!api_) return HEXLAB_PLUGIN_STATE_FAILED;
        return api_->set(api_->host_context, key, expected_revision, value, size, &new_revision);
    }
    int32_t erase(const char* key, uint64_t expected_revision,
                  uint64_t& new_revision) const noexcept {
        new_revision = 0;
        if (!api_) return HEXLAB_PLUGIN_STATE_FAILED;
        return api_->erase(api_->host_context, key, expected_revision, &new_revision);
    }
private:
    const HexLabPluginStateApi* api_ = nullptr;
};

/* RAII client for the optional host-owned project service table. */
class ProjectClient {
public:
    ProjectClient() = default;
    explicit ProjectClient(const HexLabHostApi* host) noexcept {
        if (HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, project_api) && host->project_api &&
            HEXLAB_PLUGIN_HAS_FIELD(host->project_api, HexLabProjectApi, functions) &&
            host->project_api->api_version == HEXLAB_PROJECT_API_VERSION &&
            host->project_api->create && host->project_api->open && host->project_api->close &&
            host->project_api->analyze && host->project_api->summary && host->project_api->functions)
            api_ = host->project_api;
    }
    ProjectClient(const ProjectClient&) = delete;
    ProjectClient& operator=(const ProjectClient&) = delete;
    ProjectClient(ProjectClient&& other) noexcept : api_(std::exchange(other.api_, nullptr)),
        project_(std::exchange(other.project_, nullptr)) {}
    ProjectClient& operator=(ProjectClient&& other) noexcept {
        if (this != &other) { reset(); api_ = std::exchange(other.api_, nullptr);
            project_ = std::exchange(other.project_, nullptr); }
        return *this;
    }
    ~ProjectClient() { reset(); }
    bool available() const noexcept { return api_ != nullptr; }
    int32_t create(const char* project_path, const char* input_path, uint32_t format) noexcept {
        reset(); if (!api_ || !api_->create) return -1;
        const auto status = api_->create(api_->host_context, project_path, input_path, format, &project_);
        if (status != 0) reset();
        return status;
    }
    int32_t open(const char* project_path, bool read_only = true) noexcept {
        reset(); if (!api_ || !api_->open) return -1;
        const auto status = api_->open(api_->host_context, project_path, read_only ? 1u : 0u, &project_);
        if (status != 0) reset();
        return status;
    }
    int32_t analyze() noexcept { return api_ && project_ && api_->analyze ? api_->analyze(api_->host_context, project_) : -1; }
    int32_t undo(std::uint64_t expected_edit_revision) noexcept {
        if (!supports_history() || !project_) return HEXLAB_PROJECT_HISTORY_INVALID;
        return api_->undo(api_->host_context, project_, expected_edit_revision);
    }
    int32_t redo(std::uint64_t expected_edit_revision) noexcept {
        if (!supports_history() || !project_) return HEXLAB_PROJECT_HISTORY_INVALID;
        return api_->redo(api_->host_context, project_, expected_edit_revision);
    }
    int32_t summary(HexLabProjectSummary& result) noexcept {
        result = {}; result.struct_size = sizeof(result);
        return api_ && project_ && api_->summary ? api_->summary(api_->host_context, project_, &result) : -1;
    }
    int32_t functions(uint64_t start, uint32_t capacity, HexLabFunction* output, uint32_t& written) noexcept {
        written = 0;
        if (!api_ || !project_ || !api_->functions) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->functions(api_->host_context, project_, start, capacity, output, &written);
    }
    int32_t function_owners(uint32_t address_space, uint64_t address,
                            uint64_t start, uint32_t capacity,
                            HexLabFunctionOwner* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_function_owners() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->function_owners(api_->host_context, project_, address_space, address,
                                     start, capacity, output, &written);
    }
    int32_t instructions_text(uint64_t start, uint32_t capacity,
                              HexLabInstructionText* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_instruction_text() || !project_ ||
            !detail::initialize_page_records(output, capacity)) return -1;
        return api_->instructions_text(api_->host_context, project_, start, capacity,
                                       output, &written);
    }
    int32_t block_instructions_text(uint64_t block_id, uint64_t start, uint32_t capacity,
                                    HexLabInstructionText* output,
                                    uint32_t& written) noexcept {
        written = 0;
        if (!supports_instruction_text() || !project_ ||
            !detail::initialize_page_records(output, capacity)) return -1;
        return api_->block_instructions_text(api_->host_context, project_, block_id,
                                             start, capacity, output, &written);
    }
    int32_t instructions(uint64_t start, uint32_t capacity, HexLabInstruction* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_instructions() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->instructions(api_->host_context, project_, start, capacity, output, &written);
    }
    int32_t references(uint32_t source_space, uint64_t source, uint64_t start, uint32_t capacity,
                       HexLabReference* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_references() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->references(api_->host_context, project_, source_space, source, start,
                                capacity, output, &written);
    }
    int32_t outgoing_references_range(uint32_t begin_space, uint64_t begin, uint64_t size,
                                      uint64_t start, uint32_t capacity,
                                      HexLabReference* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_outgoing_references_range() || !project_ || size == 0 ||
            !detail::initialize_page_records(output, capacity)) return -1;
        return api_->outgoing_references_range(api_->host_context, project_, begin_space,
            begin, size, start, capacity, output, &written);
    }
    int32_t strings(uint64_t start, uint32_t capacity, HexLabString* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_strings() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->strings(api_->host_context, project_, start, capacity, output, &written);
    }
    int32_t strings_text(uint64_t start, uint32_t capacity,
                         HexLabStringText* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_string_text() || !project_ ||
            !detail::initialize_page_records(output, capacity)) return -1;
        return api_->strings_text(api_->host_context, project_, start, capacity, output, &written);
    }
    int32_t strings_preview(uint64_t start, uint32_t capacity,
                            HexLabStringText* output, uint32_t& written) noexcept {
        return strings_text(start, capacity, output, written);
    }
    int32_t function_blocks(uint32_t address_space, uint64_t function_entry, uint64_t start,
                            uint32_t capacity, HexLabBasicBlock* output,
                            uint32_t& written) noexcept {
        written = 0;
        if (!supports_control_flow() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->function_blocks(api_->host_context, project_, address_space,
                                     function_entry, start, capacity, output, &written);
    }
    int32_t block_instructions(uint64_t block_id, uint64_t start, uint32_t capacity,
                               HexLabInstruction* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_control_flow() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->block_instructions(api_->host_context, project_, block_id,
                                        start, capacity, output, &written);
    }
    int32_t block_successors(uint64_t block_id, uint64_t start, uint32_t capacity,
                             HexLabBlockSuccessor* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_control_flow() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->block_successors(api_->host_context, project_, block_id,
                                      start, capacity, output, &written);
    }
    int32_t rename(uint32_t address_space, uint64_t address, const char* name) noexcept {
        if (!supports_edits() || !project_) return -1;
        return api_->rename(api_->host_context, project_, address_space, address, name);
    }
    int32_t comment(const HexLabProjectLocation& location, const char* text) noexcept {
        if (!supports_edits() || !project_) return -1;
        return api_->comment(api_->host_context, project_, &location, text);
    }
    int32_t bookmark(const HexLabProjectLocation& location, const char* label, bool remove = false) noexcept {
        if (!supports_edits() || !project_) return -1;
        return api_->bookmark(api_->host_context, project_, &location, label, remove ? 1u : 0u);
    }
    int32_t annotation_batch(std::uint64_t expected_edit_revision, std::uint64_t group,
                             const HexLabProjectAnnotationEdit* edits, std::uint32_t count) noexcept {
        if (!supports_annotation_batch() || !project_) return -1;
        return api_->annotation_batch(api_->host_context, project_, expected_edit_revision,
                                      group, edits, count);
    }
    int32_t read(const HexLabProjectLocation& location, uint32_t size, uint8_t* output) noexcept {
        if (!supports_read() || !project_) return -1;
        return api_->read(api_->host_context, project_, &location, size, output);
    }
    int32_t import_header(const char* source, const HexLabHeaderImportOptions* options,
                          HexLabHeaderImportSummary& summary) noexcept {
        summary = {}; summary.struct_size = sizeof(summary);
        if (!supports_types() || !project_) return -1;
        return api_->import_header(api_->host_context, project_, source, options, &summary);
    }
    // ABI 1.13 logical pages contain only type declarations; use declarations()
    // to inspect ABI 1.14 object and function declaration roles as well.
    int32_t types(uint64_t start, uint32_t capacity, HexLabTypeRecord* output,
                  uint32_t& written) noexcept {
        written = 0;
        if (!supports_types() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->types(api_->host_context, project_, start, capacity, output, &written);
    }
    int32_t assign_type(uint32_t address_space, uint64_t address, uint64_t type_id,
                        bool remove = false) noexcept {
        if (!supports_types() || !project_) return -1;
        return api_->assign_type(api_->host_context, project_, address_space, address,
                                 type_id, remove ? 1u : 0u);
    }
    int32_t declarations(uint64_t start, uint32_t capacity, HexLabDeclarationRecord* output,
                         uint32_t& written) noexcept {
        written = 0;
        if (!supports_declarations() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->declarations(api_->host_context, project_, start, capacity, output, &written);
    }
    int32_t enum_values(uint64_t type_id, uint64_t start, uint32_t capacity,
                        HexLabEnumConstantRecord* output, uint32_t& written) noexcept {
        written = 0;
        if (!supports_declarations() || !project_) return -1;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_->enum_values(api_->host_context, project_, type_id, start, capacity, output, &written);
    }
    bool supports_instructions() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, instructions) && api_->instructions;
    }
    bool supports_references() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, references) && api_->references;
    }
    bool supports_outgoing_references_range() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, outgoing_references_range) &&
               api_->outgoing_references_range;
    }
    bool supports_strings() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, strings) && api_->strings;
    }
    bool supports_control_flow() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, block_successors) &&
               api_->function_blocks && api_->block_instructions && api_->block_successors;
    }
    bool supports_edits() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, bookmark) &&
               api_->rename && api_->comment && api_->bookmark;
    }
    bool supports_annotation_batch() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, annotation_batch) && api_->annotation_batch;
    }
    bool supports_history() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, redo) && api_->undo && api_->redo;
    }
    bool supports_function_owners() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, function_owners) && api_->function_owners;
    }
    bool supports_instruction_text() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, block_instructions_text) &&
               api_->instructions_text && api_->block_instructions_text;
    }
    bool supports_string_text() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, strings_text) && api_->strings_text;
    }
    bool supports_string_preview() const noexcept { return supports_string_text(); }
    bool supports_read() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, read) && api_->read;
    }
    bool supports_types() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, assign_type) &&
               api_->import_header && api_->types && api_->assign_type;
    }
    bool supports_declarations() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabProjectApi, enum_values) &&
               api_->declarations && api_->enum_values;
    }
    void reset() noexcept {
        if (api_ && project_ && api_->close) api_->close(api_->host_context, project_);
        project_ = nullptr;
    }
private:
    const HexLabProjectApi* api_ = nullptr;
    void* project_ = nullptr;
};

/* Move-only owner for one host debugger session. The fixed C records are
   initialized here so callers can use the versioned table directly. */
class DebuggerClient {
public:
    DebuggerClient() = default;
    explicit DebuggerClient(const HexLabHostApi* host) noexcept {
        if (HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, debugger_api) && host->debugger_api &&
            HEXLAB_PLUGIN_HAS_FIELD(host->debugger_api, HexLabDebuggerApi, processes) &&
            host->debugger_api->api_version == HEXLAB_DEBUGGER_API_VERSION &&
            host->debugger_api->create && host->debugger_api->close)
            api_ = host->debugger_api;
    }
    DebuggerClient(const DebuggerClient&) = delete;
    DebuggerClient& operator=(const DebuggerClient&) = delete;
    DebuggerClient(DebuggerClient&& other) noexcept
        : api_(std::exchange(other.api_, nullptr)), session_(std::exchange(other.session_, nullptr)) {}
    DebuggerClient& operator=(DebuggerClient&& other) noexcept {
        if (this != &other) { reset(); api_ = std::exchange(other.api_, nullptr);
            session_ = std::exchange(other.session_, nullptr); }
        return *this;
    }
    ~DebuggerClient() { reset(); }
    bool available() const noexcept { return api_ != nullptr; }
    bool supports(const void* member, std::size_t offset, std::size_t size) const noexcept {
        return api_ && hexlab_plugin_field_available(api_, offsetof(HexLabDebuggerApi, struct_size),
                                                       offset, size) && member;
    }
    int32_t create(uint32_t backend = HEXLAB_DEBUGGER_BACKEND_NATIVE) noexcept {
        reset();
        if (!api_ || !api_->create) return -1;
        session_ = nullptr;
        const auto status = api_->create(api_->host_context, backend, &session_);
        if (status != 0 || !session_) {
            reset();
            return status != 0 ? status : -1;
        }
        return 0;
    }
    int32_t processes(uint64_t start, uint32_t capacity,
                      HexLabDebugProcess* output, uint32_t& written) const noexcept {
        written = 0;
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, processes) ||
            !api_->processes ||
            !detail::initialize_page_records(output, capacity, HEXLAB_DEBUGGER_MAX_PAGE)) return -1;
        return api_->processes(api_->host_context, session_, start, capacity, output, &written);
    }
    int32_t threads(std::uint64_t start, std::uint32_t capacity,
                    HexLabDebugThread* output, std::uint32_t& written) const noexcept {
        written = 0;
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, threads) ||
            !api_->threads ||
            !detail::initialize_page_records(output, capacity, HEXLAB_DEBUGGER_MAX_PAGE)) return -1;
        return api_->threads(api_->host_context, session_, start, capacity, output, &written);
    }
    int32_t modules(std::uint64_t start, std::uint32_t capacity,
                    HexLabDebugModule* output, std::uint32_t& written) const noexcept {
        written = 0;
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, modules) ||
            !api_->modules ||
            !detail::initialize_page_records(output, capacity, HEXLAB_DEBUGGER_MAX_PAGE)) return -1;
        return api_->modules(api_->host_context, session_, start, capacity, output, &written);
    }
    int32_t memory_regions(std::uint64_t start, std::uint32_t capacity,
                           HexLabDebugMemoryRegion* output,
                           std::uint32_t& written) const noexcept {
        written = 0;
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, memory_regions) ||
            !api_->memory_regions ||
            !detail::initialize_page_records(output, capacity, HEXLAB_DEBUGGER_MAX_PAGE)) return -1;
        return api_->memory_regions(api_->host_context, session_, start, capacity, output, &written);
    }
    int32_t launch(const HexLabDebuggerTarget& target, HexLabDebugProcess& process) noexcept {
        process = {};
        process.struct_size = sizeof(process);
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, launch) || !api_->launch)
            return -1;
        auto initialized_target = target;
        initialized_target.struct_size = sizeof(initialized_target);
        return api_->launch(api_->host_context, session_, &initialized_target, &process);
    }
    int32_t attach(std::uint64_t process_id, HexLabDebugProcess& process) noexcept {
        process = {};
        process.struct_size = sizeof(process);
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, attach) || !api_->attach)
            return -1;
        return api_->attach(api_->host_context, session_, process_id, &process);
    }
    int32_t connect_remote(const char* host_name, std::uint16_t port,
                           HexLabDebugProcess& process) noexcept {
        process = {};
        process.struct_size = sizeof(process);
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, connect_remote) ||
            !api_->connect_remote) return -1;
        return api_->connect_remote(api_->host_context, session_, host_name, port, &process);
    }
    int32_t state(std::uint32_t& debugger_state, std::uint8_t& has_process,
                  HexLabDebugProcess& process) const noexcept {
        debugger_state = 0;
        has_process = 0;
        process = {};
        process.struct_size = sizeof(process);
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, state) || !api_->state)
            return -1;
        return api_->state(api_->host_context, session_, &debugger_state, &has_process, &process);
    }
    int32_t detach() noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, detach) || !api_->detach)
            return -1;
        return api_->detach(api_->host_context, session_);
    }
    int32_t request_interrupt() noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, request_interrupt) ||
            !api_->request_interrupt) return -1;
        return api_->request_interrupt(api_->host_context, session_);
    }
    int32_t continue_event(std::uint64_t sequence, std::uint32_t status) noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, continue_event) ||
            !api_->continue_event) return -1;
        return api_->continue_event(api_->host_context, session_, sequence, status);
    }
    int32_t single_step_event(std::uint64_t sequence, std::uint32_t status) noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, single_step_event) ||
            !api_->single_step_event) return -1;
        return api_->single_step_event(api_->host_context, session_, sequence, status);
    }
    int32_t add_breakpoint(std::uint64_t address, std::uint32_t kind, std::uint8_t size,
                           HexLabDebugBreakpoint& breakpoint) noexcept {
        breakpoint = {};
        breakpoint.struct_size = sizeof(breakpoint);
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, add_breakpoint) ||
            !api_->add_breakpoint) return -1;
        return api_->add_breakpoint(api_->host_context, session_, address, kind, size, &breakpoint);
    }
    int32_t remove_breakpoint(std::uint64_t id) noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, remove_breakpoint) ||
            !api_->remove_breakpoint) return -1;
        return api_->remove_breakpoint(api_->host_context, session_, id);
    }
    int32_t set_breakpoint_enabled(std::uint64_t id, bool enabled) noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, set_breakpoint_enabled) ||
            !api_->set_breakpoint_enabled) return -1;
        return api_->set_breakpoint_enabled(api_->host_context, session_, id, enabled ? 1u : 0u);
    }
    int32_t breakpoints(std::uint64_t start, std::uint32_t capacity,
                        HexLabDebugBreakpoint* output, std::uint32_t& written) const noexcept {
        written = 0;
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, breakpoints) ||
            !api_->breakpoints ||
            !detail::initialize_page_records(output, capacity, HEXLAB_DEBUGGER_MAX_PAGE)) return -1;
        return api_->breakpoints(api_->host_context, session_, start, capacity, output, &written);
    }
    int32_t read_memory(std::uint64_t address, std::uint32_t size, std::uint8_t* output) const noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, read_memory) ||
            !api_->read_memory || !size || size > HEXLAB_DEBUGGER_MAX_IO || !output) return -1;
        return api_->read_memory(api_->host_context, session_, address, size, output);
    }
    int32_t write_memory(std::uint64_t address, std::uint32_t size,
                         const std::uint8_t* input) const noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, write_memory) ||
            !api_->write_memory || !size || size > HEXLAB_DEBUGGER_MAX_IO || !input) return -1;
        return api_->write_memory(api_->host_context, session_, address, size, input);
    }
    int32_t read_registers(std::uint64_t thread_id, std::uint64_t start, std::uint32_t capacity,
                           HexLabDebugRegister* output, std::uint32_t& written) const noexcept {
        written = 0;
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, read_registers) ||
            !api_->read_registers ||
            !detail::initialize_page_records(output, capacity, HEXLAB_DEBUGGER_MAX_PAGE)) return -1;
        return api_->read_registers(api_->host_context, session_, thread_id, start, capacity,
                                    output, &written);
    }
    int32_t write_registers(std::uint64_t thread_id, std::uint32_t count,
                            HexLabDebugRegister* input) const noexcept {
        if (!session_ || !HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, write_registers) ||
            !api_->write_registers ||
            !detail::initialize_page_records(input, count, HEXLAB_DEBUGGER_MAX_PAGE) || !count) return -1;
        return api_->write_registers(api_->host_context, session_, thread_id, count, input);
    }
    int32_t wait_event_text(std::uint32_t timeout_ms, HexLabDebugEventText& event) const noexcept {
        event = {};
        event.struct_size = sizeof(event);
        if (!session_ || !supports_event_text()) return -1;
        return api_->wait_event_text(api_->host_context, session_, timeout_ms, &event);
    }
    bool supports_event_text() const noexcept {
        return HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, wait_event_text) &&
               api_->wait_event_text;
    }
    int32_t set_breakpoint_ignore_count(uint64_t id, uint64_t count) const noexcept {
        return session_ && HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, set_breakpoint_ignore_count) &&
            api_->set_breakpoint_ignore_count
            ? api_->set_breakpoint_ignore_count(api_->host_context, session_, id, count) : -1;
    }
    int32_t set_breakpoint_condition(uint64_t id, const char* expression) const noexcept {
        return session_ && HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, set_breakpoint_condition) &&
            api_->set_breakpoint_condition
            ? api_->set_breakpoint_condition(api_->host_context, session_, id, expression) : -1;
    }
    int32_t set_breakpoint_logpoint(uint64_t id, bool enabled, const char* message) const noexcept {
        return session_ && HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, set_breakpoint_logpoint) &&
            api_->set_breakpoint_logpoint
            ? api_->set_breakpoint_logpoint(api_->host_context, session_, id,
                                            enabled ? 1u : 0u, message) : -1;
    }
    int32_t breakpoint_rule(uint64_t id, HexLabDebugBreakpointRule& rule) const noexcept {
        rule = {}; rule.struct_size = sizeof(rule);
        return session_ && HEXLAB_PLUGIN_HAS_FIELD(api_, HexLabDebuggerApi, breakpoint_rule) &&
            api_->breakpoint_rule
            ? api_->breakpoint_rule(api_->host_context, session_, id, &rule) : -1;
    }
    void reset() noexcept {
        if (api_ && session_ && api_->close) api_->close(api_->host_context, session_);
        session_ = nullptr;
    }
    void* native_handle() const noexcept { return session_; }
    const HexLabDebuggerApi* api() const noexcept { return api_; }
private:
    const HexLabDebuggerApi* api_ = nullptr;
    void* session_ = nullptr;
};

/* Non-owning client for the host's ephemeral active-document context. Every
   read/navigation call carries the token returned by query and may return
   HEXLAB_ACTIVE_DOCUMENT_STALE after a tab switch or project edit. */
class ActiveDocumentClient {
public:
    ActiveDocumentClient() = default;
    explicit ActiveDocumentClient(const HexLabHostApi* host) noexcept {
        if (HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, active_document_api) && host->active_document_api &&
            HEXLAB_PLUGIN_HAS_FIELD(host->active_document_api, HexLabActiveDocumentApi, navigate) &&
            host->active_document_api->api_version == HEXLAB_ACTIVE_DOCUMENT_API_VERSION &&
            host->active_document_api->query && host->active_document_api->read && host->active_document_api->navigate)
            api_ = host->active_document_api;
    }
    bool available() const noexcept { return api_ != nullptr; }
    int32_t query(HexLabActiveDocumentInfo& info) const noexcept {
        info = {};
        info.struct_size = sizeof(info);
        info.token.struct_size = sizeof(info.token);
        return api_ && api_->query ? api_->query(api_->host_context, &info) : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    }
    int32_t read(const HexLabDocumentToken& token, const HexLabProjectLocation& location,
                 uint32_t size, uint8_t* output) const noexcept {
        return api_ && api_->read ? api_->read(api_->host_context, &token, &location, size, output)
                                  : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    }
    int32_t navigate(const HexLabDocumentToken& token, const HexLabProjectLocation& location) const noexcept {
        return api_ && api_->navigate ? api_->navigate(api_->host_context, &token, &location)
                                      : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    }
private:
    const HexLabActiveDocumentApi* api_ = nullptr;
};

/* Non-owning client for durable rows in the active saved project. It never
   operates on debugger runtime breakpoints. Tokens expire on project/document
   identity or revision changes. */
class ActiveProjectBreakpointClient {
public:
    ActiveProjectBreakpointClient() = default;
    explicit ActiveProjectBreakpointClient(const HexLabHostApi* host) noexcept {
        if (HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, active_project_breakpoint_api) && host->active_project_breakpoint_api &&
            HEXLAB_PLUGIN_HAS_FIELD(host->active_project_breakpoint_api, HexLabActiveProjectBreakpointApi, set) &&
            host->active_project_breakpoint_api->api_version == HEXLAB_ACTIVE_PROJECT_BREAKPOINT_API_VERSION &&
            host->active_project_breakpoint_api->snapshot && host->active_project_breakpoint_api->query && host->active_project_breakpoint_api->set)
            api_ = host->active_project_breakpoint_api;
    }
    bool available() const noexcept { return api_ != nullptr; }
    int32_t snapshot(HexLabActiveProjectToken& token) const noexcept {
        token = {}; token.struct_size = sizeof(token); token.document.struct_size = sizeof(token.document);
        return api_ ? api_->snapshot(api_->host_context, &token) : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    }
    int32_t query(const HexLabActiveProjectToken& token, uint64_t start, uint32_t capacity,
                  HexLabProjectBreakpointRecord* output, uint32_t* written) const noexcept {
        if (written) *written = 0;
        if (!detail::initialize_page_records(output, capacity)) return -1;
        return api_ ? api_->query(api_->host_context, &token, start, capacity, output, written)
                    : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    }
    int32_t set(const HexLabActiveProjectToken& token, uint32_t address_space, uint64_t address,
                uint32_t kind, uint8_t size, bool enabled = true, bool remove = false) const noexcept {
        return api_ ? api_->set(api_->host_context, &token, address_space, address, kind, size,
                                enabled ? 1u : 0u, remove ? 1u : 0u)
                    : HEXLAB_ACTIVE_DOCUMENT_FAILED;
    }
private:
    const HexLabActiveProjectBreakpointApi* api_ = nullptr;
};

/* Non-owning read-only client for the desktop debugger. Every inspection call
   must reuse the token from query; it becomes stale on resume, session change,
   document switch, or document reopen. */
class ActiveDebuggerClient {
public:
    ActiveDebuggerClient() = default;
    explicit ActiveDebuggerClient(const HexLabHostApi* host) noexcept {
        if (HEXLAB_PLUGIN_HAS_FIELD(host, HexLabHostApi, active_debugger_api) && host->active_debugger_api &&
            HEXLAB_PLUGIN_HAS_FIELD(host->active_debugger_api, HexLabActiveDebuggerApi, read_memory) &&
            host->active_debugger_api->api_version == HEXLAB_ACTIVE_DEBUGGER_API_VERSION &&
            host->active_debugger_api->query && host->active_debugger_api->threads &&
            host->active_debugger_api->read_registers && host->active_debugger_api->read_memory)
            api_ = host->active_debugger_api;
    }
    bool available() const noexcept { return api_ != nullptr; }
    int32_t query(HexLabActiveDebuggerInfo& info) const noexcept {
        info = {}; info.struct_size = sizeof(info); info.token.struct_size = sizeof(info.token);
        info.token.document.struct_size = sizeof(info.token.document);
        return api_ ? api_->query(api_->host_context, &info) : HEXLAB_ACTIVE_DEBUGGER_FAILED;
    }
    int32_t threads(const HexLabActiveDebuggerToken& token, uint64_t start, uint32_t capacity,
                    HexLabDebugThread* out, uint32_t* written) const noexcept {
        return api_ ? api_->threads(api_->host_context, &token, start, capacity, out, written) : HEXLAB_ACTIVE_DEBUGGER_FAILED;
    }
    int32_t read_registers(const HexLabActiveDebuggerToken& token, uint64_t thread, uint64_t start,
                           uint32_t capacity, HexLabDebugRegister* out, uint32_t* written) const noexcept {
        return api_ ? api_->read_registers(api_->host_context, &token, thread, start, capacity, out, written) : HEXLAB_ACTIVE_DEBUGGER_FAILED;
    }
    int32_t read_memory(const HexLabActiveDebuggerToken& token, uint64_t address,
                        uint32_t size, uint8_t* out) const noexcept {
        return api_ ? api_->read_memory(api_->host_context, &token, address, size, out) : HEXLAB_ACTIVE_DEBUGGER_FAILED;
    }
private:
    const HexLabActiveDebuggerApi* api_ = nullptr;
};

/* Keeps the C++ module definition convenient while returning the same plain C ABI. */
inline HexLabPluginApi make_api(const char* id, const char* name, const char* version,
                                const char* const* capabilities, std::uint32_t capability_count,
                                HexLabPluginStart start, HexLabPluginStop stop,
                                const HexLabCapability* declared_capabilities = nullptr,
                                std::uint32_t declared_capability_count = 0,
                                const HexLabCapability* required_capabilities = nullptr,
                                std::uint32_t required_capability_count = 0) noexcept {
    return HexLabPluginApi{static_cast<std::uint32_t>(sizeof(HexLabPluginApi)), abi_major, abi_minor,
                           id, name, version, capabilities, capability_count, start, stop,
                           declared_capabilities, declared_capability_count,
                           required_capabilities, required_capability_count};
}
}
#endif
