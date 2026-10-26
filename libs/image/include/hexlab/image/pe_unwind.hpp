#pragma once

#include "hexlab/core/architecture.hpp"
#include "hexlab/core/result.hpp"
#include "hexlab/image/image_export.hpp"
#include "hexlab/image/pe_metadata.hpp"

#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace hexlab {

// A debugger-independent snapshot. Values are little-endian byte arrays and
// use canonical names (rax/rsp/xmm6 for AMD64; x0/sp/fp/lr for ARM64).
struct PeRegisterContext {
    std::map<std::string, std::vector<std::byte>, std::less<>> registers;
    bool operator==(const PeRegisterContext &) const = default;
};

using PeMemoryReader = std::function<Result<std::vector<std::byte>>(std::uint64_t, std::size_t)>;

// Unwinds exactly one frame. The input snapshot is never modified. A short
// read, missing register, unsupported opcode, or invalid arithmetic returns
// an error and no partially recovered context.
HEXLAB_IMAGE_EXPORT Result<PeRegisterContext> unwind_pe_frame(const PeMetadata &, Architecture,
                                                              std::uint64_t module_base,
                                                              std::uint64_t instruction_pointer,
                                                              const PeRegisterContext &,
                                                              const PeMemoryReader &);

enum class PeFh3CatchDisposition : std::uint8_t {
    catch_all, exact_type, different_type, type_unknown, unsupported_adjectives
};
enum class PeFh3DispatchDisposition : std::uint8_t {
    unresolved, handler_candidate, continue_search, unexpected_exception_spec,
    terminate_noexcept, ambiguous
};
struct PeFh3CleanupAction {
    std::int32_t state = -1;
    std::uint64_t action_address = 0;
    PeRecordSource source;
};
struct PeFh3CatchCandidate {
    std::uint32_t try_index = 0, handler_index = 0;
    PeFh3CatchDisposition disposition = PeFh3CatchDisposition::type_unknown;
    std::optional<std::string> decorated_type_name;
    std::uint64_t handler_address = 0;
    std::optional<std::uint64_t> catch_object_address;
    PeRecordSource source;
    std::optional<PeRecordSource> type_descriptor_source;
};
struct PeFh3ExceptionPlan {
    std::uint32_t function_begin_rva = 0;
    std::int32_t state = -1;
    std::uint64_t establisher_frame = 0;
    bool has_ehs_flag = false;
    bool has_dynamic_stack_alignment = false;
    bool is_noexcept = false;
    PeFh3DispatchDisposition dispatch = PeFh3DispatchDisposition::unresolved;
    std::optional<std::uint32_t> selected_try_index, selected_handler_index;
    std::optional<PeRecordSource> dispatch_source;
    // For a decoded legacy dynamic exception specification, this is set only
    // when exact decorated-name matching proves the result. False means the
    // exception violates the list and reaches the legacy unexpected path.
    std::optional<bool> exception_spec_allows;
    std::optional<std::uint32_t> exception_spec_type_index;
    std::string dispatch_diagnostic;
    std::vector<PeFh3CleanupAction> cleanup_actions;
    std::vector<PeFh3CatchCandidate> handlers;
};

// Build a bounded FH3 exception-state plan using source-tracked FuncInfo data.
// This reports cleanup and catch candidates only; it never invokes target code.
// Typed catches and legacy dynamic exception specifications match only exact
// decorated-name identity. The plan classifies noexcept termination and the
// legacy unexpected path without invoking target code.
HEXLAB_IMAGE_EXPORT Result<PeFh3ExceptionPlan>
plan_pe_fh3_exception(const PeMetadata &, std::uint64_t module_base,
                      std::uint64_t instruction_pointer, std::uint64_t establisher_frame,
                      std::optional<std::string_view> exception_decorated_type = {});

enum class PeFh4CatchDisposition : std::uint8_t {
    catch_all, exact_type, different_type, type_unknown, unsupported_adjectives
};
enum class PeFh4ExceptionKind : std::uint8_t { cxx, non_cxx, unknown };
enum class PeFh4DispatchDisposition : std::uint8_t {
    unresolved, handler_candidate, continue_search, terminate_noexcept, ambiguous
};
struct PeFh4CleanupAction {
    std::int32_t state = -1;
    PeCxxUnwindEntry4Type kind = PeCxxUnwindEntry4Type::no_action;
    std::uint64_t action_address = 0;
    std::optional<std::uint64_t> object_slot_address;
    std::optional<std::uint64_t> object_address;
    bool null_object_pointer = false;
    PeRecordSource source;
    std::optional<PeRecordSource> action_source, object_source;
};
struct PeFh4CatchCandidate {
    std::uint32_t try_index = 0, handler_index = 0;
    PeFh4CatchDisposition disposition = PeFh4CatchDisposition::type_unknown;
    std::optional<std::string> decorated_type_name;
    std::uint64_t handler_address = 0;
    std::optional<std::uint64_t> catch_object_address;
    std::vector<std::uint64_t> continuation_addresses;
    PeRecordSource source;
};
struct PeFh4ExceptionPlan {
    std::uint32_t function_begin_rva = 0;
    std::int32_t state = -1;
    std::uint64_t function_frame = 0;
    bool is_catch_funclet = false;
    bool has_ehs_flag = false, is_noexcept = false;
    PeFh4DispatchDisposition dispatch = PeFh4DispatchDisposition::unresolved;
    std::optional<std::uint32_t> selected_try_index, selected_handler_index;
    std::optional<PeRecordSource> dispatch_source;
    std::string dispatch_diagnostic;
    std::vector<PeFh4CleanupAction> cleanup_actions;
    // All handlers for active try regions remain visible in metadata order.
    // Multiple exact/catch-all candidates are retained; this API does not dispatch.
    std::vector<PeFh4CatchCandidate> handlers;
};

// Build a bounded exception-dispatch plan from current live IP/frame data.
// It reads pointer-to-object cleanup slots when necessary, but never invokes
// destructors or catch funclets. Typed catches match only exact decorated-name
// identity; conversions and rethrow semantics remain unsupported.
HEXLAB_IMAGE_EXPORT Result<PeFh4ExceptionPlan>
plan_pe_fh4_exception(const PeMetadata &, std::uint64_t module_base,
                      std::uint64_t instruction_pointer, std::uint64_t establisher_frame,
                      std::optional<std::string_view> exception_decorated_type = {},
                      const PeMemoryReader & = {},
                      PeFh4ExceptionKind exception_kind = PeFh4ExceptionKind::unknown);

} // namespace hexlab
