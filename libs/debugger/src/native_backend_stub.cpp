#include "hexlab/debugger/debugger.hpp"

namespace hexlab::debugger {
namespace {
constexpr const char* unavailable =
    "native debugging is unavailable for this operating-system and architecture combination; connect through make_backend_router() or make_remote_backend() when a GDB RSP server is available";
class UnsupportedBackend final : public Backend {
public:
    Result<std::vector<ProcessInfo>> processes() override { return Error{ErrorCode::unsupported, unavailable}; }
    Result<ProcessInfo> launch(const Target&) override { return Error{ErrorCode::unsupported, unavailable}; }
    Result<ProcessInfo> attach(ProcessId) override { return Error{ErrorCode::unsupported, unavailable}; }
    Status detach() override { return Error{ErrorCode::unsupported, unavailable}; }
    Result<DebugEvent> wait_event(std::chrono::milliseconds) override { return Error{ErrorCode::unsupported, unavailable}; }
    Status continue_event(std::uint64_t, ContinueStatus) override { return Error{ErrorCode::unsupported, unavailable}; }
    Result<std::vector<std::byte>> read_memory(std::uint64_t, std::size_t) override { return Error{ErrorCode::unsupported, unavailable}; }
    Status write_memory(std::uint64_t, std::span<const std::byte>) override { return Error{ErrorCode::unsupported, unavailable}; }
    Result<std::vector<ThreadInfo>> threads() override { return Error{ErrorCode::unsupported, unavailable}; }
    Result<std::vector<RegisterValue>> read_registers(ThreadId) override { return Error{ErrorCode::unsupported, unavailable}; }
    Status write_registers(ThreadId, std::span<const RegisterValue>) override { return Error{ErrorCode::unsupported, unavailable}; }
    Result<Breakpoint> add_breakpoint(std::uint64_t, BreakpointKind) override { return Error{ErrorCode::unsupported, unavailable}; }
    Status remove_breakpoint(BreakpointId) override { return Error{ErrorCode::unsupported, unavailable}; }
};
}
std::unique_ptr<Backend> make_native_backend() { return std::make_unique<UnsupportedBackend>(); }
} // namespace hexlab::debugger
