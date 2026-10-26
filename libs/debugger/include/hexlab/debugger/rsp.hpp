#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/debugger/debugger_export.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace hexlab::debugger::rsp {
using Status = Result<std::monostate>;
using Deadline = std::chrono::steady_clock::time_point;
class HEXLAB_DEBUGGER_EXPORT ByteTransport {
public:
    virtual ~ByteTransport() = default;
    virtual Result<std::size_t> read_some(std::span<std::byte>, Deadline, std::stop_token) = 0;
    virtual Result<std::size_t> write_some(std::span<const std::byte>, Deadline, std::stop_token) = 0;
};
HEXLAB_DEBUGGER_EXPORT Result<std::unique_ptr<ByteTransport>> connect_tcp(
    std::string_view host, std::uint16_t port,
    std::chrono::milliseconds timeout = std::chrono::seconds(3), std::stop_token = {});
enum class BreakpointType { software, hardware, write_watch, read_watch, access_watch };
struct StopReply {
    char kind = '?';
    unsigned signal = 0;
    std::uint64_t exit_code = 0;
    std::uint64_t thread = 0;
    std::map<std::string, std::string, std::less<>> fields;
};
struct Capabilities {
    std::map<std::string, std::string, std::less<>> features;
    bool no_ack_mode = false;
    bool non_stop_supported = false;
    bool thread_events_supported = false;
};

HEXLAB_DEBUGGER_EXPORT std::string encode_packet(std::string_view payload);
HEXLAB_DEBUGGER_EXPORT Result<std::string> decode_packet(std::string_view frame,
    std::size_t max_decoded_payload = 1024 * 1024);

class HEXLAB_DEBUGGER_EXPORT Client {
public:
    explicit Client(ByteTransport&, std::chrono::milliseconds timeout = std::chrono::seconds(3),
                    std::size_t max_packet = 1024 * 1024);
    Result<std::string> request(std::string_view command, std::stop_token = {});
    Result<Capabilities> negotiate(std::stop_token = {});
    Status set_non_stop_mode(bool enabled, std::stop_token = {});
    bool non_stop_mode() const noexcept { return non_stop_mode_; }
    // Requests asynchronous thread-created/thread-exited stop notifications.
    Status set_thread_events(bool enabled, std::stop_token = {});
    bool thread_events_enabled() const noexcept { return thread_events_enabled_; }
    Result<StopReply> read_stop_reply(std::stop_token = {});
    Result<std::optional<StopReply>> read_stop_reply_optional(std::stop_token = {});
    Result<StopReply> wait_stop_reply(std::chrono::milliseconds timeout, std::stop_token = {});
    Status send_resume(std::string_view command, std::stop_token = {});
    // Sends one exact thread-qualified vCont action.
    Status send_vcont(std::string_view action, std::stop_token = {});
    // Sends one atomic set of exact thread-qualified vCont actions.
    Status send_vcont_actions(std::span<const std::string> actions, std::stop_token = {});
    // Sends the RSP kill request, which intentionally has no packet reply.
    Status kill(std::stop_token = {});
    // Uses the multiprocess vKill packet and requires an explicit success reply.
    Status kill_process(std::uint64_t process, std::stop_token = {});
    // Attaches the current connection to one multiprocess inferior. All-stop
    // servers return its initial stop; non-stop servers may reply OK and report
    // subsequent stop notifications asynchronously.
    Result<std::optional<StopReply>> attach_process(std::uint64_t process, std::stop_token = {});
    // Starts an executable in extended-remote mode. Paths and each argument
    // are hex encoded independently according to the vRun packet grammar.
    Result<StopReply> run_program(std::string_view executable,
        std::span<const std::string> arguments = {}, std::stop_token = {});
    // Detaches one process without closing the multiprocess RSP connection.
    Status detach_process(std::uint64_t process, std::stop_token = {});
    Status interrupt(std::stop_token = {});
    Result<std::vector<std::uint64_t>> enumerate_threads(std::stop_token = {});
    // Returns validated wire IDs without dropping the process component of pPID.TID.
    Result<std::vector<std::string>> enumerate_thread_ids(std::stop_token = {});
    Result<std::vector<std::byte>> read_registers(std::stop_token = {});
    // Reads a bounded qXfer:features:read annex. Empty response means unsupported.
    Result<std::optional<std::string>> read_feature_annex(std::string_view annex = "target.xml",
        std::size_t limit = 1024 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    // Reads the standard shared-library XML object when advertised by qSupported.
    Result<std::optional<std::string>> read_libraries_annex(
        std::size_t limit = 1024 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    // Reads the standard memory-map XML object when advertised by qSupported.
    Result<std::optional<std::string>> read_memory_map_annex(
        std::size_t limit = 1024 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    // Reads the standard qXfer thread-list XML object when advertised by qSupported.
    Result<std::optional<std::string>> read_threads_annex(
        std::size_t limit = 1024 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    // Reads the standard qXfer operating-system process-list object.
    Result<std::optional<std::string>> read_processes_annex(
        std::size_t limit = 1024 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    // Reads the binary qXfer auxiliary-vector object under independent byte and chunk limits.
    Result<std::optional<std::vector<std::byte>>> read_auxv_annex(
        std::size_t limit = 1024 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    Result<std::vector<std::byte>> read_register(std::uint64_t number, std::stop_token = {});
    Status write_register(std::uint64_t number, std::span<const std::byte>, std::stop_token = {});
    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size, std::stop_token = {});
    Status set_breakpoint(std::uint64_t address, BreakpointType, std::uint8_t size, bool insert,
                          std::stop_token = {});
    Status write_memory(std::uint64_t address, std::span<const std::byte>, std::stop_token = {});
    // Selects an RSP general-thread ID. In addition to concrete IDs, accepts
    // the protocol selectors 0, -1, pPID.0, and pPID.-1.
    Status select_thread(std::uint64_t thread, std::stop_token = {});
    Status select_thread(std::string_view thread_id, std::stop_token = {});
    bool no_ack_mode() const noexcept { return no_ack_mode_; }
private:
    Status write_all(std::string_view, Deadline, std::stop_token);
    Result<unsigned char> read_byte(Deadline, std::stop_token);
    Result<std::pair<bool, std::string>> read_packet_after_start(unsigned char, Deadline, std::stop_token);
    Status queue_stop_notification(std::string);
    Result<bool> read_ack(Deadline, std::stop_token);
    Result<std::string> receive_packet(Deadline, std::stop_token, bool accept_notifications = false,
                                      bool *was_notification = nullptr);
    Result<std::string> transact(std::string_view, std::stop_token);
    Result<std::string> transact_until(std::string_view, Deadline, std::stop_token);
    ByteTransport& transport_;
    std::chrono::milliseconds timeout_;
    std::size_t max_packet_;
    std::size_t peer_packet_size_ = 4096;
    bool binary_download_supported_ = false;
    bool no_ack_mode_ = false;
    bool non_stop_supported_ = false;
    bool non_stop_mode_ = false;
    bool thread_events_supported_ = false;
    bool thread_events_enabled_ = false;
    bool stop_reply_sequence_active_ = false;
    std::deque<std::string> pending_notifications_;
    std::size_t pending_notification_bytes_ = 0;
};
} // namespace hexlab::debugger::rsp
