#pragma once

#include "hexlab/core/result.hpp"
#include "hexlab/debugger/debugger.hpp"
#include "hexlab/debugger/debugger_export.hpp"
#include "hexlab/debugger/remote_environment.hpp"

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
    bool memory_tagging_supported = false;
    bool non_stop_supported = false;
    bool thread_events_supported = false;
    bool pass_signals_supported = false;
};
struct RemoteFileStat {
    std::uint32_t device = 0, inode = 0, mode = 0, link_count = 0;
    std::uint32_t user_id = 0, group_id = 0, device_type = 0;
    std::uint64_t size = 0, block_size = 0, blocks = 0;
    std::int32_t access_time = 0, modification_time = 0, change_time = 0;
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
    Result<Capabilities> negotiate(std::stop_token, bool request_no_ack);
    std::size_t local_packet_limit() const noexcept { return max_packet_; }
    std::size_t peer_packet_limit() const noexcept { return peer_packet_size_; }
    Status set_non_stop_mode(bool enabled, std::stop_token = {});
    bool non_stop_mode() const noexcept { return non_stop_mode_; }
    // Requests asynchronous thread-created/thread-exited stop notifications.
    Status set_thread_events(bool enabled, std::stop_token = {});
    bool thread_events_enabled() const noexcept { return thread_events_enabled_; }
    // Replaces the target's pass-through signal set. Values must be strictly
    // increasing 8-bit RSP signal numbers, as required by QPassSignals.
    Status set_pass_signals(std::span<const unsigned>, std::stop_token = {});
    bool pass_signals_supported() const noexcept { return pass_signals_supported_; }
    bool memory_tagging_supported() const noexcept { return memory_tagging_supported_; }
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
    // Configures the next extended-mode launch using advertised QSetWorkingDir.
    // Empty restores the server's default. Paths are opaque target bytes,
    // contain no NUL, and are bounded to 16 KiB and the negotiated PacketSize.
    Status set_working_directory(std::string_view directory, std::stop_token = {});
    bool supports_working_directory() const noexcept { return working_directory_supported_; }
    // Extended mode only. Validates the full bounded batch and negotiated
    // features/PacketSize before QEnvironmentReset, then applies set/unset
    // packets. Failures restore the previous environment only when this Client
    // established it; otherwise it resets to target defaults and reports that
    // the prior state could not be queried. A failed batch never launches.
    Status set_environment(std::span<const RemoteEnvironmentChange>, std::stop_token = {});
    // Applies the per-launch environment and working directory as a
    // best-effort transaction. Previously acknowledged values on this Client
    // are restored on failure; otherwise target defaults are used and the
    // error states that the original remote values were not queryable.
    Status configure_launch_settings(std::span<const RemoteEnvironmentChange>,
        std::string_view working_directory, std::stop_token = {});
    bool supports_environment_reset() const noexcept { return environment_reset_supported_; }
    // Detaches one process without closing the multiprocess RSP connection.
    Status detach_process(std::uint64_t process, std::stop_token = {});
    Status interrupt(std::stop_token = {});
    Result<std::vector<std::uint64_t>> enumerate_threads(std::stop_token = {});
    // Returns validated wire IDs without dropping the process component of pPID.TID.
    Result<std::vector<std::string>> enumerate_thread_ids(std::stop_token = {});
    // Reads the optional qThreadExtraInfo description for one concrete thread.
    // Empty response means the remote does not provide extra thread info.
    Result<std::optional<std::string>> read_thread_extra_info(std::string_view thread_id,
        std::size_t limit = 4096, std::chrono::milliseconds timeout = std::chrono::seconds(3),
        std::stop_token = {});
    Result<std::vector<std::byte>> read_registers(std::stop_token = {});
    // Raw g/p replies preserve GDB's `x` unavailable-register marker.
    Result<std::string> read_registers_raw(std::stop_token = {});
    // Writes a complete, already hex-encoded G-register packet.
    Status write_registers_raw(std::string_view hex_registers, std::stop_token = {});
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
    // Reads a named qXfer operating-system-information XML object.
    Result<std::optional<std::string>> read_osdata_annex(std::string_view type,
        std::size_t limit = 1024 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    // Reads the executable path for the selected process (or current process
    // when no PID is supplied) through qXfer:exec-file:read.
    Result<std::optional<std::string>> read_exec_file_annex(
        std::optional<std::uint64_t> process = {}, std::size_t limit = 16 * 1024,
        std::size_t chunk = 1024, std::stop_token = {});
    // Reads the binary qXfer auxiliary-vector object under independent byte and chunk limits.
    Result<std::optional<std::vector<std::byte>>> read_auxv_annex(
        std::size_t limit = 1024 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    // Reads the opaque target siginfo object under independent byte and chunk limits.
    Result<std::optional<std::vector<std::byte>>> read_siginfo_annex(
        std::size_t limit = 64 * 1024, std::size_t chunk = 4096, std::stop_token = {});
    Result<std::vector<std::byte>> read_register(std::uint64_t number, std::stop_token = {});
    Result<std::string> read_register_raw(std::uint64_t number, std::stop_token = {});
    Status write_register(std::uint64_t number, std::span<const std::byte>, std::stop_token = {});
    Result<std::vector<std::byte>> read_memory(std::uint64_t address, std::size_t size, std::stop_token = {});
    // Searches a bounded target memory range. Empty optional means no match;
    // an unsupported remote reports ErrorCode::unsupported.
    Result<std::optional<std::uint64_t>> search_memory(std::uint64_t address,
        std::uint64_t length, std::span<const std::byte> pattern, std::stop_token = {});
    // Requests the remote CRC-32 of a non-empty, non-overflowing memory range.
    // Empty reply means qCRC is unsupported.
    Result<std::uint32_t> memory_crc32(std::uint64_t address, std::uint64_t length,
        std::stop_token = {});
    // Reads raw, architecture-defined tag bytes for one range through qMemTags.
    // The peer must advertise memory-tagging+; max_tag_bytes bounds the reply.
    Result<std::vector<std::byte>> read_memory_tags(std::uint64_t address,
        std::uint64_t length, std::int32_t type, std::size_t max_tag_bytes = 256 * 1024,
        std::stop_token = {});
    // Checks whether one target address lies in a memory-tagged region.
    // Empty replies are reported as unsupported; only exact 00/01 replies are accepted.
    Result<bool> is_address_tagged(std::uint64_t address, std::stop_token = {});
    // Reads a bounded file from the remote stub with vFile:open/pread/close.
    // Returns unsupported when vFile is not implemented by the peer.
    Result<std::vector<std::byte>> read_remote_file(std::string_view path,
        std::size_t maximum_size = 64 * 1024 * 1024, std::stop_token = {});
    // Executes a bounded printable monitor command through qRcmd and returns
    // only console-output bytes received during that command transaction.
    Result<std::vector<std::byte>> run_monitor_command(std::string_view command,
        std::stop_token = {});
    // Reads a bounded remote-file byte range with vFile:pread without fetching
    // earlier bytes. EOF may shorten the returned range.
    Result<std::vector<std::byte>> read_remote_file_range(std::string_view path,
        std::uint64_t offset, std::size_t size, std::stop_token = {});
    // Reads the protocol-defined 64-byte big-endian struct stat attachment for
    // an already-open vFile descriptor. The caller remains responsible for close.
    Result<RemoteFileStat> stat_remote_file(std::uint64_t descriptor, std::stop_token = {});
    // Reads path-based stat metadata; follow_symlinks selects vFile:stat or
    // vFile:lstat. Paths are hex-encoded and bounded by the negotiated packet size.
    Result<RemoteFileStat> stat_remote_file_path(std::string_view path,
        bool follow_symlinks = true, std::stop_token = {});
    // Reads the target bytes of a symbolic link through vFile:readlink.
    Result<std::vector<std::byte>> read_remote_symlink(std::string_view path,
        std::size_t maximum_size = 16 * 1024, std::stop_token = {});
    // Writes a bounded byte range through vFile:open/pwrite/close. Open flags
    // and mode use the remote host's conventions (RSP does not normalize them).
    Status write_remote_file_range(std::string_view path, std::uint64_t offset,
        std::span<const std::byte> bytes, std::uint64_t flags, std::uint64_t mode,
        std::stop_token = {});
    // Drains target-console O packets as raw bytes. The queue is bounded and
    // output arrives independently of command replies and stop notifications.
    std::vector<std::byte> take_console_output(std::size_t limit = 4096);
    Status set_breakpoint(std::uint64_t address, BreakpointType, std::uint8_t size, bool insert,
                          std::stop_token = {});
    Status write_memory(std::uint64_t address, std::span<const std::byte>, std::stop_token = {});
    // Erases and programs a bounded flash range with vFlashErase/vFlashWrite/
    // vFlashDone. A failure after erase may leave the remote flash partially
    // erased or programmed; the protocol has no rollback operation.
    Status program_flash(std::uint64_t address, std::span<const std::byte>, std::stop_token = {});
    // Validates the whole range against a caller-supplied memory-map snapshot
    // before beginning the destructive vFlash sequence. Exactly one flash
    // region must contain the range; map freshness and erase geometry remain
    // the caller's responsibility.
    Status program_flash_in_regions(std::uint64_t address, std::span<const std::byte>,
        std::span<const MemoryRegion> regions, std::stop_token = {});
    // Preflights map containment and qCRC availability before erase, then
    // programs and verifies the resulting bytes with the standard CRC-32.
    // A post-program CRC failure means flash may already have changed.
    Status program_flash_verified_in_regions(std::uint64_t address, std::span<const std::byte>,
        std::span<const MemoryRegion> regions, std::stop_token = {});
    // Selects an RSP general-thread ID. In addition to concrete IDs, accepts
    // the protocol selectors 0, -1, pPID.0, and pPID.-1.
    Status select_thread(std::uint64_t thread, std::stop_token = {});
    Status select_thread(std::string_view thread_id, std::stop_token = {});
    bool no_ack_mode() const noexcept { return no_ack_mode_; }
private:
    Result<std::vector<std::byte>> read_remote_file_impl(std::string_view path,
        std::uint64_t offset, std::size_t maximum_size, bool probe_limit, std::stop_token);
    Status write_all(std::string_view, Deadline, std::stop_token);
    Result<unsigned char> read_byte(Deadline, std::stop_token);
    Result<std::pair<bool, std::string>> read_packet_after_start(unsigned char, Deadline, std::stop_token);
    Status queue_stop_notification(std::string);
    Status queue_console_output(std::string_view);
    Result<bool> read_ack(Deadline, std::stop_token);
    Result<std::string> receive_packet(Deadline, std::stop_token, bool accept_notifications = false,
                                      bool *was_notification = nullptr);
    Result<std::string> transact(std::string_view, std::stop_token);
    Result<std::string> transact_until(std::string_view, Deadline, std::stop_token);
    Status apply_environment_batch(std::span<const RemoteEnvironmentChange>, std::stop_token);
    ByteTransport& transport_;
    std::chrono::milliseconds timeout_;
    std::size_t max_packet_;
    std::size_t peer_packet_size_ = 4096;
    bool binary_download_supported_ = false;
    bool working_directory_supported_ = false;
    bool environment_reset_supported_ = false;
    bool environment_set_supported_ = false;
    bool environment_unset_supported_ = false;
    // RSP has no standard readback for these launch settings. Keep exact state
    // only after acknowledgements from this Client; nullopt means unknown.
    std::optional<std::vector<RemoteEnvironmentChange>> known_environment_changes_;
    std::optional<std::string> known_working_directory_;
    bool no_ack_mode_ = false;
    bool non_stop_supported_ = false;
    bool non_stop_mode_ = false;
    bool thread_events_supported_ = false;
    bool thread_events_enabled_ = false;
    bool pass_signals_supported_ = false;
    bool memory_tagging_supported_ = false;
    bool stop_reply_sequence_active_ = false;
    std::deque<std::string> pending_notifications_;
    std::size_t pending_notification_bytes_ = 0;
    std::deque<std::byte> pending_console_output_;
};
} // namespace hexlab::debugger::rsp
