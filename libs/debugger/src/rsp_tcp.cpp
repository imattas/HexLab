#include "hexlab/debugger/rsp.hpp"

#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#  define NOMINMAX
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <cerrno>
#  include <fcntl.h>
#  include <netdb.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace hexlab::debugger::rsp {
namespace {
Error socket_error(const char* action) { return {ErrorCode::io, std::string(action) + " failed"}; }
#ifdef _WIN32
using Socket = SOCKET;
constexpr Socket invalid_socket = INVALID_SOCKET;
void close_socket(Socket s) { closesocket(s); }
bool make_nonblocking(Socket s) { u_long mode = 1; return ioctlsocket(s, FIONBIO, &mode) == 0; }
bool in_progress() { const auto error = WSAGetLastError(); return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS; }
int last_socket_error() { return WSAGetLastError(); }
int would_block_code() { return WSAEWOULDBLOCK; }
#else
using Socket = int;
constexpr Socket invalid_socket = -1;
void close_socket(Socket s) { ::close(s); }
bool make_nonblocking(Socket s) { const int flags = fcntl(s, F_GETFL, 0); return flags >= 0 && fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0; }
bool in_progress() { return errno == EINPROGRESS || errno == EWOULDBLOCK; }
int last_socket_error() { return errno; }
int would_block_code() { return EAGAIN; }
#endif

struct ResolvedAddress {
    sockaddr_storage address{};
    std::size_t length = 0;
    int family = 0;
    int socket_type = 0;
    int protocol = 0;
};
struct ResolveState {
    std::mutex mutex;
    std::condition_variable ready_changed;
    bool ready = false;
    enum class ErrorKind { none, host, no_addresses, resolver, winsock } error = ErrorKind::none;
    std::vector<ResolvedAddress> addresses;
};
#ifdef _WIN32
struct ResolverWinsockLifetime {
    WSADATA data{};
    bool started = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    ~ResolverWinsockLifetime() { if (started) WSACleanup(); }
};
#endif
std::mutex resolver_slots_mutex;
std::condition_variable resolver_slots_changed;
std::size_t active_resolvers = 0;
constexpr std::size_t max_active_resolvers = 4;
constexpr std::size_t max_resolved_addresses = 64;

Result<std::vector<ResolvedAddress>> resolve_bounded(std::string host, std::string service,
    Deadline deadline, std::stop_token stop) {
    std::shared_ptr<ResolveState> state;
    try {
        state = std::make_shared<ResolveState>();
    } catch (...) {
        return Error{ErrorCode::resource_limit, "cannot allocate bounded remote name-resolution state"};
    }
    {
        std::unique_lock lock(resolver_slots_mutex);
        while (active_resolvers >= max_active_resolvers) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "remote debugger name resolution canceled"};
            if (std::chrono::steady_clock::now() >= deadline)
                return Error{ErrorCode::busy, "remote debugger name resolution timed out"};
            resolver_slots_changed.wait_for(lock, std::chrono::milliseconds(25));
        }
        ++active_resolvers;
    }
    try {
        std::thread resolver([state, host = std::move(host), service = std::move(service)] {
            std::vector<ResolvedAddress> resolved_addresses;
            auto error = ResolveState::ErrorKind::none;
            try {
#ifdef _WIN32
                ResolverWinsockLifetime winsock;
                if (!winsock.started) error = ResolveState::ErrorKind::winsock;
#endif
                if (error == ResolveState::ErrorKind::none) {
                    addrinfo hints{};
                    hints.ai_family = AF_UNSPEC;
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_protocol = IPPROTO_TCP;
                    addrinfo* raw_addresses = nullptr;
                    const int result = getaddrinfo(host.c_str(), service.c_str(), &hints, &raw_addresses);
                    if (result != 0) {
                        error = ResolveState::ErrorKind::host;
                    } else {
                        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(raw_addresses, freeaddrinfo);
                        for (auto* address = addresses.get(); address; address = address->ai_next) {
                            if (resolved_addresses.size() >= max_resolved_addresses) break;
                            if (!address->ai_addr || address->ai_addrlen == 0 ||
                                address->ai_addrlen > sizeof(sockaddr_storage))
                                continue;
                            ResolvedAddress copy;
                            std::memcpy(&copy.address, address->ai_addr, address->ai_addrlen);
                            copy.length = address->ai_addrlen;
                            copy.family = address->ai_family;
                            copy.socket_type = address->ai_socktype;
                            copy.protocol = address->ai_protocol;
                            resolved_addresses.push_back(copy);
                        }
                        if (resolved_addresses.empty()) error = ResolveState::ErrorKind::no_addresses;
                    }
                }
            } catch (...) {
                error = ResolveState::ErrorKind::resolver;
                resolved_addresses.clear();
            }
            {
                std::lock_guard lock(state->mutex);
                state->error = error;
                state->addresses = std::move(resolved_addresses);
                state->ready = true;
            }
            state->ready_changed.notify_all();
            {
                std::lock_guard lock(resolver_slots_mutex);
                --active_resolvers;
            }
            resolver_slots_changed.notify_all();
        });
        resolver.detach();
    } catch (...) {
        {
            std::lock_guard lock(resolver_slots_mutex);
            --active_resolvers;
        }
        resolver_slots_changed.notify_all();
        return Error{ErrorCode::io, "cannot start bounded remote name resolver"};
    }

    std::unique_lock lock(state->mutex);
    while (!state->ready) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "remote debugger name resolution canceled"};
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return Error{ErrorCode::busy, "remote debugger name resolution timed out"};
        state->ready_changed.wait_until(lock, std::min(deadline, now + std::chrono::milliseconds(25)));
    }
    switch (state->error) {
    case ResolveState::ErrorKind::none: break;
    case ResolveState::ErrorKind::host:
        return Error{ErrorCode::io, "remote debugger host name could not be resolved"};
    case ResolveState::ErrorKind::no_addresses:
        return Error{ErrorCode::io, "remote debugger host resolved to no usable TCP addresses"};
    case ResolveState::ErrorKind::winsock:
        return Error{ErrorCode::io, "Winsock initialization failed during name resolution"};
    case ResolveState::ErrorKind::resolver:
        return Error{ErrorCode::resource_limit, "remote debugger name-resolution result could not be stored"};
    }
    return std::move(state->addresses);
}

class TcpTransport final : public ByteTransport {
public:
    explicit TcpTransport(Socket socket, bool winsock) : socket_(socket), winsock_(winsock) {}
    ~TcpTransport() override {
        if (socket_ != invalid_socket) close_socket(socket_);
#ifdef _WIN32
        if (winsock_) WSACleanup();
#else
        (void)winsock_;
#endif
    }
    Result<std::size_t> read_some(std::span<std::byte> output, Deadline deadline, std::stop_token stop) override {
        if (output.empty()) return std::size_t{0};
        auto ready = wait_ready(false, deadline, stop); if (!ready) return ready.error();
#ifdef _WIN32
        const int count = recv(socket_, reinterpret_cast<char*>(output.data()), static_cast<int>(std::min<std::size_t>(output.size(), INT_MAX)), 0);
#else
        const auto count = recv(socket_, output.data(), output.size(), 0);
#endif
        if (count > 0) return static_cast<std::size_t>(count);
        if (count == 0) return Error{ErrorCode::io, "remote debugger closed the TCP connection"};
        if (last_socket_error() == would_block_code()) return Error{ErrorCode::busy, "remote debugger socket is not readable yet"};
        return socket_error("TCP read");
    }
    Result<std::size_t> write_some(std::span<const std::byte> input, Deadline deadline, std::stop_token stop) override {
        if (input.empty()) return std::size_t{0};
        auto ready = wait_ready(true, deadline, stop); if (!ready) return ready.error();
#ifdef _WIN32
        const int count = send(socket_, reinterpret_cast<const char*>(input.data()), static_cast<int>(std::min<std::size_t>(input.size(), INT_MAX)), 0);
#else
#  ifdef MSG_NOSIGNAL
        const auto count = send(socket_, input.data(), input.size(), MSG_NOSIGNAL);
#  else
        const auto count = send(socket_, input.data(), input.size(), 0);
#  endif
#endif
        if (count > 0) return static_cast<std::size_t>(count);
        if (count == 0) return Error{ErrorCode::io, "TCP write made no progress"};
        if (last_socket_error() == would_block_code()) return Error{ErrorCode::busy, "remote debugger socket is not writable yet"};
        return socket_error("TCP write");
    }
private:
    Result<bool> wait_ready(bool writing, Deadline deadline, std::stop_token stop) {
        for (;;) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "remote debugger socket operation canceled"};
            const auto now = std::chrono::steady_clock::now();
            const auto remaining = now < deadline ? std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now) : std::chrono::milliseconds(0);
            const auto slice = std::min(remaining, std::chrono::milliseconds(50));
#ifdef _WIN32
            fd_set set; FD_ZERO(&set); FD_SET(socket_, &set);
            timeval timeout{static_cast<long>(slice.count() / 1000), static_cast<long>((slice.count() % 1000) * 1000)};
            const int ready = select(0, writing ? nullptr : &set, writing ? &set : nullptr, nullptr, &timeout);
#else
            pollfd descriptor{socket_, static_cast<short>(writing ? POLLOUT : POLLIN), 0};
            const int ready = poll(&descriptor, 1, static_cast<int>(slice.count()));
#endif
            if (ready > 0) return true;
            if (ready < 0) {
#ifndef _WIN32
                if (errno == EINTR) continue;
#endif
                return socket_error("TCP readiness wait");
            }
            if (std::chrono::steady_clock::now() >= deadline)
                return Error{ErrorCode::busy, "remote debugger socket operation timed out"};
        }
    }
    Socket socket_ = invalid_socket;
    bool winsock_ = false;
};
}

Result<std::unique_ptr<ByteTransport>> connect_tcp(std::string_view host, std::uint16_t port,
                                                    std::chrono::milliseconds timeout, std::stop_token stop) {
    if (host.empty() || host.size() > 255 || host.find('\0') != std::string_view::npos || port == 0 ||
        timeout.count() <= 0 || timeout > std::chrono::hours(24))
        return Error{ErrorCode::invalid_argument, "remote debugger host, port, or timeout is invalid"};
    const auto deadline = std::chrono::steady_clock::now() + timeout;
#ifdef _WIN32
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return socket_error("Winsock initialization");
    constexpr bool owns_winsock = true;
#else
    constexpr bool owns_winsock = false;
#endif
    const auto service = std::to_string(port);
    const auto host_name = std::string(host);
    auto addresses = resolve_bounded(host_name, service, deadline, stop);
    if (!addresses) {
#ifdef _WIN32
        WSACleanup();
#endif
        return addresses.error();
    }
    Socket connected = invalid_socket;
    for (const auto& address : addresses.value()) {
        if (connected != invalid_socket) break;
        if (stop.stop_requested()) break;
        if (std::chrono::steady_clock::now() >= deadline) break;
        Socket socket = ::socket(address.family, address.socket_type, address.protocol);
        if (socket == invalid_socket) continue;
        if (!make_nonblocking(socket)) { close_socket(socket); continue; }
        const int result = ::connect(socket, reinterpret_cast<const sockaddr*>(&address.address),
                                     static_cast<int>(address.length));
        if (result == 0) { connected = socket; break; }
        if (!in_progress()) { close_socket(socket); continue; }
        // select/poll in short slices keeps cancellation responsive during connect.
        for (;;) {
            if (stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) break;
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
            const auto slice = std::min(remaining, std::chrono::milliseconds(50));
#ifdef _WIN32
            fd_set write_set; FD_ZERO(&write_set); FD_SET(socket, &write_set);
            timeval wait{static_cast<long>(slice.count() / 1000), static_cast<long>((slice.count() % 1000) * 1000)};
            const int ready = select(0, nullptr, &write_set, nullptr, &wait);
#else
            pollfd descriptor{socket, POLLOUT, 0};
            const int ready = poll(&descriptor, 1, static_cast<int>(slice.count()));
#endif
            if (ready < 0) {
#ifndef _WIN32
                if (errno == EINTR) continue;
#endif
                break;
            }
            if (ready == 0) continue;
            int error = 0;
#ifdef _WIN32
            int length = sizeof(error);
#else
            socklen_t length = sizeof(error);
#endif
            if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0 && error == 0)
                connected = socket;
            break;
        }
        if (connected != socket) close_socket(socket);
    }
    if (connected == invalid_socket) {
#ifdef _WIN32
        WSACleanup();
#endif
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "remote debugger connection canceled"};
        if (std::chrono::steady_clock::now() >= deadline) return Error{ErrorCode::busy, "remote debugger connection timed out"};
        return socket_error("remote debugger connection");
    }
    return std::unique_ptr<ByteTransport>(new TcpTransport(connected, owns_winsock));
}
} // namespace hexlab::debugger::rsp
