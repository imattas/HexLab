#include "hexlab/automation/api.hpp"
#include "hexlab/core/sha256.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <fstream>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace hexlab::automation {
namespace {
constexpr std::size_t header_size = 8 + 4 + 16 + 8 + 4 + 4 + 4;
constexpr std::size_t digest_size = 32;
constexpr std::size_t maximum_file = header_size + maximum_workflow_namespace + maximum_workflow_state + digest_size;
constexpr std::array<std::byte, 8> magic{
    std::byte{'H'}, std::byte{'L'}, std::byte{'W'}, std::byte{'F'},
    std::byte{'S'}, std::byte{'T'}, std::byte{'A'}, std::byte{'T'}};

Result<bool> application_ok(const std::string& application, std::uint32_t schema) {
    if (application.empty() || application.size() > maximum_workflow_namespace)
        return Error{ErrorCode::resource_limit, "Workflow application name must contain 1..128 bytes"};
    for (const unsigned char c : application)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return Error{ErrorCode::invalid_argument, "Workflow application name must use ASCII letters, digits, '.', '_' or '-'"};
    if (!schema) return Error{ErrorCode::invalid_argument, "Workflow application schema version must be nonzero"};
    return true;
}
void append_integer(std::vector<std::byte>& bytes, std::uint64_t value, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) bytes.push_back(static_cast<std::byte>((value >> (i * 8)) & 255));
}
std::uint64_t read_integer(std::span<const std::byte> bytes, std::size_t& cursor, std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < width; ++i) value |= std::uint64_t(std::to_integer<unsigned char>(bytes[cursor++])) << (i * 8);
    return value;
}
struct StagingDirectory {
    std::filesystem::path path;
    ~StagingDirectory() {
        // Remove only our known staging file and directory, never recursively.
        std::error_code ignored;
        std::filesystem::remove(path / "state", ignored);
        std::filesystem::remove(path, ignored);
    }
};
struct OutputFile {
    std::FILE* file = nullptr;
    ~OutputFile() { if (file) std::fclose(file); }
};
Result<bool> publish(const std::filesystem::path& destination, std::span<const std::byte> bytes, std::stop_token stop) {
    if (destination.empty() || destination.filename().empty())
        return Error{ErrorCode::invalid_argument, "Workflow state destination must name a file"};
    auto parent = destination.parent_path();
    if (parent.empty()) parent = ".";
    static std::atomic<std::uint64_t> sequence{0};
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    std::filesystem::path staging;
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Workflow state save canceled"};
        auto candidate = parent / (".hexlab-workflow-" + std::to_string(nonce) + "-" + std::to_string(sequence.fetch_add(1)));
        std::error_code error;
        if (std::filesystem::create_directory(candidate, error)) { staging = std::move(candidate); break; }
        if (error && error != std::errc::file_exists)
            return Error{ErrorCode::io, "Cannot create workflow state staging directory: " + error.message()};
    }
    if (staging.empty()) return Error{ErrorCode::busy, "Cannot reserve workflow state staging directory"};
    StagingDirectory cleanup{staging};
    const auto staged = staging / "state";
    OutputFile output;
#ifdef _WIN32
    if (_wfopen_s(&output.file, staged.c_str(), L"wb") != 0)
#else
    if (!(output.file = std::fopen(staged.c_str(), "wb")))
#endif
        return Error{ErrorCode::io, "Cannot open workflow state staging file"};
    if (std::fwrite(bytes.data(), 1, bytes.size(), output.file) != bytes.size() || std::fflush(output.file) != 0)
        return Error{ErrorCode::io, "Cannot write workflow state staging file"};
#ifdef _WIN32
    if (_commit(_fileno(output.file)) != 0)
#else
    if (::fsync(fileno(output.file)) != 0)
#endif
        return Error{ErrorCode::io, "Cannot synchronize workflow state staging file"};
    auto* closing = output.file;
    output.file = nullptr;
    if (std::fclose(closing) != 0) return Error{ErrorCode::io, "Cannot close workflow state staging file"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Workflow state save canceled"};
    // Publication is the commit point: cancellation after this point succeeds.
#ifdef _WIN32
    if (!MoveFileExW(staged.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)) {
        const auto error = GetLastError();
        return Error{error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS ? ErrorCode::conflict : ErrorCode::io,
                     "Cannot publish workflow state (destination must not exist), Windows error " + std::to_string(error)};
    }
#else
    // A hard link publishes a complete file atomically without replacing a
    // concurrent writer's checkpoint. Staging is on the same filesystem.
    if (::link(staged.c_str(), destination.c_str()) != 0)
        return Error{errno == EEXIST ? ErrorCode::conflict : ErrorCode::io,
                     "Cannot publish workflow state (destination must not exist)"};
    const auto directory = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY);
    if (directory < 0) return Error{ErrorCode::io, "Workflow state was published, but its directory could not be opened for synchronization"};
    const auto synced = ::fsync(directory);
    ::close(directory);
    if (synced != 0) return Error{ErrorCode::io, "Workflow state was published, but its directory could not be synchronized"};
#endif
    return true;
}
}

Result<WorkflowState> Project::save_workflow_state(const std::filesystem::path& path, std::string application,
        std::uint32_t schema, std::span<const std::byte> payload, std::uint64_t expected, std::stop_token stop) const {
    auto valid = live_owner(); if (!valid) return valid.error();
    valid = application_ok(application, schema); if (!valid) return valid.error();
    if (payload.size() > maximum_workflow_state)
        return Error{ErrorCode::resource_limit, "Workflow state payload exceeds 1 MiB"};
    const auto current = session_->snapshot();
    if (current->state->revisions.edit != expected)
        return Error{ErrorCode::conflict, "Workflow state expected a different project edit revision"};
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Workflow state save canceled"};
    try {
        WorkflowState result{current->state->uuid, expected, std::move(application), schema, {payload.begin(), payload.end()}};
        std::vector<std::byte> bytes;
        bytes.reserve(header_size + result.application.size() + payload.size() + digest_size);
        bytes.insert(bytes.end(), magic.begin(), magic.end());
        append_integer(bytes, workflow_state_format_version, 4);
        bytes.insert(bytes.end(), result.project_uuid.begin(), result.project_uuid.end());
        append_integer(bytes, expected, 8);
        append_integer(bytes, schema, 4);
        append_integer(bytes, result.application.size(), 4);
        append_integer(bytes, payload.size(), 4);
        for (const auto c : result.application) bytes.push_back(static_cast<std::byte>(c));
        bytes.insert(bytes.end(), payload.begin(), payload.end());
        Sha256 hash;
        auto hashed = hash.update(bytes); if (!hashed) return hashed.error();
        const auto digest = hash.digest();
        bytes.insert(bytes.end(), digest.begin(), digest.end());
        auto written = publish(path, bytes, stop); if (!written) return written.error();
        return result;
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit, "Cannot allocate workflow state"};
    } catch (const std::filesystem::filesystem_error& error) {
        return Error{ErrorCode::io, std::string("Workflow state path error: ") + error.what()};
    }
}

Result<WorkflowState> Project::load_workflow_state(const std::filesystem::path& path, std::string application,
        std::uint32_t schema, std::stop_token stop) const {
    auto current = snapshot(); if (!current) return current.error();
    auto valid = application_ok(application, schema); if (!valid) return valid.error();
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "Workflow state load canceled"};
    try {
        std::error_code file_error;
        if (!std::filesystem::is_regular_file(path, file_error))
            return Error{ErrorCode::io, "Workflow state must be a readable regular file"};
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        if (!input) return Error{ErrorCode::io, "Cannot open workflow state"};
        const auto length = input.tellg();
        if (length < 0) return Error{ErrorCode::io, "Cannot determine workflow state size"};
        if (length > static_cast<std::streamoff>(maximum_file))
            return Error{ErrorCode::resource_limit, "Workflow state file exceeds bounded envelope size"};
        if (length < static_cast<std::streamoff>(header_size + digest_size))
            return Error{ErrorCode::malformed, "Workflow state header is truncated"};
        std::vector<std::byte> bytes(static_cast<std::size_t>(length));
        input.seekg(0);
        if (!input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())) || input.peek() != EOF)
            return Error{ErrorCode::io, "Workflow state file changed or could not be read completely"};
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Workflow state load canceled"};
        if (!std::equal(magic.begin(), magic.end(), bytes.begin()))
            return Error{ErrorCode::malformed, "Unrecognized workflow state magic"};
        std::size_t cursor = magic.size();
        if (read_integer(bytes, cursor, 4) != workflow_state_format_version)
            return Error{ErrorCode::unsupported, "Unsupported workflow state envelope version"};
        Sha256 hash;
        auto hashed = hash.update(std::span<const std::byte>(bytes).first(bytes.size() - digest_size));
        if (!hashed) return hashed.error();
        const auto digest = hash.digest();
        if (!std::equal(digest.begin(), digest.end(), bytes.end() - digest_size))
            return Error{ErrorCode::integrity, "Workflow state checksum mismatch"};
        WorkflowState result;
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(cursor), result.project_uuid.size(), result.project_uuid.begin());
        cursor += result.project_uuid.size();
        result.edit_revision = read_integer(bytes, cursor, 8);
        result.schema_version = static_cast<std::uint32_t>(read_integer(bytes, cursor, 4));
        const auto application_size = read_integer(bytes, cursor, 4);
        const auto payload_size = read_integer(bytes, cursor, 4);
        if (!application_size || application_size > maximum_workflow_namespace || payload_size > maximum_workflow_state ||
            header_size + application_size + payload_size + digest_size != bytes.size())
            return Error{ErrorCode::malformed, "Invalid workflow state lengths or trailing bytes"};
        result.application.assign(reinterpret_cast<const char*>(bytes.data() + cursor), static_cast<std::size_t>(application_size));
        cursor += static_cast<std::size_t>(application_size);
        if (result.application != application)
            return Error{ErrorCode::conflict, "Workflow state belongs to a different application"};
        if (result.schema_version != schema)
            return Error{ErrorCode::unsupported, "Unsupported workflow application schema version"};
        if (result.project_uuid != current.value()->state->uuid || result.edit_revision != current.value()->state->revisions.edit)
            return Error{ErrorCode::conflict, "Workflow state belongs to a different project or edit revision"};
        result.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor), bytes.end() - digest_size);
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "Workflow state load canceled"};
        return result;
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit, "Cannot allocate workflow state"};
    } catch (const std::filesystem::filesystem_error& error) {
        return Error{ErrorCode::io, std::string("Workflow state path error: ") + error.what()};
    }
}
}
