#pragma once

#include "hexlab/debugger/debugger.hpp"

#include <cstring>
#include <map>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
extern char** environ;
}

namespace hexlab::debugger::detail {

struct LinuxLaunchEnvironment {
    // Own the entire snapshot so concurrent parent environment changes cannot
    // invalidate inherited row pointers between preparation and fork/exec.
    std::vector<std::string> owned_entries;
    std::vector<char*> entries;
};

inline Result<LinuxLaunchEnvironment> prepare_linux_launch_environment(
    std::span<const RemoteEnvironmentChange> changes, char* const* inherited) {
    if (changes.size() > 256)
        return Error{ErrorCode::resource_limit, "launch environment has more than 256 changes"};

    try {
        std::map<std::string, std::optional<std::string>, std::less<>> values;
        std::size_t total = 0;
        for (const auto& change : changes) {
            if (change.name.empty() || change.name.find('=') != std::string::npos ||
                change.name.find('\0') != std::string::npos ||
                (change.value && change.value->find('\0') != std::string::npos))
                return Error{ErrorCode::invalid_argument,
                    "launch environment names must be nonempty and contain no '=' or NUL; values cannot contain NUL"};
            if (change.name.size() > 4096 || (change.value && change.value->size() > 16 * 1024))
                return Error{ErrorCode::resource_limit, "launch environment name or value exceeds its byte limit"};
            const auto value_size = change.value ? change.value->size() : 0;
            if (change.name.size() > 64 * 1024 - total ||
                value_size > 64 * 1024 - total - change.name.size())
                return Error{ErrorCode::resource_limit, "launch environment exceeds 64 KiB"};
            total += change.name.size() + value_size;
            if (!values.emplace(change.name, change.value).second)
                return Error{ErrorCode::invalid_argument, "launch environment repeats a variable name"};
        }

        LinuxLaunchEnvironment result;
        std::vector<std::string> rows;
        rows.reserve(4096);
        std::map<std::string, std::size_t, std::less<>> indexes;
        for (std::size_t i = 0; i < changes.size(); ++i)
            indexes.emplace(changes[i].name, i);
        std::vector<bool> found(changes.size(), false);
        constexpr std::size_t max_inherited_entries = 65536;
        constexpr std::size_t max_inherited_bytes = 16 * 1024 * 1024;
        std::size_t inherited_count = 0, inherited_bytes = 0;
        if (inherited) {
            for (char* const* row = inherited; *row; ++row) {
                const auto row_size = std::strlen(*row);
                if (inherited_count == max_inherited_entries ||
                    row_size >= max_inherited_bytes - inherited_bytes)
                    return Error{ErrorCode::resource_limit, "inherited launch environment exceeds its snapshot limit"};
                ++inherited_count;
                inherited_bytes += row_size + 1;
                const std::string_view entry(*row, row_size);
                const auto equals = entry.find('=');
                if (equals == std::string_view::npos) {
                    rows.emplace_back(*row);
                    continue;
                }
                const auto change = indexes.find(entry.substr(0, equals));
                if (change == indexes.end()) {
                    rows.emplace_back(*row);
                    continue;
                }
                const auto index = change->second;
                if (found[index])
                    continue; // Collapse duplicate inherited names after a patch.
                found[index] = true;
                if (!changes[index].value)
                    continue;
                rows.push_back(changes[index].name + "=" + *changes[index].value);
            }
        }
        for (std::size_t i = 0; i < changes.size(); ++i) {
            if (found[i] || !changes[i].value)
                continue;
            rows.push_back(changes[i].name + "=" + *changes[i].value);
        }
        result.owned_entries = std::move(rows);
        result.entries.reserve(result.owned_entries.size() + 1);
        for (auto& row : result.owned_entries)
            result.entries.push_back(row.data());
        result.entries.push_back(nullptr);
        return result;
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::resource_limit, "insufficient memory to prepare the launch environment"};
    }
}

} // namespace hexlab::debugger::detail
