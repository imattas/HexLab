#pragma once

#include <fstream>
#include <string>

#include <sys/types.h>

namespace hexlab::debugger::detail {

// Return a display-ready copy of Linux's task state from field 3 of stat.
// `comm` is parenthesized and may itself contain spaces or parentheses, so the
// delimiter must be the final ')' rather than a token split of the whole line.
inline std::string linux_proc_task_state(pid_t process, pid_t thread) {
    if (process <= 0 || thread <= 0) return {};
    std::ifstream input("/proc/" + std::to_string(process) + "/task/" +
                        std::to_string(thread) + "/stat");
    if (!input) return {};
    std::string line(4097, '\0');
    input.read(line.data(), static_cast<std::streamsize>(line.size()));
    const auto length = input.gcount();
    if (length <= 0 || length > 4096) return {};
    line.resize(static_cast<std::size_t>(length));
    const auto comm_end = line.rfind(')');
    if (comm_end == std::string::npos) return {};
    auto state_offset = comm_end + 1;
    while (state_offset < line.size() && line[state_offset] == ' ') ++state_offset;
    if (state_offset >= line.size()) return {};
    const char state = line[state_offset];
    if (state_offset + 1 < line.size() && line[state_offset + 1] != ' ') return {};

    const char* description = nullptr;
    switch (state) {
    case 'R': description = "running"; break;
    case 'S': description = "sleeping"; break;
    case 'D': description = "uninterruptible sleep"; break;
    case 'T': description = "stopped"; break;
    case 't': description = "tracing stop"; break;
    case 'Z': description = "zombie"; break;
    case 'X': case 'x': description = "dead"; break;
    case 'K': description = "wakekill"; break;
    case 'W': description = "waking"; break;
    case 'P': description = "parked"; break;
    case 'I': description = "idle"; break;
    default: return {};
    }
    return std::string(1, state) + " (" + description + ")";
}

} // namespace hexlab::debugger::detail
