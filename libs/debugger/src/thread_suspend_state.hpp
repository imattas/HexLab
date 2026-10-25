#pragma once

#include "hexlab/core/result.hpp"

#include <utility>
#include <vector>

namespace hexlab::debugger::detail {

// Acquire one extra suspend count for every peer thread as a single logical
// operation. If acquisition fails, undo all counts acquired by this call.
template<class Thread, class Suspend, class Resume>
Status suspend_other_threads(const std::vector<Thread>& threads, Thread stepping_thread,
                             Suspend suspend, Resume resume, std::vector<Thread>& suspended) {
    std::vector<Thread> acquired;
    for (const auto& thread : threads) {
        if (thread == stepping_thread) continue;
        auto result = suspend(thread);
        if (!result) {
            auto error = result.error();
            for (auto it = acquired.rbegin(); it != acquired.rend(); ++it) {
                auto restored = resume(*it);
                if (!restored) {
                    error.message += "; rolling back thread suspension also failed: " + restored.error().message;
                    suspended.push_back(*it);
                }
            }
            return error;
        }
        acquired.push_back(thread);
    }
    suspended = std::move(acquired);
    return std::monostate{};
}

// Keep handles whose extra suspend count could not yet be released, allowing
// the caller to retry before acknowledging the next debug event.
template<class Thread, class Resume>
Status resume_suspended_threads(std::vector<Thread>& suspended, Resume resume) {
    Error failure{};
    bool failed = false;
    for (auto it = suspended.begin(); it != suspended.end();) {
        auto result = resume(*it);
        if (!result) {
            if (!failed) failure = result.error();
            else failure.message += "; resuming another thread also failed: " + result.error().message;
            failed = true;
            ++it;
        } else {
            it = suspended.erase(it);
        }
    }
    if (failed) return failure;
    return std::monostate{};
}

} // namespace hexlab::debugger::detail
