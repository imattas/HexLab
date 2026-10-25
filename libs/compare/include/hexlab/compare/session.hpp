#pragma once
#include "hexlab/compare/compare.hpp"
#include <filesystem>

namespace hexlab::compare {
// A completed comparison can be reopened without either input binary. The
// session stores the derived report, function matches, and bounded instruction
// alignment runs, not image bytes or complete fingerprint sequences.
struct Session {
    std::string old_name;
    std::string new_name;
    Report report;
    std::vector<FunctionMatch> functions;
    std::vector<FunctionBodyDiff> function_body_diffs;
};

HEXLAB_COMPARE_EXPORT Result<bool> save_session(const std::filesystem::path &, const Session &);
HEXLAB_COMPARE_EXPORT Result<Session> load_session(const std::filesystem::path &);
} // namespace hexlab::compare
