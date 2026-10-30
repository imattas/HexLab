#pragma once
#include "project_arguments.hpp"
#include <optional>
#include <ostream>

namespace hexlab::cli::project_detail {
struct HistoryVerificationOutcome {
    bool attempted=false;
    std::optional<database::HistoryReplayReport> report;
    std::string budget_diagnostic;
};
HistoryVerificationOutcome verify_history_semantics(
    database::ProjectStore&,std::uint64_t expected_edit,database::HistoryReplayLimits);
// Both printers describe the same verification status and budgets. JSON emits
// one nested object; text emits a suffix suitable for an audit summary line.
void print_history_verification_json(std::ostream&,const HistoryVerificationOutcome&,database::HistoryReplayLimits);
void print_history_verification_text(std::ostream&,const HistoryVerificationOutcome&);
int run_history_verify(const Arguments&,std::ostream&);
}
