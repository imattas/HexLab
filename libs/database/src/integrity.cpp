#include "project_internal.hpp"
#include <algorithm>
#include <string>

namespace hexlab::database {
Result<ProjectIntegrityReport> ProjectStore::check_integrity(
    std::uint64_t expected_edit, std::size_t max_issues, std::stop_token stop) const {
    return detail::guarded([&]() -> Result<ProjectIntegrityReport> {
        if (max_issues == 0 || max_issues > 256)
            return Error{ErrorCode::invalid_argument, "Project integrity issue limit must be in 1..256"};
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Project integrity check canceled"};

        std::lock_guard lock(impl_->mutex);
        detail::Cancellation cancellation(*impl_->connection, stop);
        auto transaction = detail::take(Transaction::begin_read(*impl_->connection));

        ProjectIntegrityReport report;
        auto header = detail::take(impl_->connection->prepare(
            "SELECT uuid,edit_revision,byte_revision,decision_revision FROM project WHERE singleton=1"));
        if (!detail::take(header->step()))
            return Error{ErrorCode::integrity, "Project header is missing"};
        const auto uuid = detail::take(header->blob(0));
        if (uuid.size() != report.uuid.size())
            return Error{ErrorCode::integrity, "Project UUID extent is invalid"};
        std::copy(uuid.begin(), uuid.end(), report.uuid.begin());
        const auto edit = detail::take(decode_u64(detail::take(header->blob(1))));
        report.revisions.edit = edit;
        report.revisions.bytes = detail::take(decode_u64(detail::take(header->blob(2))));
        report.revisions.decisions = detail::take(decode_u64(detail::take(header->blob(3))));
        if (detail::take(header->step()))
            return Error{ErrorCode::integrity, "Project header is duplicated"};
        if (edit != expected_edit)
            return Error{ErrorCode::conflict, "Project revision changed before integrity check"};

        const auto append_issue = [&](std::string value) {
            constexpr std::size_t issue_bytes_limit = 4096;
            if (value.size() > issue_bytes_limit) value.resize(issue_bytes_limit);
            report.issues.push_back(std::move(value));
        };

        const auto integrity_sql = "PRAGMA integrity_check(" + std::to_string(max_issues) + ")";
        auto integrity = detail::take(impl_->connection->prepare(integrity_sql));
        bool sqlite_ok = false;
        while (detail::take(integrity->step())) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Project integrity check canceled"};
            const auto message = detail::take(integrity->text(0));
            if (message == "ok") {
                sqlite_ok = true;
                break;
            }
            append_issue("SQLite integrity: " + message);
        }
        if (!sqlite_ok && report.issues.empty())
            append_issue("SQLite integrity check returned no result");
        if (report.issues.size() >= max_issues) report.complete = false;

        if (report.complete) {
            auto foreign_keys = detail::take(impl_->connection->prepare("PRAGMA foreign_key_check"));
            while (detail::take(foreign_keys->step())) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Project integrity check canceled"};
                if (report.issues.size() == max_issues) {
                    report.complete = false;
                    break;
                }
                auto table = detail::take(foreign_keys->text(0));
                auto parent = detail::take(foreign_keys->text(2));
                const auto rowid_is_null = detail::take(foreign_keys->is_null(1));
                const auto rowid = rowid_is_null ? std::string("without rowid")
                                                  : std::to_string(detail::take(foreign_keys->integer(1)));
                const auto constraint = detail::take(foreign_keys->integer(3));
                append_issue("Foreign key violation: " + table + " row " + rowid +
                             " references " + parent + " constraint " + std::to_string(constraint));
            }
        }

        report.consistent = report.complete && report.issues.empty() && sqlite_ok;
        detail::take(transaction->commit());
        return report;
    });
}
}
