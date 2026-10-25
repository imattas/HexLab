#pragma once
#include "project_internal.hpp"
#include "hexlab/database/transaction.hpp"
namespace hexlab::database::detail {
std::vector<std::byte> encode_delta(const StateDelta&);
StateDelta decode_delta(std::span<const std::byte>);
struct HistoryRow {uint64_t step,group;};
void append_history(Connection&,uint64_t step,uint64_t group,bool bytes,bool decisions,const StateDelta&);
StateDelta read_history(Connection&,uint64_t step,bool inverse);
StateDelta read_history_bounded(Connection&,uint64_t step,bool inverse,std::size_t& remaining);
HistoryPage read_history_header(Connection&, bool validate_full_history = true);
std::vector<HistoryRow> history_rows(Connection&);
// Caller owns a transaction (and any store lock) over the supplied connection.
Result<HistoryPreview> project_history_at(Connection&,uint64_t expected,uint64_t target,HistoryPreviewLimits,std::stop_token);
// Applies an exact projection to an unpublished copy without discarding redo.
// The copy retains its allocation cursor; revisions advance as for undo/redo.
void restore_history_copy(Connection&,const HistoryPreview&);
}
