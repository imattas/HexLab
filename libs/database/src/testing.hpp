#pragma once
#ifdef HEXLAB_DATABASE_TESTING
#include "hexlab/database/database_export.hpp"
#include <functional>
#include "hexlab/core/result.hpp"
#include <optional>
#include <filesystem>
#include <cstdint>
namespace hexlab::database::testing {
// Private, thread-local, one-shot checkpoint. Never selected by app input/env.
HEXLAB_DATABASE_EXPORT void set_migration_callback(std::function<void()>);
void migration_checkpoint();
HEXLAB_DATABASE_EXPORT void fail_next_commit(ErrorCode);
std::optional<ErrorCode> take_commit_failure();
enum class TransactionPhase {before_write,during_commit,after_commit};
HEXLAB_DATABASE_EXPORT void set_transaction_callback(std::function<void(TransactionPhase)>);
void transaction_checkpoint(TransactionPhase);
HEXLAB_DATABASE_EXPORT void set_input_callback(std::function<void(std::uint64_t,const std::filesystem::path&)>);
void input_checkpoint(std::uint64_t,const std::filesystem::path&);
enum class BackupPhase {copied,before_publish,after_publish};
HEXLAB_DATABASE_EXPORT void set_backup_callback(std::function<void(BackupPhase,const std::filesystem::path&)>);
void backup_checkpoint(BackupPhase,const std::filesystem::path&);
HEXLAB_DATABASE_EXPORT void fail_next_publication(ErrorCode);
std::optional<ErrorCode> take_publication_failure();
}
#endif
