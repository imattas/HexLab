#include "testing.hpp"
#ifdef HEXLAB_DATABASE_TESTING
namespace hexlab::database::testing {
namespace {thread_local std::function<void(std::uint64_t,const std::filesystem::path&)> input_callback;}
namespace {thread_local std::function<void(BackupPhase,const std::filesystem::path&)> backup_callback;}
namespace {thread_local std::optional<ErrorCode> publication_failure;}
namespace {thread_local std::function<void()> migration_callback;thread_local std::optional<ErrorCode> commit_failure;thread_local std::function<void(TransactionPhase)> transaction_callback;}
void set_migration_callback(std::function<void()> callback){migration_callback=std::move(callback);}
void migration_checkpoint(){auto callback=std::move(migration_callback);migration_callback={};if(callback)callback();}
void fail_next_commit(ErrorCode code){commit_failure=code;}
std::optional<ErrorCode> take_commit_failure(){return std::exchange(commit_failure,{});}
void set_transaction_callback(std::function<void(TransactionPhase)> callback){transaction_callback=std::move(callback);}
void transaction_checkpoint(TransactionPhase phase){if(transaction_callback)transaction_callback(phase);}
void set_input_callback(std::function<void(std::uint64_t,const std::filesystem::path&)> callback){input_callback=std::move(callback);}
void input_checkpoint(std::uint64_t offset,const std::filesystem::path& path){if(input_callback)input_callback(offset,path);}
void set_backup_callback(std::function<void(BackupPhase,const std::filesystem::path&)> callback){backup_callback=std::move(callback);}
void backup_checkpoint(BackupPhase phase,const std::filesystem::path& path){if(backup_callback)backup_callback(phase,path);}
void fail_next_publication(ErrorCode error){publication_failure=error;}
std::optional<ErrorCode> take_publication_failure(){return std::exchange(publication_failure,{});}
}
#endif
