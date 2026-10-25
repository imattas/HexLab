#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/database/database_export.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <stop_token>
#include <string_view>
#include <vector>
namespace hexlab::database {
struct DatabaseBuildInfo {std::string version;bool threadsafe,load_extensions;};
HEXLAB_DATABASE_EXPORT DatabaseBuildInfo database_build_info();
enum class OpenMode {create,read_write,read_only};
struct ConnectionState;
class Statement;
// Connections and their statements are used by one owning actor/thread.
// Statements retain the native connection; closing the wrapper cannot dangle them.
class Connection {
public:
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<Connection>> open(const std::filesystem::path&,OpenMode,std::stop_token);
    HEXLAB_DATABASE_EXPORT ~Connection();
    Connection(const Connection&)=delete;Connection& operator=(const Connection&)=delete;
    HEXLAB_DATABASE_EXPORT Result<std::shared_ptr<Statement>> prepare(std::string_view);
    HEXLAB_DATABASE_EXPORT Result<bool> execute(std::string_view);
    HEXLAB_DATABASE_EXPORT std::stop_token exchange_cancellation(std::stop_token) noexcept;
    HEXLAB_DATABASE_EXPORT Result<bool> backup_to(Connection& destination,std::stop_token);
    HEXLAB_DATABASE_EXPORT Result<bool> checkpoint();
private:
    explicit Connection(std::shared_ptr<ConnectionState>);
    std::shared_ptr<ConnectionState> state_;
    friend class Transaction;
};
class Statement {
public:
    HEXLAB_DATABASE_EXPORT ~Statement();
    Statement(const Statement&)=delete;Statement& operator=(const Statement&)=delete;
    HEXLAB_DATABASE_EXPORT Result<bool> bind_integer(int,std::int64_t);
    HEXLAB_DATABASE_EXPORT Result<bool> bind_text(int,std::string_view);
    HEXLAB_DATABASE_EXPORT Result<bool> bind_blob(int,std::span<const std::byte>);
    HEXLAB_DATABASE_EXPORT Result<bool> bind_null(int);
    HEXLAB_DATABASE_EXPORT Result<bool> step(); // true is a row, false is end; errors stay errors.
    HEXLAB_DATABASE_EXPORT Result<bool> reset();
    HEXLAB_DATABASE_EXPORT Result<std::int64_t> integer(int) const;
    HEXLAB_DATABASE_EXPORT Result<std::string> text(int) const;
    HEXLAB_DATABASE_EXPORT Result<std::vector<std::byte>> blob(int) const;
    HEXLAB_DATABASE_EXPORT Result<bool> is_null(int) const;
private:
    struct Impl;
    explicit Statement(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
    friend class Connection;
};
class Transaction {
public:
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<Transaction>> begin(Connection&);
    // Deferred transaction: pins a consistent snapshot without reserving a writer.
    HEXLAB_DATABASE_EXPORT static Result<std::shared_ptr<Transaction>> begin_read(Connection&);
    HEXLAB_DATABASE_EXPORT ~Transaction();
    Transaction(const Transaction&)=delete;Transaction& operator=(const Transaction&)=delete;
    HEXLAB_DATABASE_EXPORT Result<bool> commit();
private:
    explicit Transaction(std::shared_ptr<ConnectionState>);
    std::shared_ptr<ConnectionState> state_;bool active_=true;
};
}
