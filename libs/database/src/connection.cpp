#include "hexlab/database/connection.hpp"
#include "sqlite3.h"
#include "testing.hpp"
#include <limits>
#include <chrono>
#include <thread>
namespace hexlab::database {
struct ConnectionState {
    sqlite3* db=nullptr;std::stop_token stop;bool rolling_back=false;
    ~ConnectionState(){if(db)sqlite3_close_v2(db);}
};
namespace {
Error failure(sqlite3* db,int code){
    ErrorCode mapped=ErrorCode::io;
    switch(code&255){
    case SQLITE_BUSY:case SQLITE_LOCKED:mapped=ErrorCode::busy;break;
    case SQLITE_READONLY:mapped=ErrorCode::read_only;break;
    case SQLITE_INTERRUPT:mapped=ErrorCode::canceled;break;
    case SQLITE_CORRUPT:case SQLITE_NOTADB:mapped=ErrorCode::integrity;break;
    case SQLITE_CONSTRAINT:mapped=ErrorCode::conflict;break;
    case SQLITE_NOMEM:case SQLITE_FULL:case SQLITE_TOOBIG:mapped=ErrorCode::resource_limit;break;
    case SQLITE_RANGE:case SQLITE_MISUSE:mapped=ErrorCode::invalid_argument;break;
    }
    return {mapped,db?sqlite3_errmsg(db):sqlite3_errstr(code)};
}
int progress(void* ptr){const auto& state=*static_cast<ConnectionState*>(ptr);return !state.rolling_back && state.stop.stop_requested();}
#ifdef HEXLAB_DATABASE_TESTING
int commit_checkpoint(void*)noexcept{
    try{testing::transaction_checkpoint(testing::TransactionPhase::during_commit);return 0;}
    catch(...){return 1;} // Never unwind C++ exceptions through SQLite's C frames.
}
#endif
Result<bool> status(const ConnectionState& state,int code){if(code==SQLITE_OK)return true;return failure(state.db,code);}
Result<bool> execute_native(ConnectionState& state,const char* sql){
    if(state.stop.stop_requested())return Error{ErrorCode::canceled,"Database operation canceled"};
#ifdef HEXLAB_DATABASE_TESTING
    if(std::string_view(sql)=="COMMIT")if(auto failure=testing::take_commit_failure())return Error{*failure,"Injected commit failure"};
#endif
    const auto code=sqlite3_exec(state.db,sql,nullptr,nullptr,nullptr);
#ifdef HEXLAB_DATABASE_TESTING
    if(code==SQLITE_OK && std::string_view(sql)=="COMMIT")testing::transaction_checkpoint(testing::TransactionPhase::after_commit);
#endif
    return status(state,code);
}
}
DatabaseBuildInfo database_build_info(){return {sqlite3_libversion(),sqlite3_threadsafe()!=0,sqlite3_compileoption_used("OMIT_LOAD_EXTENSION")==0};}
Connection::Connection(std::shared_ptr<ConnectionState> state):state_(std::move(state)){}
Connection::~Connection()=default;
std::stop_token Connection::exchange_cancellation(std::stop_token stop)noexcept{return std::exchange(state_->stop,stop);}
Result<bool> Connection::checkpoint(){
    if(state_->stop.stop_requested())return Error{ErrorCode::canceled,"Checkpoint canceled"};
    int log=-1,done=-1;const auto code=sqlite3_wal_checkpoint_v2(state_->db,"main",SQLITE_CHECKPOINT_TRUNCATE,&log,&done);
    if(code!=SQLITE_OK)return failure(state_->db,code);
    if(log!=0 || done!=0)return Error{ErrorCode::integrity,"Checkpoint did not truncate the complete WAL"};
    return true;
}
Result<bool> Connection::backup_to(Connection& destination,std::stop_token stop){
    if(this==&destination || state_==destination.state_)return Error{ErrorCode::invalid_argument,"Backup needs a separate destination connection"};
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Backup canceled"};
    auto* backup=sqlite3_backup_init(destination.state_->db,"main",state_->db,"main");
    if(!backup)return failure(destination.state_->db,sqlite3_errcode(destination.state_->db));
    struct Guard {sqlite3_backup* value;~Guard(){if(value)sqlite3_backup_finish(value);}} guard{backup};
    auto busy_since=std::chrono::steady_clock::now();
    for(;;){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Backup canceled"};
        const auto code=sqlite3_backup_step(backup,128);
        if(code==SQLITE_DONE){const auto finished=sqlite3_backup_finish(backup);guard.value=nullptr;return status(*destination.state_,finished);}
        if(code==SQLITE_OK){busy_since=std::chrono::steady_clock::now();continue;}
        if((code&255)!=SQLITE_BUSY && (code&255)!=SQLITE_LOCKED)return failure(destination.state_->db,code);
        if(std::chrono::steady_clock::now()-busy_since>=std::chrono::seconds(2))return Error{ErrorCode::busy,"Backup remained busy for two seconds"};
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
Result<std::shared_ptr<Connection>> Connection::open(const std::filesystem::path& path,OpenMode mode,std::stop_token stop){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Database opening canceled"};
    if(path.empty() || path.native().find(typename std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos)
        return Error{ErrorCode::invalid_argument,"Invalid database path"};
    if(mode!=OpenMode::create && mode!=OpenMode::read_write && mode!=OpenMode::read_only)return Error{ErrorCode::invalid_argument,"Unknown database open mode"};
    try {
        auto state=std::make_shared<ConnectionState>();state->stop=stop;
        const auto native=std::filesystem::absolute(path).u8string();
        int flags=SQLITE_OPEN_FULLMUTEX|SQLITE_OPEN_PRIVATECACHE|SQLITE_OPEN_EXRESCODE;
        flags|=mode==OpenMode::read_only?SQLITE_OPEN_READONLY:SQLITE_OPEN_READWRITE;
        if(mode==OpenMode::create)flags|=SQLITE_OPEN_CREATE;
        const auto opened=sqlite3_open_v2(reinterpret_cast<const char*>(native.c_str()),&state->db,flags,nullptr);
        if(opened!=SQLITE_OK)return failure(state->db,opened);
        if(mode!=OpenMode::read_only && sqlite3_db_readonly(state->db,"main")!=0)return Error{ErrorCode::read_only,"Writable database requested but native connection is read only"};
        auto result=status(*state,sqlite3_busy_timeout(state->db,2000));if(!result)return result.error();
        sqlite3_progress_handler(state->db,1000,progress,state.get());
#ifdef HEXLAB_DATABASE_TESTING
        sqlite3_commit_hook(state->db,commit_checkpoint,nullptr);
#endif
        sqlite3_limit(state->db,SQLITE_LIMIT_LENGTH,64*1024*1024);
        sqlite3_limit(state->db,SQLITE_LIMIT_SQL_LENGTH,1024*1024);
        result=status(*state,sqlite3_db_config(state->db,SQLITE_DBCONFIG_DEFENSIVE,1,nullptr));if(!result)return result.error();
        result=execute_native(*state,"PRAGMA foreign_keys=ON");if(!result)return result.error();
        result=execute_native(*state,"PRAGMA trusted_schema=OFF");if(!result)return result.error();
        result=execute_native(*state,"PRAGMA synchronous=FULL");if(!result)return result.error();
        auto connection=std::shared_ptr<Connection>(new Connection(state));
        if(mode!=OpenMode::read_only){
            auto wal=connection->prepare("PRAGMA journal_mode=WAL");if(!wal)return wal.error();
            auto row=wal.value()->step();if(!row)return row.error();
            if(!row.value())return Error{ErrorCode::integrity,"Database did not report a journal mode"};
            auto name=wal.value()->text(0);if(!name)return name.error();
            if(name.value()!="wal")return Error{ErrorCode::unsupported,"Database cannot enable WAL"};
        }
        return connection;
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate database connection"};}
     catch(const std::filesystem::filesystem_error& error){return Error{ErrorCode::io,error.what()};}
}
struct Statement::Impl {
    std::shared_ptr<ConnectionState> state;sqlite3_stmt* statement=nullptr;bool row=false,done=false;
    ~Impl(){if(statement)sqlite3_finalize(statement);}
    bool column(int index)const{return row && index>=0 && index<sqlite3_column_count(statement);}
};
Statement::Statement(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
Statement::~Statement()=default;
Result<std::shared_ptr<Statement>> Connection::prepare(std::string_view sql){
    if(state_->stop.stop_requested())return Error{ErrorCode::canceled,"Database preparation canceled"};
    if(sql.empty() || sql.size()>1024*1024 || sql.find('\0')!=std::string_view::npos)return Error{ErrorCode::invalid_argument,"Invalid SQL statement extent"};
    try {
        auto impl=std::make_unique<Statement::Impl>();impl->state=state_;const char* tail=nullptr;
        auto code=sqlite3_prepare_v3(state_->db,sql.data(),static_cast<int>(sql.size()),SQLITE_PREPARE_PERSISTENT,&impl->statement,&tail);
        if(code!=SQLITE_OK)return failure(state_->db,code);
        if(!impl->statement)return Error{ErrorCode::invalid_argument,"SQL has no statement"};
        const auto remaining=sql.substr(static_cast<size_t>(tail-sql.data()));
        if(remaining.find_first_not_of(" \t\r\n")!=std::string_view::npos)return Error{ErrorCode::invalid_argument,"Only one prepared statement is allowed"};
        return std::shared_ptr<Statement>(new Statement(std::move(impl)));
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate SQL statement"};}
}
Result<bool> Connection::execute(std::string_view sql){
    auto prepared=prepare(sql);if(!prepared)return prepared.error();
    for(;;){auto row=prepared.value()->step();if(!row)return row.error();if(!row.value())return true;}
}
Result<bool> Statement::bind_integer(int index,std::int64_t value){return status(*impl_->state,sqlite3_bind_int64(impl_->statement,index,value));}
Result<bool> Statement::bind_text(int index,std::string_view value){return status(*impl_->state,sqlite3_bind_text64(impl_->statement,index,value.empty()?"":value.data(),value.size(),SQLITE_TRANSIENT,SQLITE_UTF8));}
Result<bool> Statement::bind_blob(int index,std::span<const std::byte> value){
    static const std::byte empty{};return status(*impl_->state,sqlite3_bind_blob64(impl_->statement,index,value.empty()?&empty:value.data(),value.size(),SQLITE_TRANSIENT));
}
Result<bool> Statement::bind_null(int index){return status(*impl_->state,sqlite3_bind_null(impl_->statement,index));}
Result<bool> Statement::step(){
    impl_->row=false;
    if(impl_->state->stop.stop_requested())return Error{ErrorCode::canceled,"Database step canceled"};
    if(impl_->done)return false;
    auto code=sqlite3_step(impl_->statement);
    if(code==SQLITE_ROW){impl_->row=true;return true;}
    if(code==SQLITE_DONE){impl_->done=true;return false;}
    return failure(impl_->state->db,code);
}
Result<bool> Statement::reset(){
    auto code=sqlite3_reset(impl_->statement);impl_->row=false;impl_->done=false;
    auto cleared=sqlite3_clear_bindings(impl_->statement);if(code!=SQLITE_OK)return failure(impl_->state->db,code);
    return status(*impl_->state,cleared);
}
Result<std::int64_t> Statement::integer(int index)const{
    if(!impl_->column(index) || sqlite3_column_type(impl_->statement,index)!=SQLITE_INTEGER)return Error{ErrorCode::integrity,"SQL column is not an integer"};
    return sqlite3_column_int64(impl_->statement,index);
}
Result<std::string> Statement::text(int index)const{
    if(!impl_->column(index) || sqlite3_column_type(impl_->statement,index)!=SQLITE_TEXT)return Error{ErrorCode::integrity,"SQL column is not text"};
    const auto* data=sqlite3_column_text(impl_->statement,index);const auto count=sqlite3_column_bytes(impl_->statement,index);
    if(!data)return failure(impl_->state->db,SQLITE_NOMEM);
    try{return std::string(reinterpret_cast<const char*>(data),count);}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot copy SQL text"};}
}
Result<std::vector<std::byte>> Statement::blob(int index)const{
    if(!impl_->column(index) || sqlite3_column_type(impl_->statement,index)!=SQLITE_BLOB)return Error{ErrorCode::integrity,"SQL column is not a blob"};
    const auto* data=static_cast<const std::byte*>(sqlite3_column_blob(impl_->statement,index));const auto count=sqlite3_column_bytes(impl_->statement,index);
    if(!count)return std::vector<std::byte>{};if(!data)return failure(impl_->state->db,SQLITE_NOMEM);
    try{return std::vector<std::byte>(data,data+count);}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot copy SQL blob"};}
}
Result<bool> Statement::is_null(int index)const{
    if(!impl_->column(index))return Error{ErrorCode::invalid_argument,"SQL column is unavailable"};
    return sqlite3_column_type(impl_->statement,index)==SQLITE_NULL;
}
Transaction::Transaction(std::shared_ptr<ConnectionState> state):state_(std::move(state)){}
Result<std::shared_ptr<Transaction>> Transaction::begin(Connection& connection){
    try {
        auto transaction=std::shared_ptr<Transaction>(new Transaction(connection.state_));transaction->active_=false;
        auto started=execute_native(*connection.state_,"BEGIN IMMEDIATE");if(!started)return started.error();
        transaction->active_=true;return transaction;
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate database transaction"};}
}
Result<std::shared_ptr<Transaction>> Transaction::begin_read(Connection& connection){
    try {
        auto transaction=std::shared_ptr<Transaction>(new Transaction(connection.state_));transaction->active_=false;
        auto started=execute_native(*connection.state_,"BEGIN");if(!started)return started.error();
        transaction->active_=true;return transaction;
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate database read transaction"};}
}
Transaction::~Transaction(){
    if(active_){state_->rolling_back=true;sqlite3_exec(state_->db,"ROLLBACK",nullptr,nullptr,nullptr);state_->rolling_back=false;}
}
Result<bool> Transaction::commit(){
    if(!active_)return Error{ErrorCode::invalid_argument,"Transaction already completed"};
    auto committed=execute_native(*state_,"COMMIT");if(committed)active_=false;return committed;
}
}
