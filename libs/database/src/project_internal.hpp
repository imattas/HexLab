#pragma once
#include "hexlab/database/codec.hpp"
#include "hexlab/core/encoding.hpp"
#include "hexlab/database/lease.hpp"
#include "hexlab/core/sha256.hpp"
#include <mutex>
#include <utility>
namespace hexlab::database {
struct ProjectStore::Impl {
    std::filesystem::path path;ProjectMode mode;
    std::shared_ptr<ProjectLease> lease;
    std::shared_ptr<Connection> connection;
    std::shared_ptr<const ProjectState> state;
    std::shared_ptr<const ByteStorage> original;
    mutable std::mutex mutex;
};
namespace detail {
struct Failure {Error error;};
template<class T>T take(Result<T> result){if(!result)throw Failure{result.error()};return std::move(result.value());}
inline void require(bool condition,const char* message){if(!condition)throw Failure{{ErrorCode::integrity,message}};}
template<class F>auto guarded(F operation)->decltype(operation()){
    try{return operation();}catch(const Failure& failure){return failure.error;}
    catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate project state"};}
    catch(const std::filesystem::filesystem_error& error){return Error{ErrorCode::io,error.what()};}
    catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Project state exceeds allocation limits"};}
}
int schema_version(Connection&);
ProjectUuid new_uuid();
std::shared_ptr<const ByteStorage> extract_input(Connection&,const ProjectState&,std::stop_token);
InputProvenance make_provenance(const std::filesystem::path&,const std::filesystem::path& project);
std::optional<InputProvenance> read_provenance(Connection&);
void verify_patches(const ByteStorage&,const UserState&);
void validate_schema(Connection&,int);
void create_schema(Connection&,const ProjectState&);
void migrate_schema(Connection&);
std::shared_ptr<const ProjectState> read_state(Connection&,int version=-1);
void write_user_state(Connection&,const UserState& before,const UserState& after);
Result<std::vector<std::byte>> encode_location_ranges(const std::vector<DebugLocationRange>&);
Result<std::vector<DebugLocationRange>> decode_location_ranges(std::span<const std::byte>);
Result<std::pair<std::uint64_t, Sha256Digest>> hash_recovery_artifact(
    const std::filesystem::path &, std::uint64_t byte_limit, std::stop_token);
struct Cancellation {
    Connection& connection;std::stop_token previous;
    Cancellation(Connection& value,std::stop_token stop):connection(value),previous(value.exchange_cancellation(stop)){}
    ~Cancellation(){connection.exchange_cancellation(previous);}
};
}
}
