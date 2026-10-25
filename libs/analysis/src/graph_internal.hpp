#pragma once
#include "hexlab/analysis/graph.hpp"
#include "hexlab/core/encoding.hpp"
#include <bit>
#include <cmath>
#include <set>
#include <limits>
#include <algorithm>
#include <charconv>
namespace hexlab::graph_detail {
struct Failure {Error error;};
template<class T>T take(Result<T> value){if(!value)throw Failure{value.error()};return std::move(value.value());}
inline void require(bool condition,const char* message){if(!condition)throw Failure{{ErrorCode::invalid_argument,message}};}
inline void canceled(std::stop_token stop){if(stop.stop_requested())throw Failure{{ErrorCode::canceled,"Graph operation canceled"}};}
template<class F>auto guarded(F operation)->decltype(operation()){
    try{return operation();}catch(const Failure& failure){return failure.error;}
    catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate graph model"};}
    catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Graph exceeds allocation limits"};}
}
using LocationKey=std::tuple<unsigned,uint32_t,uint64_t>;
inline LocationKey location_key(Location location){if(auto address=std::get_if<Address>(&location))return {0,address->space.value,address->offset};return {1,0,std::get<FileOffset>(location).value};}
struct Hash {
    Sha256 hash;
    void bytes(std::span<const std::byte> value){take(hash.update(value));}
    void number(uint64_t value){bytes(encode_u64(value));}
    void text(std::string_view value){number(value.size());bytes(std::as_bytes(std::span(value)));}
    void real(double value){static_assert(std::numeric_limits<double>::is_iec559);number(std::bit_cast<uint64_t>(value==0?0.0:value));}
    void location(Location value){auto [tag,space,offset]=location_key(value);number(tag);number(space);number(offset);}
};
void validate_options(const GraphOptions&);
void validate_model(const GraphModel&,std::stop_token);
Sha256Digest fingerprint(const GraphModel&,std::stop_token);
std::string safe_text(std::string_view,std::size_t max_bytes=65536);
std::string hexadecimal(std::uint64_t);
std::string location_text(Location);
std::string external_text(const ExternalIdentity&);
std::string external_identity_key(const ExternalIdentity&);
}
