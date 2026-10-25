#pragma once
#include "hexlab/analysis/search.hpp"
#include <algorithm>
namespace hexlab::search_detail {
struct Failure {Error error;};
template<class T>T take(Result<T> result){if(!result)throw Failure{result.error()};return std::move(result.value());}
inline void require(bool ok,const char* reason,ErrorCode code=ErrorCode::invalid_argument){if(!ok)throw Failure{{code,reason}};}
inline void canceled(std::stop_token stop){require(!stop.stop_requested(),"Search canceled",ErrorCode::canceled);}
template<class F>auto guarded(F f)->decltype(f()){try{return f();}catch(const Failure& error){return error.error;}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate search page"};}catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Search allocation limit"};}}
struct PatternOctet { std::byte value{}; std::byte mask{}; };
struct Compiled {std::vector<PatternOctet> pattern;std::optional<ImmediateQuery> immediate;std::uint64_t bits=0;Sha256Digest fingerprint{};};
Compiled compile(const SearchQuery&);
}
