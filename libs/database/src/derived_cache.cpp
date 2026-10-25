#include "project_internal.hpp"
#include "hexlab/database/cache.hpp"
namespace hexlab::database {
namespace {
constexpr int derived_kind=2;
int recognition_kind(FunctionRecognitionKind kind){
    if(kind==FunctionRecognitionKind::byte_signatures)return 3;
    if(kind==FunctionRecognitionKind::normalized_fingerprints)return 4;
    if(kind==FunctionRecognitionKind::flirt_patterns)return 5;
    return 0;
}
std::vector<std::byte> cache_key(const AnalysisKey& key){
    std::vector<std::byte> bytes{std::byte{1},std::byte{derived_kind}};const auto append=[&](std::span<const std::byte> value){bytes.insert(bytes.end(),value.begin(),value.end());};append(encode_u64(key.input.size));append(key.input.sha256);append(encode_u64(key.byte_revision));append(encode_u64(key.decision_revision));append(key.recipe_fingerprint);append(key.engine_fingerprint);return bytes;
}
std::vector<std::byte> recognition_key(const AnalysisKey& key,FunctionRecognitionKind kind){
    auto bytes=cache_key(key);bytes[1]=std::byte(recognition_kind(kind));return bytes;
}
bool matches(const ProjectState& state,const AnalysisKey& key){
    if(state.input!=key.input || state.revisions.bytes!=key.byte_revision || state.revisions.decisions!=key.decision_revision)return false;Sha256 recipe;detail::take(recipe.update(detail::take(encode_recipe(state.recipe))));return recipe.digest()==key.recipe_fingerprint;
}
DerivedCacheLookup miss(CacheStatus status,const char* reason){return {status,{},reason};}
}
Result<DerivedCacheLookup> ProjectStore::load_derived_cache(const AnalysisKey& key,const Image& image,const ImageMetadata& metadata,const AnalysisOptions& options,std::stop_token stop){return detail::guarded([&]()->Result<DerivedCacheLookup>{
    auto bytes=detail::take(read_derived_cache(key,stop));if(bytes.status!=CacheStatus::hit || !bytes.payload)return DerivedCacheLookup{bytes.status,{},std::move(bytes.reason)};auto state=detail::take(snapshot());if(!matches(*state,key))return miss(CacheStatus::stale,"Derived source changed while reading its cache");auto proposal=decode_derived(*bytes.payload,image,metadata,state->user->decisions,options,key,stop);if(!proposal){if(proposal.error().code==ErrorCode::canceled)return proposal.error();return DerivedCacheLookup{CacheStatus::corrupt,{},"Derived cache recompute required: "+proposal.error().message};}return DerivedCacheLookup{CacheStatus::hit,std::make_shared<const DerivedProposal>(std::move(proposal.value())),{}};
});}
Result<bool> ProjectStore::store_derived_cache(const DerivedProposal& proposal,std::stop_token stop){return detail::guarded([&]()->Result<bool>{
    if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};auto payload=detail::take(encode_derived(proposal,stop));return write_derived_cache(proposal.source_key,payload,stop);
});}
Result<DerivedCacheBytes> ProjectStore::read_derived_cache(const AnalysisKey& key,std::stop_token stop){return detail::guarded([&]()->Result<DerivedCacheBytes>{
    std::lock_guard lock(impl_->mutex);if(stop.stop_requested())return Error{ErrorCode::canceled,"Derived cache read canceled"};if(!matches(*impl_->state,key))return DerivedCacheBytes{CacheStatus::stale,{},"Derived source key differs from the current project snapshot"};detail::Cancellation cancellation(*impl_->connection,stop);auto row=detail::take(impl_->connection->prepare("SELECT kind,engine_version,length(payload),payload FROM derived_cache WHERE cache_key=?1"));detail::take(row->bind_blob(1,cache_key(key)));auto next=row->step();if(!next){if(next.error().code==ErrorCode::resource_limit || next.error().code==ErrorCode::integrity)return DerivedCacheBytes{CacheStatus::corrupt,{},"Derived cache exceeds checked database limits"};return next.error();}if(!next.value())return DerivedCacheBytes{CacheStatus::absent,{},"No complete derived cache exists for this source key"};
    auto kind=row->integer(0),version=row->integer(1),size=row->integer(2);if(!kind || !version || !size)return DerivedCacheBytes{CacheStatus::corrupt,{},"Derived cache scalar types are invalid"};if(kind.value()!=derived_kind || version.value()!=derived_cache_version)return DerivedCacheBytes{CacheStatus::incompatible,{},"Derived cache kind or engine version is incompatible"};if(size.value()<180 || static_cast<uint64_t>(size.value())>derived_payload_limit)return DerivedCacheBytes{CacheStatus::corrupt,{},"Derived cache payload extent is invalid"};auto payload=row->blob(3);if(!payload)return DerivedCacheBytes{CacheStatus::corrupt,{},"Derived cache payload is not a readable blob"};return DerivedCacheBytes{CacheStatus::hit,std::make_shared<const std::vector<std::byte>>(std::move(payload.value())),{}};
});}
Result<bool> ProjectStore::write_derived_cache(const AnalysisKey& key,std::span<const std::byte> payload,std::stop_token stop){return detail::guarded([&]()->Result<bool>{
    if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};if(stop.stop_requested())return Error{ErrorCode::canceled,"Derived cache write canceled"};if(detail::take(inspect_derived_key(payload,stop))!=key)return Error{ErrorCode::conflict,"Encoded derived cache has another source key"};const auto encoded_key=cache_key(key);std::lock_guard lock(impl_->mutex);detail::Cancellation cancellation(*impl_->connection,stop);auto transaction=detail::take(Transaction::begin(*impl_->connection));auto state=detail::read_state(*impl_->connection);if(!matches(*state,key))return Error{ErrorCode::conflict,"Derived worker source key is stale"};
    auto remove=detail::take(impl_->connection->prepare("DELETE FROM derived_cache WHERE kind=?1 AND cache_key<>?2"));detail::take(remove->bind_integer(1,derived_kind));detail::take(remove->bind_blob(2,encoded_key));detail::take(remove->step());auto write=detail::take(impl_->connection->prepare("INSERT INTO derived_cache(cache_key,kind,engine_version,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(cache_key) DO UPDATE SET kind=excluded.kind,engine_version=excluded.engine_version,payload=excluded.payload"));detail::take(write->bind_blob(1,encoded_key));detail::take(write->bind_integer(2,derived_kind));detail::take(write->bind_integer(3,derived_cache_version));detail::take(write->bind_blob(4,payload));detail::take(write->step());detail::take(transaction->commit());return true;
});}
Result<FunctionRecognitionCache> ProjectStore::read_function_recognition(const AnalysisKey& key,FunctionRecognitionKind kind,std::stop_token stop){return detail::guarded([&]()->Result<FunctionRecognitionCache>{
    const auto encoded_kind=recognition_kind(kind);if(!encoded_kind)return Error{ErrorCode::invalid_argument,"Unknown function recognition evidence kind"};
    std::lock_guard lock(impl_->mutex);if(stop.stop_requested())return Error{ErrorCode::canceled,"Function recognition cache read canceled"};
    if(!matches(*impl_->state,key))return FunctionRecognitionCache{CacheStatus::stale,{},"Recognition source key differs from current project"};
    detail::Cancellation cancellation(*impl_->connection,stop);auto row=detail::take(impl_->connection->prepare("SELECT kind,engine_version,length(payload),payload FROM derived_cache WHERE cache_key=?1"));detail::take(row->bind_blob(1,recognition_key(key,kind)));
    auto next=row->step();if(!next){if(next.error().code==ErrorCode::resource_limit||next.error().code==ErrorCode::integrity)return FunctionRecognitionCache{CacheStatus::corrupt,{},"Recognition evidence exceeds checked database limits"};return next.error();}
    if(!next.value())return FunctionRecognitionCache{CacheStatus::absent,{},"No function recognition evidence is stored for this source"};
    auto stored_kind=row->integer(0),version=row->integer(1),size=row->integer(2);
    if(!stored_kind||!version||!size)return FunctionRecognitionCache{CacheStatus::corrupt,{},"Recognition cache scalar types are invalid"};
    if(stored_kind.value()!=encoded_kind||version.value()!=1)return FunctionRecognitionCache{CacheStatus::incompatible,{},"Recognition cache kind or version is incompatible"};
    if(size.value()<164||static_cast<std::uint64_t>(size.value())>16*1024*1024)return FunctionRecognitionCache{CacheStatus::corrupt,{},"Recognition evidence extent is invalid"};
    auto payload=row->blob(3);if(!payload)return FunctionRecognitionCache{CacheStatus::corrupt,{},"Recognition evidence blob is unreadable"};
    auto evidence=decode_function_recognition_evidence(payload.value(),key,kind,stop);if(!evidence){if(evidence.error().code==ErrorCode::canceled)return evidence.error();return FunctionRecognitionCache{evidence.error().code==ErrorCode::conflict?CacheStatus::stale:CacheStatus::corrupt,{},evidence.error().message};}
    return FunctionRecognitionCache{CacheStatus::hit,std::make_shared<const FunctionRecognitionEvidence>(std::move(evidence.value())),{}};
});}
Result<bool> ProjectStore::write_function_recognition(const AnalysisKey& key,const FunctionRecognitionEvidence& evidence,std::stop_token stop){return detail::guarded([&]()->Result<bool>{
    if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Function recognition cache write canceled"};
    if(evidence.source_key!=key)return Error{ErrorCode::conflict,"Recognition evidence has another source key"};
    const auto encoded_kind=recognition_kind(evidence.kind);if(!encoded_kind)return Error{ErrorCode::invalid_argument,"Unknown function recognition evidence kind"};
    auto payload=detail::take(encode_function_recognition_evidence(evidence,stop));const auto encoded_key=recognition_key(key,evidence.kind);
    std::lock_guard lock(impl_->mutex);detail::Cancellation cancellation(*impl_->connection,stop);auto transaction=detail::take(Transaction::begin(*impl_->connection));
    auto state=detail::read_state(*impl_->connection);if(!matches(*state,key))return Error{ErrorCode::conflict,"Recognition worker source key is stale"};
    auto decoded=decode_function_recognition_evidence(payload,key,evidence.kind,stop);if(!decoded)return decoded.error();
    auto remove=detail::take(impl_->connection->prepare("DELETE FROM derived_cache WHERE kind=?1 AND cache_key<>?2"));detail::take(remove->bind_integer(1,encoded_kind));detail::take(remove->bind_blob(2,encoded_key));detail::take(remove->step());
    auto write=detail::take(impl_->connection->prepare("INSERT INTO derived_cache(cache_key,kind,engine_version,payload) VALUES(?1,?2,1,?3) ON CONFLICT(cache_key) DO UPDATE SET kind=excluded.kind,engine_version=excluded.engine_version,payload=excluded.payload"));detail::take(write->bind_blob(1,encoded_key));detail::take(write->bind_integer(2,encoded_kind));detail::take(write->bind_blob(3,payload));detail::take(write->step());detail::take(transaction->commit());return true;
});}
}
