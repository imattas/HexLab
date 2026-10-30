#include "project_internal.hpp"
#include "hexlab/database/cache.hpp"
namespace hexlab::database {
namespace {
constexpr int references_kind=1;
std::vector<std::byte> cache_key(const AnalysisKey& key){
    std::vector<std::byte> bytes{std::byte{1},std::byte{references_kind}};
    const auto append=[&](std::span<const std::byte> value){bytes.insert(bytes.end(),value.begin(),value.end());};
    append(encode_u64(key.input.size));append(key.input.sha256);append(encode_u64(key.byte_revision));append(encode_u64(key.decision_revision));append(key.recipe_fingerprint);append(key.engine_fingerprint);if(key.external_input_fingerprint){bytes.push_back(std::byte{1});append(*key.external_input_fingerprint);}return bytes;
}
bool matches(const ProjectState& state,const AnalysisKey& key){
    if(state.input!=key.input || state.revisions.bytes!=key.byte_revision || state.revisions.decisions!=key.decision_revision)return false;
    Sha256 recipe;detail::take(recipe.update(detail::take(encode_recipe(state.recipe))));return recipe.digest()==key.recipe_fingerprint;
}
CacheLookup miss(CacheStatus status,const char* reason){return {status,{},reason};}
}
Result<CacheLookup> ProjectStore::load_reference_cache(const AnalysisKey& key,std::stop_token stop){
    return detail::guarded([&]()->Result<CacheLookup>{
        std::lock_guard lock(impl_->mutex);if(stop.stop_requested())return Error{ErrorCode::canceled,"Reference cache lookup canceled"};
        if(!matches(*impl_->state,key))return miss(CacheStatus::stale,"Reference source key differs from the current project snapshot");
        detail::Cancellation cancellation(*impl_->connection,stop);auto row=detail::take(impl_->connection->prepare("SELECT kind,engine_version,length(payload),payload FROM derived_cache WHERE cache_key=?1"));detail::take(row->bind_blob(1,cache_key(key)));
        auto next=row->step();if(!next){if(next.error().code==ErrorCode::resource_limit || next.error().code==ErrorCode::integrity)return miss(CacheStatus::corrupt,"Reference cache record exceeds checked database limits");return next.error();}
        if(!next.value())return miss(CacheStatus::absent,"No reference cache exists for this source key");
        const auto kind=row->integer(0),version=row->integer(1),size=row->integer(2);
        if(!kind || !version || !size)return miss(CacheStatus::corrupt,"Reference cache scalar types are invalid");
        if(kind.value()!=references_kind || (version.value()!=14 && version.value()!=reference_cache_version))return miss(CacheStatus::incompatible,"Reference cache kind or engine version is incompatible");
        if(version.value()==14 && key.external_input_fingerprint)return miss(CacheStatus::stale,"Legacy reference cache has no external-input identity");
        if(size.value()<40 || static_cast<uint64_t>(size.value())>reference_payload_limit)return miss(CacheStatus::corrupt,"Reference cache payload extent is invalid");
        auto payload=row->blob(3);if(!payload)return miss(CacheStatus::corrupt,"Reference cache payload is not a readable blob");
        auto index=decode_reference_index(payload.value(),stop);if(!index){if(index.error().code==ErrorCode::canceled)return index.error();return CacheLookup{CacheStatus::corrupt,{},"Reference cache recompute required: "+index.error().message};}
        if(!index.value()->key() || *index.value()->key()!=key)return miss(CacheStatus::corrupt,"Reference cache payload source key does not match its index key");
        return CacheLookup{CacheStatus::hit,std::move(index.value()),{}};
    });
}
Result<bool> ProjectStore::store_reference_cache(const AnalysisKey& key,const ReferenceIndex& index,std::stop_token stop){
    return detail::guarded([&]()->Result<bool>{
        if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Reference cache write canceled"};
        if(!index.key() || *index.key()!=key)return Error{ErrorCode::conflict,"Reference index was not derived from the supplied source key"};
        // Serialize before acquiring the writer so a larger optional cache does
        // not hold a SQL write transaction while its records are encoded.
        auto payload=detail::take(encode_reference_index(index,stop));const auto encoded_key=cache_key(key);
        std::lock_guard lock(impl_->mutex);detail::Cancellation cancellation(*impl_->connection,stop);auto transaction=detail::take(Transaction::begin(*impl_->connection));auto state=detail::read_state(*impl_->connection);
        if(!matches(*state,key))return Error{ErrorCode::conflict,"Reference worker source key is stale"};
        auto remove=detail::take(impl_->connection->prepare("DELETE FROM derived_cache WHERE kind=?1 AND cache_key<>?2"));detail::take(remove->bind_integer(1,references_kind));detail::take(remove->bind_blob(2,encoded_key));detail::take(remove->step());
        auto write=detail::take(impl_->connection->prepare("INSERT INTO derived_cache(cache_key,kind,engine_version,payload) VALUES(?1,?2,?3,?4) ON CONFLICT(cache_key) DO UPDATE SET kind=excluded.kind,engine_version=excluded.engine_version,payload=excluded.payload"));
        detail::take(write->bind_blob(1,encoded_key));detail::take(write->bind_integer(2,references_kind));detail::take(write->bind_integer(3,reference_cache_version));detail::take(write->bind_blob(4,payload));detail::take(write->step());detail::take(transaction->commit());return true;
    });
}
}
