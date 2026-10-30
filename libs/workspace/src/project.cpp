#include "project_internal.hpp"
#include "hexlab/workspace/project_analysis.hpp"
namespace hexlab::project_detail {
ReadSet effective_changes(const ByteStorage& before,const ByteStorage& after,const ReadSet& candidates,std::stop_token stop){
    ReadSet changes;
    for(auto range:candidates.ranges()){
        uint64_t cursor=range.begin.value,end=take(checked_add(cursor,range.size));
        while(cursor<end){canceled(stop);auto size=static_cast<size_t>(std::min<uint64_t>(65536,end-cursor));auto old=take(before.read_at({cursor},size));auto now=take(after.read_at({cursor},size));require(old.bytes.size()==size && now.bytes.size()==size,"Short read while comparing analysis revisions",ErrorCode::io);
            size_t offset=0;while(offset<size){while(offset<size && old.bytes[offset]==now.bytes[offset])++offset;auto first=offset;while(offset<size && old.bytes[offset]!=now.bytes[offset])++offset;if(first!=offset)take(changes.include({cursor+first},offset-first));}
            if(changes.ranges().size()>100000){ReadSet conservative;for(auto candidate:candidates.ranges())take(conservative.include(candidate.begin,candidate.size));return conservative;}cursor+=size;}
    }return changes;
}
std::shared_ptr<ProjectSnapshot> project_bytes(const ProjectSnapshot& before,std::shared_ptr<const database::ProjectState> state,std::stop_token stop){
    canceled(stop);auto output=std::make_shared<ProjectSnapshot>(before);output->state=std::move(state);
    if(!output->effective || !before.state || output->state->revisions.bytes!=before.state->revisions.bytes){
        output->effective=take(make_overlay(output->original,output->state->user->patches));
        ReadSet candidates;if(before.state)for(auto& span:before.state->user->patches)take(candidates.include(span.begin,span.replacement.size()));for(auto& span:output->state->user->patches)take(candidates.include(span.begin,span.replacement.size()));
        ReadSet changed=before.effective?effective_changes(*before.effective,*output->effective,candidates,stop):std::move(candidates);for(auto range:changed.ranges())take(output->pending_byte_ranges.include(range.begin,range.size));
        bool reparse=!before.loaded || !before.state || !before.loaded->metadata_complete ||
                     (!before.loaded->metadata_reads_complete && !changed.ranges().empty()) ||
                     take(encode_recipe(before.state->recipe))!=take(encode_recipe(output->state->recipe));
        if(!reparse){for(auto range:changed.ranges())if(take(before.loaded->metadata_reads.intersects(range.begin,range.size))){reparse=true;break;}}
        auto loaded=[&]()->Result<LoadedImage>{if(reparse){++output->loader_parses;return load_durable_image(output->effective,output->state->recipe,stop);}auto rebound=*before.loaded;rebound.image=take(Image::create(output->effective,before.loaded->image->layout()));return rebound;}();
        if(loaded){output->loaded=std::make_shared<const LoadedImage>(std::move(loaded.value()));output->status=DerivedStatus::stale;output->reason="Effective bytes changed; reanalysis required";}
        else{if(loaded.error().code==ErrorCode::canceled || loaded.error().code==ErrorCode::resource_limit || loaded.error().code==ErrorCode::io || loaded.error().code==ErrorCode::busy)throw Failure{loaded.error()};output->loaded.reset();output->status=DerivedStatus::file_only;output->reason="Effective input has no valid image mapping: "+loaded.error().message;}
    }else if(output->loaded && before.state->revisions.decisions!=output->state->revisions.decisions){output->status=DerivedStatus::stale;output->reason="Analysis decisions changed; reanalysis required";}
    if(output->basis && (output->basis->key.byte_revision!=output->state->revisions.bytes || output->basis->key.decision_revision!=output->state->revisions.decisions)){
        output->derived_cache_status=database::CacheStatus::stale;output->derived_cache_reason="The preceding cache belongs to an earlier derived source";
    }
    bool same_metadata=before.loaded==output->loaded || (before.loaded && output->loaded && before.loaded->metadata==output->loaded->metadata);
    if(!before.presentation || !before.state || before.state->user->annotations!=output->state->user->annotations || !same_metadata)output->presentation=make_presentation_index(output->state->user,output->loaded,stop);
    canceled(stop);return output;
}
namespace {
// These messages are not part of LoadedImage::diagnostics: that source contains
// only an aggregate context-issue count. Keep the decoder's exact detail and
// bounded file provenance, without treating a context RVA as a mapped address.
std::vector<database::TypeImportDiagnostic> minidump_context_findings(const MinidumpMetadata& metadata,std::stop_token stop){
    std::vector<database::TypeImportDiagnostic> rows;
    std::size_t bytes=0;
    bool capped=false;
    const auto add=[&](const MinidumpContext& context,std::string provenance){
        provenance+="; context RVA "+std::to_string(context.source_rva)+", size "+std::to_string(context.source_size)+": ";
        for(const auto& message:context.diagnostics){
            canceled(stop);
            const auto cost=provenance.size()+message.size()+256;
            if(rows.size()>=2047 || provenance.size()+message.size()>65536 || cost>4*1024*1024-512-bytes){capped=true;return;}
            database::TypeImportDiagnostic row;row.source="Minidump register context";row.message=provenance+message;
            rows.push_back(std::move(row));bytes+=cost;
        }
    };
    // Loader bounds threads at 65,536 and decoded contexts at 4,096. Preserve
    // stream order and reserve a row/512 bytes for a visible partial marker.
    const auto count=std::min<std::size_t>(65536,metadata.threads.size());
    for(std::size_t i=0;i<count && !capped;++i){
        canceled(stop);const auto& thread=metadata.threads[i];
        if(thread.context)add(*thread.context,"Thread record "+std::to_string(i)+", id "+std::to_string(thread.id));
    }
    if(!capped && metadata.exception && metadata.exception->context)
        add(*metadata.exception->context,"Exception thread id "+std::to_string(metadata.exception->thread_id));
    capped=capped || count<metadata.threads.size();
    if(capped){database::TypeImportDiagnostic row;row.source="Minidump register context";row.message="Partial context diagnostic report: the 2,048-row, 4 MiB, 64 KiB-message or 65,536-thread bound was reached; further context findings were not persisted.";rows.push_back(std::move(row));}
    return rows;
}
std::shared_ptr<const database::ProjectState> project_delta(const database::ProjectState& before,const database::StateDelta& delta){
    auto state=std::make_shared<database::ProjectState>(before);auto user=std::make_shared<database::UserState>(*before.user);state->user=user;
    for(auto& item:delta.changes)std::visit([&](auto& change){using T=std::decay_t<decltype(change)>;if constexpr(std::is_same_v<T,database::PatchChange>)user->patches=change.after;else{
        auto& rows=[&]()->auto&{if constexpr(std::is_same_v<T,database::AnnotationChange>)return user->annotations;else if constexpr(std::is_same_v<T,database::BookmarkChange>)return user->bookmarks;else if constexpr(std::is_same_v<T,database::RegionChange>)return user->decisions.regions;else if constexpr(std::is_same_v<T,database::FunctionChange>)return user->decisions.functions;else if constexpr(std::is_same_v<T,database::ReferenceChange>)return user->decisions.references;else if constexpr(std::is_same_v<T,database::TypeDefinitionChange>)return user->types;else if constexpr(std::is_same_v<T,database::TypeAssignmentChange>)return user->type_assignments;else if constexpr(std::is_same_v<T,database::DebugVariableChange>)return user->debug_variables;else return user->breakpoints;}();
        const auto id=change.before?change.before->id:change.after->id;auto found=std::find_if(rows.begin(),rows.end(),[&](auto& row){return row.id==id;});if(found!=rows.end()){if(change.after)*found=*change.after;else rows.erase(found);}else if(change.after)rows.push_back(*change.after);if(!change.before)state->next_entity=take(checked_add(state->next_entity,1));
    }},item);
    state->revisions.edit=take(checked_add(before.revisions.edit,1));state->history_cursor=take(checked_add(before.history_cursor,1));if(user->patches!=before.user->patches)state->revisions.bytes=take(checked_add(before.revisions.bytes,1));if(user->decisions!=before.user->decisions)state->revisions.decisions=take(checked_add(before.revisions.decisions,1));return state;
}
}
}
namespace hexlab {
Result<std::shared_ptr<ProjectSession>> ProjectSession::attach(std::shared_ptr<database::ProjectStore> store,const AnalysisOptions& options,std::stop_token stop){return attach_impl(std::move(store),options,stop,true);}
Result<std::shared_ptr<ProjectSession>> ProjectSession::attach_deferred(std::shared_ptr<database::ProjectStore> store,const AnalysisOptions& options,std::stop_token stop){return attach_impl(std::move(store),options,stop,false);}
Result<std::shared_ptr<ProjectSession>> ProjectSession::attach_impl(std::shared_ptr<database::ProjectStore> store,const AnalysisOptions& options,std::stop_token stop,bool analyze){return project_detail::guarded([&]()->Result<std::shared_ptr<ProjectSession>>{
    using namespace project_detail;require(bool(store),"Project session requires a store");canceled(stop);auto session=std::shared_ptr<ProjectSession>(new ProjectSession);session->store_=std::move(store);session->options_=options;ProjectSnapshot blank;blank.analysis_options=options;blank.original=take(session->store_->materialize_input(stop));blank.mode=session->store_->mode();auto state=take(session->store_->snapshot());
    const auto path=std::filesystem::absolute(session->store_->path());blank.protected_paths.push_back(path);for(auto suffix:{L"-wal",L"-shm",L"-journal"}){auto companion=path;companion+=suffix;blank.protected_paths.push_back(std::move(companion));}
    if(auto backing=std::dynamic_pointer_cast<const FileStorage>(blank.original))blank.protected_paths.push_back(std::filesystem::absolute(backing->backing_path()));
    if(state->provenance){const auto& provenance=*state->provenance;if(!provenance.native_path.empty())blank.protected_paths.push_back(std::filesystem::absolute(provenance.native_path));if(!provenance.relative_path.empty()){auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));blank.protected_paths.push_back((path.parent_path()/relative).lexically_normal());}}
    auto prepared=project_bytes(blank,std::move(state),stop);
    // A successful durable load completes this import's loader pass. Publish
    // both diagnostic sources in one database transaction so cancellation or
    // a failed load cannot erase the last completed set.
    if(prepared->loaded && session->store_->mode()!=database::ProjectMode::read_only){
        take(session->store_->replace_loader_diagnostics(prepared->loaded->diagnostics,
            prepared->loaded->runtime_relocation_diagnostics,stop));
        if(prepared->loaded->metadata.minidump){
            const auto key=take(project_analysis_key(*prepared,options));
            const auto diagnostics=minidump_context_findings(*prepared->loaded->metadata.minidump,stop);
            take(session->store_->replace_minidump_context_diagnostics(key,diagnostics,stop));
        }
        prepared->state=take(session->store_->snapshot());
    }
    if(!analyze && prepared->loaded){prepared->status=DerivedStatus::pending;prepared->reason="Analysis pending";}session->snapshot_=std::move(prepared);if(analyze)take(session->refresh_analysis(stop));return session;
});}
std::shared_ptr<const ProjectSnapshot> ProjectSession::snapshot()const{std::lock_guard lock(mutex_);return snapshot_;}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::set_analysis_options(const AnalysisOptions& options){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{std::lock_guard lock(mutex_);options_=options;auto next=std::make_shared<ProjectSnapshot>(*snapshot_);next->analysis_options=options;snapshot_=std::move(next);return snapshot_;});}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::execute(const ProjectCommand& command,uint64_t group,std::stop_token stop){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{
    using namespace project_detail;std::lock_guard lock(mutex_);canceled(stop);auto delta=take(validate_command(*snapshot_,command,stop));auto candidate=project_bytes(*snapshot_,project_delta(*snapshot_->state,delta),stop);take(store_->commit(snapshot_->state->revisions.edit,delta,group,stop));candidate->state=take(store_->snapshot());snapshot_=std::move(candidate);return snapshot_;
});}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::execute_batch(const std::vector<ProjectCommand>& commands,uint64_t group,std::stop_token stop){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{
    using namespace project_detail;std::lock_guard lock(mutex_);canceled(stop);require(!commands.empty(),"Cannot apply an empty command batch");
    auto projected=std::make_shared<ProjectSnapshot>(*snapshot_);database::StateDelta combined;
    auto merge=[&](const database::UserChange& incoming){
        if(auto patch=std::get_if<database::PatchChange>(&incoming)){
            auto found=std::find_if(combined.changes.begin(),combined.changes.end(),[](auto& c){return std::holds_alternative<database::PatchChange>(c);});
            if(found==combined.changes.end())combined.changes.emplace_back(*patch);else std::get<database::PatchChange>(*found).after=patch->after;
            return;
        }
        std::visit([&](const auto& change){using C=std::decay_t<decltype(change)>;if constexpr(!std::is_same_v<C,database::PatchChange>){
            auto id=change.before?change.before->id:change.after->id;
            auto found=std::find_if(combined.changes.begin(),combined.changes.end(),[&](auto& c){auto prior=std::get_if<C>(&c);return prior && (prior->before?prior->before->id:prior->after->id)==id;});
            if(found==combined.changes.end())combined.changes.emplace_back(change);else std::get<C>(*found).after=change.after;
        }
        },incoming);
    };
    for(const auto& command:commands){canceled(stop);auto delta=take(validate_command(*projected,command,stop));for(auto& change:delta.changes)merge(change);projected->state=project_delta(*projected->state,delta);}
    combined.changes.erase(std::remove_if(combined.changes.begin(),combined.changes.end(),[](auto& c){return std::visit([](auto& change){using C=std::decay_t<decltype(change)>;if constexpr(std::is_same_v<C,database::PatchChange>)return change.before==change.after;else return change.before==change.after;},c);}),combined.changes.end());
    require(!combined.changes.empty(),"Command batch has no changes");auto candidate=project_bytes(*snapshot_,projected->state,stop);take(store_->commit(snapshot_->state->revisions.edit,combined,group,stop));candidate->state=take(store_->snapshot());snapshot_=std::move(candidate);return snapshot_;
});}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::history(bool redo,std::stop_token stop){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{
    using namespace project_detail;std::lock_guard lock(mutex_);canceled(stop);auto expected=snapshot_->state->revisions.edit;auto projected=take(store_->preview_history(expected,redo,stop));auto candidate=project_bytes(*snapshot_,std::move(projected),stop);take(redo?store_->redo(expected,stop):store_->undo(expected,stop));candidate->state=take(store_->snapshot());snapshot_=std::move(candidate);return snapshot_;
});}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::undo(std::stop_token stop){return history(false,stop);}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::redo(std::stop_token stop){return history(true,stop);}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::persist_breakpoint_hit_counts(
    std::span<const database::BreakpointHitCount> counters,std::stop_token stop){
    return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{
        using namespace project_detail;std::lock_guard lock(mutex_);canceled(stop);
        take(store_->persist_breakpoint_hit_counts(counters,stop));
        auto next=std::make_shared<ProjectSnapshot>(*snapshot_);next->state=take(store_->snapshot());snapshot_=std::move(next);return snapshot_;
    });
}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::replace_type_import_diagnostics(
    std::span<const database::TypeImportDiagnostic> diagnostics,std::stop_token stop){
    return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{
        using namespace project_detail;std::lock_guard lock(mutex_);canceled(stop);
        take(store_->replace_type_import_diagnostics(diagnostics,stop));
        auto next=std::make_shared<ProjectSnapshot>(*snapshot_);next->state=take(store_->snapshot());snapshot_=std::move(next);return snapshot_;
    });
}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::upsert_decompiler_diagnostics(const AnalysisKey& key,Address function_entry,
    std::span<const database::TypeImportDiagnostic> diagnostics,std::stop_token stop){
    return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{using namespace project_detail;std::lock_guard lock(mutex_);canceled(stop);
        take(store_->upsert_decompiler_diagnostics(key,function_entry,diagnostics,stop));auto next=std::make_shared<ProjectSnapshot>(*snapshot_);next->state=take(store_->snapshot());snapshot_=std::move(next);return snapshot_;});
}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::replace_reviewed_analysis_issue_keys(std::span<const std::string> keys,std::stop_token stop){
    return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{using namespace project_detail;std::lock_guard lock(mutex_);canceled(stop);take(store_->replace_reviewed_analysis_issue_keys(keys,stop));auto next=std::make_shared<ProjectSnapshot>(*snapshot_);next->state=take(store_->snapshot());snapshot_=std::move(next);return snapshot_;});
}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::refresh_analysis(std::stop_token stop){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{
    using namespace project_detail;std::lock_guard lock(mutex_);canceled(stop);if(!snapshot_->loaded)return snapshot_;auto key=take(project_analysis_key(*snapshot_,options_));if(snapshot_->basis && snapshot_->basis->key==key && snapshot_->pending_byte_ranges.ranges().empty() && snapshot_->basis->decisions==snapshot_->state->user->decisions)return snapshot_;
    ProjectAnalysisRequest request;request.snapshot=snapshot_;request.options=options_;request.key=key;request.cache.status=snapshot_->derived_cache_status;request.cache.reason=snapshot_->derived_cache_reason;
    if(!snapshot_->basis){auto bytes=store_->read_derived_cache(key,stop);if(bytes)request.cache=std::move(bytes.value());else{if(bytes.error().code==ErrorCode::canceled)return bytes.error();request.cache.status=database::CacheStatus::corrupt;request.cache.reason=bytes.error().message;}}
    auto analysis=take(compute_project_analysis(request,stop));if(analysis.encoded_cache){auto written=store_->write_derived_cache(key,*analysis.encoded_cache,stop);if(written){analysis.cache_status=database::CacheStatus::hit;analysis.cache_reason.clear();}else analysis.cache_reason="Optional derived cache write skipped: "+written.error().message;}
    snapshot_=adopt_project_analysis(*snapshot_,analysis,options_,stop);return snapshot_;
});}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::adopt_analysis(const ProjectAnalysis& analysis,std::stop_token stop){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{std::lock_guard lock(mutex_);snapshot_=project_detail::adopt_project_analysis(*snapshot_,analysis,options_,stop);return snapshot_;});}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::record_cache_result(const AnalysisKey& key,const Result<bool>& result){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{
    using namespace project_detail;std::lock_guard lock(mutex_);require(take(project_analysis_key(*snapshot_,options_))==key,"Cache completion belongs to an earlier project source",ErrorCode::conflict);auto next=std::make_shared<ProjectSnapshot>(*snapshot_);if(result && result.value()){next->derived_cache_status=database::CacheStatus::hit;next->derived_cache_reason.clear();}else{next->derived_cache_status=database::CacheStatus::stale;next->derived_cache_reason=result?"Optional derived cache was not written":"Optional derived cache write skipped: "+result.error().message;}snapshot_=std::move(next);return snapshot_;
});}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::mark_analysis_pending(const AnalysisKey& key){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{using namespace project_detail;std::lock_guard lock(mutex_);require(take(project_analysis_key(*snapshot_,options_))==key && bool(snapshot_->loaded),"Pending analysis belongs to another source",ErrorCode::conflict);auto next=std::make_shared<ProjectSnapshot>(*snapshot_);next->status=DerivedStatus::pending;next->reason="Analysis pending";snapshot_=std::move(next);return snapshot_;});}
Result<std::shared_ptr<const ProjectSnapshot>> ProjectSession::report_analysis_error(const AnalysisKey& key,const Error& error){return project_detail::guarded([&]()->Result<std::shared_ptr<const ProjectSnapshot>>{using namespace project_detail;std::lock_guard lock(mutex_);require(take(project_analysis_key(*snapshot_,options_))==key,"Analysis error belongs to another source",ErrorCode::conflict);auto next=std::make_shared<ProjectSnapshot>(*snapshot_);if(next->basis && next->basis->key==key)next->status=next->basis->functions->complete && next->basis->references->complete() && next->basis->strings->complete && next->loaded->metadata_complete?DerivedStatus::fresh:DerivedStatus::incomplete;else next->status=next->functions?DerivedStatus::stale:DerivedStatus::incomplete;next->reason=error.message;snapshot_=std::move(next);return snapshot_;});}
}
