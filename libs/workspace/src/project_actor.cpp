#include "hexlab/workspace/project_actor.hpp"
#include "hexlab/workspace/open_recipe.hpp"
#include "project_internal.hpp"
#include "project_testing.hpp"
#include <condition_variable>
#include <map>
#include <thread>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#else
#include <random>
#endif
namespace hexlab {
namespace {
using project_detail::take;using project_detail::require;using project_detail::Failure;
using database::ProjectStore;using database::ProjectMode;using database::ReplacePolicy;
using workspace_testing::ActorPhase;
struct WorkingDirectory {
    std::filesystem::path directory,project;bool created=false;
    ~WorkingDirectory(){if(!created)return;std::error_code ignored;for(const char* suffix:{"","-wal","-shm","-journal"}){auto file=project;file+=suffix;std::filesystem::remove(file,ignored);}std::filesystem::remove(directory,ignored);}
};
std::unique_ptr<WorkingDirectory> working_directory(){
    auto root=std::filesystem::temp_directory_path();for(unsigned attempt=0;attempt<8;++attempt){
        std::array<unsigned char,16> random{};
#ifdef _WIN32
        require(BCryptGenRandom(nullptr,random.data(),static_cast<ULONG>(random.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0,"Cannot generate project working-directory identity",ErrorCode::io);
#else
        std::random_device entropy;for(auto& byte:random)byte=static_cast<unsigned char>(entropy());
#endif
        std::string name="HexLab-session-";constexpr char digits[]="0123456789abcdef";for(auto byte:random){name+=digits[byte>>4];name+=digits[byte&15];}
        auto owned=std::make_unique<WorkingDirectory>();owned->directory=root/name;owned->project=owned->directory/"project.hxproj";std::error_code error;if(std::filesystem::create_directory(owned->directory,error)){owned->created=true;return owned;}if(error && error!=std::errc::file_exists)throw Failure{{ErrorCode::io,"Cannot create project working directory: "+error.message()}};
    }throw Failure{{ErrorCode::resource_limit,"Cannot reserve a project working directory"}};
}
}
struct ProjectActor::Impl {
    struct Work {
        ProjectOperationId id;ProjectOperationKind kind=ProjectOperationKind::command;
        std::filesystem::path path;ProjectMode mode=ProjectMode::read_write;ReplacePolicy policy=ReplacePolicy::fail_if_exists;
        AnalysisOptions options;OpenRequest input;std::optional<ProjectCommand> command;std::vector<ProjectCommand> commands;std::optional<FunctionRecognitionEvidence> recognition;std::vector<database::BreakpointHitCount> breakpoint_hits;FunctionRecognitionKind recognition_kind=FunctionRecognitionKind::byte_signatures;database::HistoryPreviewLimits history_preview_limits{};database::HistoryAuditLimits history_audit_limits{};uint64_t expected_edit=0,after_step=0,target_step=0;std::size_t history_limit=256;uint64_t group=0;bool force=false,replace_options=false,finished=false;
        std::stop_source stop;std::promise<Result<ProjectReply>> promise;std::shared_future<Result<ProjectReply>> future=promise.get_future().share();
    };
    struct Waiting {std::shared_ptr<Work> work;AnalysisKey source;};
    struct Context {
        std::unique_ptr<WorkingDirectory> directory;std::shared_ptr<ProjectStore> store;std::shared_ptr<ProjectSession> session;
        AnalysisOptions options;AnalysisKey key;bool untitled=false;
        std::optional<AnalysisSubmission> analysis;std::vector<Waiting> waiting;
        std::shared_ptr<const ProjectAnalysis> cache;
    };
    SessionKey key;std::shared_ptr<AnalysisPool> pool;ActorLimits limits;
    mutable std::mutex mutex;std::condition_variable_any changed;
    std::vector<std::shared_ptr<Work>> queue;std::map<uint64_t,std::shared_ptr<Work>> operations;
    std::shared_ptr<Work> active,close_work=std::make_shared<Work>();uint64_t sequence=0;
    std::stop_source lifetime;
    ActorView published;bool unread=false,closing=false;std::optional<Error> terminal_error;
    std::jthread writer;
    Impl(SessionKey session,std::shared_ptr<AnalysisPool> workers,ActorLimits value):key(session),pool(std::move(workers)),limits(value){
        require(pool && limits.max_operations>0 && limits.max_operations<=4096,"Actor requires a pool and 1 to 4096 operation slots");queue.reserve(limits.max_operations);published.session=key;close_work->id={UINT64_MAX};close_work->kind=ProjectOperationKind::close;take(pool->activate(key));try{writer=std::jthread([this](std::stop_token stop){run(stop);});}catch(...){pool->retire(key);throw;}
    }
    ~Impl(){request_close();writer.request_stop();changed.notify_all();if(writer.joinable())writer.join();}
    bool is_closing()const{std::lock_guard lock(mutex);return closing;}
    void checkpoint(ActorPhase phase,uint64_t operation=0,std::optional<AnalysisKey> source={},std::optional<std::filesystem::path> working_file={}){workspace_testing::actor_checkpoint({key,phase,operation,std::move(source),std::move(working_file)});}
    void finish_locked(const std::shared_ptr<Work>& work,Result<ProjectReply> result){if(work->finished)return;work->promise.set_value(std::move(result));work->finished=true;if(work!=close_work)operations.erase(work->id.value);}
    void finish(const std::shared_ptr<Work>& work,Result<ProjectReply> result){std::lock_guard lock(mutex);finish_locked(work,std::move(result));}
    ProjectSubmission submission(const std::shared_ptr<Work>& work)const{return {key,work->id,work->future};}
    Result<ProjectSubmission> enqueue(std::shared_ptr<Work> work){return project_detail::guarded([&]()->Result<ProjectSubmission>{
        std::lock_guard lock(mutex);if(closing)return terminal_error?Result<ProjectSubmission>{*terminal_error}:Result<ProjectSubmission>{Error{ErrorCode::canceled,"Project writer is closed"}};require(operations.size()<limits.max_operations,"Project operation queue is full",ErrorCode::resource_limit);require(sequence<UINT64_MAX-1,"Project operation IDs exhausted",ErrorCode::resource_limit);work->id={sequence+1};operations.emplace(work->id.value,work);++sequence;queue.push_back(work);changed.notify_all();return submission(work);
    });}
    void publish(std::shared_ptr<const ProjectSnapshot> snapshot,std::optional<bool> pending={}){
        std::shared_ptr<const ProjectSnapshot> retired;{std::lock_guard lock(mutex);retired=std::move(published.snapshot);published.snapshot=std::move(snapshot);if(pending)published.analysis_pending=*pending;++published.generation;unread=true;}
    }
    void location(std::optional<std::filesystem::path> path,bool untitled){std::lock_guard lock(mutex);published.project_path=std::move(path);published.untitled=untitled;}
    ProjectSubmission request_close(){
        std::vector<std::shared_ptr<Work>> retired;std::shared_ptr<Work> running;{
            std::lock_guard lock(mutex);if(closing)return submission(close_work);closing=true;published.closing=true;unread=true;retired.swap(queue);running=active;
            for(auto it=operations.begin();it!=operations.end();){auto work=it->second;++it;if(work!=running)finish_locked(work,Error{ErrorCode::canceled,"Project closed"});}
        }
        lifetime.request_stop();pool->retire(key);if(running)running->stop.request_stop();for(auto& work:retired)work->stop.request_stop();changed.notify_all();return submission(close_work);
    }
    void prune_waiting(Context& context){
        for(auto it=context.waiting.begin();it!=context.waiting.end();){if(it->work->stop.stop_requested() || it->source!=context.key || is_closing()){finish(it->work,Error{ErrorCode::canceled,"Analysis source changed"});it=context.waiting.erase(it);}else ++it;}
    }
    Result<bool> schedule(Context& context,bool force=false){try{return project_detail::guarded([&]()->Result<bool>{
        if(is_closing())return Error{ErrorCode::canceled,"Project is closing"};auto snapshot=context.session->snapshot();if(!snapshot->loaded){pool->cancel(key);context.analysis.reset();context.cache.reset();publish(snapshot,false);return false;}
        if(!force && context.analysis && context.analysis->ticket.source==context.key)return true;
        ProjectAnalysisRequest request;request.snapshot=snapshot;request.options=context.options;request.key=context.key;request.force_full=force;request.cache.status=snapshot->derived_cache_status;request.cache.reason=snapshot->derived_cache_reason;
        if(!snapshot->basis && !force){auto bytes=context.store->read_derived_cache(context.key,lifetime.get_token());if(bytes)request.cache=std::move(bytes.value());else{if(bytes.error().code==ErrorCode::canceled)return bytes.error();request.cache.status=database::CacheStatus::corrupt;request.cache.reason=bytes.error().message;}}
        checkpoint(ActorPhase::before_analysis_submit,0,context.key);const auto session_key=key;auto ticket=take(pool->submit(key,context.key,AnalysisPriority::foreground,[request=std::move(request),session_key](std::stop_token stop)->Result<AnalysisPayload>{
            workspace_testing::actor_checkpoint({session_key,ActorPhase::analysis_started,0,request.key});auto result=compute_project_analysis(request,stop);if(!result)return result.error();workspace_testing::actor_checkpoint({session_key,ActorPhase::analysis_computed,0,request.key});return AnalysisPayload{std::make_shared<const ProjectAnalysis>(std::move(result.value()))};
        }));context.analysis=std::move(ticket);publish(take(context.session->mark_analysis_pending(context.key)),true);return true;
    });}catch(const std::exception& error){return Error{ErrorCode::io,error.what()};}catch(...){return Error{ErrorCode::io,"Unknown analysis scheduling failure"};}}
    void after_edit(Context& context,const AnalysisKey& before){
        auto snapshot=context.session->snapshot();context.key.byte_revision=snapshot->state->revisions.bytes;context.key.decision_revision=snapshot->state->revisions.decisions;publish(snapshot);if(context.key==before)return;pool->cancel(key);context.analysis.reset();context.cache.reset();prune_waiting(context);auto scheduled=schedule(context);if(!scheduled && !is_closing()){auto failed=context.session->report_analysis_error(context.key,scheduled.error());if(failed)publish(failed.value(),false);}
    }
    bool poll_analysis(Context& context){
        if(!context.session)return false;
        auto current_snapshot=context.session->snapshot();
        auto current_key=project_analysis_key(*current_snapshot,context.options);
        if(current_key && current_key.value()!=context.key){
            pool->cancel(key);context.analysis.reset();context.cache.reset();context.key=current_key.value();prune_waiting(context);
            auto scheduled=schedule(context);if(!scheduled && !is_closing()){auto failed=context.session->report_analysis_error(context.key,scheduled.error());if(failed)publish(failed.value(),false);}return true;
        }
        if(!context.analysis || context.analysis->result.wait_for(std::chrono::milliseconds(0))!=std::future_status::ready)return false;
        auto completed=std::move(*context.analysis);context.analysis.reset();auto mailbox=pool->take_completed(key);
        if(completed.ticket.session!=key || completed.ticket.source!=context.key)return true;
        if(is_closing())return true;const auto& result=completed.result.get();if(!result){if(result.error().code!=ErrorCode::canceled){auto reported=context.session->report_analysis_error(context.key,result.error());if(reported)publish(reported.value(),false);}for(auto& wait:context.waiting)finish(wait.work,result.error());context.waiting.clear();return true;}
        auto proposal=std::get_if<std::shared_ptr<const ProjectAnalysis>>(&result.value());if(!proposal || !*proposal || (*proposal)->source_key!=context.key){Error error{ErrorCode::conflict,"Analysis completion has another source or product kind"};auto reported=context.session->report_analysis_error(context.key,error);if(reported)publish(reported.value(),false);for(auto& wait:context.waiting)finish(wait.work,error);context.waiting.clear();return true;}
        auto adopted=context.session->adopt_analysis(**proposal,lifetime.get_token());if(!adopted){if(adopted.error().code==ErrorCode::conflict){auto latest=context.session->snapshot();auto changed_key=project_analysis_key(*latest,context.options);if(changed_key && changed_key.value()!=context.key){context.key=changed_key.value();context.cache.reset();prune_waiting(context);auto scheduled=schedule(context);if(!scheduled && !is_closing()){auto failed=context.session->report_analysis_error(context.key,scheduled.error());if(failed)publish(failed.value(),false);}return true;}}auto reported=context.session->report_analysis_error(context.key,adopted.error());if(reported)publish(reported.value(),false);for(auto& wait:context.waiting)finish(wait.work,adopted.error());context.waiting.clear();return true;}publish(adopted.value(),false);context.cache=(*proposal)->encoded_cache?*proposal:nullptr;
        for(auto& wait:context.waiting){if(wait.source==context.key)finish(wait.work,ProjectReply{ProjectOperationKind::analyze,adopted.value()});else finish(wait.work,Error{ErrorCode::canceled,"Analysis source changed"});}context.waiting.clear();return true;
    }
    void persist_cache(Context& context){
        auto pending=std::move(context.cache);if(!pending || !pending->encoded_cache || pending->source_key!=context.key || is_closing())return;checkpoint(ActorPhase::before_cache,0,context.key);auto stored=context.store->write_derived_cache(context.key,*pending->encoded_cache,lifetime.get_token());auto recorded=context.session->record_cache_result(context.key,stored);if(recorded)publish(recorded.value());
    }
    ProjectReply save_as(Context& context,const std::shared_ptr<Work>& work){
        auto saved=take(context.store->save_as(work->path,work->policy,work->stop.get_token()));ProjectReply result{ProjectOperationKind::save_as,context.session->snapshot()};result.saved=std::move(saved);result.adopted=false;
        try{
            checkpoint(ActorPhase::after_saved,work->id.value,context.key);auto path=result.saved->path;auto next_store=take(ProjectStore::open(path,ProjectMode::read_write,work->stop.get_token()));require(next_store->mode()==ProjectMode::read_write,"Saved copy has another editable owner",ErrorCode::busy);auto next_session=take(ProjectSession::attach_deferred(next_store,context.options,work->stop.get_token()));require(take(project_analysis_key(*next_session->snapshot(),context.options))==context.key,"Saved copy source changed during adoption",ErrorCode::conflict);
            auto current=context.session->snapshot();if(current->loaded && current->derived_key==context.key && current->strings){ProjectAnalysis existing;existing.source_key=context.key;existing.derived.source_key=context.key;take(bind_derived_source(existing.derived,*current->loaded->image,work->stop.get_token()));existing.derived.functions=current->functions;existing.derived.references=current->references;existing.derived.strings=current->strings;existing.supported=bool(current->functions) && bool(current->references);existing.derived.complete=existing.supported && current->functions->complete && current->references->complete() && current->strings->complete;existing.reason=current->reason;existing.cache_status=current->derived_cache_status;existing.cache_reason=current->derived_cache_reason;take(next_session->adopt_analysis(existing,work->stop.get_token()));}
            else if(next_session->snapshot()->loaded && !context.analysis)take(next_session->report_analysis_error(context.key,Error{ErrorCode::unsupported,current->reason.empty()?"Analysis not available":current->reason}));
            context.session.reset();context.store.reset();context.directory.reset();context.store=std::move(next_store);context.session=std::move(next_session);context.untitled=false;location(std::move(path),false);publish(context.session->snapshot());result.snapshot=context.session->snapshot();result.adopted=true;
        }catch(const Failure& error){result.adoption_error=error.error;}catch(const std::bad_alloc&){result.adoption_error=Error{ErrorCode::resource_limit,"Adoption memory"};}catch(const std::exception& error){result.adoption_error=Error{ErrorCode::io,error.what()};}
        return result;
    }
    ProjectReply refresh_external(Context& context,const std::shared_ptr<Work>& work){
        require(!context.untitled,"An untitled document has no shared project head",ErrorCode::unsupported);
        require(context.store && context.session,"No saved project is open");
        const auto previous=context.session->snapshot();
        take(context.store->refresh_external(work->stop.get_token()));
        auto next_session=take(ProjectSession::attach_deferred(context.store,context.options,work->stop.get_token()));
        auto next_snapshot=next_session->snapshot();
        require(next_snapshot->state->uuid==previous->state->uuid,
                "Project identity changed before shared-state refresh",ErrorCode::conflict);
        require(next_snapshot->state->input==previous->state->input,
                "Project input identity changed before shared-state refresh",ErrorCode::conflict);
        const auto next_key=take(project_analysis_key(*next_snapshot,context.options));

        // Annotation/bookmark-only commits do not invalidate derived analysis.
        // Rebind its source metadata to the newly loaded image and carry its
        // immutable indexes forward; byte/decision changes take the normal
        // analysis path below.
        if(next_key==context.key && previous->loaded && next_snapshot->loaded &&
           previous->derived_key==context.key &&
           previous->functions && previous->references && previous->strings){
            ProjectAnalysis existing;
            existing.source_key=context.key;
            existing.derived.source_key=context.key;
            take(bind_derived_source(existing.derived,*next_snapshot->loaded->image,work->stop.get_token()));
            existing.derived.functions=previous->functions;
            existing.derived.references=previous->references;
            existing.derived.strings=previous->strings;
            existing.derived.complete=previous->functions->complete && previous->references->complete() &&
                                      previous->strings->complete && next_snapshot->loaded->metadata_complete;
            existing.supported=bool(previous->functions) && bool(previous->references);
            existing.reason=previous->reason;
            existing.cache_status=previous->derived_cache_status;
            existing.cache_reason=previous->derived_cache_reason;
            next_snapshot=take(next_session->adopt_analysis(existing,work->stop.get_token()));
        }

        if(next_key!=context.key){
            pool->cancel(key);
            context.analysis.reset();
            context.cache.reset();
            context.key=next_key;
            prune_waiting(context);
        }
        context.session.reset();
        context.session=std::move(next_session);
        const auto current=context.session->snapshot();
        const bool current_analysis=current->loaded && current->derived_key==context.key &&
            (current->status==DerivedStatus::fresh || current->status==DerivedStatus::incomplete);
        publish(current,context.analysis.has_value() || !current_analysis);
        if(!context.analysis && !current_analysis){
            auto scheduled=schedule(context);
            if(!scheduled && !is_closing()){
                auto failed=context.session->report_analysis_error(context.key,scheduled.error());
                if(failed)publish(failed.value(),false);
            }
        }
        ProjectReply result{ProjectOperationKind::refresh_external,context.session->snapshot()};
        return result;
    }
    bool handle(Context& context,const std::shared_ptr<Work>& work){
        project_detail::canceled(work->stop.get_token());ProjectReply result{work->kind,{}};
        if(work->kind==ProjectOperationKind::open_project || work->kind==ProjectOperationKind::import_binary){
            require(!context.session,"This actor already owns a project");checkpoint(ActorPhase::before_open,work->id.value);std::unique_ptr<WorkingDirectory> directory;std::shared_ptr<ProjectStore> store;bool untitled=work->kind==ProjectOperationKind::import_binary;
            if(untitled){auto request=work->input;require(!request.path.empty() && request.path.native().find(wchar_t{})==std::wstring::npos,"Invalid binary input path");auto recipe=take(resolve_open_recipe(request,work->stop.get_token()));std::shared_ptr<const ByteStorage> input;if(request.input_storage)input=request.input_storage;else input=take(FileStorage::open(request.path));recipe=take(resolve_load_recipe(*input,recipe,work->stop.get_token()));directory=working_directory();store=take(ProjectStore::create(directory->project,work->stop.get_token()));checkpoint(ActorPhase::before_import,work->id.value,{},directory->project);take(store->import_input(*input,recipe,request.source_path.value_or(request.path),work->stop.get_token()));context.options=request.analysis_options;}
            else{store=take(ProjectStore::open(work->path,work->mode,work->stop.get_token()));context.options=work->options;}
            auto session=take(ProjectSession::attach_deferred(store,context.options,work->stop.get_token()));auto source=take(project_analysis_key(*session->snapshot(),context.options));std::optional<std::filesystem::path> path;if(!untitled)path=store->path();context.waiting.reserve(limits.max_operations);context.directory=std::move(directory);context.store=std::move(store);context.session=std::move(session);context.key=source;context.untitled=untitled;location(std::move(path),untitled);publish(context.session->snapshot());if(untitled && !work->input.run_analysis){if(context.session->snapshot()->loaded)publish(take(context.session->report_analysis_error(context.key,Error{ErrorCode::unsupported,"Analysis was not requested"})),false);}else{auto scheduled=schedule(context);if(!scheduled && !is_closing()){auto reported=context.session->report_analysis_error(context.key,scheduled.error());if(reported)publish(reported.value(),false);}}result.snapshot=context.session->snapshot();
        }else{
            require(bool(context.session),"No project is open");
            switch(work->kind){
            case ProjectOperationKind::command:{checkpoint(ActorPhase::before_command,work->id.value,context.key);auto before=context.key;if(work->command)take(context.session->execute(*work->command,work->group,work->stop.get_token()));else take(context.session->execute_batch(work->commands,work->group,work->stop.get_token()));after_edit(context,before);result.snapshot=context.session->snapshot();break;}
            case ProjectOperationKind::undo:case ProjectOperationKind::redo:{checkpoint(ActorPhase::before_command,work->id.value,context.key);auto before=context.key;take(work->kind==ProjectOperationKind::redo?context.session->redo(work->stop.get_token()):context.session->undo(work->stop.get_token()));after_edit(context,before);result.snapshot=context.session->snapshot();break;}
            case ProjectOperationKind::analyze:{auto snapshot=context.session->snapshot();if(work->replace_options){context.options=std::move(work->options);snapshot=take(context.session->set_analysis_options(context.options));auto replacement_key=take(project_analysis_key(*snapshot,context.options));if(replacement_key!=context.key){pool->cancel(key);context.analysis.reset();context.cache.reset();context.key=replacement_key;prune_waiting(context);}else if(context.analysis && context.analysis->ticket.source==context.key){context.waiting.push_back({work,context.key});return false;}}if(!work->force && !context.analysis && (!snapshot->loaded || (snapshot->derived_key==context.key && (snapshot->status==DerivedStatus::fresh || snapshot->status==DerivedStatus::incomplete)))){result.snapshot=snapshot;break;}context.waiting.push_back({work,context.key});auto scheduled=schedule(context,work->force);if(!scheduled){context.waiting.pop_back();throw Failure{scheduled.error()};}if(!scheduled.value()){context.waiting.pop_back();result.snapshot=context.session->snapshot();break;}return false;}
            case ProjectOperationKind::persist_recognition:{
                require(bool(work->recognition),"Recognition evidence is missing");auto snapshot=context.session->snapshot();
                require(bool(snapshot->functions)&&snapshot->derived_key==context.key,"Recognition persistence requires current recovered function facts",ErrorCode::conflict);
                auto current_key=take(project_analysis_key(*snapshot,context.options));require(current_key==context.key,"Recognition source changed before persistence",ErrorCode::conflict);
                take(validate_function_recognition_evidence(*work->recognition,context.key,*snapshot->functions,work->stop.get_token()));
                take(context.store->write_function_recognition(context.key,*work->recognition,work->stop.get_token()));
                result.snapshot=std::move(snapshot);break;
            }
            case ProjectOperationKind::read_recognition:{
                auto snapshot=context.session->snapshot();
                require(snapshot->loaded && snapshot->functions && snapshot->derived_key==context.key,
                        "Recognition retrieval requires current recovered function facts",ErrorCode::conflict);
                result.recognition_cache=take(context.store->read_function_recognition(context.key,work->recognition_kind,work->stop.get_token()));
                result.snapshot=std::move(snapshot);break;
            }
            case ProjectOperationKind::persist_breakpoint_hits:{
                result.snapshot=take(context.session->persist_breakpoint_hit_counts(work->breakpoint_hits,work->stop.get_token()));
                publish(result.snapshot);break;
            }
            case ProjectOperationKind::history_page:{
                result.history_page=take(context.store->history_page(work->expected_edit,work->after_step,
                    work->history_limit,work->stop.get_token()));
                result.snapshot=context.session->snapshot();break;
            }
            case ProjectOperationKind::history_preview:{
                result.history_preview=take(context.store->preview_history_at(work->expected_edit,work->target_step,
                    work->history_preview_limits,work->stop.get_token()));
                result.snapshot=context.session->snapshot();break;
            }
            case ProjectOperationKind::history_audit:{
                result.history_audit=take(context.store->audit_history(work->expected_edit,work->after_step,
                    work->history_audit_limits,work->stop.get_token()));
                result.snapshot=context.session->snapshot();break;
            }
            case ProjectOperationKind::save:require(!context.untitled,"Choose Save As for an untitled project");take(context.store->checkpoint(work->stop.get_token()));result.snapshot=context.session->snapshot();break;
            case ProjectOperationKind::save_as:result=save_as(context,work);break;
            case ProjectOperationKind::backup:
                require(!context.untitled,"Save the project before creating a backup",ErrorCode::unsupported);
                result.saved=take(context.store->backup_to(work->path,work->policy,work->stop.get_token()));
                result.snapshot=context.session->snapshot();break;
            case ProjectOperationKind::export_binary:result.exported=take(export_patched(*context.session->snapshot(),work->path,work->policy,work->stop.get_token()));result.snapshot=context.session->snapshot();break;
            case ProjectOperationKind::refresh_external:result=refresh_external(context,work);break;
            case ProjectOperationKind::refresh_if_external:{
                require(!context.untitled,"An untitled document has no shared project head",ErrorCode::unsupported);
                const auto pending=take(context.store->external_changes_pending(work->stop.get_token()));
                if(pending)result=refresh_external(context,work);
                else result.snapshot=context.session->snapshot();
                break;
            }
            default:throw Failure{{ErrorCode::invalid_argument,"Unknown project operation"}};
            }
        }finish(work,std::move(result));return true;
    }
    void run(std::stop_token stop){
        Context context;
        try{checkpoint(ActorPhase::writer_started);for(;;){
            std::shared_ptr<Work> work;{
                std::lock_guard lock(mutex);if(closing || stop.stop_requested())break;if(!queue.empty()){work=std::move(queue.front());queue.erase(queue.begin());active=work;}
            }
            if(work){try{handle(context,work);}catch(const Failure& error){finish(work,error.error);}catch(const std::bad_alloc&){finish(work,Error{ErrorCode::resource_limit,"Out of memory"});}catch(const std::exception& error){finish(work,Error{ErrorCode::io,error.what()});}catch(...){finish(work,Error{ErrorCode::io,"Unknown writer failure"});}{std::lock_guard lock(mutex);if(active==work)active.reset();}continue;}
            prune_waiting(context);if(poll_analysis(context))continue;
            if(context.cache){persist_cache(context);continue;}
            std::unique_lock lock(mutex);changed.wait_for(lock,stop,std::chrono::milliseconds(10),[&]{return closing || !queue.empty();});
        }}catch(const std::exception& error){std::lock_guard lock(mutex);terminal_error=Error{ErrorCode::io,error.what()};}
        request_close();for(auto& wait:context.waiting)finish(wait.work,Error{ErrorCode::canceled,"Project closed"});context.waiting.clear();context.analysis.reset();context.cache.reset();publish({},false);context.session.reset();context.store.reset();context.directory.reset();try{checkpoint(ActorPhase::writer_closed);}catch(...){}
        {std::lock_guard lock(mutex);ProjectReply reply{ProjectOperationKind::close,{}};reply.closed=true;finish_locked(close_work,std::move(reply));}
    }
};
ProjectActor::ProjectActor(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
ProjectActor::~ProjectActor()=default;
Result<std::shared_ptr<ProjectActor>> ProjectActor::create(SessionKey key,std::shared_ptr<AnalysisPool> pool,ActorLimits limits){return project_detail::guarded([&]()->Result<std::shared_ptr<ProjectActor>>{try{return std::shared_ptr<ProjectActor>(new ProjectActor(std::make_unique<Impl>(key,std::move(pool),limits)));}catch(const std::system_error& error){return Error{ErrorCode::resource_limit,error.what()};}});}
Result<ProjectSubmission> ProjectActor::open_project(std::filesystem::path path,ProjectMode mode,const AnalysisOptions& options){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::open_project;work->path=std::move(path);work->mode=mode;work->options=options;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::import_binary(OpenRequest request){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::import_binary;work->input=std::move(request);return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::execute(ProjectCommand command,uint64_t group){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::command;work->command=std::move(command);work->group=group;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::execute_batch(std::vector<ProjectCommand> commands,uint64_t group){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::command;work->commands=std::move(commands);work->group=group;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::undo(){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::undo;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::redo(){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::redo;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::ready(bool force){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::analyze;work->force=force;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::persist_function_recognition(FunctionRecognitionEvidence evidence){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::persist_recognition;work->recognition=std::move(evidence);return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::read_function_recognition(FunctionRecognitionKind kind){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::read_recognition;work->recognition_kind=kind;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::persist_breakpoint_hit_counts(std::vector<database::BreakpointHitCount> counters){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::persist_breakpoint_hits;work->breakpoint_hits=std::move(counters);return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::history_page(uint64_t expected_edit,uint64_t after_step,std::size_t limit){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::history_page;work->expected_edit=expected_edit;work->after_step=after_step;work->history_limit=limit;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::preview_history_at(uint64_t expected_edit,uint64_t target_step,database::HistoryPreviewLimits limits){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::history_preview;work->expected_edit=expected_edit;work->target_step=target_step;work->history_preview_limits=limits;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::audit_history(uint64_t expected_edit,uint64_t after_step,database::HistoryAuditLimits limits){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::history_audit;work->expected_edit=expected_edit;work->after_step=after_step;work->history_audit_limits=limits;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::reanalyze(AnalysisOptions options){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::analyze;work->force=true;work->replace_options=true;work->options=std::move(options);return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::refresh_external(){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::refresh_external;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::refresh_if_external(){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::refresh_if_external;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::save(){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::save;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::save_as(std::filesystem::path path,ReplacePolicy policy){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::save_as;work->path=std::move(path);work->policy=policy;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::backup_to(std::filesystem::path path,ReplacePolicy policy){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::backup;work->path=std::move(path);work->policy=policy;return impl_->enqueue(std::move(work));}
Result<ProjectSubmission> ProjectActor::export_binary(std::filesystem::path path,ReplacePolicy policy){auto work=std::make_shared<Impl::Work>();work->kind=ProjectOperationKind::export_binary;work->path=std::move(path);work->policy=policy;return impl_->enqueue(std::move(work));}
bool ProjectActor::cancel_operation(ProjectOperationId id){std::shared_ptr<Impl::Work> work;{std::lock_guard lock(impl_->mutex);auto found=impl_->operations.find(id.value);if(found==impl_->operations.end())return false;work=found->second;auto queued=std::find(impl_->queue.begin(),impl_->queue.end(),work);if(queued!=impl_->queue.end()){impl_->queue.erase(queued);impl_->finish_locked(work,Error{ErrorCode::canceled,"Operation canceled"});}}work->stop.request_stop();impl_->changed.notify_all();return true;}
void ProjectActor::cancel_analysis(){impl_->pool->cancel(impl_->key);impl_->changed.notify_all();}
void ProjectActor::cancel_analysis_and_wait(){impl_->pool->cancel_and_wait(impl_->key);impl_->changed.notify_all();}
Result<ProjectSubmission> ProjectActor::close(){return impl_->request_close();}
ActorView ProjectActor::view()const{std::lock_guard lock(impl_->mutex);auto view=impl_->published;view.pending_operations=impl_->operations.size();return view;}
std::optional<ActorView> ProjectActor::take_event(){std::lock_guard lock(impl_->mutex);if(!impl_->unread)return {};impl_->unread=false;auto view=impl_->published;view.pending_operations=impl_->operations.size();return view;}
}
