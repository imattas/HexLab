#include "native_files.hpp"
#include "history_internal.hpp"
#include "testing.hpp"
namespace hexlab::database {
Result<SavedProject> ProjectStore::save_as(const std::filesystem::path& destination,ReplacePolicy policy,std::stop_token stop){
    return save_as_impl(destination,policy,stop,{});
}
Result<SavedProject> ProjectStore::save_history_as(uint64_t expected,uint64_t target,HistoryPreviewLimits limits,const std::filesystem::path& destination,ReplacePolicy policy,std::stop_token stop){
    if(limits.max_steps>history_preview_step_limit || limits.max_delta_bytes>history_preview_payload_limit)
        return Error{ErrorCode::invalid_argument,"History save limits exceed 4096 steps or 64 MiB of delta payload"};
    return save_as_impl(destination,policy,stop,HistorySaveRequest{expected,target,limits});
}
Result<SavedProject> ProjectStore::save_as_impl(const std::filesystem::path& destination,ReplacePolicy policy,std::stop_token stop,std::optional<HistorySaveRequest> history){
    return detail::guarded([&]()->Result<SavedProject>{
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Save As canceled"};
        if(destination.empty() || destination.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos || (policy!=ReplacePolicy::fail_if_exists && policy!=ReplacePolicy::replace_existing))return Error{ErrorCode::invalid_argument,"Invalid Save As destination or replacement policy"};
        const auto target=std::filesystem::absolute(destination);
        if(detail::same_file(impl_->path,target))return Error{ErrorCode::invalid_argument,"Save As destination aliases the current project"};
        std::vector<std::filesystem::path> protected_paths{impl_->path};for(auto suffix:{L"-wal",L"-shm",L"-journal"}){auto companion=impl_->path;companion+=suffix;protected_paths.push_back(std::move(companion));}
        if(impl_->state->provenance){auto& provenance=*impl_->state->provenance;if(provenance.native_path.is_absolute())protected_paths.push_back(provenance.native_path);if(!provenance.relative_path.empty()){auto alternative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));protected_paths.push_back((impl_->path.parent_path()/alternative).lexically_normal());}}
        if(auto original=std::dynamic_pointer_cast<const FileStorage>(impl_->original))protected_paths.push_back(original->backing_path());auto protection=detail::protect_files(target,protected_paths);
        if(policy==ReplacePolicy::fail_if_exists && std::filesystem::exists(target))return Error{ErrorCode::conflict,"Save As destination already exists"};
        auto wal=target;wal+=L"-wal";auto shm=target;shm+=L"-shm";auto journal=target;journal+=L"-journal";
        if((std::filesystem::exists(wal) && std::filesystem::file_size(wal)!=0) || (!std::filesystem::exists(target) && std::filesystem::exists(shm)) || std::filesystem::exists(journal))return Error{ErrorCode::busy,"Destination has live or unrecovered journal data"};
        auto temporary=detail::reserve_owned_file(target.parent_path(),L".hexlab-save-",true);
        auto output=detail::take(Connection::open(temporary->path,OpenMode::create,stop));
        detail::Cancellation cancellation(*impl_->connection,stop);detail::take(impl_->connection->backup_to(*output,stop));
#ifdef HEXLAB_DATABASE_TESTING
        testing::backup_checkpoint(testing::BackupPhase::copied,temporary->path);
#endif
        const auto uuid=detail::new_uuid();
        std::vector<std::unique_ptr<detail::NativeHandle>> copied_protection;
        {
            detail::Cancellation output_cancellation(*output,stop);
            const auto copied_version=detail::schema_version(*output);
            detail::validate_schema(*output,copied_version);
            auto copied_source=detail::read_state(*output,copied_version);
            detail::require(copied_source->uuid==impl_->state->uuid,"Save As changed the source project identity");
            // Collaborative writers can refresh provenance after this store's
            // in-memory snapshot. Protect the actual copied paths as well.
            auto copied_paths=protected_paths;
            if(copied_source->provenance){
                const auto& provenance=*copied_source->provenance;
                if(provenance.native_path.is_absolute())copied_paths.push_back(provenance.native_path);
                if(!provenance.relative_path.empty()){
                    auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));
                    copied_paths.push_back((impl_->path.parent_path()/relative).lexically_normal());
                }
            }
            copied_protection=detail::protect_files(target,copied_paths);
            {
                auto transaction=detail::take(Transaction::begin(*output));
                // Only the unpublished copy is migrated. Read-only legacy sources
                // remain untouched and the fork opens as a normal editable project.
                if(history){
                    if(copied_version<12)detail::migrate_schema(*output);
                    auto preview=detail::take(detail::project_history_at(*output,history->expected_edit,history->target_step,history->limits,stop));
                    detail::restore_history_copy(*output,preview);
                }
                auto update=detail::take(output->prepare("UPDATE project SET uuid=?1 WHERE singleton=1"));detail::take(update->bind_blob(1,uuid));detail::take(update->step());
                auto copied=detail::read_state(*output);
                if(copied->provenance){const auto& provenance=*copied->provenance;std::filesystem::path original;
                    if(!provenance.relative_path.empty()){auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));original=(impl_->path.parent_path()/relative).lexically_normal();}
                    else if(provenance.native_path.is_absolute())original=provenance.native_path;
                    if(!original.empty()){auto relative=original.lexically_relative(target.parent_path());if(relative.empty())relative=original;auto encoded=relative.generic_u8string();detail::require(encoded.size()<=131072,"Saved provenance path exceeds its budget");auto rebase=detail::take(output->prepare("UPDATE input_provenance SET relative_path=?1 WHERE singleton=1"));detail::take(rebase->bind_text(1,std::string_view(reinterpret_cast<const char*>(encoded.data()),encoded.size())));detail::take(rebase->step());}}
                detail::take(transaction->commit());
            }
            detail::validate_schema(*output,detail::schema_version(*output));auto state=detail::read_state(*output);
            {auto original=detail::extract_input(*output,*state,stop);}
            detail::take(output->checkpoint());
        }
        output.reset();
#ifdef HEXLAB_DATABASE_TESTING
        testing::backup_checkpoint(testing::BackupPhase::before_publish,temporary->path);
#endif
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Save As canceled before publication"};
        SavedProject saved{target,uuid};detail::publish_file(*temporary,target,policy);
#ifdef HEXLAB_DATABASE_TESTING
        testing::backup_checkpoint(testing::BackupPhase::after_publish,target);
#endif
        return std::move(saved);
    });
}
Result<SavedProject> ProjectStore::backup_to(const std::filesystem::path& destination,ReplacePolicy policy,std::stop_token stop){
    return detail::guarded([&]()->Result<SavedProject>{
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project backup canceled"};
        if(destination.empty() || destination.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos ||
           (policy!=ReplacePolicy::fail_if_exists && policy!=ReplacePolicy::replace_existing))
            return Error{ErrorCode::invalid_argument,"Invalid project backup destination or replacement policy"};
        const auto target=std::filesystem::absolute(destination).lexically_normal();
        if(detail::same_file(impl_->path,target))return Error{ErrorCode::invalid_argument,"Project backup destination aliases the open project"};
        std::vector<std::filesystem::path> protected_paths{impl_->path};
        for(auto suffix:{L"-wal",L"-shm",L"-journal"}){auto companion=impl_->path;companion+=suffix;protected_paths.push_back(std::move(companion));}
        if(impl_->state->provenance){
            const auto& provenance=*impl_->state->provenance;
            if(provenance.native_path.is_absolute())protected_paths.push_back(provenance.native_path);
            if(!provenance.relative_path.empty()){
                auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));
                protected_paths.push_back((impl_->path.parent_path()/relative).lexically_normal());
            }
        }
        if(auto original=std::dynamic_pointer_cast<const FileStorage>(impl_->original))protected_paths.push_back(original->backing_path());
        auto protection=detail::protect_files(target,protected_paths);
        if(policy==ReplacePolicy::fail_if_exists && std::filesystem::exists(target))
            return Error{ErrorCode::conflict,"Project backup destination already exists"};
        auto wal=target;wal+=L"-wal";auto shm=target;shm+=L"-shm";auto journal=target;journal+=L"-journal";
        if((std::filesystem::exists(wal) && std::filesystem::file_size(wal)!=0) || (!std::filesystem::exists(target) && std::filesystem::exists(shm)) || std::filesystem::exists(journal))
            return Error{ErrorCode::busy,"Backup destination has live or unrecovered journal data"};

        auto temporary=detail::reserve_owned_file(target.parent_path(),L".hexlab-save-",true);
        auto output=detail::take(Connection::open(temporary->path,OpenMode::create,stop));
        detail::Cancellation cancellation(*impl_->connection,stop);
        detail::take(impl_->connection->backup_to(*output,stop));

        auto version=detail::schema_version(*output);
        detail::validate_schema(*output,version);
        auto copied=detail::read_state(*output,version);
        detail::require(copied->uuid==impl_->state->uuid,"Backup changed the project identity");
        auto copied_paths=protected_paths;
        if(copied->provenance){
            const auto& provenance=*copied->provenance;
            std::filesystem::path original;
            if(!provenance.relative_path.empty()){
                auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));
                original=(impl_->path.parent_path()/relative).lexically_normal();
            }else if(provenance.native_path.is_absolute())original=provenance.native_path;
            if(provenance.native_path.is_absolute())copied_paths.push_back(provenance.native_path);
            if(!original.empty())copied_paths.push_back(original);
        }
        auto copied_protection=detail::protect_files(target,copied_paths);
        if(copied->provenance){
            const auto& provenance=*copied->provenance;
            std::filesystem::path original;
            if(!provenance.relative_path.empty()){
                auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));
                original=(impl_->path.parent_path()/relative).lexically_normal();
            }else if(provenance.native_path.is_absolute())original=provenance.native_path;
            if(!original.empty()){
                auto relative=original.lexically_relative(target.parent_path());if(relative.empty())relative=original;
                auto encoded=relative.generic_u8string();detail::require(encoded.size()<=131072,"Backup provenance path exceeds its budget");
                auto transaction=detail::take(Transaction::begin(*output));
                auto rebase=detail::take(output->prepare("UPDATE input_provenance SET relative_path=?1 WHERE singleton=1"));
                detail::take(rebase->bind_text(1,std::string_view(reinterpret_cast<const char*>(encoded.data()),encoded.size())));
                detail::take(rebase->step());
                detail::take(transaction->commit());
            }
        }
        auto checked=detail::read_state(*output,version);
        {auto original=detail::extract_input(*output,*checked,stop);}
        detail::take(output->checkpoint());output.reset();
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project backup canceled before publication"};
        SavedProject saved{target,copied->uuid};
        detail::publish_file(*temporary,target,policy);
        return saved;
    });
}
}
