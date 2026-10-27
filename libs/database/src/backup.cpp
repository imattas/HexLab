#include "native_files.hpp"
#include "history_internal.hpp"
#include "testing.hpp"
#include <algorithm>
#include <chrono>
#include <string>
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
Result<BackupVerification> ProjectStore::verify_backup(const std::filesystem::path& path,
        std::size_t max_history_steps,std::size_t max_history_delta_bytes,std::stop_token stop){
    return detail::guarded([&]()->Result<BackupVerification>{
        constexpr std::size_t total_step_limit=65536;
        constexpr std::size_t total_delta_limit=512u*1024u*1024u;
        if(path.empty()||max_history_steps==0||max_history_steps>total_step_limit||
           max_history_delta_bytes==0||max_history_delta_bytes>total_delta_limit)
            return Error{ErrorCode::invalid_argument,"Backup verification budgets must be 1 through 65,536 history steps and 1 byte through 512 MiB"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Backup verification canceled"};
        auto backup=detail::take(ProjectStore::open(path,ProjectMode::read_only,stop));
        auto state=detail::take(backup->snapshot());
        BackupVerification result{{std::filesystem::absolute(path).lexically_normal(),state->uuid},
                                  state->history_count,0,0,state->history_count==0};
        std::uint64_t after=0;
        while(after<state->history_count){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Backup history verification canceled"};
            const auto remaining_steps=max_history_steps-static_cast<std::size_t>(result.history_steps_verified);
            const auto remaining_bytes=max_history_delta_bytes-static_cast<std::size_t>(result.history_bytes_verified);
            if(remaining_steps==0||remaining_bytes==0)break;
            const HistoryAuditLimits page_limits{
                std::min(remaining_steps,history_audit_step_limit),
                std::min(remaining_bytes,history_audit_payload_limit)};
            auto page=detail::take(backup->audit_history(state->revisions.edit,after,page_limits,stop));
            detail::require(page.uuid==state->uuid&&page.history_count==state->history_count,
                            "Backup history changed during verification");
            result.history_steps_verified+=page.entries_verified;
            result.history_bytes_verified+=page.delta_bytes;
            after=page.next_after_step;
            if(!page.has_more){result.history_complete=true;break;}
            if(page.entries_verified==0)break;
        }
        return result;
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

Result<BackupRotationResult> ProjectStore::backup_to_rotating(const std::filesystem::path& base,
        std::size_t retain,std::stop_token stop){
    return detail::guarded([&]()->Result<BackupRotationResult>{
        if(base.empty() || retain==0 || retain>32)
            return Error{ErrorCode::invalid_argument,"Backup rotation requires a base path and retention from 1 through 32"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project backup rotation canceled"};
        const auto normalized=std::filesystem::absolute(base).lexically_normal();
        if(!std::filesystem::is_directory(normalized.parent_path()))
            return Error{ErrorCode::invalid_argument,"Backup rotation directory does not exist"};
        if(detail::same_file(impl_->path,normalized))
            return Error{ErrorCode::invalid_argument,"Backup rotation base aliases the open project"};

        const auto millis=std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if(millis<0)return Error{ErrorCode::io,"System clock is before the Unix epoch"};
        const auto token=detail::new_uuid();
        constexpr char digits[]="0123456789abcdef";
        auto name=normalized.stem().native();
        const auto append_ascii=[&](std::string_view value){
            for(const auto ch:value)name.push_back(static_cast<std::filesystem::path::value_type>(ch));
        };
        append_ascii(".backup-");
        auto timestamp=std::to_string(millis);
        if(timestamp.size()<13)timestamp.insert(0,13-timestamp.size(),'0');
        append_ascii(timestamp);append_ascii("-");
        for(const auto byte:token){const auto value=std::to_integer<unsigned>(byte);name.push_back(static_cast<std::filesystem::path::value_type>(digits[value>>4]));name.push_back(static_cast<std::filesystem::path::value_type>(digits[value&15]));}
        name+=normalized.extension().native();
        const auto latest=normalized.parent_path()/std::filesystem::path(name);
        auto saved=backup_to(latest,ReplacePolicy::fail_if_exists,stop);
        if(!saved)return saved.error();
        BackupRotationResult result{saved.value(),0,true};
        // Enumerate and fully verify the same candidate set exposed by the
        // listing/pruning APIs. In particular, don't prune merely because a
        // candidate opens and carries the expected UUID: its embedded input,
        // patches, and retained undo/redo payloads must also validate.
        auto listing=list_rotated_backups(normalized,stop);
        if(!listing||!listing.value().complete){result.retention_satisfied=false;return result;}
        auto candidates=std::move(listing.value().backups);
        const auto newest=std::find_if(candidates.begin(),candidates.end(),[&](const RotatedBackup& row){
            return detail::same_file(row.backup.path,latest);
        });
        if(newest==candidates.end()){result.retention_satisfied=false;return result;}
        std::rotate(candidates.begin(),newest,newest+1);
        for(std::size_t i=retain;i<candidates.size();++i){
            if(stop.stop_requested()){result.retention_satisfied=false;return result;}
            std::error_code remove_error;
            if(std::filesystem::remove(candidates[i].backup.path,remove_error))++result.removed_generations;
            else result.retention_satisfied=false;
        }
        return result;
    });
}

Result<BackupListing> ProjectStore::list_rotated_backups(const std::filesystem::path& base,std::stop_token stop) const {
    return detail::guarded([&]()->Result<BackupListing>{
        if(base.empty())return Error{ErrorCode::invalid_argument,"Backup listing requires a base path"};
        const auto normalized=std::filesystem::absolute(base).lexically_normal();
        auto state=detail::take(snapshot());
        BackupListing listing;
        const auto prefix=normalized.stem().native()+std::filesystem::path(".backup-").native();
        const auto extension=normalized.extension().native();
        std::error_code ec;
        std::filesystem::directory_iterator it(normalized.parent_path(),ec),end;
        if(ec)return Error{ErrorCode::io,"Cannot scan backup directory: "+ec.message()};
        constexpr std::size_t entry_limit=8192,candidate_limit=64;
        constexpr std::uint64_t byte_limit=UINT64_C(1024)*1024*1024;
        std::size_t entries=0;std::uint64_t bytes=0;
        constexpr std::size_t total_history_step_limit=65536;
        constexpr std::size_t total_history_byte_limit=512u*1024u*1024u;
        std::size_t verified_history_steps=0,verified_history_bytes=0;
        while(it!=end){
            if(stop.stop_requested()){listing.complete=false;break;}
            if(++entries>entry_limit){listing.complete=false;break;}
            const auto entry=*it;it.increment(ec);if(ec){listing.complete=false;break;}
            const auto name=entry.path().filename().native();
            if(!name.starts_with(prefix)||!name.ends_with(extension)||name.size()!=prefix.size()+13+1+32+extension.size())continue;
            const auto stamp=name.substr(prefix.size(),13);const auto dash=name[prefix.size()+13];
            if(dash!=static_cast<std::filesystem::path::value_type>('-')||
               !std::all_of(stamp.begin(),stamp.end(),[](auto ch){return ch>=static_cast<std::filesystem::path::value_type>('0')&&ch<=static_cast<std::filesystem::path::value_type>('9');}))continue;
            bool token=true;for(std::size_t i=prefix.size()+14;i<prefix.size()+14+32;++i){const auto c=name[i];token=token&&((c>=static_cast<std::filesystem::path::value_type>('0')&&c<=static_cast<std::filesystem::path::value_type>('9'))||(c>=static_cast<std::filesystem::path::value_type>('a')&&c<=static_cast<std::filesystem::path::value_type>('f')));}
            if(!token)continue;
            const auto status=entry.symlink_status(ec);if(ec){listing.complete=false;break;}
            if(!std::filesystem::is_regular_file(status))continue;
            const auto size=entry.file_size(ec);if(ec||size>byte_limit-bytes){listing.complete=false;break;}bytes+=size;
            if(listing.backups.size()>=candidate_limit){listing.complete=false;break;}
            const auto remaining_steps=total_history_step_limit-verified_history_steps;
            const auto remaining_bytes=total_history_byte_limit-verified_history_bytes;
            if(remaining_steps==0||remaining_bytes==0){listing.complete=false;break;}
            auto verification=ProjectStore::verify_backup(entry.path(),remaining_steps,remaining_bytes,stop);
            if(!verification){listing.complete=false;continue;}
            verified_history_steps+=static_cast<std::size_t>(verification.value().history_steps_verified);
            verified_history_bytes+=static_cast<std::size_t>(verification.value().history_bytes_verified);
            if(verification.value().backup.uuid!=state->uuid||!verification.value().history_complete){
                listing.complete=false;
                if(!verification.value().history_complete)break;
                continue;
            }
            std::uint64_t timestamp=0;for(auto c:stamp)timestamp=timestamp*10+static_cast<unsigned>(c-'0');
            listing.backups.push_back({SavedProject{entry.path(),state->uuid},timestamp});
        }
        std::sort(listing.backups.begin(),listing.backups.end(),[](const auto& a,const auto& b){return a.created_unix_ms>b.created_unix_ms;});
        return listing;
    });
}

Result<BackupPruneResult> ProjectStore::prune_rotated_backups(const std::filesystem::path& base,std::size_t retain,std::stop_token stop) {
    return detail::guarded([&]()->Result<BackupPruneResult>{
        if(retain==0||retain>32)return Error{ErrorCode::invalid_argument,"Backup retention must be 1 through 32"};
        auto listing=detail::take(list_rotated_backups(base,stop));
        BackupPruneResult result;result.remaining=listing.backups.size();result.retention_satisfied=listing.complete;
        if(!listing.complete)return result; // Never delete from a partial view.
        for(std::size_t i=retain;i<listing.backups.size();++i){
            if(stop.stop_requested()){result.retention_satisfied=false;break;}
            std::error_code ec;
            if(std::filesystem::remove(listing.backups[i].backup.path,ec)){++result.removed;--result.remaining;}
            else result.retention_satisfied=false;
        }
        if(result.remaining>retain)result.retention_satisfied=false;
        return result;
    });
}

Result<SavedProject> ProjectStore::restore_backup_in_place(const std::filesystem::path& backup,
        const std::filesystem::path& target,std::stop_token stop){
    return detail::guarded([&]()->Result<SavedProject>{
        if(backup.empty()||target.empty())return Error{ErrorCode::invalid_argument,"Backup and in-place restore target paths are required"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"In-place project restore canceled"};
        const auto source_path=std::filesystem::absolute(backup).lexically_normal();
        const auto target_path=std::filesystem::absolute(target).lexically_normal();
        if(detail::same_file(source_path,target_path))return Error{ErrorCode::invalid_argument,"In-place restore target aliases its backup"};
        auto source=detail::take(ProjectStore::open(source_path,ProjectMode::read_only,stop));
        auto source_state=detail::take(source->snapshot());
        auto target_probe=detail::take(ProjectStore::open(target_path,ProjectMode::read_only,stop));
        const auto target_state=detail::take(target_probe->snapshot());
        if(source_state->uuid!=target_state->uuid)
            return Error{ErrorCode::conflict,"In-place restore requires a backup of the target project's UUID"};
        auto lease=detail::take(ProjectLease::acquire(target_state->uuid));
        target_probe.reset();
        // Re-read after acquiring the ordinary project lease. This detects a
        // writer that committed while the initial validation was in progress.
        auto target_locked=detail::take(ProjectStore::open(target_path,ProjectMode::read_only,stop));
        const auto locked_state=detail::take(target_locked->snapshot());
        if(locked_state->uuid!=target_state->uuid||locked_state->revisions!=target_state->revisions||
           locked_state->history_cursor!=target_state->history_cursor)
            return Error{ErrorCode::conflict,"Target project changed while acquiring the restore lease"};

        std::vector<std::filesystem::path> protected_paths{source_path};
        const auto add_provenance=[&](const ProjectState& state,const std::filesystem::path& project){
            if(!state.provenance)return;
            const auto& provenance=*state.provenance;
            if(provenance.native_path.is_absolute())protected_paths.push_back(provenance.native_path);
            if(!provenance.relative_path.empty()){
                auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));
                protected_paths.push_back((project.parent_path()/relative).lexically_normal());
            }
        };
        add_provenance(*source_state,source_path);add_provenance(*target_state,target_path);
        auto protected_files=detail::protect_files(target_path,protected_paths);
        auto temporary=detail::reserve_owned_file(target_path.parent_path(),L".hexlab-restore-",true);
        auto output=detail::take(Connection::open(temporary->path,OpenMode::create,stop));
        detail::Cancellation cancellation(*source->impl_->connection,stop);
        detail::take(source->impl_->connection->backup_to(*output,stop));
        const auto version=detail::schema_version(*output);
        detail::validate_schema(*output,version);
        auto copied=detail::read_state(*output,version);
        detail::require(copied->uuid==source_state->uuid&&copied->uuid==target_state->uuid,
                        "Restored copy changed the logical project identity");
        {
            auto transaction=detail::take(Transaction::begin(*output));
            if(copied->provenance){
                const auto& provenance=*copied->provenance;
                std::filesystem::path original;
                if(!provenance.relative_path.empty()){
                    auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));
                    original=(source_path.parent_path()/relative).lexically_normal();
                }else if(provenance.native_path.is_absolute())original=provenance.native_path;
                if(!original.empty()){
                    auto relative=original.lexically_relative(target_path.parent_path());if(relative.empty())relative=original;
                    auto encoded=relative.generic_u8string();detail::require(encoded.size()<=131072,"Restored provenance path exceeds its budget");
                    auto update=detail::take(output->prepare("UPDATE input_provenance SET relative_path=?1 WHERE singleton=1"));
                    detail::take(update->bind_text(1,std::string_view(reinterpret_cast<const char*>(encoded.data()),encoded.size())));
                    detail::take(update->step());
                }
            }
            detail::take(transaction->commit());
        }
        detail::validate_schema(*output,detail::schema_version(*output));
        const auto restored_state=detail::read_state(*output);
        {auto original=detail::extract_input(*output,*restored_state,stop);}
        detail::take(output->checkpoint());output.reset();
        target_locked.reset();
        if(stop.stop_requested())return Error{ErrorCode::canceled,"In-place project restore canceled before publication"};
        detail::publish_file(*temporary,target_path,ReplacePolicy::replace_existing);
        return SavedProject{target_path,source_state->uuid};
    });
}
}
