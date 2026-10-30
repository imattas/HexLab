#include "native_files.hpp"
#include "history_internal.hpp"
#include "testing.hpp"
#include "hexlab/core/sha256.hpp"
#include "hexlab/image/file_storage.hpp"
#include "hexlab/image/file_publication.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <fstream>
#include <string>
#if defined(__linux__)
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <stdio.h>
#endif
namespace hexlab::database {
namespace {
constexpr std::uint64_t project_bundle_byte_limit=UINT64_C(8)*1024*1024*1024;
void require_history_verified(const std::filesystem::path& path,std::stop_token stop){
    constexpr std::size_t history_steps=65536;
    constexpr std::size_t history_bytes=512u*1024u*1024u;
    auto verification=detail::take(ProjectStore::verify_backup(path,history_steps,history_bytes,stop));
    detail::require(verification.history_complete,
                    "History exceeds the complete backup-verification budget");
}
std::filesystem::path external_source_path(const ProjectState& state,const std::filesystem::path& project){
    if(!state.provenance)return {};
    const auto& provenance=*state.provenance;
    if(!provenance.relative_path.empty()){
        auto relative=std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(provenance.relative_path.data()),provenance.relative_path.size()));
        return (project.parent_path()/relative).lexically_normal();
    }
    return provenance.native_path.is_absolute()?provenance.native_path:std::filesystem::path{};
}
void verify_external_source(const ProjectState& state,const std::filesystem::path& project,std::stop_token stop){
    const auto source_path=external_source_path(state,project);
    if(source_path.empty())throw detail::Failure{{ErrorCode::invalid_argument,"Project has no external source path to verify"}};
    auto source=detail::take(FileStorage::open(source_path));
    if(source->size()!=state.input.size)throw detail::Failure{{ErrorCode::conflict,"External source file size differs from embedded project input"}};
    Sha256 hash;
    for(std::uint64_t position=0;position<state.input.size;){
        if(stop.stop_requested())throw detail::Failure{{ErrorCode::canceled,"External source verification canceled"}};
        const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>(1024u*1024u,state.input.size-position));
        auto view=detail::take(source->read_at({position},amount));
        if(view.bytes.size()!=amount)throw detail::Failure{{ErrorCode::io,"External source returned an incomplete verification read"}};
        detail::take(hash.update(view.bytes));
        position+=amount;
    }
    if(hash.digest()!=state.input.sha256)
        throw detail::Failure{{ErrorCode::conflict,"External source file SHA-256 differs from embedded project input"}};
}
std::filesystem::path unique_bundle_stage(const std::filesystem::path& target){
    static std::atomic_uint64_t sequence{0};
    for(unsigned attempt=0;attempt<64;++attempt){
        const auto uuid=detail::new_uuid();
        constexpr char digits[]="0123456789abcdef";
        std::string suffix=".hexlab-bundle-";
        for(const auto byte:uuid){const auto value=std::to_integer<unsigned char>(byte);suffix.push_back(digits[value>>4]);suffix.push_back(digits[value&15]);}
        suffix+="-"+std::to_string(sequence.fetch_add(1,std::memory_order_relaxed));
        auto stage=target.parent_path()/(target.filename().native()+std::filesystem::path(suffix).native());
        std::error_code ec;
        if(std::filesystem::create_directory(stage,ec))return stage;
        if(ec && ec!=std::errc::file_exists)throw detail::Failure{{ErrorCode::io,"Cannot create backup bundle staging directory: "+ec.message()}};
    }
    throw detail::Failure{{ErrorCode::busy,"Cannot reserve a unique backup bundle staging directory"}};
}
struct BundleStage {
    std::filesystem::path path;
    bool published=false;
    ~BundleStage(){if(!published&&!path.empty()){std::error_code ec;std::filesystem::remove_all(path,ec);}}
};
void publish_bundle_directory(const std::filesystem::path& stage,const std::filesystem::path& target){
    // A check followed by filesystem::rename can replace a directory that
    // appears between the two operations on POSIX. Require native no-replace.
#ifdef _WIN32
    if(!MoveFileExW(stage.c_str(),target.c_str(),MOVEFILE_WRITE_THROUGH))
        throw detail::Failure{detail::native_error("Cannot publish backup bundle directory")};
#elif defined(__linux__) && defined(SYS_renameat2)
    constexpr unsigned no_replace=1;
    if(syscall(SYS_renameat2,AT_FDCWD,stage.c_str(),AT_FDCWD,target.c_str(),no_replace)!=0)
        throw detail::Failure{detail::native_error("Cannot publish backup bundle directory without replacement")};
#elif defined(__APPLE__)
    if(renamex_np(stage.c_str(),target.c_str(),RENAME_EXCL)!=0)
        throw detail::Failure{detail::native_error("Cannot publish backup bundle directory without replacement")};
#else
    throw detail::Failure{{ErrorCode::unsupported,"Atomic no-replace directory publication is unavailable on this platform"}};
#endif
}
void require_bundle_without_journals(const std::filesystem::path& project){
    for(const auto suffix:{"-wal","-shm","-journal"}){
        auto companion=project;companion+=suffix;
        std::error_code ec;
        const auto status=std::filesystem::symlink_status(companion,ec);
        if(ec&&ec!=std::errc::no_such_file_or_directory)
            throw detail::Failure{{ErrorCode::io,"Cannot inspect backup bundle journal companions"}};
        if(std::filesystem::exists(status))
            throw detail::Failure{{ErrorCode::busy,"Backup bundle project has journal companions; close and checkpoint it before restore"}};
    }
}
void write_bundle_source_relative(const std::filesystem::path& project,std::stop_token stop){
    auto connection=detail::take(Connection::open(project,OpenMode::read_write,stop));
    auto transaction=detail::take(Transaction::begin(*connection));
    {
        auto provenance=detail::take(connection->prepare("SELECT singleton FROM input_provenance WHERE singleton=1"));
        detail::require(detail::take(provenance->step()),"Backup bundle project has no source provenance");
    }
    auto update=detail::take(connection->prepare("UPDATE input_provenance SET relative_path=?1 WHERE singleton=1"));
    detail::take(update->bind_text(1,"source.bin"));
    detail::take(update->step());
    detail::take(transaction->commit());
    update.reset();
    transaction.reset();
    detail::take(connection->checkpoint());
}
void finalize_bundle_project(const std::filesystem::path& project,std::stop_token stop){
    // Read-only validation of a WAL-mode database can create empty journal
    // companions. Publish a DELETE-mode main file so the bundle remains
    // self-contained even when opened later from read-only media.
    {
        auto connection=detail::take(Connection::open(project,OpenMode::read_write,stop));
        detail::take(connection->checkpoint());
        auto journal=detail::take(connection->prepare("PRAGMA journal_mode=DELETE"));
        detail::require(detail::take(journal->step()),"Bundle project did not report a journal mode");
        detail::require(detail::take(journal->text(0))=="delete","Cannot finalize self-contained bundle project");
    }
    require_bundle_without_journals(project);
}
void copy_bundle_file(const std::filesystem::path& source,const std::filesystem::path& destination,
                      std::uint64_t max_bytes,std::stop_token stop){
    std::error_code ec;
    const auto status=std::filesystem::symlink_status(source,ec);
    if(ec||!std::filesystem::is_regular_file(status)||std::filesystem::is_symlink(status))
        throw detail::Failure{{ErrorCode::invalid_argument,"Backup bundle member must be a regular non-symlink file"}};
    const auto size=std::filesystem::file_size(source,ec);
    if(ec)throw detail::Failure{{ErrorCode::io,"Cannot inspect backup bundle member size"}};
    if(size>max_bytes)throw detail::Failure{{ErrorCode::resource_limit,"Backup bundle member exceeds its restore budget"}};
    std::ifstream input(source,std::ios::binary);
    std::ofstream output(destination,std::ios::binary|std::ios::trunc);
    if(!input||!output)throw detail::Failure{{ErrorCode::io,"Cannot open backup bundle member for restore"}};
    std::vector<char> buffer(1024*1024);
    std::uint64_t remaining=size;
    while(remaining){
        if(stop.stop_requested())throw detail::Failure{{ErrorCode::canceled,"Backup bundle restore canceled"}};
        const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>(remaining,buffer.size()));
        input.read(buffer.data(),static_cast<std::streamsize>(amount));
        if(input.gcount()!=static_cast<std::streamsize>(amount)||input.bad())
            throw detail::Failure{{ErrorCode::io,"Backup bundle member returned an incomplete read"}};
        output.write(buffer.data(),static_cast<std::streamsize>(amount));
        if(!output)throw detail::Failure{{ErrorCode::io,"Cannot write staged backup bundle member"}};
        remaining-=amount;
    }
    output.flush();
    if(!output)throw detail::Failure{{ErrorCode::io,"Cannot flush staged backup bundle member"}};
    output.close();
    if(!output)throw detail::Failure{{ErrorCode::io,"Cannot close staged backup bundle member"}};
    const auto final_size=std::filesystem::file_size(source,ec);
    if(ec||final_size!=size)throw detail::Failure{{ErrorCode::conflict,"Backup bundle member changed during restore"}};
}
}
Result<SavedProject> ProjectStore::save_as(const std::filesystem::path& destination,ReplacePolicy policy,std::stop_token stop){
    return save_as_impl(destination,policy,stop,{});
}
Result<SavedProject> ProjectStore::save_history_as(uint64_t expected,uint64_t target,HistoryPreviewLimits limits,const std::filesystem::path& destination,ReplacePolicy policy,std::stop_token stop){
    if(limits.max_steps>history_preview_step_limit || limits.max_delta_bytes>history_preview_payload_limit)
        return Error{ErrorCode::invalid_argument,"History save limits exceed 4096 steps or 64 MiB of delta payload"};
    return save_as_impl(destination,policy,stop,HistorySaveRequest{expected,target,limits});
}
Result<SavedProject> ProjectStore::save_as_impl(const std::filesystem::path& destination,ReplacePolicy policy,std::stop_token stop,std::optional<HistorySaveRequest> history,bool verify_history){
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
                    if(copied_version<current_project_schema_version)detail::migrate_schema(*output);
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
        if(verify_history)require_history_verified(temporary->path,stop);
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
        BackupVerification result{{std::filesystem::absolute(path).lexically_normal(),state->uuid},state->input,
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
    return backup_to(destination,policy,stop,ProjectBackupOptions{});
}
Result<SavedProject> ProjectStore::backup_to(const std::filesystem::path& destination,ReplacePolicy policy,
        std::stop_token stop,ProjectBackupOptions options){
    return detail::guarded([&]()->Result<SavedProject>{
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project backup canceled"};
        if(destination.empty() || destination.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos ||
           (policy!=ReplacePolicy::fail_if_exists && policy!=ReplacePolicy::replace_existing) ||
           (options.external_source!=ExternalSourcePolicy::preserve_provenance &&
            options.external_source!=ExternalSourcePolicy::require_matching_input))
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
        if(options.external_source==ExternalSourcePolicy::require_matching_input)
            verify_external_source(*copied,impl_->path,stop);
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
        require_history_verified(temporary->path,stop);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project backup canceled before publication"};
        SavedProject saved{target,copied->uuid};
        detail::publish_file(*temporary,target,policy);
        return saved;
    });
}

Result<ProjectBackupBundle> ProjectStore::backup_bundle_to(
        const std::filesystem::path& destination,SourceArchiveOptions source_options,std::stop_token stop){
    return detail::guarded([&]()->Result<ProjectBackupBundle>{
        if(destination.empty()||destination.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos||
           source_options.max_bytes==0||source_options.max_bytes>source_archive_byte_limit)
            return Error{ErrorCode::invalid_argument,"Backup bundle requires a directory and a source byte budget from 1 byte through 1 GiB"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Backup bundle canceled"};
        const auto target=std::filesystem::absolute(destination).lexically_normal();
        if(target.filename().empty()||!std::filesystem::is_directory(target.parent_path()))
            return Error{ErrorCode::invalid_argument,"Backup bundle parent directory must already exist"};
        std::error_code ec;
        if(std::filesystem::exists(target,ec)||ec)
            return ec?Error{ErrorCode::io,"Cannot inspect backup bundle destination"}:
                      Error{ErrorCode::conflict,"Backup bundle destination already exists"};
        BundleStage stage{unique_bundle_stage(target)};
        const auto project_path=stage.path/"project.hxproj";
        const auto source_path=stage.path/"source.bin";
        const auto current=detail::take(snapshot());
        if(current->input.size>source_options.max_bytes)
            return Error{ErrorCode::resource_limit,"Project input exceeds the source archive byte budget"};
        ProjectBackupOptions backup_options;
        auto saved=detail::take(backup_to(project_path,ReplacePolicy::fail_if_exists,stop,backup_options));
        const auto project_size=std::filesystem::file_size(project_path,ec);
        if(ec)return Error{ErrorCode::io,"Cannot inspect staged project backup size"};
        if(project_size>project_bundle_byte_limit)
            return Error{ErrorCode::resource_limit,"Project backup exceeds the 8 GiB bundle member limit"};
        // Archive using provenance from the saved snapshot, so concurrent
        // source-store edits cannot select a different input/provenance pair.
        auto archive_store=detail::take(ProjectStore::open(project_path,ProjectMode::read_only,stop));
        auto archived=detail::take(archive_store->archive_external_source(source_path,source_options,stop));
        archive_store.reset();
        if(saved.uuid!=archived.uuid)
            return Error{ErrorCode::conflict,"Project identity changed between bundle backup and source archival"};
        write_bundle_source_relative(project_path,stop);
        auto verification=detail::take(ProjectStore::verify_backup(project_path,65536,512u*1024u*1024u,stop));
        if(!verification.history_complete||verification.backup.uuid!=saved.uuid||verification.input!=archived.input)
            return Error{ErrorCode::conflict,"Project backup and source archive do not describe the same complete input snapshot"};
        auto staged_store=detail::take(ProjectStore::open(project_path,ProjectMode::read_only,stop));
        auto source_verification=detail::take(staged_store->verify_source_archive(source_path,source_options.max_bytes,stop));
        if(source_verification.project_uuid!=saved.uuid||source_verification.input!=verification.input)
            return Error{ErrorCode::conflict,"Staged source archive does not match the project backup"};
        staged_store.reset();
        finalize_bundle_project(project_path,stop);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Backup bundle canceled before publication"};
        publish_bundle_directory(stage.path,target);
        stage.published=true;
        saved.path=target/"project.hxproj";
        archived.path=target/"source.bin";
        return ProjectBackupBundle{target,std::move(saved),std::move(archived)};
    });
}

Result<ProjectBackupBundleRestore> ProjectStore::restore_bundle_to(
        const std::filesystem::path& bundle,const std::filesystem::path& destination,
        std::uint64_t max_source_bytes,std::stop_token stop){
    return detail::guarded([&]()->Result<ProjectBackupBundleRestore>{
        if(bundle.empty()||destination.empty()||
           bundle.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos||
           destination.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos||
           max_source_bytes==0||max_source_bytes>source_archive_byte_limit)
            return Error{ErrorCode::invalid_argument,"Bundle restore requires bundle/output directories and a source byte budget from 1 byte through 1 GiB"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Backup bundle restore canceled"};
        const auto source_dir=std::filesystem::absolute(bundle).lexically_normal();
        const auto target=std::filesystem::absolute(destination).lexically_normal();
        std::error_code ec;
        const auto bundle_status=std::filesystem::symlink_status(source_dir,ec);
        if(ec||std::filesystem::is_symlink(bundle_status)||!std::filesystem::is_directory(bundle_status))
            return Error{ErrorCode::invalid_argument,"Backup bundle must be an existing non-symlink directory"};
        if(target.filename().empty()||!std::filesystem::is_directory(target.parent_path()))
            return Error{ErrorCode::invalid_argument,"Bundle restore parent directory must already exist"};
        if(std::filesystem::exists(target,ec)||ec)
            return ec?Error{ErrorCode::io,"Cannot inspect bundle restore destination"}:
                      Error{ErrorCode::conflict,"Bundle restore destination already exists"};
        const auto project_source=source_dir/"project.hxproj";
        const auto archive_source=source_dir/"source.bin";
        for(const auto& member:{project_source,archive_source}){
            const auto member_status=std::filesystem::symlink_status(member,ec);
            if(ec||std::filesystem::is_symlink(member_status)||!std::filesystem::is_regular_file(member_status))
                return Error{ErrorCode::invalid_argument,"Backup bundle members must be regular non-symlink files"};
        }
        const auto project_size=std::filesystem::file_size(project_source,ec);
        if(ec)return Error{ErrorCode::io,"Cannot inspect backup bundle project size"};
        if(project_size>project_bundle_byte_limit)
            return Error{ErrorCode::resource_limit,"Backup bundle project exceeds the 8 GiB restore limit"};
        const auto archive_size=std::filesystem::file_size(archive_source,ec);
        if(ec)return Error{ErrorCode::io,"Cannot inspect backup bundle source size"};
        if(archive_size>max_source_bytes)
            return Error{ErrorCode::resource_limit,"Backup bundle source exceeds the restore byte budget"};
        // Never open the source SQLite file: a portable bundle must be
        // self-contained, without committed state hidden in a neighboring WAL.
        require_bundle_without_journals(project_source);
        BundleStage stage{unique_bundle_stage(target)};
        const auto project_target=stage.path/"project.hxproj";
        const auto archive_target=stage.path/"source.bin";
        copy_bundle_file(project_source,project_target,project_bundle_byte_limit,stop);
        copy_bundle_file(archive_source,archive_target,max_source_bytes,stop);
        require_bundle_without_journals(project_source);
        auto copied_verification=detail::take(ProjectStore::verify_backup(project_target,65536,512u*1024u*1024u,stop));
        if(!copied_verification.history_complete)
            return Error{ErrorCode::resource_limit,"Backup bundle history exceeds the complete verification budget"};
        auto copied_store=detail::take(ProjectStore::open(project_target,ProjectMode::read_only,stop));
        auto copied_source=detail::take(copied_store->verify_source_archive(archive_target,max_source_bytes,stop));
        if(copied_source.project_uuid!=copied_verification.backup.uuid||copied_source.input!=copied_verification.input)
            return Error{ErrorCode::conflict,"Staged bundle source changed or failed validation"};
        copied_store.reset();
        write_bundle_source_relative(project_target,stop);
        finalize_bundle_project(project_target,stop);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Backup bundle restore canceled before publication"};
        publish_bundle_directory(stage.path,target);
        stage.published=true;
        const SavedProject project{target/"project.hxproj",copied_verification.backup.uuid};
        const SourceArchiveRestore source{source_dir/"source.bin",target/"source.bin",project.uuid,copied_verification.input};
        return ProjectBackupBundleRestore{target,project,source};
    });
}

Result<SourceArchiveResult> ProjectStore::archive_external_source(const std::filesystem::path& destination,
        SourceArchiveOptions options,std::stop_token stop){
    return detail::guarded([&]()->Result<SourceArchiveResult>{
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Source archive canceled"};
        if(destination.empty() ||
           destination.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos ||
           options.max_bytes==0 || options.max_bytes>source_archive_byte_limit)
            return Error{ErrorCode::invalid_argument,"Source archive requires a destination and a byte budget from 1 byte through 1 GiB"};
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=detail::take(Transaction::begin_read(*impl_->connection));
        const auto version=detail::schema_version(*impl_->connection);
        auto state=detail::read_state(*impl_->connection,version);
        if(state->uuid!=impl_->state->uuid || state->input!=impl_->state->input)
            return Error{ErrorCode::conflict,"Project identity changed; reopen before archiving its external source"};
        if(state->input.size>options.max_bytes)
            return Error{ErrorCode::resource_limit,"External source exceeds the source-archive byte budget"};
        const auto source_path=external_source_path(*state,impl_->path);
        if(source_path.empty())return Error{ErrorCode::invalid_argument,"Project has no external source path to archive"};
        const auto target=std::filesystem::absolute(destination).lexically_normal();
        if(!std::filesystem::is_regular_file(source_path))
            return Error{ErrorCode::invalid_argument,"External source archive requires a regular file"};
        if(std::filesystem::file_size(source_path)!=state->input.size)
            return Error{ErrorCode::conflict,"External source file size differs from embedded project input"};
        // Stream into owned chunks instead of mapping the external file: a
        // concurrent POSIX truncation must produce a read failure, not SIGBUS.
        std::ifstream source(source_path,std::ios::binary);
        if(!source)return Error{ErrorCode::io,"Cannot open external source for archival"};
        std::vector<std::filesystem::path> protected_paths{impl_->path,source_path};
        for(auto suffix:{L"-wal",L"-shm",L"-journal"}){
            auto companion=impl_->path;companion+=suffix;protected_paths.push_back(std::move(companion));
        }
        if(state->provenance && state->provenance->native_path.is_absolute())
            protected_paths.push_back(state->provenance->native_path);
        if(auto original=std::dynamic_pointer_cast<const FileStorage>(impl_->original))
            protected_paths.push_back(original->backing_path());
        // FilePublication rejects existing output, aliases, and WAL/SHM peers.
        // Also guard orphan rollback journals, even though this is a raw copy.
        auto journal=target;journal+=L"-journal";
        if(std::filesystem::exists(journal))
            return Error{ErrorCode::busy,"Source archive destination has an unrecovered rollback journal"};
        auto publication=detail::take(FilePublication::create(target,ExistingFilePolicy::reject,protected_paths,stop));
        Sha256 hash;
        std::vector<std::byte> buffer(static_cast<std::size_t>(std::min<std::uint64_t>(1024u*1024u,state->input.size)));
        for(std::uint64_t position=0;position<state->input.size;){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Source archive canceled before publication"};
            const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>(1024u*1024u,state->input.size-position));
            source.read(reinterpret_cast<char*>(buffer.data()),static_cast<std::streamsize>(amount));
            if(source.gcount()!=static_cast<std::streamsize>(amount) || source.bad())
                return Error{ErrorCode::io,"External source returned an incomplete archive read"};
            // Hash and publish the same owned bytes even if the external
            // source is concurrently writable on this operating system.
            const auto chunk=std::span<const std::byte>(buffer.data(),amount);
            detail::take(hash.update(chunk));
            detail::take(publication->append(chunk));
            position+=amount;
        }
        if(hash.digest()!=state->input.sha256)
            return Error{ErrorCode::conflict,"External source file SHA-256 differs from embedded project input"};
        // This detects growth/truncation visible at the provenance path; the
        // digest above always establishes the identity of the copied bytes.
        if(std::filesystem::file_size(source_path)!=state->input.size)
            return Error{ErrorCode::conflict,"External source size changed during archival"};
        detail::take(transaction->commit());
        if(std::filesystem::exists(journal))
            return Error{ErrorCode::busy,"Source archive destination acquired a rollback journal"};
        SourceArchiveResult result{target,source_path,state->uuid,state->input};
        detail::take(publication->publish());
        return result;
    });
}

Result<SourceArchiveVerification> ProjectStore::verify_source_archive(
        const std::filesystem::path& archive,std::uint64_t max_bytes,std::stop_token stop) const {
    return detail::guarded([&]()->Result<SourceArchiveVerification>{
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Source archive verification canceled"};
        if(archive.empty() || archive.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos ||
           max_bytes==0 || max_bytes>source_archive_byte_limit)
            return Error{ErrorCode::invalid_argument,"Source archive verification requires a path and a byte budget from 1 byte through 1 GiB"};
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=detail::take(Transaction::begin_read(*impl_->connection));
        const auto version=detail::schema_version(*impl_->connection);
        auto state=detail::read_state(*impl_->connection,version);
        if(state->uuid!=impl_->state->uuid || state->input!=impl_->state->input)
            return Error{ErrorCode::conflict,"Project identity changed; reopen before verifying its source archive"};
        if(state->input.size>max_bytes)
            return Error{ErrorCode::resource_limit,"Embedded project input exceeds the source-archive verification budget"};
        const auto path=std::filesystem::absolute(archive).lexically_normal();
        std::error_code error;
        const auto status=std::filesystem::symlink_status(path,error);
        if(error || !std::filesystem::is_regular_file(status))
            return Error{ErrorCode::invalid_argument,"Source archive must be an existing regular file"};
        if(std::filesystem::file_size(path,error)!=state->input.size || error)
            return Error{ErrorCode::conflict,"Source archive size differs from embedded project input"};
        std::ifstream input(path,std::ios::binary);
        if(!input)return Error{ErrorCode::io,"Cannot open source archive for verification"};
        Sha256 hash;
        std::vector<std::byte> buffer(static_cast<std::size_t>(std::min<std::uint64_t>(1024u*1024u,state->input.size)));
        for(std::uint64_t position=0;position<state->input.size;){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Source archive verification canceled"};
            const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>(1024u*1024u,state->input.size-position));
            input.read(reinterpret_cast<char*>(buffer.data()),static_cast<std::streamsize>(amount));
            if(input.gcount()!=static_cast<std::streamsize>(amount) || input.bad())
                return Error{ErrorCode::io,"Source archive returned an incomplete verification read"};
            detail::take(hash.update(std::span<const std::byte>(buffer.data(),amount)));
            position+=amount;
        }
        if(hash.digest()!=state->input.sha256)
            return Error{ErrorCode::conflict,"Source archive SHA-256 differs from embedded project input"};
        if(std::filesystem::file_size(path,error)!=state->input.size || error)
            return Error{ErrorCode::conflict,"Source archive size changed during verification"};
        detail::take(transaction->commit());
        return SourceArchiveVerification{path,state->uuid,state->input,state->input.size};
    });
}

Result<SourceArchiveRestore> ProjectStore::restore_source_archive(
        const std::filesystem::path& archive,const std::filesystem::path& destination,
        std::uint64_t max_bytes,std::stop_token stop) {
    return detail::guarded([&]()->Result<SourceArchiveRestore>{
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Source archive restore canceled"};
        if(archive.empty() || destination.empty() ||
           archive.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos ||
           destination.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos ||
           max_bytes==0 || max_bytes>source_archive_byte_limit)
            return Error{ErrorCode::invalid_argument,"Source archive restore requires archive/output paths and a byte budget from 1 byte through 1 GiB"};
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=detail::take(Transaction::begin_read(*impl_->connection));
        const auto version=detail::schema_version(*impl_->connection);
        auto state=detail::read_state(*impl_->connection,version);
        if(state->uuid!=impl_->state->uuid || state->input!=impl_->state->input)
            return Error{ErrorCode::conflict,"Project identity changed; reopen before restoring its source archive"};
        if(state->input.size>max_bytes)
            return Error{ErrorCode::resource_limit,"Embedded project input exceeds the source-archive restore budget"};
        const auto source=std::filesystem::absolute(archive).lexically_normal();
        const auto target=std::filesystem::absolute(destination).lexically_normal();
        std::error_code error;
        const auto status=std::filesystem::symlink_status(source,error);
        if(error || !std::filesystem::is_regular_file(status))
            return Error{ErrorCode::invalid_argument,"Source archive must be an existing regular file"};
        if(std::filesystem::file_size(source,error)!=state->input.size || error)
            return Error{ErrorCode::conflict,"Source archive size differs from embedded project input"};
        auto journal=target;journal+=L"-journal";
        if(std::filesystem::exists(journal))
            return Error{ErrorCode::busy,"Source restore destination has an unrecovered rollback journal"};
        std::vector<std::filesystem::path> protected_paths{impl_->path,source,archive};
        for(auto suffix:{L"-wal",L"-shm",L"-journal"}){
            auto companion=impl_->path;companion+=suffix;protected_paths.push_back(std::move(companion));
        }
        if(state->provenance && state->provenance->native_path.is_absolute())
            protected_paths.push_back(state->provenance->native_path);
        if(auto original=std::dynamic_pointer_cast<const FileStorage>(impl_->original))
            protected_paths.push_back(original->backing_path());
        std::ifstream input(source,std::ios::binary);
        if(!input)return Error{ErrorCode::io,"Cannot open source archive for restore"};
        auto publication=detail::take(FilePublication::create(target,ExistingFilePolicy::reject,protected_paths,stop));
        Sha256 hash;
        std::vector<std::byte> buffer(static_cast<std::size_t>(std::min<std::uint64_t>(1024u*1024u,state->input.size)));
        for(std::uint64_t position=0;position<state->input.size;){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Source archive restore canceled before publication"};
            const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>(1024u*1024u,state->input.size-position));
            input.read(reinterpret_cast<char*>(buffer.data()),static_cast<std::streamsize>(amount));
            if(input.gcount()!=static_cast<std::streamsize>(amount) || input.bad())
                return Error{ErrorCode::io,"Source archive returned an incomplete restore read"};
            const auto chunk=std::span<const std::byte>(buffer.data(),amount);
            detail::take(hash.update(chunk));
            detail::take(publication->append(chunk));
            position+=amount;
        }
        if(hash.digest()!=state->input.sha256)
            return Error{ErrorCode::conflict,"Source archive SHA-256 differs from embedded project input"};
        if(std::filesystem::file_size(source,error)!=state->input.size || error)
            return Error{ErrorCode::conflict,"Source archive size changed during restore"};
        detail::take(transaction->commit());
        if(std::filesystem::exists(journal))
            return Error{ErrorCode::busy,"Source restore destination acquired a rollback journal"};
        detail::take(publication->publish());
        return SourceArchiveRestore{source,target,state->uuid,state->input};
    });
}

Result<SourceArchiveRotationResult> ProjectStore::archive_external_source_rotating(
        const std::filesystem::path& base,std::size_t retain,SourceArchiveOptions options,
        std::stop_token stop){
    return detail::guarded([&]()->Result<SourceArchiveRotationResult>{
        if(base.empty()||retain==0||retain>32)
            return Error{ErrorCode::invalid_argument,"Source archive rotation requires a base path and retention from 1 through 32"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Source archive rotation canceled"};
        const auto normalized=std::filesystem::absolute(base).lexically_normal();
        if(!std::filesystem::is_directory(normalized.parent_path()))
            return Error{ErrorCode::invalid_argument,"Source archive rotation directory does not exist"};
        if(detail::same_file(impl_->path,normalized))
            return Error{ErrorCode::invalid_argument,"Source archive rotation base aliases the open project"};
        std::uint64_t prior_timestamp=0;
        const auto prior=list_rotated_source_archives(normalized,options.max_bytes,stop);
        if(prior&&prior.value().complete&&!prior.value().archives.empty())
            prior_timestamp=prior.value().archives.front().created_unix_ms;
        const auto clock_millis=std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if(clock_millis<0)return Error{ErrorCode::io,"System clock is before the Unix epoch"};
        const auto millis=std::max<std::uint64_t>(static_cast<std::uint64_t>(clock_millis),prior_timestamp+1);
        const auto token=detail::new_uuid();
        constexpr char digits[]="0123456789abcdef";
        auto name=normalized.stem().native();
        const auto append_ascii=[&](std::string_view value){
            for(const auto ch:value)name.push_back(static_cast<std::filesystem::path::value_type>(ch));
        };
        append_ascii(".source-archive-");
        auto timestamp=std::to_string(millis);
        if(timestamp.size()>13)return Error{ErrorCode::resource_limit,"Source archive timestamp exceeds the fixed generation-name width"};
        if(timestamp.size()<13)timestamp.insert(0,13-timestamp.size(),'0');
        append_ascii(timestamp);append_ascii("-");
        for(const auto byte:token){const auto value=std::to_integer<unsigned>(byte);name.push_back(static_cast<std::filesystem::path::value_type>(digits[value>>4]));name.push_back(static_cast<std::filesystem::path::value_type>(digits[value&15]));}
        name+=normalized.extension().native();
        const auto latest=normalized.parent_path()/std::filesystem::path(name);
        auto archived=detail::take(archive_external_source(latest,options,stop));
        SourceArchiveRotationResult result{std::move(archived),0,true};
        auto listing=list_rotated_source_archives(normalized,options.max_bytes,stop);
        if(!listing||!listing.value().complete){result.retention_satisfied=false;return result;}
        const auto newest=std::find_if(listing.value().archives.begin(),listing.value().archives.end(),[&](const auto& row){
            return detail::same_file(row.archive.path,latest);
        });
        if(newest==listing.value().archives.end()){result.retention_satisfied=false;return result;}
        // The listing is newest-first by timestamp. Keep the just-created
        // generation first even when the wall clock ties an earlier archive.
        const auto prune=detail::take(prune_rotated_source_archives(normalized,retain,options.max_bytes,stop));
        result.removed_generations=prune.removed;
        result.retention_satisfied=prune.retention_satisfied;
        return result;
    });
}

Result<SourceArchiveListing> ProjectStore::list_rotated_source_archives(
        const std::filesystem::path& base,std::uint64_t max_bytes,std::stop_token stop) const {
    return detail::guarded([&]()->Result<SourceArchiveListing>{
        if(base.empty()||max_bytes==0||max_bytes>source_archive_byte_limit)
            return Error{ErrorCode::invalid_argument,"Source archive listing requires a base path and a byte budget from 1 byte through 1 GiB"};
        const auto normalized=std::filesystem::absolute(base).lexically_normal();
        SourceArchiveListing listing;
        const auto prefix=normalized.stem().native()+std::filesystem::path(".source-archive-").native();
        const auto extension=normalized.extension().native();
        std::error_code ec;
        std::filesystem::directory_iterator it(normalized.parent_path(),ec),end;
        if(ec)return Error{ErrorCode::io,"Cannot scan source-archive directory: "+ec.message()};
        constexpr std::size_t entry_limit=8192,candidate_limit=64;
        constexpr std::uint64_t cumulative_verify_limit=UINT64_C(1024)*1024*1024;
        std::size_t entries=0;std::uint64_t accounted_bytes=0;
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
            const auto size=entry.file_size(ec);if(ec||size>cumulative_verify_limit-accounted_bytes){listing.complete=false;break;}
            accounted_bytes+=size;
            if(listing.archives.size()>=candidate_limit){listing.complete=false;break;}
            if(size>max_bytes){listing.complete=false;continue;}
            auto verification=verify_source_archive(entry.path(),max_bytes,stop);
            if(!verification){listing.complete=false;continue;}
            std::uint64_t timestamp=0;for(const auto c:stamp)timestamp=timestamp*10+static_cast<unsigned>(c-'0');
            listing.archives.push_back({std::move(verification.value()),timestamp});
        }
        std::sort(listing.archives.begin(),listing.archives.end(),[](const auto& a,const auto& b){
            if(a.created_unix_ms!=b.created_unix_ms)return a.created_unix_ms>b.created_unix_ms;
            return a.archive.path.filename().native()>b.archive.path.filename().native();
        });
        return listing;
    });
}

Result<SourceArchivePruneResult> ProjectStore::prune_rotated_source_archives(
        const std::filesystem::path& base,std::size_t retain,std::uint64_t max_bytes,std::stop_token stop){
    return detail::guarded([&]()->Result<SourceArchivePruneResult>{
        if(retain==0||retain>32)return Error{ErrorCode::invalid_argument,"Source archive retention must be 1 through 32"};
        auto listing=detail::take(list_rotated_source_archives(base,max_bytes,stop));
        SourceArchivePruneResult result{listing.archives.size(),0,listing.complete};
        if(!listing.complete)return result;
        for(std::size_t i=retain;i<listing.archives.size();++i){
            if(stop.stop_requested()){result.retention_satisfied=false;break;}
            const auto &candidate=listing.archives[i].archive;
            // Recheck immediately before deletion. If a candidate changed after
            // the listing pass, preserve it and report incomplete retention.
            auto checked=verify_source_archive(candidate.path,max_bytes,stop);
            if(!checked||checked.value().input!=candidate.input||checked.value().project_uuid!=candidate.project_uuid){
                result.retention_satisfied=false;break;
            }
            std::error_code error;
            const auto status=std::filesystem::symlink_status(candidate.path,error);
            if(error||!std::filesystem::is_regular_file(status)||
               std::filesystem::file_size(candidate.path,error)!=candidate.bytes_verified||error){
                result.retention_satisfied=false;break;
            }
            if(std::filesystem::remove(candidate.path,error)){++result.removed;--result.remaining;}
            else {result.retention_satisfied=false;break;}
        }
        if(result.remaining>retain)result.retention_satisfied=false;
        return result;
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
            const auto &candidate=candidates[i];
            const auto identity=detail::hash_recovery_artifact(candidate.backup.path,candidate.artifact_size,stop);
            if(!identity || identity.value().first!=candidate.artifact_size ||
               identity.value().second!=candidate.artifact_sha256){
                result.retention_satisfied=false;return result;
            }
            std::error_code status_error;
            const auto status=std::filesystem::symlink_status(candidate.backup.path,status_error);
            if(status_error || !std::filesystem::is_regular_file(status)){
                result.retention_satisfied=false;return result;
            }
            const auto current_size=std::filesystem::file_size(candidate.backup.path,status_error);
            if(status_error || current_size!=candidate.artifact_size){
                result.retention_satisfied=false;return result;
            }
            std::error_code remove_error;
            if(std::filesystem::remove(candidate.backup.path,remove_error))++result.removed_generations;
            else {result.retention_satisfied=false;return result;}
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
            auto identity_before=detail::hash_recovery_artifact(entry.path(),size,stop);
            if(!identity_before){listing.complete=false;continue;}
            if(identity_before.value().first!=size){listing.complete=false;continue;}
            auto verification=ProjectStore::verify_backup(entry.path(),remaining_steps,remaining_bytes,stop);
            if(!verification){listing.complete=false;continue;}
            auto identity_after=detail::hash_recovery_artifact(entry.path(),size,stop);
            if(!identity_after || identity_before.value()!=identity_after.value()){
                listing.complete=false;continue;
            }
            verified_history_steps+=static_cast<std::size_t>(verification.value().history_steps_verified);
            verified_history_bytes+=static_cast<std::size_t>(verification.value().history_bytes_verified);
            if(verification.value().backup.uuid!=state->uuid||!verification.value().history_complete){
                listing.complete=false;
                if(!verification.value().history_complete)break;
                continue;
            }
            std::uint64_t timestamp=0;for(auto c:stamp)timestamp=timestamp*10+static_cast<unsigned>(c-'0');
            listing.backups.push_back({SavedProject{entry.path(),state->uuid},timestamp,
                                       identity_after.value().first,identity_after.value().second});
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
            const auto &candidate=listing.backups[i];
            const auto identity=detail::hash_recovery_artifact(candidate.backup.path,candidate.artifact_size,stop);
            if(!identity || identity.value().first!=candidate.artifact_size ||
               identity.value().second!=candidate.artifact_sha256){
                result.retention_satisfied=false;break;
            }
            std::error_code ec;
            const auto status=std::filesystem::symlink_status(candidate.backup.path,ec);
            if(ec || !std::filesystem::is_regular_file(status)){
                result.retention_satisfied=false;break;
            }
            const auto current_size=std::filesystem::file_size(candidate.backup.path,ec);
            if(ec || current_size!=candidate.artifact_size){result.retention_satisfied=false;break;}
            if(std::filesystem::remove(candidate.backup.path,ec)){++result.removed;--result.remaining;}
            else {result.retention_satisfied=false;break;}
        }
        if(result.remaining>retain)result.retention_satisfied=false;
        return result;
    });
}

Result<SavedProject> ProjectStore::restore_backup_in_place(const std::filesystem::path& backup,
        const std::filesystem::path& target,std::stop_token stop){
    return restore_backup_in_place_checked(backup,target,nullptr,stop);
}

Result<SavedProject> ProjectStore::recover_candidate_in_place(
        const ProjectRecoveryCandidate& candidate,const std::filesystem::path& target,
        std::stop_token stop){
    if(candidate.kind!=RecoveryArtifactKind::previous_version)
        return Error{ErrorCode::invalid_argument,
                     "In-place recovery accepts only retained previous-version artifacts"};
    const auto filename=candidate.path.filename().u8string();
    if(!filename.starts_with(u8".hexlab-previous-")||!filename.ends_with(u8".tmp"))
        return Error{ErrorCode::invalid_argument,"Recovery artifact name does not match its kind"};
    return restore_backup_in_place_checked(candidate.path,target,&candidate,stop);
}

Result<SavedProject> ProjectStore::restore_backup_in_place_checked(
        const std::filesystem::path& backup,const std::filesystem::path& target,
        const ProjectRecoveryCandidate* expected_candidate,std::stop_token stop){
    return detail::guarded([&]()->Result<SavedProject>{
        if(backup.empty()||target.empty())return Error{ErrorCode::invalid_argument,"Backup and in-place restore target paths are required"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"In-place project restore canceled"};
        const auto source_path=std::filesystem::absolute(backup).lexically_normal();
        const auto target_path=std::filesystem::absolute(target).lexically_normal();
        if(detail::same_file(source_path,target_path))return Error{ErrorCode::invalid_argument,"In-place restore target aliases its backup"};
        if(expected_candidate){
            std::error_code status_error;
            const auto status=std::filesystem::symlink_status(source_path,status_error);
            if(status_error||!std::filesystem::is_regular_file(status))
                return Error{ErrorCode::conflict,"Recovery artifact is no longer a regular file"};
            const auto identity=detail::take(detail::hash_recovery_artifact(
                source_path,expected_candidate->artifact_size,stop));
            if(identity.first!=expected_candidate->artifact_size||identity.second!=expected_candidate->artifact_sha256)
                return Error{ErrorCode::conflict,"Recovery artifact bytes changed after discovery"};
        }
        auto source=detail::take(ProjectStore::open(source_path,ProjectMode::read_only,stop));
        auto source_state=detail::take(source->snapshot());
        if(expected_candidate){
            if(source_state->uuid!=expected_candidate->uuid||source_state->revisions!=expected_candidate->revisions)
                return Error{ErrorCode::conflict,"Recovery artifact changed after discovery"};
            const auto identity=detail::take(detail::hash_recovery_artifact(
                source_path,expected_candidate->artifact_size,stop));
            if(identity.first!=expected_candidate->artifact_size||identity.second!=expected_candidate->artifact_sha256)
                return Error{ErrorCode::conflict,"Recovery artifact bytes changed during restore validation"};
        }
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
        require_history_verified(temporary->path,stop);
        target_locked.reset();
        if(stop.stop_requested())return Error{ErrorCode::canceled,"In-place project restore canceled before publication"};
        detail::publish_file(*temporary,target_path,ReplacePolicy::replace_existing);
        return SavedProject{target_path,source_state->uuid};
    });
}
}
