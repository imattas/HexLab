#include "project_internal.hpp"
#include "native_files.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <map>
#include <random>
#include <set>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#endif
namespace hexlab::database {
namespace detail {
namespace {
uint64_t unsigned_column(const Statement& row,int column){return take(decode_u64(take(row.blob(column))));}
Location location_column(const Statement& row,int column){return take(decode_location(take(row.blob(column))));}
Address address_column(const Statement& row,int column){auto value=location_column(row,column);auto address=std::get_if<Address>(&value);require(address!=nullptr,"Decision has a non-address location");return *address;}
void budget(Connection& connection,const char* table,const char* expression,size_t& remaining){
    auto query=take(connection.prepare(std::string("SELECT count(*),coalesce(sum(")+expression+"),0) FROM "+table));require(take(query->step()),"Cannot count project records");
    const auto count=take(query->integer(0)),bytes=take(query->integer(1));require(count>=0 && count<=project_record_limit && bytes>=0 && static_cast<uint64_t>(bytes)<=remaining,"Project records exceed bounded loading budget");remaining-=static_cast<size_t>(bytes);
}
}
std::shared_ptr<const ProjectState> read_state(Connection& connection,int version){
    if(version<0)version=schema_version(connection);
    auto state=std::make_shared<ProjectState>();
    auto header=take(connection.prepare("SELECT uuid,recipe,input_size,input_sha256,edit_revision,byte_revision,history_cursor,next_entity FROM project WHERE singleton=1"));
    require(take(header->step()),"Project header is missing");const auto uuid=take(header->blob(0));require(uuid.size()==16 && std::any_of(uuid.begin(),uuid.end(),[](auto value){return value!=std::byte{0};}),"Invalid project UUID");std::copy(uuid.begin(),uuid.end(),state->uuid.begin());
    state->recipe=take(decode_recipe(take(header->blob(1))));state->input.size=unsigned_column(*header,2);const auto digest=take(header->blob(3));require(digest.size()==32,"Invalid input digest extent");std::copy(digest.begin(),digest.end(),state->input.sha256.begin());
    state->revisions.edit=unsigned_column(*header,4);state->revisions.bytes=unsigned_column(*header,5);state->history_cursor=unsigned_column(*header,6);state->next_entity=unsigned_column(*header,7);require(!take(header->step()),"Duplicate project header");header.reset();
    auto header_count=take(connection.prepare("SELECT count(*) FROM project"));require(take(header_count->step()) && take(header_count->integer(0))==1,"Unknown project header record ID");header_count.reset();
    state->provenance=read_provenance(connection);
    if(version>=1){auto decisions=take(connection.prepare("SELECT decision_revision FROM project WHERE singleton=1"));require(take(decisions->step()),"Project decision revision missing");state->revisions.decisions=unsigned_column(*decisions,0);}
    require(state->next_entity>0 && state->next_entity!=UINT64_MAX && state->revisions.bytes<=state->revisions.edit && state->revisions.decisions<=state->revisions.edit && state->history_cursor<=state->revisions.edit,"Inconsistent project revision header");
    size_t remaining=project_payload_limit;
    budget(connection,"annotations","8+length(location)+length(CAST(name AS BLOB))+length(CAST(comment AS BLOB))+8",remaining);
    budget(connection,"bookmarks","8+length(location)+length(CAST(label AS BLOB))+4",remaining);
    budget(connection,"regions","8+length(begin)+length(size)+1",remaining);
    budget(connection,"functions","8+length(entry)+5",remaining);
    budget(connection,"function_chunks","length(begin)+length(size)+4",remaining);
    budget(connection,"explicit_references","8+length(source)+length(target)+1",remaining);
    budget(connection,"patches","length(begin)+length(original)+length(replacement)+4",remaining);
    if(version>=2){std::string expression="8+length(CAST(name AS BLOB))+length(payload)+4";if(version>=7)expression+="+coalesce(length(CAST(source_id AS BLOB)),0)+coalesce(length(CAST(source_section AS BLOB)),0)+coalesce(length(unit_offset),0)+coalesce(length(record_offset),0)+coalesce(length(record_size),0)";if(version>=8)expression+="+1";budget(connection,"type_definitions",expression.c_str(),remaining);budget(connection,"type_assignments","8+length(location)+length(type_id)",remaining);}
    if(version>=4){std::string expression="8+length(function_entry)+length(CAST(name AS BLOB))+coalesce(length(type_id),0)+length(scope_offset)+coalesce(length(address),0)+length(location_expression)+2*length(location_operations)+length(CAST(source_id AS BLOB))+length(CAST(source_section AS BLOB))+length(unit_offset)+length(record_offset)+length(record_size)+72";if(version>=6)expression+="+length(location_ranges)";budget(connection,"debug_variables",expression.c_str(),remaining);}
    if(version>=11)budget(connection,"project_breakpoints","42+length(CAST(condition AS BLOB))+length(CAST(log_message AS BLOB))+length(ignore_count)+length(hit_count)",remaining);
    else if(version>=10)budget(connection,"project_breakpoints","34+length(CAST(condition AS BLOB))+length(CAST(log_message AS BLOB))+length(ignore_count)",remaining);
    else if(version>=9)budget(connection,"project_breakpoints","34",remaining);
    if(version>=12)budget(connection,"loader_diagnostics","16+coalesce(length(location),0)+length(CAST(message AS BLOB))",remaining);
    if(version>=12){auto rows=take(connection.prepare("SELECT source,severity,location,message FROM loader_diagnostics ORDER BY source,ordinal"));while(take(rows->step())){const auto source=take(rows->integer(0)),severity=take(rows->integer(1));require(source>=0&&source<=1&&severity>=0&&severity<=2,"Invalid persisted loader diagnostic");Diagnostic item{static_cast<DiagnosticSeverity>(severity),take(rows->text(3)),{}};if(!take(rows->is_null(2))){auto location=location_column(*rows,2);auto address=std::get_if<Address>(&location);require(address,"Persisted loader diagnostic has non-address location");item.location=*address;}if(source==0)state->loader_diagnostics.push_back(std::move(item));else state->runtime_relocation_diagnostics.push_back(std::move(item));}}
    if(version>=13){
        budget(connection,"type_import_diagnostics","8+length(CAST(source AS BLOB))+coalesce(length(location),0)+coalesce(length(function_entry),0)+length(CAST(message AS BLOB))",remaining);
        auto rows=take(connection.prepare("SELECT source,severity,location,function_entry,message FROM type_import_diagnostics ORDER BY ordinal"));
        while(take(rows->step())){
            const auto severity=take(rows->integer(1));require(severity>=0&&severity<=2,"Invalid persisted type import diagnostic severity");
            TypeImportDiagnostic item;item.source=take(rows->text(0));require(!item.source.empty(),"Persisted type import diagnostic has no source");item.severity=static_cast<DiagnosticSeverity>(severity);
            if(!take(rows->is_null(2)))item.location=address_column(*rows,2);
            if(!take(rows->is_null(3)))item.function_entry=address_column(*rows,3);
            item.message=take(rows->text(4));state->type_import_diagnostics.push_back(std::move(item));
        }
    }
    auto user=std::make_shared<UserState>();
    auto annotations=take(connection.prepare("SELECT id,location,name,comment FROM annotations ORDER BY id"));
    while(take(annotations->step()))user->annotations.push_back({unsigned_column(*annotations,0),location_column(*annotations,1),take(annotations->text(2)),take(annotations->text(3))});
    auto bookmarks=take(connection.prepare("SELECT id,location,label FROM bookmarks ORDER BY id"));
    while(take(bookmarks->step()))user->bookmarks.push_back({unsigned_column(*bookmarks,0),location_column(*bookmarks,1),take(bookmarks->text(2))});
    auto regions=take(connection.prepare("SELECT id,begin,size,kind FROM regions ORDER BY id"));
    while(take(regions->step())){auto kind=take(regions->integer(3));require(kind>=0 && kind<=1,"Unknown region kind");user->decisions.regions.push_back({unsigned_column(*regions,0),address_column(*regions,1),unsigned_column(*regions,2),static_cast<RegionKind>(kind)});}
    std::map<uint64_t,size_t> function_indices;
    auto functions=take(connection.prepare("SELECT id,entry,suppressed FROM functions ORDER BY id"));
    while(take(functions->step())){auto flag=take(functions->integer(2));require(flag==0 || flag==1,"Invalid function suppression flag");const auto id=unsigned_column(*functions,0);function_indices.emplace(id,user->decisions.functions.size());user->decisions.functions.push_back({id,address_column(*functions,1),flag!=0,{}});}
    auto chunks=take(connection.prepare("SELECT function_id,ordinal,begin,size FROM function_chunks ORDER BY function_id,ordinal"));
    while(take(chunks->step())){auto function=function_indices.find(unsigned_column(*chunks,0));require(function!=function_indices.end(),"Orphaned function chunk");auto& owned=user->decisions.functions[function->second].chunks;require(take(chunks->integer(1))==static_cast<int64_t>(owned.size()),"Missing or unordered function chunk");owned.push_back({address_column(*chunks,2),unsigned_column(*chunks,3)});}
    auto references=take(connection.prepare("SELECT id,source,target,kind FROM explicit_references ORDER BY id"));
    while(take(references->step())){const auto kind=take(references->integer(3));require(kind>=0 && kind<=6,"Unknown explicit reference kind");user->decisions.references.push_back({unsigned_column(*references,0),location_column(*references,1),location_column(*references,2),static_cast<UserReferenceKind>(kind)});}
    auto patches=take(connection.prepare("SELECT begin,original,replacement FROM patches ORDER BY begin"));
    while(take(patches->step()))user->patches.push_back({{unsigned_column(*patches,0)},take(patches->blob(1)),take(patches->blob(2))});
    if(version>=2){
        auto types=take(connection.prepare(version>=8
            ? "SELECT id,name,payload,source_id,source_section,unit_offset,record_offset,record_size,declaration_kind FROM type_definitions ORDER BY id"
            : version>=7 ? "SELECT id,name,payload,source_id,source_section,unit_offset,record_offset,record_size FROM type_definitions ORDER BY id"
            : "SELECT id,name,payload FROM type_definitions ORDER BY id"));
        while(take(types->step())){
            TypeDefinition row{unsigned_column(*types,0),take(types->text(1)),take(hexlab::types::decode(take(types->blob(2))))};
            if(version>=7&&!take(types->is_null(3))){
                require(!take(types->is_null(4))&&!take(types->is_null(5))&&!take(types->is_null(6))&&!take(types->is_null(7)),"Incomplete DWARF type source origin");
                row.origin=DwarfSourceOrigin{take(types->text(3)),take(types->text(4)),unsigned_column(*types,5),unsigned_column(*types,6),unsigned_column(*types,7)};
            }else if(version>=7){require(take(types->is_null(4))&&take(types->is_null(5))&&take(types->is_null(6))&&take(types->is_null(7)),"Incomplete DWARF type source origin");}
            if(version>=8){const auto kind=take(types->integer(8));require(kind>=0&&kind<=2,"Invalid declaration kind");row.declaration_kind=static_cast<DeclarationKind>(kind);}
            user->types.push_back(std::move(row));
        }
        auto assignments=take(connection.prepare("SELECT id,location,type_id FROM type_assignments ORDER BY id"));
        while(take(assignments->step()))user->type_assignments.push_back({unsigned_column(*assignments,0),location_column(*assignments,1),unsigned_column(*assignments,2)});
    }
    if(version>=4){
        auto variables=take(connection.prepare(version>=6
            ? "SELECT id,function_entry,name,type_id,is_parameter,scope_offset,address,location_expression,location_operations,source_id,source_section,unit_offset,record_offset,record_size,cfa_offset,location_ranges FROM debug_variables ORDER BY id"
            : version>=5 ? "SELECT id,function_entry,name,type_id,is_parameter,scope_offset,address,location_expression,location_operations,source_id,source_section,unit_offset,record_offset,record_size,cfa_offset FROM debug_variables ORDER BY id"
            : "SELECT id,function_entry,name,type_id,is_parameter,scope_offset,address,location_expression,location_operations,source_id,source_section,unit_offset,record_offset,record_size FROM debug_variables ORDER BY id"));
        while(take(variables->step())){
            DebugVariable row;row.id=unsigned_column(*variables,0);row.function_entry=address_column(*variables,1);row.name=take(variables->text(2));
            if(!take(variables->is_null(3)))row.type_id=unsigned_column(*variables,3);
            const auto parameter=take(variables->integer(4));require(parameter==0||parameter==1,"Invalid DWARF parameter flag");row.is_parameter=parameter!=0;row.scope_offset=unsigned_column(*variables,5);
            if(!take(variables->is_null(6)))row.address=unsigned_column(*variables,6);
            for(auto byte:take(variables->blob(7)))row.location_expression.push_back(std::to_integer<std::uint8_t>(byte));
            const auto operations=take(variables->blob(8));require(operations.size()%29==0 && operations.size()/29<=4096,"Invalid DWARF location operation payload");
            for(size_t offset=0;offset<operations.size();offset+=29){const auto read=[&](size_t begin,size_t width){uint64_t value=0;for(size_t i=0;i<width;++i)value=(value<<8)|std::to_integer<unsigned>(operations[begin+i]);return value;};DebugLocationOperation op;op.kind=static_cast<std::uint8_t>(read(offset,1));op.unsigned_operand=read(offset+1,8);op.signed_operand=static_cast<std::int64_t>(read(offset+9,8));op.expression_offset=static_cast<std::uint32_t>(read(offset+17,4));op.second_unsigned_operand=read(offset+21,8);row.location_operations.push_back(op);}
            row.origin.source_id=take(variables->text(9));row.origin.section=take(variables->text(10));row.origin.unit_offset=unsigned_column(*variables,11);row.origin.record_offset=unsigned_column(*variables,12);row.origin.record_size=unsigned_column(*variables,13);
            if(version>=5&&!take(variables->is_null(14)))row.cfa_offset=static_cast<std::int64_t>(unsigned_column(*variables,14));
            if(version>=6)row.location_ranges=take(decode_location_ranges(take(variables->blob(15))));
            user->debug_variables.push_back(std::move(row));
        }
    }
    if(version>=9){
        auto rows=take(connection.prepare(version>=11
            ? "SELECT id,address,kind,enabled,size,condition,logpoint,log_message,ignore_count,hit_count FROM project_breakpoints ORDER BY id"
            : version>=10
            ? "SELECT id,address,kind,enabled,size,condition,logpoint,log_message,ignore_count FROM project_breakpoints ORDER BY id"
            : "SELECT id,address,kind,enabled,size FROM project_breakpoints ORDER BY id"));
        while(take(rows->step())){
            const auto kind=take(rows->integer(2)),enabled=take(rows->integer(3)),size=take(rows->integer(4));
            require(kind>=0&&kind<=5&&enabled>=0&&enabled<=1&&size>=1&&size<=8,"Invalid project breakpoint fields");
            ProjectBreakpoint row{unsigned_column(*rows,0),address_column(*rows,1),static_cast<ProjectBreakpointKind>(kind),enabled!=0,static_cast<std::uint8_t>(size)};
            if(version>=10){
                row.condition=take(rows->text(5));
                const auto logpoint=take(rows->integer(6));require(logpoint==0||logpoint==1,"Invalid project breakpoint logpoint flag");row.logpoint=logpoint!=0;
                row.log_message=take(rows->text(7));row.ignore_count=unsigned_column(*rows,8);
                if(version>=11)row.hit_count=unsigned_column(*rows,9);
            }
            user->breakpoints.push_back(std::move(row));
        }
    }
    take(validate_user_state(*user));
    const auto check_id=[&](uint64_t id){require(id<state->next_entity,"Entity ID exceeds allocation cursor");};
    for(const auto& row:user->annotations)check_id(row.id);for(const auto& row:user->bookmarks)check_id(row.id);for(const auto& row:user->breakpoints)check_id(row.id);for(const auto& row:user->types)check_id(row.id);for(const auto& row:user->type_assignments)check_id(row.id);for(const auto& row:user->debug_variables)check_id(row.id);for(const auto& row:user->decisions.regions)check_id(row.id);for(const auto& row:user->decisions.functions)check_id(row.id);for(const auto& row:user->decisions.references)check_id(row.id);
    for(const auto& patch:user->patches)require(patch.begin.value<=state->input.size && patch.original.size()<=state->input.size-patch.begin.value,"Patch lies outside original input");
    auto history=take(connection.prepare("SELECT count(*) FROM history"));require(take(history->step()),"Cannot read history extent");auto count=take(history->integer(0));require(count>=0 && count<=project_record_limit && state->history_cursor<=static_cast<uint64_t>(count),"Invalid history extent");state->history_count=static_cast<uint64_t>(count);
    state->user=std::move(user);return state;
}
}
namespace {
ProjectUuid generate_uuid(){
    ProjectUuid result{};
#ifdef _WIN32
    if(BCryptGenRandom(nullptr,reinterpret_cast<PUCHAR>(result.data()),static_cast<ULONG>(result.size()),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)throw detail::Failure{{ErrorCode::io,"Cannot generate project UUID"}};
#else
    std::random_device entropy;for(auto& byte:result)byte=std::byte(entropy());
#endif
    result[6]=(result[6]&std::byte{0x0f})|std::byte{0x40};result[8]=(result[8]&std::byte{0x3f})|std::byte{0x80};return result;
}
}
namespace detail {ProjectUuid new_uuid(){return generate_uuid();}}
ProjectStore::ProjectStore(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
ProjectStore::~ProjectStore()=default;
Result<std::shared_ptr<ProjectStore>> ProjectStore::create(const std::filesystem::path& path,std::stop_token stop){
    return detail::guarded([&]()->Result<std::shared_ptr<ProjectStore>>{
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project creation canceled"};
        if(path.empty() || path.native().find(std::filesystem::path::value_type{})!=std::filesystem::path::string_type::npos)
            return Error{ErrorCode::invalid_argument,"Invalid project path"};
        auto wal=path;wal+="-wal";auto shm=path;shm+="-shm";
        if(std::filesystem::exists(wal) || std::filesystem::exists(shm))return Error{ErrorCode::conflict,"Existing project journal companions require recovery"};
        auto absolute=std::filesystem::absolute(path).lexically_normal();auto parent=absolute.parent_path();if(parent.empty())parent=".";
        auto temporary=detail::reserve_owned_file(parent,L".hexlab-save-",true);
        auto state=std::make_shared<ProjectState>();state->uuid=detail::new_uuid();auto lease=detail::take(ProjectLease::acquire(state->uuid));
        {
            auto connection=detail::take(Connection::open(temporary->path,OpenMode::create,stop));
            auto transaction=detail::take(Transaction::begin(*connection));detail::create_schema(*connection,*state);detail::take(transaction->commit());
            detail::take(connection->checkpoint());
        }
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project creation canceled"};
        detail::publish_file(*temporary,absolute,ReplacePolicy::fail_if_exists);
        auto impl=std::make_unique<Impl>();impl->path=std::move(absolute);impl->mode=ProjectMode::read_write;impl->lease=std::move(lease);impl->state=std::move(state);
        impl->connection=detail::take(Connection::open(impl->path,OpenMode::read_write,stop));
        return std::shared_ptr<ProjectStore>(new ProjectStore(std::move(impl)));
    });
}
Result<std::shared_ptr<ProjectStore>> ProjectStore::open(const std::filesystem::path& path,ProjectMode mode,std::stop_token stop){
    return detail::guarded([&]()->Result<std::shared_ptr<ProjectStore>>{
        if(mode!=ProjectMode::read_write && mode!=ProjectMode::read_only && mode!=ProjectMode::collaborative)return Error{ErrorCode::invalid_argument,"Unknown project open mode"};
        const bool collaborative=mode==ProjectMode::collaborative;
        // Validate unknown/newer/corrupt sources through a read-only connection first.
        auto probe=detail::take(Connection::open(path,OpenMode::read_only,stop));detail::take(probe->execute("BEGIN"));
        const auto version=detail::schema_version(*probe);detail::validate_schema(*probe,version);auto state=detail::read_state(*probe,version);
        if(version==0 && mode==ProjectMode::read_only)return Error{ErrorCode::unsupported,"Project requires migration; open an editable copy"};
        auto original=detail::extract_input(*probe,*state,stop);detail::take(probe->execute("COMMIT"));
        auto impl=std::make_unique<Impl>();impl->path=std::filesystem::absolute(path).lexically_normal();impl->mode=mode;impl->state=std::move(state);
        impl->original=std::move(original);
        if(mode==ProjectMode::read_write){auto lease=ProjectLease::acquire(impl->state->uuid);if(lease)impl->lease=std::move(lease.value());else if(lease.error().code==ErrorCode::busy){mode=ProjectMode::read_only;impl->mode=mode;}else return lease.error();}
        else if(collaborative){mode=ProjectMode::read_write;impl->mode=mode;}
        if(mode==ProjectMode::read_only)impl->connection=std::move(probe);
        else {
            probe.reset();impl->connection=detail::take(Connection::open(path,OpenMode::read_write,stop));
            auto transaction=detail::take(Transaction::begin(*impl->connection));const auto current=detail::schema_version(*impl->connection);detail::validate_schema(*impl->connection,current);
            if(current<12){detail::migrate_schema(*impl->connection);if(stop.stop_requested())return Error{ErrorCode::canceled,"Project schema migration canceled"};detail::validate_schema(*impl->connection,12);}
            auto current_state=detail::read_state(*impl->connection);
            if(current_state->input!=impl->state->input)impl->original=detail::extract_input(*impl->connection,*current_state,stop);
            else detail::verify_patches(*impl->original,*current_state->user);
            impl->state=std::move(current_state);detail::take(transaction->commit());
        }
        return std::shared_ptr<ProjectStore>(new ProjectStore(std::move(impl)));
    });
}
Result<std::shared_ptr<ProjectStore>> ProjectStore::open_collaborative(const std::filesystem::path& path,std::stop_token stop){
    return open(path,ProjectMode::collaborative,stop);
}
Result<std::vector<ProjectRecoveryCandidate>> ProjectStore::discover_recovery_candidates(
    const std::filesystem::path& directory,std::stop_token stop){
    return detail::guarded([&]()->Result<std::vector<ProjectRecoveryCandidate>>{
        if(directory.empty())return Error{ErrorCode::invalid_argument,"Recovery directory is empty"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Recovery discovery canceled"};
        std::error_code error;
        std::filesystem::directory_iterator current(directory,error),end;
        if(error)return Error{ErrorCode::io,"Cannot inspect project recovery directory: "+error.message()};
        std::vector<ProjectRecoveryCandidate> candidates;
        constexpr std::size_t entry_limit=8192,candidate_limit=256;
        std::size_t visited=0;
        while(current!=end){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Recovery discovery canceled"};
            if(++visited>entry_limit)return Error{ErrorCode::resource_limit,"Recovery directory exceeds the entry scan limit"};
            const auto entry=*current;
            current.increment(error);
            if(error)return Error{ErrorCode::io,"Cannot enumerate project recovery directory: "+error.message()};
            const auto name=entry.path().filename().u8string();
            RecoveryArtifactKind kind;
            if(name.starts_with(u8".hexlab-save-")&&name.ends_with(u8".tmp"))kind=RecoveryArtifactKind::interrupted_save;
            else if(name.starts_with(u8".hexlab-previous-")&&name.ends_with(u8".tmp"))kind=RecoveryArtifactKind::previous_version;
            else continue;
            if(candidates.size()>=candidate_limit)return Error{ErrorCode::resource_limit,"Recovery directory exceeds the candidate limit"};
            std::error_code status_error;
            const auto status=entry.symlink_status(status_error);
            if(status_error||!std::filesystem::is_regular_file(status))continue;
            auto opened=ProjectStore::open(entry.path(),ProjectMode::read_only,stop);
            if(!opened){if(stop.stop_requested()||opened.error().code==ErrorCode::canceled)return opened.error();continue;}
            auto snapshot=opened.value()->snapshot();
            if(!snapshot)continue;
            candidates.push_back({opened.value()->path(),snapshot.value()->uuid,kind});
        }
        std::sort(candidates.begin(),candidates.end(),[](const auto& left,const auto& right){return left.path.native()<right.path.native();});
        return candidates;
    });
}
Result<SavedProject> ProjectStore::recover_candidate(const ProjectRecoveryCandidate& candidate,
    const std::filesystem::path& destination,ReplacePolicy policy,std::stop_token stop){
    return detail::guarded([&]()->Result<SavedProject>{
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project recovery canceled"};
        if(candidate.path.empty() || (candidate.kind!=RecoveryArtifactKind::interrupted_save && candidate.kind!=RecoveryArtifactKind::previous_version))
            return Error{ErrorCode::invalid_argument,"Invalid project recovery candidate"};
        std::error_code error;
        const auto status=std::filesystem::symlink_status(candidate.path,error);
        if(error || !std::filesystem::is_regular_file(status))return Error{ErrorCode::conflict,"Recovery artifact is no longer a regular file"};
        const auto filename=candidate.path.filename().u8string();
        const auto expected_prefix=candidate.kind==RecoveryArtifactKind::interrupted_save?u8".hexlab-save-":u8".hexlab-previous-";
        if(!filename.starts_with(expected_prefix) || !filename.ends_with(u8".tmp"))return Error{ErrorCode::invalid_argument,"Recovery artifact name does not match its kind"};
        auto source=detail::take(open(candidate.path,ProjectMode::read_only,stop));
        auto state=detail::take(source->snapshot());
        if(state->uuid!=candidate.uuid)return Error{ErrorCode::conflict,"Recovery artifact identity changed after discovery"};
        // Save As repeats schema, embedded-input and publication validation,
        // assigns a fresh UUID, and leaves the original artifact untouched.
        return source->save_as(destination,policy,stop);
    });
}
Result<std::shared_ptr<const ProjectState>> ProjectStore::snapshot()const{std::lock_guard lock(impl_->mutex);return impl_->state;}
Result<bool> ProjectStore::persist_breakpoint_hit_counts(std::span<const BreakpointHitCount> counters,std::stop_token stop){
    return detail::guarded([&]()->Result<bool>{
        std::lock_guard lock(impl_->mutex);
        if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Breakpoint counter persistence canceled"};
        std::set<std::uint64_t> seen;
        for(const auto& counter:counters){
            if(!counter.id || !seen.insert(counter.id).second)return Error{ErrorCode::invalid_argument,"Invalid or duplicate project breakpoint counter ID"};
            const auto& rows=impl_->state->user->breakpoints;
            if(std::none_of(rows.begin(),rows.end(),[&](const auto& row){return row.id==counter.id;}))
                return Error{ErrorCode::conflict,"Project breakpoint counter refers to a missing breakpoint"};
        }
        if(counters.empty())return true;
        auto state=std::make_shared<ProjectState>(*impl_->state);
        auto user=std::make_shared<UserState>(*state->user);
        for(const auto& counter:counters){auto row=std::find_if(user->breakpoints.begin(),user->breakpoints.end(),[&](const auto& value){return value.id==counter.id;});row->hit_count=counter.hit_count;}
        state->user=std::move(user);
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=detail::take(Transaction::begin(*impl_->connection));
        auto update=detail::take(impl_->connection->prepare("UPDATE project_breakpoints SET hit_count=?2 WHERE id=?1"));
        auto changed=detail::take(impl_->connection->prepare("SELECT changes()"));
        for(const auto& counter:counters){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Breakpoint counter persistence canceled"};
            detail::take(update->bind_blob(1,encode_u64(counter.id)));
            detail::take(update->bind_blob(2,encode_u64(counter.hit_count)));
            detail::take(update->step());detail::take(update->reset());
            if(!detail::take(changed->step()) || detail::take(changed->integer(0))!=1)
                return Error{ErrorCode::conflict,"Project breakpoint was removed before its counter was saved"};
            detail::take(changed->reset());
        }
        detail::take(transaction->commit());
        impl_->state=std::move(state);
        return true;
    });
}
Result<bool> ProjectStore::replace_loader_diagnostics(std::span<const Diagnostic> loader,
        std::span<const Diagnostic> runtime,std::stop_token stop){
    return detail::guarded([&]()->Result<bool>{
        std::lock_guard lock(impl_->mutex);
        if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};
        if(loader.size()+runtime.size()>project_record_limit)return Error{ErrorCode::resource_limit,"Loader diagnostics exceed project record limit"};
        std::size_t bytes=0;for(const auto* rows:{&loader,&runtime})for(const auto& item:*rows){
            if(static_cast<unsigned>(item.severity)>2 || item.message.size()>65536)
                return Error{ErrorCode::invalid_argument,"Loader diagnostic is outside persistence limits"};
            const auto cost=item.message.size()+32;
            if(bytes>project_payload_limit || cost>project_payload_limit-bytes)
                return Error{ErrorCode::resource_limit,"Loader diagnostics exceed project payload limit"};
            bytes+=cost;
        }
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Loader diagnostic persistence canceled"};
        auto state=std::make_shared<ProjectState>(*impl_->state);
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=detail::take(Transaction::begin(*impl_->connection));
        detail::take(impl_->connection->execute("DELETE FROM loader_diagnostics"));
        auto insert=detail::take(impl_->connection->prepare("INSERT INTO loader_diagnostics(source,ordinal,severity,location,message) VALUES(?1,?2,?3,?4,?5)"));
        for(int source=0;source<2;++source){const auto& rows=source==0?loader:runtime;std::uint64_t ordinal=0;for(const auto& item:rows){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Loader diagnostic persistence canceled"};
            detail::take(insert->bind_integer(1,source));detail::take(insert->bind_integer(2,static_cast<std::int64_t>(ordinal++)));
            detail::take(insert->bind_integer(3,static_cast<int>(item.severity)));
            if(item.location)detail::take(insert->bind_blob(4,detail::take(encode_location(Location{*item.location}))));else detail::take(insert->bind_null(4));
            detail::take(insert->bind_text(5,item.message));detail::take(insert->step());detail::take(insert->reset());
        }}
        detail::take(transaction->commit());
        state->loader_diagnostics.assign(loader.begin(),loader.end());
        state->runtime_relocation_diagnostics.assign(runtime.begin(),runtime.end());
        impl_->state=std::move(state);
        return true;
    });
}
Result<bool> ProjectStore::replace_type_import_diagnostics(std::span<const TypeImportDiagnostic> diagnostics,
        std::stop_token stop){
    return detail::guarded([&]()->Result<bool>{
        std::lock_guard lock(impl_->mutex);
        if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};
        if(diagnostics.size()>2048)return Error{ErrorCode::resource_limit,"Type import diagnostics exceed the 2,048-row limit"};
        std::size_t bytes=0;
        for(const auto& item:diagnostics){
            if(item.source.empty() || item.source.size()>4096 || static_cast<unsigned>(item.severity)>2 || item.message.size()>65536)
                return Error{ErrorCode::invalid_argument,"Type import diagnostic is outside persistence limits"};
            const auto cost=item.source.size()+item.message.size()+48;
            if(bytes>project_payload_limit || cost>project_payload_limit-bytes)
                return Error{ErrorCode::resource_limit,"Type import diagnostics exceed project payload limit"};
            bytes+=cost;
        }
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Type import diagnostic persistence canceled"};
        auto state=std::make_shared<ProjectState>(*impl_->state);
        detail::Cancellation cancellation(*impl_->connection,stop);
        auto transaction=detail::take(Transaction::begin(*impl_->connection));
        detail::take(impl_->connection->execute("DELETE FROM type_import_diagnostics"));
        auto insert=detail::take(impl_->connection->prepare("INSERT INTO type_import_diagnostics(ordinal,source,severity,location,function_entry,message) VALUES(?1,?2,?3,?4,?5,?6)"));
        std::uint64_t ordinal=0;
        for(const auto& item:diagnostics){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"Type import diagnostic persistence canceled"};
            detail::take(insert->bind_integer(1,static_cast<std::int64_t>(ordinal++)));
            detail::take(insert->bind_text(2,item.source));
            detail::take(insert->bind_integer(3,static_cast<int>(item.severity)));
            if(item.location)detail::take(insert->bind_blob(4,detail::take(encode_location(Location{*item.location}))));else detail::take(insert->bind_null(4));
            if(item.function_entry)detail::take(insert->bind_blob(5,detail::take(encode_location(Location{*item.function_entry}))));else detail::take(insert->bind_null(5));
            detail::take(insert->bind_text(6,item.message));detail::take(insert->step());detail::take(insert->reset());
        }
        detail::take(transaction->commit());
        state->type_import_diagnostics.assign(diagnostics.begin(),diagnostics.end());
        impl_->state=std::move(state);
        return true;
    });
}
Result<bool> ProjectStore::external_changes_pending(std::stop_token stop) const {
    return detail::guarded([&]() -> Result<bool> {
        std::lock_guard lock(impl_->mutex);
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "External project check canceled"};
        detail::Cancellation cancellation(*impl_->connection, stop);
        auto query = detail::take(impl_->connection->prepare(
            "SELECT uuid,input_size,input_sha256,edit_revision,byte_revision,decision_revision,history_cursor "
            "FROM project WHERE singleton=1"));
        if (!detail::take(query->step()))
            return Error{ErrorCode::integrity, "Project header is missing during external check"};
        const auto uuid = detail::take(query->blob(0));
        const auto size = detail::take(decode_u64(detail::take(query->blob(1))));
        const auto digest = detail::take(query->blob(2));
        if (uuid.size() != impl_->state->uuid.size() || digest.size() != impl_->state->input.sha256.size())
            return Error{ErrorCode::integrity, "Project identity fields are malformed during external check"};
        const auto edit = detail::take(decode_u64(detail::take(query->blob(3))));
        const auto bytes = detail::take(decode_u64(detail::take(query->blob(4))));
        const auto decisions = detail::take(decode_u64(detail::take(query->blob(5))));
        const auto cursor = detail::take(decode_u64(detail::take(query->blob(6))));
        if (detail::take(query->step()))
            return Error{ErrorCode::integrity, "Duplicate project header during external check"};
        return !std::equal(uuid.begin(), uuid.end(), impl_->state->uuid.begin()) ||
               size != impl_->state->input.size ||
               !std::equal(digest.begin(), digest.end(), impl_->state->input.sha256.begin()) ||
               ProjectRevisions{edit, bytes, decisions} != impl_->state->revisions ||
               cursor != impl_->state->history_cursor;
    });
}
Result<std::shared_ptr<const ProjectState>> ProjectStore::refresh_external(std::stop_token stop){
    return detail::guarded([&]()->Result<std::shared_ptr<const ProjectState>>{
        std::lock_guard lock(impl_->mutex);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project refresh canceled"};
        detail::Cancellation cancellation(*impl_->connection,stop);
        detail::take(impl_->connection->execute("BEGIN"));
        struct ReadTransaction {
            std::shared_ptr<Connection> connection;
            bool active=true;
            ~ReadTransaction(){if(active){auto ignored=connection->execute("ROLLBACK");(void)ignored;}}
        } transaction{impl_->connection};
        const auto version=detail::schema_version(*impl_->connection);
        detail::validate_schema(*impl_->connection,version);
        auto current=detail::read_state(*impl_->connection,version);
        auto original=impl_->original;
        if(current->input!=impl_->state->input || !original)
            original=detail::extract_input(*impl_->connection,*current,stop);
        else
            detail::verify_patches(*original,*current->user);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Project refresh canceled"};
        detail::take(impl_->connection->execute("COMMIT"));
        transaction.active=false;
        impl_->original=std::move(original);
        impl_->state=std::move(current);
        return impl_->state;
    });
}
const std::filesystem::path& ProjectStore::path()const noexcept{return impl_->path;}
Result<bool> ProjectStore::checkpoint(std::stop_token stop){return detail::guarded([&]()->Result<bool>{std::lock_guard lock(impl_->mutex);if(impl_->mode==ProjectMode::read_only)return Error{ErrorCode::read_only,"Project is read only"};detail::Cancellation cancellation(*impl_->connection,stop);return impl_->connection->checkpoint();});}
}
