#include "hexlab/automation/api.hpp"
#include "hexlab/decompiler/decompiler.hpp"
#include "hexlab/decompiler/type_recovery.hpp"
#include "hexlab/loaders/recipe.hpp"
#include <algorithm>
#include <type_traits>
#include <unordered_map>
namespace hexlab::automation {
namespace {
Result<bool> version_ok(std::uint32_t version) {
    if(version!=api_version) return Error{ErrorCode::unsupported,"Unsupported HexLab automation API version"};
    return true;
}
Result<bool> page_ok(std::size_t count) {
    if(!count || count>maximum_page) return Error{ErrorCode::resource_limit,"Automation page count must be1..4096"};
    return true;
}
Result<bool> derived_ok(const ProjectSnapshot& snapshot) {
    if(snapshot.status!=DerivedStatus::fresh && snapshot.status!=DerivedStatus::incomplete)
        return Error{ErrorCode::conflict,"Automation facts are stale or unavailable; analyze the current project first"};
    return true;
}
bool account_type_tree(const types::TypePtr& type, std::size_t& nodes, std::size_t& text_bytes,
                       std::size_t depth = 0) {
    if (!type || depth > 64 || ++nodes > 262144) return false;
    auto add_text = [&](std::size_t size) {
        if (size > 16 * 1024 * 1024 - text_bytes) return false;
        text_bytes += size;
        return true;
    };
    if (!add_text(type->name().size())) return false;
    if (type->element() && !account_type_tree(type->element(), nodes, text_bytes, depth + 1)) return false;
    for (const auto& member : type->members()) {
        if (++nodes > 262144 || !add_text(member.name.size()) ||
            !account_type_tree(member.type, nodes, text_bytes, depth + 1)) return false;
        if (member.virtual_base && member.virtual_base->vbptr_type &&
            !account_type_tree(member.virtual_base->vbptr_type, nodes, text_bytes, depth + 1)) return false;
    }
    for (const auto& parameter : type->parameters())
        if (++nodes > 262144 || !add_text(parameter.name.size()) || !account_type_tree(parameter.type, nodes, text_bytes, depth + 1)) return false;
    if (type->result_type() && !account_type_tree(type->result_type(), nodes, text_bytes, depth + 1)) return false;
    for (const auto& method : type->methods())
        if (++nodes > 262144 || !add_text(method.name.size()) || !account_type_tree(method.signature, nodes, text_bytes, depth + 1) ||
            (method.this_type && !account_type_tree(method.this_type, nodes, text_bytes, depth + 1))) return false;
    for (const auto& member : type->static_data_members())
        if (++nodes > 262144 || !add_text(member.name.size()) || !account_type_tree(member.type, nodes, text_bytes, depth + 1)) return false;
    for (const auto& name : type->enumerators())
        if (++nodes > 262144 || !add_text(name.size())) return false;
    for (const auto& value : type->enumerator_values())
        if (++nodes > 262144 || !add_text(value.name.size())) return false;
    return true;
}
std::vector<const FunctionRecord*> containing_functions(const FunctionSnapshot& snapshot,Address address) {
    std::vector<const FunctionRecord*> result;
    for(const auto& function:snapshot.functions){
        if(function->entry==address){ result.push_back(function.get()); continue; }
        for(const auto& chunk:function->chunks)
            if(chunk.begin.space==address.space && address.offset>=chunk.begin.offset &&
               address.offset-chunk.begin.offset<chunk.size){ result.push_back(function.get()); break; }
    }
    return result;
}
const FunctionRecord* unique_containing_function(const FunctionSnapshot& snapshot,Address address) {
    // An exact entry is an explicit identity choice and remains unambiguous,
    // even when that function shares a tail with another function.
    for(const auto& function:snapshot.functions) if(function->entry==address) return function.get();
    const auto owners=containing_functions(snapshot,address);
    return owners.size()==1?owners.front():nullptr;
}
const BasicBlock* block_at(const FunctionSnapshot& snapshot,BlockId id) {
    for(const auto& block:snapshot.blocks)if(block->id==id)return block.get();
    return nullptr;
}
}
Result<bool> Project::owner() const {
    if(std::this_thread::get_id()!=owner_) return Error{ErrorCode::conflict,"Automation project belongs to another thread"};
    return true;
}
Result<bool> Project::live_owner() const {
    auto valid=owner();if(!valid)return valid.error();
    if(captured_)return Error{ErrorCode::read_only,"A captured workspace is read only; use the live project for this operation"};
    return true;
}
Result<std::shared_ptr<Project>> Project::open(const std::filesystem::path& path,bool readonly,std::uint32_t version,std::stop_token stop) {
    auto valid=version_ok(version);if(!valid)return valid.error();
    auto store=database::ProjectStore::open(path,readonly?database::ProjectMode::read_only:database::ProjectMode::read_write,stop);
    if(!store)return store.error();
    auto session=ProjectSession::attach(store.value(),{},stop);if(!session)return session.error();
    return std::shared_ptr<Project>(new Project(store.value(),session.value()));
}
Result<std::shared_ptr<Project>> Project::create(const std::filesystem::path& path,const std::filesystem::path& input,const LoadRecipe& recipe,std::uint32_t version,std::stop_token stop) {
    auto valid=version_ok(version);if(!valid)return valid.error();
    auto source=FileStorage::open(input);if(!source)return source.error();
    // Validate the selected loader before creating a durable project file.
    auto loaded=load_image(source.value(),recipe,stop);if(!loaded)return loaded.error();
    auto store=database::ProjectStore::create(path,stop);if(!store)return store.error();
    auto imported=store.value()->import_input(*source.value(),recipe,input,stop);if(!imported)return imported.error();
    auto session=ProjectSession::attach(store.value(),{},stop);if(!session)return session.error();
    return std::shared_ptr<Project>(new Project(store.value(),session.value()));
}
Result<std::shared_ptr<const ProjectSnapshot>> Project::snapshot() const {
    auto valid=owner();if(!valid)return valid.error();
    if(captured_)return captured_;
    return session_->snapshot();
}
Result<std::shared_ptr<Project>> Project::capture(std::optional<std::uint64_t> expected,std::stop_token stop) const {
    auto current=snapshot();if(!current)return current.error();
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Workspace capture canceled"};
    if(expected&&*expected!=current.value()->state->revisions.edit)
        return Error{ErrorCode::conflict,"Workspace capture expected a different project edit revision"};
    try {
        if(captured_)return std::shared_ptr<Project>(new Project(captured_));
        auto pinned=std::make_shared<ProjectSnapshot>(*current.value());
        pinned->mode=database::ProjectMode::read_only;
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Workspace capture canceled"};
        return std::shared_ptr<Project>(new Project(std::move(pinned)));
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate captured workspace"};}
}
Result<ImageInfo> Project::image_info() const {
    auto s=snapshot();if(!s)return s.error(); ImageInfo out;
    if(!s.value()->loaded)return out;
    const auto& loaded=*s.value()->loaded;const auto& layout=loaded.image->layout();
    out.mapped=true;out.metadata_complete=loaded.metadata_complete;out.format=loaded.metadata.format;
    out.machine=loaded.metadata.machine;out.preferred_base=loaded.metadata.preferred_base;
    out.image_size=loaded.metadata.image_size;out.header_size=loaded.metadata.header_size;
    out.architecture=static_cast<std::uint8_t>(layout.architecture);out.mode=static_cast<std::uint8_t>(layout.mode);
    out.segment_count=layout.segments.size();out.address_space_count=layout.domains.size()+1;out.entries=layout.entries;
    return out;
}
Result<std::vector<database::Annotation>> Project::annotations(std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    const auto& rows=s.value()->state->user->annotations;const auto first=std::min(start,rows.size());
    const auto end=first+std::min(count,rows.size()-first);
    return std::vector<database::Annotation>(rows.begin()+static_cast<std::ptrdiff_t>(first),rows.begin()+static_cast<std::ptrdiff_t>(end));
}
Result<std::vector<database::TypeDefinition>> Project::types(std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    const auto& rows=s.value()->state->user->types;const auto first=std::min(start,rows.size());
    const auto end=first+std::min(count,rows.size()-first);
    return std::vector<database::TypeDefinition>(rows.begin()+static_cast<std::ptrdiff_t>(first),rows.begin()+static_cast<std::ptrdiff_t>(end));
}
Result<std::vector<database::TypeAssignment>> Project::type_assignments(std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    const auto& rows=s.value()->state->user->type_assignments;const auto first=std::min(start,rows.size());
    const auto end=first+std::min(count,rows.size()-first);
    return std::vector<database::TypeAssignment>(rows.begin()+static_cast<std::ptrdiff_t>(first),rows.begin()+static_cast<std::ptrdiff_t>(end));
}
Result<std::vector<std::byte>> Project::read(Location location,std::size_t count,std::stop_token stop) const {
    auto s=snapshot();if(!s)return s.error();
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Workspace byte read canceled"};
    if(count>maximum_read)return Error{ErrorCode::resource_limit,"Automation read exceeds1MiB"};
    if(auto address=std::get_if<Address>(&location)){
        if(!s.value()->loaded)return Error{ErrorCode::unsupported,"Project has no image mapping"};
        auto result=s.value()->loaded->image->read(*address,count);
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Workspace byte read canceled"};
        return result;
    }
    const auto offset=std::get<FileOffset>(location);
    if(!s.value()->effective || offset.value>s.value()->effective->size() || count>s.value()->effective->size()-offset.value)
        return Error{ErrorCode::out_of_bounds,"Automation file read exceeds input"};
    auto bytes=s.value()->effective->read_at(offset,count);if(!bytes)return bytes.error();
    if(stop.stop_requested())return Error{ErrorCode::canceled,"Workspace byte read canceled"};
    if(bytes.value().bytes.size()!=count)return Error{ErrorCode::io,"Automation input returned a short read"};
    return std::vector<std::byte>(bytes.value().bytes.begin(),bytes.value().bytes.end());
}
Result<Address> Project::logical(X86LogicalAddress logical) const {
    auto s=snapshot();if(!s)return s.error();
    if(!s.value()->loaded)return Error{ErrorCode::unsupported,"Project has no image mapping"};
    return s.value()->loaded->image->from_logical(logical);
}
Result<std::vector<FunctionRecord>> Project::functions(std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    std::vector<FunctionRecord> output;
    if(!s.value()->functions)return output;
    const auto& rows=s.value()->functions->functions;
    for(auto i=std::min(start,rows.size()),end=i+std::min(count,rows.size()-i);i<end;++i)output.push_back(*rows[i]);
    return output;
}
Result<std::optional<FunctionRecord>> Project::function_at(Address address) const {
    auto s=snapshot();if(!s)return s.error();auto valid=derived_ok(*s.value());if(!valid)return valid.error();
    if(!s.value()->functions)return std::optional<FunctionRecord>{};
    const auto owners=containing_functions(*s.value()->functions,address);
    for(const auto* function:owners) if(function->entry==address) return std::optional<FunctionRecord>{*function};
    if(owners.size()>1)return Error{ErrorCode::conflict,"Address is owned by multiple functions; query function_owners to select an owner"};
    if(!owners.empty())return std::optional<FunctionRecord>{*owners.front()};
    return std::optional<FunctionRecord>{};
}
Result<std::vector<FunctionOwnerCandidate>> Project::function_owners(Address address) const {
    auto s=snapshot();if(!s)return s.error();auto valid=derived_ok(*s.value());if(!valid)return valid.error();
    std::vector<FunctionOwnerCandidate> result;
    if(!s.value()->functions)return result;
    for(const auto* function:containing_functions(*s.value()->functions,address))
        result.push_back({function->id,function->entry});
    std::sort(result.begin(),result.end(),[](const auto& a,const auto& b){return a.id<b.id;});
    return result;
}
Result<std::optional<StackFrameInfo>> Project::stack_frame(Address address) const {
    auto s=snapshot();if(!s)return s.error();
    auto valid=derived_ok(*s.value());if(!valid)return valid.error();
    if(!s.value()->functions)return std::optional<StackFrameInfo>{};
    const auto* function=unique_containing_function(*s.value()->functions,address);
    if(!function){
        const auto owners=containing_functions(*s.value()->functions,address);
        if(owners.size()>1)return Error{ErrorCode::conflict,"Address has multiple function owners; query function_owners and select a function entry"};
        return std::optional<StackFrameInfo>{};
    }
    const auto found=std::find_if(s.value()->stack_frames.begin(),s.value()->stack_frames.end(),
        [&](const auto& row){return row.function==function->id;});
    if(found==s.value()->stack_frames.end())return std::optional<StackFrameInfo>{};
    return std::optional<StackFrameInfo>{StackFrameInfo{found->function,function->entry,
        found->frame.maximum_stack_allocation_bytes,found->frame.slots.size(),found->frame.complete}};
}
Result<std::vector<StackSlotInfo>> Project::stack_slots(Address address,std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    std::vector<StackSlotInfo> output;
    if(!s.value()->functions)return output;
    const auto* function=unique_containing_function(*s.value()->functions,address);
    if(!function){
        const auto owners=containing_functions(*s.value()->functions,address);
        if(owners.size()>1)return Error{ErrorCode::conflict,"Address has multiple function owners; query function_owners and select a function entry"};
        return output;
    }
    const auto frame=std::find_if(s.value()->stack_frames.begin(),s.value()->stack_frames.end(),
        [&](const auto& row){return row.function==function->id;});
    if(frame==s.value()->stack_frames.end())return output;
    const auto& rows=frame->frame.slots;
    const auto first=std::min(start,rows.size()),end=first+std::min(count,rows.size()-first);
    output.reserve(end-first);
    for(auto i=first;i<end;++i){
        const auto& row=rows[i];
        output.push_back({row.offset_from_entry_sp,row.width,row.access_details.size(),
                          row.read,row.written,row.address_taken});
    }
    return output;
}
Result<std::vector<StackSlotAccessInfo>> Project::stack_slot_accesses(
    Address address,std::size_t slot_index,std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    std::vector<StackSlotAccessInfo> output;
    if(!s.value()->functions)return output;
    const auto* function=unique_containing_function(*s.value()->functions,address);
    if(!function){
        const auto owners=containing_functions(*s.value()->functions,address);
        if(owners.size()>1)return Error{ErrorCode::conflict,"Address has multiple function owners; query function_owners and select a function entry"};
        return output;
    }
    const auto frame=std::find_if(s.value()->stack_frames.begin(),s.value()->stack_frames.end(),
        [&](const auto& row){return row.function==function->id;});
    if(frame==s.value()->stack_frames.end())return output;
    if(slot_index>=frame->frame.slots.size())return Error{ErrorCode::invalid_argument,"Unknown stack-slot index"};
    const auto& rows=frame->frame.slots[slot_index].access_details;
    const auto first=std::min(start,rows.size()),end=first+std::min(count,rows.size()-first);
    output.reserve(end-first);
    for(auto i=first;i<end;++i){const auto& row=rows[i];output.push_back({row.instruction,row.read,row.written,row.address_taken});}
    return output;
}
Result<Decompilation> Project::decompile(Address address) const {
    auto s=snapshot();if(!s)return s.error();
    auto valid=derived_ok(*s.value());if(!valid)return valid.error();
    if(!s.value()->functions)
        return Error{ErrorCode::conflict,"Project has no current recovered functions to decompile"};
    const auto* function=unique_containing_function(*s.value()->functions,address);
    if(!function)return Error{ErrorCode::conflict,"Address has no unique recovered function owner; query function_owners to select an owner"};

    const auto *jvm_metadata=s.value()->loaded && s.value()->loaded->metadata.jvm
                                 ? &*s.value()->loaded->metadata.jvm : nullptr;
    auto lifted=decompiler::lift_function(*function,*s.value()->functions,jvm_metadata);
    if(!lifted)return lifted.error();
    auto ssa=decompiler::to_ssa(lifted.value());if(!ssa)return ssa.error();
    auto constants=decompiler::simplify_constants(ssa.value());if(!constants)return constants.error();
    auto identities=decompiler::simplify_identities(constants.value());if(!identities)return identities.error();
    auto dead=decompiler::eliminate_dead_code(identities.value());if(!dead)return dead.error();
    auto locals=decompiler::recover_stack_variables(dead.value());if(!locals)return locals.error();
    auto pseudocode=decompiler::format_structured_pseudocode(locals.value());
    Decompilation result;
    result.entry=function->entry;
    result.text=std::move(pseudocode.text);
    result.complete=function->complete && s.value()->status==DerivedStatus::fresh;
    result.used_fallback=pseudocode.used_fallback;
    result.fallback_reason=std::move(pseudocode.fallback_reason);
    result.diagnostics=std::move(locals.value().diagnostics);
    return result;
}
Result<LocationPresentation> Project::presentation(Location location) const {
    auto s=snapshot();if(!s)return s.error();
    return presentation_at(*s.value(),location);
}
Result<std::vector<FunctionBlock>> Project::function_blocks(Address address,std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    const auto* function=s.value()->functions?unique_containing_function(*s.value()->functions,address):nullptr;
    if(!function)return Error{ErrorCode::conflict,"Address has no unique recovered function owner; query function_owners to select an owner"};
    const auto first=std::min(start,function->blocks.size());
    const auto length=std::min(count,function->blocks.size()-first);
    std::vector<FunctionBlock> output(length);
    // Index only this page, so metadata memory remains bounded even for a large
    // function. Scan the immutable block table once instead of once per row.
    std::unordered_map<std::uint64_t,std::size_t> selected;
    for(std::size_t i=0;i<length;++i)selected.emplace(function->blocks[first+i].value,i);
    for(const auto& block:s.value()->functions->blocks){
        if(selected.empty())break;
        auto found=selected.find(block->id.value);if(found==selected.end())continue;
        output[found->second]={block->id,block->begin,block->instructions.size(),block->successors.size(),block->stop,presentation_at(*s.value(),block->begin)};
        selected.erase(found);
    }
    if(!selected.empty())return Error{ErrorCode::integrity,"Recovered function references an unavailable block"};
    return output;
}
Result<std::vector<Instruction>> Project::block_instructions(BlockId id,std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    const auto* block=s.value()->functions?block_at(*s.value()->functions,id):nullptr;
    if(!block)return Error{ErrorCode::invalid_argument,"Unknown analysis block identity"};
    std::vector<Instruction> output;
    const auto& rows=block->instructions;
    for(auto i=std::min(start,rows.size()),end=i+std::min(count,rows.size()-i);i<end;++i)output.push_back(rows[i]->instruction);
    return output;
}
Result<std::vector<BlockSuccessor>> Project::block_successors(BlockId id,std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    const auto* block=s.value()->functions?block_at(*s.value()->functions,id):nullptr;
    if(!block)return Error{ErrorCode::invalid_argument,"Unknown analysis block identity"};
    const auto& rows=block->successors;
    const auto first=std::min(start,rows.size()),end=first+std::min(count,rows.size()-first);
    return std::vector<BlockSuccessor>(rows.begin()+static_cast<std::ptrdiff_t>(first),rows.begin()+static_cast<std::ptrdiff_t>(end));
}
Result<std::vector<Instruction>> Project::instructions(std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    std::vector<Instruction> output;
    if(!s.value()->functions)return output;
    const auto& rows=s.value()->functions->instructions;
    for(auto i=std::min(start,rows.size()),end=i+std::min(count,rows.size()-i);i<end;++i)output.push_back(rows[i]->instruction);
    return output;
}
Result<std::vector<MappedSegment>> Project::segments(std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    if(!s.value()->loaded)return Error{ErrorCode::unsupported,"Project has no image mapping"};
    const auto& rows=s.value()->loaded->image->layout().segments;
    std::vector<MappedSegment> output;
    for(auto i=std::min(start,rows.size()),end=i+std::min(count,rows.size()-i);i<end;++i){
        const auto& row=rows[i];output.push_back({row.name,row.begin,row.size,row.file_begin,row.file_size,row.readable,row.writable,row.executable});
    }
    return output;
}
Result<std::vector<Reference>> Project::references(Location at,std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    std::vector<Reference> output;
    if(!s.value()->references)return output;
    const auto rows=s.value()->references->outgoing_view(at);
    for(auto i=std::min(start,rows.size()),end=i+std::min(count,rows.size()-i);i<end;++i)output.push_back(rows[i]);
    return output;
}
Result<ReferencePage> Project::incoming_references(Location at,std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    if(!s.value()->references)return ReferencePage{};
    return s.value()->references->incoming(at,PageRequest{start,count});
}
Result<ReferencePage> Project::all_references(std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    if(!s.value()->references)return ReferencePage{};
    const auto rows=s.value()->references->all();
    const auto first=std::min(start,rows.size());
    const auto end=first+std::min(count,rows.size()-first);
    ReferencePage page;page.total=rows.size();
    page.rows.assign(rows.begin()+static_cast<std::ptrdiff_t>(first),rows.begin()+static_cast<std::ptrdiff_t>(end));
    if(end<rows.size())page.next_offset=end;
    return page;
}
Result<std::vector<StringRecord>> Project::strings(std::size_t start,std::size_t count) const {
    auto s=snapshot();if(!s)return s.error();auto valid=page_ok(count);if(!valid)return valid.error();
    valid=derived_ok(*s.value());if(!valid)return valid.error();
    std::vector<StringRecord> output;
    if(!s.value()->strings)return output;
    const auto& rows=s.value()->strings->records;
    for(auto i=std::min(start,rows.size()),end=i+std::min(count,rows.size()-i);i<end;++i)output.push_back(rows[i]);
    return output;
}
Result<SearchPage> Project::search(const SearchQuery& query,std::optional<SearchCursor> cursor,const SearchLimits& limits,std::stop_token stop) const {
    auto current=snapshot();if(!current)return current.error();
    return hexlab::search(*current.value(),query,std::move(cursor),limits,stop);
}
Result<std::shared_ptr<const ProjectSnapshot>> Project::execute(const ProjectCommand& command,std::uint64_t group,std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();return session_->execute(command,group,stop);
}
Result<std::shared_ptr<const ProjectSnapshot>> Project::execute_batch(const std::vector<ProjectCommand>& commands,
    std::uint64_t group,std::optional<std::uint64_t> expected_edit_revision,std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();
    if(commands.empty() || commands.size()>maximum_page)
        return Error{ErrorCode::resource_limit,"Automation batch must contain 1..4096 commands"};
    std::size_t text_bytes=0,patch_bytes=0,chunk_count=0,type_nodes=0;
    auto add_text=[&](std::size_t size){if(size>16*1024*1024-text_bytes)return false;text_bytes+=size;return true;};
    for(const auto& command:commands){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"Automation batch canceled before validation"};
        const auto size=std::visit([&](const auto& edit)->std::optional<std::size_t>{
            using T=std::decay_t<decltype(edit)>;
            if constexpr(std::is_same_v<T,Rename>)return edit.name.size();
            else if constexpr(std::is_same_v<T,Comment>)return edit.text.size();
            else if constexpr(std::is_same_v<T,BookmarkCommand>)return edit.label.size();
            else if constexpr(std::is_same_v<T,SetProjectBreakpoint>){
                if(!add_text(edit.condition.size())||!add_text(edit.log_message.size()))return std::size_t{16*1024*1024+1};
                return std::size_t{0};
            }
            else if constexpr(std::is_same_v<T,PatchBytes>)return edit.replacement.size();
            else if constexpr(std::is_same_v<T,SetFunctionChunks>){
                if(edit.chunks.size()>maximum_page*16-chunk_count)return std::size_t{maximum_page*16+1};
                chunk_count+=edit.chunks.size();return std::size_t{0};
            }
            else if constexpr(std::is_same_v<T,DefineType>||std::is_same_v<T,UpdateType>){
                if(!add_text(edit.name.size())||!account_type_tree(edit.type,type_nodes,text_bytes))
                    return std::size_t{16*1024*1024+1};
                return std::size_t{0};
            }
            else if constexpr(std::is_same_v<T,DefineRegion>||std::is_same_v<T,DefineFunction>||
                              std::is_same_v<T,SuppressFunction>||std::is_same_v<T,SetReference>||
                              std::is_same_v<T,AssignType>)return std::size_t{0};
            else if constexpr(std::is_same_v<T,ImportPortableTypes>)return std::size_t{16*1024*1024+1};
            else if constexpr(std::is_same_v<T,ImportPortableDebugVariables>||std::is_same_v<T,ImportSymbols>||std::is_same_v<T,ImportDwarfInfo>)
                return std::size_t{16*1024*1024+1};
            else return std::nullopt;
        },command);
        if(!size)return Error{ErrorCode::invalid_argument,"Automation batch contains an unsupported project command"};
        if(*size>16*1024*1024)return Error{ErrorCode::resource_limit,"Automation batch exceeds its aggregate payload limit"};
        if(std::holds_alternative<PatchBytes>(command)){
            if(*size>maximum_read)return Error{ErrorCode::resource_limit,"An automation batch patch exceeds1MiB"};
            if(*size>16*1024*1024-patch_bytes)return Error{ErrorCode::resource_limit,"Automation batch patches exceed16MiB"};
            patch_bytes+=*size;
        }else if(!std::holds_alternative<PatchBytes>(command)&&
                 !std::holds_alternative<SetProjectBreakpoint>(command)&&
                 !std::holds_alternative<SetFunctionChunks>(command)&&
                 !std::holds_alternative<DefineType>(command)&&
                 !std::holds_alternative<UpdateType>(command)){
            if(*size>16*1024*1024-text_bytes)return Error{ErrorCode::resource_limit,"Automation batch text exceeds16MiB"};
            text_bytes+=*size;
        }
    }
    auto current=session_->snapshot();
    if(expected_edit_revision && current->state->revisions.edit!=*expected_edit_revision)
        return Error{ErrorCode::conflict,"Automation edit batch expected a different project revision"};
    return session_->execute_batch(commands,group,stop);
}
Result<std::shared_ptr<const ProjectSnapshot>> Project::patch(Location at,std::vector<std::byte> replacement,
    std::uint64_t expected_edit_revision,std::uint64_t group,std::stop_token stop){
    auto valid=live_owner();if(!valid)return valid.error();auto current=session_->snapshot();
    if(current->state->revisions.edit!=expected_edit_revision)
        return Error{ErrorCode::conflict,"Patch expected a different project edit revision"};
    if(replacement.size()>maximum_read)return Error{ErrorCode::resource_limit,"Automation patch exceeds1MiB"};
    return session_->execute(PatchBytes{std::move(at),std::move(replacement)},group,stop);
}
Result<std::shared_ptr<const ProjectSnapshot>> Project::undo(std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();return session_->undo(stop);
}
Result<std::shared_ptr<const ProjectSnapshot>> Project::redo(std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();return session_->redo(stop);
}
Result<std::shared_ptr<const ProjectSnapshot>> Project::analyze(std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();return session_->refresh_analysis(stop);
}
Result<bool> Project::save(std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();return store_->checkpoint(stop);
}
Result<database::SavedProject> Project::save_as(const std::filesystem::path& path,std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();return store_->save_as(path,database::ReplacePolicy::fail_if_exists,stop);
}
Result<database::SavedProject> Project::backup_to(const std::filesystem::path& path,bool replace,std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();
    return store_->backup_to(path,replace?database::ReplacePolicy::replace_existing:database::ReplacePolicy::fail_if_exists,stop);
}
Result<BackupRotationInfo> Project::backup_to_rotating(const std::filesystem::path& base,std::size_t retain,std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();
    auto result=store_->backup_to_rotating(base,retain,stop);if(!result)return result.error();
    auto value=std::move(result.value());
    return BackupRotationInfo{std::move(value.backup),value.removed_generations,value.retention_satisfied};
}
Result<BackupListInfo> Project::list_rotated_backups(const std::filesystem::path& base,std::stop_token stop) const {
    auto valid=live_owner();if(!valid)return valid.error();
    auto result=store_->list_rotated_backups(base,stop);if(!result)return result.error();
    BackupListInfo output;output.complete=result.value().complete;output.backups.reserve(result.value().backups.size());
    for(auto& row:result.value().backups)output.backups.push_back({std::move(row.backup),row.created_unix_ms});
    return output;
}
Result<BackupPruneInfo> Project::prune_rotated_backups(const std::filesystem::path& base,std::size_t retain,std::stop_token stop) {
    auto valid=live_owner();if(!valid)return valid.error();
    auto result=store_->prune_rotated_backups(base,retain,stop);if(!result)return result.error();
    return BackupPruneInfo{result.value().remaining,result.value().removed,result.value().retention_satisfied};
}
Result<database::SavedProject> Project::restore_backup_in_place(const std::filesystem::path& backup,
        const std::filesystem::path& target,std::uint32_t version,std::stop_token stop) {
    auto valid=version_ok(version);if(!valid)return valid.error();
    return database::ProjectStore::restore_backup_in_place(backup,target,stop);
}
Result<ExportReceipt> Project::export_binary(const std::filesystem::path& path,std::stop_token stop) {
    auto s=snapshot();if(!s)return s.error();return export_patched(*s.value(),path,database::ReplacePolicy::fail_if_exists,stop);
}

Result<bool> Archive::owner() const {
    if (std::this_thread::get_id() != owner_)
        return Error{ErrorCode::conflict, "Automation archive belongs to another thread"};
    return true;
}
Result<std::shared_ptr<Archive>> Archive::open(const std::filesystem::path &path,
                                               std::uint32_t version, std::stop_token stop) {
    auto valid = version_ok(version); if (!valid) return valid.error();
    auto storage = FileStorage::open(path); if (!storage) return storage.error();
    auto loaded = load_archive(storage.value(), LoadRecipe{Format::ar}, stop);
    if (!loaded) return loaded.error();
    return std::shared_ptr<Archive>(new Archive(loaded.value().storage, std::move(loaded.value().archive)));
}
Result<ArchiveSummary> Archive::summary() const {
    auto valid = owner(); if (!valid) return valid.error();
    return ArchiveSummary{archive_.members.size(), archive_.symbols.size(), archive_.has_symbol_index,
                          archive_.symbol_index_complete, archive_.diagnostics};
}
Result<std::vector<ArchiveMemberRecord>> Archive::members(std::size_t start, std::size_t count) const {
    auto valid = owner(); if (!valid) return valid.error();
    valid = page_ok(count); if (!valid) return valid.error();
    std::vector<ArchiveMemberRecord> output;
    const auto first = std::min(start, archive_.members.size());
    const auto end = first + std::min(count, archive_.members.size() - first);
    output.reserve(end - first);
    for (auto i = first; i < end; ++i) {
        const auto &member = archive_.members[i];
        output.push_back({i, member.name, member.header_offset, member.data_offset, member.size, member.kind});
    }
    return output;
}
Result<std::vector<ArchiveSymbolRecord>> Archive::symbols(std::size_t start, std::size_t count) const {
    auto valid = owner(); if (!valid) return valid.error();
    valid = page_ok(count); if (!valid) return valid.error();
    std::vector<ArchiveSymbolRecord> output;
    const auto first = std::min(start, archive_.symbols.size());
    const auto end = first + std::min(count, archive_.symbols.size() - first);
    output.reserve(end - first);
    for (auto i = first; i < end; ++i)
        output.push_back({archive_.symbols[i].name, archive_.symbols[i].member_index});
    return output;
}
Result<std::vector<std::byte>> Archive::read_member(std::size_t index, std::uint64_t offset,
                                                    std::size_t count) const {
    auto valid = owner(); if (!valid) return valid.error();
    if (count > maximum_read) return Error{ErrorCode::resource_limit, "Automation archive read exceeds1MiB"};
    if (index >= archive_.members.size()) return Error{ErrorCode::invalid_argument, "Unknown archive member index"};
    const auto &member = archive_.members[index];
    if (member.kind != ArMemberKind::regular)
        return Error{ErrorCode::unsupported, "Only regular archive members can be read"};
    if (offset > member.size || count > member.size - offset)
        return Error{ErrorCode::out_of_bounds, "Archive member read exceeds member extent"};
    auto view = open_ar_member(storage_, member); if (!view) return view.error();
    auto bytes = view.value()->read_at({offset}, count); if (!bytes) return bytes.error();
    if (bytes.value().bytes.size() != count)
        return Error{ErrorCode::io, "Archive member returned a short read"};
    return std::vector<std::byte>(bytes.value().bytes.begin(), bytes.value().bytes.end());
}
}
