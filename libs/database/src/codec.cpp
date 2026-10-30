#include "hexlab/database/codec.hpp"
#include <algorithm>
#include <set>
#include <tuple>
namespace hexlab::database {
namespace {
struct Failure {Error error;};
void require(bool condition,const char* message){if(!condition)throw Failure{{ErrorCode::malformed,message}};}
bool utf8(std::string_view value,bool name){
    size_t i=0;
    while(i<value.size()){
        const auto first=static_cast<unsigned char>(value[i++]);uint32_t cp=first;unsigned continuation=0;uint32_t minimum=0;
        if(first>=0xc2 && first<=0xdf){cp=first&31;continuation=1;minimum=0x80;}
        else if(first>=0xe0 && first<=0xef){cp=first&15;continuation=2;minimum=0x800;}
        else if(first>=0xf0 && first<=0xf4){cp=first&7;continuation=3;minimum=0x10000;}
        else if(first>=0x80)return false;
        if(continuation>value.size()-i)return false;
        for(unsigned j=0;j<continuation;++j){const auto next=static_cast<unsigned char>(value[i++]);if((next&0xc0)!=0x80)return false;cp=(cp<<6)|(next&63);}
        if(cp<minimum || cp>0x10ffff || (cp>=0xd800 && cp<=0xdfff) || cp==0)return false;
        if(name && (cp<32 || (cp>=127 && cp<=159)))return false;
    }
    return true;
}
struct Writer {
    std::vector<std::byte> bytes;
    void append(std::span<const std::byte> value){require(value.size()<=project_payload_limit-bytes.size(),"Project payload exceeds 64 MiB budget");bytes.insert(bytes.end(),value.begin(),value.end());}
    void number(uint64_t value,size_t width){std::array<std::byte,8> data{};for(size_t i=0;i<width;++i)data[width-i-1]=std::byte(value>>(8*i));append(std::span(data).first(width));}
    void count(size_t count){require(count<=project_record_limit,"Project record count exceeds budget");number(count,4);}
    void text(std::string_view text){number(text.size(),4);append(std::as_bytes(std::span(text)));}
    void address(Address address){number(address.space.value,4);number(address.offset,8);}
    void location(Location location){if(auto address_value=std::get_if<Address>(&location)){number(0,1);address(*address_value);}else{number(1,1);number(std::get<FileOffset>(location).value,8);}}
};
struct Reader {
    std::span<const std::byte> input;size_t cursor=0;
    std::span<const std::byte> read(size_t count){require(count<=input.size()-cursor,"Truncated project record");auto value=input.subspan(cursor,count);cursor+=count;return value;}
    uint64_t number(size_t width){uint64_t value=0;for(auto byte:read(width))value=(value<<8)|std::to_integer<unsigned>(byte);return value;}
    size_t count(size_t minimum){const auto count=number(4);require(count<=project_record_limit && count<=(input.size()-cursor)/minimum,"Invalid project record count");return static_cast<size_t>(count);}
    std::string text(size_t limit){const auto count=number(4);require(count<=limit,"Project text exceeds its field budget");auto value=read(static_cast<size_t>(count));return {reinterpret_cast<const char*>(value.data()),value.size()};}
    Address address(){const auto space=number(4);return {{static_cast<uint32_t>(space)},number(8)};}
    Location location(){const auto tag=number(1);if(tag==0)return address();require(tag==1,"Unknown location domain");return FileOffset{number(8)};}
    void finish(){require(cursor==input.size(),"Trailing project record bytes");}
};
void validate(const UserState& user){
    size_t payload=26;
    const auto charge=[&](size_t count){require(count<=project_payload_limit-payload,"User state exceeds aggregate payload budget");payload+=count;};
    const auto location_size=[](Location location)->size_t{return std::holds_alternative<Address>(location)?13:9;};
    std::set<uint64_t> ids;std::set<std::tuple<uint32_t,std::string>> names;
    std::set<std::tuple<unsigned,uint32_t,uint64_t>> annotated,bookmarked;
    const auto id=[&](uint64_t value){require(value!=0 && value!=UINT64_MAX && ids.insert(value).second,"Invalid or duplicate entity ID");};
    const auto location_key=[](Location value){if(auto address=std::get_if<Address>(&value))return std::tuple<unsigned,uint32_t,uint64_t>{0,address->space.value,address->offset};return std::tuple<unsigned,uint32_t,uint64_t>{1,0,std::get<FileOffset>(value).value};};
    const auto range=[](Address begin,uint64_t size){require(size!=0 && bool(AddressRange::create(begin,size)),"Invalid decision range");};
    require(user.annotations.size()<=project_record_limit && user.bookmarks.size()<=project_record_limit && user.breakpoints.size()<=project_record_limit && user.decisions.regions.size()<=project_record_limit && user.decisions.functions.size()<=project_record_limit && user.decisions.references.size()<=project_record_limit && user.patches.size()<=project_record_limit && user.debug_variables.size()<=project_record_limit,"Project record count exceeds budget");
    for(const auto& annotation:user.annotations){
        charge(16+location_size(annotation.location));charge(annotation.name.size());charge(annotation.comment.size());
        id(annotation.id);require(annotated.insert(location_key(annotation.location)).second,"Duplicate annotation location");
        require(annotation.name.size()<=512 && utf8(annotation.name,true),"Invalid UTF-8 name or name length");
        require(annotation.comment.size()<=1024*1024 && utf8(annotation.comment,false),"Invalid UTF-8 comment or comment length");
        require(!annotation.name.empty() || !annotation.comment.empty(),"Empty annotation must be removed");
        if(!annotation.name.empty()){auto address=std::get_if<Address>(&annotation.location);require(address!=nullptr,"Names require an address domain");require(names.emplace(address->space.value,annotation.name).second,"Duplicate name in address space");}
    }
    for(const auto& bookmark:user.bookmarks){charge(12+location_size(bookmark.location));charge(bookmark.label.size());id(bookmark.id);require(bookmarked.insert(location_key(bookmark.location)).second,"Duplicate bookmark location");require(bookmark.label.size()<=512 && utf8(bookmark.label,true),"Invalid bookmark label");}
    std::set<std::pair<uint32_t,uint64_t>> breakpoint_addresses;
    for(const auto& row:user.breakpoints){charge(27+row.condition.size()+row.log_message.size()+16);id(row.id);require(static_cast<unsigned>(row.kind)<=5,"Invalid project breakpoint kind");require(row.size==1||row.size==2||row.size==4||row.size==8,"Invalid project breakpoint size");if(row.kind==ProjectBreakpointKind::software||row.kind==ProjectBreakpointKind::hardware||row.kind==ProjectBreakpointKind::execute)require(row.size==1,"Execution breakpoints have a fixed size of one byte");require(bool(AddressRange::create(row.address,1)),"Invalid project breakpoint address");require(breakpoint_addresses.emplace(row.address.space.value,row.address.offset).second,"Duplicate project breakpoint address");require(row.condition.size()<=256&&utf8(row.condition,false),"Invalid project breakpoint condition");require(row.log_message.size()<=1024&&utf8(row.log_message,false),"Invalid project breakpoint log message");}
    std::set<std::string> type_names;std::set<uint64_t> type_ids;
    for(const auto& row:user.types){id(row.id);charge(18+row.name.size());require(declaration_type_matches(row.declaration_kind,row.type.get()),"Declaration kind does not match its type");require(row.type && row.name.size()<=512 && utf8(row.name,true) && type_names.insert(row.name).second,"Invalid or duplicate type name");type_ids.insert(row.id);auto encoded=types::encode(*row.type);require(bool(encoded),"Invalid type definition");charge(encoded.value().size());if(row.origin){const auto& origin=*row.origin;require(!origin.source_id.empty()&&origin.source_id.size()<=1024&&utf8(origin.source_id,false)&&!origin.section.empty()&&origin.section.size()<=256&&utf8(origin.section,false)&&origin.record_size>0,"Invalid DWARF type source origin");charge(origin.source_id.size()+origin.section.size()+32);}}
    std::set<std::tuple<unsigned,uint32_t,uint64_t>> typed_locations;
    for(const auto& row:user.type_assignments){id(row.id);charge(24+location_size(row.location));require(type_ids.contains(row.type_id),"Type assignment references an unknown definition");require(std::holds_alternative<Address>(row.location),"Types can only be assigned to address symbols");require(typed_locations.insert(location_key(row.location)).second,"Duplicate type assignment");}
    std::set<std::tuple<std::string,std::string,std::uint64_t,std::uint64_t>> dwarf_origins;
    std::set<std::pair<std::uint32_t,std::uint64_t>> function_entries;
    for(const auto& function:user.decisions.functions)function_entries.emplace(function.entry.space.value,function.entry.offset);
    for(const auto& row:user.debug_variables){
        id(row.id);charge(105+row.name.size()+row.origin.source_id.size()+row.origin.section.size()+row.location_expression.size()+row.location_operations.size()*29);
        require(row.name.size()<=1024 && utf8(row.name,true),"Invalid DWARF variable name");
        require(!row.origin.source_id.empty() && row.origin.source_id.size()<=1024 && utf8(row.origin.source_id,false) &&
                    !row.origin.section.empty() && row.origin.section.size()<=256 && utf8(row.origin.section,false) && row.origin.record_size>0,
                "Invalid DWARF variable source origin");
        require(row.location_expression.size()<=65536 && row.location_operations.size()<=4096 && row.location_ranges.size()<=4096,"DWARF variable location exceeds its storage budget");
        require(!(row.address && !row.location_expression.empty()),"DWARF variable cannot have both a direct address and an expression");
        require(!row.cfa_offset || (!row.address && !row.location_expression.empty()),"DWARF CFA offset requires an expression location");
        for(const auto& operation:row.location_operations)require(operation.kind<=20 && (operation.kind!=16 || operation.second_unsigned_operand<=9) && !row.location_expression.empty() && operation.expression_offset<row.location_expression.size(),"Invalid DWARF location operation");
        size_t range_expr=0,range_ops=0,range_payload=4;bool default_seen=false;for(const auto& range:row.location_ranges){const bool is_default=range.begin==UINT64_MAX&&range.end==UINT64_MAX;require((range.begin<range.end||is_default)&&(!is_default||!default_seen)&&range.expression.size()<=65536-range_expr&&range.operations.size()<=4096-range_ops,"Invalid DWARF location range");default_seen|=is_default;range_expr+=range.expression.size();range_ops+=range.operations.size();require(range_payload<=1048576-24 && range.expression.size()<=1048576-range_payload-24 && range.operations.size()*29<=1048576-range_payload-24-range.expression.size(),"DWARF location ranges exceed their encoded storage budget");range_payload+=24+range.expression.size()+range.operations.size()*29;for(const auto& op:range.operations)require(op.kind<=20 && (op.kind!=16 || op.second_unsigned_operand<=9) && !range.expression.empty() && op.expression_offset<range.expression.size(),"Invalid DWARF range operation");}charge(range_payload);
        require(function_entries.contains({row.function_entry.space.value,row.function_entry.offset}),"DWARF variable references an unknown function");
        require(!row.type_id || type_ids.contains(*row.type_id),"DWARF variable references an unknown type definition");
        require(dwarf_origins.emplace(row.origin.source_id,row.origin.section,row.origin.unit_offset,row.origin.record_offset).second,"Duplicate DWARF variable source origin");
    }
    for(const auto& region:user.decisions.regions){charge(30);id(region.id);range(region.begin,region.size);require(region.kind==RegionKind::code || region.kind==RegionKind::data,"Unknown region kind");}
    std::set<std::pair<uint32_t,uint64_t>> entries;
    size_t chunk_count=0;
    for(const auto& function:user.decisions.functions){
        id(function.id);require(entries.emplace(function.entry.space.value,function.entry.offset).second,"Duplicate function decision entry");require(function.chunks.size()<=project_record_limit,"Too many function chunks");
        require(function.chunks.size()<=project_record_limit-chunk_count,"Too many project function chunks");chunk_count+=function.chunks.size();charge(26);charge(function.chunks.size()*25);
        auto chunks=function.chunks;std::sort(chunks.begin(),chunks.end(),[](const auto& a,const auto& b){return std::tie(a.begin.space.value,a.begin.offset)<std::tie(b.begin.space.value,b.begin.offset);});
        for(size_t i=0;i<chunks.size();++i){range(chunks[i].begin,chunks[i].size);if(i && chunks[i-1].begin.space==chunks[i].begin.space)require(chunks[i-1].begin.offset+chunks[i-1].size<=chunks[i].begin.offset,"Overlapping chunks within one function");}
    }
    for(const auto& ref:user.decisions.references){charge(9+location_size(ref.source)+location_size(ref.target));id(ref.id);require(static_cast<unsigned>(ref.kind)<=static_cast<unsigned>(UserReferenceKind::address),"Unknown explicit reference kind");}
    uint64_t end=0;
    for(const auto& patch:user.patches){require(!patch.original.empty() && patch.original.size()==patch.replacement.size() && patch.original.size()<=1024*1024 && patch.begin.value>=end,"Noncanonical patch spans");charge(12+2*patch.original.size());auto limit=checked_add(patch.begin.value,patch.original.size());require(bool(limit),"Patch extent overflow");end=limit.value();for(size_t i=0;i<patch.original.size();++i)require(patch.original[i]!=patch.replacement[i],"Unchanged bytes in patch span");}
}
template<class F> auto guarded(F operation)->decltype(operation()){
    try{return operation();}catch(const Failure& error){return error.error;}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate project records"};}catch(const std::length_error&){return Error{ErrorCode::resource_limit,"Project record allocation exceeds limits"};}
}
}
Result<bool> validate_user_state(const UserState& user){return guarded([&]()->Result<bool>{validate(user);return true;});}
Result<std::vector<std::byte>> encode_location(Location location){return guarded([&]()->Result<std::vector<std::byte>>{Writer writer;writer.location(location);return std::move(writer.bytes);});}
Result<Location> decode_location(std::span<const std::byte> input){return guarded([&]()->Result<Location>{Reader reader{input};auto location=reader.location();reader.finish();return location;});}
Result<std::vector<std::byte>> encode_user_state(const UserState& user){
    return guarded([&]()->Result<std::vector<std::byte>>{
        validate(user);Writer out;out.number(10,1);out.number(0,1);
        out.count(user.annotations.size());for(const auto& row:user.annotations){out.number(row.id,8);out.location(row.location);out.text(row.name);out.text(row.comment);}
        out.count(user.bookmarks.size());for(const auto& row:user.bookmarks){out.number(row.id,8);out.location(row.location);out.text(row.label);}
        out.count(user.breakpoints.size());for(const auto& row:user.breakpoints){out.number(row.id,8);out.address(row.address);out.number(static_cast<unsigned>(row.kind),1);out.number(row.enabled,1);out.number(row.size,1);out.text(row.condition);out.number(row.logpoint,1);out.text(row.log_message);out.number(row.ignore_count,8);out.number(row.one_shot,1);}
        out.count(user.types.size());for(const auto& row:user.types){out.number(row.id,8);out.text(row.name);auto data=types::encode(*row.type);require(bool(data),"Invalid type definition encoding");out.number(data.value().size(),4);out.append(data.value());out.number(row.origin.has_value(),1);if(row.origin){out.text(row.origin->source_id);out.text(row.origin->section);out.number(row.origin->unit_offset,8);out.number(row.origin->record_offset,8);out.number(row.origin->record_size,8);}out.number(static_cast<unsigned>(row.declaration_kind),1);}
        out.count(user.type_assignments.size());for(const auto& row:user.type_assignments){out.number(row.id,8);out.location(row.location);out.number(row.type_id,8);}
        out.count(user.decisions.regions.size());for(const auto& row:user.decisions.regions){out.number(row.id,8);out.address(row.begin);out.number(row.size,8);out.number(static_cast<unsigned>(row.kind),1);}
        out.count(user.decisions.functions.size());for(const auto& row:user.decisions.functions){out.number(row.id,8);out.address(row.entry);out.number(row.suppressed,1);out.count(row.chunks.size());for(const auto& chunk:row.chunks){out.address(chunk.begin);out.number(chunk.size,8);}}
        out.count(user.decisions.references.size());for(const auto& row:user.decisions.references){out.number(row.id,8);out.location(row.source);out.location(row.target);out.number(static_cast<unsigned>(row.kind),1);}
        out.count(user.patches.size());for(const auto& row:user.patches){out.number(row.begin.value,8);out.number(row.original.size(),4);out.append(row.original);out.append(row.replacement);}
        out.count(user.debug_variables.size());for(const auto& row:user.debug_variables){
            out.number(row.id,8);out.address(row.function_entry);out.text(row.name);out.number(row.type_id.has_value(),1);if(row.type_id)out.number(*row.type_id,8);
            out.number(row.is_parameter,1);out.number(row.scope_offset,8);out.number(row.address.has_value(),1);if(row.address)out.number(*row.address,8);
            out.number(row.cfa_offset.has_value(),1);if(row.cfa_offset)out.number(static_cast<std::uint64_t>(*row.cfa_offset),8);
            out.number(row.location_expression.size(),4);out.append(std::as_bytes(std::span(row.location_expression)));
            out.count(row.location_operations.size());for(const auto& operation:row.location_operations){out.number(operation.kind,1);out.number(operation.unsigned_operand,8);out.number(static_cast<std::uint64_t>(operation.signed_operand),8);out.number(operation.expression_offset,4);out.number(operation.second_unsigned_operand,8);}
            out.text(row.origin.source_id);out.text(row.origin.section);out.number(row.origin.unit_offset,8);out.number(row.origin.record_offset,8);out.number(row.origin.record_size,8);
            out.count(row.location_ranges.size());for(const auto& range:row.location_ranges){out.number(range.begin,8);out.number(range.end,8);out.number(range.expression.size(),4);out.append(std::as_bytes(std::span(range.expression)));out.count(range.operations.size());for(const auto& operation:range.operations){out.number(operation.kind,1);out.number(operation.unsigned_operand,8);out.number(static_cast<std::uint64_t>(operation.signed_operand),8);out.number(operation.expression_offset,4);out.number(operation.second_unsigned_operand,8);}}
        }
        return std::move(out.bytes);
    });
}
Result<UserState> decode_user_state(std::span<const std::byte> input){
    return guarded([&]()->Result<UserState>{
        require(input.size()<=project_payload_limit,"Project payload exceeds budget");Reader in{input};const auto version=in.number(1);require((version>=1&&version<=10) && in.number(1)==0,"Unknown project record version");UserState user;
        for(size_t count=in.count(25);count;--count){auto id=in.number(8);auto location=in.location();auto name=in.text(512);auto comment=in.text(1024*1024);user.annotations.push_back({id,location,std::move(name),std::move(comment)});}
        for(size_t count=in.count(21);count;--count){auto id=in.number(8);auto location=in.location();auto label=in.text(512);user.bookmarks.push_back({id,location,std::move(label)});}
        if(version>=8)for(size_t count=in.count(version>=10?41:version>=9?40:24);count;--count){ProjectBreakpoint row;row.id=in.number(8);row.address=in.address();const auto kind=in.number(1),enabled=in.number(1),size=in.number(1);require(kind<=5&&enabled<=1,"Invalid project breakpoint fields");row.kind=static_cast<ProjectBreakpointKind>(kind);row.enabled=enabled!=0;row.size=static_cast<std::uint8_t>(size);if(version>=9){row.condition=in.text(256);const auto logpoint=in.number(1);require(logpoint<=1,"Invalid project breakpoint logpoint flag");row.logpoint=logpoint!=0;row.log_message=in.text(1024);row.ignore_count=in.number(8);if(version>=10){const auto one_shot=in.number(1);require(one_shot<=1,"Invalid project breakpoint one-shot flag");row.one_shot=one_shot!=0;}}user.breakpoints.push_back(std::move(row));}
        if(version>=2){for(size_t count=in.count(version>=7?18:version>=6?17:16);count;--count){auto id=in.number(8);auto name=in.text(512);auto size=in.number(4);auto data=in.read(static_cast<size_t>(size));auto type=types::decode(data);if(!type)throw Failure{type.error()};std::optional<DwarfSourceOrigin> origin;if(version>=6){const auto present=in.number(1);require(present<=1,"Invalid type source-origin flag");if(present){DwarfSourceOrigin value;value.source_id=in.text(1024);value.section=in.text(256);value.unit_offset=in.number(8);value.record_offset=in.number(8);value.record_size=in.number(8);origin=std::move(value);}}DeclarationKind kind=DeclarationKind::type;if(version>=7){const auto value=in.number(1);require(value<=static_cast<unsigned>(DeclarationKind::function),"Invalid declaration kind");kind=static_cast<DeclarationKind>(value);}user.types.push_back({id,std::move(name),std::move(type.value()),std::move(origin),kind});}for(size_t count=in.count(17);count;--count){auto id=in.number(8);auto location=in.location();auto type_id=in.number(8);user.type_assignments.push_back({id,location,type_id});}}
        for(size_t count=in.count(29);count;--count){auto id=in.number(8);auto begin=in.address();auto size=in.number(8);auto kind=static_cast<RegionKind>(in.number(1));user.decisions.regions.push_back({id,begin,size,kind});}
        for(size_t count=in.count(25);count;--count){auto id=in.number(8);auto entry=in.address();auto suppressed=in.number(1);require(suppressed<=1,"Invalid suppressed flag");FunctionDecision function{id,entry,suppressed!=0,{}};for(size_t chunks=in.count(20);chunks;--chunks){auto begin=in.address();auto size=in.number(8);function.chunks.push_back({begin,size});}user.decisions.functions.push_back(std::move(function));}
        for(size_t count=in.count(27);count;--count){auto id=in.number(8);auto source=in.location();auto target=in.location();auto kind=static_cast<UserReferenceKind>(in.number(1));user.decisions.references.push_back({id,source,target,kind});}
        for(size_t count=in.count(14);count;--count){const auto begin=in.number(8),size=in.number(4);require(size>0 && size<=1024*1024,"Invalid patch payload extent");auto original=in.read(static_cast<size_t>(size));auto replacement=in.read(static_cast<size_t>(size));user.patches.push_back({{begin},{original.begin(),original.end()},{replacement.begin(),replacement.end()}});}
        if(version>=3)for(size_t count=in.count(79);count;--count){
            DebugVariable row;row.id=in.number(8);row.function_entry=in.address();row.name=in.text(1024);const auto has_type=in.number(1);require(has_type<=1,"Invalid DWARF variable type flag");if(has_type)row.type_id=in.number(8);
            const auto parameter=in.number(1);require(parameter<=1,"Invalid DWARF parameter flag");row.is_parameter=parameter!=0;row.scope_offset=in.number(8);const auto has_address=in.number(1);require(has_address<=1,"Invalid DWARF location address flag");if(has_address)row.address=in.number(8);
            if(version>=4){const auto has_cfa_offset=in.number(1);require(has_cfa_offset<=1,"Invalid DWARF CFA offset flag");if(has_cfa_offset)row.cfa_offset=static_cast<std::int64_t>(in.number(8));}
            const auto expression_size=in.number(4);require(expression_size<=65536,"DWARF location expression exceeds its limit");auto expression=in.read(static_cast<size_t>(expression_size));for(auto byte:expression)row.location_expression.push_back(std::to_integer<std::uint8_t>(byte));
            for(size_t operations=in.count(29);operations;--operations){DebugLocationOperation operation;operation.kind=static_cast<std::uint8_t>(in.number(1));operation.unsigned_operand=in.number(8);operation.signed_operand=static_cast<std::int64_t>(in.number(8));operation.expression_offset=static_cast<std::uint32_t>(in.number(4));operation.second_unsigned_operand=in.number(8);row.location_operations.push_back(operation);}
            row.origin.source_id=in.text(1024);row.origin.section=in.text(256);row.origin.unit_offset=in.number(8);row.origin.record_offset=in.number(8);row.origin.record_size=in.number(8);
            if(version>=5)for(size_t ranges=in.count(20);ranges;--ranges){DebugLocationRange range;range.begin=in.number(8);range.end=in.number(8);const auto size=in.number(4);require(size<=65536,"DWARF range expression exceeds its limit");auto expression=in.read(static_cast<size_t>(size));for(auto byte:expression)range.expression.push_back(std::to_integer<std::uint8_t>(byte));for(size_t ops=in.count(29);ops;--ops){DebugLocationOperation op;op.kind=static_cast<std::uint8_t>(in.number(1));op.unsigned_operand=in.number(8);op.signed_operand=static_cast<std::int64_t>(in.number(8));op.expression_offset=static_cast<std::uint32_t>(in.number(4));op.second_unsigned_operand=in.number(8);range.operations.push_back(op);}row.location_ranges.push_back(std::move(range));}
            user.debug_variables.push_back(std::move(row));
        }
        in.finish();validate(user);return user;
    });
}
}
