#include "project_internal.hpp"
#include <algorithm>
namespace hexlab::database::detail {
namespace {
template<class T,class Bind>void sync_rows(Connection& connection,const char* table,const char* insert_sql,const std::vector<T>& before,const std::vector<T>& after,Bind bind){
    const auto find=[](const auto& rows,uint64_t id){auto it=std::lower_bound(rows.begin(),rows.end(),id,[](const auto& row,uint64_t value){return row.id<value;});return it!=rows.end() && it->id==id?&*it:nullptr;};
    auto remove=take(connection.prepare(std::string("DELETE FROM ")+table+" WHERE id=?1"));
    // Delete all changed rows first, allowing atomic swaps of unique names/entries.
    for(const auto& row:before){const auto* next=find(after,row.id);if(!next || *next!=row){take(remove->bind_blob(1,encode_u64(row.id)));take(remove->step());take(remove->reset());}}
    auto insert=take(connection.prepare(insert_sql));
    for(const auto& row:after){const auto* old=find(before,row.id);if(!old || *old!=row){take(insert->bind_blob(1,encode_u64(row.id)));bind(*insert,row);take(insert->step());take(insert->reset());}}
}
void sync_type_definitions(Connection& connection, const std::vector<TypeDefinition>& before,
                           const std::vector<TypeDefinition>& after) {
    const auto find=[](const auto& rows,uint64_t id){auto it=std::lower_bound(rows.begin(),rows.end(),id,[](const auto& row,uint64_t value){return row.id<value;});return it!=rows.end() && it->id==id?&*it:nullptr;};
    auto remove=take(connection.prepare("DELETE FROM type_definitions WHERE id=?1"));
    for(const auto& row:before)if(!find(after,row.id)){take(remove->bind_blob(1,encode_u64(row.id)));take(remove->step());take(remove->reset());}
    auto insert=take(connection.prepare("INSERT INTO type_definitions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)"));
    auto update=take(connection.prepare("UPDATE type_definitions SET name=?2,payload=?3,source_id=?4,source_section=?5,unit_offset=?6,record_offset=?7,record_size=?8,declaration_kind=?9 WHERE id=?1"));
    for(const auto& row:after){
        const auto* old=find(before,row.id);
        if(old && *old==row)continue;
        auto& sql=old?*update:*insert;
        take(sql.bind_blob(1,encode_u64(row.id)));
        take(sql.bind_text(2,row.name));
        take(sql.bind_blob(3,take(types::encode(*row.type))));
        if(row.origin){
            take(sql.bind_text(4,row.origin->source_id));take(sql.bind_text(5,row.origin->section));
            take(sql.bind_blob(6,encode_u64(row.origin->unit_offset)));take(sql.bind_blob(7,encode_u64(row.origin->record_offset)));take(sql.bind_blob(8,encode_u64(row.origin->record_size)));
        }else for(int column=4;column<=8;++column)take(sql.bind_null(column));
        take(sql.bind_integer(9,static_cast<unsigned>(row.declaration_kind)));
        take(sql.step());take(sql.reset());
    }
}
std::vector<std::byte> encode_location_operations(const std::vector<DebugLocationOperation>& operations) {
    std::vector<std::byte> bytes; bytes.reserve(operations.size()*29);
    const auto number=[&](std::uint64_t value,unsigned width){for(unsigned i=0;i<width;++i)bytes.push_back(std::byte(value>>(8*(width-i-1))));};
    for(const auto& operation:operations){number(operation.kind,1);number(operation.unsigned_operand,8);number(static_cast<std::uint64_t>(operation.signed_operand),8);number(operation.expression_offset,4);number(operation.second_unsigned_operand,8);}
    return bytes;
}
}
Result<std::vector<std::byte>> encode_location_ranges(const std::vector<DebugLocationRange>& ranges) {
    if (ranges.size() > 4096) return Error{ErrorCode::resource_limit,"Too many DWARF location ranges"};
    std::vector<std::byte> bytes; const auto number=[&](std::uint64_t value,unsigned width){for(unsigned i=0;i<width;++i)bytes.push_back(std::byte(value>>(8*(width-i-1))));};
    number(ranges.size(),4); size_t expression_bytes=0, operation_count=0; bool default_seen=false;
    for(const auto& range:ranges){const bool is_default=range.begin==UINT64_MAX&&range.end==UINT64_MAX;if((range.begin>=range.end&&!is_default)||(is_default&&default_seen)||range.expression.size()>65536-expression_bytes||range.operations.size()>4096-operation_count)return Error{ErrorCode::malformed,"Invalid or oversized DWARF location ranges"};default_seen|=is_default;expression_bytes+=range.expression.size();operation_count+=range.operations.size();
        number(range.begin,8);number(range.end,8);number(range.expression.size(),4);for(auto byte:range.expression)bytes.push_back(std::byte(byte));number(range.operations.size(),4);
        for(const auto& op:range.operations){number(op.kind,1);number(op.unsigned_operand,8);number(static_cast<std::uint64_t>(op.signed_operand),8);number(op.expression_offset,4);number(op.second_unsigned_operand,8);}
        if(bytes.size()>1048576)return Error{ErrorCode::resource_limit,"DWARF location ranges exceed storage budget"};
    } return bytes;
}
Result<std::vector<DebugLocationRange>> decode_location_ranges(std::span<const std::byte> bytes) {
    if(bytes.empty())return std::vector<DebugLocationRange>{};
    size_t cursor=0;const auto number=[&](unsigned width)->std::optional<std::uint64_t>{if(width>bytes.size()-cursor)return {};std::uint64_t value=0;while(width--)value=(value<<8)|std::to_integer<unsigned>(bytes[cursor++]);return value;};
    auto count=number(4);if(!count||*count>4096)return Error{ErrorCode::malformed,"Invalid DWARF location range count"};std::vector<DebugLocationRange> result;size_t expr_total=0,ops_total=0;
    bool default_seen=false; for(std::uint64_t i=0;i<*count;++i){auto begin=number(8),end=number(8),size=number(4);const bool is_default=begin&&end&&*begin==UINT64_MAX&&*end==UINT64_MAX;if(!begin||!end||!size||(*begin>=*end&&!is_default)||(is_default&&default_seen)||*size>65536-expr_total||*size>bytes.size()-cursor)return Error{ErrorCode::malformed,"Invalid DWARF location range"};default_seen|=is_default;DebugLocationRange row;row.begin=*begin;row.end=*end;expr_total+=*size;for(std::uint64_t j=0;j<*size;++j)row.expression.push_back(std::to_integer<std::uint8_t>(bytes[cursor++]));auto ops=number(4);if(!ops||*ops>4096-ops_total||*ops>(bytes.size()-cursor)/29)return Error{ErrorCode::malformed,"Invalid DWARF range operation count"};ops_total+=*ops;
        for(std::uint64_t j=0;j<*ops;++j){DebugLocationOperation op;op.kind=static_cast<std::uint8_t>(*number(1));op.unsigned_operand=*number(8);op.signed_operand=static_cast<std::int64_t>(*number(8));op.expression_offset=static_cast<std::uint32_t>(*number(4));op.second_unsigned_operand=*number(8);if(op.kind>20||(op.kind==16&&op.second_unsigned_operand>9)||row.expression.empty()||op.expression_offset>=row.expression.size())return Error{ErrorCode::malformed,"Invalid DWARF range operation"};row.operations.push_back(op);}result.push_back(std::move(row));
    } if(cursor!=bytes.size())return Error{ErrorCode::malformed,"Trailing DWARF range bytes"};return result;
}
namespace {
void sync_debug_variables(Connection& connection,const std::vector<DebugVariable>& before,const std::vector<DebugVariable>& after) {
    const auto find=[](const auto& rows,std::uint64_t id){auto it=std::lower_bound(rows.begin(),rows.end(),id,[](const auto& row,std::uint64_t value){return row.id<value;});return it!=rows.end()&&it->id==id?&*it:nullptr;};
    auto remove=take(connection.prepare("DELETE FROM debug_variables WHERE id=?1"));
    for(const auto& row:before){const auto* next=find(after,row.id);if(!next||*next!=row){take(remove->bind_blob(1,encode_u64(row.id)));take(remove->step());take(remove->reset());}}
    auto insert=take(connection.prepare("INSERT INTO debug_variables VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"));
    for(const auto& row:after){const auto* old=find(before,row.id);if(old&&*old==row)continue;
        take(insert->bind_blob(1,encode_u64(row.id)));take(insert->bind_blob(2,take(encode_location(Location{row.function_entry}))));take(insert->bind_text(3,row.name));
        if(row.type_id)take(insert->bind_blob(4,encode_u64(*row.type_id)));else take(insert->bind_null(4));
        take(insert->bind_integer(5,row.is_parameter));take(insert->bind_blob(6,encode_u64(row.scope_offset)));
        if(row.address)take(insert->bind_blob(7,encode_u64(*row.address)));else take(insert->bind_null(7));
        take(insert->bind_blob(8,std::as_bytes(std::span(row.location_expression))));take(insert->bind_blob(9,encode_location_operations(row.location_operations)));
        take(insert->bind_text(10,row.origin.source_id));take(insert->bind_text(11,row.origin.section));take(insert->bind_blob(12,encode_u64(row.origin.unit_offset)));take(insert->bind_blob(13,encode_u64(row.origin.record_offset)));take(insert->bind_blob(14,encode_u64(row.origin.record_size)));
        if(row.cfa_offset)take(insert->bind_blob(15,encode_u64(static_cast<std::uint64_t>(*row.cfa_offset))));else take(insert->bind_null(15));
        take(insert->bind_blob(16,take(encode_location_ranges(row.location_ranges))));
        take(insert->step());take(insert->reset());
    }
}
void sync_project_breakpoints(Connection& connection,const std::vector<ProjectBreakpoint>& before,
                              const std::vector<ProjectBreakpoint>& after) {
    const auto find=[](const auto& rows,std::uint64_t id){auto it=std::lower_bound(rows.begin(),rows.end(),id,[](const auto& row,std::uint64_t value){return row.id<value;});return it!=rows.end()&&it->id==id?&*it:nullptr;};
    auto remove=take(connection.prepare("DELETE FROM project_breakpoints WHERE id=?1"));
    auto insert=take(connection.prepare("INSERT INTO project_breakpoints(id,address,kind,enabled,size,condition,logpoint,log_message,ignore_count,hit_count,one_shot) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"));
    auto update=take(connection.prepare("UPDATE project_breakpoints SET address=?2,kind=?3,enabled=?4,size=?5,condition=?6,logpoint=?7,log_message=?8,ignore_count=?9,one_shot=?10 WHERE id=?1"));
    const auto bind=[&](Statement& sql,const ProjectBreakpoint& row){
        take(sql.bind_blob(1,encode_u64(row.id)));take(sql.bind_blob(2,take(encode_location(Location{row.address}))));
        take(sql.bind_integer(3,static_cast<unsigned>(row.kind)));take(sql.bind_integer(4,row.enabled));take(sql.bind_integer(5,row.size));
        take(sql.bind_text(6,row.condition));take(sql.bind_integer(7,row.logpoint));take(sql.bind_text(8,row.log_message));
        take(sql.bind_blob(9,encode_u64(row.ignore_count)));
    };
    for(const auto& row:before)if(!find(after,row.id)){take(remove->bind_blob(1,encode_u64(row.id)));take(remove->step());take(remove->reset());}
    for(const auto& row:after){const auto* old=find(before,row.id);if(old&&*old==row)continue;auto& sql=old?*update:*insert;bind(sql,row);if(old)take(sql.bind_integer(10,row.one_shot));else{take(sql.bind_blob(10,encode_u64(row.hit_count)));take(sql.bind_integer(11,row.one_shot));}take(sql.step());take(sql.reset());}
}
}
void write_user_state(Connection& connection,const UserState& before,const UserState& after){
    sync_rows(connection,"annotations","INSERT INTO annotations VALUES(?1,?2,?3,?4)",before.annotations,after.annotations,[](Statement& sql,const Annotation& row){take(sql.bind_blob(2,take(encode_location(row.location))));take(sql.bind_text(3,row.name));take(sql.bind_text(4,row.comment));});
    sync_rows(connection,"bookmarks","INSERT INTO bookmarks VALUES(?1,?2,?3)",before.bookmarks,after.bookmarks,[](Statement& sql,const Bookmark& row){take(sql.bind_blob(2,take(encode_location(row.location))));take(sql.bind_text(3,row.label));});
    sync_project_breakpoints(connection,before.breakpoints,after.breakpoints);
    sync_type_definitions(connection,before.types,after.types);
    sync_rows(connection,"type_assignments","INSERT INTO type_assignments VALUES(?1,?2,?3)",before.type_assignments,after.type_assignments,[](Statement& sql,const TypeAssignment& row){take(sql.bind_blob(2,take(encode_location(row.location))));take(sql.bind_blob(3,encode_u64(row.type_id)));});
    sync_debug_variables(connection,before.debug_variables,after.debug_variables);
    sync_rows(connection,"regions","INSERT INTO regions VALUES(?1,?2,?3,?4)",before.decisions.regions,after.decisions.regions,[](Statement& sql,const RegionDecision& row){take(sql.bind_blob(2,take(encode_location(row.begin))));take(sql.bind_blob(3,encode_u64(row.size)));take(sql.bind_integer(4,static_cast<int>(row.kind)));});
    // Function child rows follow their changed parent, in the same transaction.
    sync_rows(connection,"functions","INSERT INTO functions VALUES(?1,?2,?3)",before.decisions.functions,after.decisions.functions,[](Statement& sql,const FunctionDecision& row){take(sql.bind_blob(2,take(encode_location(row.entry))));take(sql.bind_integer(3,row.suppressed));});
    auto chunks=take(connection.prepare("INSERT INTO function_chunks VALUES(?1,?2,?3,?4)"));
    for(const auto& function:after.decisions.functions){
        auto old=std::lower_bound(before.decisions.functions.begin(),before.decisions.functions.end(),function.id,[](const auto& row,uint64_t id){return row.id<id;});
        if(old!=before.decisions.functions.end() && old->id==function.id && *old==function)continue;
        for(size_t i=0;i<function.chunks.size();++i){const auto& chunk=function.chunks[i];take(chunks->bind_blob(1,encode_u64(function.id)));take(chunks->bind_integer(2,i));take(chunks->bind_blob(3,take(encode_location(chunk.begin))));take(chunks->bind_blob(4,encode_u64(chunk.size)));take(chunks->step());take(chunks->reset());}
    }
    sync_rows(connection,"explicit_references","INSERT INTO explicit_references VALUES(?1,?2,?3,?4)",before.decisions.references,after.decisions.references,[](Statement& sql,const UserReference& row){take(sql.bind_blob(2,take(encode_location(row.source))));take(sql.bind_blob(3,take(encode_location(row.target))));take(sql.bind_integer(4,static_cast<int>(row.kind)));});
    if(before.patches!=after.patches){
        take(connection.execute("DELETE FROM patches"));auto patch=take(connection.prepare("INSERT INTO patches VALUES(?1,?2,?3)"));
        for(const auto& row:after.patches){take(patch->bind_blob(1,encode_u64(row.begin.value)));take(patch->bind_blob(2,row.original));take(patch->bind_blob(3,row.replacement));take(patch->step());take(patch->reset());}
    }
}
}
