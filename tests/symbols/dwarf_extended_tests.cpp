#include "hexlab/symbols/dwarf.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>
#include <vector>
#if defined(_MSC_VER)
#include <crtdbg.h>
#endif

namespace {
using namespace hexlab;
using namespace hexlab::symbols;
struct Attr { std::uint64_t name,form; std::variant<std::string,std::uint64_t,std::int64_t,std::vector<std::uint8_t>,struct Node*> value; };
struct Node { std::uint64_t code; std::vector<Attr> attrs; std::vector<Node*> children; std::uint64_t offset=0; };
struct Abbr { std::uint64_t code,tag;bool children;std::vector<std::pair<std::uint64_t,std::uint64_t>> attrs; };
struct Data {std::vector<std::uint8_t> info,abbrev,strings;std::vector<std::size_t> reference_patches;};
void put(std::vector<std::uint8_t>&o,std::uint64_t v,unsigned n){for(unsigned i=0;i<n;++i)o.push_back(static_cast<std::uint8_t>(v>>(8*i)));}
void uleb(std::vector<std::uint8_t>&o,std::uint64_t v){do{auto b=std::uint8_t(v&0x7f);v>>=7;if(v)b|=0x80;o.push_back(b);}while(v);}
void sleb(std::vector<std::uint8_t>&o,std::int64_t v){bool more=true;while(more){auto b=std::uint8_t(v&0x7f);v>>=7;const bool sign=(b&0x40)!=0;more=!((v==0&&!sign)||(v==-1&&sign));if(more)b|=0x80;o.push_back(b);}}
std::vector<Abbr> definitions(){return {
 {1,0x11,true,{{0x03,0x08}}}, {2,0x24,false,{{0x03,0x08},{0x0b,0x0b},{0x3e,0x0b}}},
 {3,0x13,true,{{0x03,0x08},{0x0b,0x06}}}, {4,0x0d,false,{{0x03,0x08},{0x49,0x13},{0x38,0x06}}},
 {5,0x0f,false,{{0x0b,0x0b},{0x49,0x13}}}, {6,0x16,false,{{0x03,0x08},{0x49,0x13}}},
 {7,0x26,false,{{0x49,0x13}}}, {8,0x01,true,{{0x49,0x13}}},
 {9,0x21,false,{{0x22,0x0d},{0x2f,0x0b}}}, {10,0x04,true,{{0x03,0x08},{0x0b,0x0b},{0x49,0x13}}},
 {11,0x28,false,{{0x03,0x08},{0x1c,0x0d}}}, {12,0x2e,true,{{0x03,0x08},{0x11,0x01},{0x12,0x06},{0x49,0x13}}},
 {13,0x05,false,{{0x03,0x08},{0x49,0x13}}}, {14,0x34,false,{{0x03,0x08},{0x49,0x13},{0x02,0x18}}},
 {15,0x15,true,{{0x49,0x13}}}, {16,0x18,false,{}}, {17,0x17,true,{{0x03,0x08},{0x0b,0x06}}},
 {18,0x2e,true,{{0x11,0x01},{0x12,0x06},{0x47,0x13}}},
 {19,0x2e,true,{{0x03,0x08},{0x49,0x13},{0x3c,0x0c}}},
 {20,0x2e,true,{{0x11,0x01},{0x12,0x06},{0x31,0x13}}}
};}
struct Builder {
    std::vector<std::unique_ptr<Node>> nodes;
    Node* make(std::uint64_t code,std::vector<Attr> attrs={}){nodes.push_back(std::make_unique<Node>(Node{code,std::move(attrs),{},0}));return nodes.back().get();}
    void child(Node*p,Node*c){p->children.push_back(c);}
};
Data build(std::vector<std::uint8_t> local_location={0x91,0x7c},bool with_specification=false,bool cyclic_specification=false){
    const auto defs=definitions();Data d;Builder b;auto cu=b.make(1,{{3,8,std::string("types.c")}});
    auto integer=b.make(2,{{3,8,std::string("int")},{0x0b,0x0b,std::uint64_t(4)},{0x3e,0x0b,std::uint64_t(5)}});b.child(cu,integer);
    auto pointer=b.make(5,{{0x0b,0x0b,std::uint64_t(8)},{0x49,0x13,integer}});b.child(cu,pointer);
    auto alias=b.make(6,{{3,8,std::string("Count")},{0x49,0x13,integer}});b.child(cu,alias);
    auto const_int=b.make(7,{{0x49,0x13,integer}});b.child(cu,const_int);
    auto array=b.make(8,{{0x49,0x13,integer}});b.child(cu,array);b.child(array,b.make(9,{{0x22,0x0d,std::int64_t(0)},{0x2f,0x0b,std::uint64_t(2)}}));
    auto structure=b.make(3,{{3,8,std::string("Record")},{0x0b,0x06,std::uint64_t(32)}});b.child(cu,structure);
    b.child(structure,b.make(4,{{3,8,std::string("id")},{0x49,0x13,integer},{0x38,0x06,std::uint64_t(0)}}));
    b.child(structure,b.make(4,{{3,8,std::string("data")},{0x49,0x13,pointer},{0x38,0x06,std::uint64_t(8)}}));
    b.child(structure,b.make(4,{{3,8,std::string("items")},{0x49,0x13,array},{0x38,0x06,std::uint64_t(16)}}));
    auto un=b.make(17,{{3,8,std::string("Storage")},{0x0b,0x06,std::uint64_t(8)}});b.child(cu,un);
    b.child(un,b.make(4,{{3,8,std::string("word")},{0x49,0x13,integer},{0x38,0x06,std::uint64_t(0)}}));
    b.child(un,b.make(4,{{3,8,std::string("pointer")},{0x49,0x13,pointer},{0x38,0x06,std::uint64_t(0)}}));
    auto en=b.make(10,{{3,8,std::string("Mode")},{0x0b,0x0b,std::uint64_t(4)},{0x49,0x13,integer}});b.child(cu,en);
    b.child(en,b.make(11,{{3,8,std::string("Ready")},{0x1c,0x0d,std::int64_t(1)}}));
    b.child(en,b.make(11,{{3,8,std::string("Failed")},{0x1c,0x0d,std::int64_t(-2)}}));
    auto fn_type=b.make(15,{{0x49,0x13,integer}});b.child(cu,fn_type);
    b.child(fn_type,b.make(13,{{3,8,std::string("value")},{0x49,0x13,alias}}));b.child(fn_type,b.make(16));
    auto sub=b.make(12,{{3,8,std::string("process")},{0x11,0x01,std::uint64_t(0x401000)},{0x12,0x06,std::uint64_t(0x30)},{0x49,0x13,integer}});b.child(cu,sub);
    b.child(sub,b.make(13,{{3,8,std::string("count")},{0x49,0x13,alias}}));
    b.child(sub,b.make(13,{{3,8,std::string("record")},{0x49,0x13,structure}}));
    b.child(sub,b.make(14,{{3,8,std::string("local")},{0x49,0x13,integer},{0x02,0x18,std::move(local_location)}}));
    if(with_specification){
        auto declaration=b.make(19,{{3,8,std::string("specified_function")},{0x49,0x13,integer},{0x3c,0x0c,std::uint64_t(1)}});b.child(cu,declaration);
        b.child(declaration,b.make(13,{{3,8,std::string("declared_value")},{0x49,0x13,alias}}));
        auto definition=b.make(18,{{0x11,0x01,std::uint64_t(0x402000)},{0x12,0x06,std::uint64_t(0x20)},{0x47,0x13,cyclic_specification?static_cast<Node*>(nullptr):declaration}});b.child(cu,definition);
        if(cyclic_specification)definition->attrs.back().value=definition;
        auto abstract=b.make(19,{{3,8,std::string("abstract_function")},{0x49,0x13,integer},{0x3c,0x0c,std::uint64_t(1)}});b.child(cu,abstract);
        b.child(abstract,b.make(13,{{3,8,std::string("abstract_value")},{0x49,0x13,alias}}));
        auto concrete=b.make(20,{{0x11,0x01,std::uint64_t(0x403000)},{0x12,0x06,std::uint64_t(0x10)},{0x31,0x13,abstract}});b.child(cu,concrete);
    }
    for(const auto&a:defs){uleb(d.abbrev,a.code);uleb(d.abbrev,a.tag);d.abbrev.push_back(a.children?1:0);for(auto [n,f]:a.attrs){uleb(d.abbrev,n);uleb(d.abbrev,f);}uleb(d.abbrev,0);uleb(d.abbrev,0);}uleb(d.abbrev,0);
    auto len_pos=d.info.size();put(d.info,0,4);put(d.info,4,2);put(d.info,0,4);d.info.push_back(8);
    std::vector<std::pair<std::size_t,Node*>> patches;
    auto emit=[&](auto&&self,Node*n)->void{n->offset=d.info.size();uleb(d.info,n->code);const auto def=std::find_if(defs.begin(),defs.end(),[&](const Abbr&a){return a.code==n->code;});assert(def!=defs.end());assert(def->attrs.size()==n->attrs.size());for(std::size_t i=0;i<n->attrs.size();++i){auto&v=n->attrs[i].value;auto form=def->attrs[i].second;if(auto*s=std::get_if<std::string>(&v)){d.info.insert(d.info.end(),s->begin(),s->end());d.info.push_back(0);}else if(auto*u=std::get_if<std::uint64_t>(&v)){put(d.info,*u,form==1?8:form==6?4:form==5?2:1);}else if(auto*x=std::get_if<std::int64_t>(&v))sleb(d.info,*x);else if(auto*blob=std::get_if<std::vector<std::uint8_t>>(&v)){uleb(d.info,blob->size());d.info.insert(d.info.end(),blob->begin(),blob->end());}else {auto*target=std::get<Node*>(v);patches.emplace_back(d.info.size(),target);d.reference_patches.push_back(d.info.size());put(d.info,0,4);}}for(auto*c:n->children)self(self,c);if(def->children)uleb(d.info,0);};
    emit(emit,cu);for(auto [at,target]:patches){auto value=target->offset;for(unsigned i=0;i<4;++i)d.info[at+i]=std::uint8_t(value>>(8*i));}auto length=d.info.size()-4;for(unsigned i=0;i<4;++i)d.info[len_pos+i]=std::uint8_t(length>>(8*i));return d;
}
}

int main(){
#if defined(_MSC_VER)
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
    auto data=build();auto imported=import_dwarf_v4({"synthetic.o",data.info,data.abbrev,data.strings});assert(imported);
    const auto&r=imported.value();assert(r.symbols.size()==1&&r.symbols[0].name=="process"&&r.symbols[0].size==0x30);
    assert(r.symbols[0].type&&r.symbols[0].type->kind()==types::Kind::function&&r.symbols[0].type->parameters().size()==2);
    assert(r.symbols[0].origin.source_id=="synthetic.o"&&r.symbols[0].origin.section==".debug_info");
    auto specified_data=build({0x91,0x7c},true);
    auto specified=import_dwarf_v4({"specification.o",specified_data.info,specified_data.abbrev,specified_data.strings});
    assert(specified&&specified.value().symbols.size()==3);
    const auto specified_function=std::find_if(specified.value().symbols.begin(),specified.value().symbols.end(),[](const auto&s){return s.address==0x402000;});
    assert(specified_function!=specified.value().symbols.end()&&specified_function->name=="specified_function"&&specified_function->size==0x20);
    assert(specified_function->type&&specified_function->type->kind()==types::Kind::function&&specified_function->type->result_type()->size()==4);
    assert(specified_function->type->parameters().size()==1&&specified_function->type->parameters()[0].name=="declared_value");
    const auto abstract_function=std::find_if(specified.value().symbols.begin(),specified.value().symbols.end(),[](const auto&s){return s.address==0x403000;});
    assert(abstract_function!=specified.value().symbols.end()&&abstract_function->name=="abstract_function"&&abstract_function->type->parameters().size()==1&&abstract_function->type->parameters()[0].name=="abstract_value");
    auto cyclic_data=build({0x91,0x7c},true,true);
    auto cyclic=import_dwarf_v4({"cyclic-specification.o",cyclic_data.info,cyclic_data.abbrev,cyclic_data.strings});
    assert(!cyclic&&cyclic.error().code==ErrorCode::malformed&&cyclic.error().message.find("cycle")!=std::string::npos);
    auto find_type=[&](std::string_view name){for(const auto&t:r.types)if(t.source_name==name)return t.type;return types::TypePtr{};};
    auto record=find_type("Record");assert(record&&record->kind()==types::Kind::structure&&record->size()==32&&record->members().size()==3);
    assert(record->members()[1].offset==8&&record->members()[2].offset==16&&record->members()[2].type->kind()==types::Kind::array&&record->members()[2].type->count()==3);
    auto storage=find_type("Storage");assert(storage&&storage->kind()==types::Kind::union_type&&storage->size()==8);
    bool saw_alias=false,saw_const=false,saw_pointer=false,saw_function_type=false;for(const auto&t:r.types){saw_alias|=t.is_typedef&&t.source_name=="Count";saw_const|=t.is_const;saw_pointer|=t.type->kind()==types::Kind::pointer;saw_function_type|=t.type->kind()==types::Kind::function;}assert(saw_alias&&saw_const&&saw_pointer&&saw_function_type);
    assert(r.enumerators.size()==2&&r.enumerators[0].name=="Ready"&&r.enumerators[0].value==1&&r.enumerators[1].value==-2);
    assert(r.variables.size()==3);bool local=false,parameter=false;for(const auto&v:r.variables){assert(v.origin.record_size>0&&v.origin.source_id=="synthetic.o");if(v.name=="local"){local=true;assert(!v.is_parameter&&v.scope_offset!=0&&v.location_expression.size()==2);assert(v.location_operations.size()==1&&v.location_operations[0].kind==LocationOperationKind::frame_base_relative&&v.location_operations[0].signed_operand==-4);}if(v.name=="record")parameter=true;}assert(local&&parameter);

    auto rich=build({0x92,0x05,0x70,0x9c,0x11,0x7d,0x9f,0x93,0x04,0x9d,0x08,0x03});auto decoded=import_dwarf_v4({"locations.o",rich.info,rich.abbrev,rich.strings});assert(decoded);const auto&ops=decoded.value().variables.back().location_operations;assert(ops.size()==6);assert(ops[0].kind==LocationOperationKind::base_register_plus_offset&&ops[0].unsigned_operand==5&&ops[0].signed_operand==-16);assert(ops[1].kind==LocationOperationKind::call_frame_cfa);assert(ops[2].kind==LocationOperationKind::signed_constant&&ops[2].signed_operand==-3);assert(ops[3].kind==LocationOperationKind::stack_value);assert(ops[4].kind==LocationOperationKind::piece&&ops[4].unsigned_operand==4);assert(ops[5].kind==LocationOperationKind::bit_piece&&ops[5].unsigned_operand==8&&ops[5].second_unsigned_operand==3);
    auto truncated_expr=build({0x92,0x80});auto truncated_location=import_dwarf_v4({"truncated-expression.o",truncated_expr.info,truncated_expr.abbrev,truncated_expr.strings});assert(!truncated_location&&truncated_location.error().code==ErrorCode::malformed);
    auto unknown_expr=build({0xff});auto unknown_location=import_dwarf_v4({"unknown-expression.o",unknown_expr.info,unknown_expr.abbrev,unknown_expr.strings});assert(!unknown_location&&unknown_location.error().code==ErrorCode::unsupported);
    std::vector<std::uint8_t> too_many_ops(4097,0x30);auto bounded_expr=build(std::move(too_many_ops));auto bounded_location=import_dwarf_v4({"bounded-expression.o",bounded_expr.info,bounded_expr.abbrev,bounded_expr.strings});assert(!bounded_location&&bounded_location.error().code==ErrorCode::resource_limit);

    // A reference to a nonexistent local DIE offset is malformed rather than
    // being silently resolved to an unrelated type.
    auto bad=build();assert(!bad.reference_patches.empty());for(unsigned i=0;i<4;++i)bad.info[bad.reference_patches.front()+i]=0xff;auto invalid=import_dwarf_v4({"bad-reference.o",bad.info,bad.abbrev,bad.strings});assert(!invalid&&invalid.error().code==ErrorCode::malformed);
    auto absolute_refs=build();const std::vector<std::uint8_t> relative_type_form{0x49,0x13};for(auto it=absolute_refs.abbrev.begin();(it=std::search(it,absolute_refs.abbrev.end(),relative_type_form.begin(),relative_type_form.end()))!=absolute_refs.abbrev.end();++it)it[1]=0x10;auto absolute_ref_result=import_dwarf_v4({"absolute-reference.o",absolute_refs.info,absolute_refs.abbrev,absolute_refs.strings});assert(absolute_ref_result&&absolute_ref_result.value().symbols.size()==1&&absolute_ref_result.value().symbols[0].type->parameters().size()==2);

    // DWARF v5 compile-unit headers and abbreviation-carried implicit constants.
    std::vector<std::uint8_t> v5_abbrev;uleb(v5_abbrev,1);uleb(v5_abbrev,0x11);v5_abbrev.push_back(1);uleb(v5_abbrev,3);uleb(v5_abbrev,8);uleb(v5_abbrev,0);uleb(v5_abbrev,0);uleb(v5_abbrev,2);uleb(v5_abbrev,0x24);v5_abbrev.push_back(0);uleb(v5_abbrev,3);uleb(v5_abbrev,8);uleb(v5_abbrev,0x0b);uleb(v5_abbrev,0x0b);uleb(v5_abbrev,0x3e);uleb(v5_abbrev,0x21);sleb(v5_abbrev,5);uleb(v5_abbrev,0);uleb(v5_abbrev,0);uleb(v5_abbrev,0);
    std::vector<std::uint8_t> v5_info;put(v5_info,0,4);put(v5_info,5,2);v5_info.push_back(1);v5_info.push_back(8);put(v5_info,0,4);uleb(v5_info,1);v5_info.insert(v5_info.end(),{'v','5','.','c',0});uleb(v5_info,2);v5_info.insert(v5_info.end(),{'i','n','t',0});v5_info.push_back(4);uleb(v5_info,0);auto v5_length=static_cast<std::uint32_t>(v5_info.size()-4);for(unsigned i=0;i<4;++i)v5_info[i]=std::uint8_t(v5_length>>(8*i));
    auto v5=import_dwarf({"v5.o",v5_info,v5_abbrev,{},{},{},{},{}});assert(v5&&v5.value().types.size()==1&&v5.value().types[0].source_name=="int");
    auto v5_line_abbrev=v5_abbrev;v5_line_abbrev[4]=0x1f;auto v5_line_info=v5_info;v5_line_info.erase(v5_line_info.begin()+13,v5_line_info.begin()+18);for(unsigned i=0;i<4;++i)v5_line_info.insert(v5_line_info.begin()+13+i,0);v5_length=static_cast<std::uint32_t>(v5_line_info.size()-4);for(unsigned i=0;i<4;++i)v5_line_info[i]=std::uint8_t(v5_length>>(8*i));std::vector<std::uint8_t> line_strings{'v','5','.','c',0};auto v5_line_name=import_dwarf({"line-string-v5.o",v5_line_info,v5_line_abbrev,{},{},{},line_strings,{}});assert(v5_line_name&&v5_line_name.value().types.size()==1);
    auto short_v5=v5_info;short_v5.resize(8);auto short_result=import_dwarf({"short-v5.o",short_v5,v5_abbrev,{},{},{},{},{}});assert(!short_result&&short_result.error().code==ErrorCode::malformed);
    auto underdeclared_v5=v5_info;for(unsigned i=0;i<4;++i)underdeclared_v5[i]=static_cast<std::uint8_t>(7u>>(i*8));underdeclared_v5.insert(underdeclared_v5.end(),16,0);auto underdeclared_result=import_dwarf({"underdeclared-v5-header.o",underdeclared_v5,v5_abbrev,{},{},{},{},{}});assert(!underdeclared_result&&underdeclared_result.error().code==ErrorCode::malformed&&underdeclared_result.error().message.find("unit header")!=std::string::npos);
    // A DWARF v5 type unit has a signature and type-DIE offset after the
    // common header. Import the type DIE as a standalone record.
    std::vector<std::uint8_t> type_unit_abbrev;uleb(type_unit_abbrev,1);uleb(type_unit_abbrev,0x24);type_unit_abbrev.push_back(0);uleb(type_unit_abbrev,3);uleb(type_unit_abbrev,8);uleb(type_unit_abbrev,0x0b);uleb(type_unit_abbrev,0x0b);uleb(type_unit_abbrev,0x3e);uleb(type_unit_abbrev,0x0b);uleb(type_unit_abbrev,0);uleb(type_unit_abbrev,0);uleb(type_unit_abbrev,0);
    std::vector<std::uint8_t> type_unit;put(type_unit,0,4);put(type_unit,5,2);type_unit.push_back(2);type_unit.push_back(8);put(type_unit,0,4);put(type_unit,0x1122334455667788ULL,8);put(type_unit,24,4);uleb(type_unit,1);type_unit.insert(type_unit.end(),{'u','i','n','t',0});type_unit.push_back(4);type_unit.push_back(5);auto type_unit_length=static_cast<std::uint32_t>(type_unit.size()-4);for(unsigned i=0;i<4;++i)type_unit[i]=std::uint8_t(type_unit_length>>(8*i));
    auto type_import=import_dwarf({"type-unit.o",type_unit,type_unit_abbrev,{},{},{},{},{}});assert(type_import&&type_import.value().types.size()==1&&type_import.value().types[0].source_name=="uint"&&type_import.value().types[0].type->size()==4);
    // A compile unit may use the signature form to refer to a previously
    // indexed standalone type unit. The reference resolves to the shared
    // immutable type object rather than an invented local DIE offset.
    std::vector<std::uint8_t> signature_cu_abbrev;uleb(signature_cu_abbrev,1);uleb(signature_cu_abbrev,0x11);signature_cu_abbrev.push_back(1);uleb(signature_cu_abbrev,3);uleb(signature_cu_abbrev,8);uleb(signature_cu_abbrev,0);uleb(signature_cu_abbrev,0);uleb(signature_cu_abbrev,2);uleb(signature_cu_abbrev,0x16);signature_cu_abbrev.push_back(0);uleb(signature_cu_abbrev,3);uleb(signature_cu_abbrev,8);uleb(signature_cu_abbrev,0x49);uleb(signature_cu_abbrev,0x20);uleb(signature_cu_abbrev,0);uleb(signature_cu_abbrev,0);uleb(signature_cu_abbrev,0);
    std::vector<std::uint8_t> signature_cu;put(signature_cu,0,4);put(signature_cu,5,2);signature_cu.push_back(1);signature_cu.push_back(8);put(signature_cu,0,4);uleb(signature_cu,1);signature_cu.insert(signature_cu.end(),{'r','e','f','e','r','e','n','c','e','.','c',0});uleb(signature_cu,2);signature_cu.insert(signature_cu.end(),{'U','i','n','t',0});put(signature_cu,0x1122334455667788ULL,8);signature_cu.push_back(0);auto signature_cu_length=static_cast<std::uint32_t>(signature_cu.size()-4);for(unsigned i=0;i<4;++i)signature_cu[i]=std::uint8_t(signature_cu_length>>(i*8));
    auto multi_unit=type_unit;auto signature_cu_offset=static_cast<std::uint32_t>(type_unit_abbrev.size());signature_cu[8]=std::uint8_t(signature_cu_offset);signature_cu[9]=std::uint8_t(signature_cu_offset>>8);signature_cu[10]=std::uint8_t(signature_cu_offset>>16);signature_cu[11]=std::uint8_t(signature_cu_offset>>24);multi_unit.insert(multi_unit.end(),signature_cu.begin(),signature_cu.end());auto multi_abbrev=type_unit_abbrev;multi_abbrev.insert(multi_abbrev.end(),signature_cu_abbrev.begin(),signature_cu_abbrev.end());auto signature_import=import_dwarf({"signature-reference.o",multi_unit,multi_abbrev,{},{},{},{},{}});assert(signature_import&&signature_import.value().types.size()==2);auto signature_alias=std::find_if(signature_import.value().types.begin(),signature_import.value().types.end(),[](const auto&t){return t.source_name=="Uint";});assert(signature_alias!=signature_import.value().types.end()&&signature_alias->is_typedef&&signature_alias->type->kind()==types::Kind::integer&&signature_alias->type->size()==4);
    auto absolute_cu=signature_cu;const auto absolute_target_field=absolute_cu.size()-9;absolute_cu.erase(absolute_cu.begin()+static_cast<std::ptrdiff_t>(absolute_target_field+4),absolute_cu.begin()+static_cast<std::ptrdiff_t>(absolute_target_field+8));for(unsigned i=0;i<4;++i)absolute_cu[absolute_target_field+i]=std::uint8_t(24u>>(i*8));const auto absolute_cu_length=static_cast<std::uint32_t>(absolute_cu.size()-4);for(unsigned i=0;i<4;++i)absolute_cu[i]=std::uint8_t(absolute_cu_length>>(i*8));auto absolute_cu_abbrev=signature_cu_abbrev;const std::vector<std::uint8_t> signature_form{0x49,0x20};auto signature_form_at=std::search(absolute_cu_abbrev.begin(),absolute_cu_abbrev.end(),signature_form.begin(),signature_form.end());assert(signature_form_at!=absolute_cu_abbrev.end());*(signature_form_at+1)=0x10;auto absolute_multi_info=type_unit;absolute_multi_info.insert(absolute_multi_info.end(),absolute_cu.begin(),absolute_cu.end());auto absolute_multi_abbrev=type_unit_abbrev;absolute_multi_abbrev.insert(absolute_multi_abbrev.end(),absolute_cu_abbrev.begin(),absolute_cu_abbrev.end());auto absolute_multi_import=import_dwarf({"cross-unit-ref-addr.o",absolute_multi_info,absolute_multi_abbrev,{},{},{},{},{}});assert(absolute_multi_import&&absolute_multi_import.value().types.size()==2);
    auto missing_signature_info=signature_cu;for(unsigned i=0;i<4;++i)missing_signature_info[8+i]=0;for(unsigned i=0;i<8;++i)missing_signature_info[missing_signature_info.size()-9+i]=std::uint8_t(0xaa+i);auto missing_signature_import=import_dwarf({"missing-signature.o",missing_signature_info,signature_cu_abbrev,{},{},{},{},{}});assert(!missing_signature_import&&missing_signature_import.error().code==ErrorCode::unsupported);
    auto forward_signature_units=signature_cu;for(unsigned i=0;i<4;++i)forward_signature_units[8+i]=0;auto later_type_unit=type_unit;for(unsigned i=0;i<4;++i)later_type_unit[8+i]=std::uint8_t(signature_cu_abbrev.size()>>(i*8));forward_signature_units.insert(forward_signature_units.end(),later_type_unit.begin(),later_type_unit.end());auto forward_abbrev=signature_cu_abbrev;forward_abbrev.insert(forward_abbrev.end(),type_unit_abbrev.begin(),type_unit_abbrev.end());auto forward_signature_import=import_dwarf({"forward-signature.o",forward_signature_units,forward_abbrev,{},{},{},{},{}});assert(forward_signature_import&&forward_signature_import.value().types.size()==2);auto forward_signature_alias=std::find_if(forward_signature_import.value().types.begin(),forward_signature_import.value().types.end(),[](const auto&t){return t.source_name=="Uint";});assert(forward_signature_alias!=forward_signature_import.value().types.end()&&forward_signature_alias->type->size()==4);
    auto truncated_signature=signature_cu;truncated_signature.resize(truncated_signature.size()-5);const auto truncated_signature_length=static_cast<std::uint32_t>(truncated_signature.size()-4);for(unsigned i=0;i<4;++i)truncated_signature[i]=std::uint8_t(truncated_signature_length>>(i*8));for(unsigned i=0;i<4;++i)truncated_signature[8+i]=0;auto truncated_signature_import=import_dwarf({"truncated-signature.o",truncated_signature,signature_cu_abbrev,{},{},{},{},{}});assert(!truncated_signature_import&&truncated_signature_import.error().code==ErrorCode::malformed);
    auto duplicate_signature_units=type_unit;duplicate_signature_units.insert(duplicate_signature_units.end(),type_unit.begin(),type_unit.end());auto duplicate_signature_import=import_dwarf({"duplicate-signature.o",duplicate_signature_units,type_unit_abbrev,{},{},{},{},{}});assert(!duplicate_signature_import&&duplicate_signature_import.error().code==ErrorCode::malformed&&duplicate_signature_import.error().message.find("duplicate")!=std::string::npos);
    auto bad_type_target=type_unit;bad_type_target[20]=23;auto bad_type_target_import=import_dwarf({"bad-type-target.o",bad_type_target,type_unit_abbrev,{},{},{},{},{}});assert(!bad_type_target_import&&bad_type_target_import.error().code==ErrorCode::malformed);
    auto truncated_type_unit=type_unit;truncated_type_unit.resize(20);for(unsigned i=0;i<4;++i)truncated_type_unit[i]=std::uint8_t((truncated_type_unit.size()-4)>>(i*8));auto truncated_type_import=import_dwarf({"truncated-type-unit.o",truncated_type_unit,type_unit_abbrev,{},{},{},{},{}});assert(!truncated_type_import&&truncated_type_import.error().code==ErrorCode::malformed);

    std::vector<std::uint8_t> indexed_abbrev;uleb(indexed_abbrev,1);uleb(indexed_abbrev,0x11);indexed_abbrev.push_back(1);uleb(indexed_abbrev,0x72);uleb(indexed_abbrev,0x17);uleb(indexed_abbrev,0x73);uleb(indexed_abbrev,0x17);uleb(indexed_abbrev,3);uleb(indexed_abbrev,0x25);uleb(indexed_abbrev,0);uleb(indexed_abbrev,0);uleb(indexed_abbrev,2);uleb(indexed_abbrev,0x24);indexed_abbrev.push_back(0);uleb(indexed_abbrev,3);uleb(indexed_abbrev,0x25);uleb(indexed_abbrev,0x0b);uleb(indexed_abbrev,0x0b);uleb(indexed_abbrev,0x3e);uleb(indexed_abbrev,0x0b);uleb(indexed_abbrev,0);uleb(indexed_abbrev,0);uleb(indexed_abbrev,3);uleb(indexed_abbrev,0x2e);indexed_abbrev.push_back(0);uleb(indexed_abbrev,3);uleb(indexed_abbrev,0x25);uleb(indexed_abbrev,0x11);uleb(indexed_abbrev,0x29);uleb(indexed_abbrev,0x12);uleb(indexed_abbrev,0x06);uleb(indexed_abbrev,0);uleb(indexed_abbrev,0);uleb(indexed_abbrev,0);
    std::vector<std::uint8_t> indexed_info;put(indexed_info,0,4);put(indexed_info,5,2);indexed_info.push_back(1);indexed_info.push_back(8);put(indexed_info,0,4);uleb(indexed_info,1);put(indexed_info,8,4);put(indexed_info,8,4);indexed_info.push_back(0);uleb(indexed_info,2);indexed_info.push_back(1);indexed_info.push_back(4);indexed_info.push_back(5);uleb(indexed_info,3);indexed_info.push_back(2);indexed_info.push_back(0);put(indexed_info,2,4);uleb(indexed_info,0);v5_length=static_cast<std::uint32_t>(indexed_info.size()-4);for(unsigned i=0;i<4;++i)indexed_info[i]=std::uint8_t(v5_length>>(8*i));
    std::vector<std::uint8_t> indexed_strings{'c','u',0,'i','n','t',0,'f','u','n','c',0};std::vector<std::uint8_t> str_offsets;put(str_offsets,16,4);put(str_offsets,5,2);put(str_offsets,0,2);put(str_offsets,0,4);put(str_offsets,3,4);put(str_offsets,7,4);std::vector<std::uint8_t> addr_table;put(addr_table,12,4);put(addr_table,5,2);addr_table.push_back(8);addr_table.push_back(0);put(addr_table,0x400000,8);
    auto indexed=import_dwarf({"indexed-v5.o",indexed_info,indexed_abbrev,indexed_strings,str_offsets,addr_table,{},{}});assert(indexed&&indexed.value().symbols.size()==1&&indexed.value().symbols[0].name=="func"&&indexed.value().symbols[0].address==0x400000&&indexed.value().types.size()==1&&indexed.value().types[0].source_name=="int");
    auto bad_index=indexed_info;bad_index[21]=3;auto indexed_bad=import_dwarf({"bad-index-v5.o",bad_index,indexed_abbrev,indexed_strings,str_offsets,addr_table,{},{}});assert(!indexed_bad&&indexed_bad.error().code==ErrorCode::malformed);
    auto no_str_offsets=import_dwarf({"missing-str-offsets.o",indexed_info,indexed_abbrev,indexed_strings,{},{},{},{}});assert(!no_str_offsets&&no_str_offsets.error().code==ErrorCode::malformed);
    auto bad_str_offsets=str_offsets;bad_str_offsets[4]=4;auto bad_contribution=import_dwarf({"bad-contribution.o",indexed_info,indexed_abbrev,indexed_strings,bad_str_offsets,addr_table,{},{}});assert(!bad_contribution&&bad_contribution.error().code==ErrorCode::unsupported);
    auto unterminated_strings=indexed_strings;unterminated_strings.back()='x';auto bad_string=import_dwarf({"bad-string.o",indexed_info,indexed_abbrev,unterminated_strings,str_offsets,addr_table,{},{}});assert(!bad_string&&bad_string.error().code==ErrorCode::malformed);
    auto bad_base=indexed_info;bad_base[13]=7;auto bad_base_result=import_dwarf({"bad-base.o",bad_base,indexed_abbrev,indexed_strings,str_offsets,addr_table,{},{}});assert(!bad_base_result&&bad_base_result.error().code==ErrorCode::malformed);
    // Supplementary strings are resolved from an explicitly supplied table.
    auto supplementary_info=v5_info;auto supplementary_abbrev=v5_abbrev;
    const std::vector<std::uint8_t> base_name_abbrev{2,0x24,0,3,8};
    auto name_form=std::search(supplementary_abbrev.begin(),supplementary_abbrev.end(),base_name_abbrev.begin(),base_name_abbrev.end());assert(name_form!=supplementary_abbrev.end());*(name_form+4)=0x1d;
    for(unsigned i=0;i<4;++i)supplementary_info[19+i]=0;
    std::vector<std::uint8_t> supplementary_strings{'s','u','p','p','l','e','m','e','n','t','a','r','y','-','i','n','t',0};
    DwarfSections supplementary_sections;supplementary_sections.source_id="supplementary.o";supplementary_sections.info=supplementary_info;supplementary_sections.abbrev=supplementary_abbrev;supplementary_sections.supplementary_strings=supplementary_strings;auto supplementary_import=import_dwarf(supplementary_sections);
    assert(supplementary_import);
    assert(supplementary_import.value().types.size()==1&&supplementary_import.value().types[0].source_name=="supplementary-int");
    auto missing_supplementary=import_dwarf({"missing-supplementary.o",supplementary_info,supplementary_abbrev,{},{},{},{},{}});
    assert(!missing_supplementary&&missing_supplementary.error().code==ErrorCode::unsupported);
    supplementary_info[19]=0xff;
    supplementary_sections.source_id="bad-supplementary.o";auto bad_supplementary=import_dwarf(supplementary_sections);
    assert(!bad_supplementary&&bad_supplementary.error().code==ErrorCode::malformed);
    // ref_sup4 is delegated to an explicit resolver and its echoed identity
    // (including checksum) must match the bounded .debug_sup descriptor.
    std::vector<std::uint8_t> sup_ref_abbrev;uleb(sup_ref_abbrev,1);uleb(sup_ref_abbrev,0x11);sup_ref_abbrev.push_back(1);uleb(sup_ref_abbrev,0);uleb(sup_ref_abbrev,0);uleb(sup_ref_abbrev,2);uleb(sup_ref_abbrev,0x16);sup_ref_abbrev.push_back(0);uleb(sup_ref_abbrev,3);uleb(sup_ref_abbrev,8);uleb(sup_ref_abbrev,0x49);uleb(sup_ref_abbrev,0x1c);uleb(sup_ref_abbrev,0);uleb(sup_ref_abbrev,0);uleb(sup_ref_abbrev,0);
    std::vector<std::uint8_t> sup_ref_info;put(sup_ref_info,0,4);put(sup_ref_info,5,2);sup_ref_info.push_back(1);sup_ref_info.push_back(8);put(sup_ref_info,0,4);uleb(sup_ref_info,1);uleb(sup_ref_info,2);sup_ref_info.insert(sup_ref_info.end(),{'T','y','p','e',0});put(sup_ref_info,0x1234,4);uleb(sup_ref_info,0);auto sup_ref_len=static_cast<std::uint32_t>(sup_ref_info.size()-4);for(unsigned i=0;i<4;++i)sup_ref_info[i]=std::uint8_t(sup_ref_len>>(8*i));
    DwarfSections sup_ref_sections;sup_ref_sections.source_id="sup-ref.o";sup_ref_sections.info=sup_ref_info;sup_ref_sections.abbrev=sup_ref_abbrev;sup_ref_sections.supplementary_identity.present=true;sup_ref_sections.supplementary_identity.version=5;sup_ref_sections.supplementary_identity.supplementary=false;sup_ref_sections.supplementary_identity.filename="supplementary.debug";sup_ref_sections.supplementary_identity.checksum={0xaa,0xbb};
    auto resolved_int=types::Type::integer("external-int",4,1,true);assert(resolved_int);
    sup_ref_sections.supplementary_type_resolver=[&](const DwarfSupplementaryIdentity &identity,std::uint64_t offset)->Result<DwarfSupplementaryType>{assert(offset==0x1234);return DwarfSupplementaryType{identity,resolved_int.value(),offset,0,true};};
    auto sup_ref_result=import_dwarf(sup_ref_sections);assert(sup_ref_result&&sup_ref_result.value().types.size()==1&&sup_ref_result.value().types[0].type->kind()==types::Kind::integer);
    auto no_sup_descriptor=sup_ref_sections;no_sup_descriptor.supplementary_identity={};auto no_sup_descriptor_result=import_dwarf(no_sup_descriptor);assert(!no_sup_descriptor_result&&no_sup_descriptor_result.error().code==ErrorCode::unsupported&&no_sup_descriptor_result.error().message.find("descriptor")!=std::string::npos);
    auto sup_ref8_abbrev=sup_ref_abbrev;const std::vector<std::uint8_t> ref_sup4_form{0x49,0x1c};auto ref_sup4_at=std::search(sup_ref8_abbrev.begin(),sup_ref8_abbrev.end(),ref_sup4_form.begin(),ref_sup4_form.end());assert(ref_sup4_at!=sup_ref8_abbrev.end());*(ref_sup4_at+1)=0x24;
    auto sup_ref8_info=sup_ref_info;sup_ref8_info.insert(sup_ref8_info.end(),{0,0,0,0});sup_ref_len=static_cast<std::uint32_t>(sup_ref8_info.size()-4);for(unsigned i=0;i<4;++i)sup_ref8_info[i]=std::uint8_t(sup_ref_len>>(8*i));sup_ref_sections.info=sup_ref8_info;sup_ref_sections.abbrev=sup_ref8_abbrev;
    auto sup_ref8_result=import_dwarf(sup_ref_sections);assert(sup_ref8_result&&sup_ref8_result.value().types.size()==1);
    sup_ref_sections.supplementary_type_resolver={};auto sup_ref_without_resolver=import_dwarf(sup_ref_sections);assert(!sup_ref_without_resolver&&sup_ref_without_resolver.error().code==ErrorCode::unsupported);
    sup_ref_sections.info=sup_ref_info;sup_ref_sections.abbrev=sup_ref_abbrev;
    sup_ref_sections.supplementary_type_resolver=[&](const DwarfSupplementaryIdentity &identity,std::uint64_t)->Result<DwarfSupplementaryType>{auto wrong=identity;wrong.checksum.clear();return DwarfSupplementaryType{wrong,resolved_int.value()};};
    auto sup_ref_bad_identity=import_dwarf(sup_ref_sections);assert(!sup_ref_bad_identity&&sup_ref_bad_identity.error().code==ErrorCode::malformed);
    return 0;
}
