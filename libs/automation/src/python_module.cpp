#include "python_internal.hpp"
#include "hexlab/automation/api.hpp"
#include "hexlab/loaders/x86_raw_profile.hpp"
#include "hexlab/processors/format.hpp"
#include "hexlab/types/types.hpp"
#include "hexlab/debugger/debugger.hpp"
#include <algorithm>
#include <limits>
#include <stop_token>
#include <stdexcept>

namespace {
using namespace hexlab;
using Project=automation::Project;
constexpr const char* capsule_name="hexlab.automation.Project.v1";
constexpr const char* archive_capsule_name="hexlab.automation.Archive.v1";
constexpr const char* history_capsule_name="hexlab.automation.HistoricalState.v1";
constexpr const char* search_cursor_name="hexlab.automation.SearchCursor.v1";
constexpr const char* stop_source_name="hexlab.automation.StopSource.v1";
constexpr const char* debugger_name="hexlab.automation.Debugger.v1";
PyObject* error_type=nullptr; // module-owned; this executable owns one interpreter
struct PythonFailure {};
struct NativeFailure {Error error;};
template<class F>PyObject* guarded(F operation);
struct Object {
    PyObject* value=nullptr;
    explicit Object(PyObject* p=nullptr):value(p){if(!p)throw PythonFailure{};}
    ~Object(){Py_XDECREF(value);}
    Object(const Object&)=delete;
    PyObject* release(){auto* p=value;value=nullptr;return p;}
    operator PyObject*() const{return value;}
};
template<class T>T take(Result<T> result){if(!result)throw NativeFailure{result.error()};return std::move(result.value());}
template<class F>auto without_gil(F&& operation){
    auto* thread_state=PyEval_SaveThread();
    try{auto result=operation();PyEval_RestoreThread(thread_state);return result;}
    catch(...){PyEval_RestoreThread(thread_state);throw;}
}
void invalid(const char* text){throw NativeFailure{{ErrorCode::invalid_argument,text}};}
void count(PyObject* args,Py_ssize_t expected){if(!PyTuple_Check(args) || PyTuple_Size(args)!=expected)invalid("Wrong automation argument count");}
PyObject* argument(PyObject* args,Py_ssize_t index){return PyTuple_GetItem(args,index);}
std::uint64_t number(PyObject* object){auto value=PyLong_AsUnsignedLongLong(object);if(PyErr_Occurred())throw PythonFailure{};return value;}
std::uint32_t number32(PyObject* object){auto value=number(object);if(value>UINT32_MAX)invalid("Integer exceeds32 bits");return static_cast<std::uint32_t>(value);}
std::uint8_t number8(PyObject* object){auto value=number(object);if(value>UINT8_MAX)invalid("Integer exceeds8 bits");return static_cast<std::uint8_t>(value);}
std::size_t size(PyObject* object){auto value=number(object);if(value>SIZE_MAX)invalid("Integer exceeds host size");return static_cast<std::size_t>(value);}
bool boolean(PyObject* object){auto value=PyObject_IsTrue(object);if(value<0)throw PythonFailure{};return value!=0;}
std::string text(PyObject* object){Py_ssize_t length=0;const char* data=PyUnicode_AsUTF8AndSize(object,&length);if(!data)throw PythonFailure{};return {data,static_cast<std::size_t>(length)};}
std::filesystem::path path(PyObject* object){
    auto value=text(object);if(value.empty() || value.find('\0')!=value.npos)invalid("Path is empty or contains NUL");
    return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(value.data()),value.size()));
}
Location location(PyObject* object){
    if(!PyTuple_Check(object))invalid("Expected typed location tuple");
    const auto length=PyTuple_Size(object);
    if(length<1)invalid("Empty location tuple");
    const auto kind=text(argument(object,0));
    if(kind=="file" && length==2)return FileOffset{number(argument(object,1))};
    if(kind=="va" && length==3)return Address{{number32(argument(object,1))},number(argument(object,2))};
    invalid("Unknown typed location");return FileOffset{0};
}
Address address(PyObject* object){auto value=location(object);if(auto* at=std::get_if<Address>(&value))return *at;invalid("Command requires Address");return {};}
automation::DebugImportKind debug_import_kind(PyObject* object){
    const auto kind=text(object);
    if(kind=="symbols")return automation::DebugImportKind::symbols;
    if(kind=="dwarf")return automation::DebugImportKind::dwarf;
    invalid("Debug import kind must be symbols or dwarf");return automation::DebugImportKind::symbols;
}
PyObject* encode(Location value){
    if(auto* at=std::get_if<Address>(&value))return Py_BuildValue("(sIK)","va",at->space.value,static_cast<unsigned long long>(at->offset));
    return Py_BuildValue("(sK)","file",static_cast<unsigned long long>(std::get<FileOffset>(value).value));
}
PyObject* integer(std::uint64_t value){return PyLong_FromUnsignedLongLong(value);}
PyObject* signed_integer(std::int64_t value){return PyLong_FromLongLong(value);}
PyObject* string(std::string_view value){return PyUnicode_DecodeUTF8(value.data(),static_cast<Py_ssize_t>(value.size()),"strict");}
types::FunctionConvention function_convention(std::string_view value){
    using Convention=types::FunctionConvention;
    if(value=="platform_default")return Convention::platform_default;
    if(value=="c_decl")return Convention::c_decl;
    if(value=="stdcall")return Convention::stdcall;
    if(value=="fastcall")return Convention::fastcall;
    if(value=="thiscall")return Convention::thiscall;
    if(value=="vectorcall")return Convention::vectorcall;
    if(value=="sysv_abi")return Convention::sysv_abi;
    if(value=="ms_abi")return Convention::ms_abi;
    if(value=="aapcs64")return Convention::aapcs64;
    if(value=="aapcs32")return Convention::aapcs32;
    if(value=="mips_n64")return Convention::mips_n64;
    invalid("Unknown function calling convention");return Convention::platform_default;
}
std::string_view function_convention_name(types::FunctionConvention value){
    using Convention=types::FunctionConvention;
    switch(value){
    case Convention::platform_default:return "platform_default";
    case Convention::c_decl:return "c_decl";
    case Convention::stdcall:return "stdcall";
    case Convention::fastcall:return "fastcall";
    case Convention::thiscall:return "thiscall";
    case Convention::vectorcall:return "vectorcall";
    case Convention::sysv_abi:return "sysv_abi";
    case Convention::ms_abi:return "ms_abi";
    case Convention::aapcs64:return "aapcs64";
    case Convention::aapcs32:return "aapcs32";
    case Convention::mips_n64:return "mips_n64";
    }
    invalid("Unknown native function calling convention");return "platform_default";
}
PyObject* none();
void append(PyObject* list,PyObject* value);
PyObject* tuple_item(PyObject* tuple, Py_ssize_t index){return PyTuple_GetItem(tuple,index);}
PyObject* sequence_item(PyObject* sequence, Py_ssize_t index){return PyList_Check(sequence)?PyList_GetItem(sequence,index):PyTuple_GetItem(sequence,index);}
std::string tuple_text(PyObject* tuple, Py_ssize_t index){return text(tuple_item(tuple,index));}
PyObject* tagged_type(std::string_view kind, Py_ssize_t size){
    Object tuple(PyTuple_New(size));
    PyTuple_SET_ITEM(tuple.value,0,string("type"));PyTuple_SET_ITEM(tuple.value,1,string(kind));
    return tuple.release();
}
void tuple_set(PyObject* tuple, Py_ssize_t index, PyObject* value){
    if(!value)throw PythonFailure{};PyTuple_SET_ITEM(tuple,index,value);
}
PyObject* encode_type_spec(const types::Type& type){
    using K=types::Kind;
    switch(type.kind()){
    case K::void_type:return tagged_type("void",2);
    case K::boolean:{Object out(tagged_type("boolean",4));tuple_set(out,2,integer(*type.size()));tuple_set(out,3,integer(type.alignment()));return out.release();}
    case K::integer:{Object out(tagged_type("integer",6));tuple_set(out,2,string(type.name()));tuple_set(out,3,integer(*type.size()));tuple_set(out,4,integer(type.alignment()));tuple_set(out,5,PyBool_FromLong(type.is_signed()));return out.release();}
    case K::floating:{Object out(tagged_type("floating",5));tuple_set(out,2,string(type.name()));tuple_set(out,3,integer(*type.size()));tuple_set(out,4,integer(type.alignment()));return out.release();}
    case K::vector:{Object out(tagged_type("vector",5));tuple_set(out,2,encode_type_spec(*type.element()));tuple_set(out,3,integer(type.count()));tuple_set(out,4,integer(type.alignment()));return out.release();}
    case K::pointer:{Object out(tagged_type("pointer",5));tuple_set(out,2,encode_type_spec(*type.element()));tuple_set(out,3,integer(*type.size()));tuple_set(out,4,integer(type.alignment()));return out.release();}
    case K::array:{Object out(tagged_type("array",4));tuple_set(out,2,encode_type_spec(*type.element()));tuple_set(out,3,integer(type.count()));return out.release();}
    case K::qualified:{Object out(tagged_type("qualified",4));tuple_set(out,2,encode_type_spec(*type.element()));tuple_set(out,3,integer(type.qualifiers()));return out.release();}
    case K::named_reference:{Object out(tagged_type("named_reference",3));tuple_set(out,2,string(type.name()));return out.release();}
    case K::structure:case K::union_type:{
        Object out(tagged_type(type.kind()==K::structure?"structure":"union",6)),members(PyList_New(0));
        for(const auto& member:type.members()){
            Object row(PyTuple_New(5));tuple_set(row,0,string(member.name));tuple_set(row,1,encode_type_spec(*member.type));tuple_set(row,2,integer(member.offset));
            tuple_set(row,3,member.bit_width?integer(*member.bit_width):none());tuple_set(row,4,member.bit_offset?integer(*member.bit_offset):none());append(members,row.release());
        }
        tuple_set(out,2,string(type.name()));tuple_set(out,3,members.release());tuple_set(out,4,integer(*type.size()));tuple_set(out,5,integer(type.alignment()));return out.release();
    }
    case K::enumeration:{
        Object out(tagged_type("enumeration",5)),rows(PyList_New(0));
        for(const auto& item:type.enumerator_values()){Object row(PyTuple_New(2));tuple_set(row,0,string(item.name));tuple_set(row,1,integer(item.value));append(rows,row.release());}
        tuple_set(out,2,string(type.name()));tuple_set(out,3,encode_type_spec(*type.element()));tuple_set(out,4,rows.release());return out.release();
    }
    case K::function:{
        Object out(tagged_type("function",6)),rows(PyList_New(0));
        for(const auto& parameter:type.parameters()){Object row(PyTuple_New(2));tuple_set(row,0,string(parameter.name));tuple_set(row,1,encode_type_spec(*parameter.type));append(rows,row.release());}
        tuple_set(out,2,encode_type_spec(*type.result_type()));tuple_set(out,3,rows.release());tuple_set(out,4,PyBool_FromLong(type.variadic()));
        tuple_set(out,5,string(function_convention_name(type.function_convention())));return out.release();
    }
    }
    invalid("Unknown native type kind");return nullptr;
}
types::TypePtr type_value(PyObject* object,std::size_t depth=0){
    using T=types::Type;
    if(depth>64)invalid("TypeSpec nesting exceeds64 levels");
    if(!PyTuple_Check(object)||PyTuple_Size(object)<2||tuple_text(object,0)!="type")invalid("Expected a hexlab.TypeSpec value");
    const auto kind=tuple_text(object,1);const auto n=PyTuple_Size(object);
    if(kind=="void"&&n==2)return T::void_type();
    if(kind=="boolean"&&n==4)return take(T::boolean(number(tuple_item(object,2)),number(tuple_item(object,3))));
    if(kind=="integer"&&n==6)return take(T::integer(text(tuple_item(object,2)),number(tuple_item(object,3)),number(tuple_item(object,4)),boolean(tuple_item(object,5))));
    if(kind=="floating"&&n==5)return take(T::floating(text(tuple_item(object,2)),number(tuple_item(object,3)),number(tuple_item(object,4))));
    if(kind=="vector"&&n==5)return take(T::vector(type_value(tuple_item(object,2),depth+1),number(tuple_item(object,3)),number(tuple_item(object,4))));
    if(kind=="pointer"&&n==5)return take(T::pointer(type_value(tuple_item(object,2),depth+1),number(tuple_item(object,3)),number(tuple_item(object,4))));
    if(kind=="array"&&n==4)return take(T::array(type_value(tuple_item(object,2),depth+1),number(tuple_item(object,3))));
    if(kind=="qualified"&&n==4)return take(T::qualified(type_value(tuple_item(object,2),depth+1),number8(tuple_item(object,3))));
    if(kind=="named_reference"&&n==3)return take(T::named_reference(text(tuple_item(object,2))));
    if((kind=="structure"||kind=="union")&&n==6){
        auto* rows=tuple_item(object,3);if((!PyList_Check(rows)&&!PyTuple_Check(rows))||PySequence_Size(rows)>65536)invalid("Type members must be a bounded sequence");std::vector<types::Member> members;
        for(Py_ssize_t i=0;i<PySequence_Size(rows);++i){auto* row=PySequence_GetItem(rows,i);Object owned_row(row);if((!PyTuple_Check(row)&&!PyList_Check(row))||PySequence_Size(row)!=5)invalid("Malformed type member");
            std::optional<std::uint32_t> width,offset;if(sequence_item(row,3)!=Py_None)width=number32(sequence_item(row,3));if(sequence_item(row,4)!=Py_None)offset=number32(sequence_item(row,4));
            members.push_back({text(sequence_item(row,0)),type_value(sequence_item(row,1),depth+1),number(sequence_item(row,2)),width,offset});
        }
        return take(kind=="structure"?T::structure(text(tuple_item(object,2)),std::move(members),number(tuple_item(object,4)),number(tuple_item(object,5))):T::union_type(text(tuple_item(object,2)),std::move(members),number(tuple_item(object,4)),number(tuple_item(object,5))));
    }
    if(kind=="enumeration"&&n==5){auto* rows=tuple_item(object,4);if((!PyList_Check(rows)&&!PyTuple_Check(rows))||PySequence_Size(rows)>65536)invalid("Enumerators must be a bounded sequence");std::vector<types::Enumerator> values;
        for(Py_ssize_t i=0;i<PySequence_Size(rows);++i){Object row(PySequence_GetItem(rows,i));if((!PyTuple_Check(row)&&!PyList_Check(row))||PySequence_Size(row)!=2)invalid("Malformed enumerator");values.push_back({text(sequence_item(row,0)),number(sequence_item(row,1))});}
        return take(T::enumeration_with_values(text(tuple_item(object,2)),type_value(tuple_item(object,3),depth+1),std::move(values)));
    }
    if(kind=="function"&&(n==5||n==6)){auto* rows=tuple_item(object,3);if((!PyList_Check(rows)&&!PyTuple_Check(rows))||PySequence_Size(rows)>65536)invalid("Parameters must be a bounded sequence");std::vector<types::Parameter> parameters;
        for(Py_ssize_t i=0;i<PySequence_Size(rows);++i){Object row(PySequence_GetItem(rows,i));if((!PyTuple_Check(row)&&!PyList_Check(row))||PySequence_Size(row)!=2)invalid("Malformed function parameter");parameters.push_back({text(sequence_item(row,0)),type_value(sequence_item(row,1),depth+1)});}
        const auto convention=n==6?function_convention(text(tuple_item(object,5))):types::FunctionConvention::platform_default;
        return take(T::function(type_value(tuple_item(object,2),depth+1),std::move(parameters),boolean(tuple_item(object,4)),convention));
    }
    invalid("Malformed or unsupported TypeSpec");return {};
}
void set(PyObject* dict,const char* key,PyObject* value){Object owned(value);if(PyDict_SetItemString(dict,key,owned)<0)throw PythonFailure{};}
void append(PyObject* list,PyObject* value){Object owned(value);if(PyList_Append(list,owned)<0)throw PythonFailure{};}
PyObject* none(){Py_INCREF(Py_None);return Py_None;}
PyObject* encode_snapshot(const ProjectSnapshot& snapshot){
    Object out(PyDict_New());
    set(out,"edit_revision",integer(snapshot.state->revisions.edit));
    set(out,"byte_revision",integer(snapshot.state->revisions.bytes));
    set(out,"decision_revision",integer(snapshot.state->revisions.decisions));
    set(out,"history_cursor",integer(snapshot.state->history_cursor));
    set(out,"history_count",integer(snapshot.state->history_count));
    set(out,"input_size",integer(snapshot.state->input.size));
    set(out,"readonly",PyBool_FromLong(snapshot.mode==database::ProjectMode::read_only));
    set(out,"status",integer(static_cast<unsigned>(snapshot.status)));
    set(out,"reason",string(snapshot.reason));
    set(out,"format",string(snapshot.loaded?snapshot.loaded->metadata.format:""));
    Object entries(PyList_New(0));
    if(snapshot.loaded)for(auto entry:snapshot.loaded->image->layout().entries)append(entries,encode(entry));
    set(out,"entries",entries.release());
    Object annotations(PyList_New(0)),bookmarks(PyList_New(0));
    const auto& user=*snapshot.state->user;
    for(std::size_t i=0;i<std::min(user.annotations.size(),automation::maximum_page);++i){
        const auto& row=user.annotations[i];Object item(PyDict_New());
        set(item,"location",encode(row.location));set(item,"name",string(row.name));set(item,"comment",string(row.comment));append(annotations,item.release());
    }
    for(std::size_t i=0;i<std::min(user.bookmarks.size(),automation::maximum_page);++i){
        const auto& row=user.bookmarks[i];Object item(PyDict_New());
        set(item,"location",encode(row.location));set(item,"label",string(row.label));append(bookmarks,item.release());
    }
    set(out,"annotation_count",integer(user.annotations.size()));set(out,"bookmark_count",integer(user.bookmarks.size()));
    set(out,"annotations",annotations.release());set(out,"bookmarks",bookmarks.release());
    set(out,"function_count",integer(snapshot.functions?snapshot.functions->functions.size():0));
    set(out,"instruction_count",integer(snapshot.functions?snapshot.functions->instructions.size():0));
    Object types(PyList_New(0)),assignments(PyList_New(0));
    for(const auto& row:user.types){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"name",string(row.name));set(item,"type",encode_type_spec(*row.type));append(types,item.release());}
    for(const auto& row:user.type_assignments){Object item(PyDict_New());set(item,"location",encode(row.location));set(item,"type_id",integer(row.type_id));append(assignments,item.release());}
    set(out,"types",types.release());set(out,"type_assignments",assignments.release());
    return out.release();
}
PyObject* encode_uuid(const database::ProjectUuid& uuid){
    constexpr char digits[]="0123456789abcdef";
    std::string result;result.reserve(uuid.size()*2);
    for(auto byte:uuid){const auto value=std::to_integer<unsigned>(byte);result.push_back(digits[value>>4]);result.push_back(digits[value&15]);}
    return string(result);
}
PyObject* encode_revisions(const database::ProjectRevisions& revisions){
    Object item(PyDict_New());set(item,"edit",integer(revisions.edit));set(item,"bytes",integer(revisions.bytes));
    set(item,"decisions",integer(revisions.decisions));return item.release();
}
PyObject* encode_history_page(const database::HistoryPage& page){
    Object result(PyDict_New()),rows(PyList_New(0));
    set(result,"project_uuid",encode_uuid(page.uuid));set(result,"source_revisions",encode_revisions(page.source_revisions));
    set(result,"history_cursor",integer(page.history_cursor));set(result,"history_count",integer(page.history_count));
    set(result,"next",page.has_more?integer(page.next_after_step):none());
    for(const auto& row:page.entries){
        Object item(PyDict_New());set(item,"step",integer(row.step));set(item,"group_id",integer(row.group_id));
        set(item,"byte_change",PyBool_FromLong(row.byte_change));set(item,"decision_change",PyBool_FromLong(row.decision_change));
        set(item,"applied",PyBool_FromLong(row.applied));append(rows,item.release());
    }
    set(result,"entries",rows.release());return result.release();
}
PyObject* encode_historical_metadata(const automation::HistoricalState& state){
    const auto& metadata=state.metadata();const auto& user=*metadata.user;
    Object result(PyDict_New());set(result,"project_uuid",encode_uuid(metadata.uuid));
    set(result,"source_revisions",encode_revisions(metadata.source_revisions));set(result,"source_cursor",integer(metadata.source_cursor));
    set(result,"target_step",integer(metadata.target_step));set(result,"history_count",integer(metadata.history_count));
    set(result,"replayed_steps",integer(metadata.replayed_steps));set(result,"delta_bytes",integer(metadata.delta_bytes));
    set(result,"input_size",integer(state.input_size()));set(result,"annotation_count",integer(user.annotations.size()));
    set(result,"bookmark_count",integer(user.bookmarks.size()));set(result,"type_count",integer(user.types.size()));
    set(result,"type_assignment_count",integer(user.type_assignments.size()));set(result,"patch_count",integer(user.patches.size()));
    set(result,"region_count",integer(user.decisions.regions.size()));set(result,"function_decision_count",integer(user.decisions.functions.size()));
    set(result,"user_reference_count",integer(user.decisions.references.size()));set(result,"debug_variable_count",integer(user.debug_variables.size()));
    return result.release();
}
PyObject* encode_function(const FunctionRecord& row){
    Object item(PyDict_New());set(item,"id",integer(row.id.value));set(item,"entry",encode(row.entry));set(item,"complete",PyBool_FromLong(row.complete));
    set(item,"block_count",integer(row.blocks.size()));set(item,"thunk",PyBool_FromLong(row.thunk));
    Object chunks(PyList_New(0));for(const auto& chunk:row.chunks){Object part(PyDict_New());set(part,"begin",encode(chunk.begin));set(part,"size",integer(chunk.size));append(chunks,part.release());}
    set(item,"chunks",chunks.release());return item.release();
}
PyObject* encode_instruction(const Instruction& row){
    Object item(PyDict_New());set(item,"address",encode(row.address));set(item,"text",string(format_instruction(row)));
    set(item,"bytes",PyBytes_FromStringAndSize(reinterpret_cast<const char*>(row.bytes.data()),row.length));
    set(item,"mode",integer(static_cast<unsigned>(row.context.mode)));set(item,"flow",integer(static_cast<unsigned>(row.flow)));
    constexpr std::string_view flow_names[]={"fallthrough","call","conditional_branch","jump","ret","trap"};
    const auto flow_index=static_cast<std::size_t>(row.flow);
    if(flow_index>=sizeof(flow_names)/sizeof(flow_names[0]))invalid("Unknown instruction flow kind");
    set(item,"flow_name",string(flow_names[flow_index]));
    set(item,"target",row.direct_target?encode(*row.direct_target):none());return item.release();
}
std::string_view reference_kind_name(ReferenceKind kind){
    switch(kind){
    case ReferenceKind::call:return "call";
    case ReferenceKind::jump:return "jump";
    case ReferenceKind::conditional_jump:return "conditional_jump";
    case ReferenceKind::memory_read:return "memory_read";
    case ReferenceKind::memory_write:return "memory_write";
    case ReferenceKind::memory_read_write:return "memory_read_write";
    case ReferenceKind::memory_address:return "memory_address";
    case ReferenceKind::imported_call:return "imported_call";
    case ReferenceKind::imported_jump:return "imported_jump";
    case ReferenceKind::user_code:return "user_code";
    case ReferenceKind::user_data:return "user_data";
    case ReferenceKind::relocation:return "relocation";
    case ReferenceKind::dyld_fixup:return "dyld_fixup";
    }
    invalid("Unknown reference kind");return {};
}
PyObject* encode_presentation(const LocationPresentation& row){
    Object item(PyDict_New());set(item,"name",string(row.name));set(item,"comment",string(row.comment));
    set(item,"user_name",PyBool_FromLong(row.user_name));set(item,"orphaned",PyBool_FromLong(row.orphaned));return item.release();
}
std::string_view edge_kind(BlockEdgeKind kind){
    switch(kind){
    case BlockEdgeKind::fallthrough:return "fallthrough";
    case BlockEdgeKind::conditional_true:return "conditional_true";
    case BlockEdgeKind::conditional_false:return "conditional_false";
    case BlockEdgeKind::jump:return "jump";
    case BlockEdgeKind::call_continuation:return "call_continuation";
    case BlockEdgeKind::unresolved:return "unresolved";
    case BlockEdgeKind::delay_slot:return "delay_slot";
    }
    invalid("Unknown native CFG edge kind");return {};
}
std::string_view stop_reason(FunctionStopReason reason){
    switch(reason){
    case FunctionStopReason::ret:return "ret";
    case FunctionStopReason::trap:return "trap";
    case FunctionStopReason::unsupported:return "unsupported";
    case FunctionStopReason::invalid:return "invalid";
    case FunctionStopReason::truncated:return "truncated";
    case FunctionStopReason::unmapped:return "unmapped";
    case FunctionStopReason::uninitialized:return "uninitialized";
    case FunctionStopReason::non_executable:return "non_executable";
    case FunctionStopReason::manual_data:return "manual_data";
    case FunctionStopReason::overlap:return "overlap";
    case FunctionStopReason::indirect:return "indirect";
    case FunctionStopReason::budget:return "budget";
    case FunctionStopReason::target_overflow:return "target_overflow";
    case FunctionStopReason::chunk_boundary:return "chunk_boundary";
    case FunctionStopReason::tail_candidate:return "tail_candidate";
    case FunctionStopReason::elf_relocation:return "elf_relocation";
    case FunctionStopReason::macho_relocation:return "macho_relocation";
    case FunctionStopReason::macho_dyld:return "macho_dyld";
    case FunctionStopReason::image_exclusion:return "image_exclusion";
    }
    invalid("Unknown native function stop reason");return {};
}
PyObject* encode_stop(const std::optional<FunctionStop>& stop){
    if(!stop)return none();
    Object item(PyDict_New());set(item,"address",encode(stop->address));set(item,"reason",string(stop_reason(stop->reason)));
    set(item,"detail",string(stop->detail));return item.release();
}
void capsule_destroy(PyObject* capsule){
    auto* ptr=static_cast<std::shared_ptr<Project>*>(PyCapsule_GetPointer(capsule,capsule_name));
    if(ptr)delete ptr;else PyErr_Clear();
}
PyObject* capsule(std::shared_ptr<Project> project){
    auto owned=std::make_unique<std::shared_ptr<Project>>(std::move(project));
    auto* result=PyCapsule_New(owned.get(),capsule_name,capsule_destroy);
    if(result)owned.release();return result;
}
void archive_capsule_destroy(PyObject* capsule){
    auto* ptr=static_cast<std::shared_ptr<automation::Archive>*>(PyCapsule_GetPointer(capsule,archive_capsule_name));
    if(ptr)delete ptr;else PyErr_Clear();
}
PyObject* archive_capsule(std::shared_ptr<automation::Archive> archive){
    auto owned=std::make_unique<std::shared_ptr<automation::Archive>>(std::move(archive));
    auto* result=PyCapsule_New(owned.get(),archive_capsule_name,archive_capsule_destroy);
    if(result)owned.release();return result;
}
void history_capsule_destroy(PyObject* capsule){
    auto* ptr=static_cast<std::shared_ptr<const automation::HistoricalState>*>(PyCapsule_GetPointer(capsule,history_capsule_name));
    if(ptr)delete ptr;else PyErr_Clear();
}
PyObject* history_capsule(std::shared_ptr<const automation::HistoricalState> state){
    auto owned=std::make_unique<std::shared_ptr<const automation::HistoricalState>>(std::move(state));
    auto* result=PyCapsule_New(owned.get(),history_capsule_name,history_capsule_destroy);
    if(result)owned.release();return result;
}
void search_cursor_destroy(PyObject* capsule){
    auto* ptr=static_cast<SearchCursor*>(PyCapsule_GetPointer(capsule,search_cursor_name));
    if(ptr)delete ptr;else PyErr_Clear();
}
PyObject* search_cursor_capsule(SearchCursor cursor){
    auto owned=std::make_unique<SearchCursor>(std::move(cursor));
    auto* result=PyCapsule_New(owned.get(),search_cursor_name,search_cursor_destroy);
    if(result)owned.release();return result;
}
std::optional<SearchCursor> search_cursor(PyObject* object){
    if(object==Py_None)return {};
    auto* ptr=static_cast<SearchCursor*>(PyCapsule_GetPointer(object,search_cursor_name));
    if(!ptr)throw PythonFailure{};
    return *ptr;
}
std::stop_source& stop_source(PyObject* object){
    auto* ptr=static_cast<std::shared_ptr<std::stop_source>*>(PyCapsule_GetPointer(object,stop_source_name));
    if(!ptr)throw PythonFailure{};
    return **ptr;
}
void stop_source_destroy(PyObject* capsule){
    auto* ptr=static_cast<std::shared_ptr<std::stop_source>*>(PyCapsule_GetPointer(capsule,stop_source_name));
    if(ptr)delete ptr;else PyErr_Clear();
}
PyObject* stop_source_capsule(std::shared_ptr<std::stop_source> source){
    auto owned=std::make_unique<std::shared_ptr<std::stop_source>>(std::move(source));
    auto* result=PyCapsule_New(owned.get(),stop_source_name,stop_source_destroy);
    if(result)owned.release();return result;
}
Project& project(PyObject* object){auto* ptr=static_cast<std::shared_ptr<Project>*>(PyCapsule_GetPointer(object,capsule_name));if(!ptr)throw PythonFailure{};return **ptr;}
automation::Archive& archive(PyObject* object){auto* ptr=static_cast<std::shared_ptr<automation::Archive>*>(PyCapsule_GetPointer(object,archive_capsule_name));if(!ptr)throw PythonFailure{};return **ptr;}
const automation::HistoricalState& historical_state(PyObject* object){auto* ptr=static_cast<std::shared_ptr<const automation::HistoricalState>*>(PyCapsule_GetPointer(object,history_capsule_name));if(!ptr)throw PythonFailure{};return **ptr;}
const char* thread_state_name(debugger::ThreadState state){
    switch(state){
    case debugger::ThreadState::running:return "running";
    case debugger::ThreadState::stopped:return "stopped";
    case debugger::ThreadState::exited:return "exited";
    case debugger::ThreadState::unknown:return "unknown";
    }
    return "unknown";
}
struct DebugOwner { debugger::DebugSession session; std::thread::id owner=std::this_thread::get_id(); explicit DebugOwner(std::unique_ptr<debugger::Backend> backend):session(std::move(backend)){} };
DebugOwner& debug_owner(PyObject* object){auto* ptr=static_cast<DebugOwner*>(PyCapsule_GetPointer(object,debugger_name));if(!ptr)throw PythonFailure{};if(ptr->owner!=std::this_thread::get_id())invalid("Debugger sessions are bound to their creating thread");return *ptr;}
void debugger_destroy(PyObject* capsule){auto* ptr=static_cast<DebugOwner*>(PyCapsule_GetPointer(capsule,debugger_name));if(ptr)delete ptr;else PyErr_Clear();}
PyObject* encode_process(const debugger::ProcessInfo& row){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"name",string(row.name));set(item,"architecture",integer(static_cast<unsigned>(row.architecture)));return item.release();}
PyObject* encode_debug_event(const debugger::DebugEvent& row){Object item(PyDict_New()),ids(PyList_New(0));set(item,"sequence",integer(row.sequence));set(item,"kind",integer(static_cast<unsigned>(row.kind)));set(item,"process",integer(row.process));set(item,"thread",integer(row.thread));set(item,"address",integer(row.address));set(item,"message",string(row.message));set(item,"code",integer(row.code));set(item,"first_chance",row.first_chance?PyBool_FromLong(*row.first_chance):none());for(auto id:row.breakpoint_ids)append(ids,integer(id));set(item,"breakpoint_ids",ids.release());return item.release();}
std::vector<std::byte> bytes_value(PyObject* object){char* data=nullptr;Py_ssize_t length=0;if(PyBytes_AsStringAndSize(object,&data,&length)<0)throw PythonFailure{};if(length>static_cast<Py_ssize_t>(debugger::max_inspection_read))invalid("Debugger buffer exceeds1MiB limit");auto* begin=reinterpret_cast<const std::byte*>(data);return {begin,begin+length};}
PyObject* create_debugger(PyObject*,PyObject* args){return guarded([&]()->PyObject*{count(args,0);auto owner=std::make_unique<DebugOwner>(debugger::make_backend_router(debugger::make_native_backend()));auto* result=PyCapsule_New(owner.get(),debugger_name,debugger_destroy);if(result)owner.release();return result;});}
PyObject* call_debugger(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    count(args,3);auto& owner=debug_owner(argument(args,0));auto& session=owner.session;const auto method=text(argument(args,1));auto* values=argument(args,2);
    if(method=="state"){count(values,0);return integer(static_cast<unsigned>(session.state()));}
    if(method=="launch"){
        count(values,3);debugger::Target target;target.executable=text(argument(values,0));target.working_directory=text(argument(values,2));auto* argv=argument(values,1);if(!PyList_Check(argv)&&!PyTuple_Check(argv))invalid("debugger arguments must be a sequence of strings");if(PySequence_Size(argv)>4096)invalid("too many debugger arguments");for(Py_ssize_t i=0;i<PySequence_Size(argv);++i){Object value(PySequence_GetItem(argv,i));target.arguments.push_back(text(value));}auto process=without_gil([&]{return session.launch(target);});return encode_process(take(std::move(process)));
    }
    if(method=="attach"){count(values,1);const auto process_id=number(argument(values,0));auto process=without_gil([&]{return session.attach(process_id);});return encode_process(take(std::move(process)));}
    if(method=="connect_remote"){count(values,2);auto port=number32(argument(values,1));if(port==0||port>65535)invalid("remote port must be in 1..65535");const auto host=text(argument(values,0));auto process=without_gil([&]{return session.connect_remote(host,static_cast<std::uint16_t>(port));});return encode_process(take(std::move(process)));}
    if(method=="wait_event"){
        if(PyTuple_Size(values)==1){
            const auto timeout=number(argument(values,0));if(timeout>600000)invalid("event timeout exceeds600000ms");
            auto event=without_gil([&]{return session.wait_event(std::chrono::milliseconds(timeout));});
            return encode_debug_event(take(std::move(event)));
        }
        count(values,2);const auto timeout=number(argument(values,0));if(timeout>600000)invalid("event timeout exceeds600000ms");
        auto& source=stop_source(argument(values,1));
        const auto duration=std::chrono::milliseconds(timeout);
        const auto deadline=std::chrono::steady_clock::now()+duration;
        for(;;){
            if(source.stop_requested())throw NativeFailure{{ErrorCode::canceled,"debugger event wait canceled"}};
            const auto remaining=std::chrono::ceil<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now());
            const auto slice=timeout==0?std::chrono::milliseconds(0):
                std::min(std::max(remaining,std::chrono::milliseconds(0)),std::chrono::milliseconds(50));
            auto event=without_gil([&]{return session.wait_event(slice);});
            if(event)return encode_debug_event(event.value());
            const auto& error=event.error();
            const bool timed_out=error.code==ErrorCode::busy &&
                (error.message=="debug event wait timed out" || error.message=="remote target has not stopped yet");
            if(!timed_out)throw NativeFailure{error};
            if(source.stop_requested())throw NativeFailure{{ErrorCode::canceled,"debugger event wait canceled"}};
            if(timeout==0 || std::chrono::steady_clock::now()>=deadline)throw NativeFailure{error};
        }
    }
    if(method=="continue"){count(values,2);auto status=text(argument(values,1));if(status!="handled"&&status!="not_handled")invalid("status must be handled or not_handled");take(session.continue_execution(number(argument(values,0)),status=="handled"?debugger::ContinueStatus::handled:debugger::ContinueStatus::not_handled));return none();}
    if(method=="step"){count(values,2);auto status=text(argument(values,1));if(status!="handled"&&status!="not_handled")invalid("status must be handled or not_handled");take(session.single_step_execution(number(argument(values,0)),status=="handled"?debugger::ContinueStatus::handled:debugger::ContinueStatus::not_handled));return none();}
    if(method=="resume_threads"){
        count(values,2);
        auto* rows=argument(values,1);
        if(!PyList_Check(rows)&&!PyTuple_Check(rows))
            invalid("thread resume actions must be a list or tuple");
        const auto row_count=PySequence_Size(rows);
        if(row_count<=0 || row_count>debugger::max_inspection_threads)
            invalid("thread resume actions must be a non-empty sequence of at most 4096 records");
        std::vector<debugger::ThreadResumeAction> actions;
        actions.reserve(static_cast<std::size_t>(row_count));
        for(Py_ssize_t i=0;i<row_count;++i){
            Object row(PySequence_GetItem(rows,i));
            if(!PyDict_Check(row))invalid("thread resume action must be a mapping");
            auto* thread=PyDict_GetItemString(row,"thread_id");
            auto* kind=PyDict_GetItemString(row,"kind");
            if(!thread || !kind)invalid("thread resume action requires thread_id and kind");
            const auto name=text(kind);
            auto action=debugger::ThreadResumeKind::continue_execution;
            if(name=="continue")action=debugger::ThreadResumeKind::continue_execution;
            else if(name=="step")action=debugger::ThreadResumeKind::single_step;
            else if(name=="stop")action=debugger::ThreadResumeKind::stop;
            else invalid("thread action kind must be continue, step, or stop");
            actions.push_back({number(thread),action});
        }
        take(session.resume_threads(number(argument(values,0)),actions));
        return none();
    }
    if(method=="interrupt"){count(values,0);take(session.request_interrupt());return none();}
    if(method=="detach"){count(values,0);take(session.detach());return none();}
    if(method=="read_memory"){count(values,2);auto result=take(session.read_memory(number(argument(values,0)),size(argument(values,1))));return PyBytes_FromStringAndSize(reinterpret_cast<const char*>(result.data()),static_cast<Py_ssize_t>(result.size()));}
    if(method=="write_memory"){count(values,2);auto data=bytes_value(argument(values,1));take(session.write_memory(number(argument(values,0)),data));return none();}
    if(method=="threads") {count(values,0);Object rows(PyList_New(0));for(const auto& row:take(session.threads())){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"name",string(row.name));set(item,"state",integer(static_cast<unsigned>(row.state)));append(rows,item.release());}return rows.release();}
    if(method=="thread_run_states") {count(values,0);Object rows(PyList_New(0));for(const auto& row:take(session.thread_run_states())){Object item(PyDict_New());set(item,"thread_id",integer(row.thread));set(item,"state",string(thread_state_name(row.state)));append(rows,item.release());}return rows.release();}
    if(method=="modules") {count(values,0);Object rows(PyList_New(0));for(const auto& row:take(session.modules())){Object item(PyDict_New());set(item,"name",string(row.name));set(item,"path",string(row.path));set(item,"base",integer(row.base));set(item,"size",integer(row.size));append(rows,item.release());}return rows.release();}
    if(method=="memory_regions") {count(values,0);Object rows(PyList_New(0));for(const auto& row:take(session.memory_regions())){Object item(PyDict_New());set(item,"start",integer(row.start));set(item,"length",integer(row.length));set(item,"readable",PyBool_FromLong(row.readable));set(item,"writable",PyBool_FromLong(row.writable));set(item,"executable",PyBool_FromLong(row.executable));set(item,"type",string(row.type));append(rows,item.release());}return rows.release();}
    if(method=="registers") {count(values,1);Object rows(PyList_New(0));for(const auto& row:take(session.read_registers(number(argument(values,0))))){Object item(PyDict_New());set(item,"name",string(row.name));set(item,"bytes",PyBytes_FromStringAndSize(reinterpret_cast<const char*>(row.bytes.data()),static_cast<Py_ssize_t>(row.bytes.size())));set(item,"group",string(row.group));set(item,"number",integer(row.number));set(item,"byte_order",row.byte_order?integer(static_cast<unsigned>(*row.byte_order)):none());append(rows,item.release());}return rows.release();}
    if(method=="write_registers") {count(values,2);auto* rows=argument(values,1);if(!PyList_Check(rows)||PyList_Size(rows)>4096)invalid("register writes must be a list of at most4096 records");std::vector<debugger::RegisterValue> writes;for(Py_ssize_t i=0;i<PyList_Size(rows);++i){auto* row=PyList_GetItem(rows,i);debugger::RegisterValue value;value.name=text(PyDict_GetItemString(row,"name"));value.bytes=bytes_value(PyDict_GetItemString(row,"bytes"));writes.push_back(std::move(value));}take(session.write_registers(number(argument(values,0)),writes));return none();}
    if(method=="breakpoints") {count(values,0);Object rows(PyList_New(0));for(const auto& row:session.breakpoints()){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"address",integer(row.address));set(item,"kind",integer(static_cast<unsigned>(row.kind)));set(item,"enabled",PyBool_FromLong(row.enabled));set(item,"size",integer(row.size));set(item,"hit_count",integer(row.hit_count));set(item,"ignore_count",integer(row.ignore_count));set(item,"condition",string(row.condition));set(item,"logpoint",PyBool_FromLong(row.logpoint));set(item,"log_message",string(row.log_message));append(rows,item.release());}return rows.release();}
    if(method=="add_breakpoint") {count(values,3);const auto address=number(argument(values,0));const auto kind=text(argument(values,1));const auto width=number32(argument(values,2));if(width>255)invalid("breakpoint size exceeds255");debugger::BreakpointKind selected=debugger::BreakpointKind::software;if(kind=="software")selected=debugger::BreakpointKind::software;else if(kind=="hardware")selected=debugger::BreakpointKind::hardware;else if(kind=="execute")selected=debugger::BreakpointKind::execute;else if(kind=="read")selected=debugger::BreakpointKind::read;else if(kind=="write")selected=debugger::BreakpointKind::write;else if(kind=="access")selected=debugger::BreakpointKind::access;else invalid("unknown breakpoint kind");const auto row=take(session.add_breakpoint(address,selected,static_cast<std::uint8_t>(width)));Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"address",integer(row.address));set(item,"kind",integer(static_cast<unsigned>(row.kind)));set(item,"enabled",PyBool_FromLong(row.enabled));set(item,"size",integer(row.size));return item.release();}
    if(method=="remove_breakpoint"){count(values,1);take(session.remove_breakpoint(number(argument(values,0))));return none();}
    if(method=="enable_breakpoint"){count(values,2);take(session.set_breakpoint_enabled(number(argument(values,0)),boolean(argument(values,1))));return none();}
    if(method=="set_breakpoint_ignore_count"){count(values,2);if(PyBool_Check(argument(values,1)))invalid("ignore_count must be an unsigned integer, not bool");take(session.set_breakpoint_ignore_count(number(argument(values,0)),number(argument(values,1))));return none();}
    if(method=="set_breakpoint_condition"){count(values,2);take(session.set_breakpoint_condition(number(argument(values,0)),text(argument(values,1))));return none();}
    if(method=="set_breakpoint_logpoint"){count(values,3);take(session.set_breakpoint_logpoint(number(argument(values,0)),boolean(argument(values,1)),text(argument(values,2))));return none();}
    invalid("Unknown debugger method");return nullptr;
});}

template<class F>PyObject* guarded(F operation){
    try{return operation();}
    catch(const PythonFailure&){if(!PyErr_Occurred())PyErr_SetString(PyExc_RuntimeError,"Python automation conversion failed");}
    catch(const NativeFailure& failure){
        auto* exception=PyObject_CallFunction(error_type,"s",failure.error.message.c_str());
        if(exception){
            auto* code=integer(static_cast<unsigned>(failure.error.code));
            if(code){PyObject_SetAttrString(exception,"code",code);Py_DECREF(code);}
            PyErr_SetObject(error_type,exception);Py_DECREF(exception);
        }
    }
    catch(const std::bad_alloc&){PyErr_NoMemory();}
    catch(const std::exception& error){PyErr_SetString(PyExc_RuntimeError,error.what());}
    catch(...){PyErr_SetString(PyExc_RuntimeError,"Unknown native automation failure");}
    return nullptr;
}
PyObject* create_stop_source(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    count(args,0);return stop_source_capsule(std::make_shared<std::stop_source>());
});}
PyObject* request_stop(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    count(args,1);stop_source(argument(args,0)).request_stop();return none();
});}
PyObject* stop_requested(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    count(args,1);return PyBool_FromLong(stop_source(argument(args,0)).stop_requested());
});}
PyObject* open_project(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    const bool legacy=PyTuple_Check(args)&&PyTuple_Size(args)==3;count(args,legacy?3:4);
    const auto source=path(argument(args,0));const auto readonly=boolean(argument(args,1));const auto version=number32(argument(args,2));
    const auto stop=legacy||argument(args,3)==Py_None?std::stop_token{}:stop_source(argument(args,3)).get_token();
    return capsule(take(without_gil([&]{return Project::open(source,readonly,version,stop);})));
});}
PyObject* open_archive(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    count(args,2);const auto source=path(argument(args,0));const auto version=number32(argument(args,1));
    auto opened=without_gil([&]{return automation::Archive::open(source,version);});
    return archive_capsule(take(std::move(opened)));
});}
PyObject* call_archive(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    count(args,3);auto& owner=archive(argument(args,0));const auto method=text(argument(args,1));auto* values=argument(args,2);
    if(method=="summary"){
        count(values,0);const auto row=take(owner.summary());Object item(PyDict_New()),diagnostics(PyList_New(0));
        set(item,"member_count",integer(row.member_count));set(item,"symbol_count",integer(row.symbol_count));
        set(item,"has_symbol_index",PyBool_FromLong(row.has_symbol_index));
        set(item,"symbol_index_complete",PyBool_FromLong(row.symbol_index_complete));
        for(const auto& diagnostic:row.diagnostics)append(diagnostics,string(diagnostic));
        set(item,"diagnostics",diagnostics.release());return item.release();
    }
    if(method=="members"){
        count(values,2);const auto rows=take(owner.members(size(argument(values,0)),size(argument(values,1))));Object list(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"index",integer(row.index));set(item,"name",string(row.name));
            set(item,"header_offset",integer(row.header_offset.value));set(item,"data_offset",integer(row.data_offset.value));
            set(item,"size",integer(row.size));const char* kind=row.kind==ArMemberKind::regular?"regular":row.kind==ArMemberKind::symbol_index?"symbol_index":"long_name_table";
            set(item,"kind",string(kind));append(list,item.release());}
        return list.release();
    }
    if(method=="symbols"){
        count(values,2);const auto rows=take(owner.symbols(size(argument(values,0)),size(argument(values,1))));Object list(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"name",string(row.name));set(item,"member_index",integer(row.member_index));append(list,item.release());}
        return list.release();
    }
    if(method=="read_member"){
        count(values,3);auto bytes=take(owner.read_member(size(argument(values,0)),number(argument(values,1)),size(argument(values,2))));
        return PyBytes_FromStringAndSize(reinterpret_cast<const char*>(bytes.data()),static_cast<Py_ssize_t>(bytes.size()));
    }
    invalid("Unknown archive method");return nullptr;
});}
PyObject* create_project(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    const bool legacy=PyTuple_Check(args)&&PyTuple_Size(args)==9;count(args,legacy?9:10);
    auto output=path(argument(args,0)),input=path(argument(args,1));const auto format=text(argument(args,2));
    const auto version=number32(argument(args,8));
    const auto stop=legacy||argument(args,9)==Py_None?std::stop_token{}:stop_source(argument(args,9)).get_token();
    LoadRecipe recipe{Format::automatic,{}};
    if(format=="profile"){
        const auto profile_path=path(argument(args,7));
        auto profile=take(without_gil([&]{return read_x86_profile(profile_path,stop);}));recipe={Format::raw,take(make_x86_raw_options(std::move(profile)))};
    }else if(format=="raw"){
        const auto mode=text(argument(args,3));
        if(mode!="x86-64" && mode!="x86-32")invalid("Raw mode must be x86-32 or x86-64; use create_profile for16-bit segments");
        RawOptions raw{mode=="x86-64"?Architecture::x86_64:Architecture::x86,mode=="x86-64"?ExecutionMode::x86_64:ExecutionMode::x86_32,
            {{number32(argument(args,5))},number(argument(args,4))},true,false,true,{}};
        if(argument(args,6)!=Py_None)raw.entry=Address{raw.base.space,number(argument(args,6))};
        recipe={Format::raw,raw};
    }else if(format=="pe")recipe.format=Format::pe;
    else if(format=="elf")recipe.format=Format::elf;
    else if(format=="macho")recipe.format=Format::macho;
    else if(format!="auto")invalid("Unknown automation import format");
    return capsule(take(without_gil([&]{return Project::create(output,input,recipe,version,stop);})));
});}
PyObject* call_historical_state(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    count(args,3);const auto& state=historical_state(argument(args,0));const auto method=text(argument(args,1));auto* values=argument(args,2);
    if(method=="snapshot"){count(values,0);return encode_historical_metadata(state);}
    if(method=="read"){
        count(values,2);auto at=location(argument(values,0));const auto* offset=std::get_if<FileOffset>(&at);
        if(!offset)invalid("Historical reads require FileOffset coordinates");
        const auto amount=size(argument(values,1));
        auto bytes=take(without_gil([&]{return state.read(*offset,amount);}));
        return PyBytes_FromStringAndSize(reinterpret_cast<const char*>(bytes.data()),static_cast<Py_ssize_t>(bytes.size()));
    }
    if(method=="function_chunks"){
        count(values,3);auto rows=take(state.function_chunks(number(argument(values,0)),size(argument(values,1)),size(argument(values,2))));
        Object result(PyList_New(0));for(const auto& row:rows){Object item(PyDict_New());set(item,"begin",encode(row.begin));set(item,"size",integer(row.size));append(result,item.release());}
        return result.release();
    }
    count(values,2);const auto start=size(argument(values,0)),amount=size(argument(values,1));Object result(PyList_New(0));
    if(method=="annotations"){
        for(const auto& row:take(state.annotations(start,amount))){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"location",encode(row.location));set(item,"name",string(row.name));set(item,"comment",string(row.comment));append(result,item.release());}
    }else if(method=="bookmarks"){
        for(const auto& row:take(state.bookmarks(start,amount))){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"location",encode(row.location));set(item,"label",string(row.label));append(result,item.release());}
    }else if(method=="types"){
        for(const auto& row:take(state.types(start,amount))){
            Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"name",string(row.name));set(item,"type",encode_type_spec(*row.type));
            const auto kind=row.declaration_kind;set(item,"declaration_kind",string(kind==database::DeclarationKind::type?"type":kind==database::DeclarationKind::object?"object":"function"));
            if(row.origin){Object origin(PyDict_New());set(origin,"source_id",string(row.origin->source_id));set(origin,"section",string(row.origin->section));set(origin,"unit_offset",integer(row.origin->unit_offset));set(origin,"record_offset",integer(row.origin->record_offset));set(origin,"record_size",integer(row.origin->record_size));set(item,"origin",origin.release());}
            else set(item,"origin",none());append(result,item.release());
        }
    }else if(method=="type_assignments"){
        for(const auto& row:take(state.type_assignments(start,amount))){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"location",encode(row.location));set(item,"type_id",integer(row.type_id));append(result,item.release());}
    }else if(method=="patches"){
        for(const auto& row:take(state.patches(start,amount))){Object item(PyDict_New());set(item,"begin",encode(Location{row.begin}));set(item,"size",integer(row.size));append(result,item.release());}
    }else if(method=="regions"){
        for(const auto& row:take(state.regions(start,amount))){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"begin",encode(row.begin));set(item,"size",integer(row.size));set(item,"kind",string(row.kind==RegionKind::code?"code":"data"));append(result,item.release());}
    }else if(method=="function_decisions"){
        for(const auto& row:take(state.function_decisions(start,amount))){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"entry",encode(row.entry));set(item,"suppressed",PyBool_FromLong(row.suppressed));set(item,"chunk_count",integer(row.chunk_count));append(result,item.release());}
    }else if(method=="user_references"){
        constexpr const char* kinds[]={"code","data","call","jump","read","write","address"};
        for(const auto& row:take(state.user_references(start,amount))){
            const auto index=static_cast<unsigned>(row.kind);if(index>=std::size(kinds))invalid("Unknown historical reference kind");
            Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"source",encode(row.source));set(item,"target",encode(row.target));set(item,"kind",string(kinds[index]));append(result,item.release());
        }
    }else invalid("Unknown historical state method");
    return result.release();
});}
PyObject* call_project(PyObject*,PyObject* args){return guarded([&]()->PyObject*{
    count(args,3);auto& p=project(argument(args,0));const auto method=text(argument(args,1));auto* values=argument(args,2);
    if(method=="snapshot"){count(values,0);return encode_snapshot(*take(p.snapshot()));}
    if(method=="check_owner"){count(values,0);take(p.snapshot());return none();}
    if(method=="capture"){
        count(values,2);const auto expected=argument(values,0)==Py_None?std::optional<std::uint64_t>{}:number(argument(values,0));
        const auto stop=argument(values,1)==Py_None?std::stop_token{}:stop_source(argument(values,1)).get_token();
        return capsule(take(without_gil([&]{return p.capture(expected,stop);})));
    }
    if(method=="debug_edit_revision"){count(values,0);return integer(take(p.snapshot())->state->revisions.edit);}
    if(method=="image_info"){
        count(values,0);const auto row=take(p.image_info());Object out(PyDict_New()),entries(PyList_New(0));
        set(out,"mapped",PyBool_FromLong(row.mapped));set(out,"metadata_complete",PyBool_FromLong(row.metadata_complete));
        set(out,"format",string(row.format));set(out,"machine",integer(row.machine));set(out,"preferred_base",integer(row.preferred_base));
        set(out,"image_size",integer(row.image_size));set(out,"header_size",integer(row.header_size));
        set(out,"architecture",integer(row.architecture));set(out,"mode",integer(row.mode));
        set(out,"segment_count",integer(row.segment_count));set(out,"address_space_count",integer(row.address_space_count));
        for(const auto entry:row.entries)append(entries,encode(entry));set(out,"entries",entries.release());return out.release();
    }
    if(method=="annotations"){
        count(values,2);auto rows=take(p.annotations(size(argument(values,0)),size(argument(values,1))));Object out(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"location",encode(row.location));set(item,"name",string(row.name));set(item,"comment",string(row.comment));append(out,item.release());}return out.release();
    }
    if(method=="types"){
        count(values,2);auto rows=take(p.types(size(argument(values,0)),size(argument(values,1))));Object out(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"name",string(row.name));set(item,"type",encode_type_spec(*row.type));set(item,"declaration_kind",integer(static_cast<unsigned>(row.declaration_kind)));append(out,item.release());}return out.release();
    }
    if(method=="type_assignments"){
        count(values,2);auto rows=take(p.type_assignments(size(argument(values,0)),size(argument(values,1))));Object out(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"id",integer(row.id));set(item,"location",encode(row.location));set(item,"type_id",integer(row.type_id));append(out,item.release());}return out.release();
    }
    if(method=="preview_debug_import"){
        count(values,2);const auto kind=debug_import_kind(argument(values,0));
        const auto stop=argument(values,1)==Py_None?std::stop_token{}:stop_source(argument(values,1)).get_token();
        const auto row=take(without_gil([&]{return p.preview_debug_import(kind,stop);}));Object out(PyDict_New());
        set(out,"project_uuid",encode_uuid(row.project_uuid));set(out,"edit_revision",integer(row.edit_revision));
        set(out,"ready",PyBool_FromLong(row.ready));set(out,"readonly",PyBool_FromLong(row.readonly));
        set(out,"reason",string(row.reason));set(out,"error_code",row.error_code?integer(static_cast<unsigned>(*row.error_code)):none());
        set(out,"changes",integer(row.changes));set(out,"annotations",integer(row.annotations));set(out,"types",integer(row.types));
        set(out,"type_assignments",integer(row.type_assignments));set(out,"functions",integer(row.functions));set(out,"variables",integer(row.variables));
        return out.release();
    }
    if(method=="import_debug_info"){
        count(values,4);const auto kind=debug_import_kind(argument(values,0));const auto expected=number(argument(values,1));
        const auto group=number(argument(values,2));
        const auto stop=argument(values,3)==Py_None?std::stop_token{}:stop_source(argument(values,3)).get_token();
        auto result=without_gil([&]{return p.import_debug_info(kind,expected,group,stop);});
        return encode_snapshot(*take(std::move(result)));
    }
    if(method=="debug_variables"){
        count(values,5);const auto entry=argument(values,0)==Py_None?std::optional<Address>{}:address(argument(values,0));
        const auto start=size(argument(values,1)),amount=size(argument(values,2));
        const auto expected=argument(values,3)==Py_None?std::optional<std::uint64_t>{}:number(argument(values,3));
        const auto stop=argument(values,4)==Py_None?std::stop_token{}:stop_source(argument(values,4)).get_token();
        const auto rows=take(without_gil([&]{return p.debug_variables(entry,start,amount,expected,stop);}));Object out(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New()),origin(PyDict_New());
            set(item,"id",integer(row.id));set(item,"function_entry",encode(row.function_entry));set(item,"name",string(row.name));
            set(item,"type_id",row.type_id?integer(*row.type_id):none());set(item,"is_parameter",PyBool_FromLong(row.is_parameter));
            set(item,"scope_offset",integer(row.scope_offset));set(item,"address",row.address?integer(*row.address):none());
            set(item,"cfa_offset",row.cfa_offset?signed_integer(*row.cfa_offset):none());
            set(origin,"source_id",string(row.origin.source_id));set(origin,"section",string(row.origin.section));
            set(origin,"unit_offset",integer(row.origin.unit_offset));set(origin,"record_offset",integer(row.origin.record_offset));
            set(origin,"record_size",integer(row.origin.record_size));set(item,"origin",origin.release());
            set(item,"expression_size",integer(row.expression_size));set(item,"operation_count",integer(row.operation_count));
            set(item,"location_range_count",integer(row.location_range_count));append(out,item.release());
        }return out.release();
    }
    if(method=="debug_location_ranges"){
        count(values,5);const auto id=number(argument(values,0));const auto start=size(argument(values,1)),amount=size(argument(values,2));
        const auto expected=argument(values,3)==Py_None?std::optional<std::uint64_t>{}:number(argument(values,3));
        const auto stop=argument(values,4)==Py_None?std::stop_token{}:stop_source(argument(values,4)).get_token();
        const auto rows=take(without_gil([&]{return p.debug_location_ranges(id,start,amount,expected,stop);}));
        Object out(PyList_New(0));for(const auto& row:rows){Object item(PyDict_New());
            set(item,"begin",integer(row.begin));set(item,"end",integer(row.end));set(item,"expression_size",integer(row.expression_size));
            set(item,"operation_count",integer(row.operation_count));append(out,item.release());
        }return out.release();
    }
    if(method=="debug_location_operations"){
        count(values,6);const auto range=argument(values,1)==Py_None?std::optional<std::size_t>{}:size(argument(values,1));
        const auto id=number(argument(values,0));const auto start=size(argument(values,2)),amount=size(argument(values,3));
        const auto expected=argument(values,4)==Py_None?std::optional<std::uint64_t>{}:number(argument(values,4));
        const auto stop=argument(values,5)==Py_None?std::stop_token{}:stop_source(argument(values,5)).get_token();
        const auto rows=take(without_gil([&]{return p.debug_location_operations(id,range,start,amount,expected,stop);}));
        Object out(PyList_New(0));for(const auto& row:rows){Object item(PyDict_New());
            set(item,"kind",integer(row.kind));set(item,"unsigned_operand",integer(row.unsigned_operand));
            set(item,"signed_operand",signed_integer(row.signed_operand));set(item,"expression_offset",integer(row.expression_offset));
            set(item,"second_unsigned_operand",integer(row.second_unsigned_operand));append(out,item.release());
        }return out.release();
    }
    if(method=="read_debug_expression"){
        count(values,6);const auto range=argument(values,3)==Py_None?std::optional<std::size_t>{}:size(argument(values,3));
        const auto id=number(argument(values,0));const auto offset=size(argument(values,1)),amount=size(argument(values,2));
        const auto expected=argument(values,4)==Py_None?std::optional<std::uint64_t>{}:number(argument(values,4));
        const auto stop=argument(values,5)==Py_None?std::stop_token{}:stop_source(argument(values,5)).get_token();
        const auto data=take(without_gil([&]{return p.read_debug_expression(id,offset,amount,range,expected,stop);}));
        return PyBytes_FromStringAndSize(reinterpret_cast<const char*>(data.data()),static_cast<Py_ssize_t>(data.size()));
    }
    if(method=="history"){
        count(values,4);const auto after=number(argument(values,0));const auto amount=size(argument(values,1));
        const auto expected=argument(values,2)==Py_None?std::optional<std::uint64_t>{}:number(argument(values,2));
        const auto stop=argument(values,3)==Py_None?std::stop_token{}:stop_source(argument(values,3)).get_token();
        auto page=take(without_gil([&]{return p.history(after,amount,expected,stop);}));return encode_history_page(page);
    }
    if(method=="preview_history"){
        count(values,5);const auto target=number(argument(values,0));
        const database::HistoryPreviewLimits limits{size(argument(values,1)),size(argument(values,2))};
        const auto expected=argument(values,3)==Py_None?std::optional<std::uint64_t>{}:number(argument(values,3));
        const auto stop=argument(values,4)==Py_None?std::stop_token{}:stop_source(argument(values,4)).get_token();
        return history_capsule(take(without_gil([&]{return p.preview_history(target,limits,expected,stop);})));
    }
    if(method=="read"){
        const bool legacy=PyTuple_Check(values)&&PyTuple_Size(values)==2;count(values,legacy?2:3);
        const auto at=location(argument(values,0));const auto amount=size(argument(values,1));
        const auto stop=legacy||argument(values,2)==Py_None?std::stop_token{}:stop_source(argument(values,2)).get_token();
        auto bytes=take(without_gil([&]{return p.read(at,amount,stop);}));
        return PyBytes_FromStringAndSize(reinterpret_cast<const char*>(bytes.data()),static_cast<Py_ssize_t>(bytes.size()));
    }
    if(method=="logical"){
        count(values,2);auto selector=number(argument(values,0));if(selector>UINT16_MAX)invalid("Selector exceeds16 bits");
        return encode(take(p.logical({static_cast<std::uint16_t>(selector),number32(argument(values,1))})));
    }
    if(method=="functions"){
        count(values,2);auto rows=take(p.functions(size(argument(values,0)),size(argument(values,1))));Object list(PyList_New(0));
        for(const auto& row:rows)append(list,encode_function(row));
        return list.release();
    }
    if(method=="function_at"){
        count(values,1);auto row=take(p.function_at(address(argument(values,0))));
        return row?encode_function(*row):none();
    }
    if(method=="function_owners"){
        count(values,1);auto rows=take(p.function_owners(address(argument(values,0))));Object list(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"id",integer(row.id.value));set(item,"entry",encode(row.entry));append(list,item.release());}
        return list.release();
    }
    if(method=="stack_frame"){
        count(values,1);auto row=take(p.stack_frame(address(argument(values,0))));
        if(!row)return none();
        Object item(PyDict_New());set(item,"function_id",integer(row->function.value));set(item,"entry",encode(row->entry));
        set(item,"maximum_stack_allocation_bytes",row->maximum_stack_allocation_bytes?integer(*row->maximum_stack_allocation_bytes):none());
        set(item,"slot_count",integer(row->slot_count));set(item,"complete",PyBool_FromLong(row->complete));return item.release();
    }
    if(method=="stack_slots"){
        count(values,3);auto rows=take(p.stack_slots(address(argument(values,0)),size(argument(values,1)),size(argument(values,2))));Object list(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"offset_from_entry_sp",signed_integer(row.offset_from_entry_sp));
            set(item,"width",integer(row.width));set(item,"access_count",integer(row.access_count));
            set(item,"read",PyBool_FromLong(row.read));set(item,"written",PyBool_FromLong(row.written));
            set(item,"address_taken",PyBool_FromLong(row.address_taken));append(list,item.release());}
        return list.release();
    }
    if(method=="stack_slot_accesses"){
        count(values,4);auto rows=take(p.stack_slot_accesses(address(argument(values,0)),size(argument(values,1)),size(argument(values,2)),size(argument(values,3))));Object list(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"instruction",encode(row.instruction));
            set(item,"read",PyBool_FromLong(row.read));set(item,"written",PyBool_FromLong(row.written));
            set(item,"address_taken",PyBool_FromLong(row.address_taken));append(list,item.release());}
        return list.release();
    }
    if(method=="decompile"){
        count(values,1);const auto target=address(argument(values,0));
        auto row=take(without_gil([&]{return p.decompile(target);}));
        Object result(PyDict_New()),diagnostics(PyList_New(0));
        set(result,"entry",encode(row.entry));set(result,"text",string(row.text));
        set(result,"complete",PyBool_FromLong(row.complete));set(result,"used_fallback",PyBool_FromLong(row.used_fallback));
        set(result,"fallback_reason",string(row.fallback_reason));
        for(const auto& diagnostic:row.diagnostics)append(diagnostics,string(diagnostic));
        set(result,"diagnostics",diagnostics.release());return result.release();
    }
    if(method=="presentation"){
        count(values,1);return encode_presentation(take(p.presentation(location(argument(values,0)))));
    }
    if(method=="function_blocks"){
        count(values,3);auto rows=take(p.function_blocks(address(argument(values,0)),size(argument(values,1)),size(argument(values,2))));Object list(PyList_New(0));
        for(const auto& row:rows){
            Object item(PyDict_New());set(item,"id",integer(row.id.value));set(item,"begin",encode(row.begin));
            set(item,"instruction_count",integer(row.instruction_count));set(item,"successor_count",integer(row.successor_count));
            set(item,"stop",encode_stop(row.stop));set(item,"presentation",encode_presentation(row.presentation));append(list,item.release());
        }
        return list.release();
    }
    if(method=="block_instructions"){
        count(values,3);auto rows=take(p.block_instructions(BlockId{number(argument(values,0))},size(argument(values,1)),size(argument(values,2))));Object list(PyList_New(0));
        for(const auto& row:rows)append(list,encode_instruction(row));
        return list.release();
    }
    if(method=="block_successors"){
        count(values,3);auto rows=take(p.block_successors(BlockId{number(argument(values,0))},size(argument(values,1)),size(argument(values,2))));Object list(PyList_New(0));
        for(const auto& row:rows){
            Object item(PyDict_New());set(item,"source",encode(row.source));set(item,"target",row.target?encode(*row.target):none());
            set(item,"block",row.block?integer(row.block->value):none());set(item,"kind",string(edge_kind(row.kind)));append(list,item.release());
        }
        return list.release();
    }
    if(method=="instructions"){
        count(values,2);auto rows=take(p.instructions(size(argument(values,0)),size(argument(values,1))));Object list(PyList_New(0));
        for(const auto& row:rows)append(list,encode_instruction(row));
        return list.release();
    }
    if(method=="segments"){
        count(values,2);auto rows=take(p.segments(size(argument(values,0)),size(argument(values,1))));Object list(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"name",string(row.name));set(item,"begin",encode(row.begin));set(item,"size",integer(row.size));
            set(item,"file_begin",encode(Location{row.file_begin}));set(item,"file_size",integer(row.file_size));set(item,"readable",PyBool_FromLong(row.readable));
            set(item,"writable",PyBool_FromLong(row.writable));set(item,"executable",PyBool_FromLong(row.executable));append(list,item.release());}
        return list.release();
    }
    if(method=="strings"){
        count(values,2);auto rows=take(p.strings(size(argument(values,0)),size(argument(values,1))));Object list(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"encoding",integer(static_cast<unsigned>(row.encoding)));set(item,"preview",string(row.preview));
            set(item,"characters",integer(row.characters));set(item,"byte_length",integer(row.byte_length));set(item,"file_offset",encode(Location{row.file_offset}));
            set(item,"address",row.address?encode(Location{*row.address}):none());set(item,"terminated",PyBool_FromLong(row.terminated));append(list,item.release());}
        return list.release();
    }
    if(method=="references"){
        count(values,3);auto rows=take(p.references(location(argument(values,0)),size(argument(values,1)),size(argument(values,2))));Object list(PyList_New(0));
        for(const auto& row:rows){Object item(PyDict_New());set(item,"id",integer(row.id.value));set(item,"source",encode(row.source));set(item,"kind",integer(static_cast<unsigned>(row.kind)));set(item,"kind_name",string(reference_kind_name(row.kind)));
            if(const auto* target=std::get_if<Location>(&row.target))set(item,"target",encode(*target));
            else if(const auto* external=std::get_if<ExternalIdentity>(&row.target)){Object external_record(PyDict_New());set(external_record,"library",string(external->library));set(external_record,"name",external->name?string(*external->name):none());set(item,"target",external_record.release());}
            else {Object unresolved_record(PyDict_New());set(unresolved_record,"unresolved_reason",integer(static_cast<unsigned>(std::get<UnresolvedTarget>(row.target).reason)));set(item,"target",unresolved_record.release());}
            append(list,item.release());}
        return list.release();
    }
    if(method=="incoming_references"){
        count(values,3);auto page=take(p.incoming_references(location(argument(values,0)),size(argument(values,1)),size(argument(values,2))));
        Object result(PyDict_New()),list(PyList_New(0));
        for(const auto& row:page.rows){
            Object item(PyDict_New());set(item,"id",integer(row.id.value));set(item,"source",encode(row.source));
            set(item,"kind",integer(static_cast<unsigned>(row.kind)));set(item,"kind_name",string(reference_kind_name(row.kind)));
            if(const auto* target=std::get_if<Location>(&row.target))set(item,"target",encode(*target));
            else if(const auto* external=std::get_if<ExternalIdentity>(&row.target)){Object record(PyDict_New());set(record,"library",string(external->library));set(record,"name",external->name?string(*external->name):none());set(item,"target",record.release());}
            else {Object record(PyDict_New());set(record,"unresolved_reason",integer(static_cast<unsigned>(std::get<UnresolvedTarget>(row.target).reason)));set(item,"target",record.release());}
            append(list,item.release());
        }
        set(result,"references",list.release());set(result,"total",integer(page.total));
        set(result,"next",page.next_offset?integer(*page.next_offset):none());return result.release();
    }
    if(method=="all_references"){
        count(values,2);auto page=take(p.all_references(size(argument(values,0)),size(argument(values,1))));
        Object result(PyDict_New()),list(PyList_New(0));
        for(const auto& row:page.rows){
            Object item(PyDict_New());set(item,"id",integer(row.id.value));set(item,"source",encode(row.source));
            set(item,"kind",integer(static_cast<unsigned>(row.kind)));set(item,"kind_name",string(reference_kind_name(row.kind)));
            if(const auto* target=std::get_if<Location>(&row.target))set(item,"target",encode(*target));
            else if(const auto* external=std::get_if<ExternalIdentity>(&row.target)){Object record(PyDict_New());set(record,"library",string(external->library));set(record,"name",external->name?string(*external->name):none());set(item,"target",record.release());}
            else {Object record(PyDict_New());set(record,"unresolved_reason",integer(static_cast<unsigned>(std::get<UnresolvedTarget>(row.target).reason)));set(item,"target",record.release());}
            append(list,item.release());
        }
        set(result,"references",list.release());set(result,"total",integer(page.total));
        set(result,"next",page.next_offset?integer(*page.next_offset):none());return result.release();
    }
    if(method=="search"){
        count(values,4);
        auto* encoded=argument(values,0);
        if(!PyTuple_Check(encoded) || PyTuple_Size(encoded)<2)invalid("Search query must be a typed tuple");
        const auto kind=text(argument(encoded,0));
        SearchQuery query;
        if(kind=="bytes" && PyTuple_Size(encoded)==2)query=BytePattern{text(argument(encoded,1))};
        else if(kind=="text" && PyTuple_Size(encoded)==3){
            auto encoding=number32(argument(encoded,2));
            if(encoding>static_cast<unsigned>(TextEncoding::utf32be))invalid("Unknown text search encoding");
            query=TextQuery{text(argument(encoded,1)),static_cast<TextEncoding>(encoding)};
        }else if(kind=="immediate" && PyTuple_Size(encoded)==4){
            auto width=number32(argument(encoded,2));
            if(width!=8 && width!=16 && width!=32 && width!=64)invalid("Immediate search width must be8,16,32 or64");
            query=ImmediateQuery{text(argument(encoded,1)),static_cast<std::uint16_t>(width),
                boolean(argument(encoded,3))?ImmediateInterpretation::signed_value:ImmediateInterpretation::unsigned_value};
        }else invalid("Malformed search query tuple");
        SearchLimits limits;limits.max_results=size(argument(values,2));
        auto cursor=search_cursor(argument(values,1));
        const auto stop=argument(values,3)==Py_None?std::stop_token{}:stop_source(argument(values,3)).get_token();
        auto page=take(without_gil([&]{return p.search(query,std::move(cursor),limits,stop);}));
        Object result(PyDict_New()),matches(PyList_New(0));
        for(const auto& match:page.matches){
            Object item(PyDict_New()),ranges(PyList_New(0));
            set(item,"offset",encode(Location{match.offset}));set(item,"size",integer(match.size));
            set(item,"address",match.address?encode(Location{*match.address}):none());
            set(item,"instruction_address",match.instruction_address?encode(Location{*match.instruction_address}):none());
            set(item,"operand_index",match.operand_index?integer(*match.operand_index):none());
            for(const auto& range:match.file_ranges){Object part(PyDict_New());set(part,"offset",encode(Location{range.begin}));set(part,"size",integer(range.size));append(ranges,part.release());}
            set(item,"file_ranges",ranges.release());append(matches,item.release());
        }
        set(result,"matches",matches.release());set(result,"complete",PyBool_FromLong(page.complete));
        set(result,"source_complete",PyBool_FromLong(page.source_complete));set(result,"reason",string(page.reason));
        set(result,"examined_candidates",integer(page.examined_candidates));set(result,"comparisons",integer(page.comparisons));
        set(result,"next",page.next?search_cursor_capsule(*page.next):none());
        return result.release();
    }
    if(method=="undo" || method=="redo"){
        count(values,0);return encode_snapshot(*take(method=="undo"?p.undo():p.redo()));
    }
    if(method=="analyze"){
        std::stop_token stop;
        if(PyTuple_Size(values)==1)stop=stop_source(argument(values,0)).get_token();
        else count(values,0);
        auto result=without_gil([&]{return p.analyze(stop);});
        return encode_snapshot(*take(std::move(result)));
    }
    if(method=="save"){count(values,0);return PyBool_FromLong(take(p.save()));}
    if(method=="save_as"){count(values,1);take(p.save_as(path(argument(values,0))));return none();}
    if(method=="export"){count(values,1);auto receipt=take(p.export_binary(path(argument(values,0))));Object result(PyDict_New());set(result,"bytes",integer(receipt.bytes));set(result,"revision",integer(receipt.revision));return result.release();}
    if(method=="rename" || method=="comment"){
        count(values,3);auto at=location(argument(values,0));auto value=text(argument(values,1));auto group=number(argument(values,2));
        ProjectCommand command=method=="rename"?ProjectCommand{Rename{at,std::move(value)}}:ProjectCommand{Comment{at,std::move(value)}};
        return encode_snapshot(*take(p.execute(command,group)));
    }
    if(method=="apply_annotations"){
        count(values,3);auto* rows=argument(values,0);auto group=number(argument(values,1));
        if(!PyList_Check(rows)&&!PyTuple_Check(rows))invalid("Annotation batch must be a list or tuple");
        const auto row_count=PySequence_Size(rows);
        if(row_count<=0 || row_count>static_cast<Py_ssize_t>(automation::maximum_page))
            invalid("Annotation batch must contain 1..4096 rows");
        std::optional<std::uint64_t> expected;
        if(argument(values,2)!=Py_None)expected=number(argument(values,2));
        std::size_t text_bytes=0;
        std::vector<ProjectCommand> commands;commands.reserve(static_cast<std::size_t>(row_count)*2);
        auto checked_text=[&](PyObject* value){
            Py_ssize_t length=0;const char* data=PyUnicode_AsUTF8AndSize(value,&length);if(!data)throw PythonFailure{};
            if(length<0 || static_cast<std::size_t>(length)>16*1024*1024-text_bytes)
                invalid("Annotation batch text exceeds 16 MiB");
            text_bytes+=static_cast<std::size_t>(length);return std::string(data,static_cast<std::size_t>(length));
        };
        for(Py_ssize_t i=0;i<row_count;++i){
            auto* row=sequence_item(rows,i);
            if(!PyTuple_Check(row) || PyTuple_Size(row)<3)invalid("Malformed annotation batch row");
            const auto kind=text(tuple_item(row,0));const auto at=location(tuple_item(row,1));
            if(kind=="rename" || kind=="comment"){
                if(PyTuple_Size(row)!=3)invalid("Rename/comment rows require exactly three fields");
                auto value=checked_text(tuple_item(row,2));
                commands.emplace_back(kind=="rename"?ProjectCommand{Rename{at,std::move(value)}}:
                    ProjectCommand{Comment{at,std::move(value)}});
            }else if(kind=="bookmark"){
                if(PyTuple_Size(row)!=4)invalid("Bookmark rows require four fields");
                auto label=checked_text(tuple_item(row,2));
                commands.emplace_back(BookmarkCommand{at,std::move(label),boolean(tuple_item(row,3))});
            }else invalid("Annotation batch supports rename, comment, and bookmark operations");
        }
        return encode_snapshot(*take(p.execute_batch(commands,group,expected)));
    }
    if(method=="apply_batch"){
        count(values,4);auto* rows=argument(values,0);const auto group=number(argument(values,1));
        if(!PyList_Check(rows)&&!PyTuple_Check(rows))invalid("Automation batch must be a list or tuple");
        const auto row_count=PySequence_Size(rows);
        if(row_count<=0||row_count>static_cast<Py_ssize_t>(automation::maximum_page))
            invalid("Automation batch must contain 1..4096 commands");
        std::optional<std::uint64_t> expected;
        if(argument(values,2)!=Py_None)expected=number(argument(values,2));
        std::stop_token stop;if(argument(values,3)!=Py_None)stop=stop_source(argument(values,3)).get_token();
        std::vector<ProjectCommand> commands;commands.reserve(static_cast<std::size_t>(row_count));
        for(Py_ssize_t i=0;i<row_count;++i){
            auto* row=sequence_item(rows,i);
            if((!PyTuple_Check(row)&&!PyList_Check(row))||PySequence_Size(row)<1)
                invalid("Malformed automation batch command");
            const auto kind=text(sequence_item(row,0));
            if(kind=="rename"||kind=="comment"){
                if(PySequence_Size(row)!=3)invalid("Rename/comment commands require three fields");
                const auto at=location(sequence_item(row,1));auto value=text(sequence_item(row,2));
                commands.emplace_back(kind=="rename"?ProjectCommand{Rename{at,std::move(value)}}:
                    ProjectCommand{Comment{at,std::move(value)}});
            }else if(kind=="bookmark"){
                if(PySequence_Size(row)!=4)invalid("Bookmark commands require four fields");
                commands.emplace_back(BookmarkCommand{location(sequence_item(row,1)),text(sequence_item(row,2)),boolean(sequence_item(row,3))});
            }else if(kind=="patch"){
                if(PySequence_Size(row)!=3)invalid("Patch commands require three fields");
                char* data=nullptr;Py_ssize_t length=0;
                if(PyBytes_AsStringAndSize(sequence_item(row,2),&data,&length)<0)throw PythonFailure{};
                if(length<0||length>static_cast<Py_ssize_t>(automation::maximum_read))invalid("A batch patch exceeds1MiB");
                const auto* begin=reinterpret_cast<const std::byte*>(data);
                commands.emplace_back(PatchBytes{location(sequence_item(row,1)),{begin,begin+length}});
            }else if(kind=="code"||kind=="data"){
                if(PySequence_Size(row)!=3)invalid("Code/data commands require three fields");
                commands.emplace_back(DefineRegion{address(sequence_item(row,1)),number(sequence_item(row,2)),kind=="code"?RegionKind::code:RegionKind::data});
            }else if(kind=="function"){
                if(PySequence_Size(row)!=2)invalid("Function commands require two fields");
                commands.emplace_back(DefineFunction{address(sequence_item(row,1))});
            }else if(kind=="suppress_function"){
                if(PySequence_Size(row)!=3)invalid("Function suppression commands require three fields");
                commands.emplace_back(SuppressFunction{address(sequence_item(row,1)),boolean(sequence_item(row,2))});
            }else if(kind=="reference"){
                if(PySequence_Size(row)!=5)invalid("Reference commands require five fields");
                const auto ref_kind=text(sequence_item(row,3));
                const std::array<std::string_view,7> names{"code","data","call","jump","read","write","address"};
                const auto found=std::find(names.begin(),names.end(),ref_kind);if(found==names.end())invalid("Unknown user reference kind");
                commands.emplace_back(SetReference{location(sequence_item(row,1)),location(sequence_item(row,2)),
                    static_cast<UserReferenceKind>(found-names.begin()),boolean(sequence_item(row,4))});
            }else if(kind=="chunks"){
                if(PySequence_Size(row)!=3)invalid("Function chunk commands require three fields");
                auto* chunks=sequence_item(row,2);
                if((!PyList_Check(chunks)&&!PyTuple_Check(chunks))||PySequence_Size(chunks)>static_cast<Py_ssize_t>(automation::maximum_page))
                    invalid("Function chunks must be a bounded sequence");
                SetFunctionChunks edit{address(sequence_item(row,1)),{}};edit.chunks.reserve(static_cast<std::size_t>(PySequence_Size(chunks)));
                for(Py_ssize_t j=0;j<PySequence_Size(chunks);++j){auto* range=sequence_item(chunks,j);
                    if((!PyTuple_Check(range)&&!PyList_Check(range))||PySequence_Size(range)!=2)invalid("Malformed function chunk");
                    edit.chunks.push_back({address(sequence_item(range,0)),number(sequence_item(range,1))});}
                commands.emplace_back(std::move(edit));
            }else if(kind=="type_assignment"){
                if(PySequence_Size(row)!=4)invalid("Type assignment commands require four fields");
                commands.emplace_back(AssignType{address(sequence_item(row,1)),number(sequence_item(row,2)),boolean(sequence_item(row,3))});
            }else if(kind=="update_type"){
                if(PySequence_Size(row)!=4)invalid("Type update commands require four fields");
                commands.emplace_back(UpdateType{number(sequence_item(row,1)),text(sequence_item(row,2)),type_value(sequence_item(row,3))});
            }else if(kind=="breakpoint"){
                if(PySequence_Size(row)!=10)invalid("Project breakpoint commands require ten fields");
                const auto breakpoint_kind=text(sequence_item(row,2));
                const std::array<std::string_view,6> names{"software","hardware","execute","read","write","access"};
                const auto found=std::find(names.begin(),names.end(),breakpoint_kind);if(found==names.end())invalid("Unknown project breakpoint kind");
                commands.emplace_back(SetProjectBreakpoint{address(sequence_item(row,1)),
                    static_cast<database::ProjectBreakpointKind>(found-names.begin()),number8(sequence_item(row,3)),
                    boolean(sequence_item(row,4)),boolean(sequence_item(row,5)),text(sequence_item(row,6)),
                    boolean(sequence_item(row,7)),text(sequence_item(row,8)),number(sequence_item(row,9))});
            }else invalid("Unsupported automation batch command");
        }
        auto result=without_gil([&]{return p.execute_batch(commands,group,expected,stop);});
        return encode_snapshot(*take(std::move(result)));
    }
    if(method=="bookmark"){
        count(values,4);return encode_snapshot(*take(p.execute(BookmarkCommand{location(argument(values,0)),text(argument(values,1)),boolean(argument(values,2))},number(argument(values,3)))));
    }
    if(method=="patch"){
        count(values,3);char* data=nullptr;Py_ssize_t length=0;
        if(PyBytes_AsStringAndSize(argument(values,1),&data,&length)<0)throw PythonFailure{};
        if(length>static_cast<Py_ssize_t>(automation::maximum_read))invalid("Patch exceeds1MiB automation limit");
        auto* begin=reinterpret_cast<const std::byte*>(data);
        return encode_snapshot(*take(p.execute(PatchBytes{location(argument(values,0)),{begin,begin+length}},number(argument(values,2)))));
    }
    if(method=="patch_at_revision"){
        count(values,4);char* data=nullptr;Py_ssize_t length=0;
        if(PyBytes_AsStringAndSize(argument(values,1),&data,&length)<0)throw PythonFailure{};
        if(length>static_cast<Py_ssize_t>(automation::maximum_read))invalid("Patch exceeds1MiB automation limit");
        auto* begin=reinterpret_cast<const std::byte*>(data);
        return encode_snapshot(*take(p.patch(location(argument(values,0)),{begin,begin+length},
            number(argument(values,2)),number(argument(values,3)))));
    }
    if(method=="code" || method=="data"){
        count(values,3);return encode_snapshot(*take(p.execute(DefineRegion{address(argument(values,0)),number(argument(values,1)),method=="code"?RegionKind::code:RegionKind::data},number(argument(values,2)))));
    }
    if(method=="function"){
        count(values,2);return encode_snapshot(*take(p.execute(DefineFunction{address(argument(values,0))},number(argument(values,1)))));
    }
    if(method=="suppress"){
        count(values,3);return encode_snapshot(*take(p.execute(SuppressFunction{address(argument(values,0)),boolean(argument(values,1))},number(argument(values,2)))));
    }
    if(method=="reference"){
        count(values,5);const auto kind=text(argument(values,2));
        const std::array<std::string_view,7> names{"code","data","call","jump","read","write","address"};
        const auto found=std::find(names.begin(),names.end(),kind);if(found==names.end())invalid("Unknown user reference kind");
        return encode_snapshot(*take(p.execute(SetReference{location(argument(values,0)),location(argument(values,1)),
            static_cast<UserReferenceKind>(found-names.begin()),boolean(argument(values,3))},number(argument(values,4)))));
    }
    if(method=="chunks"){
        count(values,3);auto* rows=argument(values,1);
        if(!PyList_Check(rows) || PyList_Size(rows)>static_cast<Py_ssize_t>(automation::maximum_page))invalid("Chunks must be a list of at most4096 ranges");
        SetFunctionChunks command{address(argument(values,0)),{}};
        for(Py_ssize_t i=0;i<PyList_Size(rows);++i){auto* row=PyList_GetItem(rows,i);count(row,2);command.chunks.push_back({address(argument(row,0)),number(argument(row,1))});}
        return encode_snapshot(*take(p.execute(command,number(argument(values,2)))));
    }
    if(method=="define_type"){
        count(values,3);auto name=text(argument(values,0));auto type=type_value(argument(values,1));
        auto snapshot=take(p.execute(DefineType{name,std::move(type)},number(argument(values,2))));
        const auto& definitions=snapshot->state->user->types;
        const auto found=std::find_if(definitions.begin(),definitions.end(),[&](const auto& row){return row.name==name;});
        if(found==definitions.end())invalid("Defined type was not returned by the project");
        return integer(found->id);
    }
    if(method=="update_type"){
        count(values,4);auto snapshot=take(p.execute(UpdateType{number(argument(values,0)),text(argument(values,1)),type_value(argument(values,2))},number(argument(values,3))));
        return encode_snapshot(*snapshot);
    }
    if(method=="assign_type"){
        count(values,4);return encode_snapshot(*take(p.execute(AssignType{address(argument(values,0)),number(argument(values,1)),boolean(argument(values,2))},number(argument(values,3)))));
    }
    if(method=="import_types" || method=="import_types_at_revision"){
        const bool snapshot_planned=method=="import_types_at_revision";
        count(values,snapshot_planned?4:3);auto* definition_rows=argument(values,0);auto* assignment_rows=argument(values,1);
        const auto planning_snapshot=take(p.snapshot());
        if(snapshot_planned && planning_snapshot->state->revisions.edit!=number(argument(values,3)))
            throw NativeFailure{{ErrorCode::conflict,"Portable type import expected a different project edit revision"}};
        auto sequence=[](PyObject* object,std::size_t limit,const char* description){
            if(!PyList_Check(object)&&!PyTuple_Check(object))invalid(description);
            const auto length=PySequence_Size(object);
            if(length<0)throw PythonFailure{};
            if(static_cast<std::size_t>(length)>limit)invalid(description);
            return length;
        };
        const auto definition_count=sequence(definition_rows,automation::maximum_page,"Portable type definitions exceed4096 rows");
        const auto assignment_count=sequence(assignment_rows,automation::maximum_page,"Portable type assignments exceed4096 rows");
        ImportPortableTypes command;
        command.definitions.reserve(static_cast<std::size_t>(definition_count));
        command.assignments.reserve(static_cast<std::size_t>(assignment_count));
        for(Py_ssize_t i=0;i<definition_count;++i){
            Object row(PySequence_GetItem(definition_rows,i));
            if((!PyTuple_Check(row)&&!PyList_Check(row))||PySequence_Size(row)!=3)invalid("Malformed portable type definition");
            std::optional<std::uint64_t> existing_id;
            if(sequence_item(row,2)!=Py_None)existing_id=number(sequence_item(row,2));
            PortableTypeDefinition definition{text(sequence_item(row,0)),type_value(sequence_item(row,1)),existing_id,{}};
            if(snapshot_planned && existing_id){
                const auto& current=planning_snapshot->state->user->types;
                const auto found=std::lower_bound(current.begin(),current.end(),*existing_id,
                    [](const auto& item,std::uint64_t id){return item.id<id;});
                if(found==current.end() || found->id!=*existing_id || found->name!=definition.name)
                    throw NativeFailure{{ErrorCode::conflict,"Portable type destination changed after import planning"}};
                definition.expected_existing=*found;
                definition.declaration_kind=found->declaration_kind;
            }
            command.definitions.push_back(std::move(definition));
        }
        for(Py_ssize_t i=0;i<assignment_count;++i){
            Object row(PySequence_GetItem(assignment_rows,i));
            if((!PyTuple_Check(row)&&!PyList_Check(row))||PySequence_Size(row)!=2)invalid("Malformed portable type assignment");
            command.assignments.push_back({address(sequence_item(row,0)),text(sequence_item(row,1))});
        }
        return encode_snapshot(*take(p.execute(command,number(argument(values,2)))));
    }
    invalid("Unknown automation method");return nullptr;
});}
PyMethodDef methods[]={
    {"open",open_project,METH_VARARGS,"Open a versioned native project owner."},
    {"open_archive",open_archive,METH_VARARGS,"Open a bounded, read-only archive owner."},
    {"archive_call",call_archive,METH_VARARGS,"Query an archive owner."},
    {"history_call",call_historical_state,METH_VARARGS,"Read an immutable exact-step historical projection."},
    {"create",create_project,METH_VARARGS,"Import input into a real project."},
    {"call",call_project,METH_VARARGS,"Execute a version1 typed project operation."},
    {"debugger",create_debugger,METH_VARARGS,"Create a native or remote debugger session."},
    {"debug_call",call_debugger,METH_VARARGS,"Execute a typed debugger session operation."},
    {"stop_source",create_stop_source,METH_VARARGS,"Create a thread-safe analysis cancellation source."},
    {"request_stop",request_stop,METH_VARARGS,"Request cancellation from any Python thread."},
    {"stop_requested",stop_requested,METH_VARARGS,"Query a cancellation source."},
    {nullptr,nullptr,0,nullptr}
};
PyModuleDef definition={PyModuleDef_HEAD_INIT,"_hexlab","HexLab native automation v1",-1,methods};
}

namespace hexlab::automation::python {
PyObject* make_stop_source_capsule(std::shared_ptr<std::stop_source> source){
    return stop_source_capsule(std::move(source));
}
}

extern "C" PyObject* PyInit__hexlab(){
    auto* module=PyModule_Create(&definition);if(!module)return nullptr;
    error_type=PyErr_NewException("hexlab.Error",PyExc_RuntimeError,nullptr);
    if(!error_type || PyModule_AddObject(module,"Error",error_type)<0){Py_XDECREF(error_type);Py_DECREF(module);return nullptr;}
    if(PyModule_AddIntConstant(module,"CANCELED_ERROR_CODE",static_cast<long>(ErrorCode::canceled))<0){Py_DECREF(module);return nullptr;}
    if(PyModule_AddIntConstant(module,"CONFLICT_ERROR_CODE",static_cast<long>(ErrorCode::conflict))<0){Py_DECREF(module);return nullptr;}
    return module;
}
