#include "hexlab/symbols/dwarf.hpp"

#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <unordered_map>
#include <variant>

namespace hexlab::symbols {
namespace {
struct Reference { std::uint64_t offset=0; bool section_absolute=false; bool signature=false; bool supplementary=false; };
struct IndexedForm { std::uint64_t index=0; bool address=false; bool location_list=false; bool range_list=false; };
using Blob=std::vector<std::uint8_t>;
using Value=std::variant<std::uint64_t,std::int64_t,std::string,Blob,Reference,IndexedForm>;
struct AttributeSpec { std::uint64_t name; std::uint64_t form; std::optional<std::int64_t> implicit; };
struct Abbreviation { std::uint64_t tag; bool children; std::vector<AttributeSpec> attributes; };
struct Die {
    std::uint64_t code=0,tag=0,offset=0,end=0;
    std::optional<std::size_t> parent;
    std::vector<std::size_t> children;
    std::map<std::uint64_t,Value> attributes;
};

constexpr std::uint64_t tag_array=0x01,tag_enumeration=0x04,tag_formal_parameter=0x05,
    tag_member=0x0d,tag_pointer_type=0x0f,tag_compile_unit=0x11,tag_structure_type=0x13,
    tag_subroutine_type=0x15,tag_typedef=0x16,tag_union_type=0x17,tag_unspecified_parameters=0x18,
    tag_subrange_type=0x21,tag_base_type=0x24,tag_const_type=0x26,tag_enumerator=0x28,
    tag_subprogram=0x2e,tag_volatile_type=0x35,tag_variable=0x34,tag_type_unit=0x41,
    tag_inheritance=0x1c;
constexpr std::uint64_t attr_sibling=0x01,attr_location=0x02,attr_name=0x03,attr_byte_size=0x0b,
    attr_bit_offset=0x0c,attr_bit_size=0x0d,attr_const_value=0x1c,attr_low_pc=0x11,attr_high_pc=0x12,
    attr_data_member_location=0x38,attr_encoding=0x3e,attr_type=0x49,attr_declaration=0x3c,
    attr_virtuality=0x4c,
    attr_data_bit_offset=0x6b,
    attr_count=0x37,attr_lower_bound=0x22,attr_upper_bound=0x2f,
    attr_abstract_origin=0x31,attr_specification=0x47,attr_linkage_name=0x6e,
    attr_frame_base=0x40,attr_comp_dir=0x1b,attr_dwo_name=0x76,
    attr_gnu_dwo_name=0x2130,attr_gnu_dwo_id=0x2131,
    attr_str_offsets_base=0x72,attr_addr_base=0x73,attr_rnglists_base=0x74,attr_loclists_base=0x8c,
    attr_ranges=0x55;
constexpr std::uint64_t form_addr=0x01,form_block2=0x03,form_block4=0x04,form_data2=0x05,
    form_data4=0x06,form_data8=0x07,form_string=0x08,form_block=0x09,form_block1=0x0a,
    form_data1=0x0b,form_flag=0x0c,form_sdata=0x0d,form_strp=0x0e,form_udata=0x0f,
    form_ref_addr=0x10,form_ref1=0x11,form_ref2=0x12,form_ref4=0x13,form_ref8=0x14,
    form_ref_udata=0x15,form_indirect=0x16,form_sec_offset=0x17,form_exprloc=0x18,
    form_flag_present=0x19,form_strx=0x1a,form_addrx=0x1b,form_line_strp=0x1f,
    form_implicit_const=0x21,form_loclistx=0x22,form_rnglistx=0x23,form_strx1=0x25,form_strx2=0x26,form_strx3=0x27,form_strx4=0x28,
    form_addrx1=0x29,form_addrx2=0x2a,form_addrx3=0x2b,form_addrx4=0x2c,form_strp_sup=0x1d,form_ref_sig8=0x20,
    form_ref_sup4=0x1c,form_ref_sup8=0x24;

hexlab::Error malformed(std::string message){return {hexlab::ErrorCode::malformed,std::move(message)};}
hexlab::Error unsupported(std::string message){return {hexlab::ErrorCode::unsupported,std::move(message)};}

class Reader {
public:
    Reader(std::span<const std::uint8_t> b,std::size_t begin,std::size_t end):bytes_(b),pos_(begin),end_(end){}
    std::size_t position()const{return pos_;}
    bool done()const{return pos_==end_;}
    bool can_read(std::size_t n)const{return n<=end_-pos_;}
    hexlab::Result<std::uint64_t> fixed(std::size_t n){if(n>8||!can_read(n))return malformed("truncated or oversized fixed-width DWARF value");std::uint64_t v=0;for(std::size_t i=0;i<n;++i)v|=std::uint64_t(bytes_[pos_++])<<(i*8);return v;}
    hexlab::Result<std::uint64_t> uleb(){std::uint64_t v=0;unsigned shift=0;for(unsigned i=0;i<10;++i){if(!can_read(1))return malformed("truncated DWARF ULEB128");auto b=bytes_[pos_++];if(shift==63&&(b&0x7e))return malformed("DWARF ULEB128 overflows 64 bits");if(shift>63&&(b&0x7f))return malformed("DWARF ULEB128 overflows 64 bits");v|=std::uint64_t(b&0x7f)<<shift;if(!(b&0x80))return v;shift+=7;}return malformed("DWARF ULEB128 is longer than 10 bytes");}
    hexlab::Result<std::int64_t> sleb(){std::uint64_t v=0;unsigned shift=0;std::uint8_t b=0;for(unsigned i=0;i<10;++i){if(!can_read(1))return malformed("truncated DWARF SLEB128");b=bytes_[pos_++];if(i==9&&((b&0x80)||((b&0x7f)!=0&&((b&0x7f)!=0x7f))))return malformed("DWARF SLEB128 overflows 64 bits");v|=std::uint64_t(b&0x7f)<<shift;shift+=7;if(!(b&0x80)){if(shift<64&&(b&0x40))v|=(~std::uint64_t{0})<<shift;return static_cast<std::int64_t>(v);}}return malformed("DWARF SLEB128 is longer than 10 bytes");}
    hexlab::Result<std::string> cstring(){const auto begin=pos_;while(pos_<end_&&bytes_[pos_]){if(pos_-begin>=1024*1024)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF string exceeds 1 MiB"};++pos_;}if(pos_==end_)return malformed("unterminated DWARF string");std::string s(reinterpret_cast<const char*>(bytes_.data()+begin),pos_-begin);++pos_;return s;}
    hexlab::Result<Blob> bytes(std::size_t n){if(!can_read(n))return malformed("truncated DWARF block/expression");Blob b(bytes_.begin()+static_cast<std::ptrdiff_t>(pos_),bytes_.begin()+static_cast<std::ptrdiff_t>(pos_+n));pos_+=n;return b;}
private: std::span<const std::uint8_t> bytes_;std::size_t pos_,end_;
};

struct InitialLength { std::uint64_t length = 0; std::uint8_t offset_size = 4; };
hexlab::Result<InitialLength> read_initial_length(Reader& reader) {
    auto marker = reader.fixed(4);
    if (!marker) return marker.error();
    if (marker.value() == 0xffffffffu) {
        auto length = reader.fixed(8);
        if (!length) return length.error();
        return InitialLength{length.value(), 8};
    }
    if (marker.value() >= 0xfffffff0u)
        return malformed("reserved DWARF initial-length marker");
    return InitialLength{marker.value(), 4};
}

hexlab::Result<std::unordered_map<std::uint64_t,Abbreviation>> read_abbrevs(std::span<const std::uint8_t> bytes,std::uint64_t offset,std::stop_token stop){
    if(offset>=bytes.size())return malformed("DWARF abbreviation offset is outside .debug_abbrev");Reader r(bytes,static_cast<std::size_t>(offset),bytes.size());std::unordered_map<std::uint64_t,Abbreviation> out;
    while(!r.done()){if(stop.stop_requested())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};auto code=r.uleb();if(!code)return code.error();if(!code.value())return out;auto tag=r.uleb();if(!tag)return tag.error();auto child=r.fixed(1);if(!child)return child.error();if(child.value()>1)return malformed("invalid DWARF abbreviation children flag");Abbreviation a{tag.value(),child.value()!=0,{}};
        for(;;){if(stop.stop_requested())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};auto name=r.uleb(),form=r.uleb();if(!name)return name.error();if(!form)return form.error();if(!name.value()&&!form.value())break;if(!name.value()||!form.value())return malformed("invalid DWARF abbreviation attribute terminator");if(a.attributes.size()>=256)return hexlab::Error{hexlab::ErrorCode::resource_limit,"too many DWARF attributes in abbreviation"};std::optional<std::int64_t> implicit;if(form.value()==form_implicit_const){auto value=r.sleb();if(!value)return value.error();implicit=value.value();}a.attributes.push_back({name.value(),form.value(),implicit});}
        if(!out.emplace(code.value(),std::move(a)).second)return malformed("duplicate DWARF abbreviation code");if(out.size()>65536)return hexlab::Error{hexlab::ErrorCode::resource_limit,"too many DWARF abbreviations"};}
    return malformed("unterminated DWARF abbreviation table");
}

hexlab::Result<Value> read_form(Reader&r,std::uint64_t form,std::uint8_t address_size,std::uint8_t offset_size,std::span<const std::uint8_t> strings,std::span<const std::uint8_t> line_strings,std::span<const std::uint8_t> supplementary_strings,std::optional<std::int64_t> implicit={},unsigned depth=0){
    if(depth>4)return unsupported("nested DW_FORM_indirect chain exceeds limit");
    switch(form){
    case form_addr:{auto v=r.fixed(address_size);if(!v)return v.error();return Value(v.value());}
    case form_data1:case form_data2:case form_data4:case form_data8:{auto n=form==form_data1?1u:form==form_data2?2u:form==form_data4?4u:8u;auto v=r.fixed(n);if(!v)return v.error();return Value(v.value());}
    case form_flag:{auto v=r.fixed(1);if(!v)return v.error();if(v.value()>1)return malformed("invalid DWARF flag value");return Value(v.value());}
    case form_flag_present:return Value(std::uint64_t{1});
    case form_implicit_const:if(!implicit)return malformed("DW_FORM_implicit_const has no abbreviation value");if(*implicit>=0)return Value(static_cast<std::uint64_t>(*implicit));return Value(*implicit);
    case form_sdata:{auto v=r.sleb();if(!v)return v.error();return Value(v.value());}
    case form_string:{auto v=r.cstring();if(!v)return v.error();return Value(std::move(v.value()));}
    case form_strp:{auto off=r.fixed(offset_size);if(!off)return off.error();if(off.value()>=strings.size())return malformed("DWARF .debug_str offset is out of bounds");Reader s(strings,static_cast<std::size_t>(off.value()),strings.size());auto v=s.cstring();if(!v)return v.error();return Value(std::move(v.value()));}
    case form_strp_sup:{auto off=r.fixed(offset_size);if(!off)return off.error();if(off.value()>=supplementary_strings.size())return supplementary_strings.empty()?unsupported("DW_FORM_strp_sup requires supplementary .debug_str_sup"):malformed("supplementary DWARF string offset is out of bounds");Reader s(supplementary_strings,static_cast<std::size_t>(off.value()),supplementary_strings.size());auto v=s.cstring();if(!v)return v.error();return Value(std::move(v.value()));}
    case form_line_strp:{auto off=r.fixed(offset_size);if(!off)return off.error();if(off.value()>=line_strings.size())return line_strings.empty()?unsupported("DW_FORM_line_strp requires .debug_line_str"):malformed("DWARF .debug_line_str offset is out of bounds");Reader s(line_strings,static_cast<std::size_t>(off.value()),line_strings.size());auto v=s.cstring();if(!v)return v.error();return Value(std::move(v.value()));}
    case form_udata:case form_ref_udata:{auto v=r.uleb();if(!v)return v.error();if(form==form_ref_udata)return Value(Reference{v.value(),false});return Value(v.value());}
    case form_loclistx:{auto v=r.uleb();if(!v)return v.error();return Value(IndexedForm{v.value(),false,true});}
    case form_rnglistx:{auto v=r.uleb();if(!v)return v.error();return Value(IndexedForm{v.value(),false,false,true});}
    case form_strx:case form_addrx:{auto v=r.uleb();if(!v)return v.error();return Value(IndexedForm{v.value(),form==form_addrx});}
    case form_strx1:case form_strx2:case form_strx3:case form_strx4:case form_addrx1:case form_addrx2:case form_addrx3:case form_addrx4:{const auto n=(form==form_strx1||form==form_addrx1)?1u:(form==form_strx2||form==form_addrx2)?2u:(form==form_strx3||form==form_addrx3)?3u:4u;auto v=r.fixed(n);if(!v)return v.error();const bool address=form>=form_addrx1;return Value(IndexedForm{v.value(),address});}
    case form_ref1:case form_ref2:case form_ref4:case form_ref8:{const auto n=form==form_ref1?1u:form==form_ref2?2u:form==form_ref4?4u:8u;auto v=r.fixed(n);if(!v)return v.error();return Value(Reference{v.value(),false});}
    case form_ref_addr:{auto v=r.fixed(offset_size);if(!v)return v.error();return Value(Reference{v.value(),true});}
    case form_ref_sig8:{auto v=r.fixed(8);if(!v)return v.error();return Value(Reference{v.value(),false,true});}
    case form_ref_sup4:case form_ref_sup8:{auto v=r.fixed(form==form_ref_sup4?4:8);if(!v)return v.error();return Value(Reference{v.value(),false,false,true});}
    case form_indirect:{auto actual=r.uleb();if(!actual)return actual.error();return read_form(r,actual.value(),address_size,offset_size,strings,line_strings,supplementary_strings,{},depth+1);}
    case form_sec_offset:{auto v=r.fixed(offset_size);if(!v)return v.error();return Value(v.value());}
    case form_exprloc:case form_block:{auto n=r.uleb();if(!n)return n.error();if(n.value()>16*1024*1024)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF expression/block exceeds 16 MiB"};auto b=r.bytes(static_cast<std::size_t>(n.value()));if(!b)return b.error();return Value(std::move(b.value()));}
    case form_block1:case form_block2:case form_block4:{const auto n=form==form_block1?1u:form==form_block2?2u:4u;auto size=r.fixed(n);if(!size)return size.error();if(size.value()>16*1024*1024)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF block exceeds 16 MiB"};auto b=r.bytes(static_cast<std::size_t>(size.value()));if(!b)return b.error();return Value(std::move(b.value()));}
    default:return unsupported("unsupported DWARF v4 form "+std::to_string(form));}
}
const Value* attr(const Die&d,std::uint64_t n){auto i=d.attributes.find(n);return i==d.attributes.end()?nullptr:&i->second;}
const std::string* str(const Die&d,std::uint64_t n){auto*v=attr(d,n);return v?std::get_if<std::string>(v):nullptr;}
const std::uint64_t* num(const Die&d,std::uint64_t n){auto*v=attr(d,n);return v?std::get_if<std::uint64_t>(v):nullptr;}
std::optional<std::int64_t> signed_num(const Die&d,std::uint64_t n){auto*v=attr(d,n);if(!v)return{};if(auto*s=std::get_if<std::int64_t>(v))return *s;if(auto*u=std::get_if<std::uint64_t>(v);u&&*u<=std::uint64_t(INT64_MAX))return static_cast<std::int64_t>(*u);return{};}
const Reference* ref(const Die&d,std::uint64_t n){auto*v=attr(d,n);return v?std::get_if<Reference>(v):nullptr;}
SourceOrigin origin(const DwarfSections&s,std::uint64_t unit,const Die&d){return{s.source_id,".debug_info",s.info_section_offset+unit,s.info_section_offset+d.offset,d.end-d.offset};}
bool is_type_tag(std::uint64_t t){return t==tag_base_type||t==tag_pointer_type||t==tag_typedef||t==tag_const_type||t==tag_volatile_type||t==tag_array||t==tag_structure_type||t==tag_union_type||t==tag_enumeration||t==tag_subroutine_type;}

hexlab::Result<std::vector<LocationOperation>> decode_location_expression_impl(
    std::span<const std::uint8_t> bytes,std::uint8_t address_size,std::size_t depth,std::size_t& total_operations){
    constexpr std::size_t max_operations=4096;
    constexpr std::size_t max_nesting=16;
    constexpr std::size_t max_entry_expression_bytes=64*1024;
    if(depth>max_nesting)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF entry-value nesting exceeds 16 levels"};
    Reader r(bytes,0,bytes.size());std::vector<LocationOperation> out;out.reserve(std::min(bytes.size(),max_operations));
    auto uleb=[&]()->hexlab::Result<std::uint64_t>{return r.uleb();};
    auto sleb=[&]()->hexlab::Result<std::int64_t>{return r.sleb();};
    while(!r.done()){
        if(total_operations>=max_operations)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF nested location expressions exceed 4096 operations"};
        ++total_operations;
        const auto at=r.position();auto opcode=r.fixed(1);if(!opcode)return opcode.error();const auto op=static_cast<std::uint8_t>(opcode.value());
        LocationOperation item;item.expression_offset=static_cast<std::uint32_t>(at);
        if(op>=0x30&&op<=0x4f){item.kind=LocationOperationKind::literal;item.unsigned_operand=op-0x30;}
        else if(op>=0x50&&op<=0x6f){item.kind=LocationOperationKind::register_location;item.unsigned_operand=op-0x50;}
        else if(op>=0x70&&op<=0x8f){item.kind=LocationOperationKind::base_register_plus_offset;item.unsigned_operand=op-0x70;auto v=sleb();if(!v)return v.error();item.signed_operand=v.value();}
        else switch(op){
        case 0x03:{item.kind=LocationOperationKind::address;auto v=r.fixed(address_size);if(!v)return v.error();item.unsigned_operand=v.value();break;}
        case 0x06:item.kind=LocationOperationKind::dereference;break;
        case 0x08:case 0x0a:case 0x0c:case 0x0e:{item.kind=LocationOperationKind::unsigned_constant;const auto n=op==0x08?1u:op==0x0a?2u:op==0x0c?4u:8u;auto v=r.fixed(n);if(!v)return v.error();item.unsigned_operand=v.value();break;}
        case 0x09:case 0x0b:case 0x0d:case 0x0f:{item.kind=LocationOperationKind::signed_constant;const auto n=op==0x09?1u:op==0x0b?2u:op==0x0d?4u:8u;auto v=r.fixed(n);if(!v)return v.error();auto raw=v.value();if(n<8&&(raw&(std::uint64_t{1}<<(n*8-1))))raw|=(~std::uint64_t{0})<<(n*8);item.signed_operand=static_cast<std::int64_t>(raw);break;}
        case 0x10:{item.kind=LocationOperationKind::unsigned_constant;auto v=uleb();if(!v)return v.error();item.unsigned_operand=v.value();break;}
        case 0x11:{item.kind=LocationOperationKind::signed_constant;auto v=sleb();if(!v)return v.error();item.signed_operand=v.value();break;}
        case 0x12:case 0x13:case 0x14:case 0x16:case 0x17:case 0x96:
        case 0x19:case 0x1a:case 0x1b:case 0x1c:case 0x1d:case 0x1e:
        case 0x1f:case 0x20:case 0x21:case 0x24:case 0x25:case 0x26:case 0x27:
        case 0x29:case 0x2a:case 0x2b:case 0x2c:case 0x2d:case 0x2e:
            item.kind=LocationOperationKind::stack_operation;item.unsigned_operand=op;break;
        case 0x15:{item.kind=LocationOperationKind::stack_operation;item.unsigned_operand=op;auto v=r.fixed(1);if(!v)return v.error();item.second_unsigned_operand=v.value();break;}
        case 0x22:item.kind=LocationOperationKind::plus;break;
        case 0x23:{item.kind=LocationOperationKind::plus_unsigned;auto v=uleb();if(!v)return v.error();item.unsigned_operand=v.value();break;}
        case 0x28:case 0x2f:{item.kind=op==0x28?LocationOperationKind::branch_if_nonzero:LocationOperationKind::branch;auto raw=r.fixed(2);if(!raw)return raw.error();const auto displacement=static_cast<std::int16_t>(raw.value());const auto base=static_cast<std::int64_t>(r.position());const auto target=base+displacement;if(target<0||target>static_cast<std::int64_t>(bytes.size()))return malformed("DWARF branch target is outside the expression");item.second_unsigned_operand=static_cast<std::uint64_t>(target);break;}
        case 0x90:{item.kind=LocationOperationKind::register_location;auto v=uleb();if(!v)return v.error();item.unsigned_operand=v.value();break;}
        case 0x91:{item.kind=LocationOperationKind::frame_base_relative;auto v=sleb();if(!v)return v.error();item.signed_operand=v.value();break;}
        case 0x92:{item.kind=LocationOperationKind::base_register_plus_offset;auto reg=uleb();if(!reg)return reg.error();auto off=sleb();if(!off)return off.error();item.unsigned_operand=reg.value();item.signed_operand=off.value();break;}
        case 0x93:{item.kind=LocationOperationKind::piece;auto v=uleb();if(!v)return v.error();item.unsigned_operand=v.value();break;}
        case 0x94:{item.kind=LocationOperationKind::dereference_sized;auto v=r.fixed(1);if(!v)return v.error();if(!v.value())return malformed("DW_OP_deref_size has zero size");item.unsigned_operand=v.value();break;}
        case 0x9c:item.kind=LocationOperationKind::call_frame_cfa;break;
        case 0x9d:{item.kind=LocationOperationKind::bit_piece;auto size=uleb();if(!size)return size.error();auto off=uleb();if(!off)return off.error();item.unsigned_operand=size.value();item.second_unsigned_operand=off.value();break;}
        case 0x9f:item.kind=LocationOperationKind::stack_value;break;
        case 0xa3:{
            item.kind=LocationOperationKind::entry_value;
            auto length=uleb();if(!length)return length.error();
            if(length.value()>max_entry_expression_bytes)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DW_OP_entry_value block exceeds 64 KiB"};
            auto block=r.bytes(static_cast<std::size_t>(length.value()));if(!block)return block.error();
            auto nested=decode_location_expression_impl(block.value(),address_size,depth+1,total_operations);
            if(!nested)return nested.error();
            if(nested.value().empty())return malformed("DW_OP_entry_value block is empty");
            item.nested_operations=std::move(nested.value());
            break;
        }
        default:return unsupported("unsupported DWARF v4 location opcode 0x"+[&]{char b[3]{};constexpr char d[]="0123456789abcdef";b[0]=d[op>>4];b[1]=d[op&15];return std::string(b,2);}());
        }
        out.push_back(item);
    }
    for(const auto& item:out)if(item.kind==LocationOperationKind::branch||item.kind==LocationOperationKind::branch_if_nonzero){const auto target=item.second_unsigned_operand;if(target!=bytes.size()&&std::none_of(out.begin(),out.end(),[&](const auto& candidate){return candidate.expression_offset==target;}))return malformed("DWARF branch target is not an operation boundary");}
    return out;
}
hexlab::Result<std::vector<LocationOperation>> decode_location_expression(
    std::span<const std::uint8_t> bytes,std::uint8_t address_size){
    std::size_t total_operations=0;
    return decode_location_expression_impl(bytes,address_size,0,total_operations);
}
std::optional<std::int64_t> cfa_relative_offset(
    const std::vector<LocationOperation>& expression,
    const std::vector<LocationOperation>& frame_base) {
    if(frame_base.size()!=1 || frame_base[0].kind!=LocationOperationKind::call_frame_cfa)return {};
    if(expression.size()==1 && expression[0].kind==LocationOperationKind::frame_base_relative)
        return expression[0].signed_operand;
    if(expression.size()!=3 || expression[0].kind!=LocationOperationKind::call_frame_cfa ||
       expression[2].kind!=LocationOperationKind::plus)return {};
    const auto& offset=expression[1];
    if(offset.kind==LocationOperationKind::signed_constant)return offset.signed_operand;
    if(offset.kind==LocationOperationKind::unsigned_constant && offset.unsigned_operand<=static_cast<std::uint64_t>(INT64_MAX))
        return static_cast<std::int64_t>(offset.unsigned_operand);
    return {};
}

hexlab::Result<std::uint64_t> constant_member_offset(
    const Value &value, std::uint64_t form, std::uint8_t address_size) {
    const bool constant_form = form == form_data1 || form == form_data2 || form == form_data4 ||
        form == form_data8 || form == form_udata || form == form_sdata || form == form_implicit_const;
    if (constant_form) if (const auto *constant = std::get_if<std::uint64_t>(&value)) return *constant;
    if (constant_form) if (const auto *constant = std::get_if<std::int64_t>(&value)) {
        if (*constant < 0) return unsupported("negative DWARF structure member offset is unsupported");
        return static_cast<std::uint64_t>(*constant);
    }
    const bool expression_form = form == form_exprloc || form == form_block ||
        form == form_block1 || form == form_block2 || form == form_block4;
    const auto *bytes = std::get_if<Blob>(&value);
    if (!expression_form || !bytes)
        return unsupported("structure member location is not a constant offset or constant expression");
    auto decoded = decode_location_expression(*bytes, address_size);
    if (!decoded) return decoded.error();
    std::vector<std::uint64_t> stack;
    for (const auto &operation : decoded.value()) {
        switch (operation.kind) {
        case LocationOperationKind::literal:
            stack.push_back(operation.unsigned_operand);
            break;
        case LocationOperationKind::unsigned_constant:
            stack.push_back(operation.unsigned_operand);
            break;
        case LocationOperationKind::signed_constant:
            if (operation.signed_operand < 0)
                return unsupported("negative DWARF structure member offset is unsupported");
            stack.push_back(static_cast<std::uint64_t>(operation.signed_operand));
            break;
        case LocationOperationKind::plus:
            if (stack.size() < 2) return malformed("DWARF member-offset expression stack underflow");
            if (stack.back() > UINT64_MAX - stack[stack.size() - 2])
                return hexlab::Error{hexlab::ErrorCode::overflow, "DWARF member offset overflows"};
            stack[stack.size() - 2] += stack.back();
            stack.pop_back();
            break;
        case LocationOperationKind::plus_unsigned:
            if (stack.empty()) return malformed("DWARF member-offset expression stack underflow");
            if (operation.unsigned_operand > UINT64_MAX - stack.back())
                return hexlab::Error{hexlab::ErrorCode::overflow, "DWARF member offset overflows"};
            stack.back() += operation.unsigned_operand;
            break;
        default:
            return unsupported("DWARF structure member expression is not a constant offset");
        }
        if (stack.size() > 16) return hexlab::Error{hexlab::ErrorCode::resource_limit,
                                                     "DWARF member-offset expression stack exceeds 16 values"};
    }
    if (stack.size() != 1) return malformed("DWARF member-offset expression does not yield one value");
    return stack.back();
}

enum class IndexedTableKind { addresses, strings, locations, ranges };
struct IndexedTableContribution {
    std::size_t begin = 0;
    std::size_t end = 0;
    std::size_t entries = 0;
    std::size_t offset_entry_count = 0;
    std::uint8_t offset_size = 4;
};

hexlab::Result<IndexedTableContribution> indexed_table_contribution(
    std::span<const std::uint8_t> section, std::uint64_t base,
    IndexedTableKind kind, std::uint8_t address_size) {
    if (base > section.size()) return malformed("DWARF indexed-table base is outside its section");
    const bool lists = kind == IndexedTableKind::locations || kind == IndexedTableKind::ranges;
    const std::size_t fixed_header_after_length = lists ? 8 : 4;
    std::optional<IndexedTableContribution> selected;
    for (const std::uint8_t offset_size : {std::uint8_t{4}, std::uint8_t{8}}) {
        const std::size_t initial_size = offset_size == 4 ? 4 : 12;
        const std::size_t header_size = initial_size + fixed_header_after_length;
        if (base < header_size) continue;
        const auto candidate = static_cast<std::size_t>(base - header_size);
        Reader reader(section, candidate, section.size());
        auto initial = read_initial_length(reader);
        if (!initial || initial.value().offset_size != offset_size) continue;
        if (initial.value().length > section.size() - reader.position()) continue;
        const auto end = reader.position() + static_cast<std::size_t>(initial.value().length);
        auto version = reader.fixed(2);
        if (!version || version.value() != 5) continue;
        auto width = reader.fixed(1);
        if (!width) continue;
        auto segment = reader.fixed(1);
        if (!segment) continue;
        if (lists) {
            auto count = reader.fixed(4);
            if (!count || reader.position() != base || segment.value() != 0 ||
                width.value() != address_size)
                continue;
            if (base > end || count.value() > (end - static_cast<std::size_t>(base)) / offset_size)
                return malformed("DWARF indexed-list offset table exceeds its contribution");
            if (selected) return malformed("DWARF indexed-list base identifies multiple contributions");
            selected = IndexedTableContribution{candidate, end, static_cast<std::size_t>(base),
                                                static_cast<std::size_t>(count.value()), offset_size};
        } else {
            if (base > end || reader.position() != base || segment.value() != 0) continue;
            if (kind == IndexedTableKind::addresses && width.value() != address_size) continue;
            if (kind == IndexedTableKind::strings && width.value() != 0) continue;
            if (selected) return malformed("DWARF indexed-table base identifies multiple contributions");
            selected = IndexedTableContribution{candidate, end, static_cast<std::size_t>(base), 0, offset_size};
        }
    }
    if (!selected) return malformed("DWARF indexed-table base does not match a DWARF v5 contribution header");
    return *selected;
}

hexlab::Result<std::uint64_t> resolve_indexed_list(std::span<const std::uint8_t> section,
                                                  std::uint64_t base,
                                                  std::uint64_t index,
                                                  std::uint8_t address_size,
                                                  IndexedTableKind kind) {
    auto contribution = indexed_table_contribution(section, base, kind, address_size);
    if (!contribution) return contribution.error();
    const auto &table = contribution.value();
    if (index >= table.offset_entry_count)
        return malformed(kind == IndexedTableKind::locations
                             ? "DW_FORM_loclistx index is outside the contribution offset table"
                             : "DW_FORM_rnglistx index is outside the contribution offset table");
    const auto entry_offset = table.entries + static_cast<std::size_t>(index) * table.offset_size;
    Reader entry(section, entry_offset, entry_offset + table.offset_size);
    auto relative = entry.fixed(table.offset_size);
    if (!relative) return relative.error();
    if (relative.value() > UINT64_MAX - table.begin)
        return malformed("DWARF indexed-list offset overflows");
    const auto offset = static_cast<std::uint64_t>(table.begin) + relative.value();
    const auto list_start = table.entries + table.offset_entry_count * table.offset_size;
    if (offset < list_start || offset >= table.end)
        return malformed(kind == IndexedTableKind::locations
                             ? "DW_FORM_loclistx resolves outside the location-list area"
                             : "DW_FORM_rnglistx resolves outside the range-list area");
    return offset;
}

hexlab::Result<std::uint64_t> resolve_loclistx(std::span<const std::uint8_t> section,
                                              std::uint64_t base,
                                              std::uint64_t index,
                                              std::uint8_t address_size) {
    return resolve_indexed_list(section, base, index, address_size, IndexedTableKind::locations);
}

hexlab::Result<std::uint64_t> resolve_rnglistx(std::span<const std::uint8_t> section,
                                              std::uint64_t base,
                                              std::uint64_t index,
                                              std::uint8_t address_size) {
    return resolve_indexed_list(section, base, index, address_size, IndexedTableKind::ranges);
}

hexlab::Result<std::uint64_t> resolve_addrx(std::span<const std::uint8_t> section,
                                           std::uint64_t base,
                                           std::uint64_t index,
                                           std::uint8_t address_size) {
    if (address_size != 4 && address_size != 8)
        return malformed("DWARF .debug_addr address size is invalid");
    auto contribution = indexed_table_contribution(section, base, IndexedTableKind::addresses, address_size);
    if (!contribution) return contribution.error();
    const auto &table = contribution.value();
    const auto width_bytes = static_cast<std::size_t>(address_size);
    const auto available = table.end - table.entries;
    if (index >= available / width_bytes)
        return malformed("DW_LLE address index is outside the .debug_addr contribution");
    const auto entry_offset = table.entries + static_cast<std::size_t>(index) * width_bytes;
    Reader value(section, entry_offset, entry_offset + width_bytes);
    return value.fixed(width_bytes);
}

hexlab::Result<std::vector<ImportedSymbol::Range>> decode_range_list(
    std::span<const std::uint8_t> section, std::uint64_t offset, std::uint8_t address_size,
    std::optional<std::uint64_t> initial_base,
    const std::function<hexlab::Result<std::uint64_t>(std::uint64_t)>& resolve_address_index) {
    constexpr std::size_t max_ranges = 4096;
    if ((address_size != 4 && address_size != 8) || offset >= section.size())
        return malformed("DWARF range-list offset or address size is invalid");
    Reader reader(section, static_cast<std::size_t>(offset), section.size());
    std::vector<ImportedSymbol::Range> ranges;
    auto base = initial_base;
    bool terminated = false;
    std::size_t entry_count = 0;
    const auto address_max = address_size == 4 ? UINT64_C(0xffffffff) : UINT64_MAX;
    while (!reader.done()) {
        auto op_value = reader.fixed(1); if (!op_value) return op_value.error();
        const auto op = static_cast<std::uint8_t>(op_value.value());
        if (op == 0) { terminated = true; break; }
        if (++entry_count > max_ranges * 2)
            return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF range list exceeds 8192 entries"};
        if (op != 1 && op != 5 && ranges.size() >= max_ranges)
            return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF range list exceeds 4096 entries"};
        if (op == 1 || op == 5) { // DW_RLE_base_addressx / DW_RLE_base_address
            std::uint64_t value = 0;
            if (op == 1) {
                auto index = reader.uleb(); if (!index) return index.error();
                auto resolved = resolve_address_index(index.value()); if (!resolved) return resolved.error();
                value = resolved.value();
            } else {
                auto fixed = reader.fixed(address_size); if (!fixed) return fixed.error();
                value = fixed.value();
            }
            base = value;
            continue;
        }
        ImportedSymbol::Range range;
        if (op == 2) { // DW_RLE_startx_endx
            auto begin_index = reader.uleb(); if (!begin_index) return begin_index.error();
            auto end_index = reader.uleb(); if (!end_index) return end_index.error();
            auto begin = resolve_address_index(begin_index.value()); if (!begin) return begin.error();
            auto end = resolve_address_index(end_index.value()); if (!end) return end.error();
            range = {begin.value(), end.value()};
        } else if (op == 3) { // DW_RLE_startx_length
            auto index = reader.uleb(); if (!index) return index.error();
            auto begin = resolve_address_index(index.value()); if (!begin) return begin.error();
            auto length = reader.uleb(); if (!length) return length.error();
            if (length.value() > address_max - begin.value()) return malformed("DWARF range-list start/length overflows");
            range = {begin.value(), begin.value() + length.value()};
        } else if (op == 4) { // DW_RLE_offset_pair
            if (!base) return malformed("DW_RLE_offset_pair has no compilation-unit base address");
            auto begin = reader.uleb(); if (!begin) return begin.error();
            auto end = reader.uleb(); if (!end) return end.error();
            if (begin.value() > address_max - *base || end.value() > address_max - *base)
                return malformed("DWARF range-list offset pair overflows");
            range = {*base + begin.value(), *base + end.value()};
        } else if (op == 6) { // DW_RLE_start_end
            auto begin = reader.fixed(address_size); if (!begin) return begin.error();
            auto end = reader.fixed(address_size); if (!end) return end.error();
            range = {begin.value(), end.value()};
        } else if (op == 7) { // DW_RLE_start_length
            auto begin = reader.fixed(address_size); if (!begin) return begin.error();
            auto length = reader.uleb(); if (!length) return length.error();
            if (length.value() > address_max - begin.value()) return malformed("DWARF range-list start/length overflows");
            range = {begin.value(), begin.value() + length.value()};
        } else {
            return unsupported("unsupported DWARF v5 range-list entry 0x" +
                [&]{char b[3]{};constexpr char d[]="0123456789abcdef";b[0]=d[op>>4];b[1]=d[op&15];return std::string(b,2);}());
        }
        if (range.begin >= range.end || range.end > address_max)
            return malformed("DWARF range-list entry is empty, reversed, or outside address width");
        ranges.push_back(range);
    }
    if (!terminated) return malformed("DWARF range list has no end-of-list marker");
    return ranges;
}

hexlab::Result<std::vector<LocationRange>> decode_location_list(
    std::span<const std::uint8_t> section, std::uint64_t offset, std::uint8_t address_size,
    const std::function<hexlab::Result<std::uint64_t>(std::uint64_t)>& resolve_address_index) {
    constexpr std::size_t max_ranges = 4096;
    constexpr std::size_t max_expression_bytes = 65536;
    if (offset >= section.size()) return malformed("DWARF location-list offset is outside .debug_loclists");
    Reader reader(section, static_cast<std::size_t>(offset), section.size());
    std::vector<LocationRange> ranges;
    std::optional<std::uint64_t> base_address;
    std::size_t expression_bytes = 0, operation_count = 0;
    bool terminated = false;
    while (!reader.done()) {
        if (ranges.size() >= max_ranges) return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF location list exceeds 4096 ranges"};
        auto opcode_value = reader.fixed(1); if (!opcode_value) return opcode_value.error();
        const auto opcode = static_cast<std::uint8_t>(opcode_value.value());
        if (opcode == 0x00) { terminated = true; break; } // DW_LLE_end_of_list
        if (opcode == 0x06) { // DW_LLE_base_address
            auto value = reader.fixed(address_size); if (!value) return value.error();
            base_address = value.value();
            continue;
        }
        if (opcode == 0x01) { // DW_LLE_base_addressx
            auto index = reader.uleb(); if (!index) return index.error();
            auto value = resolve_address_index(index.value()); if (!value) return value.error();
            base_address = value.value();
            continue;
        }
        LocationRange range;
        if (opcode == 0x05) { // DW_LLE_default_location; [MAX,MAX) is reserved in persisted model.
            if (std::any_of(ranges.begin(), ranges.end(), [](const auto &entry) {
                    return entry.begin == UINT64_MAX && entry.end == UINT64_MAX;
                })) return malformed("DWARF location list has multiple default-location entries");
            range.begin = UINT64_MAX;
            range.end = UINT64_MAX;
        } else if (opcode == 0x07) { // DW_LLE_start_end
            auto begin = reader.fixed(address_size); if (!begin) return begin.error();
            auto end = reader.fixed(address_size); if (!end) return end.error();
            range.begin = begin.value(); range.end = end.value();
        } else if (opcode == 0x08) { // DW_LLE_start_length
            auto begin = reader.fixed(address_size); if (!begin) return begin.error();
            auto length = reader.uleb(); if (!length) return length.error();
            if (length.value() > UINT64_MAX - begin.value()) return malformed("DWARF location-list range overflows");
            range.begin = begin.value(); range.end = begin.value() + length.value();
        } else if (opcode == 0x02) { // DW_LLE_startx_endx
            auto begin_index = reader.uleb(); if (!begin_index) return begin_index.error();
            auto end_index = reader.uleb(); if (!end_index) return end_index.error();
            auto begin = resolve_address_index(begin_index.value()); if (!begin) return begin.error();
            auto end = resolve_address_index(end_index.value()); if (!end) return end.error();
            range.begin = begin.value(); range.end = end.value();
        } else if (opcode == 0x03) { // DW_LLE_startx_length
            auto begin_index = reader.uleb(); if (!begin_index) return begin_index.error();
            auto begin = resolve_address_index(begin_index.value()); if (!begin) return begin.error();
            auto length = reader.uleb(); if (!length) return length.error();
            if (length.value() > UINT64_MAX - begin.value()) return malformed("DWARF location-list range overflows");
            range.begin = begin.value(); range.end = begin.value() + length.value();
        } else if (opcode == 0x04) { // DW_LLE_offset_pair
            if (!base_address) return malformed("DW_LLE_offset_pair has no base address");
            auto begin = reader.uleb(); if (!begin) return begin.error();
            auto end = reader.uleb(); if (!end) return end.error();
            if (begin.value() > UINT64_MAX - *base_address || end.value() > UINT64_MAX - *base_address)
                return malformed("DWARF location-list offset-pair range overflows");
            range.begin = *base_address + begin.value(); range.end = *base_address + end.value();
        } else {
            return unsupported("unsupported DWARF v5 location-list entry 0x" +
                [&]{char b[3]{};constexpr char d[]="0123456789abcdef";b[0]=d[opcode>>4];b[1]=d[opcode&15];return std::string(b,2);}());
        }
        const bool is_default = range.begin == UINT64_MAX && range.end == UINT64_MAX;
        if (!is_default && range.begin >= range.end) return malformed("DWARF location-list range is empty or reversed");
        auto size = reader.uleb(); if (!size) return size.error();
        if (size.value() > max_expression_bytes - expression_bytes)
            return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF location-list expressions exceed 65536 bytes"};
        auto expression = reader.bytes(static_cast<std::size_t>(size.value())); if (!expression) return expression.error();
        auto operations = decode_location_expression(expression.value(), address_size); if (!operations) return operations.error();
        if (operations.value().size() > 4096 - operation_count)
            return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF location-list operations exceed 4096"};
        expression_bytes += expression.value().size(); operation_count += operations.value().size();
        range.expression = std::move(expression.value()); range.operations = std::move(operations.value());
        ranges.push_back(std::move(range));
    }
    if (!terminated) return malformed("DWARF location list has no end-of-list marker");
    return ranges;
}

hexlab::Result<std::vector<LocationRange>> decode_legacy_location_list(
    std::span<const std::uint8_t> section, std::uint64_t offset,
    std::uint8_t address_size, std::optional<std::uint64_t> initial_base) {
    constexpr std::size_t max_ranges = 4096, max_expression_bytes = 65536;
    if (offset >= section.size()) return malformed("DWARF location-list offset is outside .debug_loc");
    Reader reader(section, static_cast<std::size_t>(offset), section.size());
    const auto address_max = address_size == 4 ? UINT64_C(0xffffffff) : UINT64_MAX;
    auto base = initial_base;
    std::vector<LocationRange> ranges;
    std::size_t expression_bytes = 0, operation_count = 0;
    bool terminated = false;
    while (!reader.done()) {
        if (ranges.size() >= max_ranges) return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF location list exceeds 4096 ranges"};
        auto begin = reader.fixed(address_size); if (!begin) return begin.error();
        auto end = reader.fixed(address_size); if (!end) return end.error();
        if (!begin.value() && !end.value()) { terminated = true; break; }
        if (begin.value() == address_max) { base = end.value(); continue; }
        if (!base) return malformed("DWARF .debug_loc offset pair has no DW_AT_low_pc base");
        if (begin.value() > address_max - *base || end.value() > address_max - *base) return malformed("DWARF .debug_loc range overflows");
        LocationRange range{*base + begin.value(), *base + end.value(), {}, {}};
        if (range.begin >= range.end) return malformed("DWARF .debug_loc range is empty or reversed");
        auto size = reader.fixed(2); if (!size) return size.error();
        if (size.value() > max_expression_bytes - expression_bytes) return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF location-list expressions exceed 65536 bytes"};
        auto expression = reader.bytes(static_cast<std::size_t>(size.value())); if (!expression) return expression.error();
        auto operations = decode_location_expression(expression.value(), address_size); if (!operations) return operations.error();
        if (operations.value().size() > 4096 - operation_count) return hexlab::Error{hexlab::ErrorCode::resource_limit, "DWARF location-list operations exceed 4096"};
        expression_bytes += expression.value().size(); operation_count += operations.value().size();
        range.expression = std::move(expression.value()); range.operations = std::move(operations.value());
        ranges.push_back(std::move(range));
    }
    if (!terminated) return malformed("DWARF .debug_loc list has no end-of-list marker");
    return ranges;
}

} // namespace

hexlab::Result<ImportResult> import_dwarf(const DwarfSections&sections){
    const auto canceled = [&]() -> bool { return sections.stop.stop_requested(); };
    if(sections.source_id.empty()||sections.info.empty()||sections.abbrev.empty())return hexlab::Error{hexlab::ErrorCode::invalid_argument,"DWARF source id, info, and abbrev are required"};
    if(sections.info_section_offset>UINT64_MAX-sections.info.size())return hexlab::Error{hexlab::ErrorCode::overflow,"DWARF package info contribution offset overflows"};
    if(sections.info.size()>256u*1024u*1024u||sections.abbrev.size()>64u*1024u*1024u||sections.strings.size()>256u*1024u*1024u||sections.string_offsets.size()>256u*1024u*1024u||sections.addresses.size()>256u*1024u*1024u||sections.line_strings.size()>256u*1024u*1024u||sections.location_lists.size()>256u*1024u*1024u||sections.locations.size()>256u*1024u*1024u||sections.range_lists.size()>256u*1024u*1024u)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF sections exceed importer limits"};
    ImportResult output;Reader info(sections.info,0,sections.info.size());std::uint64_t die_count=0;
    std::uint64_t supplementary_bytes_used=0;std::uint32_t supplementary_requests=0;
    std::vector<DwarfSplitUnitRequest> pending_split_units;
    std::set<std::uint64_t> seen_skeleton_ids;
    struct UnitPosition { std::size_t offset; bool type_unit; std::uint8_t unit_type; std::uint8_t offset_size; };
    std::vector<UnitPosition> unit_positions;
    Reader unit_scan(sections.info,0,sections.info.size());
    while(!unit_scan.done()){
        if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};
        const auto offset=unit_scan.position();auto initial=read_initial_length(unit_scan);if(!initial)return initial.error();
        const auto length=initial.value().length;
        if(length<7||length>sections.info.size()-unit_scan.position())return malformed("invalid DWARF compilation unit length");
        const auto end=unit_scan.position()+static_cast<std::size_t>(length);
        auto version=unit_scan.fixed(2);if(!version)return version.error();bool type_unit=false;std::uint8_t unit_type=1;
        if(version.value()==5){if(length<static_cast<std::uint64_t>(4+initial.value().offset_size))return malformed("DWARF v5 unit header exceeds its declared unit length");auto kind=unit_scan.fixed(1);if(!kind)return kind.error();unit_type=static_cast<std::uint8_t>(kind.value());type_unit=unit_type==2||unit_type==6;}
        else if(version.value()==4&&sections.dwarf4_type_units)type_unit=true;
        else if(version.value()!=4)return unsupported("only DWARF versions 4 and 5 are supported");
        unit_positions.push_back({offset,type_unit,unit_type,initial.value().offset_size});unit_scan=Reader(sections.info,end,sections.info.size());
    }
    // A compile unit may refer to a type unit that appears later in .debug_info.
    // Process bounded type-unit headers first so their signatures are available
    // when ordinary compile-unit DIEs resolve DW_FORM_ref_sig8.
    std::stable_sort(unit_positions.begin(),unit_positions.end(),[](const auto&a,const auto&b){return a.type_unit&&!b.type_unit;});
    std::unordered_map<std::uint64_t,types::TypePtr> signature_types;
    std::unordered_map<std::uint64_t,types::TypePtr> absolute_type_references;
    struct PriorFunctionSignature {
        std::string name;
        types::TypePtr return_type;
        std::vector<types::Parameter> parameters;
        bool variadic = false;
    };
    std::unordered_map<std::uint64_t,PriorFunctionSignature> prior_function_signatures;
    std::map<std::uint64_t,DwarfCrossContributionDie> cross_contribution_dies;
    std::uint64_t cross_contribution_bytes_used=0;
    std::uint32_t cross_contribution_requests=0;
    auto resolve_cross_contribution_die=[&](std::uint64_t absolute_offset)->hexlab::Result<const DwarfCrossContributionDie*>{
        if(auto found=cross_contribution_dies.find(absolute_offset);found!=cross_contribution_dies.end())return &found->second;
        if(!sections.cross_contribution_die_resolver&&!sections.source_cross_contribution_die_resolver)return unsupported("cross-contribution DW_FORM_ref_addr requires an explicit package-index resolver");
        if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF cross-contribution resolution canceled"};
        if(cross_contribution_requests>=sections.cross_contribution_max_requests)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF cross-contribution reference request limit exceeded"};
        ++cross_contribution_requests;
        auto resolved=sections.source_cross_contribution_die_resolver
            ? sections.source_cross_contribution_die_resolver(sections.source_id,absolute_offset)
            : sections.cross_contribution_die_resolver(absolute_offset);
        if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF cross-contribution resolution canceled"};
        if(!resolved)return resolved.error();
        auto die=std::move(resolved.value());
        if(!die.identity_verified)return malformed("DWARF cross-contribution resolver did not verify the selected package-index row");
        if(die.die_offset>=die.contribution_size||die.info_section_offset>UINT64_MAX-die.die_offset||die.info_section_offset+die.die_offset!=absolute_offset)return malformed("DWARF cross-contribution resolver returned a different or out-of-range DIE offset");
        if(die.index_kind!=DwarfPackageIndexKind::compile_units&&die.index_kind!=DwarfPackageIndexKind::type_units)return malformed("DWARF cross-contribution resolver returned an invalid package-index kind");
        if(!die.type)return malformed("DWARF cross-contribution resolver returned an empty DIE type");
        if(die.kind==DwarfReferencedDieKind::subprogram){if(die.type->kind()!=types::Kind::function||die.name.empty())return malformed("DWARF cross-contribution subprogram lacks a named function type");}
        else if(die.kind==DwarfReferencedDieKind::type){if(die.type->kind()==types::Kind::function||die.type->kind()==types::Kind::void_type)return malformed("DWARF cross-contribution type DIE returned a non-object type");}
        else return malformed("DWARF cross-contribution resolver returned an invalid DIE kind");
        auto encoded=types::encode(*die.type);if(!encoded)return encoded.error();
        const auto encoded_size=static_cast<std::uint64_t>(encoded.value().size());
        if(die.bytes_examined>sections.cross_contribution_max_bytes-cross_contribution_bytes_used||encoded_size>sections.cross_contribution_max_bytes-cross_contribution_bytes_used-die.bytes_examined)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF cross-contribution byte budget exceeded"};
        cross_contribution_bytes_used+=die.bytes_examined+encoded_size;
        auto [stored,inserted]=cross_contribution_dies.emplace(absolute_offset,std::move(die));
        (void)inserted;
        return &stored->second;
    };
    std::set<std::uint64_t> seen_type_signatures;
    struct UnitContext {
        std::uint64_t offset = 0;
        std::uint64_t end = 0;
        std::uint64_t address_size = 0;
        std::uint64_t abbrev_offset = 0;
        std::uint16_t version = 0;
        std::uint8_t unit_type = 1;
        bool type_unit = false;
        std::optional<std::uint64_t> type_die_offset, type_signature;
        std::vector<Die> dies;
        std::unordered_map<std::uint64_t,Abbreviation> abbrevs;
    };
    std::vector<UnitContext> contexts;
    std::unordered_map<std::uint64_t,std::size_t> die_unit_index;
    for(const auto&indexed_unit:unit_positions){
        if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};
        info=Reader(sections.info,indexed_unit.offset,sections.info.size());
        const auto unit_offset=info.position();auto initial=read_initial_length(info);if(!initial)return initial.error();const auto length=initial.value().length;const auto offset_size=initial.value().offset_size;if(length<7||length>sections.info.size()-info.position())return malformed("invalid DWARF compilation unit length");const auto unit_end=info.position()+static_cast<std::size_t>(length);
        auto version=info.fixed(2);if(!version)return version.error();std::uint64_t aboff_value=0,as_value=0;bool type_unit=false;std::uint8_t unit_type=1;std::optional<std::uint64_t> type_die_offset,type_signature,dwo_id;
        if(version.value()==4){auto aboff=info.fixed(offset_size);if(!aboff)return aboff.error();auto as=info.fixed(1);if(!as)return as.error();aboff_value=aboff.value();as_value=as.value();if(sections.dwarf4_type_units){if(length<static_cast<std::uint64_t>(7+offset_size+8))return malformed("DWARF v4 type-unit header exceeds its declared unit length");auto signature=info.fixed(8);if(!signature)return signature.error();auto type_offset=info.fixed(offset_size);if(!type_offset)return type_offset.error();type_signature=signature.value();type_die_offset=type_offset.value();if(!seen_type_signatures.insert(*type_signature).second)return malformed("duplicate DWARF type-unit signature");}}
        else if(version.value()==5){if(length<static_cast<std::uint64_t>(4+offset_size))return malformed("DWARF v5 unit header exceeds its declared unit length");auto unit_type_value=info.fixed(1);if(!unit_type_value)return unit_type_value.error();unit_type=static_cast<std::uint8_t>(unit_type_value.value());auto as=info.fixed(1);if(!as)return as.error();auto aboff=info.fixed(offset_size);if(!aboff)return aboff.error();if(info.position()>unit_end)return malformed("DWARF v5 unit header exceeds its declared unit length");
            if(unit_type==2||unit_type==6){if(length<static_cast<std::uint64_t>(12+2*offset_size))return malformed("DWARF v5 type-unit header exceeds its declared unit length");auto signature=info.fixed(8);if(!signature)return signature.error();auto offset=info.fixed(offset_size);if(!offset)return offset.error();type_unit=true;type_signature=signature.value();type_die_offset=offset.value();if(!seen_type_signatures.insert(*type_signature).second)return malformed("duplicate DWARF type-unit signature");}
            else if(unit_type==4||unit_type==5){if(length<static_cast<std::uint64_t>(12+offset_size))return malformed("DWARF v5 skeleton/split-compile header exceeds its declared unit length");auto id=info.fixed(8);if(!id)return id.error();dwo_id=id.value();}
            else if(unit_type!=1)return unsupported("unsupported DWARF v5 unit type "+std::to_string(unit_type));
            as_value=as.value();aboff_value=aboff.value();}
        else return unsupported("only DWARF versions 4 and 5 are supported");
        if(sections.expected_split_dwo_id && version.value()==5){if(unit_type!=5||!dwo_id)return malformed("DWO contribution contains a non-split compile unit");if(*dwo_id!=*sections.expected_split_dwo_id)return malformed("DWO contribution ID does not match its skeleton");if(sections.expected_split_address_size&&as_value!=*sections.expected_split_address_size)return malformed("DWO address size does not match its skeleton");output.split_unit=true;output.split_dwo_id=*dwo_id;}
        else if(unit_type==5)return unsupported("split compile unit must be imported through its matching skeleton");
        if(as_value!=4&&as_value!=8)return unsupported("DWARF address size must be 4 or 8");auto abbrevs=read_abbrevs(sections.abbrev,aboff_value,sections.stop);if(!abbrevs)return abbrevs.error();
        std::vector<Die> dies;std::vector<std::size_t> parents;Reader body(sections.info,info.position(),unit_end);
        while(!body.done()){
            if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};
            const auto off=body.position();auto code=body.uleb();if(!code)return code.error();if(!code.value()){if(parents.empty())return malformed("unexpected DWARF null DIE");parents.pop_back();continue;}
            auto ai=abbrevs.value().find(code.value());if(ai==abbrevs.value().end())return malformed("DIE references missing abbreviation code "+std::to_string(code.value())+" at offset "+std::to_string(off));
            if(dies.empty()&&ai->second.tag!=tag_compile_unit&&!(type_unit&&(is_type_tag(ai->second.tag)||ai->second.tag==tag_type_unit)))return malformed("DWARF unit does not begin with a compile_unit or type DIE");if(!dies.empty()&&parents.empty())return malformed("multiple top-level DIEs in one DWARF unit");
            Die d;d.code=code.value();d.tag=ai->second.tag;d.offset=off;if(!parents.empty())d.parent=parents.back();
            for(const auto&spec:ai->second.attributes){if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};auto v=read_form(body,spec.form,static_cast<std::uint8_t>(as_value),offset_size,sections.strings,sections.line_strings,sections.supplementary_strings,spec.implicit);if(!v)return v.error();d.attributes.emplace(spec.name,std::move(v.value()));}
            d.end=body.position();const auto index=dies.size();dies.push_back(std::move(d));if(dies[index].parent)dies[*dies[index].parent].children.push_back(index);if(ai->second.children)parents.push_back(index);
            if(++die_count>2'000'000)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF DIE count exceeds importer limit"};
        }
        if(!parents.empty())return malformed("unterminated DWARF child list");if(dies.empty())return malformed("DWARF unit has no root DIE");if(type_die_offset){if(*type_die_offset>UINT64_MAX-unit_offset||unit_offset+*type_die_offset>=unit_end)return malformed("DWARF type-unit type offset is outside its unit");const auto target=unit_offset+*type_die_offset;if(std::none_of(dies.begin(),dies.end(),[&](const Die&die){return die.offset==target&&is_type_tag(die.tag);}))return malformed("DWARF type-unit offset does not identify a type DIE");}
        if(version.value()==4){
            const auto *gnu_id=num(dies.front(),attr_gnu_dwo_id);
            const auto *gnu_name=str(dies.front(),attr_gnu_dwo_name);
            if(sections.expected_split_dwo_id){
                if(!gnu_id)return malformed("DWARF v4 DWO contribution lacks its GNU DWO ID");
                if(*gnu_id!=*sections.expected_split_dwo_id)return malformed("DWARF v4 DWO contribution ID does not match its skeleton");
                if(sections.expected_split_address_size&&as_value!=*sections.expected_split_address_size)return malformed("DWO address size does not match its skeleton");
                output.split_unit=true;output.split_dwo_id=*gnu_id;
            } else if(gnu_id&&gnu_name&&!gnu_name->empty()){
                if(!seen_skeleton_ids.insert(*gnu_id).second)return malformed("duplicate DWARF skeleton DWO ID");
                const auto *comp_dir=str(dies.front(),attr_comp_dir);
                if(pending_split_units.size()>=4096)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF skeleton unit count exceeds 4096"};
                pending_split_units.push_back({*gnu_id,*gnu_name,comp_dir?*comp_dir:std::string{},static_cast<std::uint8_t>(as_value)});
            } else if(gnu_id&&!sections.expected_split_dwo_id) {
                // A v4 split object without its skeleton path is not independently resolvable.
            }
        }
        if(unit_type==4){
            if(!dwo_id)return malformed("DWARF skeleton unit lacks its DWO ID");
            if(!seen_skeleton_ids.insert(*dwo_id).second)return malformed("duplicate DWARF skeleton DWO ID");
            const auto *dwo_name=str(dies.front(),attr_dwo_name);
            const auto *comp_dir=str(dies.front(),attr_comp_dir);
            if(!dwo_name||dwo_name->empty())output.diagnostics.push_back("DWARF skeleton has no DW_AT_dwo_name for DWO ID "+std::to_string(*dwo_id));
            else {
                if(pending_split_units.size()>=4096)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF skeleton unit count exceeds 4096"};
                pending_split_units.push_back({*dwo_id,*dwo_name,comp_dir?*comp_dir:std::string{},static_cast<std::uint8_t>(as_value)});
            }
        }
        if(version.value()==5){
            const auto *str_base=num(dies.front(),attr_str_offsets_base),*addr_base=num(dies.front(),attr_addr_base);
            std::optional<std::uint64_t> implicit_split_type_str_base;
            if (unit_type == 6 && !str_base && !sections.string_offsets.empty()) {
                implicit_split_type_str_base = 8;
                Reader initial_reader(sections.string_offsets, 0, sections.string_offsets.size());
                auto table_initial_length = read_initial_length(initial_reader);
                if (table_initial_length && table_initial_length.value().offset_size == 8)
                    implicit_split_type_str_base = 16;
            }
            for(auto&die:dies)for(auto&[attribute,value]:die.attributes)if(auto*indexed=std::get_if<IndexedForm>(&value)){
                if(indexed->location_list||indexed->range_list)continue;
                const std::optional<std::uint64_t> base=indexed->address?(addr_base?std::optional<std::uint64_t>{*addr_base}:std::nullopt):(str_base?std::optional<std::uint64_t>{*str_base}:implicit_split_type_str_base);const auto table=indexed->address?sections.addresses:sections.string_offsets;
                if(!base)return unsupported(indexed->address?"DW_FORM_addrx requires DW_AT_addr_base":"DW_FORM_strx requires DW_AT_str_offsets_base");
                if (indexed->address) {
                    auto address = resolve_addrx(table, *base, indexed->index, static_cast<std::uint8_t>(as_value));
                    if (!address) return address.error();
                    value = address.value();
                } else {
                    auto contribution = indexed_table_contribution(table, *base, IndexedTableKind::strings,
                                                                   static_cast<std::uint8_t>(as_value));
                    if (!contribution) return contribution.error();
                    const auto &entries = contribution.value();
                    const auto entry_width = static_cast<std::size_t>(entries.offset_size);
                    if (indexed->index >= (entries.end - entries.entries) / entry_width)
                        return malformed("DWARF indexed string index is outside its contribution");
                    const auto entry = entries.entries + static_cast<std::size_t>(indexed->index) * entry_width;
                    Reader offset_reader(table, entry, entry + entry_width);
                    auto offset = offset_reader.fixed(entry_width);
                    if (!offset) return offset.error();
                    if (offset.value() >= sections.strings.size())
                        return malformed("DWARF indexed string offset is out of .debug_str bounds");
                    Reader string_reader(sections.strings, static_cast<std::size_t>(offset.value()),
                                         sections.strings.size());
                    auto text = string_reader.cstring();
                    if (!text) return text.error();
                    value = std::move(text.value());
                }
            }
        }
        UnitContext context;
        context.offset=unit_offset;context.end=unit_end;context.address_size=as_value;
        context.abbrev_offset=aboff_value;context.version=static_cast<std::uint16_t>(version.value());
        context.unit_type=unit_type;context.type_unit=type_unit;context.type_die_offset=type_die_offset;
        context.type_signature=type_signature;context.dies=std::move(dies);context.abbrevs=std::move(abbrevs.value());
        const auto context_index=contexts.size();
        for(const auto&die:context.dies){
            if(!die_unit_index.emplace(die.offset,context_index).second)return malformed("duplicate absolute DWARF DIE offset");
        }
        contexts.push_back(std::move(context));
    }
    // Build a bounded dependency order so uniquely indexed target units are
    // resolved before consumers, including targets later in this supplied
    // contribution. Offsets do not identify units in other contributions.
    std::vector<std::set<std::size_t>> dependencies(contexts.size());
    std::vector<unsigned> indegree(contexts.size());
    std::unordered_map<std::uint64_t,std::size_t> signature_units;
    for(std::size_t i=0;i<contexts.size();++i){
        if(contexts[i].type_signature)signature_units.emplace(*contexts[i].type_signature,i);
    }
    for(std::size_t i=0;i<contexts.size();++i){
        for(const auto&die:contexts[i].dies)for(const auto&[attribute,value]:die.attributes){
            (void)attribute;const auto*reference=std::get_if<Reference>(&value);
            if(!reference||reference->supplementary)continue;
            if(reference->signature){
                const auto target=signature_units.find(reference->offset);
                if(target!=signature_units.end()&&target->second!=i&&dependencies[target->second].insert(i).second)++indegree[i];
                continue;
            }
            if(!reference->section_absolute)continue;
            if(reference->offset<sections.info_section_offset || reference->offset-sections.info_section_offset>=sections.info.size())continue;
            const auto local_offset=reference->offset-sections.info_section_offset;
            auto target=die_unit_index.find(local_offset);
            if(target==die_unit_index.end())continue; // normal resolution reports the precise unsupported/malformed case
            if(target->second!=i&&dependencies[target->second].insert(i).second)++indegree[i];
        }
    }
    std::vector<std::size_t> resolution_order;resolution_order.reserve(contexts.size());
    std::set<std::size_t> ready;
    for(std::size_t i=0;i<contexts.size();++i)if(!indegree[i])ready.insert(i);
    while(!ready.empty()){
        const auto i=*ready.begin();ready.erase(ready.begin());resolution_order.push_back(i);
        for(const auto dependent:dependencies[i])if(--indegree[dependent]==0)ready.insert(dependent);
    }
    if(resolution_order.size()!=contexts.size())return unsupported("cyclic cross-unit DWARF reference dependencies, including type-signature dependencies, are unsupported");
    for(const auto context_index:resolution_order){
        if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};
        auto&context=contexts[context_index];
        const auto unit_offset=context.offset,unit_end=static_cast<std::size_t>(context.end);
        const auto as_value=context.address_size;
        const auto version_value=context.version;const auto type_die_offset=context.type_die_offset;
        const auto type_signature=context.type_signature;
        auto&dies=context.dies;auto&abbrev_map=context.abbrevs;
        hexlab::Result<std::unordered_map<std::uint64_t,Abbreviation>> abbrevs(abbrev_map);
        info=Reader(sections.info,unit_end,sections.info.size());
        std::unordered_map<std::uint64_t,std::size_t> by_offset;for(std::size_t i=0;i<dies.size();++i)by_offset.emplace(dies[i].offset,i);
        auto resolve_index=[&](const Reference&r)->hexlab::Result<std::size_t>{std::uint64_t target_offset=r.offset;if(r.section_absolute){if(r.offset<sections.info_section_offset||r.offset-sections.info_section_offset>=sections.info.size())return unsupported("cross-unit reference is outside the supplied DWARF package contribution");target_offset=r.offset-sections.info_section_offset;}else{if(r.offset>UINT64_MAX-unit_offset)return malformed("DWARF DIE reference overflows");target_offset=unit_offset+r.offset;}auto target=by_offset.find(target_offset);if(target!=by_offset.end())return target->second;if(!r.section_absolute)return malformed("DWARF reference does not identify a DIE in this compilation unit");const auto global_target=die_unit_index.find(target_offset);if(global_target==die_unit_index.end())return malformed("DW_FORM_ref_addr points inside the supplied .debug_info section but does not identify a DIE");if(global_target->second!=context_index)return unsupported("DW_FORM_ref_addr identifies a DIE in another compilation unit; this local DIE lookup cannot materialize it");return malformed("DW_FORM_ref_addr global and compilation-unit DIE indexes disagree");};
        // Concrete function DIEs commonly inherit their source-level signature
        // from a declaration through DW_AT_specification or DW_AT_abstract_origin.
        // Keep this lookup local to the owning unit and reject cycles explicitly.
        std::function<hexlab::Result<const Value*>(std::size_t,std::uint64_t,std::set<std::size_t>&)> inherited_attribute;
        inherited_attribute=[&](std::size_t index,std::uint64_t attribute,std::set<std::size_t>&visited)->hexlab::Result<const Value*>{
            if(!visited.insert(index).second)return malformed("cycle in DWARF function declaration references");
            struct VisitGuard{std::set<std::size_t>&visited;std::size_t index;~VisitGuard(){visited.erase(index);}} guard{visited,index};
            const auto&die=dies[index];if(const auto*value=attr(die,attribute))return value;
            for(const auto reference_attribute:{attr_abstract_origin,attr_specification}){
                const auto*reference=ref(die,reference_attribute);if(!reference)continue;
                auto target=resolve_index(*reference);if(!target)return target.error();
                if(dies[target.value()].tag!=tag_subprogram)return malformed("DWARF function declaration reference does not target a subprogram DIE");
                auto value=inherited_attribute(target.value(),attribute,visited);if(!value)return value.error();if(value.value())return value.value();
            }
            return static_cast<const Value*>(nullptr);
        };
        auto function_attribute=[&](std::size_t index,std::uint64_t attribute)->hexlab::Result<const Value*>{std::set<std::size_t> visited;return inherited_attribute(index,attribute,visited);};
        std::function<hexlab::Result<std::size_t>(std::size_t,std::set<std::size_t>&)> parameter_source;
        parameter_source=[&](std::size_t index,std::set<std::size_t>&visited)->hexlab::Result<std::size_t>{
            if(!visited.insert(index).second)return malformed("cycle in DWARF function declaration references");
            struct VisitGuard{std::set<std::size_t>&visited;std::size_t index;~VisitGuard(){visited.erase(index);}} guard{visited,index};
            const auto&die=dies[index];if(std::any_of(die.children.begin(),die.children.end(),[&](auto child){return dies[child].tag==tag_formal_parameter||dies[child].tag==tag_unspecified_parameters;}))return index;
            for(const auto reference_attribute:{attr_abstract_origin,attr_specification}){
                const auto*reference=ref(die,reference_attribute);if(!reference)continue;
                auto target=resolve_index(*reference);if(!target)return target.error();
                if(dies[target.value()].tag!=tag_subprogram)return malformed("DWARF function declaration reference does not target a subprogram DIE");
                auto source=parameter_source(target.value(),visited);if(!source)return source.error();if(source.value()!=index)return source.value();
            }
            return index;
        };
        std::unordered_map<std::uint64_t,types::TypePtr> cache;std::unordered_map<std::uint64_t,unsigned> state;unsigned resolve_depth=0;
        auto enum_value=[&](const Die&e,const types::TypePtr&base)->hexlab::Result<std::int64_t>{const auto*v=attr(e,attr_const_value);if(!v)return malformed("enumerator DIE lacks DW_AT_const_value");std::optional<std::int64_t> value;if(auto*s=std::get_if<std::int64_t>(v))value=*s;else if(auto*u=std::get_if<std::uint64_t>(v)){std::uint64_t raw=*u;auto ab=abbrevs.value().find(e.code);auto spec=std::find_if(ab->second.attributes.begin(),ab->second.attributes.end(),[](const auto&a){return a.name==attr_const_value;});if(spec!=ab->second.attributes.end()&&base->is_signed()){unsigned bytes=spec->form==form_data1?1:spec->form==form_data2?2:spec->form==form_data4?4:spec->form==form_data8?8:0;if(bytes&&bytes<8&&(raw&(std::uint64_t{1}<<(bytes*8-1))))raw|=(~std::uint64_t{0})<<(bytes*8);}if(raw<=std::uint64_t(INT64_MAX))value=static_cast<std::int64_t>(raw);else if(base->is_signed()&&raw>=std::uint64_t(INT64_MIN))value=static_cast<std::int64_t>(raw);}if(!value)return malformed("enumerator constant is outside the supported signed 64-bit range");if(base->size()){const unsigned bits=static_cast<unsigned>(*base->size()*8);if(base->is_signed()&&bits<64){const auto lo=-(std::int64_t{1}<<(bits-1)),hi=(std::int64_t{1}<<(bits-1))-1;if(*value<lo||*value>hi)return malformed("enumerator value does not fit its underlying type");}else if(!base->is_signed()&&*value<0)return malformed("negative enumerator value has an unsigned underlying type");}return *value;};
        std::function<hexlab::Result<types::TypePtr>(std::size_t)> resolve_type;
        std::function<hexlab::Result<types::TypePtr>(const Reference&)> resolve_type_reference;
        std::function<hexlab::Result<std::vector<types::Parameter>>(const Die&)> parameters;
        resolve_type_reference=[&](const Reference&r)->hexlab::Result<types::TypePtr>{if(r.supplementary){if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};if(!sections.supplementary_identity.present)return unsupported("DW_FORM_ref_sup requires a .debug_sup descriptor");if(sections.supplementary_identity.version!=5||sections.supplementary_identity.supplementary)return unsupported("DW_FORM_ref_sup requires an application .debug_sup identity (is_supplementary=0)");if(!sections.supplementary_type_resolver)return unsupported("DW_FORM_ref_sup requires an explicit supplementary type resolver");if(supplementary_requests>=sections.supplementary_resolution_max_requests)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF supplementary reference request limit exceeded"};++supplementary_requests;auto resolved=sections.supplementary_type_resolver(sections.supplementary_identity,r.offset);if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};if(!resolved)return resolved.error();if(!resolved.value().identity_verified||resolved.value().identity!=sections.supplementary_identity)return malformed("supplementary type resolver did not verify the requested object identity/checksum");if(resolved.value().die_offset!=r.offset)return malformed("supplementary type resolver returned a different DIE offset");if(!resolved.value().type)return malformed("supplementary type resolver returned an empty type");auto encoded=types::encode(*resolved.value().type);if(!encoded)return encoded.error();const auto cost=resolved.value().bytes_examined;if(cost>sections.supplementary_resolution_max_bytes-supplementary_bytes_used||encoded.value().size()>sections.supplementary_resolution_max_bytes-supplementary_bytes_used-cost)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF supplementary resolution byte budget exceeded"};supplementary_bytes_used+=cost+encoded.value().size();return resolved.value().type;}if(r.signature){auto found=signature_types.find(r.offset);if(found!=signature_types.end())return found->second;if(!sections.type_signature_resolver)return unsupported("DW_FORM_ref_sig8 has no supported type unit with that signature in the supplied contribution");if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};auto resolved=sections.type_signature_resolver(r.offset);if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};if(!resolved)return resolved.error();if(!resolved.value())return malformed("DW_FORM_ref_sig8 resolver returned an empty type");return resolved.value();}auto target=resolve_index(r);if(!target){if(r.section_absolute){auto external=absolute_type_references.find(r.offset);if(external!=absolute_type_references.end())return external->second;const bool local_info=r.offset>=sections.info_section_offset&&r.offset-sections.info_section_offset<sections.info.size();if(!local_info){auto external_die=resolve_cross_contribution_die(r.offset);if(!external_die)return external_die.error();if(external_die.value()->kind!=DwarfReferencedDieKind::type)return unsupported("DW_FORM_ref_addr type reference targets a non-type DIE in another contribution");return external_die.value()->type;}}return target.error();}return resolve_type(target.value());};
        parameters=[&](const Die&parent)->hexlab::Result<std::vector<types::Parameter>>{std::vector<types::Parameter> out;auto found=by_offset.find(parent.offset);if(found==by_offset.end())return malformed("function DIE is not indexed in its compilation unit");std::set<std::size_t> visited;auto source=parameter_source(found->second,visited);if(!source)return source.error();unsigned index=0;for(auto ci:dies[source.value()].children){const auto&child=dies[ci];if(child.tag==tag_unspecified_parameters)continue;if(child.tag!=tag_formal_parameter)continue;const auto*r=ref(child,attr_type);if(!r)return malformed("formal parameter DIE lacks DW_AT_type");auto ty=resolve_type_reference(*r);if(!ty)return ty.error();const auto*n=str(child,attr_name);out.push_back({n?*n:"arg"+std::to_string(index),ty.value()});++index;}return out;};
        resolve_type=[&](std::size_t ix)->hexlab::Result<types::TypePtr>{if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};const auto&d=dies[ix];if(auto it=cache.find(d.offset);it!=cache.end())return it->second;if(state[d.offset]==1)return unsupported("recursive DWARF type graph cannot be represented by the current immutable type model");if(state[d.offset]==2)return malformed("failed DWARF type resolution");if(resolve_depth>=256)return hexlab::Error{hexlab::ErrorCode::resource_limit,"DWARF type-reference nesting exceeds 256"};++resolve_depth;struct DepthGuard{unsigned&depth;~DepthGuard(){--depth;}} depth_guard{resolve_depth};state[d.offset]=1;
            auto resolve_attr_type=[&](bool required)->hexlab::Result<types::TypePtr>{const auto*r=ref(d,attr_type);if(!r){if(required)return malformed("type DIE lacks DW_AT_type");return types::TypePtr{};}return resolve_type_reference(*r);};
            types::TypePtr result;const auto*name=str(d,attr_name);const auto*size=num(d,attr_byte_size);
            switch(d.tag){
            case tag_base_type:{if(!name||name->empty()||!size||!*size||*size>32)return malformed("base_type DIE lacks a valid name/byte_size");const auto*enc=num(d,attr_encoding);if(!enc)return malformed("base_type DIE lacks DW_AT_encoding");hexlab::Result<types::TypePtr> t=unsupported("unsupported DWARF base-type encoding "+std::to_string(*enc));if(*enc==0x04)t=types::Type::floating(*name,*size,1);else if(*enc==0x02)t=types::Type::boolean(*size,1);else if(*enc==0x05||*enc==0x06)t=types::Type::integer(*name,*size,1,true);else if(*enc==0x07||*enc==0x08)t=types::Type::integer(*name,*size,1,false);else if(*enc==0x01)t=types::Type::pointer(types::Type::void_type(),*size,1);if(!t)return t.error();result=t.value();break;}
            case tag_pointer_type:{auto pointee=resolve_attr_type(false);if(!pointee)return pointee.error();const auto bytes=size?*size:as_value;auto t=types::Type::pointer(pointee.value()?pointee.value():types::Type::void_type(),bytes,std::min<std::uint64_t>(bytes,8));if(!t)return t.error();result=t.value();break;}
            case tag_typedef:case tag_const_type:case tag_volatile_type:{if(d.tag==tag_typedef&&(!name||name->empty()))return malformed("typedef DIE lacks DW_AT_name");auto target=resolve_attr_type(true);if(!target)return target.error();result=target.value();break;}
            case tag_array:{auto element=resolve_attr_type(true);if(!element)return element.error();if(!element.value())return malformed("array element type resolved to void");std::vector<std::uint64_t> dimensions;for(auto ci:d.children)if(dies[ci].tag==tag_subrange_type){const auto&sub=dies[ci];std::optional<std::uint64_t> count;if(auto*c=num(sub,attr_count))count=*c;else {auto lo=signed_num(sub,attr_lower_bound).value_or(0);auto hi=signed_num(sub,attr_upper_bound);if(hi){if(*hi<lo)return malformed("array subrange upper bound precedes lower bound");const auto difference=static_cast<std::uint64_t>(*hi)-static_cast<std::uint64_t>(lo);if(difference==UINT64_MAX)return hexlab::Error{hexlab::ErrorCode::overflow,"array subrange element count overflows"};count=difference+1;}}if(!count||!*count)return unsupported("array subrange has no finite positive element count");dimensions.push_back(*count);}if(dimensions.empty()){if(auto*c=num(d,attr_count);c&&*c)dimensions.push_back(*c);else return unsupported("array type has no supported fixed subrange");}for(auto it=dimensions.rbegin();it!=dimensions.rend();++it){auto a=types::Type::array(element.value(),*it);if(!a)return a.error();element=a.value();}result=element.value();break;}
            case tag_structure_type:case tag_union_type:{
                if(!name||name->empty())return unsupported("anonymous aggregate DIE is unsupported");
                if(num(d,attr_declaration)&&*num(d,attr_declaration))return unsupported("incomplete aggregate declaration has no layout");
                if(!size||!*size)return malformed("aggregate DIE lacks DW_AT_byte_size");
                std::vector<types::Member> members;std::set<std::string> member_names;std::uint64_t align=1;
                std::map<std::string,std::size_t,std::less<>> base_name_counts;
                for(auto ci:d.children){
                    const auto&m=dies[ci];
                    if(m.tag==tag_inheritance){
                        // Preserve statically located, non-virtual base subobjects
                        // as nested aggregate members. The current type model does
                        // not carry DWARF access/virtual-base expression metadata.
                        if(d.tag!=tag_structure_type)continue;
                        if(const auto*virtuality=num(m,attr_virtuality);virtuality&&*virtuality)continue;
                        const auto*base_reference=ref(m,attr_type);
                        if(!base_reference)return malformed("inheritance DIE lacks DW_AT_type");
                        auto base_type=resolve_type_reference(*base_reference);
                        if(!base_type)return base_type.error();
                        const auto*location=attr(m,attr_data_member_location);
                        if(!location)continue;
                        auto base_abbrev=abbrevs.value().find(m.code);
                        if(base_abbrev==abbrevs.value().end())return malformed("inheritance DIE abbreviation is unavailable");
                        auto location_spec=std::find_if(base_abbrev->second.attributes.begin(),base_abbrev->second.attributes.end(),
                            [](const auto&a){return a.name==attr_data_member_location;});
                        if(location_spec==base_abbrev->second.attributes.end())return malformed("inheritance location is absent from its abbreviation");
                        auto base_offset=constant_member_offset(*location,location_spec->form,static_cast<std::uint8_t>(as_value));
                        if(!base_offset)return base_offset.error();
                        const auto &base_type_name=base_type.value()->name();
                        const auto base_label=base_type_name.empty()?std::string("anonymous"):base_type_name;
                        auto &ordinal=base_name_counts[base_label];
                        std::string member_name="$base$"+base_label;
                        if(ordinal)member_name+="#"+std::to_string(ordinal+1);
                        ++ordinal;
                        while(!member_names.insert(member_name).second)member_name+="#";
                        members.push_back({std::move(member_name),base_type.value(),base_offset.value()});
                        align=std::max(align,base_type.value()->alignment());
                        continue;
                    }
                    if(m.tag!=tag_member)continue;
                    const auto*mn=str(m,attr_name);const auto*mr=ref(m,attr_type);
                    if(!mn||mn->empty()||!mr)return malformed("member DIE lacks name or type reference");
                    if(!member_names.insert(*mn).second)return malformed("aggregate contains duplicate member names");
                    auto mt=resolve_type_reference(*mr);if(!mt)return mt.error();
                    std::uint64_t off=0;std::optional<std::uint32_t> bit_width,bit_position;
                    const auto*width=num(m,attr_bit_size);const auto*data_bits=num(m,attr_data_bit_offset);const auto*legacy_bits=num(m,attr_bit_offset);
                    if(width||data_bits||legacy_bits){
                        if(!width||(!data_bits&&!legacy_bits))return unsupported("DWARF bitfield is missing its bit size or bit offset");
                        if(!width||!*width||!mt.value()->size()||*mt.value()->size()>UINT32_MAX/8)
                            return unsupported("DWARF bitfield has an invalid width or unsized storage type");
                        const auto storage_bits=*mt.value()->size()*8;
                        auto base=mt.value();while(base&&base->kind()==types::Kind::qualified)base=base->element();
                        if(!base||(base->kind()!=types::Kind::integer&&base->kind()!=types::Kind::boolean)||*width>storage_bits)
                            return unsupported("DWARF bitfield storage is not a supported integral type");
                        bit_width=static_cast<std::uint32_t>(*width);
                        if(data_bits){
                            off=*data_bits/storage_bits*(*mt.value()->size());
                            bit_position=static_cast<std::uint32_t>(*data_bits%storage_bits);
                        }else{
                            const auto*mv=attr(m,attr_data_member_location);
                            if(d.tag==tag_structure_type){
                                if(!mv)return malformed("legacy DWARF bitfield lacks DW_AT_data_member_location");
                                auto member_abbrev=abbrevs.value().find(m.code);if(member_abbrev==abbrevs.value().end())return malformed("member DIE abbreviation is unavailable");
                                auto member_spec=std::find_if(member_abbrev->second.attributes.begin(),member_abbrev->second.attributes.end(),[](const auto&a){return a.name==attr_data_member_location;});
                                if(member_spec==member_abbrev->second.attributes.end())return malformed("member location attribute is absent from its abbreviation");
                                auto member_offset=constant_member_offset(*mv,member_spec->form,static_cast<std::uint8_t>(as_value));if(!member_offset)return member_offset.error();off=member_offset.value();
                            }
                            if(legacy_bits){
                                if(*legacy_bits>storage_bits||*width>storage_bits-*legacy_bits)return unsupported("legacy DWARF bitfield exceeds its storage unit");
                                bit_position=static_cast<std::uint32_t>(storage_bits-*legacy_bits-*width);
                            }else bit_position=0;
                        }
                        if(*bit_position>storage_bits||*width>storage_bits-*bit_position)return unsupported("DWARF bitfield crosses its modeled storage unit");
                    }else if(d.tag==tag_structure_type){
                        const auto*mv=attr(m,attr_data_member_location);if(!mv)return malformed("structure member lacks DW_AT_data_member_location");
                        auto member_abbrev=abbrevs.value().find(m.code);if(member_abbrev==abbrevs.value().end())return malformed("member DIE abbreviation is unavailable");
                        auto member_spec=std::find_if(member_abbrev->second.attributes.begin(),member_abbrev->second.attributes.end(),[](const auto&a){return a.name==attr_data_member_location;});
                        if(member_spec==member_abbrev->second.attributes.end())return malformed("member location attribute is absent from its abbreviation");
                        auto member_offset=constant_member_offset(*mv,member_spec->form,static_cast<std::uint8_t>(as_value));if(!member_offset)return member_offset.error();off=member_offset.value();
                    }
                    members.push_back({*mn,mt.value(),off,bit_width,bit_position});align=std::max(align,mt.value()->alignment());
                }
                auto t=d.tag==tag_structure_type?types::Type::structure(*name,std::move(members),*size,align):types::Type::union_type(*name,std::move(members),*size,align);
                if(!t)return t.error();result=t.value();break;
            }
            case tag_enumeration:{if(!name||name->empty())return unsupported("anonymous enumeration DIE is unsupported");types::TypePtr base;if(ref(d,attr_type)){auto b=resolve_attr_type(true);if(!b)return b.error();base=b.value();}else {const auto bytes=size?*size:4;auto b=types::Type::integer("enum-underlying",bytes,1,true);if(!b)return b.error();base=b.value();}if(base->kind()!=types::Kind::integer)return malformed("enum underlying type is not an integer");std::vector<std::string> enumerators;for(auto ci:d.children)if(dies[ci].tag==tag_enumerator){const auto&e=dies[ci];const auto*en=str(e,attr_name);auto val=enum_value(e,base);if(!en||!val)return !en?hexlab::Result<types::TypePtr>(malformed("enumerator DIE lacks DW_AT_name")):hexlab::Result<types::TypePtr>(val.error());enumerators.push_back(*en);output.enumerators.push_back({*en,*name,val.value(),origin(sections,unit_offset,e)});}if(enumerators.empty())return unsupported("enumeration DIE contains no supported enumerators");auto t=types::Type::enumeration(*name,base,std::move(enumerators));if(!t)return t.error();result=t.value();break;}
            case tag_subroutine_type:{types::TypePtr ret=types::Type::void_type();if(ref(d,attr_type)){auto r=resolve_attr_type(true);if(!r)return r.error();ret=r.value();}auto ps=parameters(d);if(!ps)return ps.error();bool variadic=std::any_of(d.children.begin(),d.children.end(),[&](auto ci){return dies[ci].tag==tag_unspecified_parameters;});auto t=types::Type::function(ret,std::move(ps.value()),variadic);if(!t)return t.error();result=t.value();break;}
            default:return unsupported("referenced DIE is not a supported type");
            }
            state[d.offset]=2;cache.emplace(d.offset,result);return result;
        };
        // Resolve every recognized, complete type DIE. A declaration DIE may
        // remain intentionally opaque unless another DIE requires its layout.
        for(std::size_t i=0;i<dies.size();++i){if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};if(is_type_tag(dies[i].tag)){
            if((dies[i].tag==tag_structure_type||dies[i].tag==tag_union_type)&&num(dies[i],attr_declaration)&&*num(dies[i],attr_declaration))continue;
            auto t=resolve_type(i);if(!t)return t.error();const auto&d=dies[i];const auto*n=str(d,attr_name);ImportedType it;it.type=t.value();it.origin=origin(sections,unit_offset,d);it.alignment_is_inferred=true;it.source_name=n?*n:t.value()->name();it.is_typedef=d.tag==tag_typedef;it.is_const=d.tag==tag_const_type;it.is_volatile=d.tag==tag_volatile_type;output.types.push_back(std::move(it));
        }}
        // Preserve complete declaration signatures from earlier compilation
        // units so later DW_FORM_ref_addr specification/origin edges can reuse
        // their already-resolved types and parameter locations. When a
        // declaration itself inherits its signature from an earlier unit,
        // carry that summary forward as well; this resolves chained
        // cross-CU declaration/origin edges without retaining unbounded DIE
        // graphs across units.
        for(std::size_t i=0;i<dies.size();++i){
            const auto&die=dies[i];
            if(die.tag!=tag_subprogram)continue;
            const PriorFunctionSignature*prior=nullptr;
            for(const auto reference_attribute:{attr_abstract_origin,attr_specification}){
                const auto*reference=ref(die,reference_attribute);
                if(!reference)continue;
                std::uint64_t target_offset=reference->offset;
                if(!reference->section_absolute){
                    if(reference->offset>UINT64_MAX-unit_offset)continue;
                    const auto relative_target=unit_offset+reference->offset;
                    if(relative_target>UINT64_MAX-sections.info_section_offset)continue;
                    target_offset=sections.info_section_offset+relative_target;
                }
                const auto found=prior_function_signatures.find(target_offset);
                if(found!=prior_function_signatures.end()){prior=&found->second;break;}
            }
            std::optional<std::string> name;
            auto name_value=function_attribute(i,attr_name);
            if(name_value&&name_value.value()){
                if(const auto*value=std::get_if<std::string>(name_value.value()))name=*value;
                else return malformed("inherited DW_AT_name is not a string");
            }
            if((!name||name->empty())&&prior)name=prior->name;
            if(!name||name->empty())continue;
            PriorFunctionSignature signature;
            signature.name=*name;
            signature.return_type=types::Type::void_type();
            bool return_resolved=false;
            if(const auto*return_reference=ref(die,attr_type)){
                auto resolved_type=resolve_type_reference(*return_reference);
                if(!resolved_type)continue;
                signature.return_type=resolved_type.value();
                return_resolved=true;
            }else{
                auto type_value=function_attribute(i,attr_type);
                if(type_value&&type_value.value()){
                    const auto*inherited_return_reference=std::get_if<Reference>(type_value.value());
                    if(!inherited_return_reference)return malformed("inherited DW_AT_type is not a DIE reference");
                    auto resolved_type=resolve_type_reference(*inherited_return_reference);
                    if(!resolved_type)continue;
                    signature.return_type=resolved_type.value();
                    return_resolved=true;
                }else if(!type_value&&prior){
                    signature.return_type=prior->return_type;
                    return_resolved=true;
                }else if(type_value){
                    // No DW_AT_type on the complete declaration means void.
                    return_resolved=true;
                }else continue;
            }
            const bool has_parameters=std::any_of(die.children.begin(),die.children.end(),[&](auto child){
                return dies[child].tag==tag_formal_parameter||dies[child].tag==tag_unspecified_parameters;
            });
            if(has_parameters){
                auto resolved_parameters=parameters(die);
                if(!resolved_parameters)continue;
                signature.parameters=std::move(resolved_parameters.value());
                signature.variadic=std::any_of(die.children.begin(),die.children.end(),[&](auto child){
                    return dies[child].tag==tag_unspecified_parameters;
                });
            }else if(prior){
                signature.parameters=prior->parameters;
                signature.variadic=prior->variadic;
            }else{
                auto resolved_parameters=parameters(die);
                if(!resolved_parameters)continue;
                signature.parameters=std::move(resolved_parameters.value());
            }
            if(return_resolved)
                prior_function_signatures.emplace(sections.info_section_offset+die.offset,std::move(signature));
        }
        for(const auto&[offset,type]:cache)absolute_type_references.emplace(sections.info_section_offset+offset,type);
        if(type_signature){const auto target_offset=unit_offset+*type_die_offset;auto target=by_offset.find(target_offset);if(target==by_offset.end())return malformed("DWARF type-unit target DIE is not indexed");auto target_type=resolve_type(target->second);if(!target_type)return target_type.error();signature_types.emplace(*type_signature,target_type.value());}
        auto parent_function_index=[&](std::size_t i)->std::optional<std::size_t>{auto p=dies[i].parent;while(p){if(dies[*p].tag==tag_subprogram)return *p;p=dies[*p].parent;}return {};};
        for(std::size_t i=0;i<dies.size();++i){if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};const auto&d=dies[i];
            if(d.tag==tag_variable||d.tag==tag_formal_parameter){
                const auto scope_index=parent_function_index(i);const auto scope=scope_index?dies[*scope_index].offset:0;
                if(d.tag==tag_formal_parameter&&!scope_index)continue;
                const auto*n=str(d,attr_name);const auto*r=ref(d,attr_type);if(!n||!r)continue;
                auto ty=resolve_type_reference(*r);if(!ty)return ty.error();
                ImportedVariable v;v.name=*n;v.type=ty.value();v.is_parameter=d.tag==tag_formal_parameter;v.scope_offset=scope;v.origin=origin(sections,unit_offset,d);
                if(const auto*loc=attr(d,attr_location)){
                    auto ab=abbrevs.value().find(d.code);
                    auto spec=std::find_if(ab->second.attributes.begin(),ab->second.attributes.end(),[](const auto&a){return a.name==attr_location;});
                    if(spec==ab->second.attributes.end())return malformed("variable location attribute is absent from its abbreviation");
                    if(spec->form==form_addr){
                        auto*a=std::get_if<std::uint64_t>(loc);if(!a)return malformed("address-form variable location is not numeric");v.address=*a;
                    }else if(spec->form==form_exprloc||spec->form==form_block||spec->form==form_block1||spec->form==form_block2||spec->form==form_block4){
                        auto*b=std::get_if<Blob>(loc);if(!b)return malformed("block-form variable location is not an expression");
                        v.location_expression=*b;auto decoded=decode_location_expression(*b,static_cast<std::uint8_t>(as_value));if(!decoded)return decoded.error();v.location_operations=std::move(decoded.value());
                        if(scope_index){
                            const auto&function=dies[*scope_index];
                            if(const auto*frame_attr=attr(function,attr_frame_base)){
                                const auto function_abbrev=abbrevs.value().find(function.code);
                                const auto frame_spec=std::find_if(function_abbrev->second.attributes.begin(),function_abbrev->second.attributes.end(),[](const auto&a){return a.name==attr_frame_base;});
                                if(frame_spec!=function_abbrev->second.attributes.end()&&(frame_spec->form==form_exprloc||frame_spec->form==form_block||frame_spec->form==form_block1||frame_spec->form==form_block2||frame_spec->form==form_block4)){
                                    if(const auto*frame_bytes=std::get_if<Blob>(frame_attr)){
                                        auto frame_ops=decode_location_expression(*frame_bytes,static_cast<std::uint8_t>(as_value));if(!frame_ops)return frame_ops.error();
                                        v.cfa_offset=cfa_relative_offset(v.location_operations,frame_ops.value());
                                    }
                                }
                            }
                        }
                    }else if(version_value==5&&(spec->form==form_sec_offset||spec->form==form_loclistx)){
                        if(sections.location_lists.empty())return unsupported("DWARF v5 variable location list requires .debug_loclists");
                        std::uint64_t list_offset=0;
                        if(spec->form==form_sec_offset){
                            const auto*value=std::get_if<std::uint64_t>(loc);if(!value)return malformed("DW_FORM_sec_offset location-list value is not numeric");list_offset=*value;
                        }else{
                            const auto*indexed=std::get_if<IndexedForm>(loc);if(!indexed||!indexed->location_list)return malformed("DW_FORM_loclistx value is not an index");
                            const auto*base=num(dies.front(),attr_loclists_base);if(!base)return unsupported("DW_FORM_loclistx requires DW_AT_loclists_base");
                            auto resolved=resolve_loclistx(sections.location_lists,*base,indexed->index,static_cast<std::uint8_t>(as_value));if(!resolved)return resolved.error();list_offset=resolved.value();
                        }
                        const auto*addr_base=num(dies.front(),attr_addr_base);
                        auto ranges=decode_location_list(sections.location_lists,list_offset,static_cast<std::uint8_t>(as_value),[&](std::uint64_t index)->hexlab::Result<std::uint64_t>{if(!addr_base)return unsupported("indexed DWARF v5 location-list entries require DW_AT_addr_base");return resolve_addrx(sections.addresses,*addr_base,index,static_cast<std::uint8_t>(as_value));});if(!ranges)return ranges.error();v.location_ranges=std::move(ranges.value());
                    }else if(version_value<=4&&spec->form==form_sec_offset){
                        if(sections.locations.empty())return unsupported("DWARF v2-v4 variable location list requires .debug_loc");
                        const auto*value=std::get_if<std::uint64_t>(loc);if(!value)return malformed("DW_FORM_sec_offset location-list value is not numeric");
                        auto ranges=decode_legacy_location_list(sections.locations,*value,static_cast<std::uint8_t>(as_value),num(dies.front(),attr_low_pc)?std::optional<std::uint64_t>(*num(dies.front(),attr_low_pc)):std::nullopt);if(!ranges)return ranges.error();v.location_ranges=std::move(ranges.value());
                    }else return unsupported("variable location form is not a direct address, expression block, or supported DWARF v5 location list");
                }
                output.variables.push_back(std::move(v));
            }
            if(d.tag==tag_subprogram){
                const auto*low=num(d,attr_low_pc);const auto*high=num(d,attr_high_pc);
                auto function_ranges=std::vector<ImportedSymbol::Range>{};
                if(const auto*ranges_value=attr(d,attr_ranges)){
                    if(version_value!=5)return unsupported("DW_AT_ranges is currently supported only with DWARF v5 .debug_rnglists");
                    if(sections.range_lists.empty())return unsupported("DW_AT_ranges requires the matching .debug_rnglists contribution");
                    auto ab=abbrevs.value().find(d.code);if(ab==abbrevs.value().end())return malformed("DW_AT_ranges abbreviation is absent");
                    auto spec=std::find_if(ab->second.attributes.begin(),ab->second.attributes.end(),[](const auto&a){return a.name==attr_ranges;});
                    if(spec==ab->second.attributes.end())return malformed("DW_AT_ranges has no abbreviation form");
                    std::uint64_t list_offset=0;
                    if(spec->form==form_sec_offset){
                        const auto*offset=std::get_if<std::uint64_t>(ranges_value);if(!offset)return malformed("DW_FORM_sec_offset DW_AT_ranges value is not numeric");list_offset=*offset;
                    }else if(spec->form==form_rnglistx){
                        const auto*indexed=std::get_if<IndexedForm>(ranges_value);if(!indexed||!indexed->range_list)return malformed("DW_FORM_rnglistx DW_AT_ranges value is not an index");
                        const auto*base=num(dies.front(),attr_rnglists_base);if(!base)return unsupported("DW_FORM_rnglistx requires DW_AT_rnglists_base");
                        auto resolved=resolve_rnglistx(sections.range_lists,*base,indexed->index,static_cast<std::uint8_t>(as_value));if(!resolved)return resolved.error();list_offset=resolved.value();
                    }else return unsupported("DW_AT_ranges form is not a supported DW_FORM_sec_offset or DW_FORM_rnglistx");
                    const auto*addr_base=num(dies.front(),attr_addr_base);
                    auto decoded=decode_range_list(sections.range_lists,list_offset,static_cast<std::uint8_t>(as_value),low?std::optional<std::uint64_t>(*low):std::nullopt,
                        [&](std::uint64_t index)->hexlab::Result<std::uint64_t>{if(!addr_base)return unsupported("indexed DWARF range-list entries require DW_AT_addr_base");return resolve_addrx(sections.addresses,*addr_base,index,static_cast<std::uint8_t>(as_value));});
                    if(!decoded)return decoded.error();function_ranges=std::move(decoded.value());
                }else if(low&&high){
                    auto ab=abbrevs.value().find(d.code);auto hf=std::find_if(ab->second.attributes.begin(),ab->second.attributes.end(),[](const auto&a){return a.name==attr_high_pc;});if(hf==ab->second.attributes.end())continue;
                    std::uint64_t end=*high;if(hf->form!=form_addr){if(*high>UINT64_MAX-*low)return malformed("subprogram range overflows");end=*low+*high;}if(end<=*low)continue;
                    function_ranges.push_back({*low,end});
                }else continue;
                if(function_ranges.empty())continue;
                const PriorFunctionSignature*prior=nullptr;
                for(const auto reference_attribute:{attr_abstract_origin,attr_specification}){
                    const auto*reference=ref(d,reference_attribute);
                    if(!reference||!reference->section_absolute)continue;
                    const bool in_local_info=reference->offset>=sections.info_section_offset&&reference->offset-sections.info_section_offset<sections.info.size();
                    if(!in_local_info&&!prior_function_signatures.contains(reference->offset)){
                        auto external_die=resolve_cross_contribution_die(reference->offset);
                        if(!external_die)return external_die.error();
                        if(external_die.value()->kind!=DwarfReferencedDieKind::subprogram)return malformed("cross-contribution DW_AT_specification or DW_AT_abstract_origin does not target a subprogram DIE");
                        PriorFunctionSignature summary;
                        summary.name=external_die.value()->name;
                        summary.return_type=external_die.value()->type->result_type()?external_die.value()->type->result_type():types::Type::void_type();
                        summary.parameters=external_die.value()->type->parameters();
                        summary.variadic=external_die.value()->type->variadic();
                        prior_function_signatures.emplace(reference->offset,std::move(summary));
                    }
                    auto found=prior_function_signatures.find(reference->offset);
                    if(found!=prior_function_signatures.end()){prior=&found->second;break;}
                }
                auto name_value=function_attribute(i,attr_name);
                if(!name_value&&!prior)return name_value.error();
                const auto*n=name_value&&name_value.value()?std::get_if<std::string>(name_value.value()):nullptr;
                if((!n||n->empty())&&prior)n=&prior->name;
                if(!n||n->empty())continue;
                types::TypePtr ret=types::Type::void_type();
                auto type_value=function_attribute(i,attr_type);
                if(!type_value&&!prior)return type_value.error();
                if(type_value&&type_value.value()){
                    const auto*r=std::get_if<Reference>(type_value.value());
                    if(!r)return malformed("inherited DW_AT_type is not a DIE reference");
                    auto ty=resolve_type_reference(*r);if(!ty)return ty.error();ret=ty.value();
                }else if(prior)ret=prior->return_type;
                const bool has_parameter_children=std::any_of(d.children.begin(),d.children.end(),[&](auto child){
                    return dies[child].tag==tag_formal_parameter||dies[child].tag==tag_unspecified_parameters;
                });
                std::vector<types::Parameter> resolved_parameters;
                bool variadic=false;
                if(has_parameter_children||!prior){
                    auto ps=parameters(d);if(!ps)return ps.error();resolved_parameters=std::move(ps.value());
                    variadic=std::any_of(d.children.begin(),d.children.end(),[&](auto child){return dies[child].tag==tag_unspecified_parameters;});
                }else{resolved_parameters=prior->parameters;variadic=prior->variadic;}
                auto fn=types::Type::function(ret,std::move(resolved_parameters),variadic);if(!fn)return fn.error();
                ImportedSymbol imported{*n,SymbolKind::function,function_ranges.front().begin,
                    function_ranges.front().end-function_ranges.front().begin,origin(sections,unit_offset,d),fn.value()};
                imported.ranges=std::move(function_ranges);
                output.symbols.push_back(std::move(imported));
            }
        }
    }
    if(sections.expected_split_dwo_id && (!output.split_unit || output.split_dwo_id!=sections.expected_split_dwo_id))
        return malformed("DWARF split contribution does not contain the requested DWO ID");
    if(!pending_split_units.empty()){
        if(!sections.split_unit_resolver){
            for(const auto &request:pending_split_units)
                output.diagnostics.push_back("DWO "+request.dwo_name+" (ID "+std::to_string(request.dwo_id)+") was not loaded because no split-unit resolver is configured");
        }else for(const auto &request:pending_split_units){
            if(canceled())return hexlab::Error{hexlab::ErrorCode::canceled,"DWARF import canceled"};
            auto resolved=sections.split_unit_resolver(request);
            if(!resolved){
                if(resolved.error().code==hexlab::ErrorCode::io||resolved.error().code==hexlab::ErrorCode::out_of_bounds||resolved.error().code==hexlab::ErrorCode::unsupported){
                    output.diagnostics.push_back("DWO "+request.dwo_name+" (ID "+std::to_string(request.dwo_id)+") unavailable: "+resolved.error().message);
                    continue;
                }
                return resolved.error();
            }
            if(!resolved.value())return malformed("DWARF split-unit resolver returned a null result");
            auto &split=*resolved.value();
            if(!split.split_unit||split.split_dwo_id!=request.dwo_id)
                return malformed("DWARF split-unit resolver returned a mismatched DWO ID");
            const auto merged_count=std::uint64_t{output.symbols.size()}+output.types.size()+output.variables.size()+output.enumerators.size()+
                split.symbols.size()+split.types.size()+split.variables.size()+split.enumerators.size();
            if(merged_count>2'000'000)return hexlab::Error{hexlab::ErrorCode::resource_limit,"Merged DWARF records exceed importer limit"};
            output.symbols.insert(output.symbols.end(),std::make_move_iterator(split.symbols.begin()),std::make_move_iterator(split.symbols.end()));
            output.types.insert(output.types.end(),std::make_move_iterator(split.types.begin()),std::make_move_iterator(split.types.end()));
            output.variables.insert(output.variables.end(),std::make_move_iterator(split.variables.begin()),std::make_move_iterator(split.variables.end()));
            output.enumerators.insert(output.enumerators.end(),std::make_move_iterator(split.enumerators.begin()),std::make_move_iterator(split.enumerators.end()));
            output.diagnostics.insert(output.diagnostics.end(),std::make_move_iterator(split.diagnostics.begin()),std::make_move_iterator(split.diagnostics.end()));
        }
    }
    return output;
}

hexlab::Result<ImportResult> import_dwarf_v4(const DwarfV4Sections &sections) {
    DwarfSections bounded;
    bounded.source_id = sections.source_id;
    bounded.info = sections.info;
    bounded.abbrev = sections.abbrev;
    bounded.strings = sections.strings;
    bounded.stop = sections.stop;
    bounded.locations = sections.locations;
    return import_dwarf(bounded);
}
} // namespace hexlab::symbols
