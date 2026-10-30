#include "hexlab/types/types.hpp"
#include <algorithm>
#include <functional>
#include <limits>
#include <sstream>
#include <string_view>
#include <unordered_set>

namespace hexlab::types {
namespace {
constexpr std::size_t max_type_record_size = 16 * 1024 * 1024;
constexpr std::size_t max_type_text_size = 65536;
constexpr std::size_t max_type_collection_items = 100000;
constexpr unsigned max_type_nesting = 128;
hexlab::Error invalid(std::string message) { return {hexlab::ErrorCode::invalid_argument, std::move(message)}; }
struct TypeWriter {
    std::vector<std::byte> bytes;
    void number(std::uint64_t value, std::size_t n) { if (bytes.size() > max_type_record_size || n > max_type_record_size - bytes.size()) throw std::length_error("type record exceeds limit"); for (std::size_t i=0;i<n;++i) bytes.push_back(std::byte(value>>(8*(n-i-1)))); }
    void count(std::size_t value) { if (value > max_type_collection_items) throw std::length_error("type collection exceeds limit"); number(value, 4); }
    void text(std::string_view value) { if (value.size() > max_type_text_size) throw std::length_error("type text exceeds limit"); if (bytes.size() > max_type_record_size - 4 || value.size() > max_type_record_size - bytes.size() - 4) throw std::length_error("type record exceeds limit"); number(value.size(),4); auto data=std::as_bytes(std::span(value)); bytes.insert(bytes.end(),data.begin(),data.end()); }
};
struct TypeReader {
    std::span<const std::byte> bytes; std::size_t cursor=0;
    std::uint64_t number(std::size_t n) { if (cursor > bytes.size() || n > bytes.size() - cursor) throw std::runtime_error("truncated type record"); std::uint64_t v=0; while(n--) v=(v<<8)|std::to_integer<unsigned>(bytes[cursor++]); return v; }
    std::string text() { auto n=number(4); if(n>max_type_text_size || n>bytes.size()-cursor) throw std::runtime_error("invalid type text extent"); std::string v(reinterpret_cast<const char*>(bytes.data()+cursor),static_cast<std::size_t>(n)); cursor+=static_cast<std::size_t>(n); return v; }
};
void write_type(TypeWriter& out,const Type& t,unsigned depth,std::uint8_t version) {
    if(depth>max_type_nesting) throw std::length_error("type nesting exceeds limit");
    out.number(static_cast<unsigned>(t.kind()),1); out.text(t.name()); out.number(t.size().value_or(UINT64_MAX),8); out.number(t.alignment(),8); out.number(t.is_signed(),1); out.number(t.count(),8);
    switch(t.kind()) {
    case Kind::void_type: break;
    case Kind::boolean: case Kind::integer: case Kind::floating: break;
    case Kind::named_reference: break;
    case Kind::pointer: case Kind::vector: write_type(out,*t.element(),depth+1,version); break;
    case Kind::array: if(version>=19)out.number(t.array_stride(),8);write_type(out,*t.element(),depth+1,version); break;
    case Kind::enumeration:
        write_type(out,*t.element(),depth+1,version);
        out.count(t.enumerators().size());
        if (version == 1) { for (const auto& v : t.enumerators()) out.text(v); }
        else for (const auto& v : t.enumerator_values()) { out.text(v.name); out.number(v.value,8); }
        break;
    case Kind::structure: case Kind::union_type: if(version>=10)out.number(t.size().has_value(),1);if(version>=6){out.number(t.packing_alignment().has_value(),1);if(t.packing_alignment())out.number(*t.packing_alignment(),8);}out.count(t.members().size());for(auto& m:t.members()){out.text(m.name);out.number(m.offset,8);if(version>=3){out.number(m.bit_width.has_value(),1);if(m.bit_width){out.number(*m.bit_width,4);out.number(*m.bit_offset,4);}}if(version>=4){out.number(m.effective_alignment.has_value(),1);if(m.effective_alignment)out.number(*m.effective_alignment,8);}if(version>=9){out.number(m.virtual_base.has_value(),1);if(m.virtual_base){out.number(m.virtual_base->vbptr_offset,8);out.number(m.virtual_base->vbtable_index,8);out.number(m.virtual_base->indirect,1);write_type(out,*m.virtual_base->vbptr_type,depth+1,version);}}if(version>=15)out.number(static_cast<unsigned>(m.access),1);if(version>=18)out.number(m.anonymous,1);write_type(out,*m.type,depth+1,version);}if(version>=11){out.count(t.methods().size());for(const auto& m:t.methods()){out.text(m.name);out.number(static_cast<unsigned>(m.access),1);out.number(static_cast<unsigned>(m.dispatch),1);out.number(m.source_attributes,2);out.number(m.is_static,1);out.number(m.introducing_vtable_offset.has_value(),1);if(m.introducing_vtable_offset)out.number(*m.introducing_vtable_offset,4);out.number(static_cast<std::uint32_t>(m.this_adjustment),4);out.number(m.function_options,1);out.number(m.declaration_ordinal,4);out.number(m.signature!=nullptr,1);if(m.signature)write_type(out,*m.signature,depth+1,version);out.number(m.this_type!=nullptr,1);if(m.this_type)write_type(out,*m.this_type,depth+1,version);if(version>=12){out.count(m.vtable_slots.size());for(const auto& slot:m.vtable_slots){out.number(slot.vfptr_offset,4);out.number(slot.slot_index,4);out.text(slot.table_name);out.text(slot.method_name);out.number(slot.source_namespace,1);out.number(slot.source_type_index,4);out.number(slot.source_record_offset,4);}}}}if(version>=13){out.count(t.static_data_members().size());for(const auto& member:t.static_data_members()){out.text(member.name);out.number(static_cast<unsigned>(member.access),1);out.number(member.source_attributes,2);out.number(member.declaration_ordinal,4);write_type(out,*member.type,depth+1,version);}}break;
    case Kind::function: if(version>=7)out.number(static_cast<std::uint8_t>(t.function_convention()),1);write_type(out,*t.result_type(),depth+1,version);out.count(t.parameters().size());for(auto& p:t.parameters()){out.text(p.name);write_type(out,*p.type,depth+1,version);}out.number(t.variadic(),1);break;
    case Kind::qualified: if(version<8)throw std::runtime_error("qualified type requires type record version 8");if(version<17&&(t.qualifiers()&static_cast<std::uint8_t>(Qualifier::atomic_)))throw std::runtime_error("atomic qualification requires type record version 17");out.number(t.qualifiers(),1);write_type(out,*t.element(),depth+1,version);break;
    }
}
TypePtr read_type(TypeReader& in,unsigned depth,std::uint8_t version) {
    if(depth>max_type_nesting) throw std::runtime_error("type nesting exceeds limit");
    auto kind=static_cast<Kind>(in.number(1));auto name=in.text();auto size=in.number(8),align=in.number(8),sign=in.number(1),count=in.number(8);
    if(kind==Kind::void_type)return Type::void_type();
    if(kind==Kind::named_reference)return Type::named_reference(std::move(name)).value();
    if(kind==Kind::boolean)return Type::boolean(size,align).value();
    if(kind==Kind::integer)return Type::integer(std::move(name),size,align,sign!=0).value();
    if(kind==Kind::floating)return Type::floating(std::move(name),size,align).value();
    if(kind==Kind::pointer)return Type::pointer(read_type(in,depth+1,version),size,align).value();
    if(kind==Kind::array){
        if(version>=19){
            const auto stride=in.number(8);
            auto element=read_type(in,depth+1,version);
            // A zero count represents an incomplete array. It is valid only
            // with the natural element stride; padded arrays need a count to
            // define their occupied extent.
            if(count==0){
                if(!element->size() || stride!=*element->size())
                    throw std::runtime_error("incomplete array has an invalid stride");
                return Type::array(std::move(element),0).value();
            }
            return Type::strided_array(std::move(element),count,stride).value();
        }
        return Type::array(read_type(in,depth+1,version),count).value();
    }
    if(kind==Kind::vector){if(version<5)throw std::runtime_error("vector type requires type record version 5");return Type::vector(read_type(in,depth+1,version),count,align).value();}
    if(kind==Kind::enumeration){auto base=read_type(in,depth+1,version);auto n=in.number(4);if(n>max_type_collection_items)throw std::runtime_error("too many enumerators");if(version==1){std::vector<std::string> values;while(n--)values.push_back(in.text());return Type::enumeration(std::move(name),std::move(base),std::move(values)).value();}std::vector<Enumerator> values;while(n--)values.push_back({in.text(),in.number(8)});return Type::enumeration_with_values(std::move(name),std::move(base),std::move(values)).value();}
    if(kind==Kind::structure||kind==Kind::union_type){const auto has_size=version>=10?in.number(1):1;if(has_size>1)throw std::runtime_error("invalid aggregate completeness flag");if(version>=10&&((has_size==0)!=(size==UINT64_MAX)))throw std::runtime_error("aggregate completeness flag disagrees with its size");std::optional<std::uint64_t> packing_alignment;if(version>=6){const auto has_pack=in.number(1);if(has_pack>1)throw std::runtime_error("invalid aggregate packing flag");if(has_pack)packing_alignment=in.number(8);}auto n=in.number(4);if(n>max_type_collection_items)throw std::runtime_error("too many members");std::vector<Member> members;while(n--){auto member=in.text();auto offset=in.number(8);std::optional<std::uint32_t> width,bit_offset;std::optional<std::uint64_t> effective_alignment;if(version>=3){const auto has_bits=in.number(1);if(has_bits>1)throw std::runtime_error("invalid bitfield flag");if(has_bits){width=static_cast<std::uint32_t>(in.number(4));bit_offset=static_cast<std::uint32_t>(in.number(4));}}if(version>=4){const auto has_alignment=in.number(1);if(has_alignment>1)throw std::runtime_error("invalid effective alignment flag");if(has_alignment)effective_alignment=in.number(8);}std::optional<Member::VirtualBaseLocation> virtual_base;if(version>=9){const auto has_virtual_base=in.number(1);if(has_virtual_base>1)throw std::runtime_error("invalid virtual-base flag");if(has_virtual_base){auto vbptr_offset=in.number(8),vbtable_index=in.number(8),indirect=in.number(1);if(indirect>1)throw std::runtime_error("invalid indirect virtual-base flag");virtual_base=Member::VirtualBaseLocation{read_type(in,depth+1,version),vbptr_offset,vbtable_index,indirect!=0};}}MemberAccess access=MemberAccess::unknown;if(version>=15){const auto encoded_access=in.number(1);if(encoded_access>static_cast<unsigned>(MemberAccess::public_))throw std::runtime_error("invalid member access");access=static_cast<MemberAccess>(encoded_access);}bool anonymous=false;if(version>=18){const auto flag=in.number(1);if(flag>1)throw std::runtime_error("invalid anonymous member flag");anonymous=flag!=0;}members.push_back({std::move(member),read_type(in,depth+1,version),offset,width,bit_offset,effective_alignment,std::move(virtual_base),access,anonymous});}std::vector<Method> methods;if(version>=11){auto count=in.number(4);if(count>max_type_collection_items)throw std::runtime_error("too many methods");while(count--){Method m;m.name=in.text();auto access=in.number(1),dispatch=in.number(1);if(access>static_cast<unsigned>(MemberAccess::public_)||dispatch>static_cast<unsigned>(MemberDispatch::unknown))throw std::runtime_error("invalid method access or dispatch");m.access=static_cast<MemberAccess>(access);m.dispatch=static_cast<MemberDispatch>(dispatch);m.source_attributes=static_cast<std::uint16_t>(in.number(2));auto is_static=in.number(1),has_slot=in.number(1);if(is_static>1||has_slot>1)throw std::runtime_error("invalid method flag");m.is_static=is_static!=0;if(has_slot)m.introducing_vtable_offset=static_cast<std::uint32_t>(in.number(4));m.this_adjustment=static_cast<std::int32_t>(in.number(4));m.function_options=static_cast<std::uint8_t>(in.number(1));m.declaration_ordinal=static_cast<std::uint32_t>(in.number(4));auto has_signature=in.number(1);if(has_signature>1)throw std::runtime_error("invalid method signature flag");if(has_signature)m.signature=read_type(in,depth+1,version);auto has_this=in.number(1);if(has_this>1)throw std::runtime_error("invalid method this flag");if(has_this)m.this_type=read_type(in,depth+1,version);if(version>=12){auto slot_count=in.number(4);if(slot_count>max_type_collection_items)throw std::runtime_error("too many virtual-table slots");while(slot_count--){VTableSlot slot;slot.vfptr_offset=static_cast<std::uint32_t>(in.number(4));slot.slot_index=static_cast<std::uint32_t>(in.number(4));slot.table_name=in.text();slot.method_name=in.text();slot.source_namespace=static_cast<std::uint8_t>(in.number(1));slot.source_type_index=static_cast<std::uint32_t>(in.number(4));slot.source_record_offset=static_cast<std::uint32_t>(in.number(4));m.vtable_slots.push_back(std::move(slot));}}methods.push_back(std::move(m));}}std::vector<StaticDataMember> static_data_members;if(version>=13){auto count=in.number(4);if(count>max_type_collection_items)throw std::runtime_error("too many static data members");while(count--){StaticDataMember member;member.name=in.text();auto access=in.number(1);if(access>static_cast<unsigned>(MemberAccess::public_))throw std::runtime_error("invalid static data access");member.access=static_cast<MemberAccess>(access);member.source_attributes=static_cast<std::uint16_t>(in.number(2));member.declaration_ordinal=static_cast<std::uint32_t>(in.number(4));member.type=read_type(in,depth+1,version);static_data_members.push_back(std::move(member));}}TypePtr aggregate;if(!has_size){if(!members.empty()||packing_alignment)throw std::runtime_error("incomplete aggregate has layout metadata");aggregate=Type::incomplete_aggregate(kind,std::move(name)).value();}else aggregate=(kind==Kind::structure?Type::structure(std::move(name),std::move(members),size,align,packing_alignment):Type::union_type(std::move(name),std::move(members),size,align,packing_alignment)).value();if(!methods.empty())aggregate=Type::with_methods(std::move(aggregate),std::move(methods)).value();if(!static_data_members.empty())aggregate=Type::with_static_data_members(std::move(aggregate),std::move(static_data_members)).value();return aggregate;}
    if(kind==Kind::function){auto convention=version>=7?in.number(1):0;if(convention>static_cast<std::uint8_t>(FunctionConvention::aapcs32_vfp)|| (convention==static_cast<std::uint8_t>(FunctionConvention::mips_n32)&&version<14)||(convention==static_cast<std::uint8_t>(FunctionConvention::aapcs32_vfp)&&version<16))throw std::runtime_error("invalid function calling convention");auto result=read_type(in,depth+1,version);auto n=in.number(4);if(n>max_type_collection_items)throw std::runtime_error("too many parameters");std::vector<Parameter> params;while(n--)params.push_back({in.text(),read_type(in,depth+1,version)});auto variadic=in.number(1);if(variadic>1)throw std::runtime_error("invalid variadic flag");return Type::function(std::move(result),std::move(params),variadic!=0,static_cast<FunctionConvention>(convention)).value();}
    if(kind==Kind::qualified){if(version<8)throw std::runtime_error("qualified type requires type record version 8");const auto qualifiers=in.number(1);if(version<17&&(qualifiers&static_cast<std::uint8_t>(Qualifier::atomic_)))throw std::runtime_error("atomic qualification requires type record version 17");return Type::qualified(read_type(in,depth+1,version),static_cast<std::uint8_t>(qualifiers)).value();}
    throw std::runtime_error("unknown type kind");
}
std::uint64_t hash(std::string_view text) {
    std::uint64_t value = 14695981039346656037ULL;
    for (unsigned char c : text) {
        value ^= c;
        value *= 1099511628211ULL;
    }
    return value ? value : 1;
}
bool valid_layout(std::uint64_t size, std::uint64_t alignment) {
    return size > 0 && alignment > 0 && (alignment & (alignment - 1)) == 0;
}
const Type *unqualified(const Type *type) {
    while (type && type->kind() == Kind::qualified) type = type->element().get();
    return type;
}
void append_text(std::ostringstream &out, std::string_view value) { out << value.size() << ':' << value; }
std::string canonical(const Type &type, std::unordered_set<const Type *> &active) {
    if (!active.insert(&type).second)
        return "<recursive>";
    std::ostringstream out;
    out << static_cast<int>(type.kind()) << ':';
    append_text(out, type.name());
    out << ':' << type.size().value_or(UINT64_MAX) << ':' << type.alignment() << ':' << type.packing_alignment().value_or(0) << ':' << type.is_signed() << ':'
        << type.count() << ':' << type.array_stride() << ':';
    if (!type.size() && (type.kind() == Kind::structure || type.kind() == Kind::union_type))
        out << "incomplete:";
    if (type.qualifiers()) out << 'q' << static_cast<unsigned>(type.qualifiers()) << ':';
    if (type.function_convention() != FunctionConvention::platform_default)
        out << 'c' << static_cast<unsigned>(type.function_convention());
    if (type.element())
        out << '[' << canonical(*type.element(), active) << ']';
    out << "m" << type.members().size();
    for (const auto &member : type.members()) {
        out << '{';
        append_text(out, member.name);
        if (member.virtual_base) {
            out << "@vbase:" << member.virtual_base->vbptr_offset << ':'
                << member.virtual_base->vbtable_index << ':' << member.virtual_base->indirect << ':'
                << canonical(*member.virtual_base->vbptr_type, active) << ':';
        } else {
            out << '@' << member.offset << ':';
        }
        if (member.effective_alignment) out << 'a' << *member.effective_alignment;
        if (member.bit_width) out << 'b' << *member.bit_width << '@' << *member.bit_offset;
        if (member.anonymous) out << 'n';
        if (member.access != MemberAccess::unknown)
            out << 'a' << static_cast<unsigned>(member.access) << ':';
        out << canonical(*member.type, active) << '}';
    }
    out << "e" << type.enumerators().size();
    for (std::size_t i = 0; i < type.enumerators().size(); ++i) {
        const auto &item = type.enumerators()[i];
        append_text(out, item);
        out << '=' << type.enumerator_values()[i].value;
    }
    if (type.result_type())
        out << "->" << canonical(*type.result_type(), active);
    out << "p" << type.parameters().size();
    for (const auto &parameter : type.parameters()) {
        out << '(';
        append_text(out, parameter.name);
        out << ':' << canonical(*parameter.type, active) << ')';
    }
    out << "d" << type.methods().size();
    for (const auto &method : type.methods()) {
        out << '{'; append_text(out, method.name);
        out << ':' << static_cast<unsigned>(method.access) << ':' << static_cast<unsigned>(method.dispatch)
            << ':' << method.source_attributes << ':' << method.is_static << ':'
            << method.introducing_vtable_offset.value_or(UINT32_MAX) << ':' << method.this_adjustment
            << ':' << static_cast<unsigned>(method.function_options) << ':' << method.declaration_ordinal;
        if (method.signature) out << ':' << canonical(*method.signature, active);
        if (method.this_type) out << ':' << canonical(*method.this_type, active);
        if (!method.vtable_slots.empty()) {
            out << ":vslots" << method.vtable_slots.size();
            for (const auto &slot : method.vtable_slots) {
                out << '{' << slot.vfptr_offset << ':' << slot.slot_index << ':'
                    << static_cast<unsigned>(slot.source_namespace) << ':' << slot.source_type_index << ':'
                    << slot.source_record_offset << ':';
                append_text(out, slot.table_name);
                append_text(out, slot.method_name);
                out << '}';
            }
        }
        out << '}';
    }
    if (!type.static_data_members().empty()) {
        out << "s" << type.static_data_members().size();
        for (const auto &member : type.static_data_members()) {
            out << '{'; append_text(out, member.name);
            out << ':' << static_cast<unsigned>(member.access) << ':' << member.source_attributes
                << ':' << member.declaration_ordinal << ':' << canonical(*member.type, active) << '}';
        }
    }
    out << 'v' << type.variadic();
    active.erase(&type);
    return out.str();
}
} // namespace
void assign_id(Type &type) {
    std::unordered_set<const Type *> active;
    type.id_ = hash(canonical(type, active));
}

std::vector<std::size_t> Type::members_covering_offset(std::uint64_t byte_offset) const {
    std::vector<std::size_t> result;
    if (kind_ != Kind::structure && kind_ != Kind::union_type) return result;
    for (std::size_t i = 0; i < members_.size(); ++i) {
        const auto &member = members_[i];
        if (member.virtual_base || !member.type || (member.bit_width && *member.bit_width == 0) || !member.type->size())
            continue;
        const auto extent = *member.type->size();
        // Aggregate validation guarantees member extents fit their owner;
        // subtraction keeps the query safe even for malformed future sources.
        if (byte_offset >= member.offset && byte_offset - member.offset < extent)
            result.push_back(i);
    }
    return result;
}

std::vector<MemberPath> Type::member_paths(std::string_view name) const {
    std::vector<MemberPath> result;
    if ((kind_ != Kind::structure && kind_ != Kind::union_type) || name.empty()) return result;
    std::vector<std::size_t> indexes;
    std::unordered_set<const Type *> active;
    std::function<void(const Type &, std::uint64_t, unsigned)> visit =
        [&](const Type &aggregate, std::uint64_t base, unsigned depth) {
            if (depth > 64 || (aggregate.kind() != Kind::structure && aggregate.kind() != Kind::union_type) ||
                !active.insert(&aggregate).second)
                return;
            for (std::size_t i = 0; i < aggregate.members().size(); ++i) {
                const auto &member = aggregate.members()[i];
                if (member.offset > UINT64_MAX - base) continue;
                const auto offset = base + member.offset;
                indexes.push_back(i);
                if (member.anonymous && member.type) {
                    const auto *child = unqualified(member.type.get());
                    if (child && (child->kind() == Kind::structure || child->kind() == Kind::union_type))
                        visit(*child, offset, depth + 1);
                } else if (!member.name.empty() && member.name == name) {
                    result.push_back(MemberPath{indexes, offset});
                }
                indexes.pop_back();
            }
            active.erase(&aggregate);
        };
    visit(*this, 0, 0);
    return result;
}

hexlab::Result<TypePtr> Type::aggregate(Kind kind, std::string name, std::vector<Member> members, std::uint64_t size,
                                        std::uint64_t alignment, std::optional<std::uint64_t> packing_alignment) {
    if (name.empty() || !valid_layout(size, alignment))
        return invalid("aggregate requires a name and valid size/alignment");
    if (packing_alignment && (*packing_alignment == 0 || *packing_alignment > 16 ||
        (*packing_alignment & (*packing_alignment - 1)) != 0))
        return invalid("aggregate packing alignment must be a power of two from 1 through 16");
    std::unordered_set<std::string> names;
    std::function<bool(const Type &, unsigned)> add_promoted_names = [&](const Type &aggregate, unsigned depth) {
        if (depth > 64 || (aggregate.kind() != Kind::structure && aggregate.kind() != Kind::union_type))
            return false;
        for (const auto &nested : aggregate.members()) {
            if (nested.anonymous) {
                const auto *child = unqualified(nested.type.get());
                if (!child || !add_promoted_names(*child, depth + 1)) return false;
            } else if (!nested.name.empty() && !names.insert(nested.name).second) {
                return false;
            }
        }
        return true;
    };
    for (std::size_t member_index = 0; member_index < members.size(); ++member_index) {
        const auto &member = members[member_index];
        const auto *member_base = unqualified(member.type.get());
        if (member.virtual_base) {
            const auto *vbptr = unqualified(member.virtual_base->vbptr_type.get());
            const auto *entry = vbptr && vbptr->kind() == Kind::pointer ? unqualified(vbptr->element().get()) : nullptr;
            if (kind != Kind::structure || !member.type || !member.virtual_base->vbptr_type ||
                !member_base || (member_base->kind() != Kind::structure && member_base->kind() != Kind::named_reference) ||
                !vbptr || vbptr->kind() != Kind::pointer || !vbptr->size() || member.offset != 0 ||
                (*vbptr->size() != 4 && *vbptr->size() != 8) ||
                !entry || entry->kind() != Kind::integer || entry->size() != 4 || !entry->is_signed() ||
                member.bit_width || member.bit_offset || member.effective_alignment ||
                member.virtual_base->vbptr_offset > size ||
                *vbptr->size() > size - member.virtual_base->vbptr_offset)
                return invalid("virtual base requires a structure and an in-bounds 32/64-bit pointer to signed 32-bit vbtable entries");
            const auto address_max = *vbptr->size() == 4 ? std::uint64_t{UINT32_MAX} : UINT64_MAX;
            if (member.virtual_base->vbptr_offset > address_max - (*vbptr->size() - 1))
                return invalid("virtual-base pointer field extent exceeds its address width");
            if (member.virtual_base->vbtable_index > (address_max - 3) / 4)
                return invalid("virtual-base table entry extent exceeds its vbptr address width");
        }
        const bool flexible = member_base && member_base->kind() == Kind::array &&
                              member_base->count() == 0 && !member_base->size();
        const bool deferred_named = member_base && member_base->kind() == Kind::named_reference;
        const bool zero_width_barrier = member.bit_width && *member.bit_width == 0 &&
                                        member.bit_offset && *member.bit_offset == 0;
        const bool anonymous_type = member_base &&
            (member_base->kind() == Kind::structure || member_base->kind() == Kind::union_type);
        if ((!member.bit_width && member.name.empty() && !member.anonymous) ||
            (member.anonymous && (!member.name.empty() || !anonymous_type || member.bit_width || member.bit_offset ||
                                  member.virtual_base)) ||
            (!member.name.empty() && !names.insert(member.name).second) ||
            (member.anonymous && !add_promoted_names(*member_base, 0)) || !member.type ||
            static_cast<unsigned>(member.access) > static_cast<unsigned>(MemberAccess::public_) ||
            (!member.type->size() && !flexible && !deferred_named))
            return invalid("aggregate members require unique names and sized types or a named reference");
        if (member.virtual_base) continue;
        if (flexible && (kind != Kind::structure || member_index == 0 || member_index + 1 != members.size() ||
                         member.bit_width || member.bit_offset))
            return invalid("flexible array must be the final member of a structure with at least one preceding member");
        const auto member_size = member.type->size().value_or(0);
        if (member.offset > size ||
            (!(zero_width_barrier) && member_size > size - member.offset))
            return invalid("member exceeds aggregate size");
        // Stored effective alignment preserves compiler-derived member
        // packing and explicit over-alignment. The aggregate's alignment must
        // be large enough to satisfy every recorded member requirement.
        if (!deferred_named || member.effective_alignment) {
            const auto natural_member_alignment = deferred_named
                ? alignment : std::min(alignment, member.type->alignment());
            const auto effective_member_alignment = member.effective_alignment.value_or(natural_member_alignment);
            if (!effective_member_alignment || (effective_member_alignment & (effective_member_alignment - 1)) != 0 ||
                effective_member_alignment > alignment)
                return invalid("member effective alignment must be a power of two no greater than aggregate alignment");
            if (member.offset % effective_member_alignment != 0)
                return invalid("member offset violates member alignment");
        }
        if (member.bit_width.has_value() != member.bit_offset.has_value())
            return invalid("bitfield width and bit offset must be specified together");
        if (member.bit_width) {
            const Type *storage_type = member_base;
            if (storage_type->kind() == Kind::enumeration && storage_type->element())
                storage_type = unqualified(storage_type->element().get());
            if (!storage_type || (storage_type->kind() != Kind::integer && storage_type->kind() != Kind::boolean) ||
                *member.type->size() > UINT64_MAX / 8 ||
                (!*member.bit_width && (!member.name.empty() || *member.bit_offset != 0)))
                return invalid("bitfield requires an integral storage type; zero-width barriers must be unnamed with bit offset zero");
            const auto storage_bits = *member.type->size() * 8;
            if (*member.bit_width && (*member.bit_offset > storage_bits || *member.bit_width > storage_bits - *member.bit_offset))
                return invalid("bitfield exceeds its storage unit");
        }
    }
    if (kind == Kind::structure) {
        auto ordered = members;
        std::sort(ordered.begin(), ordered.end(), [](const auto &a, const auto &b) { return a.offset < b.offset; });
        for (std::size_t i = 1; i < ordered.size(); ++i) {
            const auto &a = ordered[i - 1];
            const auto &b = ordered[i];
            if (a.virtual_base || b.virtual_base) continue;
            const auto a_size = a.type->size().value_or(0);
            const auto b_size = b.type->size().value_or(0);
            if (a.offset + a_size <= b.offset || (a.bit_width && !*a.bit_width) ||
                (b.bit_width && !*b.bit_width)) continue;
            const bool same_storage = a.bit_width && b.bit_width && a.offset == b.offset &&
                                      a_size == b_size;
            if (!same_storage) return invalid("structure members overlap");
            const auto a_end = *a.bit_offset + *a.bit_width;
            const auto b_end = *b.bit_offset + *b.bit_width;
            if (*a.bit_offset < b_end && *b.bit_offset < a_end)
                return invalid("structure bitfields overlap within a storage unit");
        }
    }
    if (kind == Kind::union_type)
        for (const auto &member : members)
            if (member.offset != 0)
                return invalid("union members must begin at offset zero");
    auto type = std::shared_ptr<Type>(new Type(kind));
    type->name_ = std::move(name);
    type->members_ = std::move(members);
    type->size_ = size;
    type->alignment_ = alignment;
    type->packing_alignment_ = packing_alignment;
    assign_id(*type);
    return TypePtr(type);
}
TypePtr Type::void_type() {
    static const auto type = [] {
        auto value = std::shared_ptr<Type>(new Type(Kind::void_type));
        value->name_ = "void";
        assign_id(*value);
        return TypePtr(value);
    }();
    return type;
}
hexlab::Result<TypePtr> Type::named_reference(std::string name) {
    if (name.empty())
        return invalid("named type reference requires a name");
    auto type = std::shared_ptr<Type>(new Type(Kind::named_reference));
    type->name_ = std::move(name);
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::qualified(TypePtr base, std::uint8_t qualifiers) {
    constexpr std::uint8_t known = static_cast<std::uint8_t>(Qualifier::const_) |
        static_cast<std::uint8_t>(Qualifier::volatile_) | static_cast<std::uint8_t>(Qualifier::restrict_) |
        static_cast<std::uint8_t>(Qualifier::atomic_);
    if (!base || !qualifiers || (qualifiers & ~known)) return invalid("qualified type requires a base and known qualifiers");
    if (base->kind() == Kind::qualified && base->element() && base->element()->kind() != Kind::pointer) {
        qualifiers |= base->qualifiers();
        base = base->element();
    }
    const Type *unqualified = base.get();
    while (unqualified && unqualified->kind() == Kind::qualified) unqualified = unqualified->element().get();
    if (!unqualified || unqualified->kind() == Kind::function)
        return invalid("function types cannot be qualified");
    if ((qualifiers & static_cast<std::uint8_t>(Qualifier::restrict_)) && unqualified->kind() != Kind::pointer)
        return invalid("restrict qualification requires a pointer type");
    auto type = std::shared_ptr<Type>(new Type(Kind::qualified));
    type->name_ = "qualified";
    type->element_ = std::move(base);
    type->qualifiers_ = qualifiers;
    type->size_ = type->element_->size();
    type->alignment_ = type->element_->alignment();
    type->signed_ = type->element_->is_signed();
    type->count_ = type->element_->count();
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::with_alignment(TypePtr base, std::uint64_t alignment) {
    if (!base || !alignment || (alignment & (alignment - 1)) != 0 || alignment < base->alignment())
        return invalid("type alignment must be a power of two no smaller than its existing alignment");
    if (base->kind() == Kind::void_type || base->kind() == Kind::function || base->kind() == Kind::named_reference)
        return invalid("alignment cannot be applied to this type kind");
    auto type = std::shared_ptr<Type>(new Type(*base));
    type->alignment_ = alignment;
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::with_methods(TypePtr aggregate, std::vector<Method> methods) {
    if (!aggregate || (aggregate->kind() != Kind::structure && aggregate->kind() != Kind::union_type))
        return invalid("methods require an aggregate type");
    for (const auto &method : methods) {
        if (method.name.empty() || !method.signature || method.signature->kind() != Kind::function ||
            static_cast<unsigned>(method.access) > static_cast<unsigned>(MemberAccess::public_) ||
            static_cast<unsigned>(method.dispatch) > static_cast<unsigned>(MemberDispatch::unknown) ||
            (method.is_static && method.this_type))
            return invalid("aggregate method metadata is invalid");
        for (const auto &member : aggregate->members())
            if (!member.name.empty() && member.name == method.name)
                return invalid("aggregate method name conflicts with a data member");
        for (const auto &member : aggregate->static_data_members())
            if (member.name == method.name)
                return invalid("aggregate method name conflicts with a static data member");
        if (method.introducing_vtable_offset &&
            method.dispatch != MemberDispatch::introducing_virtual &&
            method.dispatch != MemberDispatch::pure_introducing_virtual)
            return invalid("only an introducing virtual method may have a vtable offset");
        if (method.vtable_slots.size() > max_type_collection_items)
            return invalid("aggregate method has too many virtual-table slots");
        for (const auto &slot : method.vtable_slots)
            if (method.is_static || slot.table_name.empty() || slot.method_name.empty() ||
                slot.slot_index > 100000 || slot.source_type_index < 0x1000 ||
                method.dispatch == MemberDispatch::non_virtual ||
                method.dispatch == MemberDispatch::unknown)
                return invalid("aggregate method virtual-table slot metadata is invalid");
    }
    auto type = std::shared_ptr<Type>(new Type(*aggregate));
    type->methods_ = std::move(methods);
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::with_static_data_members(TypePtr aggregate, std::vector<StaticDataMember> members) {
    if (!aggregate || (aggregate->kind() != Kind::structure && aggregate->kind() != Kind::union_type))
        return invalid("static data declarations require an aggregate type");
    std::unordered_set<std::string> names;
    for (const auto &member : members) {
        if (member.name.empty() || member.name.size() > 4096 || !member.type ||
            static_cast<unsigned>(member.access) > static_cast<unsigned>(MemberAccess::public_) ||
            !names.insert(member.name).second)
            return invalid("aggregate static data metadata is invalid");
        for (const auto &instance_member : aggregate->members())
            if (!instance_member.name.empty() && instance_member.name == member.name)
                return invalid("aggregate static data name conflicts with an instance data member");
        for (const auto &method : aggregate->methods())
            if (method.name == member.name)
                return invalid("aggregate static data name conflicts with a method");
    }
    auto type = std::shared_ptr<Type>(new Type(*aggregate));
    type->static_data_members_ = std::move(members);
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::boolean(std::uint64_t size, std::uint64_t alignment) {
    if (!valid_layout(size, alignment))
        return invalid("invalid boolean size/alignment");
    auto type = std::shared_ptr<Type>(new Type(Kind::boolean));
    type->name_ = "bool";
    type->size_ = size;
    type->alignment_ = alignment;
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::integer(std::string name, std::uint64_t size, std::uint64_t alignment, bool is_signed) {
    if (name.empty() || !valid_layout(size, alignment))
        return invalid("invalid integer name/size/alignment");
    auto type = std::shared_ptr<Type>(new Type(Kind::integer));
    type->name_ = std::move(name);
    type->size_ = size;
    type->alignment_ = alignment;
    type->signed_ = is_signed;
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::floating(std::string name, std::uint64_t size, std::uint64_t alignment) {
    if (name.empty() || !valid_layout(size, alignment))
        return invalid("invalid float name/size/alignment");
    auto type = std::shared_ptr<Type>(new Type(Kind::floating));
    type->name_ = std::move(name);
    type->size_ = size;
    type->alignment_ = alignment;
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::vector(TypePtr element, std::uint64_t lanes, std::uint64_t alignment) {
    if (!element || (element->kind() != Kind::integer && element->kind() != Kind::floating) ||
        !element->size() || !*element->size() || !lanes || !alignment ||
        (alignment & (alignment - 1)) != 0 || *element->size() > UINT64_MAX / lanes)
        return invalid("vector requires a complete integer/floating lane type, nonzero lane count, and power-of-two alignment");
    const auto size = *element->size() * lanes;
    if (!valid_layout(size, alignment)) return invalid("invalid vector size/alignment");
    auto type = std::shared_ptr<Type>(new Type(Kind::vector));
    type->name_ = "vector";
    type->element_ = std::move(element);
    type->count_ = lanes;
    type->size_ = size;
    type->alignment_ = alignment;
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::pointer(TypePtr pointee, std::uint64_t size, std::uint64_t alignment) {
    if (!pointee || !valid_layout(size, alignment))
        return invalid("invalid pointer target/size/alignment");
    auto type = std::shared_ptr<Type>(new Type(Kind::pointer));
    type->name_ = "ptr";
    type->element_ = std::move(pointee);
    type->size_ = size;
    type->alignment_ = alignment;
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::array(TypePtr element, std::uint64_t count) {
    if (!element || !element->size())
        return invalid("array element must have a complete size");
    if (count && *element->size() > UINT64_MAX / count)
        return invalid("array size overflows");
    auto type = std::shared_ptr<Type>(new Type(Kind::array));
    type->name_ = "array";
    type->element_ = std::move(element);
    type->count_ = count;
    type->array_stride_ = *type->element_->size();
    if (count) type->size_ = *type->element_->size() * count;
    type->alignment_ = type->element_->alignment();
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::strided_array(TypePtr element, std::uint64_t count, std::uint64_t stride) {
    if (!element || !element->size() || !*element->size() || stride < *element->size())
        return invalid("strided array requires a complete element and a stride at least as large as the element");
    if (!count) return invalid("strided array count must be nonzero");
    if (count - 1 > (UINT64_MAX - *element->size()) / stride)
        return invalid("strided array size overflows");
    auto type = std::shared_ptr<Type>(new Type(Kind::array));
    type->name_ = "array"; type->element_ = std::move(element); type->count_ = count;
    type->array_stride_ = stride; type->size_ = (count - 1) * stride + *type->element_->size();
    type->alignment_ = type->element_->alignment(); assign_id(*type); return TypePtr(type);
}
hexlab::Result<TypePtr> Type::incomplete_aggregate(Kind kind, std::string name) {
    if ((kind != Kind::structure && kind != Kind::union_type) || name.empty())
        return invalid("incomplete aggregate requires a structure/union kind and a name");
    auto type = std::shared_ptr<Type>(new Type(kind));
    type->name_ = std::move(name);
    type->alignment_ = 1;
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::structure(std::string name, std::vector<Member> members, std::uint64_t size,
                                        std::uint64_t alignment, std::optional<std::uint64_t> packing_alignment) {
    return aggregate(Kind::structure, std::move(name), std::move(members), size, alignment, packing_alignment);
}
hexlab::Result<TypePtr> Type::union_type(std::string name, std::vector<Member> members, std::uint64_t size,
                                         std::uint64_t alignment, std::optional<std::uint64_t> packing_alignment) {
    return aggregate(Kind::union_type, std::move(name), std::move(members), size, alignment, packing_alignment);
}
hexlab::Result<TypePtr> Type::enumeration(std::string name, TypePtr underlying, std::vector<std::string> values) {
    std::vector<Enumerator> enumerators;
    enumerators.reserve(values.size());
    for (std::size_t i = 0; i < values.size(); ++i) enumerators.push_back({std::move(values[i]), i});
    return enumeration_with_values(std::move(name), std::move(underlying), std::move(enumerators));
}
hexlab::Result<TypePtr> Type::enumeration_with_values(std::string name, TypePtr underlying, std::vector<Enumerator> values) {
    if (name.empty() || !underlying || !unqualified(underlying.get()) || unqualified(underlying.get())->kind() != Kind::integer || values.empty())
        return invalid("enum requires name, integer underlying type, and enumerators");
    std::unordered_set<std::string> names;
    const auto bits = std::min<std::uint64_t>(underlying->size().value_or(0), 8) * 8;
    const auto mask = bits >= 64 ? UINT64_MAX : (std::uint64_t{1} << bits) - 1;
    for (const auto &value : values) {
        if (value.name.empty() || !names.insert(value.name).second)
            return invalid("enum values require unique nonempty names");
        if (bits < 64) {
            const auto upper = value.value & ~mask;
            const auto sign = std::uint64_t{1} << (bits - 1);
            const auto expected = underlying->is_signed() && (value.value & sign) ? ~mask : 0;
            if (upper != expected) return invalid("enum value does not fit its underlying integer type");
        }
    }
    auto type = std::shared_ptr<Type>(new Type(Kind::enumeration));
    type->name_ = std::move(name);
    type->element_ = std::move(underlying);
    type->size_ = type->element_->size();
    type->alignment_ = type->element_->alignment();
    type->enumerators_.reserve(values.size());
    for (const auto &value : values) type->enumerators_.push_back(value.name);
    type->enumerator_values_ = std::move(values);
    assign_id(*type);
    return TypePtr(type);
}
hexlab::Result<TypePtr> Type::function(TypePtr result, std::vector<Parameter> parameters, bool variadic,
                                       FunctionConvention convention) {
    if (static_cast<std::uint8_t>(convention) > static_cast<std::uint8_t>(FunctionConvention::aapcs32_vfp))
        return invalid("invalid function calling convention");
    if (!result || unqualified(result.get())->kind() == Kind::array || unqualified(result.get())->kind() == Kind::function)
        return invalid("invalid function result type");
    std::unordered_set<std::string> names;
    for (const auto &parameter : parameters)
        if (parameter.name.empty() || !names.insert(parameter.name).second || !parameter.type ||
            unqualified(parameter.type.get())->kind() == Kind::void_type)
            return invalid("function parameters require unique names and non-void types");
    auto type = std::shared_ptr<Type>(new Type(Kind::function));
    type->name_ = "function";
    type->result_ = std::move(result);
    type->parameters_ = std::move(parameters);
    type->variadic_ = variadic;
    type->function_convention_ = convention;
    assign_id(*type);
    return TypePtr(type);
}
std::string format(const Type &type) {
    std::ostringstream out;
    switch (type.kind()) {
    case Kind::void_type:
        return "void";
    case Kind::named_reference:
        return type.name();
    case Kind::boolean:
        return "bool";
    case Kind::integer:
    case Kind::floating:
    case Kind::enumeration:
        return type.name();
    case Kind::pointer:
        return format(*type.element()) + "*";
    case Kind::qualified: {
        std::string prefix;
        if (type.qualifiers() & static_cast<std::uint8_t>(Qualifier::const_)) prefix += "const ";
        if (type.qualifiers() & static_cast<std::uint8_t>(Qualifier::volatile_)) prefix += "volatile ";
        if (type.qualifiers() & static_cast<std::uint8_t>(Qualifier::restrict_)) prefix += "restrict ";
        if (type.qualifiers() & static_cast<std::uint8_t>(Qualifier::atomic_)) {
            auto underlying = format(*type.element());
            if (type.element()->kind() == Kind::pointer && !prefix.empty())
                underlying += " " + prefix.substr(0, prefix.size() - 1);
            else
                underlying = prefix + underlying;
            return "_Atomic(" + underlying + ")";
        }
        if (type.element()->kind() == Kind::pointer) return format(*type.element()) + " " + prefix.substr(0, prefix.size()-1);
        return prefix + format(*type.element());
    }
    case Kind::array:
        return format(*type.element()) + "[" + (type.count() ? std::to_string(type.count()) : std::string{}) + "]" +
            (type.element()->size() && type.array_stride() > *type.element()->size()
                ? " (stride " + std::to_string(type.array_stride()) + ")" : "");
    case Kind::vector:
        return "vector<" + format(*type.element()) + ", " + std::to_string(type.count()) + ">";
    case Kind::structure:
    case Kind::union_type:
        if (!type.size())
            return std::string(type.kind() == Kind::structure ? "struct " : "union ") + type.name() + " (incomplete)";
        out << (type.kind() == Kind::structure ? "struct " : "union ") << type.name() << " { ";
        if (type.packing_alignment()) out << "#pragma pack(" << *type.packing_alignment() << ") ";
        for (const auto &member : type.members()) {
            out << member.name;
            if (member.virtual_base) {
                out << " virtual-base(vbptr@" << member.virtual_base->vbptr_offset
                    << ", vbtable-index=" << member.virtual_base->vbtable_index
                    << (member.virtual_base->indirect ? ", indirect)" : ")");
            } else {
                out << '@' << member.offset;
            }
            out << ": " << format(*member.type);
            if (member.bit_width) out << " : " << *member.bit_width << '@' << *member.bit_offset;
            out << "; ";
        }
        if (!type.methods().empty() || !type.static_data_members().empty()) {
            out << " }";
            if (!type.static_data_members().empty()) {
                out << " static data (not part of object layout): ";
                for (const auto &member : type.static_data_members()) {
                    out << member.name << " : " << format(*member.type);
                    if (member.access == MemberAccess::public_) out << " public";
                    else if (member.access == MemberAccess::protected_) out << " protected";
                    else if (member.access == MemberAccess::private_) out << " private";
                    out << "; ";
                }
            }
            if (type.methods().empty()) return out.str();
            out << " methods (not part of object layout): ";
            for (const auto &method : type.methods()) {
                out << method.name << " : " << format(*method.signature);
                if (method.is_static) out << " static";
                if (method.access == MemberAccess::public_) out << " public";
                else if (method.access == MemberAccess::protected_) out << " protected";
                else if (method.access == MemberAccess::private_) out << " private";
                if (method.introducing_vtable_offset) out << " vtable+" << *method.introducing_vtable_offset;
                for (const auto &slot : method.vtable_slots)
                    out << " [vfptr+" << slot.vfptr_offset << " slot#" << slot.slot_index
                        << " " << slot.method_name << ']';
                out << "; ";
            }
            return out.str();
        }
        return out.str() + "}";
    case Kind::function:
        out << format(*type.result_type());
        if (type.function_convention() != FunctionConvention::platform_default) {
            static constexpr const char *names[] = {"default", "cdecl", "stdcall", "fastcall", "thiscall", "vectorcall", "sysv_abi", "ms_abi", "aapcs64", "aapcs32", "mips_n64", "mips_n32", "aapcs32_vfp"};
            out << " [" << names[static_cast<unsigned>(type.function_convention())] << "]";
        }
        out << " (";
        for (std::size_t i = 0; i < type.parameters().size(); ++i) {
            if (i)
                out << ", ";
            out << format(*type.parameters()[i].type) << ' ' << type.parameters()[i].name;
        }
        if (type.variadic()) {
            if (!type.parameters().empty())
                out << ", ";
            out << "...";
        }
        return out.str() + ")";
    }
    return {};
}
hexlab::Result<std::vector<std::byte>> encode(const Type& type) {
    try { TypeWriter out;out.number(19,1);write_type(out,type,0,19);if(out.bytes.size()>max_type_record_size)return invalid("type record exceeds limit");return std::move(out.bytes); }
    catch(const std::bad_alloc&){return hexlab::Error{hexlab::ErrorCode::resource_limit,"Cannot encode type"};}
    catch(const std::exception& e){return invalid(e.what());}
}
hexlab::Result<TypePtr> decode(std::span<const std::byte> bytes) {
    try {if(bytes.size()>max_type_record_size)return invalid("type record exceeds limit");TypeReader in{bytes};const auto version=in.number(1);if(version<1||version>19)return invalid("unknown type record version");auto value=read_type(in,0,static_cast<std::uint8_t>(version));if(in.cursor!=bytes.size())return invalid("trailing type record data");TypeWriter canonical;canonical.number(version,1);write_type(canonical,*value,0,static_cast<std::uint8_t>(version));if(canonical.bytes!=std::vector<std::byte>(bytes.begin(),bytes.end()))return invalid("noncanonical type record");return value;}
    catch(const std::bad_alloc&){return hexlab::Error{hexlab::ErrorCode::resource_limit,"Cannot decode type"};}
    catch(const std::exception& e){return invalid(e.what());}
}
} // namespace hexlab::types
