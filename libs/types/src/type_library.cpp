#include "hexlab/types/type_library.hpp"
#include <algorithm>
#include <set>
#include <stdexcept>
#include <unordered_set>

namespace hexlab::types {
namespace {
constexpr std::size_t max_entries = 4096, max_name = 512, max_record = 16u * 1024u * 1024u;
struct Writer {
    std::vector<std::byte> b;
    void num(std::uint64_t v, unsigned n) { for (unsigned i=0;i<n;++i) b.push_back(std::byte((v>>(i*8))&255)); }
    void raw(std::span<const std::byte> s) { b.insert(b.end(),s.begin(),s.end()); }
    void str(std::string_view s) { num(s.size(),4); for(unsigned char c:s)b.push_back(std::byte(c)); }
};
struct Reader {
    std::span<const std::byte> b; std::size_t p=0;
    std::uint64_t num(unsigned n) { if(p>b.size()||n>b.size()-p) throw std::runtime_error("truncated type library"); std::uint64_t v=0; for(unsigned i=0;i<n;++i)v|=std::uint64_t(std::to_integer<unsigned char>(b[p++]))<<(i*8); return v; }
    std::string str(std::size_t max) { auto n=num(4); if(n>max||n>b.size()-p)throw std::runtime_error("invalid type library string length"); std::string s(reinterpret_cast<const char*>(b.data()+p),static_cast<std::size_t>(n));p+=static_cast<std::size_t>(n);return s; }
    std::span<const std::byte> take(std::size_t n) { if(p>b.size()||n>b.size()-p)throw std::runtime_error("truncated type library");auto s=b.subspan(p,n);p+=n;return s; }
};
Error invalid(std::string s) { return {ErrorCode::invalid_argument,std::move(s)}; }
bool valid_entry(const LibraryEntry &e) { return !e.name.empty()&&e.name.size()<=max_name&&e.type&&static_cast<unsigned>(e.declaration_kind)<=2&&(!e.origin||(!e.origin->source_id.empty()&&e.origin->source_id.size()<=1024&&!e.origin->section.empty()&&e.origin->section.size()<=256&&e.origin->record_size)); }
void write_entry(Writer &w,const LibraryEntry &e) {
    w.str(e.name); w.num(static_cast<unsigned>(e.declaration_kind),1); w.num(e.origin?1:0,1);
    if(e.origin){w.str(e.origin->source_id);w.str(e.origin->section);w.num(e.origin->unit_offset,8);w.num(e.origin->record_offset,8);w.num(e.origin->record_size,8);}
    auto record=encode(*e.type);if(!record)throw std::runtime_error(record.error().message);w.num(record.value().size(),4);w.raw(record.value());
}
LibraryEntry read_entry(Reader &r) {
    LibraryEntry e;e.name=r.str(max_name);auto kind=r.num(1),has_origin=r.num(1);if(kind>2||has_origin>1)throw std::runtime_error("invalid type library entry metadata");e.declaration_kind=static_cast<LibraryDeclarationKind>(kind);
    if(has_origin){LibraryTypeOrigin o;o.source_id=r.str(1024);o.section=r.str(256);o.unit_offset=r.num(8);o.record_offset=r.num(8);o.record_size=r.num(8);if(o.source_id.empty()||o.section.empty()||!o.record_size)throw std::runtime_error("invalid type library source origin");e.origin=std::move(o);}
    auto n=r.num(4);if(n>max_record)throw std::runtime_error("invalid type record length");auto type=decode(r.take(static_cast<std::size_t>(n)));if(!type)throw std::runtime_error(type.error().message);e.type=std::move(type.value());if(!valid_entry(e))throw std::runtime_error("invalid type library definition");return e;
}
void check_end(const Reader &r){if(r.p!=r.b.size())throw std::runtime_error("Trailing type library data");}
}
Result<std::vector<std::byte>> encode_library(std::span<const LibraryEntry> entries,std::size_t max_bytes) {
 try { if(entries.size()>max_entries)return Error{ErrorCode::resource_limit,"Type library exceeds 4096 definitions"};Writer w;for(char c:std::string_view("HXTL"))w.b.push_back(std::byte(c));w.num(1,2);w.num(entries.size(),4);std::set<std::string> names;
  for(const auto&e:entries){if(!valid_entry(e)||!names.insert(e.name).second)return invalid("Type library definitions must have valid unique names and types");auto record=encode(*e.type);if(!record)return record.error();w.str(e.name);w.num(record.value().size(),4);w.raw(record.value());if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};}if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};return std::move(w.b);
 }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot encode type library"};}catch(const std::exception&e){return invalid(e.what());}
}
Result<std::vector<LibraryEntry>> decode_library(std::span<const std::byte> bytes,std::size_t max_bytes) {
 try {if(bytes.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};Reader r{bytes};if(r.num(1)!='H'||r.num(1)!='X'||r.num(1)!='T'||r.num(1)!='L')return invalid("Invalid type library signature");if(r.num(2)!=1)return invalid("Unsupported type library version");auto count=r.num(4);if(count>max_entries)return Error{ErrorCode::resource_limit,"Type library exceeds 4096 definitions"};std::vector<LibraryEntry> out;out.reserve(static_cast<std::size_t>(count));std::set<std::string> names;
  for(std::uint64_t i=0;i<count;++i){auto name=r.str(max_name);if(name.empty()||!names.insert(name).second)return invalid("Type library names must be unique and nonempty");auto n=r.num(4);if(n>max_record)return invalid("Invalid type record length");auto type=decode(r.take(static_cast<std::size_t>(n)));if(!type)return type.error();out.push_back({std::move(name),std::move(type.value())});}check_end(r);return out;
 }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot decode type library"};}catch(const std::exception&e){return invalid(e.what());}
}
Result<std::vector<std::byte>> encode_library_bundle(const LibraryBundle &bundle,std::size_t max_bytes) {
 try {if(bundle.entries.size()>max_entries)return Error{ErrorCode::resource_limit,"Type library exceeds 4096 definitions"};if(bundle.assignments.size()>262144)return Error{ErrorCode::resource_limit,"Type library exceeds assignment limit"};if(!bundle.source_identity&&!bundle.assignments.empty())return invalid("Type assignments require a source identity");
  Writer w;for(char c:std::string_view("HXTL"))w.b.push_back(std::byte(c));w.num(3,2);w.num(bundle.source_identity?1:0,2);w.num(bundle.entries.size(),4);w.num(bundle.assignments.size(),4);
  if(bundle.source_identity){w.num(bundle.source_identity->input_size,8);w.raw(bundle.source_identity->input_sha256);w.raw(bundle.source_identity->recipe_sha256);}
  std::set<std::string> names;for(auto &e:bundle.entries){if(!valid_entry(e)||!names.insert(e.name).second)return invalid("Type library definitions must have valid unique names and types");write_entry(w,e);if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};}
  std::set<std::string> locations;for(const auto &a:bundle.assignments){if(a.type_name.empty()||a.type_name.size()>max_name)return invalid("Invalid symbolic type assignment");std::string key;
   if(const auto *addr=std::get_if<Address>(&a.location)){w.num(0,1);w.num(addr->space.value,4);w.num(addr->offset,8);key="A:"+std::to_string(addr->space.value)+":"+std::to_string(addr->offset);}
   else {const auto offset=std::get<FileOffset>(a.location).value;w.num(1,1);w.num(offset,8);key="F:"+std::to_string(offset);}
   w.str(a.type_name);if(!locations.insert(key).second)return invalid("Duplicate type assignment location");if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};}if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};return std::move(w.b);
 }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot encode type library"};}catch(const std::exception&e){return invalid(e.what());}
}
Result<LibraryBundle> decode_library_bundle(std::span<const std::byte> bytes,std::size_t max_bytes) {
 try {if(bytes.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};Reader r{bytes};if(r.num(1)!='H'||r.num(1)!='X'||r.num(1)!='T'||r.num(1)!='L')return invalid("Invalid type library signature");auto version=r.num(2);LibraryBundle out;
  if(version==1){auto count=r.num(4);if(count>max_entries)return Error{ErrorCode::resource_limit,"Type library exceeds 4096 definitions"};std::set<std::string> names;for(std::uint64_t i=0;i<count;++i){auto name=r.str(max_name);auto n=r.num(4);if(name.empty()||!names.insert(name).second||n>max_record)return invalid("Invalid type library definition");auto type=decode(r.take(static_cast<std::size_t>(n)));if(!type)return type.error();out.entries.push_back({std::move(name),std::move(type.value())});}check_end(r);return out;}
   if(version!=2&&version!=3)return invalid("Unsupported type library version");auto flags=r.num(2);if(flags&~1u)return invalid("Invalid type library flags");auto count=r.num(4),assignments=r.num(4);if(count>max_entries||assignments>262144)return Error{ErrorCode::resource_limit,"Type library count limit exceeded"};if(flags&1){LibrarySourceIdentity id;id.input_size=r.num(8);auto a=r.take(32),b=r.take(32);std::copy(a.begin(),a.end(),id.input_sha256.begin());std::copy(b.begin(),b.end(),id.recipe_sha256.begin());out.source_identity=id;}if(assignments&&!out.source_identity)return invalid("Type assignments require a source identity");std::set<std::string> names;out.entries.reserve(count);for(std::uint64_t i=0;i<count;++i){auto e=read_entry(r);if(!names.insert(e.name).second)return invalid("Duplicate type library definition");out.entries.push_back(std::move(e));}
  std::set<std::string> locations;out.assignments.reserve(assignments);for(std::uint64_t i=0;i<assignments;++i){auto tag=r.num(1);Location loc;std::string key;if(tag==0){auto space=r.num(4),off=r.num(8);Address addr{AddressSpaceId{static_cast<std::uint32_t>(space)},off};loc=addr;key="A:"+std::to_string(addr.space.value)+":"+std::to_string(addr.offset);}else if(tag==1&&version>=3){auto off=r.num(8);loc=FileOffset{off};key="F:"+std::to_string(off);}else return invalid("Invalid type assignment location tag");auto name=r.str(max_name);if(name.empty())return invalid("Invalid symbolic type assignment");if(!locations.insert(key).second)return invalid("Duplicate type assignment location");out.assignments.push_back({loc,std::move(name)});}check_end(r);return out;
 }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot decode type library"};}catch(const std::exception&e){return invalid(e.what());}
}
Result<std::size_t> validate_library_references(
    const LibraryBundle &bundle, const std::set<std::string, std::less<>> &available_names,
    std::size_t max_type_nodes) {
    try {
    if (bundle.entries.size() > max_entries)
        return Error{ErrorCode::resource_limit, "Type library exceeds 4096 definitions"};
    if (!max_type_nodes)
        return Error{ErrorCode::resource_limit, "Type reference validation has no node budget"};

    std::set<std::string, std::less<>> bundled_names;
    for (const auto &entry : bundle.entries) {
        if (!valid_entry(entry) || !bundled_names.insert(entry.name).second)
            return invalid("Type library definitions must have valid unique names and types");
    }

    constexpr std::size_t max_type_edges = 4'000'000;
    std::size_t edge_count = 0;
    std::unordered_set<const Type *> visited;
    std::vector<const Type *> pending;
    const auto schedule = [&](const Type *type) {
        if (!type) return;
        if (edge_count == max_type_edges)
            throw std::length_error("Type library reference graph exceeds edge budget");
        ++edge_count;
        pending.push_back(type);
    };
    for (const auto &entry : bundle.entries) schedule(entry.type.get());
    while (!pending.empty()) {
        const auto *type = pending.back();
        pending.pop_back();
        if (!type || !visited.insert(type).second) continue;
        if (visited.size() > max_type_nodes)
            return Error{ErrorCode::resource_limit, "Type library reference graph exceeds node budget"};
        if (type->kind() == Kind::named_reference &&
            !bundled_names.contains(type->name()) && !available_names.contains(type->name()))
            return invalid("Type library refers to missing definition " + type->name());
        if (type->element()) schedule(type->element().get());
        if (type->result_type()) schedule(type->result_type().get());
        for (const auto &member : type->members()) {
            if (member.type) schedule(member.type.get());
            if (member.virtual_base && member.virtual_base->vbptr_type)
                schedule(member.virtual_base->vbptr_type.get());
        }
        for (const auto &parameter : type->parameters())
            if (parameter.type) schedule(parameter.type.get());
        for (const auto &method : type->methods()) {
            if (method.signature) schedule(method.signature.get());
            if (method.this_type) schedule(method.this_type.get());
        }
        for (const auto &member : type->static_data_members())
            if (member.type) schedule(member.type.get());
    }
    return visited.size();
    } catch (const std::length_error &error) {
        return Error{ErrorCode::resource_limit, error.what()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot validate type library references"};
}
}
}
