#include "hexlab/types/type_library.hpp"
#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string_view>
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
bool valid_utf8_text(std::string_view text) noexcept {
    std::size_t i = 0;
    while (i < text.size()) {
        const auto first = static_cast<unsigned char>(text[i]);
        if (first == 0) return false;
        if (first < 0x80) { ++i; continue; }

        std::uint32_t value = 0;
        std::size_t count = 0;
        if (first >= 0xc2 && first <= 0xdf) { value = first & 0x1f; count = 2; }
        else if (first >= 0xe0 && first <= 0xef) { value = first & 0x0f; count = 3; }
        else if (first >= 0xf0 && first <= 0xf4) { value = first & 0x07; count = 4; }
        else return false;
        if (count > text.size() - i) return false;

        for (std::size_t j = 1; j < count; ++j) {
            const auto next = static_cast<unsigned char>(text[i + j]);
            if ((next & 0xc0) != 0x80) return false;
            if (j == 1 && ((first == 0xe0 && next < 0xa0) ||
                           (first == 0xed && next >= 0xa0) ||
                           (first == 0xf0 && next < 0x90) ||
                           (first == 0xf4 && next >= 0x90))) return false;
            value = (value << 6) | (next & 0x3f);
        }
        if (value == 0 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
        i += count;
    }
    return true;
}
bool valid_type_text(const Type &root) {
    constexpr std::size_t max_nodes = 1'000'000;
    constexpr std::size_t max_edges = 4'000'000;
    std::unordered_set<const Type *> visited;
    std::vector<const Type *> pending{&root};
    std::size_t edges = 0;
    const auto valid = [](const std::string &s) { return valid_utf8_text(s); };
    const auto schedule = [&](const TypePtr &type) {
        if (!type) return true;
        if (++edges > max_edges) return false;
        pending.push_back(type.get());
        return true;
    };
    while (!pending.empty()) {
        const auto *type = pending.back(); pending.pop_back();
        if (!visited.insert(type).second) continue;
        if (visited.size() > max_nodes || !valid(type->name())) return false;
        for (const auto &name : type->enumerators()) if (!valid(name)) return false;
        for (const auto &value : type->enumerator_values()) if (!valid(value.name)) return false;
        if (!schedule(type->element()) || !schedule(type->result_type())) return false;
        for (const auto &member : type->members()) {
            if (!valid(member.name) || !schedule(member.type)) return false;
            if (member.virtual_base && !schedule(member.virtual_base->vbptr_type)) return false;
        }
        for (const auto &parameter : type->parameters())
            if (!valid(parameter.name) || !schedule(parameter.type)) return false;
        for (const auto &method : type->methods()) {
            if (!valid(method.name) || !schedule(method.signature) || !schedule(method.this_type)) return false;
            for (const auto &slot : method.vtable_slots)
                if (!valid(slot.table_name) || !valid(slot.method_name)) return false;
        }
        for (const auto &member : type->static_data_members())
            if (!valid(member.name) || !schedule(member.type)) return false;
    }
    return true;
}
Sha256Digest sha256(std::span<const std::byte> bytes) {
    Sha256 hash;
    auto updated = hash.update(bytes);
    if (!updated) throw std::runtime_error(updated.error().message);
    return hash.digest();
}
bool valid_entry(const LibraryEntry &e) {
    return !e.name.empty() && e.name.size() <= max_name && valid_utf8_text(e.name) && e.type && valid_type_text(*e.type) &&
        static_cast<unsigned>(e.declaration_kind) <= 2 &&
        (!e.origin || (!e.origin->source_id.empty() && e.origin->source_id.size() <= 1024 &&
                       valid_utf8_text(e.origin->source_id) && !e.origin->section.empty() &&
                       e.origin->section.size() <= 256 && valid_utf8_text(e.origin->section) &&
                       e.origin->record_size));
}
bool file_assignment_fits(const LibraryAssignment &assignment, std::uint64_t input_size,
                          const std::map<std::string, std::optional<std::uint64_t>, std::less<>> &type_sizes) {
    const auto *file = std::get_if<FileOffset>(&assignment.location);
    if (!file) return true;
    if (file->value >= input_size) return false;
    const auto type = type_sizes.find(assignment.type_name);
    if (type == type_sizes.end() || !type->second) return true;
    return *type->second <= input_size - file->value;
}
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
  for(const auto&e:entries){if(!valid_entry(e)||!names.insert(e.name).second)return invalid("Type library definitions must have valid unique names and types");if(e.origin||e.declaration_kind!=LibraryDeclarationKind::type)return invalid("Legacy type library encoding cannot preserve declaration origins or non-type declarations");auto record=encode(*e.type);if(!record)return record.error();w.str(e.name);w.num(record.value().size(),4);w.raw(record.value());if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};}if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};return std::move(w.b);
 }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot encode type library"};}catch(const std::exception&e){return invalid(e.what());}
}
Result<std::vector<LibraryEntry>> decode_library(std::span<const std::byte> bytes,std::size_t max_bytes) {
 try {if(bytes.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};Reader r{bytes};if(r.num(1)!='H'||r.num(1)!='X'||r.num(1)!='T'||r.num(1)!='L')return invalid("Invalid type library signature");if(r.num(2)!=1)return invalid("Unsupported type library version");auto count=r.num(4);if(count>max_entries)return Error{ErrorCode::resource_limit,"Type library exceeds 4096 definitions"};std::vector<LibraryEntry> out;out.reserve(static_cast<std::size_t>(count));std::set<std::string> names;
  for(std::uint64_t i=0;i<count;++i){auto name=r.str(max_name);if(name.empty()||!valid_utf8_text(name)||!names.insert(name).second)return invalid("Type library names must be unique, nonempty UTF-8");auto n=r.num(4);if(n>max_record)return invalid("Invalid type record length");auto type=decode(r.take(static_cast<std::size_t>(n)));if(!type)return type.error();out.push_back({std::move(name),std::move(type.value())});}check_end(r);return out;
 }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot decode type library"};}catch(const std::exception&e){return invalid(e.what());}
}
Result<std::vector<std::byte>> encode_library_bundle(const LibraryBundle &bundle,std::size_t max_bytes) {
 try {if(bundle.entries.size()>max_entries)return Error{ErrorCode::resource_limit,"Type library exceeds 4096 definitions"};if(bundle.assignments.size()>262144)return Error{ErrorCode::resource_limit,"Type library exceeds assignment limit"};if(!bundle.source_identity&&!bundle.assignments.empty())return invalid("Type assignments require a source identity");if(std::any_of(bundle.assignments.begin(),bundle.assignments.end(),[](const auto &a){return std::holds_alternative<FileOffset>(a.location);})&&!bundle.file_offset_identity)return invalid("File-offset assignments require a binary identity");if(bundle.file_offset_identity&&bundle.source_identity&&(bundle.file_offset_identity->input_size!=bundle.source_identity->input_size||bundle.file_offset_identity->input_sha256!=bundle.source_identity->input_sha256))return invalid("File-offset binary identity must match the bundle source identity");
  Writer w;for(char c:std::string_view("HXTL"))w.b.push_back(std::byte(c));w.num(6,2);w.num((bundle.source_identity?1u:0u)|(bundle.file_offset_identity?2u:0u),2);w.num(bundle.entries.size(),4);w.num(bundle.assignments.size(),4);
  if(bundle.source_identity){w.num(bundle.source_identity->input_size,8);w.raw(bundle.source_identity->input_sha256);w.raw(bundle.source_identity->recipe_sha256);}
  if(bundle.file_offset_identity){w.num(bundle.file_offset_identity->input_size,8);w.raw(bundle.file_offset_identity->input_sha256);}
  std::set<std::string> names;std::map<std::string,std::optional<std::uint64_t>,std::less<>> type_sizes;for(auto &e:bundle.entries){if(!valid_entry(e)||!names.insert(e.name).second)return invalid("Type library definitions must have valid unique names and types");type_sizes.emplace(e.name,e.type->size());write_entry(w,e);if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};}
  std::set<std::string> locations;for(const auto &a:bundle.assignments){if(a.type_name.empty()||a.type_name.size()>max_name||!valid_utf8_text(a.type_name))return invalid("Invalid UTF-8 symbolic type assignment");std::string key;
   if(const auto *addr=std::get_if<Address>(&a.location)){w.num(0,1);w.num(addr->space.value,4);w.num(addr->offset,8);key="A:"+std::to_string(addr->space.value)+":"+std::to_string(addr->offset);}
   else {const auto offset=std::get<FileOffset>(a.location).value;if(!file_assignment_fits(a,bundle.file_offset_identity->input_size,type_sizes))return invalid("File-offset type assignment exceeds the identified input");w.num(1,1);w.num(offset,8);key="F:"+std::to_string(offset);}
   w.str(a.type_name);if(a.source_bytes){const auto *file=std::get_if<FileOffset>(&a.location);const auto type=type_sizes.find(a.type_name);if(!file||!a.source_bytes->size||type==type_sizes.end()||!type->second||*type->second!=a.source_bytes->size)return invalid("Source-byte witness must match a bundled file-offset type with known size");if(!bundle.source_identity||file->value>bundle.source_identity->input_size||a.source_bytes->size>bundle.source_identity->input_size-file->value)return invalid("Source-byte witness exceeds the identified input");w.num(1,1);w.num(a.source_bytes->size,8);w.raw(a.source_bytes->sha256);}else w.num(0,1);if(!locations.insert(key).second)return invalid("Duplicate type assignment location");if(w.b.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};}if(max_bytes<32||w.b.size()>max_bytes-32)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};const auto checksum=sha256(w.b);w.raw(checksum);return std::move(w.b);
 }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot encode type library"};}catch(const std::exception&e){return invalid(e.what());}
}
Result<LibraryBundle> decode_library_bundle(std::span<const std::byte> bytes,std::size_t max_bytes) {
 try {if(bytes.size()>max_bytes)return Error{ErrorCode::resource_limit,"Type library exceeds size limit"};Reader r{bytes};if(r.num(1)!='H'||r.num(1)!='X'||r.num(1)!='T'||r.num(1)!='L')return invalid("Invalid type library signature");auto version=r.num(2);if(version==4||version==5||version==6){if(bytes.size()<38)return invalid("Truncated checksummed type library");const auto payload=bytes.first(bytes.size()-32);const auto expected=sha256(payload);if(!std::equal(expected.begin(),expected.end(),bytes.end()-32))return invalid("Type library SHA-256 checksum mismatch");r.b=payload;}LibraryBundle out;
  if(version==1){auto count=r.num(4);if(count>max_entries)return Error{ErrorCode::resource_limit,"Type library exceeds 4096 definitions"};std::set<std::string> names;for(std::uint64_t i=0;i<count;++i){auto name=r.str(max_name);auto n=r.num(4);if(name.empty()||!valid_utf8_text(name)||!names.insert(name).second||n>max_record)return invalid("Invalid UTF-8 type library definition");auto type=decode(r.take(static_cast<std::size_t>(n)));if(!type)return type.error();out.entries.push_back({std::move(name),std::move(type.value())});}check_end(r);return out;}
   if(version!=2&&version!=3&&version!=4&&version!=5&&version!=6)return invalid("Unsupported type library version");auto flags=r.num(2);if(flags&~(version>=6?3u:1u))return invalid("Invalid type library flags");auto count=r.num(4),assignments=r.num(4);if(count>max_entries||assignments>262144)return Error{ErrorCode::resource_limit,"Type library count limit exceeded"};if(flags&1){LibrarySourceIdentity id;id.input_size=r.num(8);auto a=r.take(32),b=r.take(32);std::copy(a.begin(),a.end(),id.input_sha256.begin());std::copy(b.begin(),b.end(),id.recipe_sha256.begin());out.source_identity=id;}if(flags&2){LibraryBinaryIdentity id;id.input_size=r.num(8);auto a=r.take(32);std::copy(a.begin(),a.end(),id.input_sha256.begin());out.file_offset_identity=id;}if(assignments&&!out.source_identity)return invalid("Type assignments require a source identity");if(out.file_offset_identity&&out.source_identity&&(out.file_offset_identity->input_size!=out.source_identity->input_size||out.file_offset_identity->input_sha256!=out.source_identity->input_sha256))return invalid("File-offset binary identity does not match the bundle source identity");std::set<std::string> names;out.entries.reserve(count);for(std::uint64_t i=0;i<count;++i){auto e=read_entry(r);if(!names.insert(e.name).second)return invalid("Duplicate type library definition");out.entries.push_back(std::move(e));}std::map<std::string,std::optional<std::uint64_t>,std::less<>> type_sizes;for(const auto &entry:out.entries)type_sizes.emplace(entry.name,entry.type->size());
  std::set<std::string> locations;out.assignments.reserve(assignments);bool has_file_offsets=false;for(std::uint64_t i=0;i<assignments;++i){auto tag=r.num(1);Location loc;std::string key;if(tag==0){auto space=r.num(4),off=r.num(8);Address addr{AddressSpaceId{static_cast<std::uint32_t>(space)},off};loc=addr;key="A:"+std::to_string(addr.space.value)+":"+std::to_string(addr.offset);}else if(tag==1&&version>=3){auto off=r.num(8);loc=FileOffset{off};has_file_offsets=true;key="F:"+std::to_string(off);}else return invalid("Invalid type assignment location tag");auto name=r.str(max_name);if(name.empty()||!valid_utf8_text(name))return invalid("Invalid UTF-8 symbolic type assignment");LibraryAssignment assignment{loc,std::move(name)};if(std::holds_alternative<FileOffset>(loc)&&out.source_identity&&!file_assignment_fits(assignment,out.source_identity->input_size,type_sizes))return invalid("File-offset type assignment exceeds the identified input");if(version>=5){auto has_source_bytes=r.num(1);if(has_source_bytes>1)return invalid("Invalid type assignment source-byte witness flag");if(has_source_bytes){const auto *file=std::get_if<FileOffset>(&loc);if(!file)return invalid("Source-byte witness requires a file-offset assignment");LibraryAssignment::SourceBytes witness;witness.size=r.num(8);if(!witness.size)return invalid("Empty type assignment source-byte witness");const auto type=type_sizes.find(assignment.type_name);if(type==type_sizes.end()||!type->second||*type->second!=witness.size)return invalid("Source-byte witness must match a bundled file-offset type with known size");if(file->value>out.source_identity->input_size||witness.size>out.source_identity->input_size-file->value)return invalid("Source-byte witness exceeds the identified input");auto digest=r.take(32);std::copy(digest.begin(),digest.end(),witness.sha256.begin());assignment.source_bytes=witness;}}if(!locations.insert(key).second)return invalid("Duplicate type assignment location");out.assignments.push_back(std::move(assignment));}if(version>=6&&has_file_offsets&&!out.file_offset_identity)return invalid("HXTL v6 file-offset assignments require a binary identity");check_end(r);return out;
 }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot decode type library"};}catch(const std::exception&e){return invalid(e.what());}
}
Result<std::vector<LibraryEntry>> merge_library_definitions(
    std::span<const LibraryBundle> bundles,
    const std::set<std::string, std::less<>> &available_names,
    std::size_t max_type_nodes) {
    struct Candidate {
        LibraryEntry entry;
        std::vector<std::byte> encoded_type;
    };
    constexpr std::size_t max_input_entries = 65'536;
    try {
        std::map<std::string, Candidate, std::less<>> merged;
        std::size_t input_entries = 0;
        for (const auto &bundle : bundles) {
            if (!bundle.assignments.empty())
                return invalid("Definition merge does not carry source-specific type assignments");
            if (bundle.entries.size() > max_entries ||
                bundle.entries.size() > max_input_entries - input_entries)
                return Error{ErrorCode::resource_limit, "Type library merge input exceeds 65,536 definitions"};
            input_entries += bundle.entries.size();
            std::set<std::string, std::less<>> bundle_names;
            for (const auto &entry : bundle.entries) {
                if (!valid_entry(entry) || !bundle_names.insert(entry.name).second)
                    return invalid("Type library merge inputs must have valid unique definitions");
                auto encoded = encode(*entry.type);
                if (!encoded) return encoded.error();
                const auto existing = merged.find(entry.name);
                if (existing != merged.end()) {
                    if (existing->second.entry.declaration_kind != entry.declaration_kind ||
                        existing->second.entry.origin != entry.origin ||
                        existing->second.encoded_type != encoded.value())
                        return invalid("Conflicting portable type definition " + entry.name);
                    continue;
                }
                if (merged.size() == max_entries)
                    return Error{ErrorCode::resource_limit, "Merged type library exceeds 4096 definitions"};
                merged.emplace(entry.name, Candidate{entry, std::move(encoded.value())});
            }
        }

        std::vector<LibraryEntry> result;
        result.reserve(merged.size());
        for (auto &[name, candidate] : merged) {
            (void)name;
            result.push_back(std::move(candidate.entry));
        }
        LibraryBundle validation;
        validation.entries = result;
        auto checked = validate_library_references(validation, available_names, max_type_nodes);
        if (!checked) return checked.error();
        return result;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot merge portable type definitions"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Portable type definition merge exceeds host limits"};
    }
}
Result<LibraryAssignmentSelection> select_library_assignments(
    const LibraryBundle &bundle, const std::optional<LibrarySourceIdentity> &destination_source,
    const std::optional<LibraryBinaryIdentity> &destination_binary,
    const LibraryAssignmentSourceVerifier &verify_source_bytes) {
    try {
        if (bundle.assignments.size() > 262144)
            return Error{ErrorCode::resource_limit, "Type library exceeds assignment limit"};
        if (!bundle.assignments.empty() && !bundle.source_identity)
            return invalid("Type assignments require a source identity");
        if (bundle.file_offset_identity && bundle.source_identity &&
            (bundle.file_offset_identity->input_size != bundle.source_identity->input_size ||
             bundle.file_offset_identity->input_sha256 != bundle.source_identity->input_sha256))
            return invalid("File-offset binary identity must match the bundle source identity");

        std::map<std::string, std::optional<std::uint64_t>, std::less<>> type_sizes;
        for (const auto &entry : bundle.entries) {
            if (!entry.type || entry.name.empty() || entry.name.size() > max_name ||
                !valid_utf8_text(entry.name) || !type_sizes.emplace(entry.name, entry.type->size()).second)
                return invalid("Type library definitions must have valid unique names and types");
        }

        LibraryAssignmentSelection selection;
        selection.applicable.reserve(bundle.assignments.size());
        selection.skipped.reserve(bundle.assignments.size());
        for (const auto &assignment : bundle.assignments) {
            if (assignment.type_name.empty() || assignment.type_name.size() > max_name ||
                !valid_utf8_text(assignment.type_name))
                return invalid("Invalid UTF-8 symbolic type assignment");

            if (const auto *file = std::get_if<FileOffset>(&assignment.location)) {
                if (!bundle.file_offset_identity)
                    return invalid("File-offset assignments require a binary identity");
                if (!file_assignment_fits(assignment, bundle.file_offset_identity->input_size, type_sizes))
                    return invalid("File-offset type assignment exceeds the identified input");
                if (assignment.source_bytes) {
                    const auto &witness = *assignment.source_bytes;
                    const auto type = type_sizes.find(assignment.type_name);
                    if (!bundle.source_identity || !witness.size || type == type_sizes.end() || !type->second ||
                        *type->second != witness.size || file->value > bundle.source_identity->input_size ||
                        witness.size > bundle.source_identity->input_size - file->value)
                        return invalid("Invalid file-offset assignment source-byte witness");
                }
                if (!destination_binary || *destination_binary != *bundle.file_offset_identity) {
                    selection.skipped.push_back(
                        {assignment, LibraryAssignmentSkipReason::binary_identity_mismatch});
                    continue;
                }
                if (assignment.source_bytes) {
                    if (!verify_source_bytes) {
                        selection.skipped.push_back(
                            {assignment, LibraryAssignmentSkipReason::source_byte_verifier_unavailable});
                        continue;
                    }
                    auto matches = verify_source_bytes(*file, *assignment.source_bytes);
                    if (!matches) return matches.error();
                    if (!matches.value()) {
                        selection.skipped.push_back(
                            {assignment, LibraryAssignmentSkipReason::source_bytes_mismatch});
                        continue;
                    }
                }
                selection.applicable.push_back(assignment);
            } else {
                if (assignment.source_bytes)
                    return invalid("Source-byte witness requires a file-offset assignment");
                if (!destination_source || *destination_source != *bundle.source_identity) {
                    selection.skipped.push_back(
                        {assignment, LibraryAssignmentSkipReason::source_identity_mismatch});
                    continue;
                }
                selection.applicable.push_back(assignment);
            }
        }
        return selection;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot select portable type assignments"};
    }
}
Result<LibraryImportPlan> prepare_library_import(
    const LibraryBundle &bundle, const std::set<std::string, std::less<>> &available_names,
    const std::optional<LibrarySourceIdentity> &destination_source,
    const std::optional<LibraryBinaryIdentity> &destination_binary,
    const LibraryAssignmentSourceVerifier &verify_source_bytes,
    std::size_t max_type_nodes) {
    auto validated = validate_library_references(bundle, available_names, max_type_nodes);
    if (!validated) return validated.error();
    auto selected = select_library_assignments(bundle, destination_source, destination_binary,
                                               verify_source_bytes);
    if (!selected) return selected.error();
    try {
        std::set<std::string, std::less<>> resolvable = available_names;
        for (const auto &entry : bundle.entries) resolvable.insert(entry.name);
        std::set<std::string> locations;
        for (const auto &assignment : selected.value().applicable) {
            if (!resolvable.contains(assignment.type_name))
                return invalid("Selected type assignment names missing definition " + assignment.type_name);
            std::string key;
            if (const auto *address = std::get_if<Address>(&assignment.location))
                key = "A:" + std::to_string(address->space.value) + ":" + std::to_string(address->offset);
            else
                key = "F:" + std::to_string(std::get<FileOffset>(assignment.location).value);
            if (!locations.insert(std::move(key)).second)
                return invalid("Selected type assignments contain duplicate locations");
        }
        return LibraryImportPlan{std::move(selected.value()), validated.value()};
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot prepare portable type-library import"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Portable type-library import plan exceeds host limits"};
    }
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
