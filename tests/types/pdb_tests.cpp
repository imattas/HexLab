#include "hexlab/types/pdb.hpp"
#include "hexlab/types/pdb_import.hpp"
#include "hexlab/types/layout.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <stop_token>
#include <iterator>
#include <vector>

namespace {
enum class ArtifactEnum : std::int32_t { ready = 5, done = -7 };

void put(std::vector<std::byte> &data, std::size_t offset, std::uint64_t value, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
        data.at(offset + i) = static_cast<std::byte>((value >> (i * 8)) & 0xff);
}
std::vector<std::byte> fixture() {
    constexpr std::size_t block = 512;
    std::vector<std::byte> data(block * 5);
    constexpr char magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0";
    for (std::size_t i = 0; i < sizeof(magic) - 1; ++i)
        data[i] = static_cast<std::byte>(magic[i]);
    put(data, 32, block, 4);
    put(data, 36, 1, 4); // Free block map.
    put(data, 40, 5, 4); // Number of blocks.
    put(data, 44, 20, 4); // Directory bytes.
    put(data, 52, 2, 4); // Block-map block.
    put(data, 2 * block, 3, 4); // Directory is block 3.
    put(data, 3 * block, 3, 4); // Three streams.
    put(data, 3 * block + 4, 0xffffffff, 4); // Stream 0 absent.
    put(data, 3 * block + 8, 28, 4); // PDB info stream.
    put(data, 3 * block + 12, 0xffffffff, 4); // TPI stream absent.
    put(data, 3 * block + 16, 4, 4); // PDB info is block 4.
    put(data, 4 * block, 20000404, 4); // PDB 7.0 version.
    put(data, 4 * block + 4, 0x12345678, 4); // Signature.
    put(data, 4 * block + 8, 7, 4); // Age.
    for (std::size_t i = 0; i < 16; ++i)
        data[4 * block + 12 + i] = static_cast<std::byte>(i + 1);
    return data;
}
}

int main(int argc, char **argv) {
    volatile auto artifact_enum_anchor = ArtifactEnum::done;
    (void)artifact_enum_anchor;
    const auto valid = fixture();
    const auto parsed = hexlab::types::parse_pdb(valid);
    if (!parsed) {
        std::cerr << parsed.error().message << '\n';
        return 1;
    }
    if (parsed.value().block_size != 512 || parsed.value().streams.size() != 3 ||
        parsed.value().streams[0].has_value() || !parsed.value().streams[1] ||
        parsed.value().streams[2].has_value())
        return 2;
    if (parsed.value().info.age != 7 || parsed.value().info.signature != 0x12345678)
        return 3;
    for (std::size_t i = 0; i < 16; ++i)
        if (parsed.value().info.guid[i] != static_cast<std::byte>(i + 1))
            return 4;

    auto malformed = valid;
    put(malformed, 32, 513, 4);
    if (hexlab::types::parse_pdb(malformed))
        return 5;
    malformed = valid;
    put(malformed, 40, 4, 4); // Block map references a block outside declared file.
    if (hexlab::types::parse_pdb(malformed))
        return 6;
    malformed = valid;
    put(malformed, 3 * 512 + 8, 0x7fffffff, 4);
    if (hexlab::types::parse_pdb(malformed))
        return 7;
    std::stop_source stopped;
    stopped.request_stop();
    const auto canceled = hexlab::types::parse_pdb(valid, stopped.get_token());
    if (canceled || canceled.error().code != hexlab::ErrorCode::canceled)
        return 8;
    // A compact TPI exercising LF_FIELDLIST/LF_MEMBER, LF_STRUCTURE, LF_ARRAY, LF_POINTER.
    hexlab::types::PdbDatabase types_db; types_db.streams.resize(3); types_db.streams[2].emplace(56, std::byte{0});
    auto &tpi = *types_db.streams[2];
    auto append16 = [&](std::uint16_t x) { auto n=tpi.size(); tpi.resize(n+2); put(tpi,n,x,2); };
    auto append32 = [&](std::uint32_t x) { auto n=tpi.size(); tpi.resize(n+4); put(tpi,n,x,4); };
    auto record = [&](std::uint16_t leaf, const std::vector<std::byte> &body) { append16(static_cast<std::uint16_t>(body.size()+2)); append16(leaf); tpi.insert(tpi.end(),body.begin(),body.end()); };
    auto body16=[](std::uint16_t x){std::vector<std::byte>b(2);put(b,0,x,2);return b;};
    auto body32=[](std::uint32_t x){std::vector<std::byte>b(4);put(b,0,x,4);return b;};
    std::vector<std::byte> field; auto add=[&](std::uint64_t v,std::size_t w){auto n=field.size();field.resize(n+w);put(field,n,v,w);};
    add(0x150d,2); add(3,2); add(0x74,4); add(0,2); add('x',1); add(0,1); add(0x1404,2); add(0,2); add(0x1009,4); field.push_back(std::byte{0xf2}); field.push_back(std::byte{0xf1}); record(0x1203,field);
    std::vector<std::byte> st; auto s16=[&](std::uint64_t x){auto n=st.size();st.resize(n+2);put(st,n,x,2);}; auto s32=[&](std::uint64_t x){auto n=st.size();st.resize(n+4);put(st,n,x,4);};
    s16(1);s16(0);s32(0x1000);s32(0);s32(0);s16(4);s16('S');s16(0);record(0x1505,st);
    std::vector<std::byte> arr; auto a32=[&](std::uint64_t x){auto n=arr.size();arr.resize(n+4);put(arr,n,x,4);}; a32(0x74);a32(0x74);arr.push_back(std::byte{8});arr.push_back(std::byte{0});arr.push_back(std::byte{'A'});arr.push_back(std::byte{0});record(0x1503,arr);
    auto pointer_bytes = body32(0x1001); pointer_bytes.resize(8); put(pointer_bytes, 4, 0x0c | 0x100 | (8u << 13), 4); record(0x1002,pointer_bytes);
    std::vector<std::byte> enumerator; auto e16=[&](std::uint16_t x){auto n=enumerator.size();enumerator.resize(n+2);put(enumerator,n,x,2);};
    e16(0x1502); e16(0); e16(42); enumerator.push_back(std::byte{'E'}); enumerator.push_back(std::byte{0}); record(0x1203,enumerator);
    std::vector<std::byte> enumeration; auto en16=[&](std::uint16_t x){auto n=enumeration.size();enumeration.resize(n+2);put(enumeration,n,x,2);};
    auto en32=[&](std::uint32_t x){auto n=enumeration.size();enumeration.resize(n+4);put(enumeration,n,x,4);};
    en16(1); en16(0); en32(0x74); en32(0x1004); enumeration.push_back(std::byte{'T'}); enumeration.push_back(std::byte{0}); record(0x1507,enumeration);
    std::vector<std::byte> union_type; auto un16=[&](std::uint16_t x){auto n=union_type.size();union_type.resize(n+2);put(union_type,n,x,2);};
    auto un32=[&](std::uint32_t x){auto n=union_type.size();union_type.resize(n+4);put(union_type,n,x,4);};
    un16(0); un16(0); un32(0); un16(4); union_type.push_back(std::byte{'U'}); union_type.push_back(std::byte{0}); record(0x1506,union_type);
    record(0x7777,body32(0));
    record(0x1203,body16(0x9999));
    std::vector<std::byte> continued; auto c16=[&](std::uint16_t x){auto n=continued.size();continued.resize(n+2);put(continued,n,x,2);}; auto c32=[&](std::uint32_t x){auto n=continued.size();continued.resize(n+4);put(continued,n,x,4);};
    c16(0x150d); c16(0); c32(0x74); c16(4); continued.push_back(std::byte{'y'}); continued.push_back(std::byte{0}); record(0x1203,continued);
    std::vector<std::byte> alias=body32(0x1001); alias.push_back(std::byte{'S'}); alias.push_back(std::byte{'A'}); alias.push_back(std::byte{0}); record(0x150a,alias);
    std::vector<std::byte> cls; auto cl16=[&](std::uint16_t x){auto n=cls.size();cls.resize(n+2);put(cls,n,x,2);}; auto cl32=[&](std::uint32_t x){auto n=cls.size();cls.resize(n+4);put(cls,n,x,4);};
    cl16(0); cl16(0); cl32(0); cl32(0); cl32(0); cl16(0); cl16('Q'); cl16(0); record(0x1504,cls);
    put(tpi,0,20040203,4); put(tpi,4,56,4); put(tpi,8,0x1000,4); put(tpi,12,0x100c,4); put(tpi,16,static_cast<std::uint32_t>(tpi.size()-56),4);
    const auto decoded=hexlab::types::parse_pdb_types(types_db);
    if(!decoded) { std::cerr << decoded.error().message << '\n'; return 13; }
    if(!decoded || decoded.value().records.size()!=12 || decoded.value().records[0].fields.size()!=1 || decoded.value().records[0].field_list_continuations.size()!=1 || decoded.value().records[1].name!="S" || decoded.value().records[1].size!=4 || decoded.value().records[2].size!=8 || decoded.value().records[3].referenced_type!=0x1001 || decoded.value().records[3].size!=8 || decoded.value().records[4].fields.size()!=1 || decoded.value().records[4].fields[0].name!="E" || decoded.value().records[4].fields[0].value!=42 || decoded.value().records[5].kind!=hexlab::types::CodeViewTypeKind::enumeration || decoded.value().records[5].field_list!=0x1004 || decoded.value().records[6].kind!=hexlab::types::CodeViewTypeKind::union_type || decoded.value().records[6].size!=4 || decoded.value().records[7].kind!=hexlab::types::CodeViewTypeKind::unsupported || decoded.value().records[7].leaf!=0x7777 || decoded.value().records[8].fields.size()!=1 || decoded.value().records[8].fields[0].leaf!=0x9999 || decoded.value().records[10].kind!=hexlab::types::CodeViewTypeKind::typedef_type || decoded.value().records[10].name!="SA" || decoded.value().records[11].kind!=hexlab::types::CodeViewTypeKind::class_type) { std::cerr << "unexpected decoded PDB type or enum leaf state\n"; return 13; }
    if(decoded.value().records[3].pointer_kind!=0x0c || decoded.value().records[3].pointer_mode!=0 ||
       decoded.value().records[3].pointer_options!=0x100) return 31;
    auto decoded_graph=hexlab::types::resolve_pdb_type_graph(decoded.value());
    if(!decoded_graph || decoded_graph.value().nodes[1].expanded_fields.size()!=2 ||
       std::none_of(decoded_graph.value().references.begin(),decoded_graph.value().references.end(),[](const auto &edge){return edge.kind==hexlab::types::PdbTypeReferenceKind::typedef_target && edge.target_index==0x1001 && edge.resolved;})) {
        std::cerr << "parsed LF_INDEX and LF_ALIAS records were not represented in the type graph\n"; return 17;
    }
    if(std::none_of(decoded_graph.value().references.begin(),decoded_graph.value().references.end(),[](const auto &edge){return edge.kind==hexlab::types::PdbTypeReferenceKind::member && edge.target_index==0x74 && edge.primitive && edge.resolved;})) return 30;
    auto imported_graph = hexlab::types::import_pdb_type_graph(decoded_graph.value());
    if (!imported_graph || !imported_graph.value().definitions.contains("T") ||
        imported_graph.value().definitions.at("T")->kind() != hexlab::types::Kind::enumeration ||
        imported_graph.value().definitions.at("T")->enumerator_values().size() != 1 ||
        imported_graph.value().definitions.at("T")->enumerator_values()[0].value != 42) return 32;
    // Static members and nested type declarations carry type edges but are
    // not instance fields in the project aggregate layout.
    hexlab::types::PdbDatabase extended_fields_db; extended_fields_db.streams.resize(3);
    extended_fields_db.streams[2].emplace(56, std::byte{0});
    auto &extended_tpi = *extended_fields_db.streams[2];
    auto ext16=[&](std::uint16_t x){auto n=extended_tpi.size();extended_tpi.resize(n+2);put(extended_tpi,n,x,2);};
    auto ext_record=[&](std::uint16_t leaf,const std::vector<std::byte>& body){ext16(static_cast<std::uint16_t>(body.size()+2));ext16(leaf);extended_tpi.insert(extended_tpi.end(),body.begin(),body.end());};
    std::vector<std::byte> extended_list;
    auto lf16=[&](std::uint16_t x){auto n=extended_list.size();extended_list.resize(n+2);put(extended_list,n,x,2);};
    auto lf32=[&](std::uint32_t x){auto n=extended_list.size();extended_list.resize(n+4);put(extended_list,n,x,4);};
    lf16(0x150e);lf16(0);lf32(0x74);extended_list.insert(extended_list.end(),{std::byte{'c'},std::byte{'o'},std::byte{'u'},std::byte{'n'},std::byte{'t'},std::byte{'e'},std::byte{'r'},std::byte{0}});
    lf16(0x1510);lf16(0);lf32(0x75);extended_list.insert(extended_list.end(),{std::byte{'N'},std::byte{'e'},std::byte{'s'},std::byte{'t'},std::byte{'e'},std::byte{'d'},std::byte{0}});
    ext_record(0x1203,extended_list);
    std::vector<std::byte> extended_struct(20);put(extended_struct,4,0x1000,4);put(extended_struct,16,4,2);extended_struct[18]=std::byte{'H'};extended_struct[19]=std::byte{0};ext_record(0x1505,extended_struct);
    put(extended_tpi,0,20040203,4);put(extended_tpi,4,56,4);put(extended_tpi,8,0x1000,4);put(extended_tpi,12,0x1002,4);put(extended_tpi,16,extended_tpi.size()-56,4);
    auto extended_parsed=hexlab::types::parse_pdb_types(extended_fields_db);
    if(!extended_parsed || extended_parsed.value().records[0].fields.size()!=2 ||
       extended_parsed.value().records[0].fields[0].leaf!=0x150e || extended_parsed.value().records[0].fields[0].type!=0x74 || extended_parsed.value().records[0].fields[0].name!="counter" ||
       extended_parsed.value().records[0].fields[1].leaf!=0x1510 || extended_parsed.value().records[0].fields[1].type!=0x75 || extended_parsed.value().records[0].fields[1].name!="Nested") return 52;
    auto extended_graph=hexlab::types::resolve_pdb_type_graph(extended_parsed.value());
    if(!extended_graph || extended_graph.value().nodes[1].expanded_fields.size()!=2 ||
       std::none_of(extended_graph.value().references.begin(),extended_graph.value().references.end(),[](const auto &edge){return edge.kind==hexlab::types::PdbTypeReferenceKind::member && edge.target_index==0x74 && edge.primitive && edge.resolved;}) ||
       std::none_of(extended_graph.value().references.begin(),extended_graph.value().references.end(),[](const auto &edge){return edge.kind==hexlab::types::PdbTypeReferenceKind::nested_type && edge.target_index==0x75 && edge.primitive && edge.resolved;})) return 53;
    auto extended_import=hexlab::types::import_pdb_type_graph(extended_graph.value());
    if(!extended_import || !extended_import.value().definitions.contains("H") ||
       extended_import.value().definitions.at("H")->kind()!=hexlab::types::Kind::structure ||
       extended_import.value().definitions.at("H")->size()!=4 ||
       !extended_import.value().definitions.at("H")->members().empty()) return 54;
    hexlab::types::PdbDatabase malformed_static_db; malformed_static_db.streams.resize(3); malformed_static_db.streams[2].emplace(56+12,std::byte{0});
    auto &malformed_static=*malformed_static_db.streams[2];put(malformed_static,0,20040203,4);put(malformed_static,4,56,4);put(malformed_static,8,0x1000,4);put(malformed_static,12,0x1001,4);put(malformed_static,16,12,4);
    put(malformed_static,56,10,2);put(malformed_static,58,0x1203,2);put(malformed_static,60,0x150e,2);put(malformed_static,62,0,2);put(malformed_static,64,0x74,4);
    if(hexlab::types::parse_pdb_types(malformed_static_db)) return 55;
    hexlab::types::PdbTypeStream cyclic; cyclic.type_index_begin=0x1000; cyclic.type_index_end=0x1007;
    hexlab::types::CodeViewTypeRecord fl; fl.index=0x1000; fl.kind=hexlab::types::CodeViewTypeKind::field_list;
    fl.fields.push_back({0x150d,0x1002,0,0,"next"}); fl.field_list_continuations.push_back(0x1003);
    hexlab::types::CodeViewTypeRecord structure; structure.index=0x1001; structure.kind=hexlab::types::CodeViewTypeKind::structure; structure.name="Node"; structure.field_list=0x1000;
    hexlab::types::CodeViewTypeRecord pointer; pointer.index=0x1002; pointer.kind=hexlab::types::CodeViewTypeKind::pointer; pointer.referenced_type=0x1001;
    hexlab::types::CodeViewTypeRecord tail; tail.index=0x1003; tail.kind=hexlab::types::CodeViewTypeKind::field_list;
    tail.fields.push_back({0x150d,0x74,0,8,"value"}); tail.field_list_continuations.push_back(0x1000);
    auto forward=structure; forward.index=0x1004; forward.forward_declaration=true; forward.field_list=0; cyclic.records={fl,structure,pointer,tail,forward};
    auto missing=pointer; missing.index=0x1005; missing.kind=hexlab::types::CodeViewTypeKind::typedef_type; missing.referenced_type=0x5000; missing.name="Missing";
    hexlab::types::CodeViewTypeRecord unsupported; unsupported.index=0x1006; unsupported.leaf=0x7777; unsupported.kind=hexlab::types::CodeViewTypeKind::unsupported;
    cyclic.records.push_back(missing); cyclic.records.push_back(unsupported);
    auto graph=hexlab::types::resolve_pdb_type_graph(cyclic);
    if(!graph || graph.value().nodes.size()!=7 || graph.value().nodes[1].expanded_fields.size()!=2 || graph.value().nodes[4].canonical_index!=0x1001 || graph.value().nodes[6].record.kind!=hexlab::types::CodeViewTypeKind::unsupported ||
       std::none_of(graph.value().references.begin(),graph.value().references.end(),[](const auto &edge){return edge.source_index==0x1002 && edge.target_index==0x1001 && edge.resolved;}) ||
       std::none_of(graph.value().references.begin(),graph.value().references.end(),[](const auto &edge){return edge.source_index==0x1000 && edge.target_index==0x1003 && edge.resolved;}) ||
       std::none_of(graph.value().references.begin(),graph.value().references.end(),[](const auto &edge){return edge.source_index==0x1005 && edge.target_index==0x5000 && !edge.resolved;})) {
        std::cerr << "PDB TPI graph did not resolve cyclic and continued type references safely\n"; return 16;
    }
    const auto canceled_graph=hexlab::types::resolve_pdb_type_graph(cyclic,stopped.get_token());
    if(canceled_graph || canceled_graph.error().code!=hexlab::ErrorCode::canceled) return 29;
    auto bad_db=types_db; (*bad_db.streams[2])[56]=std::byte{0xff};
    if(hexlab::types::parse_pdb_types(bad_db)) return 14;
    hexlab::types::PdbDatabase malformed_enum_db; malformed_enum_db.streams.resize(3);
    malformed_enum_db.streams[2].emplace(56, std::byte{0});
    auto &malformed_enum_tpi = *malformed_enum_db.streams[2];
    const std::vector<std::byte> truncated_enumerator{std::byte{0x02}, std::byte{0x15}, // LF_ENUMERATE
        std::byte{0}, std::byte{0}, std::byte{0x03}, std::byte{0x80}, // signed 8-byte numeric leaf
        std::byte{0x01}, std::byte{0x02}, std::byte{0x03}}; // deliberately short payload
    malformed_enum_tpi.resize(56 + 4 + truncated_enumerator.size());
    put(malformed_enum_tpi, 56, truncated_enumerator.size() + 2, 2);
    put(malformed_enum_tpi, 58, 0x1203, 2); // LF_FIELDLIST
    std::copy(truncated_enumerator.begin(), truncated_enumerator.end(), malformed_enum_tpi.begin() + 60);
    put(malformed_enum_tpi, 0, 20040203, 4); put(malformed_enum_tpi, 4, 56, 4);
    put(malformed_enum_tpi, 8, 0x1000, 4); put(malformed_enum_tpi, 12, 0x1001, 4);
    put(malformed_enum_tpi, 16, malformed_enum_tpi.size() - 56, 4);
    if (hexlab::types::parse_pdb_types(malformed_enum_db)) return 42;
    const auto canceled_types=hexlab::types::parse_pdb_types(types_db,stopped.get_token());
    if(canceled_types || canceled_types.error().code!=hexlab::ErrorCode::canceled) return 15;
    // LF_BITFIELD keeps its storage type, declared width, and LSB-relative position.
    hexlab::types::PdbDatabase bitfield_db; bitfield_db.streams.resize(3);
    bitfield_db.streams[2].emplace(56, std::byte{0});
    auto &bf_tpi=*bitfield_db.streams[2];
    auto bf16=[&](std::uint16_t x){auto n=bf_tpi.size();bf_tpi.resize(n+2);put(bf_tpi,n,x,2);};
    auto bf32=[&](std::uint32_t x){auto n=bf_tpi.size();bf_tpi.resize(n+4);put(bf_tpi,n,x,4);};
    auto bf_record=[&](std::uint16_t leaf,const std::vector<std::byte>& body){bf16(static_cast<std::uint16_t>(body.size()+2));bf16(leaf);bf_tpi.insert(bf_tpi.end(),body.begin(),body.end());};
    std::vector<std::byte> bf_body(6); put(bf_body,0,0x74,4); bf_body[4]=std::byte{3}; bf_body[5]=std::byte{5};
    bf_record(0x1205,bf_body);
    std::vector<std::byte> bf_fields; auto bf_add=[&](std::uint64_t v,std::size_t w){auto n=bf_fields.size();bf_fields.resize(n+w);put(bf_fields,n,v,w);};
    bf_add(0x150d,2);bf_add(0,2);bf_add(0x1000,4);bf_add(0,2);bf_fields.push_back(std::byte{'f'});bf_fields.push_back(std::byte{0});
    bf_record(0x1203,bf_fields);
    std::vector<std::byte> bf_struct(20); put(bf_struct,0,1,2);put(bf_struct,2,0,2);put(bf_struct,4,0x1001,4);put(bf_struct,16,4,2);put(bf_struct,18,'B',1);
    bf_record(0x1505,bf_struct);
    put(bf_tpi,0,20040203,4);put(bf_tpi,4,56,4);put(bf_tpi,8,0x1000,4);put(bf_tpi,12,0x1003,4);put(bf_tpi,16,bf_tpi.size()-56,4);
    auto bf_parsed=hexlab::types::parse_pdb_types(bitfield_db);
    if(!bf_parsed || bf_parsed.value().records[0].kind!=hexlab::types::CodeViewTypeKind::bitfield ||
       bf_parsed.value().records[0].referenced_type!=0x74 || bf_parsed.value().records[0].bitfield_width!=3 ||
       bf_parsed.value().records[0].bitfield_position!=5) return 49;
    auto bf_graph=hexlab::types::resolve_pdb_type_graph(bf_parsed.value());
    auto bf_import=bf_graph ? hexlab::types::import_pdb_type_graph(bf_graph.value()) : hexlab::Result<hexlab::types::PdbTypeImportResult>(bf_graph.error());
    if(!bf_import || !bf_import.value().definitions.contains("B") ||
       bf_import.value().definitions.at("B")->members()[0].bit_width!=3 ||
       bf_import.value().definitions.at("B")->members()[0].bit_offset!=5) return 50;
    auto truncated_bitfield_db=bitfield_db;
    truncated_bitfield_db.streams[2]->pop_back();
    put(*truncated_bitfield_db.streams[2],16,truncated_bitfield_db.streams[2]->size()-56,4);
    auto truncated_bitfield=hexlab::types::parse_pdb_types(truncated_bitfield_db);
    if(truncated_bitfield || truncated_bitfield.error().code!=hexlab::ErrorCode::malformed) return 51;
    // LF_BCLASS is a non-virtual base subobject with an explicit byte offset.
    hexlab::types::PdbDatabase base_db; base_db.streams.resize(3);
    base_db.streams[2].emplace(56, std::byte{0}); auto &base_tpi=*base_db.streams[2];
    auto bt16=[&](std::uint16_t x){auto n=base_tpi.size();base_tpi.resize(n+2);put(base_tpi,n,x,2);};
    auto bt32=[&](std::uint32_t x){auto n=base_tpi.size();base_tpi.resize(n+4);put(base_tpi,n,x,4);};
    auto bt_record=[&](std::uint16_t leaf,const std::vector<std::byte>& body){bt16(static_cast<std::uint16_t>(body.size()+2));bt16(leaf);base_tpi.insert(base_tpi.end(),body.begin(),body.end());};
    std::vector<std::byte> base_fields; auto b16=[&](std::uint16_t x){auto n=base_fields.size();base_fields.resize(n+2);put(base_fields,n,x,2);}; auto b32=[&](std::uint32_t x){auto n=base_fields.size();base_fields.resize(n+4);put(base_fields,n,x,4);};
    b16(0x150d);b16(0);b32(0x74);b16(0);base_fields.insert(base_fields.end(),{std::byte{'x'},std::byte{0}});bt_record(0x1203,base_fields);
    std::vector<std::byte> derived_fields;auto d16=[&](std::uint16_t x){auto n=derived_fields.size();derived_fields.resize(n+2);put(derived_fields,n,x,2);};auto d32=[&](std::uint32_t x){auto n=derived_fields.size();derived_fields.resize(n+4);put(derived_fields,n,x,4);};
    d16(0x1400);d16(3);d32(0x1002);d16(0);d16(0x150d);d16(0);d32(0x74);d16(4);derived_fields.insert(derived_fields.end(),{std::byte{'y'},std::byte{0}});bt_record(0x1203,derived_fields);
    std::vector<std::byte> base_forward(20);put(base_forward,2,0x80,2);base_forward[18]=std::byte{'B'};bt_record(0x1505,base_forward);
    std::vector<std::byte> derived_type(20);put(derived_type,0,2,2);put(derived_type,4,0x1001,4);put(derived_type,16,8,2);derived_type[18]=std::byte{'D'};derived_type[19]=std::byte{0};bt_record(0x1505,derived_type);
    std::vector<std::byte> base_type(20);put(base_type,0,1,2);put(base_type,4,0x1000,4);put(base_type,16,4,2);base_type[18]=std::byte{'B'};base_type[19]=std::byte{0};bt_record(0x1505,base_type);
    put(base_tpi,0,20040203,4);put(base_tpi,4,56,4);put(base_tpi,8,0x1000,4);put(base_tpi,12,0x1005,4);put(base_tpi,16,base_tpi.size()-56,4);
    auto base_parsed=hexlab::types::parse_pdb_types(base_db); if(!base_parsed) return 56;
    if(base_parsed.value().records[1].fields.size()!=2 || base_parsed.value().records[1].fields[0].leaf!=0x1400 ||
       base_parsed.value().records[1].fields[0].type!=0x1002 || base_parsed.value().records[1].fields[0].offset!=0 || !base_parsed.value().records[2].forward_declaration || base_parsed.value().records[2].name!="B") return 57;
    auto base_graph=hexlab::types::resolve_pdb_type_graph(base_parsed.value());
    if(!base_graph || base_graph.value().nodes[2].canonical_index!=0x1004 || std::none_of(base_graph.value().references.begin(),base_graph.value().references.end(),[](const auto &e){return e.source_index==0x1001 && e.target_index==0x1002 && e.kind==hexlab::types::PdbTypeReferenceKind::base_class && e.resolved;})) return 58;
    auto base_import=hexlab::types::import_pdb_type_graph(base_graph.value());
    if(!base_import || !base_import.value().definitions.contains("D")) return 59;
    const auto derived=base_import.value().definitions.at("D");
    if(derived->members().size()!=2 || derived->members()[0].name!="$base$B" || derived->members()[0].offset!=0 || derived->members()[1].name!="y" || derived->members()[1].offset!=4) return 60;
    auto persisted_base=hexlab::types::encode(*derived); auto roundtrip_base=persisted_base ? hexlab::types::decode(persisted_base.value()) : hexlab::Result<hexlab::types::TypePtr>(persisted_base.error());
    auto laid_out_base=roundtrip_base ? hexlab::types::layout(*roundtrip_base.value(),hexlab::types::Abi::x86_64) : hexlab::Result<hexlab::types::TypeLayout>(roundtrip_base.error());
    if(!roundtrip_base || !laid_out_base || laid_out_base.value().size!=8 || laid_out_base.value().members.size()!=2 || laid_out_base.value().members[0].offset!=0 || laid_out_base.value().members[1].offset!=4) return 61;
    auto truncated_base_db=base_db; auto &truncated_base=*truncated_base_db.streams[2];
    truncated_base.resize(truncated_base.size()-1);put(truncated_base,16,truncated_base.size()-56,4);
    if(hexlab::types::parse_pdb_types(truncated_base_db)) return 62;
    // DBI module metadata plus public/procedure/data records in a module stream.
    hexlab::types::PdbDatabase symbol_db; symbol_db.streams.resize(7);
    symbol_db.streams[3].emplace(64 + 88, std::byte{0});
    auto &dbi = *symbol_db.streams[3];
    put(dbi, 24, 88, 4); // One aligned module record.
    put(dbi, 20, 0xffff, 2); // No DBI symbol-record stream yet.
    put(dbi, 64 + 34, 4, 2); // Module symbol stream.
    std::size_t module_name = 64 + 64;
    const char module_text[] = "src\\main.cpp";
    for (char c : module_text) dbi[module_name++] = static_cast<std::byte>(c);
    const char object_text[] = "main.obj";
    for (char c : object_text) dbi[module_name++] = static_cast<std::byte>(c);
    symbol_db.streams[4].emplace(4, std::byte{0}); // C13 signature prefix.
    auto &syms = *symbol_db.streams[4];
    auto append_symbol = [&](std::uint16_t kind, const std::vector<std::byte> &body) {
        auto n = syms.size(); syms.resize(n + 4 + body.size());
        put(syms, n, body.size() + 2, 2); put(syms, n + 2, kind, 2);
        std::copy(body.begin(), body.end(), syms.begin() + static_cast<std::ptrdiff_t>(n + 4));
    };
    auto symbol_body = [&](bool procedure, std::uint32_t address, std::uint16_t section, const char *name) {
        std::vector<std::byte> body(procedure ? 35 : 10, std::byte{0});
        if (procedure) put(body, 12, 0x24, 4); // code length
        put(body, procedure ? 28 : 4, address, 4);
        put(body, procedure ? 32 : 8, section, 2);
        body.insert(body.end(), reinterpret_cast<const std::byte *>(name), reinterpret_cast<const std::byte *>(name + std::char_traits<char>::length(name) + 1));
        return body;
    };
    append_symbol(0x1110, symbol_body(true, 0x120, 2, "?entry@@YAHXZ"));
    auto append_name_record = [&](std::uint16_t kind, std::vector<std::byte> body, const char *name) {
        body.insert(body.end(), reinterpret_cast<const std::byte *>(name),
                    reinterpret_cast<const std::byte *>(name + std::char_traits<char>::length(name) + 1));
        append_symbol(kind, body);
    };
    std::vector<std::byte> parameter_body(6, std::byte{0});
    put(parameter_body, 0, 0x74, 4); put(parameter_body, 4, 1, 2);
    append_name_record(0x113e, std::move(parameter_body), "arg"); // S_LOCAL, parameter flag.
    // S_DEFRANGE_REGISTER: register 17 over [section 2:0x124, +0x10),
    // with a two-byte hole beginning four bytes into the range.
    std::vector<std::byte> register_range_body(16, std::byte{0});
    put(register_range_body, 0, 17, 2);
    put(register_range_body, 4, 0x124, 4); put(register_range_body, 8, 2, 2); put(register_range_body, 10, 0x10, 2);
    put(register_range_body, 12, 4, 2); put(register_range_body, 14, 2, 2);
    const auto register_range_offset = syms.size();
    append_symbol(0x1141, register_range_body);
    // A second local with a frame-pointer-relative full-scope location.
    std::vector<std::byte> full_scope_local_body(6, std::byte{0});
    put(full_scope_local_body, 0, 0x1001, 4);
    append_name_record(0x113e, std::move(full_scope_local_body), "frame_local");
    std::vector<std::byte> full_scope_range_body(4, std::byte{0});
    put(full_scope_range_body, 0, static_cast<std::uint32_t>(-24), 4);
    append_symbol(0x1144, full_scope_range_body);
    std::vector<std::byte> frame_range_body(12, std::byte{0});
    put(frame_range_body, 0, static_cast<std::uint32_t>(-28), 4);
    put(frame_range_body, 4, 0x140, 4); put(frame_range_body, 8, 2, 2); put(frame_range_body, 10, 6, 2);
    append_symbol(0x1142, frame_range_body);
    std::vector<std::byte> regrel_range_local_body(6, std::byte{0});
    put(regrel_range_local_body, 0, 0x1001, 4);
    append_name_record(0x113e, std::move(regrel_range_local_body), "regrel_range");
    std::vector<std::byte> regrel_range_body(16, std::byte{0});
    put(regrel_range_body, 0, 21, 2);
    put(regrel_range_body, 4, static_cast<std::uint32_t>(-32), 4);
    put(regrel_range_body, 8, 0x150, 4); put(regrel_range_body, 12, 2, 2); put(regrel_range_body, 14, 8, 2);
    append_symbol(0x1145, regrel_range_body);
    std::vector<std::byte> frame_local_body(8, std::byte{0});
    put(frame_local_body, 0, static_cast<std::uint32_t>(-16), 4); put(frame_local_body, 4, 0x1001, 4);
    append_name_record(0x0100, std::move(frame_local_body), "temporary"); // S_BPREL32.
    std::vector<std::byte> block_scope_body(18, std::byte{0});
    put(block_scope_body, 8, 4, 4); put(block_scope_body, 12, 0x140, 4); put(block_scope_body, 16, 2, 2);
    append_symbol(0x1103, std::move(block_scope_body)); // Nested S_BLOCK32 scope: section 2:[0x140,0x144).
    std::vector<std::byte> register_local_body(10, std::byte{0});
    put(register_local_body, 0, 8, 4); put(register_local_body, 4, 0x74, 4); put(register_local_body, 8, 17, 2);
    append_name_record(0x1111, std::move(register_local_body), "register_local"); // S_REGREL32.
    append_symbol(0x0006, {}); // Nested block end.
    append_symbol(0x0006, {}); // Procedure scope end.
    append_symbol(0x110d, symbol_body(false, 0x200, 3, "global_value"));
    put(dbi, 64 + 36, static_cast<std::uint32_t>(syms.size()), 4);
    const auto symbols = hexlab::types::parse_pdb_symbols(symbol_db);
    if (!symbols || symbols.value().symbols.size() != 2 ||
        symbols.value().symbols[0].name != "?entry@@YAHXZ" ||
        symbols.value().symbols[0].kind != hexlab::types::PdbSymbolKind::procedure ||
        symbols.value().symbols[0].section != 2 || symbols.value().symbols[0].section_offset != 0x120 ||
        symbols.value().symbols[0].size != 0x24 || symbols.value().symbols[0].object_name != "main.obj" ||
        symbols.value().symbols[1].name != "global_value" || symbols.value().symbols[1].section != 3 ||
        symbols.value().symbols[1].section_offset != 0x200 || symbols.value().symbols[1].module_name != "src\\main.cpp") {
        std::cerr << (symbols ? "unexpected PDB module symbol result" : symbols.error().message) << '\n'; return 16;
    }
    const auto locals = hexlab::types::parse_pdb_locals(symbol_db);
    if (!locals || locals.value().locals.size() != 5 ||
        locals.value().locals[0].name != "arg" || !locals.value().locals[0].parameter ||
        locals.value().locals[0].type_index != 0x74 ||
        locals.value().locals[0].procedure_name != "?entry@@YAHXZ" ||
        locals.value().locals[0].procedure_section != 2 ||
        locals.value().locals[0].procedure_section_offset != 0x120 ||
        locals.value().locals[3].name != "temporary" || locals.value().locals[3].parameter ||
        locals.value().locals[3].location_kind != hexlab::types::PdbLocalLocationKind::frame_relative ||
        locals.value().locals[3].frame_offset != -16 || locals.value().locals[3].object_name != "main.obj" ||
        locals.value().locals[4].name != "register_local" ||
        locals.value().locals[4].location_kind != hexlab::types::PdbLocalLocationKind::register_relative ||
        locals.value().locals[4].frame_offset != 8 || locals.value().locals[4].register_id != 17 ||
        locals.value().locals[0].live_ranges.size() != 1 ||
        locals.value().locals[0].live_ranges[0].location_kind != hexlab::types::PdbLocalLocationKind::register_value ||
        locals.value().locals[0].live_ranges[0].register_id != 17 ||
        locals.value().locals[0].live_ranges[0].section != 2 ||
        locals.value().locals[0].live_ranges[0].section_offset != 0x124 ||
        locals.value().locals[0].live_ranges[0].size != 0x10 ||
        locals.value().locals[0].live_ranges[0].gaps.size() != 1 ||
        locals.value().locals[0].live_ranges[0].gaps[0].offset != 4 ||
        locals.value().locals[0].live_ranges[0].gaps[0].size != 2 ||
        locals.value().locals[1].name != "frame_local" ||
        locals.value().locals[1].live_ranges.size() != 2 ||
        locals.value().locals[1].live_ranges[0].location_kind != hexlab::types::PdbLocalLocationKind::frame_relative ||
        locals.value().locals[1].live_ranges[0].frame_offset != -24 ||
        locals.value().locals[1].live_ranges[0].section_offset != 0x120 ||
        locals.value().locals[1].live_ranges[0].size != 0x24 ||
        locals.value().locals[1].live_ranges[1].location_kind != hexlab::types::PdbLocalLocationKind::frame_relative ||
        locals.value().locals[1].live_ranges[1].frame_offset != -28 ||
        locals.value().locals[1].live_ranges[1].section_offset != 0x140 ||
        locals.value().locals[1].live_ranges[1].size != 6 ||
        locals.value().locals[2].name != "regrel_range" ||
        locals.value().locals[2].live_ranges.size() != 1 ||
        locals.value().locals[2].live_ranges[0].location_kind != hexlab::types::PdbLocalLocationKind::register_relative ||
        locals.value().locals[2].live_ranges[0].register_id != 21 ||
        locals.value().locals[2].live_ranges[0].frame_offset != -32 ||
        locals.value().locals[2].live_ranges[0].section_offset != 0x150 ||
        locals.value().locals[2].live_ranges[0].size != 8) {
        std::cerr << (locals ? "unexpected PDB local/parameter result" : locals.error().message) << '\n'; return 35;
    }
    auto malformed_local = symbol_db;
    // Corrupt S_LOCAL's required six-byte fixed payload while keeping record framing valid.
    const auto local_offset = 4u + 4u + 35u + std::char_traits<char>::length("?entry@@YAHXZ") + 1u;
    put(*malformed_local.streams[4], local_offset, 2, 2);
    if (hexlab::types::parse_pdb_locals(malformed_local)) return 36;
    auto malformed_defrange = symbol_db;
    put(*malformed_defrange.streams[4], register_range_offset, 17, 2); // Leaves a partial gap entry.
    if (hexlab::types::parse_pdb_locals(malformed_defrange)) return 38;
    const auto canceled_locals = hexlab::types::parse_pdb_locals(symbol_db, stopped.get_token());
    if (canceled_locals || canceled_locals.error().code != hexlab::ErrorCode::canceled) return 37;
    // DBI's symbol-record stream carries public/global CodeView definitions.
    // It is separate from the module stream and has no module provenance.
    put(dbi, 20, 6, 2); // SymRecordStream index.
    symbol_db.streams[6].emplace();
    auto &global_syms = *symbol_db.streams[6];
    auto append_global = [&](std::uint16_t kind, const std::vector<std::byte> &body) {
        const auto n = global_syms.size(); global_syms.resize(n + 4 + body.size());
        put(global_syms, n, body.size() + 2, 2); put(global_syms, n + 2, kind, 2);
        std::copy(body.begin(), body.end(), global_syms.begin() + static_cast<std::ptrdiff_t>(n + 4));
    };
    std::vector<std::byte> public_body(10, std::byte{0});
    put(public_body, 0, 1, 4); // Public function flag.
    put(public_body, 4, 0x340, 4); put(public_body, 8, 2, 2);
    const char public_name[] = "public_entry";
    public_body.insert(public_body.end(), reinterpret_cast<const std::byte *>(public_name),
                       reinterpret_cast<const std::byte *>(public_name + sizeof(public_name)));
    append_global(0x110e, public_body); // S_PUB32.
    auto global_data = symbol_body(false, 0x500, 4, "global_data");
    append_global(0x110d, global_data); // S_GDATA32.
    auto global_procedure = symbol_body(true, 0x600, 5, "global_function");
    append_global(0x1110, global_procedure); // S_GPROC32.
    const auto with_globals = hexlab::types::parse_pdb_symbols(symbol_db);
    if (!with_globals || with_globals.value().symbols.size() != 5 ||
        with_globals.value().symbols[2].name != "public_entry" ||
        with_globals.value().symbols[2].record_kind != 0x110e ||
        with_globals.value().symbols[2].section != 2 || with_globals.value().symbols[2].section_offset != 0x340 ||
        !with_globals.value().symbols[2].public_symbol ||
        with_globals.value().symbols[3].name != "global_data" || with_globals.value().symbols[3].module_name.size() ||
        with_globals.value().symbols[4].name != "global_function" ||
        with_globals.value().symbols[4].kind != hexlab::types::PdbSymbolKind::procedure) {
        std::cerr << (with_globals ? "unexpected PDB global/public symbol result" : with_globals.error().message) << '\n'; return 30;
    }
    auto malformed_globals = symbol_db; malformed_globals.streams[6]->at(0) = std::byte{0xff};
    if (hexlab::types::parse_pdb_symbols(malformed_globals)) return 31;
    auto truncated_global_name = symbol_db; put(*truncated_global_name.streams[6], 0, 12, 2);
    if (hexlab::types::parse_pdb_symbols(truncated_global_name)) return 32;
    const auto canceled_globals = hexlab::types::parse_pdb_symbols(symbol_db, stopped.get_token());
    if (canceled_globals || canceled_globals.error().code != hexlab::ErrorCode::canceled) return 33;
    auto malformed_symbols = symbol_db; put(*malformed_symbols.streams[3], 64 + 34, 0xfffe, 2);
    if (hexlab::types::parse_pdb_symbols(malformed_symbols)) return 17;
    const auto canceled_symbols = hexlab::types::parse_pdb_symbols(symbol_db, stopped.get_token());
    if (canceled_symbols || canceled_symbols.error().code != hexlab::ErrorCode::canceled) return 18;
    auto line_db = symbol_db;
    auto &line_stream = *line_db.streams[4];
    const auto c11_padding = (4 - (syms.size() % 4)) % 4;
    line_stream.insert(line_stream.end(), c11_padding, std::byte{0});
    put(*line_db.streams[3], 64 + 40, c11_padding, 4); // DBI C11 alignment padding.
    std::vector<std::byte> string_payload(4, std::byte{0}); put(string_payload, 0, 0xeffeeffe, 4);
    const char source_path[] = "src/main.cpp";
    for (char c : source_path) string_payload.push_back(static_cast<std::byte>(c));
    std::vector<std::byte> checksum_payload(12, std::byte{0});
    put(checksum_payload, 0, 0, 4); put(checksum_payload, 4, 4, 1); put(checksum_payload, 5, 1, 1);
    put(checksum_payload, 6, 0xaa, 1); put(checksum_payload, 7, 0xbb, 1); put(checksum_payload, 8, 0xcc, 1); put(checksum_payload, 9, 0xdd, 1);
    std::vector<std::byte> line_payload(12 + 12 + 2 * 8 + 2 * 4, std::byte{0});
    put(line_payload, 0, 0x300, 4); put(line_payload, 4, 5, 2); put(line_payload, 6, 1, 2); put(line_payload, 8, 0x20, 4);
    put(line_payload, 12, 0, 4); put(line_payload, 16, 2, 4); put(line_payload, 20, 36, 4);
    put(line_payload, 24, 0, 4); put(line_payload, 28, 10 | (2u << 24) | 0x80000000u, 4);
    put(line_payload, 32, 0x10, 4); put(line_payload, 36, 11 | (1u << 24), 4);
    put(line_payload, 40, 2, 2); put(line_payload, 42, 8, 2); put(line_payload, 44, 1, 2); put(line_payload, 46, 4, 2);
    auto append_subsection = [&](std::uint32_t kind, const std::vector<std::byte> &payload) {
        auto n = line_stream.size(); line_stream.resize(n + 8 + payload.size()); put(line_stream, n, kind, 4);
        put(line_stream, n + 4, payload.size(), 4); std::copy(payload.begin(), payload.end(), line_stream.begin() + static_cast<std::ptrdiff_t>(n + 8));
        while (line_stream.size() % 4) line_stream.push_back(std::byte{0});
    };
    append_subsection(0xf2, line_payload); // Lines precede their checksum/string tables intentionally.
    append_subsection(0xf4, checksum_payload);
    append_subsection(0xf3, string_payload);
    put(*line_db.streams[3], 64 + 44, line_stream.size() - syms.size() - c11_padding, 4); // DBI C13 byte count.
    const auto source_lines = hexlab::types::parse_pdb_source_lines(line_db);
    if (!source_lines || source_lines.value().lines.size() != 2 ||
        source_lines.value().lines[0].source_path != "src/main.cpp" || source_lines.value().lines[0].source_file_id != 0 ||
        source_lines.value().lines[0].checksum_kind != 1 || source_lines.value().lines[0].checksum.size() != 4 ||
        source_lines.value().lines[0].section != 5 || source_lines.value().lines[0].reloc_offset != 0x300 ||
        source_lines.value().lines[0].section_offset != 0x300 ||
        source_lines.value().lines[0].line != 10 || source_lines.value().lines[0].end_line != 12 ||
        source_lines.value().lines[0].start_column != 2 || source_lines.value().lines[0].end_column != 8 ||
        !source_lines.value().lines[0].is_statement || source_lines.value().lines[0].end_sequence ||
        source_lines.value().lines[1].section_offset != 0x310 || source_lines.value().lines[1].line != 11 ||
        source_lines.value().lines[1].module_index != 0 || source_lines.value().lines[1].module_name != "src\\main.cpp" ||
        source_lines.value().lines[1].object_name != "main.obj") {
        std::cerr << (source_lines ? "unexpected PDB source-line result" : source_lines.error().message) << '\n'; return 21;
    }
    auto truncated_lines = line_db; truncated_lines.streams[4]->pop_back();
    if (hexlab::types::parse_pdb_source_lines(truncated_lines)) return 22;
    auto bad_line_count = line_db;
    put(*bad_line_count.streams[4], syms.size() + 8 + 12 + 4, 0xffffffff, 4);
    if (hexlab::types::parse_pdb_source_lines(bad_line_count)) return 23;
    auto bad_checksum_path = line_db;
    put(*bad_checksum_path.streams[4], syms.size() + 56 + 8, 0xffffffff, 4);
    if (hexlab::types::parse_pdb_source_lines(bad_checksum_path)) return 28;
    auto bad_file_identity = line_db;
    put(*bad_file_identity.streams[4], syms.size() + 8 + 12, 0xffffffff, 4);
    if (hexlab::types::parse_pdb_source_lines(bad_file_identity)) return 29;
    auto over_limit_lines = line_db; put(*over_limit_lines.streams[3], 64 + 44, 33 * 1024 * 1024, 4);
    const auto limited = hexlab::types::parse_pdb_source_lines(over_limit_lines);
    if (limited || limited.error().code != hexlab::ErrorCode::resource_limit) return 24;
    const auto canceled_lines = hexlab::types::parse_pdb_source_lines(line_db, stopped.get_token());
    if (canceled_lines || canceled_lines.error().code != hexlab::ErrorCode::canceled) return 25;
    if (argc > 1) {
        std::ifstream input(argv[1], std::ios::binary);
        if (!input) {
            std::cerr << "Cannot open generated MSVC PDB: " << argv[1] << '\n';
            return 9;
        }
        std::vector<char> raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        if (input.bad() || raw.empty()) {
            std::cerr << "Cannot read generated MSVC PDB: " << argv[1] << '\n';
            return 10;
        }
        std::vector<std::byte> pdb(raw.size());
        for (std::size_t i = 0; i < raw.size(); ++i)
            pdb[i] = static_cast<std::byte>(static_cast<unsigned char>(raw[i]));
        const auto actual = hexlab::types::parse_pdb(pdb);
        if (!actual) {
            std::cerr << actual.error().message << '\n';
            return 11;
        }
        if (actual.value().streams.size() < 3 || !actual.value().streams[2] || actual.value().info.age == 0)
            return 12;
        const auto actual_tpi = hexlab::types::parse_pdb_types(actual.value());
        if (!actual_tpi) { std::cerr << "Cannot parse generated MSVC TPI: " << actual_tpi.error().message << '\n'; return 26; }
        const auto actual_graph = hexlab::types::resolve_pdb_type_graph(actual_tpi.value());
        if (!actual_graph) { std::cerr << "Cannot resolve generated MSVC TPI graph: " << actual_graph.error().message << '\n'; return 27; }
        if (actual_graph.value().nodes.size() != actual_tpi.value().records.size() || actual_graph.value().references.empty()) {
            std::cerr << "Generated MSVC TPI did not produce a nonempty indexed type graph\n"; return 28;
        }
        const auto artifact_enum = std::find_if(actual_graph.value().nodes.begin(), actual_graph.value().nodes.end(), [](const auto &node) {
            return node.record.kind == hexlab::types::CodeViewTypeKind::enumeration &&
                   node.record.name.find("ArtifactEnum") != std::string::npos &&
                   !node.record.forward_declaration;
        });
        if (artifact_enum == actual_graph.value().nodes.end() || artifact_enum->expanded_fields.size() != 2 ||
            artifact_enum->expanded_fields[0].value != 5 || artifact_enum->expanded_fields[1].value != 0xffff'ffff'ffff'fff9ULL) {
            std::cerr << "Generated MSVC PDB did not preserve signed enum values in the TPI graph";
            std::cerr << '\n';
            return 40;
        }
        if (std::none_of(actual_graph.value().nodes.begin(), actual_graph.value().nodes.end(), [](const auto &node) {
                return node.record.kind == hexlab::types::CodeViewTypeKind::pointer &&
                       node.record.pointer_mode == 0 && node.record.size != 0 &&
                       (node.record.pointer_kind == 0x0a || node.record.pointer_kind == 0x0c);
            })) {
            std::cerr << "Generated MSVC PDB has no supported ordinary pointer records\n";
            return 32;
        }
        const auto actual_import = hexlab::types::import_pdb_type_graph(actual_graph.value());
        if (!actual_import) {
            std::cerr << "Cannot import supported types from generated MSVC PDB: " << actual_import.error().message << '\n';
            return 29;
        }
        if (actual_import.value().definitions.empty()) {
            std::cerr << "Generated MSVC PDB produced no importable project types\n";
            return 30;
        }
        const auto imported_artifact_enum = actual_import.value().definitions.find(artifact_enum->record.name);
        if (imported_artifact_enum == actual_import.value().definitions.end() ||
            imported_artifact_enum->second->enumerator_values().size() != 2 ||
            imported_artifact_enum->second->enumerator_values()[1].value != 0xffff'ffff'ffff'fff9ULL) {
            std::cerr << "Generated MSVC PDB enum values were not imported into the project type graph\n";
            return 41;
        }
        const auto actual_symbols = hexlab::types::parse_pdb_symbols(actual.value());
        if (!actual_symbols) {
            std::cerr << "Cannot parse module symbols from generated MSVC PDB: " << actual_symbols.error().message << '\n';
            return 19;
        }
        if (actual_symbols.value().symbols.empty()) {
            std::cerr << "Generated MSVC PDB has no imported module procedure/data symbols\n";
            return 20;
        }
        bool actual_global_symbol = false, actual_public_symbol = false;
        for (const auto &symbol : actual_symbols.value().symbols) {
            actual_global_symbol = actual_global_symbol ||
                symbol.source == hexlab::types::PdbSymbolSource::global_stream;
            actual_public_symbol = actual_public_symbol || symbol.public_symbol;
        }
        if (!actual_global_symbol || !actual_public_symbol) {
            std::cerr << "Generated MSVC PDB has no imported DBI global/public symbols\n";
            return 34;
        }
        const auto actual_locals = hexlab::types::parse_pdb_locals(actual.value());
        if (!actual_locals) {
            std::cerr << "Cannot parse locals from generated MSVC PDB: " << actual_locals.error().message << '\n';
            return 38;
        }
        if (actual_locals.value().locals.empty()) {
            std::cerr << "Generated MSVC PDB has no imported S_LOCAL/frame-relative locals\n";
            return 39;
        }
        const auto actual_lines = hexlab::types::parse_pdb_source_lines(actual.value());
        if (!actual_lines) {
            std::cerr << "Cannot parse source lines from generated MSVC PDB: " << actual_lines.error().message << '\n';
            return 26;
        }
        if (actual_lines.value().lines.empty()) {
            std::cerr << "Generated MSVC PDB has no imported C13 source lines\n";
            return 27;
        }
    }
    std::cout << "PDB container tests passed\n";
}
