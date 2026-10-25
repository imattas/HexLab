#include "hexlab/loaders/dex.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace hexlab {
namespace {
constexpr std::uint64_t max_file_size = UINT64_C(512) * 1024 * 1024;
constexpr std::uint32_t max_items = 1'000'000;
constexpr std::uint32_t header_bytes = 0x70;

struct Reader {
    std::span<const std::byte> bytes;
    std::size_t pos = 0;
    bool u16(std::uint16_t &v) {
        if (bytes.size() - pos < 2) return false;
        v = std::to_integer<std::uint8_t>(bytes[pos]) |
            (std::uint16_t(std::to_integer<std::uint8_t>(bytes[pos + 1])) << 8);
        pos += 2; return true;
    }
    bool u32(std::uint32_t &v) {
        if (bytes.size() - pos < 4) return false;
        v = 0;
        for (unsigned i = 0; i < 4; ++i) v |= std::uint32_t(std::to_integer<std::uint8_t>(bytes[pos + i])) << (8 * i);
        pos += 4; return true;
    }
    bool uleb(std::uint32_t &v) {
        v = 0;
        for (unsigned i = 0; i < 5; ++i) {
            if (pos >= bytes.size()) return false;
            const auto b = std::to_integer<std::uint8_t>(bytes[pos++]);
            if (i == 4 && (b & 0xf0)) return false;
            v |= std::uint32_t(b & 0x7f) << (7 * i);
            if (!(b & 0x80)) return true;
        }
        return false;
    }
    bool sleb(std::int32_t &v) {
        std::uint32_t raw = 0;
        unsigned shift = 0;
        for (unsigned i = 0; i < 5; ++i) {
            if (pos >= bytes.size()) return false;
            const auto b = std::to_integer<std::uint8_t>(bytes[pos++]);
            raw |= std::uint32_t(b & 0x7f) << shift;
            shift += 7;
            if (!(b & 0x80)) {
                if (shift < 32 && (b & 0x40)) raw |= ~std::uint32_t{0} << shift;
                v = static_cast<std::int32_t>(raw); return true;
            }
        }
        return false;
    }
    bool seek(std::size_t p) { if (p > bytes.size()) return false; pos = p; return true; }
    bool skip(std::size_t n) { if (n > bytes.size() - pos) return false; pos += n; return true; }
};
struct Proto { std::uint32_t return_type = 0; std::vector<std::uint16_t> parameters; };
struct Method { std::uint16_t owner = 0, proto = 0; std::uint32_t name = 0; };
struct Field { std::uint16_t owner = 0, type = 0; std::uint32_t name = 0; };
struct Code { std::uint32_t method = 0; std::uint64_t file_offset = 0; std::uint32_t byte_size = 0, debug = 0, registers = 0, ins = 0; };

bool extent(std::uint64_t off, std::uint64_t count, std::uint64_t stride, std::uint64_t size) {
    return off <= size && (!count || (stride && count <= (size - off) / stride));
}
std::string utf8(std::uint32_t cp) {
    std::string out;
    if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) { out.push_back(static_cast<char>(0xc0 | (cp >> 6))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
    else if (cp <= 0xffff) { out.push_back(static_cast<char>(0xe0 | (cp >> 12))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
    else { out.push_back(static_cast<char>(0xf0 | (cp >> 18))); out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f))); out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f))); out.push_back(static_cast<char>(0x80 | (cp & 0x3f))); }
    return out;
}
bool decode_mutf8(std::span<const std::byte> raw, std::uint32_t expected_units, std::string &out) {
    std::vector<std::uint16_t> units;
    for (std::size_t p = 0; p < raw.size();) {
        const auto b = std::to_integer<std::uint8_t>(raw[p++]);
        if (b == 0) return false;
        if (b < 0x80) units.push_back(b);
        else if ((b & 0xe0) == 0xc0) {
            if (p >= raw.size()) return false;
            const auto b2 = std::to_integer<std::uint8_t>(raw[p++]);
            if ((b2 & 0xc0) != 0x80) return false;
            const auto cp = std::uint16_t(((b & 0x1f) << 6) | (b2 & 0x3f));
            if (cp == 0) { units.push_back(0); continue; }
            if (cp < 0x80) return false;
            units.push_back(cp);
        } else if ((b & 0xf0) == 0xe0) {
            if (raw.size() - p < 2) return false;
            const auto b2 = std::to_integer<std::uint8_t>(raw[p++]);
            const auto b3 = std::to_integer<std::uint8_t>(raw[p++]);
            if ((b2 & 0xc0) != 0x80 || (b3 & 0xc0) != 0x80) return false;
            const auto cp = std::uint16_t(((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
            if (cp < 0x800) return false;
            units.push_back(cp);
        } else return false;
    }
    if (units.size() != expected_units) return false;
    out.clear();
    for (std::size_t i = 0; i < units.size(); ++i) {
        std::uint32_t cp = units[i];
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (i + 1 >= units.size() || units[i + 1] < 0xdc00 || units[i + 1] > 0xdfff) return false;
            cp = 0x10000 + ((cp - 0xd800) << 10) + (units[++i] - 0xdc00);
        } else if (cp >= 0xdc00 && cp <= 0xdfff) return false;
        out += utf8(cp);
    }
    return true;
}

Result<std::vector<std::uint32_t>> parse_map(std::span<const std::byte> bytes, std::uint32_t offset) {
    if (!offset || (offset & 3) || !extent(offset, 1, 4, bytes.size()))
        return Error{ErrorCode::malformed, "DEX map_list offset is invalid"};
    Reader r{bytes}; r.seek(offset);
    std::uint32_t count = 0;
    if (!r.u32(count) || count == 0 || count > 4096 || !extent(offset + 4, count, 12, bytes.size()))
        return Error{ErrorCode::malformed, "DEX map_list extent is invalid"};
    std::vector<std::uint32_t> offsets;
    std::array<bool, 0x10001> seen{};
    offsets.reserve(count);
    std::uint32_t previous = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint16_t type = 0, unused = 0; std::uint32_t size = 0, item_off = 0;
        if (!r.u16(type) || !r.u16(unused) || !r.u32(size) || !r.u32(item_off) || unused || type >= seen.size() || seen[type] ||
            item_off > bytes.size() || (i && item_off < previous))
            return Error{ErrorCode::malformed, "DEX map entry is invalid, duplicated, or out of order"};
        seen[type] = true; previous = item_off; offsets.push_back(item_off);
        if (size && item_off == bytes.size()) return Error{ErrorCode::malformed, "DEX map entry starts at end of file"};
    }
    return offsets;
}

Result<LoadedImage> parse(std::shared_ptr<const ByteStorage> storage, std::stop_token stop) {
    const auto file_size = storage->size();
    if (file_size < header_bytes) return Error{ErrorCode::malformed, "Truncated DEX header"};
    if (file_size > max_file_size || file_size > SIZE_MAX)
        return Error{ErrorCode::resource_limit, "DEX input exceeds the 512 MiB parser limit"};
    auto source = storage->read_at({0}, static_cast<std::size_t>(file_size));
    if (!source) return source.error();
    if (source.value().bytes.size() != file_size) return Error{ErrorCode::io, "DEX source returned an incomplete read"};
    const auto bytes = std::span<const std::byte>(source.value().bytes);
    if (std::memcmp(bytes.data(), "dex\n", 4) != 0 || bytes[7] != std::byte{0})
        return Error{ErrorCode::malformed, "Invalid DEX magic"};
    for (std::size_t i = 4; i <= 6; ++i)
        if (bytes[i] < std::byte{'0'} || bytes[i] > std::byte{'9'})
            return Error{ErrorCode::malformed, "DEX version field is not decimal"};
    const auto version = (std::to_integer<unsigned>(bytes[4]) - '0') * 100 +
                         (std::to_integer<unsigned>(bytes[5]) - '0') * 10 +
                         (std::to_integer<unsigned>(bytes[6]) - '0');
    if (version < 35 || version > 40)
        return Error{ErrorCode::unsupported, "DEX versions 035 through 040 are supported; 041 containers are not"};
    Reader h{bytes}; h.seek(32);
    std::uint32_t stored_file_size=0, header_size=0, endian=0, link_size=0, link_off=0, map_off=0;
    std::uint32_t string_count=0,string_off=0,type_count=0,type_off=0,proto_count=0,proto_off=0;
    std::uint32_t field_count=0,field_off=0,method_count=0,method_off=0,class_count=0,class_off=0,data_size=0,data_off=0;
    if (!h.u32(stored_file_size)||!h.u32(header_size)||!h.u32(endian)||!h.u32(link_size)||!h.u32(link_off)||!h.u32(map_off)||
        !h.u32(string_count)||!h.u32(string_off)||!h.u32(type_count)||!h.u32(type_off)||!h.u32(proto_count)||!h.u32(proto_off)||
        !h.u32(field_count)||!h.u32(field_off)||!h.u32(method_count)||!h.u32(method_off)||!h.u32(class_count)||!h.u32(class_off)||!h.u32(data_size)||!h.u32(data_off))
        return Error{ErrorCode::malformed, "Truncated DEX header fields"};
    if (stored_file_size != file_size || header_size != header_bytes || endian != 0x12345678)
        return Error{ErrorCode::malformed, "DEX header size, file size, or endian tag is unsupported"};
    if (string_count > max_items || type_count > max_items || proto_count > max_items || method_count > max_items || class_count > max_items || field_count > max_items)
        return Error{ErrorCode::resource_limit, "DEX identifier table exceeds one million items"};
    if ((string_count && (string_off & 3)) || (type_count && (type_off & 3)) ||
        (proto_count && (proto_off & 3)) || (field_count && (field_off & 3)) ||
        (method_count && (method_off & 3)) || (class_count && (class_off & 3)) ||
        (data_size && (data_off & 3)) || !extent(string_off,string_count,4,file_size) || !extent(type_off,type_count,4,file_size) ||
        !extent(proto_off,proto_count,12,file_size) || !extent(field_off,field_count,8,file_size) ||
        !extent(method_off,method_count,8,file_size) || !extent(class_off,class_count,32,file_size) ||
        !extent(data_off,data_size,1,file_size) || (link_size && !extent(link_off,link_size,1,file_size)))
        return Error{ErrorCode::malformed, "DEX table or data section exceeds the input"};
    auto map = parse_map(bytes,map_off); if (!map) return map.error();
    if (stop.stop_requested()) return Error{ErrorCode::canceled, "DEX loading canceled"};

    std::vector<std::string> strings; strings.reserve(string_count);
    std::uint64_t decoded_string_bytes = 0;
    Reader ids{bytes};
    for (std::uint32_t i=0;i<string_count;++i) {
        if (!ids.seek(string_off + std::size_t(i)*4)) return Error{ErrorCode::malformed,"DEX string_ids offset is invalid"};
        std::uint32_t off=0; if(!ids.u32(off)||off<data_off||off>=std::uint64_t(data_off)+data_size) return Error{ErrorCode::malformed,"DEX string_data offset is outside data section"};
        Reader str{bytes}; str.seek(off); std::uint32_t utf16_size=0;
        if(!str.uleb(utf16_size)||utf16_size>1'000'000) return Error{ErrorCode::malformed,"DEX string length is invalid"};
        const auto begin=str.pos; while(str.pos<bytes.size()&&str.pos-begin<=3'000'000&&bytes[str.pos]!=std::byte{0}) ++str.pos;
        if(str.pos==bytes.size()||str.pos-begin>3'000'000) return Error{ErrorCode::malformed,"DEX string terminator is missing or exceeds the string budget"};
        std::string value; if(!decode_mutf8(bytes.subspan(begin,str.pos-begin),utf16_size,value)) return Error{ErrorCode::malformed,"DEX string is not valid modified UTF-8 or its UTF-16 length disagrees"};
        if(value.size()>4'000'000) return Error{ErrorCode::resource_limit,"Decoded DEX string exceeds the size budget"};
        decoded_string_bytes += value.size();
        if(decoded_string_bytes > max_file_size) return Error{ErrorCode::resource_limit,"Aggregate DEX strings exceed the memory budget"};
        strings.push_back(std::move(value));
    }
    std::vector<std::string> types; types.reserve(type_count);
    for(std::uint32_t i=0;i<type_count;++i){
        ids.seek(type_off+std::size_t(i)*4);std::uint32_t string_idx=0;
        if(!ids.u32(string_idx)||string_idx>=strings.size())return Error{ErrorCode::malformed,"DEX type_id references an invalid string"};
        types.push_back(strings[string_idx]);
    }
    std::vector<Field> fields; fields.reserve(field_count);
    for(std::uint32_t i=0;i<field_count;++i){
        ids.seek(field_off+std::size_t(i)*8);Field f;
        if(!ids.u16(f.owner)||!ids.u16(f.type)||!ids.u32(f.name)||f.owner>=types.size()||f.type>=types.size()||f.name>=strings.size())
            return Error{ErrorCode::malformed,"DEX field_id contains an invalid index"};
        fields.push_back(f);
    }
    std::vector<Proto> protos; protos.reserve(proto_count);
    std::uint64_t total_proto_parameters = 0;
    for(std::uint32_t i=0;i<proto_count;++i){
        ids.seek(proto_off+std::size_t(i)*12); std::uint32_t shorty=0,ret=0,param_off=0;
        if(!ids.u32(shorty)||!ids.u32(ret)||!ids.u32(param_off)||shorty>=strings.size()||ret>=types.size())return Error{ErrorCode::malformed,"DEX proto_id references invalid string or type"};
        Proto p; p.return_type=ret;
        if(param_off){
            if((param_off&3)||!extent(param_off,1,4,file_size))return Error{ErrorCode::malformed,"DEX proto parameter list offset is invalid"};
            Reader list{bytes};list.seek(param_off);std::uint32_t n=0;
            if(!list.u32(n)||n>255||!extent(param_off+4,n,2,file_size))return Error{ErrorCode::malformed,"DEX proto parameter list extent is invalid"};
            total_proto_parameters += n;
            if(total_proto_parameters > max_items)return Error{ErrorCode::resource_limit,"Aggregate DEX proto parameters exceed item budget"};
            p.parameters.reserve(n);
            for(std::uint32_t j=0;j<n;++j){std::uint16_t t=0;if(!list.u16(t)||t>=types.size())return Error{ErrorCode::malformed,"DEX proto parameter type is invalid"};p.parameters.push_back(t);}
        }
        protos.push_back(std::move(p));
    }
    std::vector<Method> methods; methods.reserve(method_count);
    for(std::uint32_t i=0;i<method_count;++i){
        ids.seek(method_off+std::size_t(i)*8);Method m;
        if(!ids.u16(m.owner)||!ids.u16(m.proto)||!ids.u32(m.name)||m.owner>=types.size()||m.proto>=protos.size()||m.name>=strings.size())return Error{ErrorCode::malformed,"DEX method_id contains an invalid index"};
        methods.push_back(m);
    }
    auto method_name=[&](std::uint32_t idx){
        const auto&m=methods[idx]; const auto&p=protos[m.proto]; std::string out=types[m.owner]+"->"+strings[m.name]+"(";
        for(auto t:p.parameters)out+=types[t]; return out+")"+types[p.return_type];
    };
    std::vector<Code> code;
    std::unordered_set<std::uint32_t> class_data_offsets;
    std::uint64_t total_code_units=0;
    for(std::uint32_t ci=0;ci<class_count;++ci){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"DEX class-data parsing canceled"};
        ids.seek(class_off+std::size_t(ci)*32);std::uint32_t class_type=0,access=0,super=0,interfaces=0,source_file=0,annotations=0,class_data=0,static_values=0;
        if(!ids.u32(class_type)||!ids.u32(access)||!ids.u32(super)||!ids.u32(interfaces)||!ids.u32(source_file)||!ids.u32(annotations)||!ids.u32(class_data)||!ids.u32(static_values)||class_type>=types.size()||(super!=0xffffffffu&&super>=types.size())||(source_file!=0xffffffffu&&source_file>=strings.size()))return Error{ErrorCode::malformed,"DEX class_def contains an invalid index"};
        const auto data_end=std::uint64_t(data_off)+data_size;
        if((interfaces&&((interfaces&3)||interfaces<data_off||interfaces>=data_end))||
           (annotations&&(annotations<data_off||annotations>=data_end))||
           (class_data&&(class_data<data_off||class_data>=data_end))||
           (static_values&&(static_values<data_off||static_values>=data_end)))
            return Error{ErrorCode::malformed,"DEX class_def data offset is outside the data section"};
        if(!class_data)continue;
        if(!class_data_offsets.insert(class_data).second)return Error{ErrorCode::malformed,"DEX classes share a class_data_item offset"};
        if(class_data_offsets.size()>max_items)return Error{ErrorCode::resource_limit,"DEX class-data count exceeds item budget"};
        Reader cd{bytes};cd.seek(class_data);std::uint32_t sf=0,inf=0,dm=0,vm=0;
        if(!cd.uleb(sf)||!cd.uleb(inf)||!cd.uleb(dm)||!cd.uleb(vm)||sf>max_items||inf>max_items||dm>max_items||vm>max_items)return Error{ErrorCode::malformed,"DEX class_data counts are invalid"};
        const auto encoded_field_count=std::uint64_t(sf)+inf, defined=std::uint64_t(dm)+vm;
        if(encoded_field_count>max_items||defined>max_items)return Error{ErrorCode::resource_limit,"DEX class_data exceeds item budget"};
        for(std::uint64_t group=0;group<2;++group){const auto count=group?inf:sf;std::uint64_t field_idx=0;for(std::uint32_t n=0;n<count;++n){std::uint32_t delta=0,flags=0;if(!cd.uleb(delta)||!cd.uleb(flags))return Error{ErrorCode::malformed,"Truncated DEX encoded field"};field_idx+=delta;if(field_idx>=fields.size()||fields[field_idx].owner!=class_type)return Error{ErrorCode::malformed,"DEX encoded field index is invalid for its defining class"};}}
        for(std::uint64_t group=0;group<2;++group){
            const auto count=group?vm:dm;std::uint64_t method_idx=0;
            for(std::uint32_t n=0;n<count;++n){std::uint32_t delta=0,flags=0,code_off=0;if(!cd.uleb(delta)||!cd.uleb(flags)||!cd.uleb(code_off))return Error{ErrorCode::malformed,"Truncated DEX encoded method"};method_idx+=delta;
                if(method_idx>=methods.size()||methods[method_idx].owner!=class_type)return Error{ErrorCode::malformed,"DEX encoded method index is invalid for its defining class"};
                if(!code_off)continue;
                if((code_off&3)||code_off<data_off||code_off>=std::uint64_t(data_off)+data_size||!extent(code_off,1,16,file_size))return Error{ErrorCode::malformed,"DEX code_item header offset is invalid"};
                Reader cr{bytes};cr.seek(code_off);std::uint16_t registers=0,ins=0,outs=0,tries=0;std::uint32_t debug=0,insns=0;
                if(!cr.u16(registers)||!cr.u16(ins)||!cr.u16(outs)||!cr.u16(tries)||!cr.u32(debug)||!cr.u32(insns)||ins>registers||!extent(cr.pos,insns,2,file_size))return Error{ErrorCode::malformed,"DEX code_item header or instruction extent is invalid"};
                if(debug&&(debug<data_off||debug>=std::uint64_t(data_off)+data_size))return Error{ErrorCode::malformed,"DEX debug_info offset is outside data section"};
                total_code_units+=insns;if(total_code_units>UINT32_MAX/2)return Error{ErrorCode::resource_limit,"DEX mapped code exceeds the method address-space budget"};
                const auto insns_off=cr.pos; cr.skip(std::size_t(insns)*2);
                if(tries){
                    if(insns&1){std::uint16_t padding=0;if(!cr.u16(padding)||padding)return Error{ErrorCode::malformed,"DEX code_item try padding is invalid"};}
                    if(!extent(cr.pos,tries,8,file_size))return Error{ErrorCode::malformed,"DEX try_item table exceeds input"};
                    std::vector<std::uint16_t> handler_refs; handler_refs.reserve(tries);
                    for(std::uint16_t n=0;n<tries;++n){std::uint32_t start=0;std::uint16_t count=0,handler=0;if(!cr.u32(start)||!cr.u16(count)||!cr.u16(handler)||!count||std::uint64_t(start)+count>insns)return Error{ErrorCode::malformed,"DEX try_item range is invalid"};handler_refs.push_back(handler);}
                    const auto handlers_base=cr.pos;
                    std::uint32_t handlers=0;if(!cr.uleb(handlers)||handlers>max_items)return Error{ErrorCode::malformed,"DEX catch handler list count is invalid"};
                    std::vector<std::uint16_t> handler_starts; handler_starts.reserve(handlers);
                    for(std::uint32_t n=0;n<handlers;++n){if(cr.pos-handlers_base>UINT16_MAX)return Error{ErrorCode::resource_limit,"DEX catch handler offsets exceed encoding range"};handler_starts.push_back(static_cast<std::uint16_t>(cr.pos-handlers_base));std::int32_t typed=0;if(!cr.sleb(typed))return Error{ErrorCode::malformed,"Truncated DEX catch handler"};const auto typed_count=std::uint32_t(typed<0?-std::int64_t(typed):typed);if(typed_count>max_items)return Error{ErrorCode::resource_limit,"DEX catch handler exceeds item budget"};for(std::uint32_t j=0;j<typed_count;++j){std::uint32_t type=0,addr=0;if(!cr.uleb(type)||!cr.uleb(addr)||type>=types.size()||addr>=insns)return Error{ErrorCode::malformed,"DEX typed catch entry is invalid"};}if(typed<=0){std::uint32_t addr=0;if(!cr.uleb(addr)||addr>=insns)return Error{ErrorCode::malformed,"DEX catch-all address is invalid"};}}
                    for(const auto ref:handler_refs)if(std::find(handler_starts.begin(),handler_starts.end(),ref)==handler_starts.end())return Error{ErrorCode::malformed,"DEX try_item references a missing catch handler"};
                }
                if(insns==0||cr.pos>data_end)return Error{ErrorCode::malformed,"DEX code_item is empty or extends outside data section"};
                code.push_back({static_cast<std::uint32_t>(method_idx),insns_off,insns*2,debug,registers,ins});
            }
        }
    }
    if(code.size()>max_items)return Error{ErrorCode::resource_limit,"DEX defined method count exceeds address-space budget"};
    DexMetadata dex_metadata;
    std::uint64_t total_debug_rows = 0;
    std::size_t total_debug_bytes = 0;
    for (const auto &compiled : code) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled,"DEX debug-info parsing canceled"};
        if (!compiled.debug) continue;
        const auto data_end = static_cast<std::size_t>(std::uint64_t(data_off) + data_size);
        Reader dr{bytes.first(data_end)};
        if (!dr.seek(compiled.debug)) return Error{ErrorCode::malformed,"DEX debug_info offset is invalid"};
        DexMethodDebug decoded; decoded.method_index = compiled.method;
        const auto account_debug_bytes = [&](std::size_t amount) -> bool {
            constexpr std::size_t limit = 64ull * 1024 * 1024;
            if (total_debug_bytes > limit || amount > limit - total_debug_bytes) return false;
            total_debug_bytes += amount;
            return true;
        };
        std::uint32_t line_start = 0, parameter_count = 0;
        if (!dr.uleb(line_start) || !dr.uleb(parameter_count) || parameter_count > 255 || parameter_count != protos[methods[compiled.method].proto].parameters.size())
            return Error{ErrorCode::malformed,"DEX debug_info line or parameter header is invalid"};
        decoded.line_start = line_start;
        for (std::uint32_t n = 0; n < parameter_count; ++n) {
            std::uint32_t index = 0;
            if (!dr.uleb(index)) return Error{ErrorCode::malformed,"Truncated DEX debug parameter names"};
            if (index && index - 1 >= strings.size()) return Error{ErrorCode::malformed,"DEX debug parameter name index is invalid"};
            if (!account_debug_bytes(sizeof(std::optional<std::string>) + (index ? strings[index - 1].size() : 0))) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds 64 MiB"};
            decoded.parameter_names.push_back(index ? std::optional<std::string>(strings[index - 1]) : std::nullopt);
        }
        struct ActiveLocal { DexDebugLocal local; };
        std::vector<std::optional<ActiveLocal>> active(compiled.registers);
        std::vector<std::optional<DexDebugLocal>> previous(compiled.registers);
        bool debug_output_overflow = false;
        std::uint32_t pc = 0;
        std::int64_t line = line_start;
        std::uint32_t file_index = UINT32_MAX;
        std::size_t opcode_count = 0;
        bool ended = false;
        auto close_local = [&](std::uint32_t reg) {
            if (!active[reg]) return;
            auto local = std::move(active[reg]->local);
            local.end = pc * 2;
            if (local.begin < local.end) {
                const auto bytes = sizeof(DexDebugLocal) + (local.name ? local.name->size() : 0) +
                    (local.type ? local.type->size() : 0) + (local.signature ? local.signature->size() : 0);
                if (decoded.locals.size() >= 2'000'000 || !account_debug_bytes(bytes)) debug_output_overflow = true;
                else decoded.locals.push_back(local);
            }
            previous[reg] = std::move(local);
            active[reg].reset();
        };
        auto emit_line = [&]() -> bool {
            if (pc > compiled.byte_size / 2 || line < 0 || line > UINT32_MAX) return false;
            DexDebugLine row; row.address = pc * 2; row.line = static_cast<std::uint32_t>(line);
            if (file_index != UINT32_MAX) {
                if (!account_debug_bytes(sizeof(DexDebugLine) + strings[file_index].size())) return false;
                row.source_file = strings[file_index];
            } else if (!account_debug_bytes(sizeof(DexDebugLine))) return false;
            decoded.lines.push_back(std::move(row)); return true;
        };
        while (!dr.bytes.empty() && dr.pos < dr.bytes.size()) {
            if (++opcode_count > 2'000'000) return Error{ErrorCode::resource_limit,"DEX debug program exceeds opcode limit"};
            if (stop.stop_requested()) return Error{ErrorCode::canceled,"DEX debug-info parsing canceled"};
            const auto opcode = std::to_integer<std::uint8_t>(dr.bytes[dr.pos++]);
            std::uint32_t a = 0, b = 0, c = 0;
            if (opcode == 0) {
                ended = true;
                for (std::uint32_t reg = 0; reg < active.size(); ++reg) close_local(reg);
                break;
            } else if (opcode == 1) {
                if (!dr.uleb(a) || a > compiled.byte_size / 2 - std::min(pc, compiled.byte_size / 2)) return Error{ErrorCode::malformed,"DEX debug address exceeds method"};
                pc += a;
            } else if (opcode == 2) {
                std::int32_t delta = 0; if (!dr.sleb(delta) || (delta < 0 && line < -std::int64_t(delta)) || (delta > 0 && line > INT32_MAX - delta)) return Error{ErrorCode::malformed,"DEX debug line adjustment overflows"};
                line += delta;
            } else if (opcode == 3 || opcode == 4) {
                if (!dr.uleb(a) || !dr.uleb(b) || !dr.uleb(c) || a >= compiled.registers || (b && b - 1 >= strings.size()) || (c && c - 1 >= types.size())) return Error{ErrorCode::malformed,"DEX debug local entry is invalid"};
                std::uint32_t signature = 0;
                if (opcode == 4 && (!dr.uleb(signature) || (signature && signature - 1 >= strings.size()))) return Error{ErrorCode::malformed,"DEX debug local signature is invalid"};
                close_local(a);
                DexDebugLocal local; local.register_index = a; local.begin = pc * 2;
                const auto local_bytes = sizeof(DexDebugLocal) + (b ? strings[b - 1].size() : 0) +
                    (c ? types[c - 1].size() : 0) + (signature ? strings[signature - 1].size() : 0);
                if (!account_debug_bytes(local_bytes)) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds 64 MiB"};
                if (b) local.name = strings[b - 1]; if (c) local.type = types[c - 1];
                if (signature) local.signature = strings[signature - 1];
                active[a] = ActiveLocal{std::move(local)};
            } else if (opcode == 5 || opcode == 6) {
                if (!dr.uleb(a) || a >= compiled.registers) return Error{ErrorCode::malformed,"DEX debug local register is invalid"};
                if (opcode == 5) close_local(a);
                else {
                    if (active[a] || !previous[a]) return Error{ErrorCode::malformed,"DEX debug restart_local has no ended local"};
                    auto local = *previous[a]; local.begin = pc * 2; local.end = 0;
                    const auto bytes = sizeof(DexDebugLocal) + (local.name ? local.name->size() : 0) +
                        (local.type ? local.type->size() : 0) + (local.signature ? local.signature->size() : 0);
                    if (!account_debug_bytes(bytes)) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds 64 MiB"};
                    active[a] = ActiveLocal{std::move(local)};
                }
            } else if (opcode == 7 || opcode == 8) {
                // Prologue/epilogue markers do not change the address/line state.
            } else if (opcode == 9) {
                if (!dr.uleb(a) || (a && a - 1 >= strings.size())) return Error{ErrorCode::malformed,"DEX debug source-file index is invalid"};
                file_index = a ? a - 1 : UINT32_MAX;
            } else if (opcode >= 0x0a) {
                constexpr std::uint32_t opcode_base = 0x0a, line_range = 15;
                const auto adjusted = opcode - opcode_base;
                const auto address_delta = adjusted / line_range;
                if (address_delta > compiled.byte_size / 2 - std::min(pc, compiled.byte_size / 2)) return Error{ErrorCode::malformed,"DEX debug special address exceeds method"};
                pc += address_delta; line += -4 + static_cast<std::int32_t>(adjusted % line_range);
                if (!emit_line()) return Error{ErrorCode::malformed,"DEX debug source row is outside the method"};
            } else return Error{ErrorCode::malformed,"Invalid DEX debug opcode"};
            if (pc > compiled.byte_size / 2) return Error{ErrorCode::malformed,"DEX debug address exceeds method"};
        }
        if (!ended) return Error{ErrorCode::malformed,"DEX debug program has no end_sequence"};
        if (debug_output_overflow) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds its output budget"};
        total_debug_rows += decoded.lines.size() + decoded.locals.size();
        if (total_debug_rows > 2'000'000 || decoded.lines.size() > 2'000'000 || decoded.locals.size() > 2'000'000) return Error{ErrorCode::resource_limit,"DEX debug metadata exceeds its output budget"};
        dex_metadata.methods.push_back(std::move(decoded));
    }
    std::sort(code.begin(),code.end(),[](const Code&a,const Code&b){return a.method<b.method;});
    ImageLayout layout{{{0},32,2,ByteOrder::little},Architecture::dex,ExecutionMode::dex,{}, {}};
    layout.segments.reserve(code.size());layout.entries.reserve(code.size());layout.domains.reserve(code.size());
    for(const auto &c:code){
        const AddressSpaceId space{c.method+1};
        const DecodeContext context{Architecture::dex,ExecutionMode::dex,ByteOrder::little};
        layout.domains.push_back({AddressSpace{space,32,2,ByteOrder::little},context});
        const Address begin{space,0};
        layout.segments.push_back({method_name(c.method),begin,c.byte_size,{c.file_offset},c.byte_size,true,false,true});
        layout.entries.push_back(begin);
    }
    auto image=Image::create(std::move(storage),std::move(layout));if(!image)return image.error();
    LoadedImage loaded;loaded.image=std::move(image.value());loaded.metadata.format="Dalvik DEX (035-040)";loaded.metadata.image_size=file_size;loaded.metadata_complete=false;
    loaded.metadata.dex = std::move(dex_metadata);
    loaded.diagnostics.push_back({DiagnosticSeverity::info,"DEX methods are mapped to method-relative address spaces; checksum/signature validation and full verifier semantics are not implemented",{}});
    auto read=loaded.metadata_reads.include({0},file_size);if(!read)return read.error();return loaded;
}
}

Result<LoadedImage> load_dex(std::shared_ptr<const ByteStorage> storage,std::stop_token stop){
    if(!storage)return Error{ErrorCode::invalid_argument,"DEX loader requires input storage"};
    if(stop.stop_requested())return Error{ErrorCode::canceled,"DEX loading canceled"};
    try{return parse(std::move(storage),stop);}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"Cannot allocate DEX parser state"};}catch(const std::length_error&){return Error{ErrorCode::resource_limit,"DEX parser state exceeds container limits"};}
}
} // namespace hexlab
