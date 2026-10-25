#include "pe_internal.hpp"
#include <iterator>
#include <map>
#include <functional>
#include <limits>
#include <set>
#include <string_view>

namespace hexlab::pe_detail {
namespace {
std::optional<PeVersionInfo> parse_version_info(const ImageReader &reader, const PeResource &resource,
                                                std::uint64_t &remaining_budget) {
    constexpr std::uint64_t fixed_info_size = 52;
    constexpr std::uint32_t fixed_info_signature = 0xfeef04bdu;
    if (!resource.size || resource.size < 6)
        return {};
    constexpr std::uint32_t per_resource_budget = 1024 * 1024;
    // Version resources can contain arbitrary string data. Keep each parse
    // bounded; callers also charge this against a shared image budget.
    const auto bounded_size = std::min<std::uint64_t>(
        {resource.size, per_resource_budget, remaining_budget});
    if (bounded_size < 64) return {};
    const auto prefix_size = static_cast<std::size_t>(bounded_size);
    remaining_budget -= prefix_size;
    const auto bytes = reader.bytes(resource.data_rva, prefix_size);
    const auto u16 = [&](std::uint64_t at) -> std::uint16_t {
        if (at > bytes.size() || bytes.size() - at < 2) return 0;
        return std::to_integer<std::uint8_t>(bytes[at]) |
               (std::uint16_t{std::to_integer<std::uint8_t>(bytes[at + 1])} << 8);
    };
    const auto u32 = [&](std::uint64_t at) -> std::uint32_t {
        if (at > bytes.size() || bytes.size() - at < 4) return 0;
        return std::to_integer<std::uint8_t>(bytes[at]) |
               (std::uint32_t{std::to_integer<std::uint8_t>(bytes[at + 1])} << 8) |
               (std::uint32_t{std::to_integer<std::uint8_t>(bytes[at + 2])} << 16) |
               (std::uint32_t{std::to_integer<std::uint8_t>(bytes[at + 3])} << 24);
    };
    const auto root_length = u16(0);
    if (root_length < 6 || root_length > resource.size || u16(4) != 0)
        return {};
    std::uint64_t cursor = 6;
    constexpr std::string_view root_key = "VS_VERSION_INFO";
    for (const char expected : root_key) {
        if (cursor + 2 > bytes.size() || u16(cursor) != static_cast<unsigned char>(expected)) return {};
        cursor += 2;
    }
    if (cursor + 2 > bytes.size() || u16(cursor) != 0) return {};
    cursor += 2;
    cursor = (cursor + 3) & ~std::uint64_t{3};
    const auto value_size = u16(2);
    if (value_size < fixed_info_size || cursor > root_length || fixed_info_size > root_length - cursor ||
        cursor > bytes.size() || fixed_info_size > bytes.size() - cursor ||
        u32(cursor) != fixed_info_signature)
        return {};

    const auto file_ms = u32(cursor + 8);
    const auto file_ls = u32(cursor + 12);
    const auto product_ms = u32(cursor + 16);
    const auto product_ls = u32(cursor + 20);
    PeVersionInfo result;
    result.file_version = {static_cast<std::uint16_t>(file_ms >> 16), static_cast<std::uint16_t>(file_ms),
                           static_cast<std::uint16_t>(file_ls >> 16), static_cast<std::uint16_t>(file_ls)};
    result.product_version = {static_cast<std::uint16_t>(product_ms >> 16), static_cast<std::uint16_t>(product_ms),
                              static_cast<std::uint16_t>(product_ls >> 16), static_cast<std::uint16_t>(product_ls)};
    result.file_flags = u32(cursor + 28);
    result.file_os = u32(cursor + 32);
    result.file_type = u32(cursor + 36);
    result.file_subtype = u32(cursor + 40);
    result.fixed_info = {resource.data_entry.index, reader.sources(resource.data_rva + cursor, fixed_info_size)};

    const auto mark_incomplete = [&] { result.string_tables_complete = false; };
    if (root_length > bytes.size()) {
        mark_incomplete();
        return result;
    }
    struct Block {
        std::size_t begin = 0, end = 0, value = 0, children = 0;
        std::uint16_t value_length = 0, type = 0;
        std::string key;
    };
    const auto align4 = [](std::size_t value) -> std::optional<std::size_t> {
        if (value > std::numeric_limits<std::size_t>::max() - 3) return {};
        return (value + 3) & ~std::size_t{3};
    };
    const auto read_block = [&](std::size_t begin, std::size_t parent_end) -> std::optional<Block> {
        if (begin > parent_end || parent_end - begin < 6) return {};
        const auto length = u16(begin);
        if (length < 6 || length > parent_end - begin) return {};
        Block block;
        block.begin = begin;
        block.end = begin + length;
        block.value_length = u16(begin + 2);
        block.type = u16(begin + 4);
        std::size_t key_at = begin + 6;
        while (key_at + 2 <= block.end && u16(key_at) != 0) {
            const auto ch = u16(key_at);
            if (ch >= 0xd800 && ch <= 0xdbff) {
                if (key_at + 4 > block.end) return {};
                const auto low = u16(key_at + 2);
                if (low < 0xdc00 || low > 0xdfff) return {};
                const auto cp = 0x10000u + ((std::uint32_t{ch} - 0xd800u) << 10) + (low - 0xdc00u);
                block.key.push_back(static_cast<char>(0xf0 | (cp >> 18)));
                block.key.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
                block.key.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                block.key.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                key_at += 4;
                continue;
            }
            if (ch >= 0xdc00 && ch <= 0xdfff) return {};
            if (ch < 0x80) block.key.push_back(static_cast<char>(ch));
            else if (ch < 0x800) {
                block.key.push_back(static_cast<char>(0xc0 | (ch >> 6)));
                block.key.push_back(static_cast<char>(0x80 | (ch & 0x3f)));
            } else {
                block.key.push_back(static_cast<char>(0xe0 | (ch >> 12)));
                block.key.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3f)));
                block.key.push_back(static_cast<char>(0x80 | (ch & 0x3f)));
            }
            key_at += 2;
        }
        if (key_at + 2 > block.end || u16(key_at) != 0) return {};
        const auto value_at = align4(key_at + 2);
        if (!value_at || *value_at > block.end) return {};
        const auto value_bytes = block.type == 1
            ? std::uint64_t{block.value_length} * 2
            : std::uint64_t{block.value_length};
        if (value_bytes > block.end - *value_at) return {};
        const auto children_at = align4(*value_at + static_cast<std::size_t>(value_bytes));
        if (!children_at || *children_at > block.end) return {};
        block.value = *value_at;
        block.children = *children_at;
        return block;
    };
    const auto decode_units = [&](std::size_t begin, std::size_t units, std::size_t end) -> std::optional<std::string> {
        if (begin > end || std::uint64_t{units} * 2 > end - begin) return {};
        std::string output;
        for (std::size_t i = 0; i < units; ++i) {
            auto cp = static_cast<std::uint32_t>(u16(begin + i * 2));
            if (cp >= 0xd800 && cp <= 0xdbff) {
                if (i + 1 >= units) return {};
                const auto low = u16(begin + (i + 1) * 2);
                if (low < 0xdc00 || low > 0xdfff) return {};
                cp = 0x10000u + ((cp - 0xd800u) << 10) + (low - 0xdc00u);
                ++i;
            } else if (cp >= 0xdc00 && cp <= 0xdfff) return {};
            if (cp == 0) {
                if (i + 1 != units) return {};
                break;
            }
            if (cp < 0x80) output.push_back(static_cast<char>(cp));
            else if (cp < 0x800) {
                output.push_back(static_cast<char>(0xc0 | (cp >> 6)));
                output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            } else if (cp < 0x10000) {
                output.push_back(static_cast<char>(0xe0 | (cp >> 12)));
                output.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            } else {
                output.push_back(static_cast<char>(0xf0 | (cp >> 18)));
                output.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
                output.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                output.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
            }
        }
        return output;
    };
    const auto decode_hex_word = [](std::string_view text, std::uint16_t &value) {
        if (text.size() != 4) return false;
        value = 0;
        for (const char ch : text) {
            value = static_cast<std::uint16_t>(value << 4);
            if (ch >= '0' && ch <= '9') value |= static_cast<std::uint16_t>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') value |= static_cast<std::uint16_t>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') value |= static_cast<std::uint16_t>(ch - 'A' + 10);
            else return false;
        }
        return true;
    };
    const auto root = read_block(0, root_length);
    if (!root) {
        mark_incomplete();
        return result;
    }
    std::size_t emitted = 0;
    const auto parse_children = [&](const Block &parent, auto &&consume) {
        std::size_t child_at = parent.children;
        while (child_at < parent.end) {
            if (parent.end - child_at < 6) {
                bool padding = true;
                for (std::size_t pos = child_at; pos < parent.end; ++pos)
                    if (bytes[pos] != std::byte{0}) { padding = false; break; }
                if (!padding) mark_incomplete();
                break;
            }
            if (u16(child_at) == 0) {
                bool padding = true;
                for (std::size_t pos = child_at; pos < parent.end; ++pos)
                    if (bytes[pos] != std::byte{0}) { padding = false; break; }
                if (!padding) mark_incomplete();
                break;
            }
            auto child = read_block(child_at, parent.end);
            if (!child) { mark_incomplete(); break; }
            consume(*child);
            const auto next = align4(child->end);
            if (!next || *next <= child_at || *next > parent.end) {
                mark_incomplete();
                break;
            }
            child_at = *next;
        }
    };
    parse_children(*root, [&](const Block &group) {
        if (group.key != "StringFileInfo") return;
        parse_children(group, [&](const Block &table) {
            if (table.key.size() != 8) { mark_incomplete(); return; }
            std::uint16_t language = 0, code_page = 0;
            if (!decode_hex_word(std::string_view(table.key).substr(0, 4), language) ||
                !decode_hex_word(std::string_view(table.key).substr(4, 4), code_page)) {
                mark_incomplete();
                return;
            }
            parse_children(table, [&](const Block &field) {
                if (field.key.empty() || field.type != 1) return;
                if (++emitted > 4096) { mark_incomplete(); return; }
                const auto value = decode_units(field.value, field.value_length, field.end);
                if (!value) { mark_incomplete(); return; }
                PeVersionString decoded;
                decoded.key = field.key;
                decoded.value = *value;
                decoded.language = language;
                decoded.code_page = code_page;
                decoded.source = {static_cast<std::uint32_t>(emitted - 1),
                                  reader.sources(resource.data_rva + field.begin, field.end - field.begin)};
                result.strings.push_back(std::move(decoded));
            });
        });
    });
    if (resource.size > prefix_size) mark_incomplete();
    return result;
}
}

Result<std::size_t> read_exports(const Image& image,const Directory& directory,ImageMetadata& metadata,std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader r(image,metadata,stop);
        require(directory.size>=40,"Export directory is shorter than its header");
        const auto at=std::uint64_t{directory.location};
        (void)r.bytes(at,40);
        const auto base=r.integer<std::uint32_t>(at+16);
        const auto functions=r.integer<std::uint32_t>(at+20);
        const auto name_count=r.integer<std::uint32_t>(at+24);
        const auto function_table=r.integer<std::uint32_t>(at+28);
        const auto name_table=r.integer<std::uint32_t>(at+32);
        const auto ordinal_table=r.integer<std::uint32_t>(at+36);
        r.array(function_table,functions,4);r.array(name_table,name_count,4);r.array(ordinal_table,name_count,2);
        struct NameRef { std::string name; std::uint32_t row; std::vector<PeSourceSpan> name_source; PeRecordSource table_source; };
        std::multimap<std::uint32_t,NameRef> names;
        for (std::uint64_t i=0;i<name_count;++i) {
            canceled(stop);
            const auto index=r.integer<std::uint16_t>(std::uint64_t{ordinal_table}+i*2);
            require(index<functions,"Export ordinal index exceeds address table");
            const auto name_rva=r.integer<std::uint32_t>(std::uint64_t{name_table}+i*4);
            auto [name,name_source]=r.sourced_string(name_rva);
            require(!name.empty(),"Empty export name");
            std::vector<PeSourceSpan> rows=r.sources(std::uint64_t{name_table}+i*4,4);
            auto ordinal_rows=r.sources(std::uint64_t{ordinal_table}+i*2,2);
            rows.insert(rows.end(),ordinal_rows.begin(),ordinal_rows.end());
            names.emplace(index,NameRef{std::move(name),static_cast<std::uint32_t>(i),std::move(name_source),{static_cast<std::uint32_t>(i),std::move(rows)}});
        }
        std::vector<ExportSymbol> exports;
        std::vector<PeExportSource> provenance;
        for (std::uint64_t i=0;i<functions;++i) {
            canceled(stop);
            require(i<=UINT32_MAX-base,"Export ordinal arithmetic overflows");
            const auto eat_rva=std::uint64_t{function_table}+i*4;
            const auto target=r.integer<std::uint32_t>(eat_rva);
            if (!target) {require(names.find(static_cast<std::uint32_t>(i))==names.end(),"Named export refers to an empty address slot");continue;}
            ExportSymbol symbol{base+static_cast<std::uint32_t>(i),{},{},{}};
            PeExportSource source;
            source.address_table={static_cast<std::uint32_t>(i),r.sources(eat_rva,4)};
            if (target>=directory.location && std::uint64_t{target}<at+directory.size) {
                auto [forwarder,forwarder_source]=r.sourced_string(target,at+directory.size);
                symbol.forwarder=std::move(forwarder);
                source.forwarder=std::move(forwarder_source);
                require(!symbol.forwarder->empty(),"Empty export forwarder");
            } else {
                symbol.address=r.address(target);
                require(image.segment_at(*symbol.address)!=nullptr,"Export address points into an unmapped gap");
            }
            const auto range=names.equal_range(static_cast<std::uint32_t>(i));
            if (range.first==range.second) {exports.push_back(symbol);provenance.push_back(source);}
            else for (auto name=range.first;name!=range.second;++name) {
                auto named=symbol;
                named.name=name->second.name;
                auto named_source=source;
                named_source.name_table=name->second.table_source;
                named_source.name=name->second.name_source;
                exports.push_back(std::move(named));
                provenance.push_back(std::move(named_source));
            }
        }
        const auto count=exports.size();
        metadata.exports.insert(metadata.exports.end(),std::make_move_iterator(exports.begin()),std::make_move_iterator(exports.end()));
        if (!metadata.pe) metadata.pe.emplace();
        metadata.pe->exports.insert(metadata.pe->exports.end(),std::make_move_iterator(provenance.begin()),std::make_move_iterator(provenance.end()));
        return count;
    });
}

Result<std::size_t> read_resources(const Image& image,const Directory& directory,ImageMetadata& metadata,std::stop_token stop) {
    return guarded([&]() -> std::size_t {
        ImageReader r(image,metadata,stop);
        require(directory.size>=16,"Resource directory is shorter than its header");
        const std::uint64_t root=directory.location, end=root+directory.size;
        std::size_t total=0;
        std::uint64_t version_parse_budget = 16u * 1024u * 1024u;
        std::vector<PeResourceIdentifier> path;
        std::set<std::uint32_t> active;
        auto source=[&](std::uint64_t at,std::uint64_t size,std::uint32_t index=0) {
            return PeRecordSource{index,r.sources(at,size)};
        };
        auto identifier=[&](std::uint32_t raw)->PeResourceIdentifier {
            PeResourceIdentifier result;
            if(raw&0x80000000u) {
                const auto name_at=root+(raw&0x7fffffffu);
                require(name_at<=end && end-name_at>=2,"Resource name offset exceeds directory");
                const auto length=r.integer<std::uint16_t>(name_at);
                require(std::uint64_t{length}*2<=end-name_at-2,"Resource name exceeds directory");
                const auto encoded=r.bytes(name_at+2,std::size_t{length}*2);
                std::string text;
                for(std::size_t i=0;i<encoded.size();i+=2) {
                    std::uint32_t cp=std::to_integer<unsigned char>(encoded[i])|
                        (std::uint32_t{std::to_integer<unsigned char>(encoded[i+1])}<<8);
                    if(cp>=0xd800 && cp<=0xdbff) {
                        require(i+3<encoded.size(),"Unpaired high surrogate in resource name");
                        const auto low=std::to_integer<unsigned char>(encoded[i+2])|
                            (std::uint32_t{std::to_integer<unsigned char>(encoded[i+3])}<<8);
                        require(low>=0xdc00 && low<=0xdfff,"Invalid surrogate pair in resource name");
                        cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00); i+=2;
                    } else require(cp<0xdc00 || cp>0xdfff,"Unpaired low surrogate in resource name");
                    if(cp<0x80) text.push_back(static_cast<char>(cp));
                    else if(cp<0x800) {text.push_back(static_cast<char>(0xc0|(cp>>6)));text.push_back(static_cast<char>(0x80|(cp&63)));}
                    else if(cp<0x10000) {text.push_back(static_cast<char>(0xe0|(cp>>12)));text.push_back(static_cast<char>(0x80|((cp>>6)&63)));text.push_back(static_cast<char>(0x80|(cp&63)));}
                    else {text.push_back(static_cast<char>(0xf0|(cp>>18)));text.push_back(static_cast<char>(0x80|((cp>>12)&63)));text.push_back(static_cast<char>(0x80|((cp>>6)&63)));text.push_back(static_cast<char>(0x80|(cp&63)));}
                }
                result.name=std::move(text); result.name_source=r.sources(name_at,2+std::uint64_t{length}*2);
            } else {
                require((raw&0xffff0000u)==0,"Resource numeric identifier has reserved bits set");
                result.id=static_cast<std::uint16_t>(raw);
            }
            return result;
        };
        std::function<void(std::uint32_t,unsigned)> walk;
        walk=[&](std::uint32_t relative,unsigned depth) {
            canceled(stop);
            require(depth<16,"Resource directory nesting exceeds limit",ErrorCode::resource_limit);
            require(relative<=directory.size && directory.size-relative>=16,"Resource subdirectory header exceeds directory");
            require(active.insert(relative).second,"Resource directory contains a cycle");
            const auto at=root+relative;
            const auto named=r.integer<std::uint16_t>(at+12), ids=r.integer<std::uint16_t>(at+14);
            const auto count=std::uint64_t{named}+ids;
            require(count<=record_limit-total,"Resource directory exceeds entry budget",ErrorCode::resource_limit);
            require(std::uint64_t{relative}+16+count*8<=directory.size,"Resource entries exceed directory");
            for(std::uint32_t i=0;i<count;++i) {
                canceled(stop);
                const auto item=at+16+std::uint64_t{i}*8;
                const auto name_raw=r.integer<std::uint32_t>(item), target=r.integer<std::uint32_t>(item+4);
                require((i<named)==((name_raw&0x80000000u)!=0),"Resource named and ID entries are not grouped as declared");
                auto id=identifier(name_raw);
                const bool subdirectory=(target&0x80000000u)!=0;
                const auto relative_target=target&0x7fffffffu;
                ++total;
                if(subdirectory) {
                    require(path.size()<3,"Resource hierarchy is deeper than type/name/language");
                    path.push_back(std::move(id)); walk(relative_target,depth+1); path.pop_back();
                } else {
                    require(path.size()==2,"Resource data entry is not at language level");
                    require(relative_target<=directory.size && directory.size-relative_target>=16,"Resource data entry exceeds directory");
                    const auto data_at=root+relative_target;
                    PeResource resource; resource.type=path[0]; resource.name=path[1]; resource.language=std::move(id);
                    resource.data_rva=r.integer<std::uint32_t>(data_at);
                    resource.size=r.integer<std::uint32_t>(data_at+4);
                    resource.code_page=r.integer<std::uint32_t>(data_at+8);
                    require(r.integer<std::uint32_t>(data_at+12)==0,"Resource data entry reserved field is nonzero");
                    require(resource.data_rva<=metadata.image_size && resource.size<=metadata.image_size-resource.data_rva,
                            "Resource payload exceeds image");
                    resource.payload=resource.size?r.sources(resource.data_rva,resource.size):std::vector<PeSourceSpan>{};
                    resource.entry=source(item,8,i); resource.data_entry=source(data_at,16,i);
                    if (resource.type.id == 16)
                        resource.version_info = parse_version_info(r, resource, version_parse_budget);
                    metadata.pe->resources.push_back(std::move(resource));
                }
            }
            active.erase(relative);
        };
        walk(0,0);
        return total;
    });
}
}
