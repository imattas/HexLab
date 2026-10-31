#include "hexlab/loaders/jvm.hpp"
#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <charconv>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace hexlab {
namespace {
constexpr std::uint64_t max_file=512ull*1024*1024, max_total_attributes=256ull*1024*1024;
struct Reader {
    std::span<const std::byte> b; std::size_t p=0;
    bool u1(std::uint8_t &v){if(p>=b.size())return false;v=std::to_integer<std::uint8_t>(b[p++]);return true;}
    bool u2(std::uint16_t &v){if(b.size()-p<2)return false;v=std::uint16_t((std::to_integer<std::uint8_t>(b[p])<<8)|std::to_integer<std::uint8_t>(b[p+1]));p+=2;return true;}
    bool u4(std::uint32_t &v){if(b.size()-p<4)return false;v=(std::uint32_t(std::to_integer<std::uint8_t>(b[p]))<<24)|(std::uint32_t(std::to_integer<std::uint8_t>(b[p+1]))<<16)|(std::uint32_t(std::to_integer<std::uint8_t>(b[p+2]))<<8)|std::to_integer<std::uint8_t>(b[p+3]);p+=4;return true;}
    bool u8(std::uint64_t &v){std::uint32_t hi=0,lo=0;if(!u4(hi)||!u4(lo))return false;v=(std::uint64_t(hi)<<32)|lo;return true;}
    bool skip(std::size_t n){if(n>b.size()-p)return false;p+=n;return true;}
    bool slice(std::size_t n,std::span<const std::byte>&out){if(n>b.size()-p)return false;out=b.subspan(p,n);p+=n;return true;}
};
Error malformed(std::string s){return {ErrorCode::malformed,std::move(s)};}
std::string_view smap_trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}
bool smap_number(std::string_view &input, std::uint32_t &value) {
    input = smap_trim(input);
    std::size_t digits = 0;
    while (digits < input.size() && input[digits] >= '0' && input[digits] <= '9') ++digits;
    if (!digits) return false;
    const auto parsed = std::from_chars(input.data(), input.data() + digits, value);
    if (parsed.ec != std::errc{}) return false;
    input.remove_prefix(digits);
    return true;
}
struct SmapParseResult {
    std::optional<JvmSourceDebugMap> map;
    std::string diagnostic;
    bool canceled = false;
};
SmapParseResult parse_source_debug_map(std::string_view source, std::stop_token stop) {
    SmapParseResult result;
    if (!source.starts_with("SMAP")) return result;
    constexpr std::size_t max_strata = 64, max_files = 8192, max_lines = 1'000'000;
    constexpr std::size_t max_owned_text = 16 * 1024 * 1024;
    std::vector<std::string_view> lines;
    lines.reserve(std::min<std::size_t>(source.size() / 12 + 1, max_lines + 16));
    for (std::size_t start = 0; start <= source.size();) {
        if ((lines.size() & 0xfff) == 0 && stop.stop_requested()) { result.canceled = true; return result; }
        auto end = source.find_first_of("\r\n", start);
        if (end == std::string_view::npos) end = source.size();
        lines.push_back(source.substr(start, end - start));
        if (lines.size() > max_lines + 16) {
            result.diagnostic = "SMAP has too many lines";
            return result;
        }
        if (end == source.size()) break;
        start = end + 1;
        if (source[end] == '\r' && start < source.size() && source[start] == '\n') ++start;
    }
    const auto fail = [&](std::string message) {
        result.diagnostic = std::move(message);
        return result;
    };
    if (lines.size() < 4 || lines[0] != "SMAP") return fail("SMAP header is incomplete");
    JvmSourceDebugMap map;
    auto generated = smap_trim(lines[1]);
    auto default_stratum = smap_trim(lines[2]);
    if (generated.empty() || generated.front() == '*' || default_stratum.empty() || default_stratum.front() == '*')
        return fail("SMAP generated file or default stratum is empty");
    std::size_t owned_text = generated.size() + default_stratum.size(), total_files = 0, total_mappings = 0;
    if (owned_text > max_owned_text) return fail("SMAP text exceeds metadata budget");
    map.generated_file.assign(generated);
    map.default_stratum.assign(default_stratum);
    enum class Section { none, files, lines, skip } section = Section::none;
    JvmSourceMapStratum *stratum = nullptr;
    bool files_seen = false, lines_seen = false, ended = false;
    std::uint32_t previous_file_id = 0;
    const auto finish_stratum = [&]() -> bool {
        if (!stratum) return true;
        return files_seen && lines_seen;
    };
    for (std::size_t index = 3; index < lines.size(); ++index) {
        if ((index & 0xfff) == 0 && stop.stop_requested()) { result.canceled = true; return result; }
        auto line = smap_trim(lines[index]);
        if (line.empty()) continue;
        if (ended) return fail("SMAP contains data after its end marker");
        if (line.front() == '*') {
            if (line == "*E") { ended = true; section = Section::none; continue; }
            if (line.starts_with("*S") && line.size() > 2 && (line[2] == ' ' || line[2] == '\t')) {
                if (!finish_stratum()) return fail("SMAP stratum is missing a file or line section");
                const auto name = smap_trim(line.substr(2));
                if (name.empty() || name.front() == '*' || map.strata.size() >= max_strata)
                    return fail("SMAP stratum name or count is invalid");
                if (std::any_of(map.strata.begin(), map.strata.end(), [&](const auto &item) { return item.name == name; }))
                    return fail("SMAP contains a duplicate stratum");
                owned_text += name.size();
                if (owned_text > max_owned_text) return fail("SMAP text exceeds metadata budget");
                map.strata.push_back({std::string(name), {}, {}});
                stratum = &map.strata.back();
                files_seen = lines_seen = false;
                previous_file_id = 0;
                section = Section::none;
                continue;
            }
            if (line == "*F") {
                if (!stratum || files_seen) return fail("SMAP file section is misplaced or duplicated");
                files_seen = true; section = Section::files; continue;
            }
            if (line == "*L") {
                if (!stratum || lines_seen) return fail("SMAP line section is misplaced or duplicated");
                lines_seen = true; section = Section::lines; continue;
            }
            if (line.starts_with("*O") || line.starts_with("*C"))
                return fail("embedded SMAP sections are not interpreted");
            if (line == "*V") {
                if (!stratum || index + 1 >= lines.size() || smap_trim(lines[index + 1]).empty())
                    return fail("SMAP vendor section has no vendor identifier");
                ++index;
                section = Section::skip;
                continue;
            }
            // JSR-45 permits future sections whose contents are to be ignored.
            section = Section::skip;
            continue;
        }
        if (section == Section::skip) continue;
        if (!stratum) return fail("SMAP data appears outside a stratum");
        if (section == Section::files) {
            if (++total_files > max_files) return fail("SMAP file count exceeds limit");
            std::string_view record = line;
            bool has_path = false;
            if (record.front() == '+') { has_path = true; record.remove_prefix(1); record = smap_trim(record); }
            std::uint32_t file_id = 0;
            if (!smap_number(record, file_id)) return fail("SMAP file entry has an invalid ID");
            record = smap_trim(record);
            if (record.empty() || record.front() == '*') return fail("SMAP file entry has an empty name");
            JvmSourceMapFile file{file_id, std::string(record), std::nullopt};
            owned_text += record.size();
            if (owned_text > max_owned_text) return fail("SMAP file names exceed metadata budget");
            if (has_path) {
                if (++index >= lines.size() || smap_trim(lines[index]).empty())
                    return fail("SMAP file path is missing");
                auto path = smap_trim(lines[index]);
                if (path.front() == '*') return fail("SMAP file path is invalid");
                file.path = std::string(path);
                owned_text += path.size();
                if (owned_text > max_owned_text) return fail("SMAP file paths exceed metadata budget");
            }
            if (std::any_of(stratum->files.begin(), stratum->files.end(), [&](const auto &item) { return item.id == file_id; }))
                return fail("SMAP file IDs must be unique within a stratum");
            stratum->files.push_back(std::move(file));
            continue;
        }
        if (section == Section::lines) {
            if (++total_mappings > max_lines) return fail("SMAP line-rule count exceeds limit");
            const auto colon = line.find(':');
            if (colon == std::string_view::npos || line.find(':', colon + 1) != std::string_view::npos)
                return fail("SMAP line rule must contain one colon");
            auto input = line.substr(0, colon), output = line.substr(colon + 1);
            std::uint32_t input_start = 0, file_id = previous_file_id, repeat = 1;
            if (!smap_number(input, input_start) || input_start == 0) return fail("SMAP input line is invalid");
            input = smap_trim(input);
            if (!input.empty() && input.front() == '#') {
                input.remove_prefix(1);
                if (!smap_number(input, file_id)) return fail("SMAP line file ID is invalid");
                input = smap_trim(input);
            }
            if (!input.empty() && input.front() == ',') {
                input.remove_prefix(1);
                if (!smap_number(input, repeat) || repeat == 0) return fail("SMAP line repeat count is invalid");
                input = smap_trim(input);
            }
            if (!smap_trim(input).empty()) return fail("SMAP input line rule has trailing data");
            std::uint32_t output_start = 0, increment = 1;
            if (!smap_number(output, output_start) || output_start == 0) return fail("SMAP output line is invalid");
            output = smap_trim(output);
            if (!output.empty() && output.front() == ',') {
                output.remove_prefix(1);
                if (!smap_number(output, increment)) return fail("SMAP output line increment is invalid");
                output = smap_trim(output);
            }
            if (!smap_trim(output).empty()) return fail("SMAP output line rule has trailing data");
            const auto input_end = std::uint64_t(input_start) + repeat - 1;
            const auto output_end = std::uint64_t(output_start) + std::uint64_t(repeat) * increment - (increment ? 1 : 0);
            if (input_end > UINT32_MAX || output_end > UINT32_MAX)
                return fail("SMAP line rule overflows 32-bit line numbering");
            previous_file_id = file_id;
            stratum->lines.push_back({input_start, file_id, repeat, output_start, increment});
            continue;
        }
        return fail("SMAP contains an unexpected non-section line");
    }
    if (!ended || !finish_stratum()) return fail("SMAP is missing its end marker or a required stratum section");
    if (map.strata.empty()) return fail("SMAP contains no strata");
    const bool default_exists = map.default_stratum == "Java" ||
        std::any_of(map.strata.begin(), map.strata.end(), [&](const auto &item) { return item.name == map.default_stratum; });
    if (!default_exists) return fail("SMAP default stratum is not declared");
    for (const auto &item : map.strata) {
        for (const auto &rule : item.lines)
            if (std::none_of(item.files.begin(), item.files.end(), [&](const auto &file) { return file.id == rule.file_id; }))
                return fail("SMAP line rule references an undeclared file ID");
    }
    result.map = std::move(map);
    return result;
}
std::unordered_set<std::string> generic_formals(const JvmGenericSignatureAnalysis *analysis) {
    std::unordered_set<std::string> names;
    if(!analysis||!analysis->parsed||analysis->parsed->nodes.empty())return names;
    const auto &tree=*analysis->parsed;
    for(const auto child:tree.nodes.front().children) {
        if(child<tree.nodes.size()&&tree.nodes[child].kind==JvmGenericNodeKind::type_parameter)
            names.insert(tree.nodes[child].name);
    }
    return names;
}
std::optional<std::string> unbound_generic_variable(const JvmGenericSignatureAnalysis *analysis,
                                                    const std::unordered_set<std::string> &scope) {
    if(!analysis||!analysis->parsed)return std::nullopt;
    for(const auto &node:analysis->parsed->nodes)
        if(node.kind==JvmGenericNodeKind::type_variable&&!scope.contains(node.name))
            return "generic type variable '"+node.name+"' is not declared by its class or method";
    return std::nullopt;
}
std::optional<std::string> erased_signature_type(const JvmGenericSignature &tree,std::uint32_t index,
        const std::unordered_map<std::string,std::string> &variables = {}) {
    if(index>=tree.nodes.size())return std::nullopt;
    const auto &node=tree.nodes[index];
    switch(node.kind) {
    case JvmGenericNodeKind::primitive:return node.name;
    case JvmGenericNodeKind::void_type:return std::string("V");
    case JvmGenericNodeKind::type_variable: {
        const auto found=variables.find(node.name);
        if(found==variables.end())return std::nullopt;
        return found->second;
    }
    case JvmGenericNodeKind::array_type:
        if(node.children.size()!=1)return std::nullopt;
        if(auto child=erased_signature_type(tree,node.children.front(),variables))return "["+*child;
        return std::nullopt;
    case JvmGenericNodeKind::class_type: {
        if(node.children.empty())return std::nullopt;
        std::string result="L";
        for(std::size_t i=0;i<node.children.size();++i) {
            const auto child=node.children[i];if(child>=tree.nodes.size()||tree.nodes[child].kind!=JvmGenericNodeKind::class_segment)return std::nullopt;
            if(i)result+="$";
            result+=tree.nodes[child].name;
        }
        result+=";";return result;
    }
    default:return std::nullopt;
    }
}
std::unordered_map<std::string,std::string> generic_variable_erasures(const JvmGenericSignature *tree,
        std::unordered_map<std::string,std::string> variables = {}) {
    if(!tree||tree->nodes.empty())return variables;
    std::vector<std::uint32_t> formals;
    for(const auto child:tree->nodes.front().children)
        if(child<tree->nodes.size()&&tree->nodes[child].kind==JvmGenericNodeKind::type_parameter)formals.push_back(child);
    std::vector<bool> resolved(formals.size(),false);
    for(std::size_t pass=0;pass<formals.size();++pass){
        bool changed=false;
        for(std::size_t i=0;i<formals.size();++i){
            if(resolved[i])continue;
            const auto &formal=tree->nodes[formals[i]];
            std::optional<std::uint32_t> bound;
            for(const auto child:formal.children)if(child<tree->nodes.size()){
                const auto &wrapper=tree->nodes[child];
                if((wrapper.kind==JvmGenericNodeKind::class_bound||wrapper.kind==JvmGenericNodeKind::interface_bound)&&!wrapper.children.empty()){
                    bound=wrapper.children.front();break;
                }
            }
            auto erased=bound?erased_signature_type(*tree,*bound,variables):std::optional<std::string>("Ljava/lang/Object;");
            if(erased){variables[formal.name]=std::move(*erased);resolved[i]=true;changed=true;}
        }
        if(!changed)break;
    }
    return variables;
}
bool valid_field_descriptor(std::string_view descriptor){
    if(descriptor.empty())return false;
    std::size_t position=0,dimensions=0;
    while(position<descriptor.size()&&descriptor[position]=='['){++position;if(++dimensions>255)return false;}
    if(position>=descriptor.size())return false;
    const auto type=descriptor[position++];
    if(type=='L'){
        const auto begin=position;const auto end=descriptor.find(';',position);
        if(end==std::string_view::npos||end==begin)return false;
        const auto name=descriptor.substr(begin,end-begin);
        if(name.find_first_of(".;[")!=std::string_view::npos||name.front()=='/'||name.back()=='/'||name.find("//")!=std::string_view::npos)return false;
        position=end+1;
    }else if(type!='B'&&type!='C'&&type!='D'&&type!='F'&&type!='I'&&type!='J'&&type!='S'&&type!='Z')return false;
    return position==descriptor.size();
}
bool valid_unqualified_member_name(std::string_view name) {
    return !name.empty() && name.find_first_of(".;[/") == std::string_view::npos;
}
Result<std::size_t> method_descriptor_parameter_count(std::string_view descriptor,bool include_this,
                                                       std::size_t *parameter_slots=nullptr){
    if(descriptor.empty()||descriptor.front()!='(')return malformed("invalid method descriptor for MethodParameters");
    std::size_t position=1,count=0,slots=0;const std::size_t slot_limit=include_this?254:255;
    const auto parse_type=[&](bool allow_void)->Result<unsigned>{
        std::size_t dimensions=0;
        while(position<descriptor.size()&&descriptor[position]=='['){++position;if(++dimensions>255)return malformed("method descriptor array dimension exceeds 255");}
        if(position>=descriptor.size())return malformed("truncated method descriptor");
        const auto tag=descriptor[position++];
        if(tag=='V'&&allow_void&&dimensions==0)return 0u;
        if(tag=='L'){
            const auto begin=position;const auto end=descriptor.find(';',position);
            if(end==std::string_view::npos||end==begin)return malformed("invalid object type in method descriptor");
            const auto name=descriptor.substr(begin,end-begin);
            if(name.find_first_of(".;[")!=std::string_view::npos||name.front()=='/'||name.back()=='/'||name.find("//")!=std::string_view::npos)
                return malformed("invalid object name in method descriptor");
            position=end+1;return 1u;
        }
        if(dimensions)return tag=='B'||tag=='C'||tag=='D'||tag=='F'||tag=='I'||tag=='J'||tag=='S'||tag=='Z' ? Result<unsigned>(1u) : Result<unsigned>(malformed("invalid array component in method descriptor"));
        if(tag=='B'||tag=='C'||tag=='F'||tag=='I'||tag=='S'||tag=='Z')return 1u;
        if(tag=='J'||tag=='D')return 2u;
        return malformed("invalid parameter type in method descriptor");
    };
    while(position<descriptor.size()&&descriptor[position]!=')'){
        auto width=parse_type(false);if(!width)return width.error();
        if(++count>255||slots>slot_limit-width.value())return malformed("method descriptor exceeds 255 parameter slots");
        slots+=width.value();
    }
    if(position>=descriptor.size()||descriptor[position++]!=')')return malformed("method descriptor has no parameter terminator");
    if(position>=descriptor.size())return malformed("method descriptor has no return type");
    if(descriptor[position]=='V')++position;
    else {auto result=parse_type(false);if(!result)return result.error();}
    if(position!=descriptor.size())return malformed("trailing bytes in method descriptor");
    if(parameter_slots)*parameter_slots=slots;
    return count;
}
// Restrict every nested attribute parser to its declared enclosing extent.
// Reader positions remain absolute class-file offsets.
struct ReaderExtent {
    Reader &reader;
    std::span<const std::byte> enclosing;
    ~ReaderExtent() { reader.b = enclosing; }
};
constexpr std::size_t max_stack_map_frames = 8192;
constexpr std::size_t max_class_stack_map_frames = 65536;
constexpr std::size_t max_expanded_verification_entries = 1024 * 1024;
Result<std::vector<bool>> scan_jvm_code(std::span<const std::byte> bytecode, Address begin,
                                        const JvmMetadata &metadata, std::stop_token stop) {
    std::vector<bool> instruction_starts(bytecode.size(), false);
    std::vector<Address> branch_targets;
    for (std::size_t offset = 0; offset < bytecode.size();) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM bytecode scan canceled"};
        auto decoded = decode_jvm(bytecode.subspan(offset), {begin.space, offset});
        if (decoded.status != DecodeStatus::decoded || !decoded.instruction) {
            if (decoded.status == DecodeStatus::unsupported)
                return Error{ErrorCode::unsupported, "unsupported JVM bytecode: " + decoded.reason};
            return malformed("invalid JVM bytecode: " + decoded.reason);
        }
        const auto &instruction = *decoded.instruction;
        const auto length = instruction.length;
        if (!length || length > bytecode.size() - offset)
            return malformed("invalid decoded JVM instruction extent");
        const auto opcode = std::to_integer<std::uint8_t>(bytecode[offset]);
        // The standalone decoder can only validate that a pool operand is a
        // nonzero index. Once the classfile pool is available, validate the
        // operand kind and (for dynamic constants) its descriptor category.
        if (opcode >= 0x12 && opcode <= 0x14) {
            const auto *constant_index = instruction.operands.empty()
                ? nullptr : std::get_if<ImmediateOperand>(&instruction.operands[0]);
            if (!constant_index || constant_index->value == 0 ||
                constant_index->value >= metadata.constant_pool.size())
                return malformed("JVM constant load has an invalid constant-pool index");
            const auto &constant = metadata.constant_pool[static_cast<std::size_t>(constant_index->value)];
            const bool wide_load = opcode == 0x14;
            bool category_two = constant.tag == 5 || constant.tag == 6;
            if (constant.tag == 17) {
                if (constant.second >= metadata.constant_pool.size())
                    return malformed("JVM dynamic constant has an invalid NameAndType index");
                const auto &name_and_type = metadata.constant_pool[static_cast<std::size_t>(constant.second)];
                if (name_and_type.tag != 12 || name_and_type.second >= metadata.constant_pool.size())
                    return malformed("JVM dynamic constant has a malformed NameAndType entry");
                const auto &descriptor = metadata.constant_pool[static_cast<std::size_t>(name_and_type.second)];
                if (descriptor.tag != 1 || descriptor.text.empty())
                    return malformed("JVM dynamic constant has an invalid field descriptor");
                category_two = descriptor.text == "J" || descriptor.text == "D";
            }
            const bool loadable = constant.tag == 3 || constant.tag == 4 || constant.tag == 5 ||
                constant.tag == 6 || constant.tag == 7 || constant.tag == 8 || constant.tag == 15 ||
                constant.tag == 16 || constant.tag == 17;
            if (!loadable || (wide_load != category_two))
                return malformed("JVM ldc opcode is incompatible with its constant-pool entry kind or category");
        }
        if (opcode >= 0xb2 && opcode <= 0xb5) {
            const auto *constant_index = instruction.operands.empty()
                ? nullptr : std::get_if<ImmediateOperand>(&instruction.operands[0]);
            if (!constant_index || constant_index->value == 0 ||
                constant_index->value >= metadata.constant_pool.size() ||
                metadata.constant_pool[static_cast<std::size_t>(constant_index->value)].tag != 9)
                return malformed("JVM field opcode must reference a CONSTANT_Fieldref entry");
        }
        if (opcode >= 0xb6 && opcode <= 0xba) {
            const auto *constant_index = instruction.operands.empty()
                ? nullptr : std::get_if<ImmediateOperand>(&instruction.operands[0]);
            if (!constant_index || constant_index->value == 0 ||
                constant_index->value >= metadata.constant_pool.size())
                return malformed("JVM invoke operand has an invalid constant-pool index");
            const auto &reference = metadata.constant_pool[static_cast<std::size_t>(constant_index->value)];
            const bool reference_kind_matches =
                (opcode == 0xb6 && reference.tag == 10) ||
                ((opcode == 0xb7 || opcode == 0xb8) &&
                    (reference.tag == 10 || (metadata.major_version >= 52 && reference.tag == 11))) ||
                (opcode == 0xb9 && reference.tag == 11) ||
                (opcode == 0xba && reference.tag == 18);
            if (!reference_kind_matches)
                return malformed("JVM invoke opcode references the wrong constant-pool entry kind");
            if(reference.second>=metadata.constant_pool.size())return malformed("JVM invoke has an invalid name-and-type index");
            const auto &name_and_type=metadata.constant_pool[static_cast<std::size_t>(reference.second)];
            if(name_and_type.tag!=12||name_and_type.second>=metadata.constant_pool.size())return malformed("JVM invoke name-and-type entry is malformed");
            const auto &descriptor=metadata.constant_pool[static_cast<std::size_t>(name_and_type.second)];
            if(descriptor.tag!=1)return malformed("JVM invoke descriptor is not CONSTANT_Utf8");
            std::size_t parameter_slots=0;
            auto parameters=method_descriptor_parameter_count(descriptor.text,opcode!=0xb8&&opcode!=0xba,&parameter_slots);
            if(!parameters)return malformed("JVM invoke descriptor violates its parameter-slot limit");
            if (opcode == 0xb9) {
                const auto *encoded_count = instruction.operands.size() > 1
                    ? std::get_if<ImmediateOperand>(&instruction.operands[1]) : nullptr;
                if (!encoded_count || encoded_count->value != parameter_slots + 1)
                    return malformed("invokeinterface argument count disagrees with its method descriptor");
            }
        }
        const bool legacy_subroutine = opcode == 0xa8 || opcode == 0xa9 || opcode == 0xc9 ||
            (opcode == 0xc4 && length >= 2 && std::to_integer<std::uint8_t>(bytecode[offset + 1]) == 0xa9);
        if (metadata.major_version >= 51 && legacy_subroutine)
            return malformed("jsr/ret bytecodes are prohibited in classfile version 51 or later");
        instruction_starts[offset] = true;
        if (instruction.direct_target) branch_targets.push_back(*instruction.direct_target);
        if (instruction.jvm_switch) {
            branch_targets.push_back(instruction.jvm_switch->default_target);
            for (const auto &entry : instruction.jvm_switch->cases) branch_targets.push_back(entry.target);
        }
        offset += length;
    }
    for (const auto target : branch_targets) {
        if (target.space != begin.space || target.offset >= bytecode.size() || !instruction_starts[target.offset])
            return malformed("JVM branch target does not identify an instruction boundary in its Code array");
    }
    return instruction_starts;
}
std::size_t verification_slots(const std::vector<JvmVerificationType> &values) {
    std::size_t result = 0;
    for (const auto &value : values)
        result += value.kind == JvmVerificationKind::long_value || value.kind == JvmVerificationKind::double_value ? 2 : 1;
    return result;
}
Result<std::vector<JvmVerificationType>> initial_verification_locals(const JvmMetadata &metadata, const JvmMember &method) {
    std::vector<JvmVerificationType> result;
    if (!(method.access_flags & 0x0008)) {
        JvmVerificationType self;
        if (method.name == "<init>" && metadata.super_class) self.kind = JvmVerificationKind::uninitialized_this;
        else { self.kind = JvmVerificationKind::object; self.class_index = metadata.this_class; }
        result.push_back(self);
    }
    const auto descriptor = std::string_view(method.descriptor);
    std::size_t position = 0;
    const auto read_type = [&](bool allow_void) -> Result<std::optional<JvmVerificationType>> {
        const auto begin = position;
        if (position >= descriptor.size()) return malformed("truncated StackMapTable method descriptor");
        const auto tag = descriptor[position++];
        if (tag == 'V' && allow_void) return std::optional<JvmVerificationType>{};
        JvmVerificationType value;
        switch (tag) {
        case 'B': case 'C': case 'I': case 'S': case 'Z': value.kind = JvmVerificationKind::integer; break;
        case 'F': value.kind = JvmVerificationKind::float_value; break;
        case 'D': value.kind = JvmVerificationKind::double_value; break;
        case 'J': value.kind = JvmVerificationKind::long_value; break;
        case 'L': case '[': {
            value.kind = JvmVerificationKind::object;
            char element = tag;
            if (tag == '[') {
                std::size_t dimensions = 1;
                while (position < descriptor.size() && descriptor[position] == '[') { ++dimensions; ++position; }
                if (dimensions > 255 || position == descriptor.size()) return malformed("invalid StackMapTable array parameter descriptor");
                element = descriptor[position++];
            }
            if (element == 'L') {
                const auto name_begin = position;
                const auto end = descriptor.find(';', position);
                if (end == std::string_view::npos || end == name_begin) return malformed("invalid StackMapTable object parameter descriptor");
                const auto name = descriptor.substr(name_begin, end - name_begin);
                if (name.find_first_of(".;[") != std::string_view::npos || name.front() == '/' || name.back() == '/' ||
                    name.find("//") != std::string_view::npos)
                    return malformed("invalid StackMapTable reference class name");
                position = end + 1;
            } else if (element != 'B' && element != 'C' && element != 'D' && element != 'F' && element != 'I' &&
                       element != 'J' && element != 'S' && element != 'Z')
                return malformed("invalid StackMapTable array element descriptor");
            value.descriptor_offset = static_cast<std::uint16_t>(begin);
            value.descriptor_length = static_cast<std::uint16_t>(position - begin);
            break;
        }
        default: return malformed("invalid StackMapTable method descriptor type");
        }
        return std::optional<JvmVerificationType>{value};
    };
    if (descriptor.size() > 65535 || descriptor.empty() || descriptor[position++] != '(')
        return malformed("invalid StackMapTable method descriptor");
    while (position < descriptor.size() && descriptor[position] != ')') {
        auto value = read_type(false); if (!value) return value.error();
        result.push_back(*value.value());
        if (verification_slots(result) > 255) return malformed("StackMapTable method descriptor exceeds the 255 parameter-slot limit");
    }
    if (position == descriptor.size() || descriptor[position++] != ')') return malformed("unterminated StackMapTable method descriptor");
    auto return_type = read_type(true); if (!return_type) return return_type.error();
    if (position != descriptor.size()) return malformed("trailing bytes in StackMapTable method descriptor");
    return result;
}
Result<JvmStackMapTable> read_stack_map_table(Reader &reader, const JvmMetadata &metadata, const JvmMember &method,
                                             const JvmCode &code, std::span<const std::byte> bytecode,
                                             std::stop_token stop, std::size_t &expanded_entries, std::size_t &total_frames) {
    JvmStackMapTable table;
    auto initial = initial_verification_locals(metadata, method); if (!initial) return initial.error();
    table.initial_locals = std::move(initial.value());
    const auto initial_slots = verification_slots(table.initial_locals);
    if (initial_slots > code.max_locals) return malformed("StackMapTable initial locals exceed Code.max_locals");
    table.initial_local_slots = static_cast<std::uint16_t>(initial_slots);
    if (table.initial_locals.size() > max_expanded_verification_entries - expanded_entries)
        return Error{ErrorCode::resource_limit, "classfile exceeds one million expanded verifier entries"};
    expanded_entries += table.initial_locals.size();
    std::uint16_t count = 0;
    if (!reader.u2(count)) return malformed("truncated StackMapTable entry count");
    if (count > max_stack_map_frames || count > max_class_stack_map_frames - total_frames)
        return Error{ErrorCode::resource_limit, "StackMapTable exceeds its per-method or per-class frame limit"};
    total_frames += count;
    // Reuse the actual decoder, including wide and switch padding/length rules.
    // No verifier offset is accepted merely because its byte resembles an opcode.
    std::vector<bool> instruction_starts;
    if (count) {
        auto scanned = scan_jvm_code(bytecode, code.begin, metadata, stop);
        if (!scanned) return scanned.error();
        instruction_starts = std::move(scanned.value());
    }
    const auto read_value = [&]() -> Result<JvmVerificationType> {
        std::uint8_t tag = 0;
        if (!reader.u1(tag)) return malformed("truncated StackMapTable verification type");
        if (tag > 8) return malformed("reserved StackMapTable verification type tag");
        JvmVerificationType value; value.kind = static_cast<JvmVerificationKind>(tag);
        if (value.kind == JvmVerificationKind::object) {
            if (!reader.u2(value.class_index) || !value.class_index || value.class_index >= metadata.constant_pool.size() ||
                metadata.constant_pool[value.class_index].tag != 7)
                return malformed("StackMapTable Object type has an invalid CONSTANT_Class index");
        } else if (value.kind == JvmVerificationKind::uninitialized) {
            if (!reader.u2(value.uninitialized_offset) || value.uninitialized_offset >= bytecode.size() ||
                !instruction_starts[value.uninitialized_offset] || bytecode[value.uninitialized_offset] != std::byte{0xbb})
                return malformed("StackMapTable uninitialized offset does not identify a decoded new instruction");
        }
        return value;
    };
    std::vector<JvmVerificationType> locals = table.initial_locals;
    table.frames.reserve(count);
    std::uint32_t previous_offset = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "StackMapTable frame parsing canceled"};
        JvmStackMapFrame frame;
        if (!reader.u1(frame.frame_type)) return malformed("truncated StackMapTable frame type");
        const auto tag = frame.frame_type;
        if (tag <= 63) frame.offset_delta = tag;
        else if (tag <= 127) frame.offset_delta = tag - 64;
        else if (tag <= 246) return malformed("reserved StackMapTable frame type");
        else if (!reader.u2(frame.offset_delta)) return malformed("truncated StackMapTable offset delta");
        frame.bytecode_offset = i == 0 ? frame.offset_delta : previous_offset + 1u + frame.offset_delta;
        if (frame.bytecode_offset >= bytecode.size() || !instruction_starts[frame.bytecode_offset])
            return malformed("StackMapTable frame offset does not identify a decoded instruction start");
        previous_offset = frame.bytecode_offset;
        if ((tag >= 64 && tag <= 127) || tag == 247) {
            auto value = read_value(); if (!value) return value.error(); frame.stack.push_back(value.value());
        } else if (tag >= 248 && tag <= 250) {
            const auto removed = static_cast<std::size_t>(251 - tag);
            if (removed > locals.size()) return malformed("StackMapTable chop removes more locals than the preceding frame");
            locals.resize(locals.size() - removed);
        } else if (tag >= 252 && tag <= 254) {
            for (unsigned n = 0; n < static_cast<unsigned>(tag - 251); ++n) {
                auto value = read_value(); if (!value) return value.error(); locals.push_back(value.value());
            }
        } else if (tag == 255) {
            std::uint16_t local_count = 0, stack_count = 0;
            if (!reader.u2(local_count) || local_count > code.max_locals) return malformed("invalid StackMapTable full-frame local count");
            locals.clear(); locals.reserve(local_count);
            for (std::size_t n = 0; n < local_count; ++n) {
                if ((n & 255u) == 0 && stop.stop_requested()) return Error{ErrorCode::canceled, "StackMapTable locals parsing canceled"};
                auto value = read_value(); if (!value) return value.error(); locals.push_back(value.value());
            }
            if (!reader.u2(stack_count) || stack_count > code.max_stack) return malformed("invalid StackMapTable full-frame stack count");
            frame.stack.reserve(stack_count);
            for (std::size_t n = 0; n < stack_count; ++n) {
                if ((n & 255u) == 0 && stop.stop_requested()) return Error{ErrorCode::canceled, "StackMapTable stack parsing canceled"};
                auto value = read_value(); if (!value) return value.error(); frame.stack.push_back(value.value());
            }
        }
        const auto local_slots = verification_slots(locals), stack_slots = verification_slots(frame.stack);
        if (local_slots > code.max_locals || stack_slots > code.max_stack)
            return malformed("StackMapTable frame exceeds Code.max_locals or Code.max_stack");
        const auto expanded = locals.size() + frame.stack.size();
        if (expanded > max_expanded_verification_entries - expanded_entries)
            return Error{ErrorCode::resource_limit, "classfile exceeds one million expanded verifier entries"};
        expanded_entries += expanded;
        frame.locals = locals;
        frame.local_slots = static_cast<std::uint16_t>(local_slots);
        frame.stack_slots = static_cast<std::uint16_t>(stack_slots);
        table.frames.push_back(std::move(frame));
    }
    return table;
}
Result<JvmStackMapTable> read_legacy_stack_map(Reader &reader, const JvmMetadata &metadata,
        const JvmMember &method, const JvmCode &code, std::span<const std::byte> bytecode,
        std::stop_token stop, std::size_t &expanded_entries, std::size_t &total_frames) {
    JvmStackMapTable table;
    auto initial = initial_verification_locals(metadata, method); if (!initial) return initial.error();
    table.initial_locals = std::move(initial.value());
    const auto initial_slots = verification_slots(table.initial_locals);
    if (initial_slots > code.max_locals) return malformed("StackMap initial locals exceed Code.max_locals");
    table.initial_local_slots = static_cast<std::uint16_t>(initial_slots);
    std::uint16_t count = 0;
    if (!reader.u2(count)) return malformed("truncated StackMap entry count");
    if (count > max_stack_map_frames || count > max_class_stack_map_frames - total_frames)
        return Error{ErrorCode::resource_limit, "StackMap exceeds its per-method or per-class frame limit"};
    total_frames += count;
    if (table.initial_locals.size() > max_expanded_verification_entries - expanded_entries)
        return Error{ErrorCode::resource_limit, "classfile exceeds one million expanded verifier entries"};
    expanded_entries += table.initial_locals.size();
    std::vector<bool> instruction_starts;
    if (count) {
        auto scanned = scan_jvm_code(bytecode, code.begin, metadata, stop);
        if (!scanned) return scanned.error();
        instruction_starts = std::move(scanned.value());
    }
    const auto read_value = [&]() -> Result<JvmVerificationType> {
        std::uint8_t tag = 0;
        if (!reader.u1(tag)) return malformed("truncated StackMap verification type");
        if (tag > 8) return malformed("reserved StackMap verification type tag");
        JvmVerificationType value; value.kind = static_cast<JvmVerificationKind>(tag);
        if (value.kind == JvmVerificationKind::object) {
            if (!reader.u2(value.class_index) || !value.class_index || value.class_index >= metadata.constant_pool.size() ||
                metadata.constant_pool[value.class_index].tag != 7)
                return malformed("StackMap Object type has an invalid CONSTANT_Class index");
        } else if (value.kind == JvmVerificationKind::uninitialized) {
            if (!reader.u2(value.uninitialized_offset) || value.uninitialized_offset >= bytecode.size() ||
                !instruction_starts[value.uninitialized_offset] || bytecode[value.uninitialized_offset] != std::byte{0xbb})
                return malformed("StackMap uninitialized offset does not identify a decoded new instruction");
        }
        return value;
    };
    table.frames.reserve(count);
    std::uint32_t previous_offset = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "StackMap frame parsing canceled"};
        JvmStackMapFrame frame;
        std::uint16_t local_count = 0, stack_count = 0;
        if (!reader.u2(frame.offset_delta) || !reader.u2(local_count) || local_count > code.max_locals)
            return malformed("invalid StackMap frame offset or local count");
        frame.frame_type = 255;
        frame.bytecode_offset = frame.offset_delta;
        if (i && frame.bytecode_offset <= previous_offset)
            return malformed("StackMap frame offsets are not strictly increasing");
        if (frame.bytecode_offset >= bytecode.size() || !instruction_starts[frame.bytecode_offset])
            return malformed("StackMap frame offset does not identify a decoded instruction start");
        previous_offset = frame.bytecode_offset;
        frame.locals.reserve(local_count);
        for (unsigned n = 0; n < local_count; ++n) {
            if ((n & 255u) == 0 && stop.stop_requested()) return Error{ErrorCode::canceled, "StackMap locals parsing canceled"};
            auto value = read_value(); if (!value) return value.error(); frame.locals.push_back(value.value());
        }
        if (!reader.u2(stack_count) || stack_count > code.max_stack)
            return malformed("invalid StackMap frame stack count");
        frame.stack.reserve(stack_count);
        for (unsigned n = 0; n < stack_count; ++n) {
            if ((n & 255u) == 0 && stop.stop_requested()) return Error{ErrorCode::canceled, "StackMap stack parsing canceled"};
            auto value = read_value(); if (!value) return value.error(); frame.stack.push_back(value.value());
        }
        const auto local_slots = verification_slots(frame.locals), stack_slots = verification_slots(frame.stack);
        if (local_slots > code.max_locals || stack_slots > code.max_stack)
            return malformed("StackMap frame exceeds Code.max_locals or Code.max_stack");
        const auto expanded = frame.locals.size() + frame.stack.size();
        if (expanded > max_expanded_verification_entries - expanded_entries)
            return Error{ErrorCode::resource_limit, "classfile exceeds one million expanded verifier entries"};
        expanded_entries += expanded;
        frame.local_slots = static_cast<std::uint16_t>(local_slots);
        frame.stack_slots = static_cast<std::uint16_t>(stack_slots);
        table.frames.push_back(std::move(frame));
    }
    return table;
}
bool valid_modified_utf8(std::string_view s){
    for(std::size_t i=0;i<s.size();){const auto a=static_cast<unsigned char>(s[i++]);
        if(a>0&&a<0x80)continue;
        if(a==0xc0){if(i>=s.size()||static_cast<unsigned char>(s[i++])!=0x80)return false;continue;}
        if(a>=0xc2&&a<=0xdf){if(i>=s.size()||(static_cast<unsigned char>(s[i++])&0xc0)!=0x80)return false;continue;}
        if(a>=0xe0&&a<=0xef){if(s.size()-i<2)return false;const auto b=static_cast<unsigned char>(s[i++]),c=static_cast<unsigned char>(s[i++]);if((b&0xc0)!=0x80||(c&0xc0)!=0x80||(a==0xe0&&b<0xa0))return false;continue;}
        return false;
    }return true;
}
bool valid_utf8(std::span<const std::byte> bytes) {
    for (std::size_t i = 0; i < bytes.size();) {
        const auto first = std::to_integer<std::uint8_t>(bytes[i++]);
        if (first <= 0x7f) continue;
        const auto continuation = [&](std::size_t offset) {
            return offset < bytes.size() && (std::to_integer<std::uint8_t>(bytes[offset]) & 0xc0) == 0x80;
        };
        if (first >= 0xc2 && first <= 0xdf) {
            if (!continuation(i)) return false;
            ++i;
        } else if (first >= 0xe0 && first <= 0xef) {
            if (bytes.size() - i < 2 || !continuation(i) || !continuation(i + 1)) return false;
            const auto second = std::to_integer<std::uint8_t>(bytes[i]);
            if ((first == 0xe0 && second < 0xa0) || (first == 0xed && second >= 0xa0)) return false;
            i += 2;
        } else if (first >= 0xf0 && first <= 0xf4) {
            if (bytes.size() - i < 3 || !continuation(i) || !continuation(i + 1) || !continuation(i + 2)) return false;
            const auto second = std::to_integer<std::uint8_t>(bytes[i]);
            if ((first == 0xf0 && second < 0x90) || (first == 0xf4 && second >= 0x90)) return false;
            i += 3;
        } else return false;
    }
    return true;
}
Result<LoadedImage> parse(std::shared_ptr<const ByteStorage> storage,std::stop_token stop){
    if(!storage)return Error{ErrorCode::invalid_argument,"JVM loading requires byte storage"};
    const auto size=storage->size(); if(size<10)return malformed("truncated JVM classfile header");
    if(size>max_file||size>SIZE_MAX)return Error{ErrorCode::resource_limit,"classfile exceeds the 512 MiB bounded loader limit"};
    auto src=storage->read_at({0},static_cast<std::size_t>(size));if(!src)return src.error();if(src.value().bytes.size()!=size)return Error{ErrorCode::io,"classfile source returned an incomplete read"};
    auto bytes=std::span<const std::byte>(src.value().bytes); Reader r{bytes};
    std::uint32_t magic=0;std::uint16_t minor=0,major=0,cp_count=0;
    if(!r.u4(magic)||magic!=0xcafebabe||!r.u2(minor)||!r.u2(major)||!r.u2(cp_count))return malformed("invalid or truncated JVM classfile header");
    if(major<45||major>70)return Error{ErrorCode::unsupported,"classfile versions 45 through 70 are supported"};
    if(cp_count==0)return malformed("constant_pool_count must be nonzero");
    JvmMetadata md;md.minor_version=minor;md.major_version=major;md.constant_pool.resize(cp_count);
    std::vector<FileOffset> constant_text_offsets(cp_count);
    for(std::uint32_t i=1;i<cp_count;++i){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"classfile constant-pool parsing canceled"};
        std::uint8_t tag=0;if(!r.u1(tag))return malformed("truncated constant-pool tag");auto &c=md.constant_pool[i];c.tag=tag;
        std::uint16_t a=0,b=0;std::uint32_t x=0;std::uint64_t wide=0;
        switch(tag){
        case 1:{if(!r.u2(a)||a>65535||a>bytes.size()-r.p)return malformed("truncated CONSTANT_Utf8 payload");
            // Preserve modified UTF-8 bytes. ASCII structural names remain directly usable;
            // non-ASCII constants are retained byte-for-byte for lossless metadata display.
            constant_text_offsets[i]=FileOffset{r.p};c.text.assign(reinterpret_cast<const char*>(bytes.data()+r.p),a);r.p+=a;if(!valid_modified_utf8(c.text))return malformed("invalid CONSTANT_Utf8 modified UTF-8");break;}
        case 3:case 4: if(!r.u4(x))return malformed("truncated numeric constant");c.first=x;break;
        case 5:case 6: if(!r.u8(wide))return malformed("truncated wide numeric constant");c.first=wide;if(++i<cp_count)md.constant_pool[i].tag=0;else return malformed("wide constant has no reserved following slot");break;
        case 7:case 8:case 16:case 19:case 20: if(!r.u2(a))return malformed("truncated constant-pool index");c.first=a;break;
        case 9:case 10:case 11:case 12:case 17:case 18: if(!r.u2(a)||!r.u2(b))return malformed("truncated constant-pool pair");c.first=a;c.second=b;break;
        case 15: if(!r.u1(tag)||!r.u2(a))return malformed("truncated method-handle constant");c.first=tag;c.second=a;break;
        default:return Error{ErrorCode::unsupported,"unknown JVM constant-pool tag " + std::to_string(tag)};
        }
    }
    for(std::size_t i=1;i<md.constant_pool.size();++i){const auto &c=md.constant_pool[i];if(!c.tag)continue;
        auto tag=[&](std::uint64_t index){return index<md.constant_pool.size()?md.constant_pool[static_cast<std::size_t>(index)].tag:std::uint8_t{0};};
        if((c.tag==15||c.tag==16||c.tag==18)&&major<51)return malformed("constant-pool method handles, method types, and InvokeDynamic require classfile version 51 or later");
        if((c.tag==19||c.tag==20)&&major<53)return malformed("constant-pool Module and Package entries require classfile version 53 or later");
        if(c.tag==17&&major<55)return malformed("constant-pool Dynamic entries require classfile version 55 or later");
        if((c.tag==7||c.tag==8||c.tag==16||c.tag==19||c.tag==20)&&tag(c.first)!=1)return malformed("constant-pool UTF-8 index has the wrong tag");
        if((c.tag==9||c.tag==10||c.tag==11)&&(tag(c.first)!=7||tag(c.second)!=12))return malformed("member reference has invalid class or name-and-type index");
        if(c.tag==12&&(tag(c.first)!=1||tag(c.second)!=1))return malformed("NameAndType has invalid UTF-8 indexes");
        if(c.tag==15){const auto kind=c.first;const auto rt=tag(c.second);const bool ok=kind>=1&&kind<=4?rt==9:kind==5||kind==8?rt==10:kind==6||kind==7?(rt==10||(major>=52&&rt==11)):kind==9?rt==11:false;if(!ok)return malformed("MethodHandle has an invalid reference kind or target");
            if(kind>=5){const auto &reference=md.constant_pool[static_cast<std::size_t>(c.second)];if(tag(reference.second)!=12)return malformed("MethodHandle method target has an invalid NameAndType index");const auto &name_and_type=md.constant_pool[static_cast<std::size_t>(reference.second)];if(tag(name_and_type.first)!=1)return malformed("MethodHandle target has an invalid method name index");const auto &name=md.constant_pool[static_cast<std::size_t>(name_and_type.first)].text;
                if((kind==8&&name!="<init>")||(kind!=8&&(name=="<init>"||name=="<clinit>")))return malformed("MethodHandle reference kind disagrees with its special method name");}}
        if((c.tag==17||c.tag==18)&&tag(c.second)!=12)return malformed("dynamic constant has invalid NameAndType index");
    }
    const auto utf8=[&](std::uint16_t ix)->Result<std::string>{if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=1)return malformed("constant-pool reference is not CONSTANT_Utf8");return md.constant_pool[ix].text;};
    const auto class_name=[&](std::uint16_t ix)->Result<std::string>{if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=7)return malformed("class index is not CONSTANT_Class");return utf8(static_cast<std::uint16_t>(md.constant_pool[ix].first));};
    const auto module_name=[&](std::uint16_t ix)->Result<std::string>{if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=19)return malformed("module index is not CONSTANT_Module");return utf8(static_cast<std::uint16_t>(md.constant_pool[ix].first));};
    const auto package_name=[&](std::uint16_t ix)->Result<std::string>{if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=20)return malformed("package index is not CONSTANT_Package");return utf8(static_cast<std::uint16_t>(md.constant_pool[ix].first));};
    for(std::size_t i=1;i<md.constant_pool.size();++i){
        const auto &entry=md.constant_pool[i];
        if(entry.tag!=9&&entry.tag!=10&&entry.tag!=11&&entry.tag!=17&&entry.tag!=18)continue;
        const auto &name_and_type=md.constant_pool[static_cast<std::size_t>(entry.second)];
        auto name=utf8(static_cast<std::uint16_t>(name_and_type.first));
        auto descriptor=utf8(static_cast<std::uint16_t>(name_and_type.second));
        if(!name)return name.error();if(!descriptor)return descriptor.error();
        if(!valid_unqualified_member_name(name.value()))return malformed("constant-pool member reference has an invalid unqualified name");
        const bool method_descriptor=entry.tag==10||entry.tag==11||entry.tag==18;
        if(method_descriptor){
            if(name.value()=="<clinit>"||(name.value()=="<init>"&&entry.tag!=10))return malformed("constant-pool method reference uses a prohibited special name");
            if((name.value().find('<')!=std::string::npos||name.value().find('>')!=std::string::npos)&&name.value()!="<init>")
                return malformed("constant-pool method reference has an invalid angle-bracket name");
            auto parsed=method_descriptor_parameter_count(descriptor.value(),false);
            if(!parsed)return malformed("constant-pool method reference has an invalid descriptor: "+parsed.error().message);
            if(name.value()=="<init>"&&descriptor.value().back()!='V')return malformed("constant-pool constructor reference must return void");
        }else if(name.value()=="<init>"||name.value()=="<clinit>"||!valid_field_descriptor(descriptor.value()))
            return malformed("constant-pool field or dynamic reference has an invalid name or descriptor");
    }
    std::uint16_t n=0;if(!r.u2(md.access_flags)||!r.u2(md.this_class)||!r.u2(md.super_class))return malformed("truncated class declaration");
    auto cn=class_name(md.this_class);if(!cn)return cn.error();md.class_name=std::move(cn.value());
    if(md.access_flags&~std::uint16_t{0xf631})return malformed("class declaration contains reserved access flags");
    if((md.access_flags&0x0010u)&&(md.access_flags&0x0400u))return malformed("class cannot be both final and abstract");
    if((md.access_flags&0x0200u)&&(!(md.access_flags&0x0400u)||(md.access_flags&0x0010u)))return malformed("interface must be abstract and cannot be final");
    if((md.access_flags&0x2000u)&&!(md.access_flags&0x0200u))return malformed("annotation class must also be an interface");
    if((md.access_flags&0x8000u)&&md.access_flags!=0x8000u)return malformed("ACC_MODULE class contains incompatible access flags");
    if(md.super_class){auto sn=class_name(md.super_class);if(!sn)return sn.error();md.super_name=std::move(sn.value());}
    if(!r.u2(n)||n>4096)return malformed("invalid interface count");md.interfaces.reserve(n);
    for(unsigned i=0;i<n;++i){std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated interface list");auto name=class_name(ix);if(!name)return name.error();md.interfaces.push_back(std::move(name.value()));}
    std::uint64_t attribute_bytes=0;bool metadata_complete=true;
    std::size_t retained_opaque_attributes=0,retained_opaque_name_bytes=0;
    std::size_t generic_attempts=0,generic_text_bytes=0,generic_nodes=0;
    const auto generic_analysis=[&](std::string_view text,std::uint16_t index,std::size_t reference,
                                    JvmGenericSignatureKind kind)->Result<JvmGenericSignatureAnalysis>{
        JvmGenericSignatureAnalysis analysis;analysis.signature_index=index;
        analysis.reference_file_offset=FileOffset{reference};analysis.text_file_offset=constant_text_offsets[index];
        if(major<49)analysis.diagnostic="Signature grammar requires class-file version 49 or newer";
        else if(generic_attempts>=4096||generic_nodes>=100000||text.size()>8u*1024u*1024u-generic_text_bytes)
            analysis.diagnostic="Class generic-signature analysis budget exhausted; raw signature retained";
        else {
            ++generic_attempts;generic_text_bytes+=text.size();auto tree=parse_jvm_generic_signature(text,kind,stop);
            if(!tree){if(tree.error().code==ErrorCode::canceled)return tree.error();analysis.diagnostic=tree.error().message;}
            else if(tree.value().nodes.size()>100000-generic_nodes)analysis.diagnostic="Class generic-signature node budget exhausted; raw signature retained";
            else {generic_nodes+=tree.value().nodes.size();analysis.parsed=std::move(tree.value());}
        }
        if(!analysis.parsed)metadata_complete=false;
        return analysis;
    };
    std::size_t expanded_verification_entries=0,stack_map_frames=0;
    bool have_record=false,have_inner_classes=false,have_enclosing_method=false,have_nest_host=false,have_nest_members=false,have_permitted_subclasses=false,have_preload=false;
    bool have_module_packages=false,have_module_main_class=false,have_module_target=false,have_module_resolution=false,have_module_hashes=false;
    bool have_bootstrap_methods=false,have_source_debug_extension=false;
    bool have_compilation_id=false,have_source_id=false;
    bool have_class_synthetic_attribute=false,have_class_deprecated_attribute=false;
    bool have_class_visible_annotations=false,have_class_invisible_annotations=false;
    bool have_class_visible_type_annotations=false,have_class_invisible_type_annotations=false;
    std::unordered_set<const JvmMember *> visible_annotations_seen,invisible_annotations_seen;
    std::unordered_set<const JvmMember *> visible_parameter_annotations_seen,invisible_parameter_annotations_seen,annotation_defaults_seen;
    std::unordered_set<const JvmMember *> visible_member_type_annotations_seen,invisible_member_type_annotations_seen;
    std::unordered_set<const JvmCode *> visible_code_type_annotations_seen,invisible_code_type_annotations_seen;
    std::unordered_set<const JvmRecordComponent *> visible_component_type_annotations_seen,invisible_component_type_annotations_seen;
    std::unordered_set<const JvmRecordComponent *> visible_component_annotations_seen,invisible_component_annotations_seen;
    std::size_t annotation_items=0;
    using LocalVariableKey=std::tuple<std::uint16_t,std::uint16_t,std::uint16_t,std::uint16_t,std::uint16_t>;
    std::unordered_map<const JvmCode *,std::set<LocalVariableKey>> local_variable_entries_seen;
    std::unordered_map<const JvmCode *,std::set<LocalVariableKey>> local_variable_type_entries_seen;
    struct ParsedAnnotationValue { std::string text; JvmAnnotationValue encoded; };
    constexpr std::size_t max_annotation_text=16*1024*1024;
    std::size_t annotation_text_bytes=0,annotation_value_nodes=0;
    const auto charge_annotation_text=[&](std::size_t size){
        if(size>max_annotation_text-annotation_text_bytes)return false;
        annotation_text_bytes+=size;return true;
    };
    const auto annotation_descriptor_ok=[](std::string_view value){
        return !value.empty()&&value.front()=='L'&&valid_field_descriptor(value);
    };
    const auto annotation_name_ok=[](std::string_view value){
        return valid_unqualified_member_name(value)&&value.find_first_of("<>")==std::string_view::npos;
    };
    std::function<Result<ParsedAnnotationValue>(unsigned)> annotation_value;
    annotation_value=[&](unsigned depth)->Result<ParsedAnnotationValue>{
        if(stop.stop_requested())return Error{ErrorCode::canceled,"annotation value parsing canceled"};
        if(depth>64)return Error{ErrorCode::resource_limit,"annotation nesting exceeds 64 levels"};
        if(annotation_value_nodes>=65536)return Error{ErrorCode::resource_limit,"annotation value trees exceed 65536 nodes"};
        ++annotation_value_nodes;
        ParsedAnnotationValue parsed;auto &node=parsed.encoded;node.file_begin={r.p};
        if(!r.u1(node.tag))return malformed("truncated annotation element_value");
        const auto tag=node.tag;
        const auto constant_ok=[&](std::uint16_t ix,std::uint8_t expected){
            return ix&&ix<md.constant_pool.size()&&md.constant_pool[ix].tag==expected;
        };
        const auto append=[&](std::string_view text){
            if(!charge_annotation_text(text.size()))return false;
            parsed.text.append(text);return true;
        };
        const auto text_limit=[](){return Error{ErrorCode::resource_limit,"annotation decoded text exceeds 16 MiB"};};
        if(tag=='B'||tag=='C'||tag=='I'||tag=='S'||tag=='Z'||tag=='D'||tag=='F'||tag=='J'){
            if(!r.u2(node.constant_pool_index))return malformed("truncated annotation constant element");
            const auto expected=(tag=='D'?6:tag=='F'?4:tag=='J'?5:3);
            if(!constant_ok(node.constant_pool_index,static_cast<std::uint8_t>(expected)))return malformed("annotation element has a constant-pool entry of the wrong kind");
            if(!append(std::string("const(")+char(tag)+":"+std::to_string(node.constant_pool_index)+")"))return text_limit();
        }else if(tag=='s'){
            if(!r.u2(node.constant_pool_index))return malformed("truncated annotation string element");
            if(!constant_ok(node.constant_pool_index,1))return malformed("annotation string does not reference CONSTANT_Utf8");
            if(!append("string#"+std::to_string(node.constant_pool_index)))return text_limit();
        }else if(tag=='e'){
            if(!r.u2(node.constant_pool_index)||!r.u2(node.enum_name_index))return malformed("truncated annotation enum element");
            auto type=utf8(node.constant_pool_index),name=utf8(node.enum_name_index);if(!type)return type.error();if(!name)return name.error();
            if(!annotation_descriptor_ok(type.value())||!valid_unqualified_member_name(name.value()))return malformed("invalid annotation enum descriptor or constant name");
            if(!append("enum(")||!append(type.value())||!append("#")||!append(name.value())||!append(")"))return text_limit();
        }else if(tag=='c'){
            if(!r.u2(node.constant_pool_index))return malformed("truncated annotation class element");
            auto descriptor=utf8(node.constant_pool_index);if(!descriptor)return descriptor.error();
            if(descriptor.value()!="V"&&!valid_field_descriptor(descriptor.value()))return malformed("annotation class literal has an invalid return descriptor");
            if(!append("class(")||!append(descriptor.value())||!append(")"))return text_limit();
        }else if(tag=='@'){
            std::uint16_t pairs=0;
            if(!r.u2(node.constant_pool_index)||!r.u2(pairs))return malformed("truncated nested annotation element");
            auto descriptor=utf8(node.constant_pool_index);if(!descriptor)return descriptor.error();
            if(!annotation_descriptor_ok(descriptor.value()))return malformed("nested annotation has an invalid object descriptor");
            if(pairs>65536-annotation_items)return Error{ErrorCode::resource_limit,"annotation metadata exceeds 65536 elements"};annotation_items+=pairs;
            node.children.reserve(pairs);node.element_name_indices.reserve(pairs);
            if(!append("annotation(")||!append(descriptor.value()))return text_limit();
            std::unordered_set<std::string> element_names;
            for(unsigned i=0;i<pairs;++i){
                std::uint16_t name=0;if(!r.u2(name))return malformed("truncated nested annotation element name");
                auto resolved=utf8(name);if(!resolved)return resolved.error();
                if(!annotation_name_ok(resolved.value())||!element_names.insert(resolved.value()).second)return malformed("invalid or duplicate nested annotation element name");
                if(!append(";")||!append(resolved.value())||!append("="))return text_limit();
                auto value=annotation_value(depth+1);if(!value)return value.error();
                if(!append(value.value().text))return text_limit();
                node.element_name_indices.push_back(name);node.children.push_back(std::move(value.value().encoded));
            }
            if(!append(")"))return text_limit();
        }else if(tag=='['){
            std::uint16_t count=0;if(!r.u2(count))return malformed("truncated annotation array element");
            if(count>65536-annotation_items)return Error{ErrorCode::resource_limit,"annotation metadata exceeds 65536 elements"};annotation_items+=count;
            node.children.reserve(count);if(!append("["))return text_limit();
            for(unsigned i=0;i<count;++i){
                auto value=annotation_value(depth+1);if(!value)return value.error();
                if((i&&!append(","))||!append(value.value().text))return text_limit();
                node.children.push_back(std::move(value.value().encoded));
            }
            if(!append("]"))return text_limit();
        }else return malformed("invalid annotation element_value tag");
        node.byte_size=static_cast<std::uint32_t>(r.p-node.file_begin.value);
        return parsed;
    };
    const auto read_one_annotation=[&]()->Result<JvmAnnotation>{
        if(stop.stop_requested())return Error{ErrorCode::canceled,"annotation declaration parsing canceled"};
        JvmAnnotation annotation;annotation.file_begin={r.p};std::uint16_t type=0,pairs=0;
        if(!r.u2(type)||!r.u2(pairs))return malformed("truncated annotation declaration");
        auto descriptor=utf8(type);if(!descriptor)return descriptor.error();
        if(!annotation_descriptor_ok(descriptor.value()))return malformed("annotation declaration has an invalid object descriptor");
        if(!charge_annotation_text(descriptor.value().size()))return Error{ErrorCode::resource_limit,"annotation decoded text exceeds 16 MiB"};
        if(pairs>65536-annotation_items)return Error{ErrorCode::resource_limit,"annotation metadata exceeds 65536 elements"};
        annotation_items+=pairs;annotation.descriptor=std::move(descriptor.value());annotation.elements.reserve(pairs);
        annotation.type_index=type;std::unordered_set<std::string> element_names;
        for(unsigned j=0;j<pairs;++j){
            std::uint16_t name=0;if(!r.u2(name))return malformed("truncated annotation element name");
            auto element_name=utf8(name);if(!element_name)return element_name.error();
            if(!annotation_name_ok(element_name.value())||!element_names.insert(element_name.value()).second)return malformed("invalid or duplicate annotation element name");
            if(!charge_annotation_text(element_name.value().size()))return Error{ErrorCode::resource_limit,"annotation decoded text exceeds 16 MiB"};
            auto value=annotation_value(0);if(!value)return value.error();
            annotation.elements.push_back({std::move(element_name.value()),std::move(value.value().text),std::move(value.value().encoded),name});
        }
        annotation.byte_size=static_cast<std::uint32_t>(r.p-annotation.file_begin.value);
        return annotation;
    };
    const auto read_annotations=[&](std::vector<JvmAnnotation> &out)->Result<bool>{
        std::uint16_t count=0;if(!r.u2(count))return malformed("truncated annotation count");
        if(count>65536-annotation_items)return Error{ErrorCode::resource_limit,"annotation metadata exceeds 65536 elements"};annotation_items+=count;
        out.reserve(out.size()+count);
        for(unsigned i=0;i<count;++i){auto annotation=read_one_annotation();if(!annotation)return annotation.error();out.push_back(std::move(annotation.value()));
        }return true;
    };
    std::unordered_set<const JvmMember *> fields_with_constant_value;
    std::function<Result<bool>(bool,JvmMember*,bool,JvmCode*,JvmRecordComponent*)> attributes;
    attributes=[&](bool method,JvmMember *member,bool class_level,JvmCode *code_owner,
                   JvmRecordComponent *record_component)->Result<bool>{
        std::uint16_t count=0;if(!r.u2(count))return malformed("truncated attributes_count");
        if(count>8192)return Error{ErrorCode::resource_limit,"attribute count exceeds the 8192-per-owner limit"};
        for(unsigned ai=0;ai<count;++ai){if(stop.stop_requested())return Error{ErrorCode::canceled,"classfile attribute parsing canceled"};std::uint16_t name_ix=0;std::uint32_t len=0;if(!r.u2(name_ix)||!r.u4(len))return malformed("truncated attribute header");
            if(len>64*1024*1024||attribute_bytes>max_total_attributes-len)return Error{ErrorCode::resource_limit,"classfile attribute data exceeds bounded size limits"};attribute_bytes+=len;
            auto an=utf8(name_ix);if(!an)return an.error();const auto start=r.p;if(len>r.b.size()-r.p)return malformed("attribute extent exceeds its enclosing owner");
            ReaderExtent extent{r,r.b};r.b=r.b.first(start+len);
            if(!class_level&&(an.value()=="NestHost"||an.value()=="NestMembers"||an.value()=="PermittedSubclasses"||an.value()=="Preload"||an.value()=="Record"||an.value()=="InnerClasses"||an.value()=="EnclosingMethod"||an.value()=="Module"||an.value()=="ModulePackages"||an.value()=="ModuleMainClass"||an.value()=="ModuleTarget"||an.value()=="ModuleResolution"||an.value()=="ModuleHashes"||an.value()=="BootstrapMethods"||an.value()=="SourceFile"||an.value()=="SourceDebugExtension"||an.value()=="CompilationID"||an.value()=="SourceID"))return malformed("class-level attribute appears on a member or Code attribute list");
            if(record_component&&an.value()=="Code")return malformed("Code attribute appears on a Record component");
            if(an.value()=="Signature"){
                if(code_owner)return malformed("Signature attribute appears inside Code");
                if(len!=2)return malformed("Signature attribute must contain one UTF-8 index");
                std::uint16_t index=0;if(!r.u2(index))return malformed("truncated Signature attribute");
                auto signature=utf8(index);if(!signature)return signature.error();
                auto generic=generic_analysis(signature.value(),index,start,class_level?JvmGenericSignatureKind::class_signature:
                    method&&!record_component?JvmGenericSignatureKind::method_signature:JvmGenericSignatureKind::field_signature);
                if(!generic)return generic.error();
                if(class_level){if(md.signature)return malformed("duplicate class Signature attribute");md.signature=std::move(signature.value());md.generic_signature=std::move(generic.value());}
                else if(record_component){if(record_component->signature)return malformed("duplicate Record component Signature attribute");record_component->signature=std::move(signature.value());record_component->generic_signature=std::move(generic.value());}
                else {if(!member)return malformed("Signature attribute has no declaration owner");if(member->signature)return malformed("duplicate member Signature attribute");member->signature=std::move(signature.value());member->generic_signature=std::move(generic.value());}
            }else if(an.value()=="Synthetic"||an.value()=="Deprecated"){
                if(code_owner||record_component||len!=0)
                    return malformed(an.value()+" attribute must be empty and appear on a class, field, or method");
                const bool synthetic=an.value()=="Synthetic";
                if(class_level){
                    bool &seen=synthetic?have_class_synthetic_attribute:have_class_deprecated_attribute;
                    if(seen)return malformed("duplicate class-level "+an.value()+" attribute");
                    seen=true;
                    if(synthetic)md.synthetic_attribute=true;
                    else md.deprecated_attribute=true;
                }else{
                    if(!member)return malformed(an.value()+" attribute has no class member owner");
                    bool &seen=synthetic?member->synthetic_attribute:member->deprecated_attribute;
                    if(seen)return malformed("duplicate member "+an.value()+" attribute");
                    seen=true;
                }
            }else if(an.value()=="ConstantValue"){
                if(!member||method||class_level||code_owner)
                    return malformed("ConstantValue attribute appears outside a field attribute list");
                if((member->access_flags&0x0008u)==0)
                    return malformed("ConstantValue attribute appears on a non-static field");
                if(!fields_with_constant_value.insert(member).second)
                    return malformed("duplicate ConstantValue attribute on a field");
                std::uint16_t index=0;
                if(len!=2||!r.u2(index)||!index||index>=md.constant_pool.size())
                    return malformed("ConstantValue attribute has an invalid constant index or length");
                const auto &constant=md.constant_pool[index];
                const auto &descriptor=member->descriptor;
                const std::uint8_t expected_tag = descriptor=="B"||descriptor=="C"||descriptor=="I"||descriptor=="S"||descriptor=="Z" ? 3 :
                    descriptor=="F" ? 4 : descriptor=="J" ? 5 : descriptor=="D" ? 6 :
                    descriptor=="Ljava/lang/String;" ? 8 : 0;
                if(!expected_tag||constant.tag!=expected_tag)
                    return malformed("ConstantValue constant kind does not match the field descriptor");
                JvmConstant value=constant;
                if(constant.tag==8){
                    const auto string_index=static_cast<std::size_t>(constant.first);
                    if(string_index>=md.constant_pool.size()||md.constant_pool[string_index].tag!=1)
                        return malformed("ConstantValue string has an invalid UTF-8 constant index");
                    value.text=md.constant_pool[string_index].text;
                }
                member->constant_value=std::move(value);
            }else if(an.value()=="RuntimeVisibleAnnotations"||an.value()=="RuntimeInvisibleAnnotations"){
                if(major<49)return malformed("annotation attributes require class-file version 49 or newer");
                if(code_owner)return malformed("declaration annotation attribute appears inside Code");
                if(!class_level&&!member&&!record_component)return malformed("annotation attribute has no declaration owner");
                const bool visible=an.value()=="RuntimeVisibleAnnotations";
                bool duplicate=false;
                if(class_level){bool &seen=visible?have_class_visible_annotations:have_class_invisible_annotations;duplicate=seen;seen=true;}
                else if(record_component){auto &owners=visible?visible_component_annotations_seen:invisible_component_annotations_seen;duplicate=!owners.insert(record_component).second;}
                else {auto &owners=visible?visible_annotations_seen:invisible_annotations_seen;duplicate=!owners.insert(member).second;}
                if(duplicate)return malformed("duplicate annotation attribute");
                auto &target=class_level?(visible?md.visible_annotations:md.invisible_annotations):record_component?(visible?record_component->visible_annotations:record_component->invisible_annotations):(visible?member->visible_annotations:member->invisible_annotations);
                auto parsed=read_annotations(target);if(!parsed)return parsed.error();
            }else if(an.value()=="MethodParameters"){
                if(major<52)return malformed("MethodParameters attribute requires class-file version 52 or newer");
                if(class_level||!member||!method||code_owner)return malformed("MethodParameters appears outside a method declaration");
                if(member->method_parameters)return malformed("duplicate MethodParameters attribute");
                std::uint8_t count=0;if(len<1||!r.u1(count)||std::uint64_t(count)*4+1!=len)
                    return malformed("MethodParameters length does not match its entries");
                auto descriptor_count=method_descriptor_parameter_count(member->descriptor,(member->access_flags&0x0008u)==0);
                if(!descriptor_count)return descriptor_count.error();
                if(descriptor_count.value()!=count)return malformed("MethodParameters count does not match the method descriptor");
                std::vector<JvmMethodParameter> parameters;parameters.reserve(count);
                for(unsigned i=0;i<count;++i){
                    JvmMethodParameter parameter;
                    if(!r.u2(parameter.name_index)||!r.u2(parameter.access_flags))return malformed("truncated MethodParameters entry");
                    if(parameter.name_index){auto name=utf8(parameter.name_index);if(!name)return name.error();
                        if(name.value().empty()||name.value().find_first_of(".;[/")!=std::string::npos)
                            return malformed("MethodParameters name is not a valid unqualified name");
                        parameter.name=std::move(name.value());}
                    if(parameter.access_flags&~std::uint16_t{0x9010})return malformed("MethodParameters entry has reserved access flags");
                    parameters.push_back(std::move(parameter));
                }
                member->method_parameters=std::move(parameters);
            }else if(an.value()=="RuntimeVisibleTypeAnnotations"||an.value()=="RuntimeInvisibleTypeAnnotations"){
                if(major<52)return malformed("type-annotation attribute requires class-file version 52 or newer");
                const bool visible=an.value()=="RuntimeVisibleTypeAnnotations";
                if(class_level){bool &seen=visible?have_class_visible_type_annotations:have_class_invisible_type_annotations;if(seen)return malformed("duplicate type-annotation attribute");seen=true;}
                else if(code_owner){auto &seen=visible?visible_code_type_annotations_seen:invisible_code_type_annotations_seen;if(!seen.insert(code_owner).second)return malformed("duplicate Code type-annotation attribute");}
                else if(record_component){auto &seen=visible?visible_component_type_annotations_seen:invisible_component_type_annotations_seen;if(!seen.insert(record_component).second)return malformed("duplicate record-component type-annotation attribute");}
                else {if(!member)return malformed("type-annotation attribute has no declaration owner");auto &seen=visible?visible_member_type_annotations_seen:invisible_member_type_annotations_seen;if(!seen.insert(member).second)return malformed("duplicate member type-annotation attribute");}
                auto &target=class_level?(visible?md.visible_type_annotations:md.invisible_type_annotations):code_owner?(visible?code_owner->visible_type_annotations:code_owner->invisible_type_annotations):record_component?(visible?record_component->visible_type_annotations:record_component->invisible_type_annotations):(visible?member->visible_type_annotations:member->invisible_type_annotations);
                std::uint16_t entries=0;if(!r.u2(entries))return malformed("truncated type-annotation count");
                if(entries>65536-annotation_items)return Error{ErrorCode::resource_limit,"type-annotation metadata exceeds 65536 entries"};annotation_items+=entries;
                if(target.size()+entries>65536)return Error{ErrorCode::resource_limit,"type-annotation owner exceeds 65536 entries"};target.reserve(target.size()+entries);
                const auto append1=[](std::vector<std::uint8_t> &out,std::uint8_t v){out.push_back(v);};
                const auto append2=[](std::vector<std::uint8_t> &out,std::uint16_t v){out.push_back(static_cast<std::uint8_t>(v>>8));out.push_back(static_cast<std::uint8_t>(v));};
                for(unsigned ti=0;ti<entries;++ti){
                    JvmTypeAnnotation item;if(!r.u1(item.target_type))return malformed("truncated type-annotation target_type");
                    const auto tt=item.target_type;
                    const bool class_target=tt==0x00||tt==0x10||tt==0x11;
                    const bool method_target=tt==0x01||tt==0x12||(tt>=0x14&&tt<=0x17);
                    const bool field_target=tt==0x13;
                    const bool code_target=tt>=0x40&&tt<=0x4b;
                    const bool owner_mismatch=class_level?!class_target:code_owner?!code_target:record_component?!field_target:method?!method_target:!field_target;
                    if(owner_mismatch)return malformed("type-annotation target is invalid for its owner");
                    std::uint8_t b1=0,b2=0;std::uint16_t w1=0,w2=0;
                    if(tt==0x00||tt==0x01||tt==0x16){if(!r.u1(b1))return malformed("truncated type-annotation target_info");append1(item.target_info,b1);}
                    else if(tt==0x10||tt==0x17||tt==0x42||(tt>=0x43&&tt<=0x46)){if(!r.u2(w1))return malformed("truncated type-annotation target_info");append2(item.target_info,w1);if(tt==0x10&&w1!=0xffff&&w1>=md.interfaces.size())return malformed("type-annotation supertype index exceeds interface table");}
                    else if(tt==0x11||tt==0x12){if(!r.u1(b1)||!r.u1(b2))return malformed("truncated type-annotation bound target_info");append1(item.target_info,b1);append1(item.target_info,b2);}
                    else if(tt==0x13||tt==0x14||tt==0x15){}
                    else if(tt==0x40||tt==0x41){if(!r.u2(w1))return malformed("truncated type-annotation local-variable table");append2(item.target_info,w1);if(w1>65536-annotation_items)return Error{ErrorCode::resource_limit,"type-annotation local-variable table exceeds bound"};annotation_items+=w1;for(unsigned j=0;j<w1;++j){std::uint16_t start_pc=0,length=0,slot=0;if(!r.u2(start_pc)||!r.u2(length)||!r.u2(slot))return malformed("truncated type-annotation local-variable entry");if(std::uint32_t(start_pc)+length>code_owner->code_size||slot>=code_owner->max_locals)return malformed("type-annotation local-variable entry exceeds Code bounds");append2(item.target_info,start_pc);append2(item.target_info,length);append2(item.target_info,slot);}}
                    else if(tt==0x47||tt==0x48||tt==0x49||tt==0x4a||tt==0x4b){if(!r.u2(w1)||!r.u1(b1))return malformed("truncated type-annotation type-argument target");if(w1>=code_owner->code_size)return malformed("type-annotation target offset exceeds Code bounds");append2(item.target_info,w1);append1(item.target_info,b1);}
                    if(tt==0x42&&w1>=code_owner->exception_table.size())return malformed("type-annotation exception target exceeds exception table");
                    if(tt>=0x43&&tt<=0x46&&w1>=code_owner->code_size)return malformed("type-annotation target offset exceeds Code bounds");
                    std::uint8_t path_length=0;if(!r.u1(path_length))return malformed("truncated type_path length");if(path_length>65536-annotation_items)return Error{ErrorCode::resource_limit,"type_path entries exceed annotation bound"};annotation_items+=path_length;item.type_path.reserve(path_length);
                    for(unsigned j=0;j<path_length;++j){std::uint8_t kind=0,arg=0;if(!r.u1(kind)||!r.u1(arg)||kind>3||(kind!=3&&arg!=0))return malformed("invalid type_path entry");item.type_path.emplace_back(kind,arg);}
                    auto annotation=read_one_annotation();if(!annotation)return annotation.error();item.annotation=std::move(annotation.value());target.push_back(std::move(item));
                }
            }else if(an.value()=="RuntimeVisibleParameterAnnotations"||an.value()=="RuntimeInvisibleParameterAnnotations"){
                if(major<49)return malformed("parameter annotation attributes require class-file version 49 or newer");
                if(class_level||!member||!method||code_owner)return malformed("parameter annotation attribute appears outside a method declaration");
                const bool visible=an.value()=="RuntimeVisibleParameterAnnotations";
                auto &owners=visible?visible_parameter_annotations_seen:invisible_parameter_annotations_seen;
                if(!owners.insert(member).second)return malformed("duplicate parameter annotation attribute");
                std::uint8_t parameters=0;if(!r.u1(parameters))return malformed("truncated parameter annotation count");
                std::vector<std::vector<JvmAnnotation>> parsed(parameters);
                for(auto &parameter:parsed){auto result=read_annotations(parameter);if(!result)return result.error();}
                (visible?member->visible_parameter_annotations:member->invisible_parameter_annotations)=std::move(parsed);
            }else if(an.value()=="AnnotationDefault"){
                if(major<49)return malformed("AnnotationDefault requires class-file version 49 or newer");
                if(class_level||!member||!method||code_owner)return malformed("AnnotationDefault appears outside a method declaration");
                if((md.access_flags&0x2000u)==0)return malformed("AnnotationDefault appears on a method outside an annotation interface");
                if(!annotation_defaults_seen.insert(member).second)return malformed("duplicate AnnotationDefault attribute");
                const auto close=member->descriptor.find(')');
                if(member->descriptor.empty()||member->descriptor.front()!='('||close==std::string::npos||close!=1)
                    return malformed("AnnotationDefault method must have no parameters and a valid method descriptor");
                const auto result_descriptor=std::string_view(member->descriptor).substr(close+1);
                if(result_descriptor.empty()||result_descriptor=="V")return malformed("AnnotationDefault method must return an annotation element type");
                const auto component=result_descriptor.front()=='['?result_descriptor.substr(1):result_descriptor;
                if(component.empty()||component.front()=='['||!valid_field_descriptor(component))
                    return malformed("AnnotationDefault return type must be a scalar annotation element or one-dimensional array");
                auto value=annotation_value(0);if(!value)return value.error();
                std::function<bool(const JvmAnnotationValue&,std::string_view)> compatible;
                compatible=[&](const JvmAnnotationValue& node,std::string_view descriptor){
                    if(stop.stop_requested())return false;
                    if(descriptor.front()=='['){
                        if(node.tag!='[')return false;
                        for(const auto& child:node.children)if(!compatible(child,descriptor.substr(1)))return false;
                        return true;
                    }
                    if(descriptor.size()==1)return node.tag==static_cast<std::uint8_t>(descriptor.front());
                    if(descriptor=="Ljava/lang/String;")return node.tag=='s';
                    if(descriptor=="Ljava/lang/Class;")return node.tag=='c';
                    return (node.tag=='e'||node.tag=='@')&&md.constant_pool[node.constant_pool_index].text==descriptor;
                };
                const auto matches=compatible(value.value().encoded,result_descriptor);
                if(stop.stop_requested())return Error{ErrorCode::canceled,"annotation default validation canceled"};
                if(!matches)return malformed("AnnotationDefault value kind or array element does not match its method return descriptor");
                member->annotation_default=std::move(value.value().text);
                member->annotation_default_value=std::move(value.value().encoded);
            }else if(an.value()=="StackMapTable"){
                if(!code_owner||!member)return malformed("StackMapTable appears outside a Code attribute");
                if(code_owner->stack_map_table)return malformed("duplicate StackMapTable attribute");
                const auto code_bytes=bytes.subspan(static_cast<std::size_t>(code_owner->file_begin.value),code_owner->code_size);
                auto table=read_stack_map_table(r,md,*member,*code_owner,code_bytes,stop,expanded_verification_entries,stack_map_frames);
                if(!table)return table.error();code_owner->stack_map_table=std::move(table.value());
            }else if(an.value()=="StackMap"){
                if(!code_owner||!member)return malformed("StackMap appears outside a Code attribute");
                if(md.major_version>=50)return Error{ErrorCode::unsupported,"legacy StackMap is supported only for class-file versions before 50"};
                if(code_owner->stack_map_table)return malformed("duplicate StackMap or StackMapTable attribute");
                const auto code_bytes=bytes.subspan(static_cast<std::size_t>(code_owner->file_begin.value),code_owner->code_size);
                auto table=read_legacy_stack_map(r,md,*member,*code_owner,code_bytes,stop,expanded_verification_entries,stack_map_frames);
                if(!table)return table.error();code_owner->stack_map_table=std::move(table.value());
            }else if(an.value()=="LineNumberTable"){
                if(!code_owner||!member)return malformed("LineNumberTable appears outside a Code attribute");
                std::uint16_t entries=0;if(len<2||!r.u2(entries)||std::uint64_t(entries)*4+2!=len)return malformed("LineNumberTable length does not match its entries");
                if(code_owner->line_numbers&&entries>65535-code_owner->line_numbers->size())return Error{ErrorCode::resource_limit,"aggregate LineNumberTable entries exceed 65535 per Code attribute"};
                if(!code_owner->line_numbers)code_owner->line_numbers.emplace();
                code_owner->line_numbers->reserve(code_owner->line_numbers->size()+entries);
                for(unsigned i=0;i<entries;++i){JvmLineNumber line;if(!r.u2(line.start_pc)||!r.u2(line.line_number)||line.start_pc>=code_owner->code_size)return malformed("invalid LineNumberTable code offset");code_owner->line_numbers->push_back(line);}
            }else if(an.value()=="CharacterRangeTable"){
                if(!code_owner||!member)return malformed("CharacterRangeTable appears outside a Code attribute");
                std::uint16_t entries=0;
                if(len<2||!r.u2(entries)||std::uint64_t(entries)*14+2!=len)
                    return malformed("CharacterRangeTable length does not match its entries");
                if(code_owner->character_ranges&&entries>65535-code_owner->character_ranges->size())
                    return Error{ErrorCode::resource_limit,"aggregate CharacterRangeTable entries exceed 65535 per Code attribute"};
                if(!code_owner->character_ranges)code_owner->character_ranges.emplace();
                auto &ranges=*code_owner->character_ranges;
                ranges.reserve(ranges.size()+entries);
                for(unsigned i=0;i<entries;++i){
                    JvmCharacterRange range;
                    if(!r.u2(range.start_pc)||!r.u2(range.end_pc)||!r.u4(range.character_start)||
                       !r.u4(range.character_end)||!r.u2(range.flags))
                        return malformed("truncated CharacterRangeTable entry");
                    if(range.start_pc>range.end_pc||range.end_pc>code_owner->code_size||
                       range.character_start>range.character_end)
                        return malformed("invalid CharacterRangeTable bytecode or source range");
                    ranges.push_back(range);
                }
            }else if(an.value()=="LocalVariableTable"){
                if(!code_owner||!member)return malformed("LocalVariableTable appears outside a Code attribute");
                std::uint16_t entries=0;if(len<2||!r.u2(entries)||std::uint64_t(entries)*10+2!=len)return malformed("LocalVariableTable length does not match its entries");
                if(code_owner->local_variables&&entries>65535-code_owner->local_variables->size())return Error{ErrorCode::resource_limit,"aggregate LocalVariableTable entries exceed 65535 per Code attribute"};
                if(!code_owner->local_variables)code_owner->local_variables.emplace();
                auto &locals=*code_owner->local_variables;locals.reserve(locals.size()+entries);
                for(unsigned i=0;i<entries;++i){JvmLocalVariable local;
                    if(!r.u2(local.start_pc)||!r.u2(local.length)||!r.u2(local.name_index)||!r.u2(local.descriptor_index)||!r.u2(local.slot))return malformed("truncated LocalVariableTable entry");
                    if(local.start_pc>=code_owner->code_size||std::uint32_t(local.start_pc)+local.length>code_owner->code_size||local.slot>=code_owner->max_locals)return malformed("LocalVariableTable entry exceeds Code bounds");
                    auto name=utf8(local.name_index),descriptor=utf8(local.descriptor_index);if(!name)return name.error();if(!descriptor)return descriptor.error();
                    if(!valid_field_descriptor(descriptor.value()))return malformed("LocalVariableTable entry has an invalid field descriptor");
                    if((descriptor.value()[0]=='J'||descriptor.value()[0]=='D')&&local.slot+1>=code_owner->max_locals)return malformed("category-2 local variable exceeds Code.max_locals");
                    local.name=std::move(name.value());local.descriptor=std::move(descriptor.value());
                    auto &seen=local_variable_entries_seen[code_owner];
                    if(!seen.emplace(local.start_pc,local.length,local.name_index,local.descriptor_index,local.slot).second)return malformed("duplicate LocalVariableTable entry");
                    locals.push_back(std::move(local));
                }
            }else if(an.value()=="LocalVariableTypeTable"){
                if(!code_owner||!member)return malformed("LocalVariableTypeTable appears outside a Code attribute");
                std::uint16_t entries=0;if(len<2||!r.u2(entries)||std::uint64_t(entries)*10+2!=len)return malformed("LocalVariableTypeTable length does not match its entries");
                if(code_owner->local_variable_types&&entries>65535-code_owner->local_variable_types->size())return Error{ErrorCode::resource_limit,"aggregate LocalVariableTypeTable entries exceed 65535 per Code attribute"};
                if(!code_owner->local_variable_types)code_owner->local_variable_types.emplace();
                auto &locals=*code_owner->local_variable_types;locals.reserve(locals.size()+entries);
                for(unsigned i=0;i<entries;++i){JvmLocalVariableType local;
                    if(!r.u2(local.start_pc)||!r.u2(local.length)||!r.u2(local.name_index)||!r.u2(local.signature_index)||!r.u2(local.slot))return malformed("truncated LocalVariableTypeTable entry");
                    if(local.start_pc>=code_owner->code_size||std::uint32_t(local.start_pc)+local.length>code_owner->code_size||local.slot>=code_owner->max_locals)return malformed("LocalVariableTypeTable entry exceeds Code bounds");
                    auto name=utf8(local.name_index),signature=utf8(local.signature_index);if(!name)return name.error();if(!signature)return signature.error();
                    local.name=std::move(name.value());local.signature=std::move(signature.value());
                    const auto signature_reference=start+2+std::size_t{i}*10+6;
                    auto generic=generic_analysis(local.signature,local.signature_index,signature_reference,
                                                  JvmGenericSignatureKind::field_signature);
                    if(!generic)return generic.error();
                    local.generic_signature=std::move(generic.value());
                    auto &seen=local_variable_type_entries_seen[code_owner];
                    if(!seen.emplace(local.start_pc,local.length,local.name_index,local.signature_index,local.slot).second)return malformed("duplicate LocalVariableTypeTable entry");
                    locals.push_back(std::move(local));
                }
            }else if(method&&member&&an.value()=="Exceptions"){
                if(member->declared_exceptions)return malformed("duplicate Exceptions attribute");
                std::uint16_t exception_count=0;
                if(len<2||!r.u2(exception_count)||std::uint64_t(exception_count)*2+2!=len)
                    return malformed("Exceptions attribute length does not match its class indexes");
                member->declared_exceptions.emplace();member->declared_exceptions->reserve(exception_count);
                for(unsigned i=0;i<exception_count;++i){
                    std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated Exceptions class index");
                    auto name=class_name(ix);if(!name)return name.error();
                    member->declared_exceptions->push_back(std::move(name.value()));
                }
            }else if(an.value()=="Exceptions"){
                return malformed("Exceptions attribute appears outside a method attribute list");
            }else if(method&&member&&an.value()=="Code"){
                if(member->code)return malformed("duplicate Code attribute");
                std::uint16_t ms=0,ml=0,ec=0;std::uint32_t cl=0;
                if(!r.u2(ms)||!r.u2(ml)||!r.u4(cl)||cl==0||cl>65535||cl>r.b.size()-r.p)return malformed("invalid Code attribute header or bytecode extent");
                const auto code_off=r.p;r.p+=cl;if(!r.u2(ec)||ec>8192||std::uint64_t(ec)*8>r.b.size()-r.p)return malformed("invalid Code exception table extent");
                JvmCode code; code.begin={{static_cast<std::uint32_t>(std::distance(md.methods.data(),member)+1)},0};
                code.file_begin={code_off}; code.max_stack=ms; code.max_locals=ml; code.code_size=cl;
                const auto code_bytes=bytes.subspan(code_off,cl);
                auto code_scan=scan_jvm_code(code_bytes,code.begin,md,stop);
                if(!code_scan)return code_scan.error();
                code.exception_table.reserve(ec);
                for(unsigned k=0;k<ec;++k){JvmExceptionHandler e;if(!r.u2(e.start_pc)||!r.u2(e.end_pc)||!r.u2(e.handler_pc)||!r.u2(e.catch_type)||e.start_pc>=e.end_pc||e.end_pc>cl||e.handler_pc>=cl)return malformed("invalid Code exception handler range");
                    const auto &instruction_starts=code_scan.value();
                    if(!instruction_starts[e.start_pc]||(e.end_pc<cl&&!instruction_starts[e.end_pc])||!instruction_starts[e.handler_pc])
                        return malformed("Code exception handler offsets must identify instruction boundaries");
                    if(e.catch_type){auto c=class_name(e.catch_type);if(!c)return c.error();}code.exception_table.push_back(e);}
                auto nested=attributes(false,member,false,&code,nullptr);local_variable_entries_seen.erase(&code);if(!nested)return nested.error();
                if(r.p!=start+len)return malformed("Code attribute length does not match its parsed structure");
                member->code=std::move(code);
            }else if(class_level&&an.value()=="SourceFile"){
                if(md.source_file)return malformed("duplicate SourceFile attribute");
                std::uint16_t index=0;if(len!=2||!r.u2(index))return malformed("SourceFile attribute must contain one UTF-8 index");
                auto source=utf8(index);if(!source)return source.error();md.source_file=std::move(source.value());
            }else if(class_level&&an.value()=="SourceDebugExtension"){
                if(have_source_debug_extension)return malformed("duplicate SourceDebugExtension attribute");
                const auto payload=r.b.subspan(r.p,len);
                if(!valid_utf8(payload))return malformed("SourceDebugExtension payload is not valid UTF-8");
                if(payload.empty())md.source_debug_extension=std::string{};
                else md.source_debug_extension=std::string(reinterpret_cast<const char*>(payload.data()),payload.size());
                if (md.source_debug_extension) {
                    auto parsed = parse_source_debug_map(*md.source_debug_extension, stop);
                    if (parsed.canceled) return Error{ErrorCode::canceled, "JVM SourceDebugExtension parsing canceled"};
                    if (parsed.map) md.source_debug_map = std::move(parsed.map);
                    else if (!parsed.diagnostic.empty()) md.source_debug_map_diagnostic = std::move(parsed.diagnostic);
                }
                have_source_debug_extension=true;
                if(!r.skip(len))return malformed("truncated SourceDebugExtension payload");
            }else if(class_level&&(an.value()=="CompilationID"||an.value()=="SourceID")){
                const bool compilation=an.value()=="CompilationID";
                bool &seen=compilation?have_compilation_id:have_source_id;
                auto &destination=compilation?md.compilation_id:md.source_id;
                if(seen)return malformed("duplicate "+an.value()+" attribute");
                std::uint16_t index=0;
                if(len!=2||!r.u2(index))return malformed(an.value()+" attribute must contain one UTF-8 index");
                auto value=utf8(index);if(!value)return value.error();
                destination=JvmProvenanceId{index,FileOffset{start},std::move(value.value())};
                seen=true;
            }else if(class_level&&an.value()=="EnclosingMethod"){
                if(major<49)return malformed("EnclosingMethod attribute requires class-file version 49 or newer");
                if(have_enclosing_method)return malformed("duplicate EnclosingMethod attribute");
                std::uint16_t class_index=0,method_index=0;
                if(len!=4||!r.u2(class_index)||!r.u2(method_index))return malformed("EnclosingMethod attribute must contain exactly two indexes");
                auto owner=class_name(class_index);if(!owner)return owner.error();
                JvmEnclosingMethod enclosing;enclosing.class_name=std::move(owner.value());
                if(method_index){
                    if(method_index>=md.constant_pool.size()||md.constant_pool[method_index].tag!=12)return malformed("EnclosingMethod method index is not CONSTANT_NameAndType");
                    const auto &name_and_type=md.constant_pool[method_index];
                    auto name=utf8(static_cast<std::uint16_t>(name_and_type.first));if(!name)return name.error();
                    auto descriptor=utf8(static_cast<std::uint16_t>(name_and_type.second));if(!descriptor)return descriptor.error();
                    if(name.value().empty()||name.value().find_first_of(".;[/")!=std::string::npos)return malformed("EnclosingMethod has an invalid method name");
                    auto parameters=method_descriptor_parameter_count(descriptor.value(),false);if(!parameters)return malformed("EnclosingMethod has an invalid method descriptor");
                    if(name.value()=="<clinit>"&&descriptor.value()!="()V")return malformed("EnclosingMethod class initializer must have descriptor ()V");
                    if(name.value()=="<init>"&&descriptor.value().back()!='V')return malformed("EnclosingMethod constructor must return void");
                    enclosing.method_name=std::move(name.value());enclosing.method_descriptor=std::move(descriptor.value());
                }
                md.enclosing_method=std::move(enclosing);have_enclosing_method=true;
            }else if(class_level&&an.value()=="InnerClasses"){
                if(have_inner_classes)return malformed("duplicate InnerClasses attribute");
                if(len<2)return malformed("truncated InnerClasses attribute");
                std::uint16_t count=0;
                if(!r.u2(count)||count>8192||std::uint64_t(count)*8+2!=len)
                    return malformed("InnerClasses count or extent is invalid");
                md.inner_classes.reserve(count);
                std::unordered_set<std::uint16_t> inner_indexes;
                constexpr std::uint16_t allowed_flags=0x761f;
                for(unsigned i=0;i<count;++i){
                    std::uint16_t inner_index=0,outer_index=0,name_index=0,flags=0;
                    if(!r.u2(inner_index)||!r.u2(outer_index)||!r.u2(name_index)||!r.u2(flags))
                        return malformed("truncated InnerClasses entry");
                    if(!inner_indexes.insert(inner_index).second||flags&~allowed_flags)
                        return malformed("duplicate inner class or reserved InnerClasses flags");
                    if(md.major_version>=51&&name_index==0&&outer_index!=0)
                        return malformed("InnerClasses entry with no inner name must not specify an outer class");
                    auto inner_name=class_name(inner_index);if(!inner_name)return inner_name.error();
                    JvmInnerClass entry;entry.inner_class=std::move(inner_name.value());entry.access_flags=flags;
                    if(outer_index){auto outer_name=class_name(outer_index);if(!outer_name)return outer_name.error();entry.outer_class=std::move(outer_name.value());}
                    if(name_index){auto name=utf8(name_index);if(!name)return name.error();entry.inner_name=std::move(name.value());}
                    md.inner_classes.push_back(std::move(entry));
                }
                have_inner_classes=true;
            }else if(class_level&&an.value()=="NestHost"){
                if(md.major_version<55)return malformed("NestHost requires class-file version 55 or newer");
                if(have_nest_members)return malformed("class cannot declare both NestHost and NestMembers");
                if(have_nest_host)return malformed("duplicate NestHost attribute");
                if(len!=2)return malformed("NestHost attribute must contain exactly one class index");
                const auto reference_offset=r.p;
                std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated NestHost attribute");
                auto name=class_name(ix);if(!name)return name.error();
                md.nest_host=name.value();
                md.nest_host_reference=JvmClassReference{ix,{reference_offset},std::move(name.value())};
                have_nest_host=true;
            }else if(class_level&&an.value()=="NestMembers"){
                if(md.major_version<55)return malformed("NestMembers requires class-file version 55 or newer");
                if(have_nest_host)return malformed("class cannot declare both NestHost and NestMembers");
                if(have_nest_members)return malformed("duplicate NestMembers attribute");
                if(len<2)return malformed("truncated NestMembers attribute");
                std::uint16_t count=0;if(!r.u2(count)||count>8192)return malformed("invalid NestMembers count");
                if(std::uint64_t(count)*2+2!=len)return malformed("NestMembers attribute length does not match its class indexes");
                md.nest_members.reserve(count);
                md.nest_member_references.reserve(count);
                for(unsigned i=0;i<count;++i){
                    const auto reference_offset=r.p;
                    std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated NestMembers class index");
                    auto name=class_name(ix);if(!name)return name.error();
                    md.nest_members.push_back(name.value());
                    md.nest_member_references.push_back({ix,{reference_offset},std::move(name.value())});
                }
                have_nest_members=true;
            }else if(class_level&&an.value()=="PermittedSubclasses"){
                const bool preview=md.minor_version==65535&&md.major_version>=59&&md.major_version<61;
                if(md.major_version<61&&!preview)return malformed("PermittedSubclasses requires class-file version 61 or a supported preview version");
                if(md.access_flags&0x0010)return malformed("PermittedSubclasses is not allowed on a final class or interface");
                if(have_permitted_subclasses)return malformed("duplicate PermittedSubclasses attribute");
                if(len<2)return malformed("truncated PermittedSubclasses attribute");
                std::uint16_t count=0;if(!r.u2(count)||count>8192)return malformed("invalid PermittedSubclasses count");
                if(std::uint64_t(count)*2+2!=len)return malformed("PermittedSubclasses attribute length does not match its class indexes");
                md.permitted_subclasses.reserve(count);
                md.permitted_subclass_references.reserve(count);
                for(unsigned i=0;i<count;++i){
                    const auto reference_offset=r.p;
                    std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated permitted subclass index");
                    auto name=class_name(ix);if(!name)return name.error();
                    md.permitted_subclasses.push_back(name.value());
                    md.permitted_subclass_references.push_back({ix,{reference_offset},std::move(name.value())});
                }
                have_permitted_subclasses=true;
            }else if(class_level&&an.value()=="Preload"){
                if(md.major_version!=67||md.minor_version!=65535)
                    return malformed("Preload requires the version 67 preview classfile format");
                if(have_preload)return malformed("duplicate Preload attribute");
                std::uint16_t count=0;
                if(len<2||!r.u2(count)||std::uint64_t(count)*2+2!=len||count>8192)
                    return malformed("Preload count or extent is invalid");
                md.preload_classes.emplace();
                md.preload_classes->reserve(count);
                for(unsigned i=0;i<count;++i){
                    const auto reference_offset=r.p;
                    std::uint16_t index=0;if(!r.u2(index))return malformed("truncated Preload class index");
                    auto name=class_name(index);if(!name)return name.error();
                    md.preload_classes->push_back({index,{reference_offset},std::move(name.value())});
                }
                have_preload=true;
            }else if(class_level&&an.value()=="Record"){
                if(major<60)return Error{ErrorCode::unsupported,"Record metadata requires finalized class-file version 60 or newer; preview Record layouts are unsupported"};
                if(minor!=0&&minor!=65535)return malformed("Record classfile has an invalid minor version");
                if(have_record)return malformed("duplicate Record attribute");
                const auto record_end=start+len;
                if(len<2)return malformed("truncated Record attribute");
                std::uint16_t count=0;if(!r.u2(count)||count>8192)return malformed("invalid Record component count");
                md.record_components.reserve(count);
                for(unsigned i=0;i<count;++i){
                    // Stable vector-owned addresses keep duplicate-attribute
                    // state separate for different components, including empty tables.
                    md.record_components.emplace_back();
                    auto &component=md.record_components.back();component.file_begin={r.p};
                    if(r.p>record_end||record_end-r.p<6)return malformed("truncated Record component declaration");
                    if(!r.u2(component.name_index)||!r.u2(component.descriptor_index))return malformed("truncated Record component declaration");
                    auto name=utf8(component.name_index),descriptor=utf8(component.descriptor_index);
                    if(!name)return name.error();if(!descriptor)return descriptor.error();
                    if(name.value().empty()||name.value().find_first_of(".;[/")!=std::string::npos)
                        return malformed("Record component has an invalid unqualified name");
                    if(!valid_field_descriptor(descriptor.value()))return malformed("Record component has an invalid field descriptor");
                    component.name=std::move(name.value());component.descriptor=std::move(descriptor.value());
                    if(r.p>record_end||record_end-r.p<2)return malformed("truncated Record component attributes");
                    auto nested=attributes(false,nullptr,false,nullptr,&component);if(!nested)return nested.error();
                    component.byte_size=r.p-component.file_begin.value;
                }
                if(r.p!=record_end)return malformed("Record attribute length does not match its components");
                md.record=JvmRecordDeclaration{{start-6},len};
                have_record=true;
            }else if(class_level&&an.value()=="Module"){
                if(md.module)return malformed("duplicate Module attribute");
                if(md.major_version<53||md.class_name!="module-info"||(md.access_flags&0x8000)==0)
                    return malformed("Module attribute requires a Java 9 module-info class");
                JvmModule module;
                std::uint16_t module_index=0,version_index=0,count=0;
                if(!r.u2(module_index)||!r.u2(module.flags)||!r.u2(version_index))return malformed("truncated Module header");
                auto name=module_name(module_index);if(!name)return name.error();module.name=std::move(name.value());
                if(module.flags&~std::uint16_t{0x9020})return malformed("Module attribute contains reserved module flags");
                if(version_index){auto version=utf8(version_index);if(!version)return version.error();module.version=std::move(version.value());}
                std::size_t module_items=0;
                const auto claim_items=[&](std::uint16_t items){if(items>8192-module_items)return false;module_items+=items;return true;};
                if(!r.u2(count)||!claim_items(count))return malformed("invalid Module requires count");
                module.required_modules.reserve(count);
                std::unordered_set<std::string> required_names;
                for(unsigned i=0;i<count;++i){
                    std::uint16_t index=0,flags=0,version=0;
                    if(!r.u2(index)||!r.u2(flags)||!r.u2(version))return malformed("truncated Module requires entry");
                    auto required=module_name(index);if(!required)return required.error();
                    if(!required_names.insert(required.value()).second)return malformed("Module requires contains a duplicate module");
                    if(flags&~std::uint16_t{0x9060})return malformed("Module requires entry contains reserved flags");
                    JvmModuleRequire entry;entry.module=std::move(required.value());entry.flags=flags;
                    if(version){auto version_name=utf8(version);if(!version_name)return version_name.error();entry.version=std::move(version_name.value());}
                    module.required_modules.push_back(std::move(entry));
                }
                const auto read_exports=[&](std::vector<JvmModuleExport> &entries,std::string_view label)->Result<bool>{
                    std::uint16_t items=0;if(!r.u2(items)||!claim_items(items))return malformed("invalid Module "+std::string(label)+" count");
                    entries.reserve(items);
                    std::unordered_set<std::string> package_names;
                    for(unsigned i=0;i<items;++i){
                        std::uint16_t index=0,flags=0,to_count=0;
                        if(!r.u2(index)||!r.u2(flags)||!r.u2(to_count))return malformed("truncated Module "+std::string(label)+" entry");
                        auto package=package_name(index);if(!package)return package.error();
                        if(!package_names.insert(package.value()).second)return malformed("Module "+std::string(label)+" contains a duplicate package");
                        if(flags&~std::uint16_t{0x9000}||!claim_items(to_count))return malformed("invalid Module "+std::string(label)+" flags or target count");
                        JvmModuleExport entry;entry.package_name=std::move(package.value());entry.flags=flags;entry.to_modules.reserve(to_count);
                        std::unordered_set<std::string> targets;
                        for(unsigned target=0;target<to_count;++target){std::uint16_t target_index=0;if(!r.u2(target_index))return malformed("truncated Module "+std::string(label)+" target list");auto target_name=module_name(target_index);if(!target_name)return target_name.error();if(!targets.insert(target_name.value()).second)return malformed("Module "+std::string(label)+" target list contains a duplicate module");entry.to_modules.push_back(std::move(target_name.value()));}
                        entries.push_back(std::move(entry));
                    }
                    return true;
                };
                auto exports=read_exports(module.exports,"exports");if(!exports)return exports.error();
                auto opens=read_exports(module.opens,"opens");if(!opens)return opens.error();
                if(!r.u2(count)||!claim_items(count))return malformed("invalid Module uses count");
                module.uses.reserve(count);
                std::unordered_set<std::string> used_names;
                for(unsigned i=0;i<count;++i){std::uint16_t index=0;if(!r.u2(index))return malformed("truncated Module uses entry");auto used=class_name(index);if(!used)return used.error();if(!used_names.insert(used.value()).second)return malformed("Module uses contains a duplicate class");module.uses.push_back(std::move(used.value()));}
                if(!r.u2(count)||!claim_items(count))return malformed("invalid Module provides count");
                module.provides.reserve(count);
                std::unordered_set<std::string> provided_services;
                for(unsigned i=0;i<count;++i){
                    std::uint16_t service_index=0,with_count=0;
                    if(!r.u2(service_index)||!r.u2(with_count))return malformed("truncated Module provides entry");
                    auto service=class_name(service_index);if(!service)return service.error();
                    if(!provided_services.insert(service.value()).second)return malformed("Module provides contains a duplicate service");
                    if(!with_count||!claim_items(with_count))return malformed("invalid Module provider count");
                    JvmModuleProvide entry;entry.service=std::move(service.value());entry.implementations.reserve(with_count);
                    std::unordered_set<std::string> implementations;
                    for(unsigned implementation=0;implementation<with_count;++implementation){std::uint16_t index=0;if(!r.u2(index))return malformed("truncated Module provider class index");auto name=class_name(index);if(!name)return name.error();if(!implementations.insert(name.value()).second)return malformed("Module provides contains a duplicate implementation");entry.implementations.push_back(std::move(name.value()));}
                    module.provides.push_back(std::move(entry));
                }
                md.module=std::move(module);
            }else if(class_level&&an.value()=="BootstrapMethods"){
                if(have_bootstrap_methods)return malformed("duplicate BootstrapMethods attribute");
                if(md.major_version<51)return malformed("BootstrapMethods requires classfile version 51 or later");
                std::uint16_t count=0;if(!r.u2(count)||count>8192)return malformed("invalid BootstrapMethods count");
                std::vector<JvmBootstrapMethod> methods;methods.reserve(count);
                std::size_t retained_arguments=0;
                for(unsigned i=0;i<count;++i){
                    JvmBootstrapMethod entry;std::uint16_t argument_count=0;
                    if(!r.u2(entry.method_handle_index)||!r.u2(argument_count))return malformed("truncated BootstrapMethods entry");
                    if(!entry.method_handle_index||entry.method_handle_index>=md.constant_pool.size()||md.constant_pool[entry.method_handle_index].tag!=15)
                        return malformed("BootstrapMethods entry does not reference a CONSTANT_MethodHandle");
                    const auto bootstrap_kind=md.constant_pool[entry.method_handle_index].first;
                    if(bootstrap_kind!=6&&bootstrap_kind!=8)
                        return malformed("BootstrapMethods method handle must use REF_invokeStatic or REF_newInvokeSpecial");
                    if(argument_count>8192-retained_arguments)return Error{ErrorCode::resource_limit,"BootstrapMethods argument count exceeds the 8192-entry limit"};
                    retained_arguments+=argument_count;entry.argument_indices.reserve(argument_count);
                    for(unsigned j=0;j<argument_count;++j){std::uint16_t index=0;if(!r.u2(index)||!index||index>=md.constant_pool.size())return malformed("invalid BootstrapMethods argument index");
                        const auto tag=md.constant_pool[index].tag;
                        if(tag!=3&&tag!=4&&tag!=5&&tag!=6&&tag!=7&&tag!=8&&tag!=15&&tag!=16&&tag!=17)
                            return malformed("BootstrapMethods argument has an unsupported constant kind");
                        entry.argument_indices.push_back(index);
                    }
                    methods.push_back(std::move(entry));
                }
                md.bootstrap_methods=std::move(methods);have_bootstrap_methods=true;
            }else if(class_level&&an.value()=="ModulePackages"){
                if(have_module_packages)return malformed("duplicate ModulePackages attribute");
                if(md.major_version<53||md.class_name!="module-info"||(md.access_flags&0x8000)==0||len<2)return malformed("ModulePackages requires a Java 9 module-info class");
                std::uint16_t count=0;if(!r.u2(count)||count>8192||std::uint64_t(count)*2+2!=len)return malformed("invalid ModulePackages count or length");
                md.module_packages.reserve(count);
                std::unordered_set<std::string> packages;
                for(unsigned i=0;i<count;++i){std::uint16_t index=0;if(!r.u2(index))return malformed("truncated ModulePackages entry");auto name=package_name(index);if(!name)return name.error();if(!packages.insert(name.value()).second)return malformed("ModulePackages contains a duplicate package");md.module_packages.push_back(std::move(name.value()));}
                have_module_packages=true;
            }else if(class_level&&an.value()=="ModuleMainClass"){
                if(have_module_main_class)return malformed("duplicate ModuleMainClass attribute");
                if(md.major_version<53||md.class_name!="module-info"||(md.access_flags&0x8000)==0||len!=2)return malformed("ModuleMainClass requires one class index in a Java 9 module-info class");
                std::uint16_t index=0;if(!r.u2(index))return malformed("truncated ModuleMainClass attribute");auto name=class_name(index);if(!name)return name.error();md.module_main_class=std::move(name.value());have_module_main_class=true;
            }else if(class_level&&an.value()=="ModuleTarget"){
                if(have_module_target)return malformed("duplicate ModuleTarget attribute");
                if(md.major_version<53||md.class_name!="module-info"||(md.access_flags&0x8000)==0||len!=2)
                    return malformed("ModuleTarget requires one platform index in a Java 9 module-info class");
                std::uint16_t index=0;if(!r.u2(index))return malformed("truncated ModuleTarget attribute");
                JvmModuleTarget target;
                if(index){auto platform=utf8(index);if(!platform)return platform.error();target.platform=std::move(platform.value());}
                md.module_target=std::move(target);have_module_target=true;
            }else if(class_level&&an.value()=="ModuleResolution"){
                if(have_module_resolution)return malformed("duplicate ModuleResolution attribute");
                if(md.major_version<53||md.class_name!="module-info"||(md.access_flags&0x8000)==0||len!=2)
                    return malformed("ModuleResolution requires two flag bytes in a Java 9 module-info class");
                std::uint16_t flags=0;if(!r.u2(flags))return malformed("truncated ModuleResolution attribute");
                if(flags&~std::uint16_t{0x000f})return malformed("ModuleResolution contains reserved flag bits");
                md.module_resolution=flags;have_module_resolution=true;
            }else if(class_level&&an.value()=="ModuleHashes"){
                if(have_module_hashes)return malformed("duplicate ModuleHashes attribute");
                if(md.major_version<53||md.class_name!="module-info"||(md.access_flags&0x8000)==0||len<4)
                    return malformed("ModuleHashes requires a Java 9 module-info class");
                std::uint16_t algorithm_index=0,count=0;
                if(!r.u2(algorithm_index)||!r.u2(count)||count>8192)
                    return malformed("invalid ModuleHashes algorithm or entry count");
                auto algorithm=utf8(algorithm_index);if(!algorithm)return algorithm.error();
                md.module_hash_algorithm=std::move(algorithm.value());
                md.module_hashes.reserve(count);
                std::unordered_set<std::string> hashed_modules;
                std::size_t retained_hash_bytes=0;
                for(unsigned i=0;i<count;++i){
                    std::uint16_t module_index=0,hash_length=0;
                    if(!r.u2(module_index)||!r.u2(hash_length)||hash_length>len-(r.p-start))
                        return malformed("truncated ModuleHashes entry");
                    auto name=module_name(module_index);if(!name)return name.error();
                    if(!hashed_modules.insert(name.value()).second)
                        return malformed("ModuleHashes contains a duplicate module name");
                    if(hash_length>65535-retained_hash_bytes)
                        return Error{ErrorCode::resource_limit,"ModuleHashes byte data exceeds the 65535-byte retention limit"};
                    retained_hash_bytes+=hash_length;
                    JvmModuleHash entry;entry.module=std::move(name.value());entry.hash.reserve(hash_length);
                    for(unsigned byte=0;byte<hash_length;++byte){std::uint8_t value=0;if(!r.u1(value))return malformed("truncated ModuleHashes hash value");entry.hash.push_back(value);}
                    md.module_hashes.push_back(std::move(entry));
                }
                have_module_hashes=true;
            }else{
                if(retained_opaque_attributes>=65536||an.value().size()>4*1024*1024-retained_opaque_name_bytes)
                    return Error{ErrorCode::resource_limit,"opaque JVM attribute inventory exceeds its count or name-byte limit"};
                JvmOpaqueAttribute opaque{an.value(),FileOffset{start},len};
                if(code_owner)code_owner->opaque_attributes.push_back(std::move(opaque));
                else if(record_component)record_component->opaque_attributes.push_back(std::move(opaque));
                else if(class_level)md.opaque_attributes.push_back(std::move(opaque));
                else if(member)member->opaque_attributes.push_back(std::move(opaque));
                else return malformed("opaque attribute has no owner");
                ++retained_opaque_attributes;retained_opaque_name_bytes+=an.value().size();
                if(an.value()!="ConstantValue"&&an.value()!="Exceptions"&&an.value()!="Signature"&&an.value()!="SourceFile"&&an.value()!="Synthetic"&&an.value()!="Deprecated"&&an.value()!="LineNumberTable"&&an.value()!="CharacterRangeTable"&&an.value()!="LocalVariableTable"&&an.value()!="LocalVariableTypeTable"&&an.value()!="BootstrapMethods")metadata_complete=false;
                if(!r.skip(len))return malformed("truncated attribute payload");
            }
            if(r.p!=start+len)return malformed("attribute parser did not consume its declared extent");
        }
        return true;
    };
    const auto members=[&](std::vector<JvmMember>&out,bool methods)->Result<bool>{
        std::uint16_t count=0;if(!r.u2(count)||count>8192)return Error{ErrorCode::resource_limit,"member count exceeds the 8192-per-class limit"};out.reserve(count);
        std::set<std::pair<std::string,std::string>> declarations;
        for(unsigned i=0;i<count;++i){
            JvmMember m;
            if(!r.u2(m.access_flags)||!r.u2(m.name_index)||!r.u2(m.descriptor_index))return malformed("truncated member declaration");
            auto name=utf8(m.name_index),desc=utf8(m.descriptor_index);if(!name)return name.error();if(!desc)return desc.error();
            m.name=std::move(name.value());m.descriptor=std::move(desc.value());
            if(!valid_unqualified_member_name(m.name))return malformed("field or method name is not a valid unqualified name");
            if(methods){
                if(m.access_flags&~std::uint16_t{0x1dff})return malformed("method declaration contains reserved access flags");
                const auto visibility=m.access_flags&0x0007u;
                if(visibility&&(visibility&(visibility-1)))return malformed("method declaration has conflicting visibility flags");
                if((m.access_flags&0x0400u)&&(m.access_flags&0x013au))return malformed("abstract method has incompatible access flags");
                auto parameters=method_descriptor_parameter_count(m.descriptor,(m.access_flags&0x0008u)==0);
                if(!parameters)return malformed("method declaration has an invalid descriptor: "+parameters.error().message);
                if(m.name=="<init>"&&(m.descriptor.back()!='V'||(m.access_flags&0x0008u)))return malformed("constructor must be non-static and return void");
                if(m.name=="<clinit>"&&(m.descriptor!="()V"||(m.access_flags&0x0008u)==0))return malformed("class initializer must be static and have descriptor ()V");
                if((m.name.find('<')!=std::string::npos||m.name.find('>')!=std::string::npos)&&m.name!="<init>"&&m.name!="<clinit>")
                    return malformed("angle brackets are only valid in <init> and <clinit> method names");
            }else{
                if(m.access_flags&~std::uint16_t{0x50df})return malformed("field declaration contains reserved access flags");
                const auto visibility=m.access_flags&0x0007u;
                if(visibility&&(visibility&(visibility-1)))return malformed("field declaration has conflicting visibility flags");
                if((m.access_flags&0x0010u)&&(m.access_flags&0x0040u))return malformed("field cannot be both final and volatile");
                if((md.access_flags&0x0200u)&&(m.access_flags&0x0019u)!=0x0019u)return malformed("interface field must be public, static, and final");
                if(!valid_field_descriptor(m.descriptor))return malformed("field declaration has an invalid descriptor");
            }
            if(!declarations.emplace(m.name,m.descriptor).second)return malformed("duplicate field or method name and descriptor");
            out.push_back(std::move(m));
            auto result=attributes(methods,&out.back(),false,nullptr,nullptr);if(!result)return result.error();
            if(methods){
                const auto &parsed=out.back();
                const bool no_code=(parsed.access_flags&(0x0100u|0x0400u))!=0;
                if(no_code==parsed.code.has_value())return malformed("method Code attribute presence disagrees with native/abstract flags");
            }
        }
        return true;
    };
    auto f=members(md.fields,false);if(!f)return f.error();auto m=members(md.methods,true);if(!m)return m.error();
    auto class_attrs=attributes(false,nullptr,true,nullptr,nullptr);if(!class_attrs)return class_attrs.error();if(r.p!=bytes.size())return malformed("trailing bytes after classfile attributes");
    // Generic signatures are grammar-checked when read. Bind every Tname; use
    // the containing class formals for fields, record components and locals,
    // and add method formals for method declarations and their local tables.
    auto class_formals=generic_formals(md.generic_signature?&*md.generic_signature:nullptr);
    const auto record_signature_check=[&](JvmGenericSignatureAnalysis *analysis,
                                           const std::unordered_set<std::string> &scope) {
        if(!analysis||!analysis->diagnostic.empty())return;
        auto diagnostic=unbound_generic_variable(analysis,scope);
        if(diagnostic){analysis->diagnostic=std::move(*diagnostic);metadata_complete=false;}
    };
    record_signature_check(md.generic_signature?&*md.generic_signature:nullptr,class_formals);
    auto class_erasure_variables=generic_variable_erasures(md.generic_signature&&md.generic_signature->parsed?&*md.generic_signature->parsed:nullptr);
    for(auto &field:md.fields)
        record_signature_check(field.generic_signature?&*field.generic_signature:nullptr,class_formals);
    for(auto &component:md.record_components)
        record_signature_check(component.generic_signature?&*component.generic_signature:nullptr,class_formals);
    for(auto &method:md.methods) {
        auto scope=class_formals;
        auto method_formals=generic_formals(method.generic_signature?&*method.generic_signature:nullptr);
        scope.insert(method_formals.begin(),method_formals.end());
        record_signature_check(method.generic_signature?&*method.generic_signature:nullptr,scope);
        if(method.code&&method.code->local_variable_types)
            for(auto &local:*method.code->local_variable_types)
                record_signature_check(local.generic_signature?&*local.generic_signature:nullptr,scope);
    }
    const auto check_field_erasure=[&](const JvmGenericSignatureAnalysis *analysis,std::string_view descriptor,
                                       const std::unordered_map<std::string,std::string> &variables)->Result<bool>{
        if(!analysis||!analysis->parsed||!analysis->diagnostic.empty())return true;
        const auto &tree=*analysis->parsed;
        if(tree.kind!=JvmGenericSignatureKind::field_signature||tree.nodes.empty()||tree.nodes.front().children.size()!=1)return true;
        auto erased=erased_signature_type(tree,tree.nodes.front().children.front(),variables);
        if(erased&&*erased!=descriptor)return malformed("generic field signature erasure disagrees with its descriptor");
        return true;
    };
    for(const auto &field:md.fields){auto checked=check_field_erasure(field.generic_signature?&*field.generic_signature:nullptr,field.descriptor,class_erasure_variables);if(!checked)return checked.error();}
    for(const auto &component:md.record_components){auto checked=check_field_erasure(component.generic_signature?&*component.generic_signature:nullptr,component.descriptor,class_erasure_variables);if(!checked)return checked.error();}
    if(md.generic_signature&&md.generic_signature->parsed&&md.generic_signature->diagnostic.empty()){
        const auto &tree=*md.generic_signature->parsed;
        std::vector<std::uint32_t> super_types,interface_types;
        for(const auto child:tree.nodes.front().children)if(child<tree.nodes.size()){
            const auto &wrapper=tree.nodes[child];
            if(wrapper.kind==JvmGenericNodeKind::superclass&&wrapper.children.size()==1)super_types.push_back(wrapper.children.front());
            else if(wrapper.kind==JvmGenericNodeKind::superinterface&&wrapper.children.size()==1)interface_types.push_back(wrapper.children.front());
        }
        if(super_types.size()!=(md.super_class?1u:0u)||interface_types.size()!=md.interfaces.size())
            return malformed("generic class signature superclass/interface counts disagree with the class header");
        if(md.super_class&&super_types.size()==1){
            auto erased=erased_signature_type(tree,super_types.front(),class_erasure_variables);
            if(erased&&*erased!="L"+md.super_name+";")return malformed("generic superclass signature erasure disagrees with super_class");
        }
        for(std::size_t i=0;i<interface_types.size();++i){
            auto erased=erased_signature_type(tree,interface_types[i],class_erasure_variables);
            if(erased&&*erased!="L"+md.interfaces[i]+";")return malformed("generic superinterface signature erasure disagrees with interfaces");
        }
    }
    for(const auto &method:md.methods)if(method.generic_signature&&method.generic_signature->parsed&&method.generic_signature->diagnostic.empty()){
        const auto &tree=*method.generic_signature->parsed;
        auto method_erasure_variables=generic_variable_erasures(&tree,class_erasure_variables);
        if(tree.kind!=JvmGenericSignatureKind::method_signature||tree.nodes.empty())continue;
        const JvmGenericSignatureNode *params=nullptr,*result=nullptr;
        for(const auto child:tree.nodes.front().children)if(child<tree.nodes.size()){
            const auto &node=tree.nodes[child];
            if(node.kind==JvmGenericNodeKind::parameters)params=&node;
            else if(node.kind==JvmGenericNodeKind::result)result=&node;
        }
        if(!params||!result||result->children.size()!=1)continue;
        std::string erased_descriptor="(";bool complete=true;
        for(const auto parameter:params->children){auto erased=erased_signature_type(tree,parameter,method_erasure_variables);if(!erased){complete=false;break;}erased_descriptor+=*erased;}
        auto erased_result=erased_signature_type(tree,result->children.front(),method_erasure_variables);
        if(!erased_result)complete=false;
        if(complete){
            erased_descriptor+=")"+*erased_result;
            if(erased_descriptor!=method.descriptor)return malformed("generic method signature erasure disagrees with its descriptor");
        }
    }
    for(const auto &method:md.methods)if(method.code&&method.code->local_variable_types){
        auto variables=class_erasure_variables;
        if(method.generic_signature&&method.generic_signature->parsed)
            variables=generic_variable_erasures(&*method.generic_signature->parsed,std::move(variables));
        using LocalKey=std::tuple<std::uint16_t,std::uint16_t,std::uint16_t,std::string>;
        std::map<LocalKey,std::pair<const JvmLocalVariable*,bool>> local_descriptors;
        if(method.code->local_variables)for(const auto &candidate:*method.code->local_variables){
            LocalKey key{candidate.start_pc,candidate.length,candidate.slot,candidate.name};
            auto [entry,inserted]=local_descriptors.emplace(std::move(key),std::make_pair(&candidate,false));
            if(!inserted&&entry->second.first->descriptor!=candidate.descriptor)entry->second.second=true;
        }
        for(const auto &local:*method.code->local_variable_types){
            if(!local.generic_signature||!local.generic_signature->parsed||!local.generic_signature->diagnostic.empty())continue;
            const auto variable=local_descriptors.find({local.start_pc,local.length,local.slot,local.name});
            if(variable!=local_descriptors.end()&&!variable->second.second){
                auto checked=check_field_erasure(&*local.generic_signature,variable->second.first->descriptor,variables);if(!checked)return checked.error();
            }
        }
    }
    for(std::size_t i=1;i<md.constant_pool.size();++i)if(md.constant_pool[i].tag==17||md.constant_pool[i].tag==18){
        const auto bootstrap_index=md.constant_pool[i].first;
        if(!md.bootstrap_methods||bootstrap_index>=md.bootstrap_methods->size())return malformed("dynamic constant references a missing BootstrapMethods entry");
    }
    if((have_module_packages||have_module_main_class||have_module_target||have_module_resolution||have_module_hashes)&&!md.module)
        return malformed("module companion attributes require a Module attribute");
    if(md.access_flags&0x8000){
        if(md.major_version<53||md.class_name!="module-info"||!md.module||md.super_class||!md.interfaces.empty()||!md.fields.empty()||!md.methods.empty())
            return malformed("ACC_MODULE class must be a Java 9 module-info class with a Module attribute and no supertype, interfaces, fields, or methods");
    }
    ImageLayout layout{{{0},32,1,ByteOrder::big},Architecture::jvm,ExecutionMode::jvm,{}, {}};
    layout.domains.reserve(md.methods.size());layout.segments.reserve(md.methods.size());
    for(std::size_t i=0;i<md.methods.size();++i)if(md.methods[i].code){
        auto &code=*md.methods[i].code;const AddressSpaceId sid{static_cast<std::uint32_t>(i+1)};
        code.begin={sid,0};layout.domains.push_back({{sid,32,1,ByteOrder::big},{Architecture::jvm,ExecutionMode::jvm,ByteOrder::big}});
        layout.segments.push_back({md.methods[i].name+md.methods[i].descriptor,code.begin,code.code_size,code.file_begin,code.code_size,true,false,true});
        layout.entries.push_back(code.begin);
    }
    auto image=Image::create(storage,std::move(layout));if(!image)return image.error();
    LoadedImage loaded;loaded.image=std::move(image.value());loaded.metadata.format="Java classfile";loaded.metadata.header_size=10;loaded.metadata.image_size=size;loaded.metadata.jvm=std::move(md);loaded.metadata_complete=metadata_complete;
    loaded.diagnostics.push_back({DiagnosticSeverity::info,"JVM method Code arrays use independent big-endian bytecode address spaces",{}});
    auto tracked=loaded.metadata_reads.include({0},size);if(!tracked)return tracked.error();loaded.metadata_reads_complete=true;
    return loaded;
}
}
Result<LoadedImage> load_jvm_class(std::shared_ptr<const ByteStorage> storage,std::stop_token stop){
    if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM class loading canceled"};
    try{return parse(std::move(storage),stop);}catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"cannot allocate classfile metadata"};}
}
Result<JvmModuleLinkGraph> link_jvm_modules(std::span<const JvmModule> modules,std::stop_token stop,
                                            JvmModuleLinkLimits limits){
    if(modules.size()>limits.max_modules)return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its module limit"};
    try{
        JvmModuleLinkGraph graph;graph.modules.reserve(modules.size());
        std::unordered_map<std::string,std::vector<std::size_t>> definitions;
        definitions.reserve(modules.size());
        std::size_t retained_name_bytes=0;
        const auto account_name=[&](std::string_view name)->Result<bool>{
            if(name.size()>limits.max_name_bytes-retained_name_bytes)
                return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its name-byte limit"};
            retained_name_bytes+=name.size();return true;
        };
        for(std::size_t i=0;i<modules.size();++i){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM module linking canceled"};
            if(modules[i].name.empty())return malformed("JVM module definition has an empty name");
            auto accounted=account_name(modules[i].name);if(!accounted)return accounted.error();
            graph.modules.push_back({modules[i].name,false});
            definitions[modules[i].name].push_back(i);
        }
        for(const auto &[name,indexes]:definitions)if(indexes.size()>1)
            for(const auto index:indexes)graph.modules[index].duplicate_definition=true;
        std::vector<std::vector<std::size_t>> requires_edges(modules.size());
        std::vector<std::vector<std::size_t>> transitive_requires_edges(modules.size());
        const auto add_edge=[&](std::size_t source,const std::string &target,JvmModuleLinkEdgeKind kind,
                                std::uint16_t flags)->Result<bool>{
            if(target.empty())return malformed("JVM module reference has an empty target name");
            if(graph.edges.size()>=limits.max_edges)return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its edge limit"};
            auto accounted=account_name(target);if(!accounted)return accounted.error();
            JvmModuleLinkEdge edge;edge.source_definition=source;edge.target_name=target;edge.kind=kind;
            const auto found=definitions.find(target);
            if(found==definitions.end())edge.status=(kind==JvmModuleLinkEdgeKind::requires_module&&(flags&0x0040u))
                ?JvmModuleLinkStatus::missing_optional:JvmModuleLinkStatus::missing;
            else if(found->second.size()!=1)edge.status=JvmModuleLinkStatus::duplicate_definition;
            else{
                edge.status=JvmModuleLinkStatus::resolved;edge.target_definition=found->second.front();
                if(kind==JvmModuleLinkEdgeKind::requires_module&&!graph.modules[source].duplicate_definition) {
                    requires_edges[source].push_back(found->second.front());
                    if (flags & 0x0020u) transitive_requires_edges[source].push_back(found->second.front());
                }
            }
            edge.transitive = kind == JvmModuleLinkEdgeKind::requires_module && (flags & 0x0020u);
            graph.edges.push_back(std::move(edge));return true;
        };
        for(std::size_t i=0;i<modules.size();++i){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM module linking canceled"};
            for(const auto &require:modules[i].required_modules){auto result=add_edge(i,require.module,JvmModuleLinkEdgeKind::requires_module,require.flags);if(!result)return result.error();}
            for(const auto &exported:modules[i].exports)for(const auto &target:exported.to_modules){auto result=add_edge(i,target,JvmModuleLinkEdgeKind::qualified_export,0);if(!result)return result.error();}
            for(const auto &opened:modules[i].opens)for(const auto &target:opened.to_modules){auto result=add_edge(i,target,JvmModuleLinkEdgeKind::qualified_open,0);if(!result)return result.error();}
        }
        struct Frame{std::size_t node=0,next=0;};
        std::vector<std::uint8_t> color(modules.size(),0);std::vector<Frame> frames;
        std::size_t cycle_members=0,cycle_name_bytes=0;
        for(std::size_t root=0;root<modules.size();++root){
            if(color[root]||graph.modules[root].duplicate_definition)continue;
            color[root]=1;frames.push_back({root,0});
            while(!frames.empty()){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM module cycle analysis canceled"};
                auto &frame=frames.back();
                if(frame.next>=requires_edges[frame.node].size()){
                    color[frame.node]=2;frames.pop_back();continue;
                }
                const auto target=requires_edges[frame.node][frame.next++];
                if(graph.modules[target].duplicate_definition)continue;
                if(color[target]==0){color[target]=1;frames.push_back({target,0});continue;}
                if(color[target]==1){
                    const auto begin=std::find_if(frames.begin(),frames.end(),[&](const Frame &item){return item.node==target;});
                    if(begin!=frames.end()){
                        std::vector<std::string> cycle;std::size_t cycle_bytes=0;
                        for(auto it=begin;it!=frames.end();++it){
                            const auto name_size=graph.modules[it->node].name.size();
                            if(name_size>limits.max_cycle_name_bytes-cycle_bytes)
                                return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its cycle-name limit"};
                            cycle_bytes+=name_size;cycle.push_back(graph.modules[it->node].name);
                        }
                        const auto repeated_size=graph.modules[target].name.size();
                        if(repeated_size>limits.max_cycle_name_bytes-cycle_bytes)
                            return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its cycle-name limit"};
                        cycle_bytes+=repeated_size;
                        cycle.push_back(graph.modules[target].name);
                        if(graph.requires_cycles.size()>=limits.max_cycles||cycle.size()>limits.max_cycle_members-cycle_members||
                            cycle_bytes>limits.max_cycle_name_bytes-cycle_name_bytes)
                            return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its cycle-report limit"};
                        cycle_members+=cycle.size();cycle_name_bytes+=cycle_bytes;graph.requires_cycles.push_back(std::move(cycle));
                    }
                }
            }
        }
        std::size_t readability_work = 0;
        for (std::size_t source = 0; source < modules.size(); ++source) {
            if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM module readability analysis canceled"};
            if (graph.modules[source].duplicate_definition) continue;
            std::vector<bool> seen(modules.size(), false);
            std::vector<std::size_t> pending;
            seen[source] = true;
            for (const auto target : requires_edges[source]) {
                if (seen[target]) continue;
                if (graph.readability.size() >= limits.max_readability_edges)
                    return Error{ErrorCode::resource_limit, "JVM module workspace exceeds its readability-edge limit"};
                seen[target] = true;
                graph.readability.push_back({source, target, true});
                pending.push_back(target);
            }
            for (std::size_t cursor = 0; cursor < pending.size(); ++cursor) {
                if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM module readability analysis canceled"};
                const auto readable = pending[cursor];
                for (const auto target : transitive_requires_edges[readable]) {
                    if (++readability_work > limits.max_readability_work)
                        return Error{ErrorCode::resource_limit, "JVM module readability analysis exceeds its work limit"};
                    if (seen[target]) continue;
                    if (graph.readability.size() >= limits.max_readability_edges)
                        return Error{ErrorCode::resource_limit, "JVM module workspace exceeds its readability-edge limit"};
                    seen[target] = true;
                    graph.readability.push_back({source, target, false});
                    pending.push_back(target);
                }
            }
        }
        return graph;
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"cannot allocate bounded JVM module graph"};}
}
Result<JvmModuleWorkspaceGraph> link_jvm_workspace(std::span<const JvmModule> modules,
        std::span<const JvmModuleClassInput> classes,std::stop_token stop,JvmModuleLinkLimits limits){
    if(classes.size()>limits.max_classes)return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its class limit"};
    auto linked=link_jvm_modules(modules,stop,limits);if(!linked)return linked.error();
    try{
        JvmModuleWorkspaceGraph graph;graph.module_graph=std::move(linked.value());
        std::unordered_map<std::string,std::vector<std::size_t>> module_definitions;
        module_definitions.reserve(modules.size());
        for(std::size_t i=0;i<modules.size();++i)module_definitions[modules[i].name].push_back(i);
        struct ClassRow{std::size_t input_index=0,module_index=0;};
        struct ClassCount{std::size_t count=0;ClassRow first;};
        struct ClassBucket{ClassCount all;std::unordered_map<std::size_t,ClassCount> by_module;};
        std::unordered_map<std::string,ClassBucket> classes_by_name;
        classes_by_name.reserve(classes.size());
        std::map<std::string,std::set<std::size_t>> packages;
        graph.class_ownership.reserve(classes.size());
        std::size_t retained_name_bytes=0;
        const auto account_name=[&](std::string_view name)->Result<bool>{
            if(name.size()>limits.max_name_bytes-retained_name_bytes)
                return Error{ErrorCode::resource_limit,"JVM module workspace class data exceeds its name-byte limit"};
            retained_name_bytes+=name.size();return true;
        };
        for(std::size_t i=0;i<classes.size();++i){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM module class inventory canceled"};
            const auto &item=classes[i];
            if(item.module_name.empty()||item.class_name.empty()||item.class_name.front()=='/'||item.class_name.back()=='/'||
                item.class_name.find_first_of(".;[")!=std::string::npos||item.class_name.find("//")!=std::string::npos)
                return malformed("JVM module class inventory contains an invalid module or class name");
            auto module_name_bytes=account_name(item.module_name);if(!module_name_bytes)return module_name_bytes.error();
            auto class_name_bytes=account_name(item.class_name);if(!class_name_bytes)return class_name_bytes.error();
            const auto owner=module_definitions.find(item.module_name);
            JvmModuleClassOwnership ownership;ownership.module_name=item.module_name;ownership.class_name=item.class_name;
            if(owner==module_definitions.end()){
                ownership.status=JvmModuleLinkStatus::missing;graph.class_ownership.push_back(std::move(ownership));continue;
            }
            if(owner->second.size()!=1){
                ownership.status=JvmModuleLinkStatus::duplicate_definition;graph.class_ownership.push_back(std::move(ownership));continue;
            }
            const auto module_index=owner->second.front();
            ownership.status=JvmModuleLinkStatus::resolved;ownership.module_definition=module_index;
            graph.class_ownership.push_back(std::move(ownership));
            auto &bucket=classes_by_name[item.class_name];
            if(!bucket.all.count)bucket.all.first={i,module_index};
            ++bucket.all.count;
            auto &module_bucket=bucket.by_module[module_index];
            if(!module_bucket.count)module_bucket.first={i,module_index};
            ++module_bucket.count;
            const auto slash=item.class_name.rfind('/');
            const auto package=slash==std::string::npos?std::string{}:item.class_name.substr(0,slash);
            packages[package].insert(module_index);
        }
        graph.packages.reserve(packages.size());
        for(auto &[name,owners]:packages){
            JvmPackageOwnership row;row.package_name=std::move(name);row.module_definitions.assign(owners.begin(),owners.end());
            row.split_package=row.module_definitions.size()>1;graph.packages.push_back(std::move(row));
        }
        const auto append_service=[&](std::size_t source,JvmServiceLinkKind kind,const std::string &class_name,
                                      std::optional<std::size_t> required_owner)->Result<bool>{
            if(class_name.empty())return malformed("JVM module service reference has an empty class name");
            if(graph.services.size()>=limits.max_service_references)
                return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its service-reference limit"};
            auto name_bytes=account_name(class_name);if(!name_bytes)return name_bytes.error();
            JvmServiceLink link;link.source_definition=source;link.kind=kind;link.class_name=class_name;
            const auto found=classes_by_name.find(class_name);
            if(found!=classes_by_name.end()){
                const ClassCount *candidates=&found->second.all;
                if(required_owner){const auto owner=found->second.by_module.find(*required_owner);candidates=owner==found->second.by_module.end()?nullptr:&owner->second;}
                if(candidates&&candidates->count==1){link.status=JvmModuleLinkStatus::resolved;link.class_definition=candidates->first.input_index;}
                else if(candidates&&candidates->count>1)link.status=JvmModuleLinkStatus::duplicate_definition;
            }
            graph.services.push_back(std::move(link));return true;
        };
        for(std::size_t i=0;i<modules.size();++i){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM module service linking canceled"};
            for(const auto &service:modules[i].uses){auto result=append_service(i,JvmServiceLinkKind::uses_service,service,std::nullopt);if(!result)return result.error();}
            for(const auto &provide:modules[i].provides){
                auto service=append_service(i,JvmServiceLinkKind::provides_service,provide.service,std::nullopt);if(!service)return service.error();
                for(const auto &implementation:provide.implementations){
                    auto provider=append_service(i,JvmServiceLinkKind::provider_class,implementation,i);if(!provider)return provider.error();
                }
            }
        }
        return graph;
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"cannot allocate bounded JVM module workspace graph"};}
}
Result<JvmModuleWorkspaceGraph> link_jvm_metadata_workspace(std::span<const JvmMetadata> metadata,
        std::stop_token stop,JvmModuleLinkLimits limits){
    try{
        std::vector<JvmModule> modules;
        std::unordered_map<std::string,std::vector<std::size_t>> definitions;
        std::map<std::string,std::set<std::size_t>> declared_packages;
        std::size_t retained_bytes=0,package_rows=0,descriptor_items=0;
        const auto account_name=[&](std::string_view name)->Result<bool>{
            if(name.size()>limits.max_name_bytes-retained_bytes)
                return Error{ErrorCode::resource_limit,"JVM metadata workspace exceeds its name-byte limit"};
            retained_bytes+=name.size();return true;
        };
        for(const auto &item:metadata)if(item.module){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM module metadata indexing canceled"};
            if(modules.size()>=limits.max_modules)return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its module limit"};
            auto module_name_bytes=account_name(item.module->name);if(!module_name_bytes)return module_name_bytes.error();
            const auto account_item=[&]()->Result<bool>{
                if(descriptor_items>=limits.max_edges)return Error{ErrorCode::resource_limit,"JVM metadata workspace exceeds its descriptor-entry limit"};
                ++descriptor_items;return true;
            };
            if(item.module->version){auto result=account_name(*item.module->version);if(!result)return result.error();}
            for(const auto &require:item.module->required_modules){
                auto counted=account_item();if(!counted)return counted.error();
                auto name=account_name(require.module);if(!name)return name.error();
                if(require.version){auto version=account_name(*require.version);if(!version)return version.error();}
            }
            for(const auto &entry:item.module->exports){
                auto counted=account_item();if(!counted)return counted.error();
                auto package=account_name(entry.package_name);if(!package)return package.error();
                for(const auto &target:entry.to_modules){counted=account_item();if(!counted)return counted.error();auto name=account_name(target);if(!name)return name.error();}
            }
            for(const auto &entry:item.module->opens){
                auto counted=account_item();if(!counted)return counted.error();
                auto package=account_name(entry.package_name);if(!package)return package.error();
                for(const auto &target:entry.to_modules){counted=account_item();if(!counted)return counted.error();auto name=account_name(target);if(!name)return name.error();}
            }
            for(const auto &service:item.module->uses){auto counted=account_item();if(!counted)return counted.error();auto name=account_name(service);if(!name)return name.error();}
            for(const auto &provide:item.module->provides){
                auto counted=account_item();if(!counted)return counted.error();
                auto service=account_name(provide.service);if(!service)return service.error();
                for(const auto &implementation:provide.implementations){counted=account_item();if(!counted)return counted.error();auto name=account_name(implementation);if(!name)return name.error();}
            }
            const auto index=modules.size();modules.push_back(*item.module);definitions[item.module->name].push_back(index);
            for(const auto &name:item.module_packages){
                if(++package_rows>limits.max_classes)return Error{ErrorCode::resource_limit,"JVM metadata workspace exceeds its declared-package limit"};
                auto package_name_bytes=account_name(name);if(!package_name_bytes)return package_name_bytes.error();
                declared_packages[name].insert(index);
            }
        }
        std::vector<JvmModuleClassInput> classes;
        std::vector<std::optional<std::size_t>> class_input_index;
        std::vector<std::pair<std::string,JvmModuleLinkStatus>> unresolved;
        std::size_t class_count=0;
        const auto package_of=[](std::string_view name){const auto slash=name.rfind('/');return slash==std::string_view::npos?std::string{}:std::string(name.substr(0,slash));};
        for(const auto &item:metadata)if(!item.module){
            if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM module class ownership inference canceled"};
            if(++class_count>limits.max_classes)return Error{ErrorCode::resource_limit,"JVM module workspace exceeds its class limit"};
            if(item.class_name.empty()||item.class_name.front()=='/'||item.class_name.back()=='/'||
                item.class_name.find_first_of(".;[")!=std::string::npos||item.class_name.find("//")!=std::string::npos)
                return malformed("loaded JVM metadata contains an invalid internal class name");
            const auto package=package_of(item.class_name);const auto owners=declared_packages.find(package);
            if(owners==declared_packages.end()||owners->second.empty()){
                unresolved.emplace_back(item.class_name,JvmModuleLinkStatus::unresolved_ownership);class_input_index.push_back(std::nullopt);continue;
            }
            if(owners->second.size()!=1){
                unresolved.emplace_back(item.class_name,JvmModuleLinkStatus::ambiguous_ownership);class_input_index.push_back(std::nullopt);continue;
            }
            const auto module_index=*owners->second.begin();
            if(module_index>=modules.size())return malformed("module package ownership index is invalid");
            const auto module_definitions=definitions.find(modules[module_index].name);
            if(module_definitions==definitions.end()||module_definitions->second.size()!=1){
                unresolved.emplace_back(item.class_name,JvmModuleLinkStatus::ambiguous_ownership);class_input_index.push_back(std::nullopt);continue;
            }
            class_input_index.push_back(classes.size());classes.push_back({modules[module_index].name,item.class_name});
        }
        auto linked=link_jvm_workspace(modules,classes,stop,limits);if(!linked)return linked.error();
        auto graph=std::move(linked.value());
        std::vector<JvmModuleClassOwnership> ownership;ownership.reserve(class_count);
        std::size_t unresolved_row=0;
        for(std::size_t i=0;i<class_input_index.size();++i){
            if(class_input_index[i])ownership.push_back(std::move(graph.class_ownership[*class_input_index[i]]));
            else{
                if(unresolved_row>=unresolved.size())return malformed("module ownership inference rows are inconsistent");
                ownership.push_back({{},std::move(unresolved[unresolved_row].first),unresolved[unresolved_row].second,{}});
                ++unresolved_row;
            }
        }
        graph.class_ownership=std::move(ownership);
        std::map<std::string,std::set<std::size_t>> all_packages;
        for(const auto &row:graph.packages)for(const auto module:row.module_definitions)all_packages[row.package_name].insert(module);
        for(const auto &[name,owners]:declared_packages)for(const auto module:owners)all_packages[name].insert(module);
        graph.packages.clear();graph.packages.reserve(all_packages.size());
        for(auto &[name,owners]:all_packages){
            JvmPackageOwnership row;row.package_name=std::move(name);row.module_definitions.assign(owners.begin(),owners.end());
            row.split_package=row.module_definitions.size()>1;graph.packages.push_back(std::move(row));
        }
        std::unordered_map<std::string,std::vector<std::size_t>> class_definitions;
        class_definitions.reserve(class_count);
        for(std::size_t i=0;i<metadata.size();++i){
            if((i&1023u)==0&&stop.stop_requested())
                return Error{ErrorCode::canceled,"JVM sealed-class index construction canceled"};
            if(!metadata[i].module&&!metadata[i].class_name.empty())
                class_definitions[metadata[i].class_name].push_back(i);
        }
        std::size_t permitted_work=0,permitted_name_bytes=0;
        for(std::size_t source=0;source<metadata.size();++source){
            const auto &declaring=metadata[source];
            if(declaring.module||declaring.permitted_subclass_references.empty())continue;
            for(const auto &reference:declaring.permitted_subclass_references){
                if(stop.stop_requested())return Error{ErrorCode::canceled,"JVM sealed-class linking canceled"};
                if(graph.permitted_classes.size()>=limits.max_edges)
                    return Error{ErrorCode::resource_limit,"JVM permitted-class links exceed the workspace edge limit"};
                if(++permitted_work>limits.max_readability_work)
                    return Error{ErrorCode::resource_limit,"JVM permitted-class linking exceeds its work limit"};
                JvmPermittedClassLink row;row.source_metadata_index=source;row.source_class=declaring.class_name;
                row.target_class=reference.class_name;row.source_file_offset=reference.reference_file_offset;
                if(row.source_class.size()>limits.max_name_bytes-permitted_name_bytes||
                   row.target_class.size()>limits.max_name_bytes-permitted_name_bytes-row.source_class.size())
                    return Error{ErrorCode::resource_limit,"JVM permitted-class links exceed their name-byte limit"};
                permitted_name_bytes+=row.source_class.size()+row.target_class.size();
                const auto found=class_definitions.find(reference.class_name);
                if(found==class_definitions.end())row.status=JvmPermittedClassStatus::missing;
                else if(found->second.size()!=1)row.status=JvmPermittedClassStatus::ambiguous;
                else{
                    row.target_metadata_index=found->second.front();
                    const auto &candidate=metadata[*row.target_metadata_index];
                    bool direct_subtype=candidate.super_name==declaring.class_name;
                    for(const auto &interface_name:candidate.interfaces){
                        if(++permitted_work>limits.max_readability_work)
                            return Error{ErrorCode::resource_limit,"JVM permitted-class linking exceeds its work limit"};
                        if((permitted_work&255u)==0&&stop.stop_requested())
                            return Error{ErrorCode::canceled,"JVM sealed-class linking canceled"};
                        if(interface_name==declaring.class_name)direct_subtype=true;
                    }
                    row.status=direct_subtype?JvmPermittedClassStatus::resolved:JvmPermittedClassStatus::not_direct_subtype;
                }
                graph.permitted_classes.push_back(std::move(row));
            }
        }
        return graph;
    }catch(const std::bad_alloc&){return Error{ErrorCode::resource_limit,"cannot allocate bounded JVM metadata workspace graph"};}
}
} // namespace hexlab
