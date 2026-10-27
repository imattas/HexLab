#include "hexlab/loaders/jvm.hpp"
#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <string_view>
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
    std::vector<bool> instruction_starts(bytecode.size(), false);
    if (count) for (std::size_t offset = 0; offset < bytecode.size();) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "StackMapTable instruction validation canceled"};
        auto decoded = decode_jvm(bytecode.subspan(offset), {code.begin.space, offset});
        if (decoded.status != DecodeStatus::decoded || !decoded.instruction) {
            if (decoded.status == DecodeStatus::unsupported)
                return Error{ErrorCode::unsupported, "cannot validate StackMapTable instruction boundaries: " + decoded.reason};
            return malformed("invalid bytecode while validating StackMapTable instruction boundaries: " + decoded.reason);
        }
        const auto length = decoded.instruction->length;
        if (!length || length > bytecode.size() - offset) return malformed("invalid decoded StackMapTable instruction extent");
        instruction_starts[offset] = true;
        offset += length;
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
bool valid_modified_utf8(std::string_view s){
    for(std::size_t i=0;i<s.size();){const auto a=static_cast<unsigned char>(s[i++]);
        if(a>0&&a<0x80)continue;
        if(a==0xc0){if(i>=s.size()||static_cast<unsigned char>(s[i++])!=0x80)return false;continue;}
        if(a>=0xc2&&a<=0xdf){if(i>=s.size()||(static_cast<unsigned char>(s[i++])&0xc0)!=0x80)return false;continue;}
        if(a>=0xe0&&a<=0xef){if(s.size()-i<2)return false;const auto b=static_cast<unsigned char>(s[i++]),c=static_cast<unsigned char>(s[i++]);if((b&0xc0)!=0x80||(c&0xc0)!=0x80||(a==0xe0&&b<0xa0))return false;continue;}
        return false;
    }return true;
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
    for(std::uint32_t i=1;i<cp_count;++i){
        if(stop.stop_requested())return Error{ErrorCode::canceled,"classfile constant-pool parsing canceled"};
        std::uint8_t tag=0;if(!r.u1(tag))return malformed("truncated constant-pool tag");auto &c=md.constant_pool[i];c.tag=tag;
        std::uint16_t a=0,b=0;std::uint32_t x=0;std::uint64_t wide=0;
        switch(tag){
        case 1:{if(!r.u2(a)||a>65535||a>bytes.size()-r.p)return malformed("truncated CONSTANT_Utf8 payload");
            // Preserve modified UTF-8 bytes. ASCII structural names remain directly usable;
            // non-ASCII constants are retained byte-for-byte for lossless metadata display.
            c.text.assign(reinterpret_cast<const char*>(bytes.data()+r.p),a);r.p+=a;if(!valid_modified_utf8(c.text))return malformed("invalid CONSTANT_Utf8 modified UTF-8");break;}
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
        if((c.tag==7||c.tag==8||c.tag==16||c.tag==19||c.tag==20)&&tag(c.first)!=1)return malformed("constant-pool UTF-8 index has the wrong tag");
        if((c.tag==9||c.tag==10||c.tag==11)&&(tag(c.first)!=7||tag(c.second)!=12))return malformed("member reference has invalid class or name-and-type index");
        if(c.tag==12&&(tag(c.first)!=1||tag(c.second)!=1))return malformed("NameAndType has invalid UTF-8 indexes");
        if(c.tag==15){const auto kind=c.first;const auto rt=tag(c.second);const bool ok=kind>=1&&kind<=4?rt==9:kind==5||kind==8?rt==10:kind==6||kind==7?(rt==10||(major>=52&&rt==11)):kind==9?rt==11:false;if(!ok)return malformed("MethodHandle has an invalid reference kind or target");}
        if((c.tag==17||c.tag==18)&&tag(c.second)!=12)return malformed("dynamic constant has invalid NameAndType index");
    }
    const auto utf8=[&](std::uint16_t ix)->Result<std::string>{if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=1)return malformed("constant-pool reference is not CONSTANT_Utf8");return md.constant_pool[ix].text;};
    const auto class_name=[&](std::uint16_t ix)->Result<std::string>{if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=7)return malformed("class index is not CONSTANT_Class");return utf8(static_cast<std::uint16_t>(md.constant_pool[ix].first));};
    const auto module_name=[&](std::uint16_t ix)->Result<std::string>{if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=19)return malformed("module index is not CONSTANT_Module");return utf8(static_cast<std::uint16_t>(md.constant_pool[ix].first));};
    const auto package_name=[&](std::uint16_t ix)->Result<std::string>{if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=20)return malformed("package index is not CONSTANT_Package");return utf8(static_cast<std::uint16_t>(md.constant_pool[ix].first));};
    std::uint16_t n=0;if(!r.u2(md.access_flags)||!r.u2(md.this_class)||!r.u2(md.super_class))return malformed("truncated class declaration");
    auto cn=class_name(md.this_class);if(!cn)return cn.error();md.class_name=std::move(cn.value());
    if(md.super_class){auto sn=class_name(md.super_class);if(!sn)return sn.error();md.super_name=std::move(sn.value());}
    if(!r.u2(n)||n>4096)return malformed("invalid interface count");md.interfaces.reserve(n);
    for(unsigned i=0;i<n;++i){std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated interface list");auto name=class_name(ix);if(!name)return name.error();md.interfaces.push_back(std::move(name.value()));}
    std::uint64_t attribute_bytes=0;bool metadata_complete=true;
    std::size_t expanded_verification_entries=0,stack_map_frames=0;
    bool have_record=false,have_nest_host=false,have_nest_members=false,have_permitted_subclasses=false;
    bool have_module_packages=false,have_module_main_class=false;
    bool have_class_visible_annotations=false,have_class_invisible_annotations=false;
    std::unordered_set<const JvmMember *> visible_annotations_seen,invisible_annotations_seen;
    std::unordered_set<const JvmMember *> visible_parameter_annotations_seen,invisible_parameter_annotations_seen,annotation_defaults_seen;
    std::size_t annotation_items=0;
    std::function<Result<std::string>(unsigned)> annotation_value;
    annotation_value=[&](unsigned depth)->Result<std::string>{
        if(depth>64)return Error{ErrorCode::resource_limit,"annotation nesting exceeds 64 levels"};
        std::uint8_t tag=0;if(!r.u1(tag))return malformed("truncated annotation element_value");
        const auto constant=[&](std::uint16_t ix,std::uint8_t expected)->Result<std::string>{
            if(!ix||ix>=md.constant_pool.size()||md.constant_pool[ix].tag!=expected)return malformed("annotation element has a constant-pool entry of the wrong kind");
            return std::to_string(ix);
        };
        if(tag=='B'||tag=='C'||tag=='I'||tag=='S'||tag=='Z'||tag=='D'||tag=='F'||tag=='J'){
            std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated annotation constant element");
            const auto expected=(tag=='D'?6:tag=='F'?4:tag=='J'?5:3);auto value=constant(ix,expected);if(!value)return value.error();
            return std::string("const(")+char(tag)+":"+value.value()+")";
        }
        if(tag=='s'){std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated annotation string element");auto value=constant(ix,1);if(!value)return value.error();return "string#"+value.value();}
        if(tag=='e'){std::uint16_t type=0,name=0;if(!r.u2(type)||!r.u2(name))return malformed("truncated annotation enum element");auto t=utf8(type),n=utf8(name);if(!t)return t.error();if(!n)return n.error();return "enum("+t.value()+"#"+n.value()+")";}
        if(tag=='c'){std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated annotation class element");auto value=utf8(ix);if(!value)return value.error();return "class("+value.value()+")";}
        if(tag=='@'){
            std::uint16_t type=0,pairs=0;if(!r.u2(type)||!r.u2(pairs))return malformed("truncated nested annotation element");auto descriptor=utf8(type);if(!descriptor)return descriptor.error();
            if(pairs>65536-annotation_items)return Error{ErrorCode::resource_limit,"annotation metadata exceeds 65536 elements"};annotation_items+=pairs;
            std::string result="annotation("+descriptor.value();for(unsigned i=0;i<pairs;++i){std::uint16_t name=0;if(!r.u2(name))return malformed("truncated nested annotation element name");auto n=utf8(name);if(!n)return n.error();auto v=annotation_value(depth+1);if(!v)return v.error();result+=";"+n.value()+"="+v.value();}return result+")";
        }
        if(tag=='['){std::uint16_t count=0;if(!r.u2(count))return malformed("truncated annotation array element");if(count>65536-annotation_items)return Error{ErrorCode::resource_limit,"annotation metadata exceeds 65536 elements"};annotation_items+=count;std::string result="[";for(unsigned i=0;i<count;++i){auto value=annotation_value(depth+1);if(!value)return value.error();if(i)result+=",";result+=value.value();}return result+"]";}
        return malformed("invalid annotation element_value tag");
    };
    const auto read_annotations=[&](std::vector<JvmAnnotation> &out)->Result<bool>{
        std::uint16_t count=0;if(!r.u2(count))return malformed("truncated annotation count");
        if(count>65536-annotation_items)return Error{ErrorCode::resource_limit,"annotation metadata exceeds 65536 elements"};annotation_items+=count;
        out.reserve(out.size()+count);
        for(unsigned i=0;i<count;++i){JvmAnnotation annotation;std::uint16_t type=0,pairs=0;if(!r.u2(type)||!r.u2(pairs))return malformed("truncated annotation declaration");auto descriptor=utf8(type);if(!descriptor)return descriptor.error();
            if(pairs>65536-annotation_items)return Error{ErrorCode::resource_limit,"annotation metadata exceeds 65536 elements"};annotation_items+=pairs;annotation.descriptor=std::move(descriptor.value());annotation.elements.reserve(pairs);
            for(unsigned j=0;j<pairs;++j){std::uint16_t name=0;if(!r.u2(name))return malformed("truncated annotation element name");auto element_name=utf8(name);if(!element_name)return element_name.error();auto value=annotation_value(0);if(!value)return value.error();annotation.elements.push_back({std::move(element_name.value()),std::move(value.value())});}
            out.push_back(std::move(annotation));
        }return true;
    };
    std::unordered_set<const JvmMember *> fields_with_constant_value;
    std::function<Result<bool>(bool,JvmMember*,bool,JvmCode*)> attributes;
    attributes=[&](bool method,JvmMember *member,bool class_level,JvmCode *code_owner)->Result<bool>{
        std::uint16_t count=0;if(!r.u2(count))return malformed("truncated attributes_count");
        if(count>8192)return Error{ErrorCode::resource_limit,"attribute count exceeds the 8192-per-owner limit"};
        for(unsigned ai=0;ai<count;++ai){if(stop.stop_requested())return Error{ErrorCode::canceled,"classfile attribute parsing canceled"};std::uint16_t name_ix=0;std::uint32_t len=0;if(!r.u2(name_ix)||!r.u4(len))return malformed("truncated attribute header");
            if(len>64*1024*1024||attribute_bytes>max_total_attributes-len)return Error{ErrorCode::resource_limit,"classfile attribute data exceeds bounded size limits"};attribute_bytes+=len;
            auto an=utf8(name_ix);if(!an)return an.error();const auto start=r.p;if(len>r.b.size()-r.p)return malformed("attribute extent exceeds its enclosing owner");
            ReaderExtent extent{r,r.b};r.b=r.b.first(start+len);
            if(!class_level&&(an.value()=="NestHost"||an.value()=="NestMembers"||an.value()=="PermittedSubclasses"||an.value()=="Record"||an.value()=="Module"||an.value()=="ModulePackages"||an.value()=="ModuleMainClass"))return malformed("class-level attribute appears on a member or Code attribute list");
            if(an.value()=="ConstantValue"){
                if(!member||method||class_level||code_owner)
                    return malformed("ConstantValue attribute appears outside a field attribute list");
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
                // The value is validated but not represented in JvmMember yet.
                metadata_complete=false;
            }else if(an.value()=="RuntimeVisibleAnnotations"||an.value()=="RuntimeInvisibleAnnotations"){
                if(code_owner)return malformed("declaration annotation attribute appears inside Code");
                if(!class_level&&!member)return malformed("annotation attribute has no declaration owner");
                const bool visible=an.value()=="RuntimeVisibleAnnotations";
                bool duplicate=false;
                if(class_level){bool &seen=visible?have_class_visible_annotations:have_class_invisible_annotations;duplicate=seen;seen=true;}
                else {auto &owners=visible?visible_annotations_seen:invisible_annotations_seen;duplicate=!owners.insert(member).second;}
                if(duplicate)return malformed("duplicate annotation attribute");
                auto &target=class_level?(an.value()=="RuntimeVisibleAnnotations"?md.visible_annotations:md.invisible_annotations):(an.value()=="RuntimeVisibleAnnotations"?member->visible_annotations:member->invisible_annotations);
                auto parsed=read_annotations(target);if(!parsed)return parsed.error();
            }else if(an.value()=="RuntimeVisibleParameterAnnotations"||an.value()=="RuntimeInvisibleParameterAnnotations"){
                if(class_level||!member||!method||code_owner)return malformed("parameter annotation attribute appears outside a method declaration");
                const bool visible=an.value()=="RuntimeVisibleParameterAnnotations";
                auto &owners=visible?visible_parameter_annotations_seen:invisible_parameter_annotations_seen;
                if(!owners.insert(member).second)return malformed("duplicate parameter annotation attribute");
                std::uint8_t parameters=0;if(!r.u1(parameters))return malformed("truncated parameter annotation count");
                std::vector<std::vector<JvmAnnotation>> parsed(parameters);
                for(auto &parameter:parsed){auto result=read_annotations(parameter);if(!result)return result.error();}
                (visible?member->visible_parameter_annotations:member->invisible_parameter_annotations)=std::move(parsed);
            }else if(an.value()=="AnnotationDefault"){
                if(class_level||!member||!method||code_owner)return malformed("AnnotationDefault appears outside a method declaration");
                if(!annotation_defaults_seen.insert(member).second)return malformed("duplicate AnnotationDefault attribute");
                auto value=annotation_value(0);if(!value)return value.error();member->annotation_default=std::move(value.value());
            }else if(an.value()=="StackMapTable"){
                if(!code_owner||!member)return malformed("StackMapTable appears outside a Code attribute");
                if(code_owner->stack_map_table)return malformed("duplicate StackMapTable attribute");
                const auto code_bytes=bytes.subspan(static_cast<std::size_t>(code_owner->file_begin.value),code_owner->code_size);
                auto table=read_stack_map_table(r,md,*member,*code_owner,code_bytes,stop,expanded_verification_entries,stack_map_frames);
                if(!table)return table.error();code_owner->stack_map_table=std::move(table.value());
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
                code.exception_table.reserve(ec);
                for(unsigned k=0;k<ec;++k){JvmExceptionHandler e;if(!r.u2(e.start_pc)||!r.u2(e.end_pc)||!r.u2(e.handler_pc)||!r.u2(e.catch_type)||e.start_pc>=e.end_pc||e.end_pc>cl||e.handler_pc>=cl)return malformed("invalid Code exception handler range");if(e.catch_type){auto c=class_name(e.catch_type);if(!c)return c.error();}code.exception_table.push_back(e);}
                auto nested=attributes(false,member,false,&code);if(!nested)return nested.error();
                if(r.p!=start+len)return malformed("Code attribute length does not match its parsed structure");
                member->code=std::move(code);
            }else if(class_level&&an.value()=="NestHost"){
                if(have_nest_members)return malformed("class cannot declare both NestHost and NestMembers");
                if(have_nest_host)return malformed("duplicate NestHost attribute");
                if(len!=2)return malformed("NestHost attribute must contain exactly one class index");
                std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated NestHost attribute");
                auto name=class_name(ix);if(!name)return name.error();md.nest_host=std::move(name.value());have_nest_host=true;
            }else if(class_level&&an.value()=="NestMembers"){
                if(have_nest_host)return malformed("class cannot declare both NestHost and NestMembers");
                if(have_nest_members)return malformed("duplicate NestMembers attribute");
                if(len<2)return malformed("truncated NestMembers attribute");
                std::uint16_t count=0;if(!r.u2(count)||count>8192)return malformed("invalid NestMembers count");
                if(std::uint64_t(count)*2+2!=len)return malformed("NestMembers attribute length does not match its class indexes");
                md.nest_members.reserve(count);
                for(unsigned i=0;i<count;++i){std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated NestMembers class index");auto name=class_name(ix);if(!name)return name.error();md.nest_members.push_back(std::move(name.value()));}
                have_nest_members=true;
            }else if(class_level&&an.value()=="PermittedSubclasses"){
                if(have_permitted_subclasses)return malformed("duplicate PermittedSubclasses attribute");
                if(len<2)return malformed("truncated PermittedSubclasses attribute");
                std::uint16_t count=0;if(!r.u2(count)||count>8192)return malformed("invalid PermittedSubclasses count");
                if(std::uint64_t(count)*2+2!=len)return malformed("PermittedSubclasses attribute length does not match its class indexes");
                md.permitted_subclasses.reserve(count);
                for(unsigned i=0;i<count;++i){std::uint16_t ix=0;if(!r.u2(ix))return malformed("truncated permitted subclass index");auto name=class_name(ix);if(!name)return name.error();md.permitted_subclasses.push_back(std::move(name.value()));}
                have_permitted_subclasses=true;
            }else if(class_level&&an.value()=="Record"){
                if(have_record)return malformed("duplicate Record attribute");
                const auto record_end=start+len;
                if(len<2)return malformed("truncated Record attribute");
                std::uint16_t count=0;if(!r.u2(count)||count>8192)return malformed("invalid Record component count");
                md.record_components.reserve(count);
                for(unsigned i=0;i<count;++i){
                    JvmRecordComponent component;
                    if(r.p>record_end||record_end-r.p<6)return malformed("truncated Record component declaration");
                    if(!r.u2(component.name_index)||!r.u2(component.descriptor_index))return malformed("truncated Record component declaration");
                    auto name=utf8(component.name_index),descriptor=utf8(component.descriptor_index);
                    if(!name)return name.error();if(!descriptor)return descriptor.error();
                    component.name=std::move(name.value());component.descriptor=std::move(descriptor.value());
                    std::uint16_t nested_count=0;if(record_end-r.p<2||!r.u2(nested_count)||nested_count>8192)return malformed("invalid Record component attribute count");
                    bool have_signature=false;
                    for(unsigned nested_index=0;nested_index<nested_count;++nested_index){
                        std::uint16_t nested_name_index=0;std::uint32_t nested_length=0;
                        if(r.p>record_end||record_end-r.p<6)return malformed("truncated Record component attribute header");
                        if(!r.u2(nested_name_index)||!r.u4(nested_length))return malformed("truncated Record component attribute header");
                        auto nested_name=utf8(nested_name_index);if(!nested_name)return nested_name.error();
                        if(nested_length>64*1024*1024||nested_length>record_end-r.p)return malformed("Record component attribute extent exceeds its Record attribute");
                        const auto nested_start=r.p;
                        if(nested_name.value()=="Signature"){
                            if(have_signature||nested_length!=2)return malformed("invalid or duplicate Record component Signature attribute");
                            std::uint16_t signature_index=0;if(!r.u2(signature_index))return malformed("truncated Record component Signature attribute");
                            auto signature=utf8(signature_index);if(!signature)return signature.error();
                            component.signature=std::move(signature.value());have_signature=true;
                        }else{
                            metadata_complete=false;
                            if(!r.skip(nested_length))return malformed("truncated Record component attribute payload");
                        }
                        if(r.p!=nested_start+nested_length)return malformed("Record component attribute length does not match its payload");
                    }
                    md.record_components.push_back(std::move(component));
                }
                if(r.p!=record_end)return malformed("Record attribute length does not match its components");
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
                for(unsigned i=0;i<count;++i){
                    std::uint16_t index=0,flags=0,version=0;
                    if(!r.u2(index)||!r.u2(flags)||!r.u2(version))return malformed("truncated Module requires entry");
                    auto required=module_name(index);if(!required)return required.error();
                    if(flags&~std::uint16_t{0x9060})return malformed("Module requires entry contains reserved flags");
                    JvmModuleRequire entry;entry.module=std::move(required.value());entry.flags=flags;
                    if(version){auto version_name=utf8(version);if(!version_name)return version_name.error();entry.version=std::move(version_name.value());}
                    module.required_modules.push_back(std::move(entry));
                }
                const auto read_exports=[&](std::vector<JvmModuleExport> &entries,std::string_view label)->Result<bool>{
                    std::uint16_t items=0;if(!r.u2(items)||!claim_items(items))return malformed("invalid Module "+std::string(label)+" count");
                    entries.reserve(items);
                    for(unsigned i=0;i<items;++i){
                        std::uint16_t index=0,flags=0,to_count=0;
                        if(!r.u2(index)||!r.u2(flags)||!r.u2(to_count))return malformed("truncated Module "+std::string(label)+" entry");
                        auto package=package_name(index);if(!package)return package.error();
                        if(flags&~std::uint16_t{0x9000}||!claim_items(to_count))return malformed("invalid Module "+std::string(label)+" flags or target count");
                        JvmModuleExport entry;entry.package_name=std::move(package.value());entry.flags=flags;entry.to_modules.reserve(to_count);
                        for(unsigned target=0;target<to_count;++target){std::uint16_t target_index=0;if(!r.u2(target_index))return malformed("truncated Module "+std::string(label)+" target list");auto target_name=module_name(target_index);if(!target_name)return target_name.error();entry.to_modules.push_back(std::move(target_name.value()));}
                        entries.push_back(std::move(entry));
                    }
                    return true;
                };
                auto exports=read_exports(module.exports,"exports");if(!exports)return exports.error();
                auto opens=read_exports(module.opens,"opens");if(!opens)return opens.error();
                if(!r.u2(count)||!claim_items(count))return malformed("invalid Module uses count");
                module.uses.reserve(count);
                for(unsigned i=0;i<count;++i){std::uint16_t index=0;if(!r.u2(index))return malformed("truncated Module uses entry");auto used=class_name(index);if(!used)return used.error();module.uses.push_back(std::move(used.value()));}
                if(!r.u2(count)||!claim_items(count))return malformed("invalid Module provides count");
                module.provides.reserve(count);
                for(unsigned i=0;i<count;++i){
                    std::uint16_t service_index=0,with_count=0;
                    if(!r.u2(service_index)||!r.u2(with_count))return malformed("truncated Module provides entry");
                    auto service=class_name(service_index);if(!service)return service.error();
                    if(!with_count||!claim_items(with_count))return malformed("invalid Module provider count");
                    JvmModuleProvide entry;entry.service=std::move(service.value());entry.implementations.reserve(with_count);
                    for(unsigned implementation=0;implementation<with_count;++implementation){std::uint16_t index=0;if(!r.u2(index))return malformed("truncated Module provider class index");auto name=class_name(index);if(!name)return name.error();entry.implementations.push_back(std::move(name.value()));}
                    module.provides.push_back(std::move(entry));
                }
                md.module=std::move(module);
            }else if(class_level&&an.value()=="ModulePackages"){
                if(have_module_packages)return malformed("duplicate ModulePackages attribute");
                if(md.major_version<53||md.class_name!="module-info"||(md.access_flags&0x8000)==0||len<2)return malformed("ModulePackages requires a Java 9 module-info class");
                std::uint16_t count=0;if(!r.u2(count)||count>8192||std::uint64_t(count)*2+2!=len)return malformed("invalid ModulePackages count or length");
                md.module_packages.reserve(count);
                for(unsigned i=0;i<count;++i){std::uint16_t index=0;if(!r.u2(index))return malformed("truncated ModulePackages entry");auto name=package_name(index);if(!name)return name.error();md.module_packages.push_back(std::move(name.value()));}
                have_module_packages=true;
            }else if(class_level&&an.value()=="ModuleMainClass"){
                if(have_module_main_class)return malformed("duplicate ModuleMainClass attribute");
                if(md.major_version<53||md.class_name!="module-info"||(md.access_flags&0x8000)==0||len!=2)return malformed("ModuleMainClass requires one class index in a Java 9 module-info class");
                std::uint16_t index=0;if(!r.u2(index))return malformed("truncated ModuleMainClass attribute");auto name=class_name(index);if(!name)return name.error();md.module_main_class=std::move(name.value());have_module_main_class=true;
            }else{
                if(an.value()!="ConstantValue"&&an.value()!="Exceptions"&&an.value()!="Signature"&&an.value()!="SourceFile"&&an.value()!="Synthetic"&&an.value()!="Deprecated"&&an.value()!="LineNumberTable"&&an.value()!="LocalVariableTable")metadata_complete=false;
                if(!r.skip(len))return malformed("truncated attribute payload");
            }
            if(r.p!=start+len)return malformed("attribute parser did not consume its declared extent");
        }
        return true;
    };
    const auto members=[&](std::vector<JvmMember>&out,bool methods)->Result<bool>{
        std::uint16_t count=0;if(!r.u2(count)||count>8192)return Error{ErrorCode::resource_limit,"member count exceeds the 8192-per-class limit"};out.reserve(count);
        for(unsigned i=0;i<count;++i){JvmMember m;if(!r.u2(m.access_flags)||!r.u2(m.name_index)||!r.u2(m.descriptor_index))return malformed("truncated member declaration");auto name=utf8(m.name_index),desc=utf8(m.descriptor_index);if(!name)return name.error();if(!desc)return desc.error();m.name=std::move(name.value());m.descriptor=std::move(desc.value());out.push_back(std::move(m));auto result=attributes(methods,&out.back(),false,nullptr);if(!result)return result.error();}
        return true;
    };
    auto f=members(md.fields,false);if(!f)return f.error();auto m=members(md.methods,true);if(!m)return m.error();
    auto class_attrs=attributes(false,nullptr,true,nullptr);if(!class_attrs)return class_attrs.error();if(r.p!=bytes.size())return malformed("trailing bytes after classfile attributes");
    if((have_module_packages||have_module_main_class)&&!md.module)return malformed("ModulePackages and ModuleMainClass require a Module attribute");
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
} // namespace hexlab
