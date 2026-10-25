#include "hexlab/analysis/flirt.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include <bit>
#include <cstring>
#include <functional>
#include <array>
#include <memory>
#include <tuple>
#include "miniz.h"

namespace hexlab {
namespace {
struct Failure { Error error; };

void require(bool value, std::string message, ErrorCode code = ErrorCode::invalid_argument) {
    if (!value) throw Failure{{code, std::move(message)}};
}
void check_stop(std::stop_token stop) {
    require(!stop.stop_requested(), "FLIRT recognition canceled", ErrorCode::canceled);
}
template<class F> auto guarded(F &&fn) -> decltype(fn()) {
    try { return fn(); }
    catch (const Failure &failure) { return failure.error; }
    catch (const std::bad_alloc &) { return Error{ErrorCode::resource_limit, "FLIRT allocation limit reached"}; }
    catch (const std::length_error &) { return Error{ErrorCode::resource_limit, "FLIRT allocation limit reached"}; }
}

int hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

std::uint64_t parse_hex(std::string_view text, std::size_t digits, std::string_view field) {
    require(text.size() == digits, "FLIRT " + std::string(field) + " has an invalid width");
    std::uint64_t value = 0;
    for (const auto c : text) {
        const auto digit = hex_digit(c);
        require(digit >= 0, "FLIRT " + std::string(field) + " is not hexadecimal");
        value = (value << 4) | static_cast<unsigned>(digit);
    }
    return value;
}

bool valid_target(Architecture architecture, ExecutionMode mode) {
    switch (architecture) {
    case Architecture::x86: return mode == ExecutionMode::x86_16 || mode == ExecutionMode::x86_32;
    case Architecture::x86_64: return mode == ExecutionMode::x86_64;
    case Architecture::arm: return mode == ExecutionMode::a32 || mode == ExecutionMode::thumb;
    case Architecture::arm64: return mode == ExecutionMode::a64;
    case Architecture::riscv32: return mode == ExecutionMode::rv32;
    case Architecture::riscv64: return mode == ExecutionMode::rv64 || mode == ExecutionMode::rv64c;
    case Architecture::mips32: return mode == ExecutionMode::mips32;
    case Architecture::mips64: return mode == ExecutionMode::mips64;
    case Architecture::mos6502: return mode == ExecutionMode::m6502;
    case Architecture::powerpc: return mode == ExecutionMode::ppc32 || mode == ExecutionMode::ppc64;
    default: return false;
    }
}

std::int32_t parse_offset(std::string_view text) {
    const auto static_name = !text.empty() && text.back() == '@';
    if (static_name) text.remove_suffix(1);
    require(!text.empty() && text.size() <= 8, "FLIRT symbol offset has an invalid width");
    const auto value = parse_hex(text, text.size(), "symbol offset");
    require(value <= static_cast<std::uint64_t>(INT32_MAX), "FLIRT symbol offset exceeds the supported signed range",
            ErrorCode::unsupported);
    return static_cast<std::int32_t>(value);
}

std::vector<SignatureByte> parse_pattern(std::string_view text, std::size_t max_bytes) {
    require(!text.empty() && text.size() % 2 == 0 && text.size() / 2 <= max_bytes,
            "FLIRT byte pattern has an invalid length");
    std::vector<SignatureByte> result;
    result.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        if (text[i] == '.' && text[i + 1] == '.') {
            result.push_back({std::byte{}, std::byte{}});
            continue;
        }
        const auto high = hex_digit(text[i]);
        const auto low = hex_digit(text[i + 1]);
        require(high >= 0 && low >= 0, "FLIRT patterns support only exact bytes or `..` wildcards");
        result.push_back({std::byte((high << 4) | low), std::byte{0xff}});
    }
    return result;
}

using AddressKey = std::pair<std::uint32_t, std::uint64_t>;
AddressKey address_key(Address value) { return {value.space.value, value.offset}; }

bool masked_equal(std::byte value, const SignatureByte &pattern) {
    const auto mask = std::to_integer<unsigned>(pattern.mask);
    return (std::to_integer<unsigned>(value) & mask) ==
           (std::to_integer<unsigned>(pattern.value) & mask);
}

struct CandidatePattern {
    std::size_t pattern = 0;
    std::size_t catalog = 0;
    std::vector<FlirtSymbol> entry_symbols;
    std::vector<FlirtSymbol> references;
    bool resolved = false;
};

} // namespace

Result<FlirtCatalog> parse_flirt_pat(std::string_view text, Architecture architecture,
        ExecutionMode mode, std::string provenance, const FlirtCatalogLimits &limits,
        std::stop_token stop) {
    return guarded([&]() -> Result<FlirtCatalog> {
        require(text.size() <= limits.max_bytes && limits.max_bytes <= 64 * 1024 * 1024 &&
                    limits.max_patterns && limits.max_patterns <= 65536 &&
                    limits.max_symbols_per_pattern && limits.max_symbols_per_pattern <= 128 &&
                    limits.max_name_bytes && limits.max_name_bytes <= 256 &&
                    limits.max_tail_bytes <= 256,
                "FLIRT catalog exceeds its configured bounds", ErrorCode::resource_limit);
        require(valid_target(architecture, mode),
                "FLIRT catalogs require a supported architecture and execution-mode pair");
        require(!provenance.empty() && provenance.size() <= 256 &&
                    provenance.find_first_of("\r\n") == std::string::npos,
                "FLIRT provenance must be 1..256 bytes");

        FlirtCatalog catalog{1, 0, architecture, mode, std::move(provenance), {}};
        std::size_t line_number = 0;
        while (!text.empty()) {
            check_stop(stop);
            ++line_number;
            const auto line_end = text.find('\n');
            auto line = text.substr(0, line_end == text.npos ? text.size() : line_end);
            text = line_end == text.npos ? std::string_view{} : text.substr(line_end + 1);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            auto nonspace = line.find_first_not_of(" \t");
            if (nonspace == line.npos) continue;
            line.remove_prefix(nonspace);
            if (line.starts_with("---")) break;
            if (line.starts_with('#') || line.starts_with(';')) continue;
            require(nonspace == 0, "FLIRT continuation lines are unsupported at line " + std::to_string(line_number),
                    ErrorCode::unsupported);
            require(line.size() <= 4096, "FLIRT pattern line exceeds 4096 bytes", ErrorCode::resource_limit);

            std::istringstream tokens{std::string(line)};
            std::string head, crc_length, crc, module_length;
            require(bool(tokens >> head >> crc_length >> crc >> module_length),
                    "Malformed FLIRT pattern line " + std::to_string(line_number));
            auto head_pattern = parse_pattern(head, 32);
            require(head_pattern.size() == 32, "FLIRT head must contain exactly 32 bytes");
            require(std::any_of(head_pattern.begin(), head_pattern.end(), [](const auto &b) { return b.mask != std::byte{}; }),
                    "FLIRT head must constrain at least one byte");
            const auto crc_size = static_cast<std::uint8_t>(parse_hex(crc_length, 2, "CRC length"));
            const auto expected_crc = static_cast<std::uint16_t>(parse_hex(crc, 4, "CRC16"));
            const auto function_size = static_cast<std::uint16_t>(parse_hex(module_length, 4, "module length"));
            require(function_size != 0, "FLIRT module length must be nonzero");
            require(function_size >= 32 || (crc_size == 0),
                    "FLIRT CRC window extends beyond a function shorter than its head");
            const auto crc_end = std::size_t{32} + crc_size;
            require(function_size < 32 || crc_end <= function_size,
                    "FLIRT CRC window extends beyond the module length");
            for (std::size_t i = function_size; i < 32; ++i)
                require(head_pattern[i].mask == std::byte{},
                        "FLIRT short-function head must wildcard bytes beyond module length");

            FlirtPatternDefinition definition;
            definition.head = std::move(head_pattern);
            definition.crc_length = crc_size;
            definition.crc16 = expected_crc;
            definition.module_length = function_size;
            std::string token;
            while (tokens >> token) {
                check_stop(stop);
                if (token.front() == ':' || token.front() == '^') {
                    const auto kind = token.front() == '^' ? FlirtSymbolKind::reference :
                        (!token.empty() && token.back() == '@' ? FlirtSymbolKind::local_name : FlirtSymbolKind::public_name);
                    const auto offset = parse_offset(std::string_view(token).substr(1));
                    require(static_cast<std::uint32_t>(offset) < function_size,
                            "FLIRT symbol/reference offset lies outside the module length");
                    std::string name;
                    require(bool(tokens >> name), "FLIRT symbol record lacks a name");
                    require(!name.empty() && name.size() <= limits.max_name_bytes &&
                                name.find_first_of("|\r\n") == std::string::npos,
                            "FLIRT symbol name is empty, too long, or not representable");
                    definition.symbols.push_back({kind, offset, std::move(name)});
                    require(definition.symbols.size() <= limits.max_symbols_per_pattern,
                            "FLIRT pattern has too many symbol records", ErrorCode::resource_limit);
                    continue;
                }
                require(definition.tail.empty(), "FLIRT pattern has more than one tail token");
                definition.tail = parse_pattern(token, limits.max_tail_bytes);
                require(definition.module_length < 32 ? definition.tail.empty() :
                            crc_end + definition.tail.size() <= definition.module_length,
                        "FLIRT tail extends beyond the module length");
                std::string extra;
                require(!(tokens >> extra), "Unexpected token after FLIRT tail");
            }
            require(!definition.symbols.empty(), "FLIRT pattern has no symbols");
            catalog.patterns.push_back(std::move(definition));
            require(catalog.patterns.size() <= limits.max_patterns,
                    "FLIRT pattern count exceeds its configured bound", ErrorCode::resource_limit);
        }
        require(!catalog.patterns.empty(), "FLIRT catalog contains no patterns");
        return catalog;
    });
}

Result<FlirtCatalog> parse_flirt_pat_gz(std::span<const std::byte> input, Architecture architecture,
        ExecutionMode mode, std::string provenance, const FlirtCatalogLimits &limits, std::stop_token stop) {
    return guarded([&]() -> Result<FlirtCatalog> {
        require(input.size() <= limits.max_bytes && limits.max_bytes <= 64 * 1024 * 1024,
                "Compressed FLIRT .pat.gz catalog exceeds its input-byte limit", ErrorCode::resource_limit);
        require(limits.max_inflated_bytes && limits.max_inflated_bytes <= 64 * 1024 * 1024,
                "FLIRT .pat.gz inflated-byte limit exceeds its supported maximum", ErrorCode::resource_limit);
        require(input.size() >= 18, "Truncated FLIRT .pat.gz stream");
        auto u8 = [&](std::size_t at) { return std::to_integer<std::uint8_t>(input[at]); };
        require(u8(0)==0x1f && u8(1)==0x8b && u8(2)==8, "Invalid FLIRT .pat.gz header");
        const auto flags=u8(3);
        require((flags&0xe0)==0, "Reserved FLIRT .pat.gz header flags are set");
        const auto trailer=input.size()-8;
        std::size_t at=10;
        auto ensure_header=[&](std::size_t amount) {
            require(at<=trailer && amount<=trailer-at, "Truncated FLIRT .pat.gz header");
        };
        if(flags&0x04) {
            ensure_header(2);const auto length=std::size_t(u8(at))|(std::size_t(u8(at+1))<<8);at+=2;
            ensure_header(length);at+=length;
        }
        auto skip_cstring=[&] {
            while(at<trailer && u8(at)!=0)++at;
            ensure_header(1);++at;
        };
        if(flags&0x08)skip_cstring();
        if(flags&0x10)skip_cstring();
        if(flags&0x02) {
            ensure_header(2);
            const auto expected=std::uint16_t(u8(at))|(std::uint16_t(u8(at+1))<<8);
            const auto actual=static_cast<std::uint16_t>(mz_crc32(0,
                reinterpret_cast<const unsigned char*>(input.data()),at));
            require(actual==expected, "FLIRT .pat.gz header checksum mismatch");at+=2;
        }
        require(at<trailer, "FLIRT .pat.gz deflate body is empty");
        mz_stream stream{};
        require(mz_inflateInit2(&stream,-MZ_DEFAULT_WINDOW_BITS)==MZ_OK,
                "Could not initialize bounded FLIRT .pat.gz decompressor",ErrorCode::resource_limit);
        struct InflateGuard { mz_stream *stream; ~InflateGuard(){if(stream)(void)mz_inflateEnd(stream);} } guard{&stream};
        const auto compressed=input.subspan(at,trailer-at);
        stream.next_in=reinterpret_cast<const unsigned char*>(compressed.data());
        stream.avail_in=static_cast<mz_uint>(compressed.size());
        std::array<unsigned char,64*1024> chunk{};
        std::vector<std::byte> inflated;
        for(;;) {
            check_stop(stop);
            const auto before_in=stream.total_in;
            stream.next_out=chunk.data();stream.avail_out=static_cast<mz_uint>(chunk.size());
            const auto status=mz_inflate(&stream,MZ_NO_FLUSH);
            const auto produced=chunk.size()-stream.avail_out;
            require(produced<=limits.max_inflated_bytes-inflated.size(),
                    "FLIRT .pat.gz inflated body exceeds its configured limit",ErrorCode::resource_limit);
            inflated.insert(inflated.end(),reinterpret_cast<const std::byte*>(chunk.data()),
                            reinterpret_cast<const std::byte*>(chunk.data()+produced));
            if(status==MZ_STREAM_END) {
                require(stream.avail_in==0,"FLIRT .pat.gz has trailing data or multiple members");break;
            }
            require((status==MZ_OK||status==MZ_BUF_ERROR)&&(produced||stream.total_in!=before_in),
                    "Invalid or truncated FLIRT .pat.gz deflate stream");
        }
        auto le32=[&](std::size_t pos) { return std::uint32_t(u8(pos))|(std::uint32_t(u8(pos+1))<<8)|
            (std::uint32_t(u8(pos+2))<<16)|(std::uint32_t(u8(pos+3))<<24); };
        require(inflated.size()<=UINT32_MAX && le32(trailer+4)==static_cast<std::uint32_t>(inflated.size()),
                "FLIRT .pat.gz uncompressed-size trailer mismatch");
        const auto checksum=static_cast<std::uint32_t>(mz_crc32(0,
            reinterpret_cast<const unsigned char*>(inflated.data()),inflated.size()));
        require(le32(trailer)==checksum,"FLIRT .pat.gz data checksum mismatch");
        auto text_limits=limits;text_limits.max_bytes=limits.max_inflated_bytes;
        auto parsed = parse_flirt_pat(std::string_view(reinterpret_cast<const char*>(inflated.data()),inflated.size()),
                                      architecture,mode,std::move(provenance),text_limits,stop);
        if (parsed) parsed.value().inflated_body_bytes = inflated.size();
        return parsed;
    });
}

Result<FlirtCatalog> parse_flirt_sig(std::span<const std::byte> input, std::string provenance,
        const FlirtCatalogLimits &limits, std::stop_token stop) {
    return guarded([&]() -> Result<FlirtCatalog> {
        require(input.size() <= limits.max_bytes && input.size() <= 64 * 1024 * 1024,
                "FLIRT .sig catalog exceeds its configured byte limit", ErrorCode::resource_limit);
        require(limits.max_inflated_bytes && limits.max_inflated_bytes <= 64 * 1024 * 1024,
                "FLIRT inflated-body limit exceeds its supported maximum", ErrorCode::resource_limit);
        require(limits.max_patterns && limits.max_patterns <= 65536 &&
                    limits.max_symbols_per_pattern && limits.max_symbols_per_pattern <= 128 &&
                    limits.max_name_bytes && limits.max_name_bytes <= 256 && limits.max_tail_bytes <= 256,
                "FLIRT .sig parser limits exceed their supported maxima", ErrorCode::resource_limit);
        require(provenance.size() && provenance.size() <= 256 && provenance.find_first_of("\r\n") == provenance.npos,
                "FLIRT provenance must be 1..256 bytes");
        std::size_t at = 0;
        auto byte = [&]() -> std::uint8_t { require(at < input.size(), "Truncated FLIRT .sig catalog"); return std::to_integer<std::uint8_t>(input[at++]); };
        auto le = [&](unsigned count) -> std::uint32_t { std::uint32_t value=0; for(unsigned i=0;i<count;++i)value|=std::uint32_t(byte())<<(8*i); return value; };
        auto be = [&](unsigned count) -> std::uint32_t { std::uint32_t value=0; for(unsigned i=0;i<count;++i)value=(value<<8)|byte(); return value; };
        auto vint16 = [&]() -> std::uint32_t {
            const auto first = byte();
            return first & 0x80 ? ((first & 0x7f) << 8) | byte() : first;
        };
        auto vint32 = [&]() -> std::uint32_t {
            const auto first = byte();
            if (!(first & 0x80)) return first;
            if (!(first & 0x40)) return ((first & 0x3f) << 8) | byte();
            // 110xxxxx prefixes a 32-bit value with three following bytes.
            if (!(first & 0x20)) return ((first & 0x1f) << 24) | be(3);
            // 111xxxxx is only a sentinel; the next four bytes carry the value.
            return be(4);
        };
        require(input.size() >= 6 && std::memcmp(input.data(), "IDASGN", 6)==0, "Invalid FLIRT .sig magic"); at=6;
        const auto version=byte(); require(version>=5 && version<=10,"Unsupported FLIRT .sig version",ErrorCode::unsupported);
        const auto arch=byte(); const auto file_types=le(4); (void)file_types; const auto os=le(2); (void)os; const auto app=le(2);
        const auto features=le(2); (void)le(2); (void)le(2); at+=12;
        const auto liblen=byte(); (void)le(2);
        const auto valid_features=version>=10?0x3fu:0x1fu;
        require((features & ~valid_features)==0,"Unsupported FLIRT .sig feature flags",ErrorCode::unsupported);
        require(version != 5 || !(features & 0x10),"Compressed FLIRT .sig version 5 bodies are unsupported",ErrorCode::unsupported);
        std::uint32_t function_count=0; std::uint16_t head_size=32;
        if(version>=6) function_count=le(4);
        if(version>=8) head_size=static_cast<std::uint16_t>(le(2));
        if(version>=10) (void)le(2);
        require(head_size>=1 && head_size<=64,"Unsupported FLIRT .sig pattern size");
        require(at+liblen<=input.size(),"Truncated FLIRT .sig library name"); at+=liblen;
        std::vector<std::byte> inflated_body;
        if (features & 0x10) {
            require(at < input.size(), "Compressed FLIRT .sig body is empty");
            mz_stream stream{};
            require(mz_inflateInit(&stream) == MZ_OK,
                    "Could not initialize bounded FLIRT decompressor", ErrorCode::resource_limit);
            struct InflateGuard {
                mz_stream *stream;
                ~InflateGuard() { if (stream) (void)mz_inflateEnd(stream); }
            } guard{&stream};
            const auto compressed = input.subspan(at);
            stream.next_in = reinterpret_cast<const unsigned char *>(compressed.data());
            stream.avail_in = static_cast<mz_uint>(compressed.size());
            std::array<unsigned char, 64 * 1024> chunk{};
            for (;;) {
                check_stop(stop);
                const auto before_in = stream.total_in;
                stream.next_out = chunk.data();
                stream.avail_out = static_cast<mz_uint>(chunk.size());
                const auto status = mz_inflate(&stream, MZ_FINISH);
                const auto produced = chunk.size() - stream.avail_out;
                require(produced <= limits.max_inflated_bytes - inflated_body.size(),
                        "Compressed FLIRT .sig body exceeds its inflated-byte limit", ErrorCode::resource_limit);
                inflated_body.insert(inflated_body.end(), reinterpret_cast<const std::byte *>(chunk.data()),
                    reinterpret_cast<const std::byte *>(chunk.data() + produced));
                if (status == MZ_STREAM_END) {
                    require(stream.avail_in == 0, "Compressed FLIRT .sig body has trailing bytes");
                    break;
                }
                require((status == MZ_OK || status == MZ_BUF_ERROR) &&
                            (produced != 0 || stream.total_in != before_in),
                        "Invalid or truncated compressed FLIRT .sig body");
            }
            input = std::span<const std::byte>(inflated_body.data(), inflated_body.size());
            at = 0;
        }
        Architecture architecture=Architecture::unknown; ExecutionMode mode=ExecutionMode::unknown;
        const bool b16=(app&0x80)!=0,b32=(app&0x100)!=0,b64=(app&0x200)!=0;
        if(arch==0 && b16&&!b32&&!b64){architecture=Architecture::x86;mode=ExecutionMode::x86_16;}
        else if(arch==0 && b32&&!b16&&!b64){architecture=Architecture::x86;mode=ExecutionMode::x86_32;}
        else if(arch==0 && b64&&!b16&&!b32){architecture=Architecture::x86_64;mode=ExecutionMode::x86_64;}
        else if(arch==5){architecture=Architecture::mos6502;mode=ExecutionMode::m6502;}
        else if(arch==12 && b32&&!b16&&!b64){architecture=Architecture::mips32;mode=ExecutionMode::mips32;}
        else if(arch==12 && b64&&!b16&&!b32){architecture=Architecture::mips64;mode=ExecutionMode::mips64;}
        else if(arch==13 && b32&&!b16&&!b64){architecture=Architecture::arm;mode=ExecutionMode::a32;}
        else if(arch==13 && b64&&!b16&&!b32){architecture=Architecture::arm64;mode=ExecutionMode::a64;}
        else if(arch==15 && b32&&!b16&&!b64){architecture=Architecture::powerpc;mode=ExecutionMode::ppc32;}
        else if(arch==15 && b64&&!b16&&!b32){architecture=Architecture::powerpc;mode=ExecutionMode::ppc64;}
        else if(arch==72 && b32&&!b16&&!b64){architecture=Architecture::riscv32;mode=ExecutionMode::rv32;}
        else if(arch==72 && b64&&!b16&&!b32){architecture=Architecture::riscv64;mode=ExecutionMode::rv64;}
        require(valid_target(architecture,mode),"Unsupported FLIRT .sig architecture/application combination",ErrorCode::unsupported);
        FlirtCatalog catalog{1,version,architecture,mode,std::move(provenance),{},inflated_body.size()};
        std::vector<SignatureByte> prefix;
        std::uint64_t work=0;
        auto word=[&](){return version<9?vint16():vint32();};
        auto parse_leaf=[&](auto &&self)->void {
            for(;;){ check_stop(stop); require(++work<=16*1024*1024,"FLIRT .sig parser work budget reached",ErrorCode::resource_limit);
                const auto crc_len=byte(); const auto crc=static_cast<std::uint16_t>(be(2));
                for(;;){ FlirtPatternDefinition p; p.head.assign(head_size,{std::byte{},std::byte{}}); for(std::size_t i=0;i<prefix.size()&&i<p.head.size();++i)p.head[i]=prefix[i]; p.crc_length=crc_len;p.crc16=crc;
                    const auto function_size=word(); require(function_size>0,"Invalid FLIRT function length"); p.module_length=function_size;
                    std::uint32_t offset=0; bool more_names=true; while(more_names){ auto delta=word(); bool local=false; if(at<input.size()&&std::to_integer<unsigned>(input[at])<0x20){auto flags=byte();local=(flags&2)!=0; if(flags&0x10) {require(delta<=offset,"Invalid negative FLIRT name offset");offset-=delta;}else {require(delta<=UINT32_MAX-offset,"FLIRT name offset overflow");offset+=delta;}} else {require(delta<=UINT32_MAX-offset,"FLIRT name offset overflow");offset+=delta;} std::string name; while(at<input.size()&&std::to_integer<unsigned>(input[at])>=0x20){require(name.size()<limits.max_name_bytes,"FLIRT symbol name limit exceeded",ErrorCode::resource_limit);name.push_back(static_cast<char>(byte()));} require(!name.empty(),"Empty FLIRT symbol name"); require(offset<=INT32_MAX,"FLIRT symbol offset exceeds supported signed range",ErrorCode::unsupported); p.symbols.push_back({local?FlirtSymbolKind::local_name:FlirtSymbolKind::public_name,static_cast<std::int32_t>(offset),std::move(name)}); require(p.symbols.size()<=limits.max_symbols_per_pattern,"FLIRT symbol limit exceeded",ErrorCode::resource_limit); const auto flags=byte(); more_names=(flags&1)!=0; if(flags&2){auto n=version<8?1u:word();require(n<=limits.max_tail_bytes,"FLIRT tail count limit exceeded",ErrorCode::resource_limit);for(std::uint32_t i=0;i<n;++i){auto o=word();auto v=byte();p.sparse_tail.push_back({o,{std::byte(v),std::byte{0xff}}});}} if(flags&4){auto n=version<8?1u:word();require(n<=limits.max_symbols_per_pattern-p.symbols.size(),"FLIRT reference limit exceeded",ErrorCode::resource_limit);for(std::uint32_t i=0;i<n;++i){auto o=word();auto len=byte();if(!len)len=vint16();require(len&&len<=limits.max_name_bytes&&at+len<=input.size(),"Invalid FLIRT reference name");std::string ref;for(unsigned j=0;j<len;++j)ref.push_back(static_cast<char>(byte()));require(o<=INT32_MAX,"FLIRT reference offset overflow");p.symbols.push_back({FlirtSymbolKind::reference,static_cast<std::int32_t>(o),std::move(ref)});}} const bool same_crc=(flags&8)!=0; const bool more_modules=(flags&16)!=0; require(!p.symbols.empty(),"FLIRT leaf has no names"); catalog.patterns.push_back(std::move(p)); require(catalog.patterns.size()<=limits.max_patterns,"FLIRT pattern limit exceeded",ErrorCode::resource_limit); if(!same_crc) { if(!more_modules) return; break; }
                }
            }
            }
        };
        std::function<void(unsigned)> walk; walk=[&](unsigned depth){
            check_stop(stop);
            require(depth < 256, "FLIRT trie depth exceeds 256", ErrorCode::resource_limit);
            require(++work<=16*1024*1024,"FLIRT .sig parser work budget reached",ErrorCode::resource_limit);
            const auto children=vint16();
            if(!children){parse_leaf(parse_leaf);return;}
            require(children<=4096,"FLIRT trie fanout exceeds bound",ErrorCode::resource_limit);
            for(std::uint32_t c=0;c<children;++c){
                const auto len=version<10?byte():vint16();
                require(len<=head_size,"FLIRT trie node exceeds head size");
                std::uint64_t mask=0;
                if(len==0)mask=0;
                else if(len<16)mask=vint16();
                else if(len<=32)mask=vint32();
                else mask=(std::uint64_t(vint32())<<32)|vint32();
                require(std::popcount(mask)<=len,"Invalid FLIRT wildcard mask");
                std::vector<SignatureByte> node(len);
                for(std::size_t i=len;i>0;--i){
                    if(mask&(std::uint64_t{1}<<(i-1)))node[i-1]={};
                    else node[i-1]={std::byte(byte()),std::byte{0xff}};
                }
                prefix.insert(prefix.end(),node.begin(),node.end());
                require(prefix.size()<=head_size,"FLIRT trie path exceeds pattern head");
                walk(depth+1);
                prefix.resize(prefix.size()-len);
            }
        };
        walk(0);
        require(!catalog.patterns.empty(),"FLIRT .sig catalog contains no patterns"); if(function_count)require(catalog.patterns.size()<=std::uint64_t(function_count)*128,"FLIRT .sig function count mismatch"); return catalog;
    });
}

Result<FlirtRecognition> recognize_flirt_catalog(const Image &image, const ByteStorage &bytes,
        const FunctionSnapshot &snapshot, const FlirtCatalog &catalog,
        const FlirtRecognitionLimits &limits, std::stop_token stop) {
    return recognize_flirt_catalogs(image, bytes, snapshot, std::span<const FlirtCatalog>(&catalog, 1), limits, stop);
}

Result<FlirtRecognition> recognize_flirt_catalogs(const Image &image, const ByteStorage &bytes,
        const FunctionSnapshot &snapshot, std::span<const FlirtCatalog> catalogs,
        const FlirtRecognitionLimits &limits, std::stop_token stop) {
    return guarded([&]() -> Result<FlirtRecognition> {
        check_stop(stop);
        require(!catalogs.empty() && limits.max_catalogs && limits.max_catalogs <= 256 &&
                    catalogs.size() <= limits.max_catalogs && limits.max_patterns && limits.max_patterns <= 65536,
                "FLIRT catalog set exceeds its configured bounds", ErrorCode::resource_limit);
        std::vector<const FlirtPatternDefinition *> patterns;
        std::vector<std::size_t> pattern_catalogs;
        for (std::size_t catalog_index = 0; catalog_index < catalogs.size(); ++catalog_index) {
            check_stop(stop);
            const auto &catalog = catalogs[catalog_index];
            require(catalog.format_version == 1 && valid_target(catalog.target_architecture, catalog.target_mode) &&
                        catalog.target_architecture == image.layout().architecture &&
                        catalog.target_mode == image.layout().mode && !catalog.patterns.empty(),
                    "FLIRT catalog target does not match image architecture and mode");
            require(!catalog.provenance.empty() && catalog.provenance.size() <= 256 &&
                        catalog.provenance.find_first_of("\r\n") == std::string::npos,
                    "FLIRT catalog provenance is invalid");
            require(catalog.patterns.size() <= limits.max_patterns - patterns.size(),
                    "FLIRT catalog set exceeds its total pattern limit", ErrorCode::resource_limit);
            patterns.reserve(patterns.size() + catalog.patterns.size());
            pattern_catalogs.reserve(pattern_catalogs.size() + catalog.patterns.size());
            for (const auto &pattern : catalog.patterns) {
                patterns.push_back(&pattern);
                pattern_catalogs.push_back(catalog_index);
            }
        }
        require(bytes.size() == image.storage()->size(), "FLIRT byte source does not match image storage");
        require(limits.max_functions && limits.max_functions <= 1000000,
                "FLIRT function limit exceeds its supported maximum", ErrorCode::resource_limit);
        require(limits.max_pattern_candidates && limits.max_pattern_candidates <= 16777216 &&
                    limits.max_comparisons && limits.max_comparisons <= 67108864 &&
                    limits.max_reference_checks && limits.max_reference_checks <= 16777216 &&
                    limits.max_results && limits.max_results <= 1000000,
                "FLIRT recognition limits exceed their supported maximum", ErrorCode::resource_limit);
        require(snapshot.functions.size() <= limits.max_functions && snapshot.calls.size() <= 2000000,
                "FLIRT function/call snapshot exceeds its supported bound", ErrorCode::resource_limit);

        struct Anchor { std::uint8_t offset; std::byte value; };
        std::map<std::pair<std::uint8_t, unsigned>, std::vector<std::size_t>> anchors;
        std::size_t max_probe = 0;
        for (std::size_t index = 0; index < patterns.size(); ++index) {
            check_stop(stop);
            const auto &pattern = *patterns[index];
            require(pattern.head.size() >= 1 && pattern.head.size() <= 64 && pattern.module_length != 0 && pattern.symbols.size() <= 128 &&
                        pattern.tail.size() <= 256 && pattern.sparse_tail.size() <= 256 &&
                        (pattern.module_length < 32 ? (pattern.crc_length == 0 && pattern.tail.empty()) :
                            pattern.head.size() + pattern.crc_length + pattern.tail.size() <= pattern.module_length),
                    "Invalid FLIRT pattern record");
            require(!pattern.symbols.empty(), "FLIRT pattern has no symbol records");
            for (const auto &symbol : pattern.symbols) {
                require(!symbol.name.empty() && symbol.name.size() <= 256 &&
                            symbol.name.find_first_of("|\r\n") == std::string::npos,
                        "Invalid FLIRT symbol record");
                require(symbol.offset >= 0 && static_cast<std::uint32_t>(symbol.offset) < pattern.module_length,
                        "FLIRT symbol/reference offset lies outside the module length");
                switch (symbol.kind) {
                case FlirtSymbolKind::public_name:
                case FlirtSymbolKind::local_name:
                case FlirtSymbolKind::reference:
                    break;
                default:
                    require(false, "Invalid FLIRT symbol kind");
                }
            }
            const auto anchor = std::find_if(pattern.head.begin(), pattern.head.end(),
                [](const auto &byte) { return byte.mask == std::byte{0xff}; });
            require(anchor != pattern.head.end(), "FLIRT head has no exact anchor byte");
            const auto offset = static_cast<std::uint8_t>(anchor - pattern.head.begin());
            anchors[{offset, std::to_integer<unsigned>(anchor->value)}].push_back(index);
            std::size_t probe = std::min<std::size_t>(pattern.head.size(), pattern.module_length) + pattern.crc_length + pattern.tail.size();
            for (const auto &[offset, byte] : pattern.sparse_tail) {
                (void)byte;
                require(pattern.head.size() + pattern.crc_length + offset < pattern.module_length,
                        "FLIRT sparse tail byte exceeds module length");
                probe = std::max(probe, pattern.head.size() + pattern.crc_length + offset + 1);
            }
            max_probe = std::max(max_probe, probe);
        }

        FlirtRecognition result;
        result.source_key = snapshot.key;
        result.complete = snapshot.complete;
        std::map<AddressKey, std::size_t> function_indices;
        std::map<std::uint64_t, std::size_t> function_ids;
        std::vector<std::vector<CandidatePattern>> matched(snapshot.functions.size());
        std::vector<std::shared_ptr<const FunctionRecord>> records = snapshot.functions;
        std::vector<std::map<std::int32_t, std::vector<std::size_t>>> calls_by_offset(records.size());
        for (std::size_t i = 0; i < records.size(); ++i) {
            check_stop(stop);
            require(bool(records[i]), "Missing recovered function record");
            require(function_indices.emplace(address_key(records[i]->entry), i).second,
                    "Duplicate recovered function entry");
            require(function_ids.emplace(records[i]->id.value, i).second, "Duplicate recovered function ID");
            if (!records[i]->complete) result.complete = false;
        }
        for (const auto &call : snapshot.calls) {
            check_stop(stop);
            const auto owner = function_ids.find(call.owner.value);
            if (owner == function_ids.end() || !call.target) continue;
            const auto &entry = records[owner->second]->entry;
            if (call.source.space != entry.space || call.source.offset < entry.offset) continue;
            const auto relative = call.source.offset - entry.offset;
            if (relative > static_cast<std::uint64_t>(INT32_MAX)) continue;
            calls_by_offset[owner->second][static_cast<std::int32_t>(relative)].push_back(
                function_indices.contains(address_key(*call.target)) ? function_indices.at(address_key(*call.target)) : SIZE_MAX);
        }

        for (std::size_t i = 0; i < records.size(); ++i) {
            check_stop(stop);
            require(i < limits.max_functions, "FLIRT function budget reached", ErrorCode::resource_limit);
            const auto &function = *records[i];
            const auto *segment = image.segment_at(function.entry);
            if (!segment || !segment->executable) continue;
            auto file = image.to_file_offset(function.entry);
            if (!file || file.value().value >= bytes.size()) continue;
            const auto delta = function.entry.offset - segment->begin.offset;
            if (delta >= segment->file_size) continue;
            const auto chunk = std::find_if(function.chunks.begin(), function.chunks.end(),
                [&](const auto &value) { return value.begin == function.entry; });
            if (chunk == function.chunks.end()) continue;
            const auto extent = std::min<std::uint64_t>(segment->file_size - delta, chunk->size);
            const auto read_size = static_cast<std::size_t>(std::min<std::uint64_t>(max_probe, extent));
            if (!read_size) continue;
            auto read = bytes.read_at(file.value(), read_size);
            require(bool(read), read ? "" : read.error().message, ErrorCode::io);
            require(read.value().bytes.size() == read_size, "Short read while checking a FLIRT function entry", ErrorCode::io);
            const auto code = std::span<const std::byte>(read.value().bytes);

            std::vector<std::size_t> candidates;
            for (std::uint8_t offset = 0; offset < 64; ++offset) {
                if (offset >= code.size()) break;
                const auto found = anchors.find({offset, std::to_integer<unsigned>(code[offset])});
                if (found == anchors.end()) continue;
                for (const auto pattern_index : found->second) {
                    check_stop(stop);
                    require(result.pattern_candidates < limits.max_pattern_candidates,
                            "FLIRT candidate budget reached", ErrorCode::resource_limit);
                    ++result.pattern_candidates;
                    candidates.push_back(pattern_index);
                }
            }

            for (const auto pattern_index : candidates) {
                check_stop(stop);
                const auto &pattern = *patterns[pattern_index];
                const auto required = std::min<std::size_t>(pattern.head.size(), pattern.module_length) +
                    pattern.crc_length + pattern.tail.size();
                if (required > pattern.module_length || required > code.size()) continue;
                bool head_matches = true;
                const auto head_length = std::min<std::size_t>(pattern.head.size(), pattern.module_length);
                for (std::size_t byte = 0; byte < head_length; ++byte) {
                    require(result.comparisons < limits.max_comparisons,
                            "FLIRT comparison budget reached", ErrorCode::resource_limit);
                    ++result.comparisons;
                    if (!masked_equal(code[byte], pattern.head[byte])) { head_matches = false; break; }
                }
                if (!head_matches) continue;
                if (pattern.crc_length) {
                    std::uint16_t crc = 0xffff;
                    for (const auto value : code.subspan(pattern.head.size(), pattern.crc_length)) {
                        require(result.comparisons < limits.max_comparisons,
                                "FLIRT comparison budget reached", ErrorCode::resource_limit);
                        ++result.comparisons;
                        crc ^= std::to_integer<std::uint8_t>(value);
                        for (unsigned bit = 0; bit != 8; ++bit)
                            crc = (crc & 1) ? static_cast<std::uint16_t>((crc >> 1) ^ 0x8408) :
                                              static_cast<std::uint16_t>(crc >> 1);
                    }
                    if (static_cast<std::uint16_t>(crc ^ 0xffff) != pattern.crc16) continue;
                } else if (pattern.crc16 != 0) continue;
                bool tail_matches = true;
                for (std::size_t byte = 0; byte < pattern.tail.size(); ++byte) {
                    require(result.comparisons < limits.max_comparisons,
                            "FLIRT comparison budget reached", ErrorCode::resource_limit);
                    ++result.comparisons;
                    if (!masked_equal(code[pattern.head.size() + pattern.crc_length + byte], pattern.tail[byte])) {
                        tail_matches = false; break;
                    }
                }
                for (const auto &[offset, value] : pattern.sparse_tail) {
                    require(result.comparisons < limits.max_comparisons,
                            "FLIRT comparison budget reached", ErrorCode::resource_limit);
                    ++result.comparisons;
                    if (!masked_equal(code[pattern.head.size() + pattern.crc_length + offset], value)) {
                        tail_matches = false; break;
                    }
                }
                if (!tail_matches) continue;
                CandidatePattern candidate;
                candidate.pattern = pattern_index;
                candidate.catalog = pattern_catalogs[pattern_index];
                for (const auto &symbol : pattern.symbols) {
                    if (symbol.kind == FlirtSymbolKind::reference) candidate.references.push_back(symbol);
                    else if (symbol.offset == 0) candidate.entry_symbols.push_back(symbol);
                }
                if (!candidate.entry_symbols.empty()) matched[i].push_back(std::move(candidate));
            }
        }

        // Resolve references from already grounded names. Cyclic groups with
        // no nameable seed never bootstrap themselves into a match.
        bool changed = true;
        std::uint64_t reference_checks = 0;
        while (changed) {
            check_stop(stop);
            changed = false;
            for (std::size_t i = 0; i < matched.size(); ++i) {
                for (auto &candidate : matched[i]) {
                    if (candidate.resolved) continue;
                    if (candidate.references.empty()) { candidate.resolved = true; changed = true; continue; }
                    bool all_references_resolved = true;
                    for (const auto &reference : candidate.references) {
                        require(reference_checks < limits.max_reference_checks,
                                "FLIRT reference-resolution budget reached", ErrorCode::resource_limit);
                        ++reference_checks;
                        const auto calls = calls_by_offset[i].find(reference.offset);
                        if (calls == calls_by_offset[i].end()) { all_references_resolved = false; break; }
                        bool found_target = false;
                        for (const auto target_index : calls->second) {
                            if (target_index == SIZE_MAX) continue;
                            for (const auto &target_candidate : matched[target_index]) {
                                require(reference_checks < limits.max_reference_checks,
                                        "FLIRT reference-resolution budget reached", ErrorCode::resource_limit);
                                ++reference_checks;
                                if (!target_candidate.resolved) continue;
                                for (const auto &name : target_candidate.entry_symbols) {
                                    require(reference_checks < limits.max_reference_checks,
                                            "FLIRT reference-resolution budget reached", ErrorCode::resource_limit);
                                    ++reference_checks;
                                    if (name.name == reference.name) {
                                        found_target = true;
                                        break;
                                    }
                                }
                                if (found_target) break;
                            }
                        }
                        if (!found_target) { all_references_resolved = false; break; }
                    }
                    if (all_references_resolved) { candidate.resolved = true; changed = true; }
                }
            }
        }

        for (std::size_t i = 0; i < matched.size(); ++i) {
            check_stop(stop);
            std::map<std::tuple<std::string, FlirtSymbolKind, std::size_t>, std::uint32_t> names;
            for (const auto &candidate : matched[i]) {
                if (!candidate.resolved) continue;
                for (const auto &symbol : candidate.entry_symbols) {
                    auto &count = names[{symbol.name, symbol.kind, candidate.catalog}];
                    require(count != UINT32_MAX, "FLIRT matching pattern count overflow", ErrorCode::overflow);
                    ++count;
                }
            }
            if (names.empty()) continue;
            require(result.functions.size() < limits.max_results,
                    "FLIRT result limit reached", ErrorCode::resource_limit);
            FunctionFlirtMatch match{records[i]->id, records[i]->entry, {}, false};
            std::set<std::string> distinct_names;
            for (const auto &[key, count] : names) {
                const auto catalog_index = std::get<2>(key);
                match.candidates.push_back({std::get<0>(key), catalogs[catalog_index].provenance,
                                            std::get<1>(key), count, catalog_index});
                distinct_names.insert(std::get<0>(key));
            }
            match.ambiguous = distinct_names.size() > 1;
            result.functions.push_back(std::move(match));
        }
        return result;
    });
}

Result<FunctionRecognitionEvidence> make_function_recognition_evidence(const FunctionSnapshot &snapshot,
        const Sha256Digest &catalog_digest, const FlirtRecognition &recognition, std::stop_token stop) {
    return guarded([&]() -> Result<FunctionRecognitionEvidence> {
        check_stop(stop);
        require(snapshot.key && recognition.source_key && *snapshot.key == *recognition.source_key,
                "FLAIR recognition is not bound to the current source identity", ErrorCode::conflict);
        FunctionRecognitionEvidence evidence;
        evidence.format_version = 2;
        evidence.kind = FunctionRecognitionKind::flirt_patterns;
        evidence.source_key = *snapshot.key;
        evidence.catalog_digest = catalog_digest;
        evidence.complete = recognition.complete;
        evidence.functions.reserve(recognition.functions.size());
        for (const auto &match : recognition.functions) {
            check_stop(stop);
            FunctionRecognitionRecord record;
            record.function = match.function;
            record.entry = match.entry;
            record.ambiguous = match.ambiguous;
            record.candidates.reserve(match.candidates.size());
            for (const auto &candidate : match.candidates) {
                check_stop(stop);
                record.candidates.push_back({candidate.name, candidate.provenance, 0, 0, 0, {},
                    static_cast<std::uint8_t>(candidate.kind), candidate.matching_patterns});
            }
            evidence.functions.push_back(std::move(record));
        }
        auto validation = validate_function_recognition_evidence(evidence, *snapshot.key, snapshot, stop);
        if (!validation) return validation.error();
        return evidence;
    });
}

} // namespace hexlab

