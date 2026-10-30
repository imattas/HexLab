#include "search_internal.hpp"
#include <charconv>
namespace hexlab::search_detail {
namespace {
int nibble(char c){if(c=='?')return -1;if(c>='0' && c<='9')return int(c-'0');if(c>='a' && c<='f')return int(c-'a'+10);if(c>='A' && c<='F')return int(c-'A'+10);throw Failure{{ErrorCode::invalid_argument,"Byte pattern requires two-character hex octets with ? nibble wildcards, separated by whitespace"}};}
bool space(char c){return c==' ' || c=='\t' || c=='\r' || c=='\n';}
void octet(Compiled& result,unsigned b){require(result.pattern.size()<4096,"Search pattern exceeds 4096 bytes",ErrorCode::resource_limit);result.pattern.push_back({std::byte(b),std::byte{0xff}});}
void text_octet(Compiled& result,unsigned b,bool fold_ascii_case){
    require(result.pattern.size()<4096,"Search pattern exceeds 4096 bytes",ErrorCode::resource_limit);
    if(fold_ascii_case && ((b>='A' && b<='Z') || (b>='a' && b<='z')))
        result.pattern.push_back({std::byte(b&~0x20u),std::byte{0xdf}});
    else result.pattern.push_back({std::byte(b),std::byte{0xff}});
}
void utf16(Compiled& result,unsigned cp,bool big_endian,bool fold_ascii_case){
    if(big_endian){octet(result,cp>>8);if(cp<=0x7f)text_octet(result,cp,fold_ascii_case);else octet(result,cp&255);}
    else {if(cp<=0x7f)text_octet(result,cp,fold_ascii_case);else octet(result,cp&255);octet(result,cp>>8);}
}
void utf32(Compiled& result,unsigned cp,bool big_endian,bool fold_ascii_case){
    if(big_endian){octet(result,cp>>24);octet(result,cp>>16);octet(result,cp>>8);if(cp<=0x7f)text_octet(result,cp,fold_ascii_case);else octet(result,cp);}
    else {if(cp<=0x7f)text_octet(result,cp,fold_ascii_case);else octet(result,cp);octet(result,cp>>8);octet(result,cp>>16);octet(result,cp>>24);}
}
std::optional<unsigned> windows1252_byte(unsigned cp) {
    if(cp<=0x7f || (cp>=0xa0 && cp<=0xff)) return cp;
    static constexpr unsigned short upper[32]={
        0x20ac,0,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,
        0x02c6,0x2030,0x0160,0x2039,0x0152,0,0x017d,0,
        0,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0x02dc,0x2122,0x0161,0x203a,0x0153,0,0x017e,0x0178};
    for(unsigned i=0;i<32;++i) if(upper[i]==cp) return i+0x80;
    return {};
}
void text(Compiled& result,const TextQuery& query){
    require(query.encoding==TextEncoding::ascii || query.encoding==TextEncoding::utf8 || query.encoding==TextEncoding::utf16le || query.encoding==TextEncoding::utf16be || query.encoding==TextEncoding::utf32le || query.encoding==TextEncoding::utf32be || query.encoding==TextEncoding::windows1252 || query.encoding==TextEncoding::iso8859_1,"Unknown text encoding");require(!query.text.empty() && query.text.size()<=16384,"Text query is empty or too large");
    for(std::size_t at=0;at<query.text.size();){auto start=at;unsigned first=static_cast<unsigned char>(query.text[at++]),cp=first,count=0,minimum=0;
        if(first<0x80){}else if(first>=0xc2 && first<=0xdf){cp=first&31;count=1;minimum=0x80;}else if(first>=0xe0 && first<=0xef){cp=first&15;count=2;minimum=0x800;}else if(first>=0xf0 && first<=0xf4){cp=first&7;count=3;minimum=0x10000;}else require(false,"Text query is not valid UTF-8");
        require(count<=query.text.size()-at,"Text query ends inside UTF-8 sequence");for(unsigned n=0;n<count;++n){auto c=static_cast<unsigned char>(query.text[at++]);require((c&0xc0)==0x80,"Invalid UTF-8 continuation");cp=(cp<<6)|(c&63);}require(cp>=minimum && cp<=0x10ffff && !(cp>=0xd800 && cp<=0xdfff),"Invalid Unicode scalar");
        const bool fold_ascii_case=!query.case_sensitive;
        if(query.encoding==TextEncoding::ascii){require(cp<128,"ASCII text query contains non-ASCII scalar");text_octet(result,cp,fold_ascii_case);}else if(query.encoding==TextEncoding::windows1252){const auto byte=windows1252_byte(cp);require(bool(byte),"Text query contains a scalar not representable in Windows-1252");text_octet(result,*byte,fold_ascii_case);}else if(query.encoding==TextEncoding::iso8859_1){require(cp<=0xff,"Text query contains a scalar not representable in ISO-8859-1");text_octet(result,cp,fold_ascii_case);}else if(query.encoding==TextEncoding::utf8){if(cp<0x80)text_octet(result,cp,fold_ascii_case);else for(auto i=start;i<at;++i)octet(result,static_cast<unsigned char>(query.text[i]));}else if(query.encoding==TextEncoding::utf16le||query.encoding==TextEncoding::utf16be){const bool big_endian=query.encoding==TextEncoding::utf16be;if(cp<0x10000)utf16(result,cp,big_endian,fold_ascii_case);else{cp-=0x10000;utf16(result,0xd800+(cp>>10),big_endian,fold_ascii_case);utf16(result,0xdc00+(cp&1023),big_endian,fold_ascii_case);}}else utf32(result,cp,query.encoding==TextEncoding::utf32be,fold_ascii_case);
    }
}
std::uint64_t immediate_bits(const ImmediateQuery& query){
    require(query.width==8 || query.width==16 || query.width==32 || query.width==64,"Immediate width must be 8, 16, 32 or 64");require(query.interpretation==ImmediateInterpretation::signed_value || query.interpretation==ImmediateInterpretation::unsigned_value,"Unknown immediate interpretation");require(!query.value.empty() && query.value.size()<=80,"Invalid immediate value");
    std::string_view value=query.value;bool negative=value.front()=='-';if(negative || value.front()=='+')value.remove_prefix(1);require(!value.empty(),"Missing immediate digits");require(!negative || query.interpretation==ImmediateInterpretation::signed_value,"Unsigned immediate cannot be negative");int base=10;if(value.size()>=2 && value[0]=='0' && (value[1]=='x' || value[1]=='X')){base=16;value.remove_prefix(2);}require(!value.empty(),"Missing immediate digits");std::uint64_t magnitude=0;auto parsed=std::from_chars(value.data(),value.data()+value.size(),magnitude,base);require(parsed.ec==std::errc{} && parsed.ptr==value.data()+value.size(),"Invalid or overflowing immediate digits");
    auto mask=query.width==64?UINT64_MAX:(std::uint64_t{1}<<query.width)-1;if(query.interpretation==ImmediateInterpretation::unsigned_value)require(magnitude<=mask,"Immediate exceeds unsigned width");else{auto sign=std::uint64_t{1}<<(query.width-1);require(magnitude<sign || (negative && magnitude==sign),"Immediate exceeds signed width");}return (negative?std::uint64_t{0}-magnitude:magnitude)&mask;
}
}
Compiled compile(const SearchQuery& query){
    Compiled result;std::vector<std::byte> canonical{std::byte{2},std::byte(query.index())};
    if(auto pattern=std::get_if<BytePattern>(&query)){
        require(!pattern->text.empty() && pattern->text.size()<=32768,"Byte pattern is empty or too large");std::size_t at=0;while(at<pattern->text.size()){while(at<pattern->text.size() && space(pattern->text[at]))++at;if(at==pattern->text.size())break;auto begin=at;while(at<pattern->text.size() && !space(pattern->text[at]))++at;require(at-begin==2,"Byte pattern requires two-character octets");require(result.pattern.size()<4096,"Search pattern exceeds 4096 bytes",ErrorCode::resource_limit);const auto high=nibble(pattern->text[begin]),low=nibble(pattern->text[begin+1]);const auto value=static_cast<unsigned>((high<0?0:high)<<4)|(low<0?0:static_cast<unsigned>(low));const auto mask=static_cast<unsigned>((high<0?0:0xf0)|(low<0?0:0x0f));result.pattern.push_back({std::byte(value),std::byte(mask)});}
    }else if(auto literal=std::get_if<TextQuery>(&query)){text(result,*literal);canonical.push_back(std::byte(literal->encoding));canonical.push_back(std::byte(literal->case_sensitive ? 1 : 0));}else{result.immediate=std::get<ImmediateQuery>(query);result.bits=immediate_bits(*result.immediate);canonical.push_back(std::byte(result.immediate->width));canonical.push_back(std::byte(result.immediate->interpretation));for(int n=7;n>=0;--n)canonical.push_back(std::byte((result.bits>>(n*8))&255));}
    require(result.immediate || !result.pattern.empty(),"Empty search pattern");for(auto octet:result.pattern){canonical.push_back(octet.mask);canonical.push_back(octet.value);}Sha256 digest;take(digest.update(canonical));result.fingerprint=digest.digest();return result;
}
}
namespace hexlab {Result<Sha256Digest> search_query_fingerprint(const SearchQuery& query){return search_detail::guarded([&]()->Result<Sha256Digest>{return search_detail::compile(query).fingerprint;});}}
