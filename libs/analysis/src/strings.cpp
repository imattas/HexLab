#include "hexlab/analysis/strings.hpp"
#include "strings_internal.hpp"
#include <algorithm>
#include <iterator>
#include <vector>

namespace hexlab {
namespace {
struct ScanFailure {Error error;};
struct BudgetEnd {};
struct WorkBudgetEnd {};
struct ScanRange {std::uint64_t begin,end;std::optional<Address> address;bool unmapped;};
class Cursor {
public:
    Cursor(const ByteStorage& storage,std::uint64_t end,std::size_t& inspected,
           std::size_t work_budget):storage_(storage),end_(end),inspected_(inspected),work_budget_(work_budget) {}
    unsigned byte(std::uint64_t at) {
        if(inspected_>=work_budget_)throw WorkBudgetEnd{};
        ++inspected_;
        if (at<window_begin_ || at-window_begin_>=window_.bytes.size()) {
            const auto amount=static_cast<std::size_t>(std::min<std::uint64_t>(65536,end_-at));
            auto input=storage_.read_at({at},amount);
            if (!input) throw ScanFailure{input.error()};
            if(input.value().bytes.size()!=amount)throw ScanFailure{{ErrorCode::io,"String source returned an incomplete read"}};
            window_=std::move(input.value());window_begin_=at;
        }
        return std::to_integer<unsigned>(window_.bytes[static_cast<std::size_t>(at-window_begin_)]);
    }
    std::uint32_t unit(std::uint64_t at,unsigned width,bool big_endian=false) {
        std::uint32_t value=0;
        for(unsigned i=0;i<width;++i) {
            const auto shift=big_endian ? (width-i-1)*8 : i*8;
            value|=byte(at+i)<<shift;
        }
        return value;
    }
private:
    const ByteStorage& storage_;
    std::uint64_t end_,window_begin_=0;
    std::size_t& inspected_;
    std::size_t work_budget_;
    ByteView window_{};
};
void check_stop(std::stop_token stop) {if(stop.stop_requested())throw ScanFailure{{ErrorCode::canceled,"String scan canceled"}};}
void utf8(std::string& out,std::uint32_t scalar) {
    if (scalar<0x80) out.push_back(static_cast<char>(scalar));
    else if (scalar<0x800) {out.push_back(static_cast<char>(0xc0|(scalar>>6)));out.push_back(static_cast<char>(0x80|(scalar&63)));}
    else if (scalar<0x10000) {
        out.push_back(static_cast<char>(0xe0|(scalar>>12)));out.push_back(static_cast<char>(0x80|((scalar>>6)&63)));out.push_back(static_cast<char>(0x80|(scalar&63)));
    } else {
        out.push_back(static_cast<char>(0xf0|(scalar>>18)));out.push_back(static_cast<char>(0x80|((scalar>>12)&63)));
        out.push_back(static_cast<char>(0x80|((scalar>>6)&63)));out.push_back(static_cast<char>(0x80|(scalar&63)));
    }
}
std::vector<ScanRange> ranges(const Image& image,std::stop_token stop) {
    std::vector<std::uint64_t> cuts{0,image.storage()->size()};
    for(const auto& segment:image.layout().segments) {
        check_stop(stop);
        if(segment.file_size){cuts.push_back(segment.file_begin.value);cuts.push_back(segment.file_begin.value+segment.file_size);}
    }
    std::sort(cuts.begin(),cuts.end());cuts.erase(std::unique(cuts.begin(),cuts.end()),cuts.end());
    std::vector<ScanRange> output;
    for(std::size_t n=1;n<cuts.size();++n) {
        check_stop(stop);
        const auto location=image.to_address({cuts[n-1]});
        std::optional<Address> address;if(location)address=location.value();
        const bool unmapped=!location && location.error().code==ErrorCode::out_of_bounds;
        bool merge=false;
        if(!output.empty()) {
            const auto& previous=output.back();
            if(previous.unmapped && unmapped)merge=true;
            else if(previous.address && address && previous.address->space==address->space) {
                const auto next=checked_add(previous.address->offset,previous.end-previous.begin);
                merge=next && next.value()==address->offset;
            }
        }
        if(merge)output.back().end=cuts[n];
        else output.push_back({cuts[n-1],cuts[n],address,unmapped});
    }
    return output;
}
struct Run {
    std::uint64_t begin=0,characters=0,length=0;bool non_ascii=false;
    std::string preview;
    void add(std::uint64_t offset,std::uint32_t scalar,unsigned bytes) {
        if(!characters)begin=offset;
        non_ascii=non_ascii || scalar>0x7f;
        if(characters<256)utf8(preview,scalar);
        ++characters;length+=bytes;
    }
};
void emit(Run& run,bool terminated,StringEncoding encoding,const ScanRange& range,const AnalysisOptions& options,StringScan& output,
          bool require_non_ascii=false) {
    if(run.characters>=options.min_string_characters && (!require_non_ascii || run.non_ascii)) {
        if(output.records.size()>=options.string_budget)throw BudgetEnd{};
        std::optional<Address> address;
        if(range.address)address=Address{range.address->space,range.address->offset+(run.begin-range.begin)};
        output.records.push_back({encoding,std::move(run.preview),run.characters,run.length,{run.begin},address,terminated});
    }
    run={};
}
bool printable(std::uint32_t scalar) {
    return scalar>=0x20 && !(scalar>=0x7f && scalar<=0x9f) && scalar<=0x10ffff &&
           !(scalar>=0xd800 && scalar<=0xdfff) && !(scalar>=0xfdd0 && scalar<=0xfdef) &&
           (scalar&0xffff)!=0xfffe && (scalar&0xffff)!=0xffff;
}
struct Utf8Unit { std::uint32_t scalar=0; unsigned length=0; };
Utf8Unit decode_utf8(Cursor& input,std::uint64_t at,std::uint64_t end) {
    const unsigned first=input.unit(at,1);
    if(first<0x80)return {first,1};
    unsigned length=0;std::uint32_t scalar=0,minimum=0;
    if(first>=0xc2 && first<=0xdf){length=2;scalar=first&0x1f;minimum=0x80;}
    else if(first>=0xe0 && first<=0xef){length=3;scalar=first&0x0f;minimum=0x800;}
    else if(first>=0xf0 && first<=0xf4){length=4;scalar=first&0x07;minimum=0x10000;}
    else return {};
    if(end-at<length)return {};
    for(unsigned i=1;i<length;++i) {
        const unsigned next=input.unit(at+i,1);
        if((next&0xc0)!=0x80)return {};
        scalar=(scalar<<6)|(next&0x3f);
    }
    if(scalar<minimum || scalar>0x10ffff || (scalar>=0xd800 && scalar<=0xdfff))return {};
    return {scalar,length};
}
std::optional<std::uint32_t> decode_windows1252(unsigned byte) {
    static constexpr std::uint16_t c1[32]={
        0x20ac,0,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,
        0x02c6,0x2030,0x0160,0x2039,0x0152,0,0x017d,0,
        0,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0x02dc,0x2122,0x0161,0x203a,0x0153,0,0x017e,0x0178};
    if(byte<0x80)return byte;
    if(byte>=0xa0)return byte;
    const auto scalar=c1[byte-0x80];
    if(!scalar)return {};
    return scalar;
}
std::optional<std::uint32_t> decode_windows1251(unsigned byte) {
    // Windows-1251 bytes 0x80..0xff, in code-page order. Zero entries are
    // undefined and therefore break a candidate rather than becoming text.
    static constexpr std::uint16_t high[128]={
        0x0402,0x0403,0x201a,0x0453,0x201e,0x2026,0x2020,0x2021,0x20ac,0x2030,0x0409,0x2039,0x040a,0x040c,0x040b,0x040f,
        0x0452,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0,0x2122,0x0459,0x203a,0x045a,0x045c,0x045b,0x045f,
        0x00a0,0x040e,0x045e,0x0408,0x00a4,0x0490,0x00a6,0x00a7,0x0401,0x00a9,0x0404,0x00ab,0x00ac,0x00ad,0x00ae,0x0407,
        0x00b0,0x00b1,0x0406,0x0456,0x0491,0x00b5,0x00b6,0x00b7,0x0451,0x2116,0x0454,0x00bb,0x0458,0x0405,0x0455,0x0457,
        0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,0x041a,0x041b,0x041c,0x041d,0x041e,0x041f,
        0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,0x042a,0x042b,0x042c,0x042d,0x042e,0x042f,
        0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,0x0438,0x0439,0x043a,0x043b,0x043c,0x043d,0x043e,0x043f,
        0x0440,0x0441,0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,0x0448,0x0449,0x044a,0x044b,0x044c,0x044d,0x044e,0x044f};
    if(byte<0x80)return byte;
    const auto scalar=high[byte-0x80];
    if(!scalar)return {};
    return scalar;
}
std::optional<std::uint32_t> decode_windows1250(unsigned byte) {
    // Windows-1250 bytes 0x80..0xff, in code-page order. Undefined positions
    // stay invalid so they break a candidate instead of becoming replacement text.
    static constexpr std::uint16_t high[128]={
        0x20ac,0,0x201a,0,0x201e,0x2026,0x2020,0x2021,0,0x2030,0x0160,0x2039,0x015a,0x0164,0x017d,0x0179,
        0,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0,0x2122,0x0161,0x203a,0x015b,0x0165,0x017e,0x017a,
        0x00a0,0x02c7,0x02d8,0x0141,0x00a4,0x0104,0x00a6,0x00a7,0x00a8,0x00a9,0x015e,0x00ab,0x00ac,0x00ad,0x00ae,0x017b,
        0x00b0,0x00b1,0x02db,0x0142,0x00b4,0x00b5,0x00b6,0x00b7,0x00b8,0x0105,0x015f,0x00bb,0x013d,0x02dd,0x013e,0x017c,
        0x0154,0x00c1,0x00c2,0x0102,0x00c4,0x0139,0x0106,0x00c7,0x010c,0x00c9,0x0118,0x00cb,0x011a,0x00cd,0x00ce,0x010e,
        0x0110,0x0143,0x0147,0x00d3,0x00d4,0x0150,0x00d6,0x00d7,0x0158,0x016e,0x00da,0x0170,0x00dc,0x00dd,0x0162,0x00df,
        0x0155,0x00e1,0x00e2,0x0103,0x00e4,0x013a,0x0107,0x00e7,0x010d,0x00e9,0x0119,0x00eb,0x011b,0x00ed,0x00ee,0x010f,
        0x0111,0x0144,0x0148,0x00f3,0x00f4,0x0151,0x00f6,0x00f7,0x0159,0x016f,0x00fa,0x0171,0x00fc,0x00fd,0x0163,0x02d9};
    if(byte<0x80)return byte;
    const auto scalar=high[byte-0x80];
    if(!scalar)return {};
    return scalar;
}
std::optional<std::uint32_t> decode_windows1254(unsigned byte) {
    // Windows-1254 follows the Windows-1252 layout with seven undefined C1
    // slots and Turkish replacements for dotted/dotless I and S-cedilla/G-breve.
    static constexpr std::uint16_t high[128]={
        0x20ac,0,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,0x02c6,0x2030,0x0160,0x2039,0x0152,0,0,0,
        0,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0x02dc,0x2122,0x0161,0x203a,0x0153,0,0,0x0178,
        0x00a0,0x00a1,0x00a2,0x00a3,0x00a4,0x00a5,0x00a6,0x00a7,0x00a8,0x00a9,0x00aa,0x00ab,0x00ac,0x00ad,0x00ae,0x00af,
        0x00b0,0x00b1,0x00b2,0x00b3,0x00b4,0x00b5,0x00b6,0x00b7,0x00b8,0x00b9,0x00ba,0x00bb,0x00bc,0x00bd,0x00be,0x00bf,
        0x00c0,0x00c1,0x00c2,0x00c3,0x00c4,0x00c5,0x00c6,0x00c7,0x00c8,0x00c9,0x00ca,0x00cb,0x00cc,0x00cd,0x00ce,0x00cf,
        0x011e,0x00d1,0x00d2,0x00d3,0x00d4,0x00d5,0x00d6,0x00d7,0x00d8,0x00d9,0x00da,0x00db,0x00dc,0x0130,0x015e,0x00df,
        0x00e0,0x00e1,0x00e2,0x00e3,0x00e4,0x00e5,0x00e6,0x00e7,0x00e8,0x00e9,0x00ea,0x00eb,0x00ec,0x00ed,0x00ee,0x00ef,
        0x011f,0x00f1,0x00f2,0x00f3,0x00f4,0x00f5,0x00f6,0x00f7,0x00f8,0x00f9,0x00fa,0x00fb,0x00fc,0x0131,0x015f,0x00ff};
    if(byte<0x80)return byte;
    const auto scalar=high[byte-0x80];
    if(!scalar)return {};
    return scalar;
}
std::optional<std::uint32_t> decode_windows1253(unsigned byte) {
    // Windows-1253 high-byte mapping; zero entries are undefined bytes.
    static constexpr std::uint16_t high[128]={
        0x20ac,0,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,0,0x2030,0,0x2039,0,0,0,0,
        0,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0,0x2122,0,0x203a,0,0,0,0,
        0x00a0,0x0385,0x0386,0x00a3,0x00a4,0x00a5,0x00a6,0x00a7,0x00a8,0x00a9,0,0x00ab,0x00ac,0x00ad,0x00ae,0x2015,
        0x00b0,0x00b1,0x00b2,0x00b3,0x0384,0x00b5,0x00b6,0x00b7,0x0388,0x0389,0x038a,0x00bb,0x038c,0x00bd,0x038e,0x038f,
        0x0390,0x0391,0x0392,0x0393,0x0394,0x0395,0x0396,0x0397,0x0398,0x0399,0x039a,0x039b,0x039c,0x039d,0x039e,0x039f,
        0x03a0,0x03a1,0,0x03a3,0x03a4,0x03a5,0x03a6,0x03a7,0x03a8,0x03a9,0x03aa,0x03ab,0x03ac,0x03ad,0x03ae,0x03af,
        0x03b0,0x03b1,0x03b2,0x03b3,0x03b4,0x03b5,0x03b6,0x03b7,0x03b8,0x03b9,0x03ba,0x03bb,0x03bc,0x03bd,0x03be,0x03bf,
        0x03c0,0x03c1,0x03c2,0x03c3,0x03c4,0x03c5,0x03c6,0x03c7,0x03c8,0x03c9,0x03ca,0x03cb,0x03cc,0x03cd,0x03ce,0};
    if(byte<0x80)return byte;
    const auto scalar=high[byte-0x80];
    if(!scalar)return {};
    return scalar;
}
std::optional<std::uint32_t> decode_windows1255(unsigned byte) {
    // Windows-1255 Hebrew mapping; zero entries are undefined bytes.
    static constexpr std::uint16_t high[128]={
        0x20ac,0,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,0x02c6,0x2030,0,0x2039,0,0,0,0,
        0,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,0x02dc,0x2122,0,0x203a,0,0,0,0,
        0x00a0,0x00a1,0x00a2,0x00a3,0x20aa,0x00a5,0x00a6,0x00a7,0x00a8,0x00a9,0x00d7,0x00ab,0x00ac,0x00ad,0x00ae,0x00af,
        0x00b0,0x00b1,0x00b2,0x00b3,0x00b4,0x00b5,0x00b6,0x00b7,0x00b8,0x00b9,0x00f7,0x00bb,0x00bc,0x00bd,0x00be,0x00bf,
        0x05b0,0x05b1,0x05b2,0x05b3,0x05b4,0x05b5,0x05b6,0x05b7,0x05b8,0x05b9,0,0x05bb,0x05bc,0x05bd,0x05be,0x05bf,
        0x05c0,0x05c1,0x05c2,0x05c3,0x05f0,0x05f1,0x05f2,0x05f3,0x05f4,0,0,0,0,0,0,0,
        0x05d0,0x05d1,0x05d2,0x05d3,0x05d4,0x05d5,0x05d6,0x05d7,0x05d8,0x05d9,0x05da,0x05db,0x05dc,0x05dd,0x05de,0x05df,
        0x05e0,0x05e1,0x05e2,0x05e3,0x05e4,0x05e5,0x05e6,0x05e7,0x05e8,0x05e9,0x05ea,0,0,0x200e,0x200f,0};
    if(byte<0x80)return byte;
    const auto scalar=high[byte-0x80];
    if(!scalar)return {};
    return scalar;
}
}
namespace {
Result<StringScan> scan_selected(const Image& image,const AnalysisOptions& options,
                                 std::span<const ScanRange> selected,std::stop_token stop) {
    StringScan output;
    std::size_t inspected=0;
    try {
        check_stop(stop);
        for(const auto& range:selected) {
            Cursor input(*image.storage(),range.end,inspected,options.string_scan_work_budget);Run run;
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value>=0x20 && value<=0x7e)run.add(at,value,1);
                else emit(run,value==0,StringEncoding::ascii,range,options,output);
            }
            emit(run,false,StringEncoding::ascii,range,options,output);
            // UTF-8 is recognized only when it contains a non-ASCII scalar;
            // otherwise the ASCII pass already represents the same bytes.
            run={};
            for(auto at=range.begin;at<range.end;) {
                if(((at-range.begin)&2047)==0)check_stop(stop);
                if(input.byte(at)==0) {emit(run,true,StringEncoding::utf8,range,options,output,true);++at;continue;}
                const auto decoded=decode_utf8(input,at,range.end);
                if(!decoded.length || !printable(decoded.scalar)) {emit(run,false,StringEncoding::utf8,range,options,output,true);++at;continue;}
                run.add(at,decoded.scalar,decoded.length);at+=decoded.length;
            }
            emit(run,false,StringEncoding::utf8,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1252,range,options,output,true);continue;}
                const auto scalar=decode_windows1252(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1252,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1252,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1251,range,options,output,true);continue;}
                const auto scalar=decode_windows1251(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1251,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1251,range,options,output,true);
            for(unsigned endian=0;endian<2;++endian)for(unsigned alignment=0;alignment<2;++alignment) {
                const bool big_endian=endian!=0;
                const auto encoding=big_endian?StringEncoding::utf16be:StringEncoding::utf16le;
                run={};auto at=range.begin+alignment;std::size_t steps=0;
                while(at<range.end && range.end-at>=2) {
                    if((steps++&2047)==0)check_stop(stop);
                    const auto first=input.unit(at,2,big_endian);
                    std::uint32_t scalar=first;unsigned length=2;bool valid=true;
                    if(first>=0xd800 && first<=0xdbff) {
                        if(range.end-at>=4) {
                            const auto low=input.unit(at+2,2,big_endian);
                            if(low>=0xdc00 && low<=0xdfff){scalar=0x10000+((first-0xd800)<<10)+(low-0xdc00);length=4;}
                            else valid=false;
                        } else valid=false;
                    } else if(first>=0xdc00 && first<=0xdfff)valid=false;
                    if(valid && printable(scalar))run.add(at,scalar,length);
                    else emit(run,valid && first==0,encoding,range,options,output);
                    at+=length;
                }
                emit(run,false,encoding,range,options,output);
            }
            for(unsigned endian=0;endian<2;++endian)for(unsigned alignment=0;alignment<4;++alignment) {
                const bool big_endian=endian!=0;
                const auto encoding=big_endian?StringEncoding::utf32be:StringEncoding::utf32le;
                run={};auto at=range.begin+alignment;std::size_t steps=0;
                while(at<range.end && range.end-at>=4) {
                    if((steps++&2047)==0)check_stop(stop);
                    const auto scalar=input.unit(at,4,big_endian);
                    if(scalar && printable(scalar))run.add(at,scalar,4);
                    else emit(run,scalar==0,encoding,range,options,output);
                    at+=4;
                }
                emit(run,false,encoding,range,options,output);
            }
            // Keep single-byte locale fallbacks after Unicode encodings so a
            // tight result budget cannot displace UTF-16/32 candidates.
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1250,range,options,output,true);continue;}
                const auto scalar=decode_windows1250(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1250,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1250,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1254,range,options,output,true);continue;}
                const auto scalar=decode_windows1254(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1254,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1254,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1253,range,options,output,true);continue;}
                const auto scalar=decode_windows1253(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1253,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1253,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1255,range,options,output,true);continue;}
                const auto scalar=decode_windows1255(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1255,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1255,range,options,output,true);
        }
    } catch(const BudgetEnd&) {
        output.complete=false;output.diagnostics.push_back({DiagnosticSeverity::warning,"String record budget reached",{}});
    } catch(const WorkBudgetEnd&) {
        output.complete=false;output.diagnostics.push_back({DiagnosticSeverity::warning,"String scan work budget reached; results are partial",{}});
    } catch(const ScanFailure& failure) {return failure.error;}
      catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate string results"};}
    return output;
}
}
Result<StringScan> find_strings(const Image& image,const AnalysisOptions& options,std::stop_token stop) {
    if(!options.min_string_characters)return Error{ErrorCode::invalid_argument,"Minimum string length must be positive"};
    try {
        const auto selected=ranges(image,stop);
        return scan_selected(image,options,selected,stop);
    } catch(const ScanFailure& failure) {return failure.error;}
      catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate string ranges"};}
}
Result<StringScan> refresh_strings(const Image& image,const AnalysisOptions& options,const StringScan& prior,
                                   const ReadSet& changes,std::stop_token stop) {
    if(!options.min_string_characters)return Error{ErrorCode::invalid_argument,"Minimum string length must be positive"};
    if(stop.stop_requested())return Error{ErrorCode::canceled,"String refresh canceled"};
    if(!prior.complete)return find_strings(image,options,stop);
    try {
        const auto domains=ranges(image,stop);
        std::vector<ScanRange> selected;
        std::vector<bool> replaced(domains.size(),false);
        for(auto changed:changes.ranges()) {
            if(stop.stop_requested())return Error{ErrorCode::canceled,"String refresh canceled"};
            if(!changed.size)continue;
            const auto changed_end=checked_add(changed.begin.value,changed.size);
            if(!changed_end)return changed_end.error();
            for(std::size_t i=0;i<domains.size();++i) {
                if(stop.stop_requested())return Error{ErrorCode::canceled,"String refresh canceled"};
                const auto& domain=domains[i];
                if(changed.begin.value<domain.end && domain.begin<changed_end.value())replaced[i]=true;
            }
        }
        for(std::size_t i=0;i<domains.size();++i)if(replaced[i])selected.push_back(domains[i]);
        if(selected.empty())return prior;
        auto rescanned=scan_selected(image,options,selected,stop);
        if(!rescanned)return rescanned.error();
        std::vector<std::vector<StringRecord>> prior_by_domain(domains.size());
        std::vector<std::vector<StringRecord>> rescanned_by_domain(domains.size());
        const auto domain_index=[&](std::uint64_t offset)->std::optional<std::size_t>{
            const auto found=std::upper_bound(domains.begin(),domains.end(),offset,
                [](std::uint64_t value,const ScanRange& domain){return value<domain.begin;});
            if(found==domains.begin())return {};
            const auto index=static_cast<std::size_t>(std::distance(domains.begin(),found)-1);
            return offset<domains[index].end?std::optional<std::size_t>{index}:std::nullopt;
        };
        for(const auto& record:prior.records) {
            if(stop.stop_requested())return Error{ErrorCode::canceled,"String refresh canceled"};
            const auto index=domain_index(record.file_offset.value);
            if(index && !replaced[*index])prior_by_domain[*index].push_back(record);
        }
        for(auto& record:rescanned.value().records) {
            if(stop.stop_requested())return Error{ErrorCode::canceled,"String refresh canceled"};
            const auto index=domain_index(record.file_offset.value);
            if(index && replaced[*index])rescanned_by_domain[*index].push_back(std::move(record));
        }
        StringScan output;
        output.complete=rescanned.value().complete;
        output.diagnostics=prior.diagnostics;
        output.diagnostics.insert(output.diagnostics.end(),rescanned.value().diagnostics.begin(),
                                  rescanned.value().diagnostics.end());
        for(std::size_t i=0;i<domains.size();++i) {
            if(stop.stop_requested())return Error{ErrorCode::canceled,"String refresh canceled"};
            auto& rows=replaced[i]?rescanned_by_domain[i]:prior_by_domain[i];
            output.records.insert(output.records.end(),rows.begin(),rows.end());
        }
        if(output.records.size()>options.string_budget) {
            output.records.resize(options.string_budget);
            output.complete=false;
            output.diagnostics.push_back({DiagnosticSeverity::warning,"String record budget reached",{}});
        }
        return output;
    } catch(const ScanFailure& failure) {return failure.error;}
      catch(const std::bad_alloc&) {return Error{ErrorCode::resource_limit,"Cannot allocate refreshed string results"};}
      catch(const std::length_error&) {return Error{ErrorCode::resource_limit,"Refreshed string results exceed container limits"};}
}
}
