#include "hexlab/analysis/strings.hpp"
#include "strings_internal.hpp"
#include <algorithm>
#include <array>
#include <iterator>
#include <vector>

namespace hexlab {
namespace {
#include "strings_cp932_table.inc"
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
        // Most decoded units fit inside the currently loaded 64 KiB window.
        // Read those bytes directly instead of repeating byte()'s window and
        // budget checks for each byte. Preserve byte-inspection accounting;
        // when the budget cannot cover the whole unit, retain byte()'s exact
        // partial-consumption behavior through the fallback below.
        if(width<=4 && at>=window_begin_) {
            const auto delta=at-window_begin_;
            if(delta<=window_.bytes.size()) {
                const auto offset=static_cast<std::size_t>(delta);
                if(width<=window_.bytes.size()-offset && inspected_<=work_budget_ &&
                   width<=work_budget_-inspected_) {
                    std::uint32_t value=0;
                    for(unsigned i=0;i<width;++i) {
                        const auto shift=big_endian ? (width-i-1)*8 : i*8;
                        value|=std::to_integer<unsigned>(window_.bytes[offset+i])<<shift;
                    }
                    inspected_+=width;
                    return value;
                }
            }
        }
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
std::optional<std::uint32_t> decode_windows932_single(unsigned byte) {
    if (byte < 0x80) return byte;
    if (byte >= 0x80 && byte <= 0xff) {
        const auto scalar = cp932_single_table[byte - 0x80];
        if (scalar) return scalar;
    }
    return {};
}
std::optional<std::uint32_t> decode_windows932_pair(unsigned lead, unsigned trail) {
    std::size_t lead_index = 0;
    if (lead >= 0x81 && lead <= 0x9f)
        lead_index = lead - 0x81;
    else if (lead >= 0xe0 && lead <= 0xfc)
        lead_index = 31 + lead - 0xe0;
    else
        return {};
    std::size_t trail_index = 0;
    if (trail >= 0x40 && trail <= 0x7e)
        trail_index = trail - 0x40;
    else if (trail >= 0x80 && trail <= 0xfc)
        trail_index = 63 + trail - 0x80;
    else
        return {};
    const auto scalar = cp932_pair_table[lead_index * 188 + trail_index];
    return scalar ? std::optional<std::uint32_t>{scalar} : std::nullopt;
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
std::optional<std::uint32_t> decode_windows1256(unsigned byte) {
    // Windows-1256 mapping from Unicode's historical Microsoft vendor table.
    static constexpr std::uint16_t high[128]={
        0x20ac,0x067e,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,
        0x02c6,0x2030,0x0679,0x2039,0x0152,0x0686,0x0698,0x0688,
        0x06af,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0x06a9,0x2122,0x0691,0x203a,0x0153,0x200c,0x200d,0x06ba,
        0x00a0,0x060c,0x00a2,0x00a3,0x00a4,0x00a5,0x00a6,0x00a7,
        0x00a8,0x00a9,0x06be,0x00ab,0x00ac,0x00ad,0x00ae,0x00af,
        0x00b0,0x00b1,0x00b2,0x00b3,0x00b4,0x00b5,0x00b6,0x00b7,
        0x00b8,0x00b9,0x061b,0x00bb,0x00bc,0x00bd,0x00be,0x061f,
        0x06c1,0x0621,0x0622,0x0623,0x0624,0x0625,0x0626,0x0627,
        0x0628,0x0629,0x062a,0x062b,0x062c,0x062d,0x062e,0x062f,
        0x0630,0x0631,0x0632,0x0633,0x0634,0x0635,0x0636,0x00d7,
        0x0637,0x0638,0x0639,0x063a,0x0640,0x0641,0x0642,0x0643,
        0x00e0,0x0644,0x00e2,0x0645,0x0646,0x0647,0x0648,0x00e7,
        0x00e8,0x00e9,0x00ea,0x00eb,0x0649,0x064a,0x00ee,0x00ef,
        0x064b,0x064c,0x064d,0x064e,0x00f4,0x064f,0x0650,0x00f7,
        0x0651,0x00f9,0x0652,0x00fb,0x00fc,0x200e,0x200f,0x06d2};
    if(byte<0x80)return byte;
    return high[byte-0x80];
}
std::optional<std::uint32_t> decode_windows1257(unsigned byte) {
    // Windows-1257 Baltic mapping; zero entries are undefined byte positions.
    static constexpr std::uint16_t high[128]={
        0x20ac,0,0x201a,0,0x201e,0x2026,0x2020,0x2021,
        0,0x2030,0,0x2039,0,0x00a8,0x02c7,0x00b8,
        0,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0,0x2122,0,0x203a,0,0x00af,0x02db,0,
        0x00a0,0,0x00a2,0x00a3,0x00a4,0,0x00a6,0x00a7,
        0x00d8,0x00a9,0x0156,0x00ab,0x00ac,0x00ad,0x00ae,0x00c6,
        0x00b0,0x00b1,0x00b2,0x00b3,0x00b4,0x00b5,0x00b6,0x00b7,
        0x00f8,0x00b9,0x0157,0x00bb,0x00bc,0x00bd,0x00be,0x00e6,
        0x0104,0x012e,0x0100,0x0106,0x00c4,0x00c5,0x0118,0x0112,
        0x010c,0x00c9,0x0179,0x0116,0x0122,0x0136,0x012a,0x013b,
        0x0160,0x0143,0x0145,0x00d3,0x014c,0x00d5,0x00d6,0x00d7,
        0x0172,0x0141,0x015a,0x016a,0x00dc,0x017b,0x017d,0x00df,
        0x0105,0x012f,0x0101,0x0107,0x00e4,0x00e5,0x0119,0x0113,
        0x010d,0x00e9,0x017a,0x0117,0x0123,0x0137,0x012b,0x013c,
        0x0161,0x0144,0x0146,0x00f3,0x014d,0x00f5,0x00f6,0x00f7,
        0x0173,0x0142,0x015b,0x016b,0x00fc,0x017c,0x017e,0x02d9};
    if(byte<0x80)return byte;
    const auto scalar=high[byte-0x80];
    if(!scalar)return {};
    return scalar;
}
std::optional<std::uint32_t> decode_windows1258(unsigned byte) {
    // Windows-1258 Vietnamese mapping from the Unicode Consortium's Microsoft table.
    // Zero entries are undefined positions; combining marks remain separate scalars.
    static constexpr std::uint16_t high[128]={
        0x20ac,0,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,
        0x02c6,0x2030,0,0x2039,0x0152,0,0,0,
        0,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0x02dc,0x2122,0,0x203a,0x0153,0,0,0,
        0x00a0,0x00a1,0x00a2,0x00a3,0x00a4,0x00a5,0x00a6,0x00a7,
        0x00a8,0x00a9,0x00aa,0x00ab,0x00ac,0x00ad,0x00ae,0x00af,
        0x00b0,0x00b1,0x00b2,0x00b3,0x00b4,0x00b5,0x00b6,0x00b7,
        0x00b8,0x00b9,0x00ba,0x00bb,0x00bc,0x00bd,0x00be,0x00bf,
        0x00c0,0x00c1,0x00c2,0x0102,0x00c4,0x00c5,0x00c6,0x00c7,
        0x00c8,0x00c9,0x00ca,0x00cb,0x0300,0x00cd,0x00ce,0x00cf,
        0x0110,0x00d1,0x0309,0x00d3,0x00d4,0x01a0,0x00d6,0x00d7,
        0x00d8,0x00d9,0x00da,0x00db,0x00dc,0x01af,0x0303,0x00df,
        0x00e0,0x00e1,0x00e2,0x0103,0x00e4,0x00e5,0x00e6,0x00e7,
        0x00e8,0x00e9,0x00ea,0x00eb,0x0301,0x00ed,0x00ee,0x00ef,
        0x0111,0x00f1,0x0323,0x00f3,0x00f4,0x01a1,0x00f6,0x00f7,
        0x00f8,0x00f9,0x00fa,0x00fb,0x00fc,0x01b0,0x20ab,0x00ff};
    if(byte<0x80)return byte;
    const auto scalar=high[byte-0x80];
    if(!scalar)return {};
    return scalar;
}
std::optional<std::uint32_t> decode_iso8859_2(unsigned byte) {
    // ISO/IEC 8859-2 (Latin-2) to Unicode, following the Unicode Consortium's
    // 8859-2.TXT mapping. C1 controls are represented but rejected by printable().
    static constexpr std::uint16_t high[128]={
        0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,
        0x0088,0x0089,0x008a,0x008b,0x008c,0x008d,0x008e,0x008f,
        0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,
        0x0098,0x0099,0x009a,0x009b,0x009c,0x009d,0x009e,0x009f,
        0x00a0,0x0104,0x02d8,0x0141,0x00a4,0x013d,0x015a,0x00a7,
        0x00a8,0x0160,0x015e,0x0164,0x0179,0x00ad,0x017d,0x017b,
        0x00b0,0x0105,0x02db,0x0142,0x00b4,0x013e,0x015b,0x02c7,
        0x00b8,0x0161,0x015f,0x0165,0x017a,0x02dd,0x017e,0x017c,
        0x0154,0x00c1,0x00c2,0x0102,0x00c4,0x0139,0x0106,0x00c7,
        0x010c,0x00c9,0x0118,0x00cb,0x011a,0x00cd,0x00ce,0x010e,
        0x0110,0x0143,0x0147,0x00d3,0x00d4,0x0150,0x00d6,0x00d7,
        0x0158,0x016e,0x00da,0x0170,0x00dc,0x00dd,0x0162,0x00df,
        0x0155,0x00e1,0x00e2,0x0103,0x00e4,0x013a,0x0107,0x00e7,
        0x010d,0x00e9,0x0119,0x00eb,0x011b,0x00ed,0x00ee,0x010f,
        0x0111,0x0144,0x0148,0x00f3,0x00f4,0x0151,0x00f6,0x00f7,
        0x0159,0x016f,0x00fa,0x0171,0x00fc,0x00fd,0x0163,0x02d9};
    if(byte<0x80)return byte;
    return high[byte-0x80];
}
std::optional<std::uint32_t> decode_iso8859_5(unsigned byte) {
    // ISO/IEC 8859-5:1999 to Unicode, following the Unicode Consortium's
    // 8859-5.TXT mapping. C1 controls are preserved and filtered by printable().
    if (byte < 0xa0) return byte;
    if (byte == 0xa0) return 0x00a0;
    if (byte <= 0xac) return 0x0401 + (byte - 0xa1);
    if (byte == 0xad) return 0x00ad;
    if (byte <= 0xef) return 0x040e + (byte - 0xae);
    if (byte == 0xf0) return 0x2116;
    if (byte <= 0xfc) return 0x0451 + (byte - 0xf1);
    if (byte == 0xfd) return 0x00a7;
    return 0x045e + (byte - 0xfe);
}
template <std::size_t N>
std::optional<std::uint32_t> decode_high_byte_table(unsigned byte, const std::uint16_t (&high)[N]) {
    if (byte < 0x80) return byte;
    const auto scalar = high[byte - 0x80];
    if (!scalar) return {};
    return scalar;
}
std::optional<std::uint32_t> decode_dos437(unsigned byte) {
    static constexpr std::uint16_t high[128]={
        0x00c7,0x00fc,0x00e9,0x00e2,0x00e4,0x00e0,0x00e5,0x00e7,
        0x00ea,0x00eb,0x00e8,0x00ef,0x00ee,0x00ec,0x00c4,0x00c5,
        0x00c9,0x00e6,0x00c6,0x00f4,0x00f6,0x00f2,0x00fb,0x00f9,
        0x00ff,0x00d6,0x00dc,0x00a2,0x00a3,0x00a5,0x20a7,0x0192,
        0x00e1,0x00ed,0x00f3,0x00fa,0x00f1,0x00d1,0x00aa,0x00ba,
        0x00bf,0x2310,0x00ac,0x00bd,0x00bc,0x00a1,0x00ab,0x00bb,
        0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,
        0x2555,0x2563,0x2551,0x2557,0x255d,0x255c,0x255b,0x2510,
        0x2514,0x2534,0x252c,0x251c,0x2500,0x253c,0x255e,0x255f,
        0x255a,0x2554,0x2569,0x2566,0x2560,0x2550,0x256c,0x2567,
        0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256b,
        0x256a,0x2518,0x250c,0x2588,0x2584,0x258c,0x2590,0x2580,
        0x03b1,0x00df,0x0393,0x03c0,0x03a3,0x03c3,0x00b5,0x03c4,
        0x03a6,0x0398,0x03a9,0x03b4,0x221e,0x03c6,0x03b5,0x2229,
        0x2261,0x00b1,0x2265,0x2264,0x2320,0x2321,0x00f7,0x2248,
        0x00b0,0x2219,0x00b7,0x221a,0x207f,0x00b2,0x25a0,0x00a0};
    return decode_high_byte_table(byte, high);
}
std::optional<std::uint32_t> decode_dos850(unsigned byte) {
    static constexpr std::uint16_t high[128]={
        0x00c7,0x00fc,0x00e9,0x00e2,0x00e4,0x00e0,0x00e5,0x00e7,
        0x00ea,0x00eb,0x00e8,0x00ef,0x00ee,0x00ec,0x00c4,0x00c5,
        0x00c9,0x00e6,0x00c6,0x00f4,0x00f6,0x00f2,0x00fb,0x00f9,
        0x00ff,0x00d6,0x00dc,0x00f8,0x00a3,0x00d8,0x00d7,0x0192,
        0x00e1,0x00ed,0x00f3,0x00fa,0x00f1,0x00d1,0x00aa,0x00ba,
        0x00bf,0x00ae,0x00ac,0x00bd,0x00bc,0x00a1,0x00ab,0x00bb,
        0x2591,0x2592,0x2593,0x2502,0x2524,0x00c1,0x00c2,0x00c0,
        0x00a9,0x2563,0x2551,0x2557,0x255d,0x00a2,0x00a5,0x2510,
        0x2514,0x2534,0x252c,0x251c,0x2500,0x253c,0x00e3,0x00c3,
        0x255a,0x2554,0x2569,0x2566,0x2560,0x2550,0x256c,0x00a4,
        0x00f0,0x00d0,0x00ca,0x00cb,0x00c8,0x0131,0x00cd,0x00ce,
        0x00cf,0x2518,0x250c,0x2588,0x2584,0x00a6,0x00cc,0x2580,
        0x00d3,0x00df,0x00d4,0x00d2,0x00f5,0x00d5,0x00b5,0x00fe,
        0x00de,0x00da,0x00db,0x00d9,0x00fd,0x00dd,0x00af,0x00b4,
        0x00ad,0x00b1,0x2017,0x00be,0x00b6,0x00a7,0x00f7,0x00b8,
        0x00b0,0x00a8,0x00b7,0x00b9,0x00b3,0x00b2,0x25a0,0x00a0};
    return decode_high_byte_table(byte, high);
}
std::optional<std::uint32_t> decode_dos866(unsigned byte) {
    // IBM PC code page 866, from the Unicode Consortium's Microsoft mapping.
    static constexpr std::uint16_t high[128]={
        0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,
        0x0418,0x0419,0x041a,0x041b,0x041c,0x041d,0x041e,0x041f,
        0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,
        0x0428,0x0429,0x042a,0x042b,0x042c,0x042d,0x042e,0x042f,
        0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,
        0x0438,0x0439,0x043a,0x043b,0x043c,0x043d,0x043e,0x043f,
        0x2591,0x2592,0x2593,0x2502,0x2524,0x2561,0x2562,0x2556,
        0x2555,0x2563,0x2551,0x2557,0x255d,0x255c,0x255b,0x2510,
        0x2514,0x2534,0x252c,0x251c,0x2500,0x253c,0x255e,0x255f,
        0x255a,0x2554,0x2569,0x2566,0x2560,0x2550,0x256c,0x2567,
        0x2568,0x2564,0x2565,0x2559,0x2558,0x2552,0x2553,0x256b,
        0x256a,0x2518,0x250c,0x2588,0x2584,0x258c,0x2590,0x2580,
        0x0440,0x0441,0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,
        0x0448,0x0449,0x044a,0x044b,0x044c,0x044d,0x044e,0x044f,
        0x0401,0x0451,0x0404,0x0454,0x0407,0x0457,0x040e,0x045e,
        0x00b0,0x2219,0x00b7,0x221a,0x2116,0x00a4,0x25a0,0x00a0};
    return decode_high_byte_table(byte, high);
}
std::optional<std::uint32_t> decode_dos852(unsigned byte) {
    // IBM PC code page 852, from the Unicode Consortium's Microsoft mapping.
    static constexpr std::uint16_t high[128]={
        0x00c7,0x00fc,0x00e9,0x00e2,0x00e4,0x016f,0x0107,0x00e7,
        0x0142,0x00eb,0x0150,0x0151,0x00ee,0x0179,0x00c4,0x0106,
        0x00c9,0x0139,0x013a,0x00f4,0x00f6,0x013d,0x013e,0x015a,
        0x015b,0x00d6,0x00dc,0x0164,0x0165,0x0141,0x00d7,0x010d,
        0x00e1,0x00ed,0x00f3,0x00fa,0x0104,0x0105,0x017d,0x017e,
        0x0118,0x0119,0x00ac,0x017a,0x010c,0x015f,0x00ab,0x00bb,
        0x2591,0x2592,0x2593,0x2502,0x2524,0x00c1,0x00c2,0x011a,
        0x015e,0x2563,0x2551,0x2557,0x255d,0x017b,0x017c,0x2510,
        0x2514,0x2534,0x252c,0x251c,0x2500,0x253c,0x0102,0x0103,
        0x255a,0x2554,0x2569,0x2566,0x2560,0x2550,0x256c,0x00a4,
        0x0111,0x0110,0x010e,0x00cb,0x010f,0x0147,0x00cd,0x00ce,
        0x011b,0x2518,0x250c,0x2588,0x2584,0x0162,0x016e,0x2580,
        0x00d3,0x00df,0x00d4,0x0143,0x0144,0x0148,0x0160,0x0161,
        0x0154,0x00da,0x0155,0x0170,0x00fd,0x00dd,0x0163,0x00b4,
        0x00ad,0x02dd,0x02db,0x02c7,0x02d8,0x00a7,0x00f7,0x00b8,
        0x00b0,0x00a8,0x02d9,0x0171,0x0158,0x0159,0x25a0,0x00a0};
    return decode_high_byte_table(byte, high);
}
std::optional<std::uint32_t> decode_koi8_r(unsigned byte) {
    // KOI8-R high-byte mapping, following RFC 1489 / Unicode's vendor mapping.
    static constexpr std::uint16_t high[128]={
        0x2500,0x2502,0x250c,0x2510,0x2514,0x2518,0x251c,0x2524,
        0x252c,0x2534,0x253c,0x2580,0x2584,0x2588,0x258c,0x2590,
        0x2591,0x2592,0x2593,0x2320,0x25a0,0x2219,0x221a,0x2248,
        0x2264,0x2265,0x00a0,0x2321,0x00b0,0x00b2,0x00b7,0x00f7,
        0x2550,0x2551,0x2552,0x0451,0x2553,0x2554,0x2555,0x2556,
        0x2557,0x2558,0x2559,0x255a,0x255b,0x255c,0x255d,0x255e,
        0x255f,0x2560,0x2561,0x0401,0x2562,0x2563,0x2564,0x2565,
        0x2566,0x2567,0x2568,0x2569,0x256a,0x256b,0x256c,0x00a9,
        0x044e,0x0430,0x0431,0x0446,0x0434,0x0435,0x0444,0x0433,
        0x0445,0x0438,0x0439,0x043a,0x043b,0x043c,0x043d,0x043e,
        0x043f,0x044f,0x0440,0x0441,0x0442,0x0443,0x0436,0x0432,
        0x044c,0x044b,0x0437,0x0448,0x044d,0x0449,0x0447,0x044a,
        0x042e,0x0410,0x0411,0x0426,0x0414,0x0415,0x0424,0x0413,
        0x0425,0x0418,0x0419,0x041a,0x041b,0x041c,0x041d,0x041e,
        0x041f,0x042f,0x0420,0x0421,0x0422,0x0423,0x0416,0x0412,
        0x042c,0x042b,0x0417,0x0428,0x042d,0x0429,0x0427,0x042a};
    return decode_high_byte_table(byte, high);
}
std::optional<std::uint32_t> decode_koi8_u(unsigned byte) {
    // KOI8-U (RFC 2319) Unicode Consortium mapping; four Ukrainian letters
    // replace eight box-drawing positions in the KOI8-R high-byte repertoire.
    static constexpr std::uint16_t high[128]={
        0x2500,0x2502,0x250c,0x2510,0x2514,0x2518,0x251c,0x2524,
        0x252c,0x2534,0x253c,0x2580,0x2584,0x2588,0x258c,0x2590,
        0x2591,0x2592,0x2593,0x2320,0x25a0,0x2219,0x221a,0x2248,
        0x2264,0x2265,0x00a0,0x2321,0x00b0,0x00b2,0x00b7,0x00f7,
        0x2550,0x2551,0x2552,0x0451,0x0454,0x2554,0x0456,0x0457,
        0x2557,0x2558,0x2559,0x255a,0x255b,0x0491,0x255d,0x255e,
        0x255f,0x2560,0x2561,0x0401,0x0404,0x2563,0x0406,0x0407,
        0x2566,0x2567,0x2568,0x2569,0x256a,0x0490,0x256c,0x00a9,
        0x044e,0x0430,0x0431,0x0446,0x0434,0x0435,0x0444,0x0433,
        0x0445,0x0438,0x0439,0x043a,0x043b,0x043c,0x043d,0x043e,
        0x043f,0x044f,0x0440,0x0441,0x0442,0x0443,0x0436,0x0432,
        0x044c,0x044b,0x0437,0x0448,0x044d,0x0449,0x0447,0x044a,
        0x042e,0x0410,0x0411,0x0426,0x0414,0x0415,0x0424,0x0413,
        0x0425,0x0418,0x0419,0x041a,0x041b,0x041c,0x041d,0x041e,
        0x041f,0x042f,0x0420,0x0421,0x0422,0x0423,0x0416,0x0412,
        0x042c,0x042b,0x0417,0x0428,0x042d,0x0429,0x0427,0x042a};
    return byte < 0x80 ? std::optional<std::uint32_t>{byte} : decode_high_byte_table(byte, high);
}
std::optional<std::uint32_t> decode_iso8859_15(unsigned byte) {
    static constexpr std::uint16_t high[128]={
        0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,
        0x0088,0x0089,0x008a,0x008b,0x008c,0x008d,0x008e,0x008f,
        0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,
        0x0098,0x0099,0x009a,0x009b,0x009c,0x009d,0x009e,0x009f,
        0x00a0,0x00a1,0x00a2,0x00a3,0x20ac,0x00a5,0x0160,0x00a7,
        0x0161,0x00a9,0x00aa,0x00ab,0x00ac,0x00ad,0x00ae,0x00af,
        0x00b0,0x00b1,0x00b2,0x00b3,0x017d,0x00b5,0x00b6,0x00b7,
        0x017e,0x00b9,0x00ba,0x00bb,0x0152,0x0153,0x0178,0x00bf,
        0x00c0,0x00c1,0x00c2,0x00c3,0x00c4,0x00c5,0x00c6,0x00c7,
        0x00c8,0x00c9,0x00ca,0x00cb,0x00cc,0x00cd,0x00ce,0x00cf,
        0x00d0,0x00d1,0x00d2,0x00d3,0x00d4,0x00d5,0x00d6,0x00d7,
        0x00d8,0x00d9,0x00da,0x00db,0x00dc,0x00dd,0x00de,0x00df,
        0x00e0,0x00e1,0x00e2,0x00e3,0x00e4,0x00e5,0x00e6,0x00e7,
        0x00e8,0x00e9,0x00ea,0x00eb,0x00ec,0x00ed,0x00ee,0x00ef,
        0x00f0,0x00f1,0x00f2,0x00f3,0x00f4,0x00f5,0x00f6,0x00f7,
        0x00f8,0x00f9,0x00fa,0x00fb,0x00fc,0x00fd,0x00fe,0x00ff};
    return decode_high_byte_table(byte, high);
}
std::optional<std::uint32_t> decode_iso8859_9(unsigned byte) {
    // ISO/IEC 8859-9 is Latin-1 with six Turkish-letter replacements.
    // C1 bytes map to controls and are split by printable().
    switch (byte) {
    case 0xd0: return 0x011e; // capital G with breve
    case 0xdd: return 0x0130; // capital I with dot above
    case 0xde: return 0x015e; // capital S with cedilla
    case 0xf0: return 0x011f; // small g with breve
    case 0xfd: return 0x0131; // small dotless i
    case 0xfe: return 0x015f; // small s with cedilla
    default: return byte;
    }
}
std::optional<std::uint32_t> decode_iso8859_1(unsigned byte) {
    // ISO-8859-1 maps each byte to the same-numbered Unicode scalar. C0/C1
    // controls are split by the shared printable-scalar filter.
    return byte;
}
std::optional<std::uint32_t> decode_iso8859_3(unsigned byte) {
    // ISO-8859-3 retains Latin-1 positions except for its Latin-3 letters and
    // seven undefined slots. C0/C1 control bytes pass through and are split
    // by the shared printable-scalar filter.
    switch (byte) {
    case 0xa1: return 0x0126; case 0xa2: return 0x02d8;
    case 0xa6: return 0x0124; case 0xa9: return 0x0130;
    case 0xaa: return 0x015e; case 0xab: return 0x011e;
    case 0xac: return 0x0134; case 0xaf: return 0x017b;
    case 0xb1: return 0x0127; case 0xb6: return 0x0125;
    case 0xb9: return 0x0131; case 0xba: return 0x015f;
    case 0xbb: return 0x011f; case 0xbc: return 0x0135;
    case 0xbf: return 0x017c; case 0xc5: return 0x010a;
    case 0xc6: return 0x0108; case 0xd5: return 0x0120;
    case 0xd8: return 0x011c; case 0xdd: return 0x016c;
    case 0xde: return 0x015c; case 0xe5: return 0x010b;
    case 0xe6: return 0x0109; case 0xf5: return 0x0121;
    case 0xf8: return 0x011d; case 0xfd: return 0x016d;
    case 0xfe: return 0x015d; case 0xff: return 0x02d9;
    case 0xa5: case 0xae: case 0xbe: case 0xc4: case 0xd0: case 0xe3: case 0xf0:
        return {};
    default: return byte;
    }
}
std::optional<std::uint32_t> decode_iso8859_4(unsigned byte) {
    // ISO-8859-4 (Latin-4) is a complete single-byte table, mostly matching
    // Latin-1 with Baltic/Nordic letter substitutions.
    switch (byte) {
    case 0xa1: return 0x0104; case 0xa2: return 0x0138; case 0xa3: return 0x0156;
    case 0xa5: return 0x0128; case 0xa6: return 0x013b; case 0xa9: return 0x0160;
    case 0xaa: return 0x0112; case 0xab: return 0x0122; case 0xac: return 0x0166;
    case 0xae: return 0x017d; case 0xb1: return 0x0105; case 0xb2: return 0x02db;
    case 0xb3: return 0x0157; case 0xb5: return 0x0129; case 0xb6: return 0x013c;
    case 0xb7: return 0x02c7; case 0xb9: return 0x0161; case 0xba: return 0x0113;
    case 0xbb: return 0x0123; case 0xbc: return 0x0167; case 0xbd: return 0x014a;
    case 0xbe: return 0x017e; case 0xbf: return 0x014b; case 0xc0: return 0x0100;
    case 0xc7: return 0x012e; case 0xc8: return 0x010c; case 0xca: return 0x0118;
    case 0xcc: return 0x0116; case 0xcf: return 0x012a; case 0xd0: return 0x0110;
    case 0xd1: return 0x0145; case 0xd2: return 0x014c; case 0xd3: return 0x0136;
    case 0xd9: return 0x0172; case 0xdd: return 0x0168; case 0xde: return 0x016a;
    case 0xe0: return 0x0101; case 0xe7: return 0x012f; case 0xe8: return 0x010d;
    case 0xea: return 0x0119; case 0xec: return 0x0117; case 0xef: return 0x012b;
    case 0xf0: return 0x0111; case 0xf1: return 0x0146; case 0xf2: return 0x014d;
    case 0xf3: return 0x0137; case 0xf9: return 0x0173; case 0xfd: return 0x0169;
    case 0xfe: return 0x016b; case 0xff: return 0x02d9;
    default: return byte;
    }
}
std::optional<std::uint32_t> decode_iso8859_6(unsigned byte) {
    // ISO/IEC 8859-6:1999 Arabic mapping. Unassigned positions are undefined.
    if(byte<0xa0)return byte;
    switch(byte) {
    case 0xa0:return 0x00a0; case 0xa4:return 0x00a4; case 0xac:return 0x060c;
    case 0xad:return 0x00ad; case 0xbb:return 0x061b; case 0xbf:return 0x061f;
    case 0xc1:return 0x0621; case 0xc2:return 0x0622; case 0xc3:return 0x0623;
    case 0xc4:return 0x0624; case 0xc5:return 0x0625; case 0xc6:return 0x0626;
    case 0xc7:return 0x0627; case 0xc8:return 0x0628; case 0xc9:return 0x0629;
    case 0xca:return 0x062a; case 0xcb:return 0x062b; case 0xcc:return 0x062c;
    case 0xcd:return 0x062d; case 0xce:return 0x062e; case 0xcf:return 0x062f;
    case 0xd0:return 0x0630; case 0xd1:return 0x0631; case 0xd2:return 0x0632;
    case 0xd3:return 0x0633; case 0xd4:return 0x0634; case 0xd5:return 0x0635;
    case 0xd6:return 0x0636; case 0xd7:return 0x0637; case 0xd8:return 0x0638;
    case 0xd9:return 0x0639; case 0xda:return 0x063a; case 0xe0:return 0x0640;
    case 0xe1:return 0x0641; case 0xe2:return 0x0642; case 0xe3:return 0x0643;
    case 0xe4:return 0x0644; case 0xe5:return 0x0645; case 0xe6:return 0x0646;
    case 0xe7:return 0x0647; case 0xe8:return 0x0648; case 0xe9:return 0x0649;
    case 0xea:return 0x064a; case 0xeb:return 0x064b; case 0xec:return 0x064c;
    case 0xed:return 0x064d; case 0xee:return 0x064e; case 0xef:return 0x064f;
    case 0xf0:return 0x0650; case 0xf1:return 0x0651; case 0xf2:return 0x0652;
    default:return {};
    }
}
std::optional<std::uint32_t> decode_iso8859_7(unsigned byte) {
    // ISO/IEC 8859-7:2003 Greek mapping. Zero entries are undefined positions.
    static constexpr std::uint16_t high[128]={
        0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,
        0x0088,0x0089,0x008a,0x008b,0x008c,0x008d,0x008e,0x008f,
        0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,
        0x0098,0x0099,0x009a,0x009b,0x009c,0x009d,0x009e,0x009f,
        0x00a0,0x2018,0x2019,0x00a3,0x20ac,0x20af,0x00a6,0x00a7,
        0x00a8,0x00a9,0x037a,0x00ab,0x00ac,0x00ad,0x0000,0x2015,
        0x00b0,0x00b1,0x00b2,0x00b3,0x0384,0x0385,0x0386,0x00b7,
        0x0388,0x0389,0x038a,0x00bb,0x038c,0x00bd,0x038e,0x038f,
        0x0390,0x0391,0x0392,0x0393,0x0394,0x0395,0x0396,0x0397,
        0x0398,0x0399,0x039a,0x039b,0x039c,0x039d,0x039e,0x039f,
        0x03a0,0x03a1,0x0000,0x03a3,0x03a4,0x03a5,0x03a6,0x03a7,
        0x03a8,0x03a9,0x03aa,0x03ab,0x03ac,0x03ad,0x03ae,0x03af,
        0x03b0,0x03b1,0x03b2,0x03b3,0x03b4,0x03b5,0x03b6,0x03b7,
        0x03b8,0x03b9,0x03ba,0x03bb,0x03bc,0x03bd,0x03be,0x03bf,
        0x03c0,0x03c1,0x03c2,0x03c3,0x03c4,0x03c5,0x03c6,0x03c7,
        0x03c8,0x03c9,0x03ca,0x03cb,0x03cc,0x03cd,0x03ce,0x0000};
    return decode_high_byte_table(byte,high);
}
std::optional<std::uint32_t> decode_iso8859_8(unsigned byte) {
    // ISO/IEC 8859-8:1999 Hebrew mapping. Unassigned bytes are undefined.
    if(byte<0xa0)return byte;
    if(byte>=0xe0 && byte<=0xfa)return 0x05d0+(byte-0xe0);
    switch(byte){
    case 0xa0:return 0x00a0; case 0xa2:return 0x00a2; case 0xa3:return 0x00a3;
    case 0xa4:return 0x00a4; case 0xa5:return 0x00a5; case 0xa6:return 0x00a6;
    case 0xa7:return 0x00a7; case 0xa8:return 0x00a8; case 0xa9:return 0x00a9;
    case 0xaa:return 0x00d7; case 0xab:return 0x00ab; case 0xac:return 0x00ac;
    case 0xad:return 0x00ad; case 0xae:return 0x00ae; case 0xaf:return 0x00af;
    case 0xb0:return 0x00b0; case 0xb1:return 0x00b1; case 0xb2:return 0x00b2;
    case 0xb3:return 0x00b3; case 0xb4:return 0x00b4; case 0xb5:return 0x00b5;
    case 0xb6:return 0x00b6; case 0xb7:return 0x00b7; case 0xb8:return 0x00b8;
    case 0xb9:return 0x00b9; case 0xba:return 0x00f7; case 0xbb:return 0x00bb;
    case 0xbc:return 0x00bc; case 0xbd:return 0x00bd; case 0xbe:return 0x00be;
    case 0xdf:return 0x2017; case 0xfd:return 0x200e; case 0xfe:return 0x200f;
    default:return {};
    }
}
std::optional<std::uint32_t> decode_iso8859_11(unsigned byte) {
    // ISO/IEC 8859-11:2001 is TIS 620-2533 plus NO-BREAK SPACE at 0xa0.
    // The Thai block is contiguous except for the four reserved bytes 0xdb-0xde.
    if (byte < 0xa0) return byte;
    if (byte == 0xa0) return 0x00a0;
    if (byte >= 0xa1 && byte <= 0xda) return 0x0e01 + (byte - 0xa1);
    if (byte >= 0xdf && byte <= 0xfb) return 0x0e3f + (byte - 0xdf);
    return {};
}
std::optional<std::uint32_t> decode_windows874(unsigned byte) {
    // Microsoft CP874 keeps the Thai assignments used by ISO-8859-11 but
    // replaces selected C1 slots with Windows punctuation and leaves the
    // remaining C1/reserved positions undefined.
    if (byte < 0x80) return byte;
    if (byte >= 0xa1 && byte <= 0xda) return 0x0e01 + (byte - 0xa1);
    if (byte >= 0xe0 && byte <= 0xfb) return 0x0e40 + (byte - 0xe0);
    switch (byte) {
    case 0x80: return 0x20ac;
    case 0x85: return 0x2026;
    case 0x91: return 0x2018;
    case 0x92: return 0x2019;
    case 0x93: return 0x201c;
    case 0x94: return 0x201d;
    case 0x95: return 0x2022;
    case 0x96: return 0x2013;
    case 0x97: return 0x2014;
    case 0xa0: return 0x00a0;
    case 0xdf: return 0x0e3f;
    default: return {};
    }
}
std::optional<std::uint32_t> decode_iso8859_10(unsigned byte) {
    // ISO/IEC 8859-10 mapping; zero marks an undefined byte if present.
    static constexpr std::uint16_t high[128]={
        0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
        0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,
        0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
        0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
        0x00a0, 0x0104, 0x0112, 0x0122, 0x012a, 0x0128, 0x0136, 0x00a7,
        0x013b, 0x0110, 0x0160, 0x0166, 0x017d, 0x00ad, 0x016a, 0x014a,
        0x00b0, 0x0105, 0x0113, 0x0123, 0x012b, 0x0129, 0x0137, 0x00b7,
        0x013c, 0x0111, 0x0161, 0x0167, 0x017e, 0x2015, 0x016b, 0x014b,
        0x0100, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x012e,
        0x010c, 0x00c9, 0x0118, 0x00cb, 0x0116, 0x00cd, 0x00ce, 0x00cf,
        0x00d0, 0x0145, 0x014c, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x0168,
        0x00d8, 0x0172, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
        0x0101, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x012f,
        0x010d, 0x00e9, 0x0119, 0x00eb, 0x0117, 0x00ed, 0x00ee, 0x00ef,
        0x00f0, 0x0146, 0x014d, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x0169,
        0x00f8, 0x0173, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x0138,
    };
    return decode_high_byte_table(byte,high);
}

std::optional<std::uint32_t> decode_iso8859_13(unsigned byte) {
    // ISO/IEC 8859-13 mapping; zero marks an undefined byte if present.
    static constexpr std::uint16_t high[128]={
        0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
        0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,
        0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
        0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
        0x00a0, 0x201d, 0x00a2, 0x00a3, 0x00a4, 0x201e, 0x00a6, 0x00a7,
        0x00d8, 0x00a9, 0x0156, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00c6,
        0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x201c, 0x00b5, 0x00b6, 0x00b7,
        0x00f8, 0x00b9, 0x0157, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00e6,
        0x0104, 0x012e, 0x0100, 0x0106, 0x00c4, 0x00c5, 0x0118, 0x0112,
        0x010c, 0x00c9, 0x0179, 0x0116, 0x0122, 0x0136, 0x012a, 0x013b,
        0x0160, 0x0143, 0x0145, 0x00d3, 0x014c, 0x00d5, 0x00d6, 0x00d7,
        0x0172, 0x0141, 0x015a, 0x016a, 0x00dc, 0x017b, 0x017d, 0x00df,
        0x0105, 0x012f, 0x0101, 0x0107, 0x00e4, 0x00e5, 0x0119, 0x0113,
        0x010d, 0x00e9, 0x017a, 0x0117, 0x0123, 0x0137, 0x012b, 0x013c,
        0x0161, 0x0144, 0x0146, 0x00f3, 0x014d, 0x00f5, 0x00f6, 0x00f7,
        0x0173, 0x0142, 0x015b, 0x016b, 0x00fc, 0x017c, 0x017e, 0x2019,
    };
    return decode_high_byte_table(byte,high);
}

std::optional<std::uint32_t> decode_iso8859_14(unsigned byte) {
    // ISO/IEC 8859-14 mapping; zero marks an undefined byte if present.
    static constexpr std::uint16_t high[128]={
        0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
        0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,
        0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
        0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
        0x00a0, 0x1e02, 0x1e03, 0x00a3, 0x010a, 0x010b, 0x1e0a, 0x00a7,
        0x1e80, 0x00a9, 0x1e82, 0x1e0b, 0x1ef2, 0x00ad, 0x00ae, 0x0178,
        0x1e1e, 0x1e1f, 0x0120, 0x0121, 0x1e40, 0x1e41, 0x00b6, 0x1e56,
        0x1e81, 0x1e57, 0x1e83, 0x1e60, 0x1ef3, 0x1e84, 0x1e85, 0x1e61,
        0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
        0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,
        0x0174, 0x00d1, 0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x1e6a,
        0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x0176, 0x00df,
        0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7,
        0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
        0x0175, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x1e6b,
        0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x0177, 0x00ff,
    };
    return decode_high_byte_table(byte,high);
}

std::optional<std::uint32_t> decode_iso8859_16(unsigned byte) {
    // ISO/IEC 8859-16 mapping; zero marks an undefined byte if present.
    static constexpr std::uint16_t high[128]={
        0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
        0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x008d, 0x008e, 0x008f,
        0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
        0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
        0x00a0, 0x0104, 0x0105, 0x0141, 0x20ac, 0x201e, 0x0160, 0x00a7,
        0x0161, 0x00a9, 0x0218, 0x00ab, 0x0179, 0x00ad, 0x017a, 0x017b,
        0x00b0, 0x00b1, 0x010c, 0x0142, 0x017d, 0x201d, 0x00b6, 0x00b7,
        0x017e, 0x010d, 0x0219, 0x00bb, 0x0152, 0x0153, 0x0178, 0x017c,
        0x00c0, 0x00c1, 0x00c2, 0x0102, 0x00c4, 0x0106, 0x00c6, 0x00c7,
        0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf,
        0x0110, 0x0143, 0x00d2, 0x00d3, 0x00d4, 0x0150, 0x00d6, 0x015a,
        0x0170, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x0118, 0x021a, 0x00df,
        0x00e0, 0x00e1, 0x00e2, 0x0103, 0x00e4, 0x0107, 0x00e6, 0x00e7,
        0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
        0x0111, 0x0144, 0x00f2, 0x00f3, 0x00f4, 0x0151, 0x00f6, 0x015b,
        0x0171, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x0119, 0x021b, 0x00ff,
    };
    return decode_high_byte_table(byte,high);
}
std::optional<std::uint32_t> decode_mac_roman(unsigned byte) {
    static constexpr std::uint16_t high[128]={
        0x00c4,0x00c5,0x00c7,0x00c9,0x00d1,0x00d6,0x00dc,0x00e1,
        0x00e0,0x00e2,0x00e4,0x00e3,0x00e5,0x00e7,0x00e9,0x00e8,
        0x00ea,0x00eb,0x00ed,0x00ec,0x00ee,0x00ef,0x00f1,0x00f3,
        0x00f2,0x00f4,0x00f6,0x00f5,0x00fa,0x00f9,0x00fb,0x00fc,
        0x2020,0x00b0,0x00a2,0x00a3,0x00a7,0x2022,0x00b6,0x00df,
        0x00ae,0x00a9,0x2122,0x00b4,0x00a8,0x2260,0x00c6,0x00d8,
        0x221e,0x00b1,0x2264,0x2265,0x00a5,0x00b5,0x2202,0x2211,
        0x220f,0x03c0,0x222b,0x00aa,0x00ba,0x03a9,0x00e6,0x00f8,
        0x00bf,0x00a1,0x00ac,0x221a,0x0192,0x2248,0x2206,0x00ab,
        0x00bb,0x2026,0x00a0,0x00c0,0x00c3,0x00d5,0x0152,0x0153,
        0x2013,0x2014,0x201c,0x201d,0x2018,0x2019,0x00f7,0x25ca,
        0x00ff,0x0178,0x2044,0x20ac,0x2039,0x203a,0xfb01,0xfb02,
        0x2021,0x00b7,0x201a,0x201e,0x2030,0x00c2,0x00ca,0x00c1,
        0x00cb,0x00c8,0x00cd,0x00ce,0x00cf,0x00cc,0x00d3,0x00d4,
        0xf8ff,0x00d2,0x00da,0x00db,0x00d9,0x0131,0x02c6,0x02dc,
        0x00af,0x02d8,0x02d9,0x02da,0x00b8,0x02dd,0x02db,0x02c7
    };
    if(byte<0x80)return byte;
    return high[byte-0x80];
}
std::optional<std::uint32_t> decode_mac_cyrillic(unsigned byte) {
    // Mac OS Cyrillic, post-9.0 Euro-sign variant, from Apple's Unicode
    // Consortium vendor mapping. The low ASCII range is shared with Mac Roman.
    static constexpr std::uint16_t high[128]={
        0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,
        0x0418,0x0419,0x041a,0x041b,0x041c,0x041d,0x041e,0x041f,
        0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,
        0x0428,0x0429,0x042a,0x042b,0x042c,0x042d,0x042e,0x042f,
        0x2020,0x00b0,0x0490,0x00a3,0x00a7,0x2022,0x00b6,0x0406,
        0x00ae,0x00a9,0x2122,0x0402,0x0452,0x2260,0x0403,0x0453,
        0x221e,0x00b1,0x2264,0x2265,0x0456,0x00b5,0x0491,0x0408,
        0x0404,0x0454,0x0407,0x0457,0x0409,0x0459,0x040a,0x045a,
        0x0458,0x0405,0x00ac,0x221a,0x0192,0x2248,0x2206,0x00ab,
        0x00bb,0x2026,0x00a0,0x040b,0x045b,0x040c,0x045c,0x0455,
        0x2013,0x2014,0x201c,0x201d,0x2018,0x2019,0x00f7,0x201e,
        0x040e,0x045e,0x040f,0x045f,0x2116,0x0401,0x0451,0x044f,
        0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,
        0x0438,0x0439,0x043a,0x043b,0x043c,0x043d,0x043e,0x043f,
        0x0440,0x0441,0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,
        0x0448,0x0449,0x044a,0x044b,0x044c,0x044d,0x044e,0x20ac};
    return decode_high_byte_table(byte,high);
}
std::optional<std::uint32_t> decode_ebcdic_cp037(unsigned byte) {
    // IBM US/Canada EBCDIC CP037 mapping from the Unicode Consortium table.
    static constexpr std::uint16_t values[256]={
        0x0000,0x0001,0x0002,0x0003,0x009c,0x0009,0x0086,0x007f,
        0x0097,0x008d,0x008e,0x000b,0x000c,0x000d,0x000e,0x000f,
        0x0010,0x0011,0x0012,0x0013,0x009d,0x0085,0x0008,0x0087,
        0x0018,0x0019,0x0092,0x008f,0x001c,0x001d,0x001e,0x001f,
        0x0080,0x0081,0x0082,0x0083,0x0084,0x000a,0x0017,0x001b,
        0x0088,0x0089,0x008a,0x008b,0x008c,0x0005,0x0006,0x0007,
        0x0090,0x0091,0x0016,0x0093,0x0094,0x0095,0x0096,0x0004,
        0x0098,0x0099,0x009a,0x009b,0x0014,0x0015,0x009e,0x001a,
        0x0020,0x00a0,0x00e2,0x00e4,0x00e0,0x00e1,0x00e3,0x00e5,
        0x00e7,0x00f1,0x00a2,0x002e,0x003c,0x0028,0x002b,0x007c,
        0x0026,0x00e9,0x00ea,0x00eb,0x00e8,0x00ed,0x00ee,0x00ef,
        0x00ec,0x00df,0x0021,0x0024,0x002a,0x0029,0x003b,0x00ac,
        0x002d,0x002f,0x00c2,0x00c4,0x00c0,0x00c1,0x00c3,0x00c5,
        0x00c7,0x00d1,0x00a6,0x002c,0x0025,0x005f,0x003e,0x003f,
        0x00f8,0x00c9,0x00ca,0x00cb,0x00c8,0x00cd,0x00ce,0x00cf,
        0x00cc,0x0060,0x003a,0x0023,0x0040,0x0027,0x003d,0x0022,
        0x00d8,0x0061,0x0062,0x0063,0x0064,0x0065,0x0066,0x0067,
        0x0068,0x0069,0x00ab,0x00bb,0x00f0,0x00fd,0x00fe,0x00b1,
        0x00b0,0x006a,0x006b,0x006c,0x006d,0x006e,0x006f,0x0070,
        0x0071,0x0072,0x00aa,0x00ba,0x00e6,0x00b8,0x00c6,0x00a4,
        0x00b5,0x007e,0x0073,0x0074,0x0075,0x0076,0x0077,0x0078,
        0x0079,0x007a,0x00a1,0x00bf,0x00d0,0x00dd,0x00de,0x00ae,
        0x005e,0x00a3,0x00a5,0x00b7,0x00a9,0x00a7,0x00b6,0x00bc,
        0x00bd,0x00be,0x005b,0x005d,0x00af,0x00a8,0x00b4,0x00d7,
        0x007b,0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,
        0x0048,0x0049,0x00ad,0x00f4,0x00f6,0x00f2,0x00f3,0x00f5,
        0x007d,0x004a,0x004b,0x004c,0x004d,0x004e,0x004f,0x0050,
        0x0051,0x0052,0x00b9,0x00fb,0x00fc,0x00f9,0x00fa,0x00ff,
        0x005c,0x00f7,0x0053,0x0054,0x0055,0x0056,0x0057,0x0058,
        0x0059,0x005a,0x00b2,0x00d4,0x00d6,0x00d2,0x00d3,0x00d5,
        0x0030,0x0031,0x0032,0x0033,0x0034,0x0035,0x0036,0x0037,
        0x0038,0x0039,0x00b3,0x00db,0x00dc,0x00d9,0x00da,0x009f
    };
    return byte < 256 ? std::optional<std::uint32_t>{values[byte]} : std::nullopt;
}
std::optional<std::uint32_t> decode_ebcdic_cp1140(unsigned byte) {
    // IBM CP1140 is the Euro update of CP037: byte 0x9F replaces U+00A4
    // INTERNATIONAL CURRENCY SIGN with U+20AC EURO SIGN.
    if (byte == 0x9f) return 0x20ac;
    return decode_ebcdic_cp037(byte);
}
std::optional<std::uint32_t> decode_ebcdic_cp500(unsigned byte) {
    // CP500 shares most of the IBM EBCDIC repertoire with CP037. These seven
    // punctuation positions differ in the Unicode Consortium mappings.
    static constexpr std::array<std::uint16_t, 7> bytes{0x4a, 0x4f, 0x5a, 0x5f, 0xb0, 0xba, 0xbb};
    static constexpr std::array<std::uint16_t, 7> values{0x005b, 0x0021, 0x005d, 0x005e, 0x00a2, 0x00ac, 0x007c};
    if (byte >= 256) return std::nullopt;
    for (std::size_t i = 0; i < bytes.size(); ++i)
        if (byte == bytes[i]) return values[i];
    return decode_ebcdic_cp037(byte);
}
std::optional<std::uint32_t> decode_ebcdic_cp1047(unsigned byte) {
    // IBM open-systems EBCDIC CP1047, using the ICU mapping generated from
    // IBM CDRA source. Unlike ASCII-compatible tables, every byte position
    // has an explicit Unicode mapping, including control characters.
    static constexpr std::uint16_t values[256]={
        0x0000, 0x0001, 0x0002, 0x0003, 0x009c, 0x0009, 0x0086, 0x007f,
        0x0097, 0x008d, 0x008e, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f,
        0x0010, 0x0011, 0x0012, 0x0013, 0x009d, 0x0085, 0x0008, 0x0087,
        0x0018, 0x0019, 0x0092, 0x008f, 0x001c, 0x001d, 0x001e, 0x001f,
        0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x000a, 0x0017, 0x001b,
        0x0088, 0x0089, 0x008a, 0x008b, 0x008c, 0x0005, 0x0006, 0x0007,
        0x0090, 0x0091, 0x0016, 0x0093, 0x0094, 0x0095, 0x0096, 0x0004,
        0x0098, 0x0099, 0x009a, 0x009b, 0x0014, 0x0015, 0x009e, 0x001a,
        0x0020, 0x00a0, 0x00e2, 0x00e4, 0x00e0, 0x00e1, 0x00e3, 0x00e5,
        0x00e7, 0x00f1, 0x00a2, 0x002e, 0x003c, 0x0028, 0x002b, 0x007c,
        0x0026, 0x00e9, 0x00ea, 0x00eb, 0x00e8, 0x00ed, 0x00ee, 0x00ef,
        0x00ec, 0x00df, 0x0021, 0x0024, 0x002a, 0x0029, 0x003b, 0x005e,
        0x002d, 0x002f, 0x00c2, 0x00c4, 0x00c0, 0x00c1, 0x00c3, 0x00c5,
        0x00c7, 0x00d1, 0x00a6, 0x002c, 0x0025, 0x005f, 0x003e, 0x003f,
        0x00f8, 0x00c9, 0x00ca, 0x00cb, 0x00c8, 0x00cd, 0x00ce, 0x00cf,
        0x00cc, 0x0060, 0x003a, 0x0023, 0x0040, 0x0027, 0x003d, 0x0022,
        0x00d8, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
        0x0068, 0x0069, 0x00ab, 0x00bb, 0x00f0, 0x00fd, 0x00fe, 0x00b1,
        0x00b0, 0x006a, 0x006b, 0x006c, 0x006d, 0x006e, 0x006f, 0x0070,
        0x0071, 0x0072, 0x00aa, 0x00ba, 0x00e6, 0x00b8, 0x00c6, 0x00a4,
        0x00b5, 0x007e, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077, 0x0078,
        0x0079, 0x007a, 0x00a1, 0x00bf, 0x00d0, 0x005b, 0x00de, 0x00ae,
        0x00ac, 0x00a3, 0x00a5, 0x00b7, 0x00a9, 0x00a7, 0x00b6, 0x00bc,
        0x00bd, 0x00be, 0x00dd, 0x00a8, 0x00af, 0x005d, 0x00b4, 0x00d7,
        0x007b, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
        0x0048, 0x0049, 0x00ad, 0x00f4, 0x00f6, 0x00f2, 0x00f3, 0x00f5,
        0x007d, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f, 0x0050,
        0x0051, 0x0052, 0x00b9, 0x00fb, 0x00fc, 0x00f9, 0x00fa, 0x00ff,
        0x005c, 0x00f7, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058,
        0x0059, 0x005a, 0x00b2, 0x00d4, 0x00d6, 0x00d2, 0x00d3, 0x00d5,
        0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
        0x0038, 0x0039, 0x00b3, 0x00db, 0x00dc, 0x00d9, 0x00da, 0x009f,
    };
    if (byte >= 256) return {};
    return values[byte];
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
            bool has_high_bit_bytes=false;
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                has_high_bit_bytes=has_high_bit_bytes || (value&0x80)!=0;
                if(value>=0x20 && value<=0x7e)run.add(at,value,1);
                else emit(run,value==0,StringEncoding::ascii,range,options,output);
            }
            emit(run,false,StringEncoding::ascii,range,options,output);
            // UTF-8 is recognized only when it contains a non-ASCII scalar;
            // otherwise the ASCII pass already represents the same bytes.
            run={};
            auto utf8_begin=range.begin;
            // A leading UTF-8 signature belongs to the file encoding, not to
            // the first string. Keep the candidate's byte extent anchored at
            // its first character while accounting for these inspected bytes.
            if(range.end-range.begin>=3 && input.unit(range.begin,3)==0x00bfbbefu)
                utf8_begin+=3;
            for(auto at=utf8_begin;at<range.end;) {
                if(((at-range.begin)&2047)==0)check_stop(stop);
                if(input.byte(at)==0) {emit(run,true,StringEncoding::utf8,range,options,output,true);++at;continue;}
                const auto decoded=decode_utf8(input,at,range.end);
                if(!decoded.length || !printable(decoded.scalar)) {emit(run,false,StringEncoding::utf8,range,options,output,true);++at;continue;}
                run.add(at,decoded.scalar,decoded.length);at+=decoded.length;
            }
            emit(run,false,StringEncoding::utf8,range,options,output,true);
            if(has_high_bit_bytes) {
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
            }
            for(unsigned endian=0;endian<2;++endian)for(unsigned alignment=0;alignment<2;++alignment) {
                const bool big_endian=endian!=0;
                const auto encoding=big_endian?StringEncoding::utf16be:StringEncoding::utf16le;
                run={};auto at=range.begin+alignment;std::size_t steps=0;
                // A matching BOM at the start of a scan domain is metadata,
                // not part of the candidate text.
                if(alignment==0 && range.end-range.begin>=2 &&
                   input.unit(at,2,big_endian)==0xfeff)at+=2;
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
                if(alignment==0 && range.end-range.begin>=4 &&
                   input.unit(at,4,big_endian)==0xfeff)at+=4;
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
            // tight result budget cannot displace UTF-16/32 candidates. Every
            // such decoder requires a high-bit byte to produce a non-ASCII
            // candidate, so ASCII-only ranges have nothing to gain from them.
            if(has_high_bit_bytes) {
            run={};
            for(auto at=range.begin;at<range.end;) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto first=input.byte(at);
                if(first==0) {emit(run,true,StringEncoding::windows932,range,options,output,true);++at;continue;}
                std::optional<std::uint32_t> scalar;
                unsigned length=1;
                if((first>=0x81 && first<=0x9f) || (first>=0xe0 && first<=0xfc)) {
                    if(range.end-at>=2) {
                        const auto second=input.byte(at+1);
                        scalar=decode_windows932_pair(first,second);
                        if(scalar) length=2;
                    }
                } else {
                    scalar=decode_windows932_single(first);
                }
                if(scalar && printable(*scalar)) {run.add(at,*scalar,length);at+=length;}
                else {emit(run,false,StringEncoding::windows932,range,options,output,true);++at;}
            }
            emit(run,false,StringEncoding::windows932,range,options,output,true);
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
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1256,range,options,output,true);continue;}
                const auto scalar=decode_windows1256(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1256,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1256,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1257,range,options,output,true);continue;}
                const auto scalar=decode_windows1257(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1257,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1257,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::windows1258,range,options,output,true);continue;}
                const auto scalar=decode_windows1258(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::windows1258,range,options,output,true);
            }
            emit(run,false,StringEncoding::windows1258,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::iso8859_2,range,options,output,true);continue;}
                const auto scalar=decode_iso8859_2(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::iso8859_2,range,options,output,true);
            }
            emit(run,false,StringEncoding::iso8859_2,range,options,output,true);
            run={};
            for(auto at=range.begin;at<range.end;++at) {
                if(((at-range.begin)&4095)==0)check_stop(stop);
                const auto value=input.byte(at);
                if(value==0) {emit(run,true,StringEncoding::iso8859_5,range,options,output,true);continue;}
                const auto scalar=decode_iso8859_5(value);
                if(scalar && printable(*scalar))run.add(at,*scalar,1);
                else emit(run,false,StringEncoding::iso8859_5,range,options,output,true);
            }
            emit(run,false,StringEncoding::iso8859_5,range,options,output,true);
            const auto scan_single_byte = [&](StringEncoding encoding, auto decode, bool require_non_ascii = true,
                                              bool require_high_bit = false) {
                run={};
                bool run_has_high_bit=false;
                std::size_t letters=0,digits=0;
                const auto finish_run = [&](bool terminated) {
                    // EBCDIC turns many arbitrary byte sequences into valid
                    // printable Unicode. Require enough lexical evidence to
                    // keep a lone high-bit byte from making binary look like
                    // text. Preserve short names/words, and longer numeric
                    // fields, while rejecting punctuation-heavy fragments.
                    const bool plausible_text=letters>=2 || (run.characters>=8 && digits==run.characters);
                    if(require_high_bit && (!run_has_high_bit || !plausible_text)) run={};
                    else emit(run,terminated,encoding,range,options,output,require_non_ascii);
                    run_has_high_bit=false;
                    letters=digits=0;
                };
                for(auto at=range.begin;at<range.end;++at) {
                    if(((at-range.begin)&4095)==0)check_stop(stop);
                    const auto value=input.byte(at);
                    if(value==0) {finish_run(true);continue;}
                    const auto scalar=decode(value);
                    if(scalar && printable(*scalar)) {
                        run.add(at,*scalar,1);
                        run_has_high_bit=run_has_high_bit || value>=0x80;
                        if(((*scalar>='A' && *scalar<='Z') || (*scalar>='a' && *scalar<='z') ||
                            (*scalar>=0x00c0 && *scalar<=0x00d6) || (*scalar>=0x00d8 && *scalar<=0x00f6) ||
                            (*scalar>=0x00f8 && *scalar<=0x00ff))) ++letters;
                        if(*scalar>='0' && *scalar<='9') ++digits;
                    } else finish_run(false);
                }
                finish_run(false);
            };
            scan_single_byte(StringEncoding::dos437, decode_dos437);
            scan_single_byte(StringEncoding::dos850, decode_dos850);
            scan_single_byte(StringEncoding::dos866, decode_dos866);
            scan_single_byte(StringEncoding::dos852, decode_dos852);
            scan_single_byte(StringEncoding::koi8_r, decode_koi8_r);
            scan_single_byte(StringEncoding::koi8_u, decode_koi8_u);
            scan_single_byte(StringEncoding::iso8859_15, decode_iso8859_15);
            scan_single_byte(StringEncoding::iso8859_9, decode_iso8859_9);
            scan_single_byte(StringEncoding::mac_roman, decode_mac_roman);
            scan_single_byte(StringEncoding::mac_cyrillic, decode_mac_cyrillic);
            scan_single_byte(StringEncoding::ebcdic_cp037, decode_ebcdic_cp037, false, true);
            scan_single_byte(StringEncoding::ebcdic_cp500, decode_ebcdic_cp500, false, true);
            scan_single_byte(StringEncoding::ebcdic_cp1047, decode_ebcdic_cp1047, false, true);
            scan_single_byte(StringEncoding::ebcdic_cp1140, decode_ebcdic_cp1140, false, true);
            scan_single_byte(StringEncoding::iso8859_1, decode_iso8859_1);
            scan_single_byte(StringEncoding::iso8859_3, decode_iso8859_3);
            scan_single_byte(StringEncoding::iso8859_4, decode_iso8859_4);
            scan_single_byte(StringEncoding::iso8859_6, decode_iso8859_6);
            scan_single_byte(StringEncoding::iso8859_7, decode_iso8859_7);
            scan_single_byte(StringEncoding::iso8859_10, decode_iso8859_10);
            scan_single_byte(StringEncoding::iso8859_13, decode_iso8859_13);
            scan_single_byte(StringEncoding::iso8859_14, decode_iso8859_14);
            scan_single_byte(StringEncoding::iso8859_16, decode_iso8859_16);
            scan_single_byte(StringEncoding::iso8859_8, decode_iso8859_8);
            scan_single_byte(StringEncoding::iso8859_11, decode_iso8859_11);
            scan_single_byte(StringEncoding::windows874, decode_windows874);
            }
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
StringScript classify_string_script(std::string_view text) noexcept {
    // StringRecord previews retain at most 256 Unicode scalars (1,024 UTF-8
    // bytes). Keep the public helper bounded for callers outside that path.
    if (text.size() > 1024) return StringScript::unknown;
    constexpr std::array scripts{
        StringScript::latin, StringScript::cyrillic, StringScript::greek, StringScript::hebrew,
        StringScript::arabic, StringScript::thai, StringScript::han, StringScript::kana,
        StringScript::hangul, StringScript::armenian, StringScript::devanagari, StringScript::bengali,
        StringScript::gurmukhi, StringScript::gujarati, StringScript::odia, StringScript::tamil,
        StringScript::telugu, StringScript::kannada, StringScript::malayalam, StringScript::sinhala,
        StringScript::lao, StringScript::tibetan, StringScript::myanmar, StringScript::georgian,
        StringScript::ethiopic, StringScript::cherokee, StringScript::canadian_aboriginal,
        StringScript::khmer, StringScript::mongolian, StringScript::syriac, StringScript::thaana,
        StringScript::nko, StringScript::tifinagh, StringScript::vai, StringScript::yi,
        StringScript::adlam, StringScript::osage, StringScript::ol_chiki, StringScript::other
    };
    std::array<std::uint32_t, scripts.size()> counts{};
    const auto category = [](std::uint32_t cp) -> std::optional<std::size_t> {
        if ((cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z') ||
            (cp >= 0x00c0 && cp <= 0x02e4) || (cp >= 0x1e00 && cp <= 0x1eff) ||
            (cp >= 0xa720 && cp <= 0xa7ff) || (cp >= 0xab30 && cp <= 0xab6f)) return 0;
        if ((cp >= 0x0400 && cp <= 0x052f) || (cp >= 0x2de0 && cp <= 0x2dff) ||
            (cp >= 0xa640 && cp <= 0xa69f)) return 1;
        if ((cp >= 0x0370 && cp <= 0x03ff) || (cp >= 0x1f00 && cp <= 0x1fff)) return 2;
        if ((cp >= 0x05d0 && cp <= 0x05ea) || (cp >= 0x05ef && cp <= 0x05f2) ||
            (cp >= 0xfb1d && cp <= 0xfb4f)) return 3;
        if ((cp >= 0x0620 && cp <= 0x064a) || (cp >= 0x066e && cp <= 0x06d3) ||
            (cp >= 0x06fa && cp <= 0x06fc) || (cp >= 0x0750 && cp <= 0x077f) ||
            (cp >= 0x08a0 && cp <= 0x08c9) || (cp >= 0xfb50 && cp <= 0xfdff) ||
            (cp >= 0xfe70 && cp <= 0xfefc)) return 4;
        if ((cp >= 0x0e01 && cp <= 0x0e30) || (cp >= 0x0e32 && cp <= 0x0e33) ||
            (cp >= 0x0e40 && cp <= 0x0e46)) return 5;
        if ((cp >= 0x3400 && cp <= 0x4dbf) || (cp >= 0x4e00 && cp <= 0x9fff) ||
            (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0x20000 && cp <= 0x323af)) return 6;
        if ((cp >= 0x3041 && cp <= 0x3096) || (cp >= 0x30a1 && cp <= 0x30fa) ||
            (cp >= 0x31f0 && cp <= 0x31ff) || (cp >= 0x1b000 && cp <= 0x1b16f)) return 7;
        if ((cp >= 0x1100 && cp <= 0x11ff) || (cp >= 0x3130 && cp <= 0x318f) ||
            (cp >= 0xac00 && cp <= 0xd7af)) return 8;
        // Representative letter ranges for scripts without a dedicated hint.
        if ((cp >= 0x0530 && cp <= 0x058f) || (cp >= 0xfb13 && cp <= 0xfb17)) return 9;
        if (cp >= 0x0900 && cp <= 0x097f) return 10;
        if (cp >= 0x0980 && cp <= 0x09ff) return 11;
        if (cp >= 0x0a00 && cp <= 0x0a7f) return 12;
        if (cp >= 0x0a80 && cp <= 0x0aff) return 13;
        if (cp >= 0x0b00 && cp <= 0x0b7f) return 14;
        if (cp >= 0x0b80 && cp <= 0x0bff) return 15;
        if (cp >= 0x0c00 && cp <= 0x0c7f) return 16;
        if (cp >= 0x0c80 && cp <= 0x0cff) return 17;
        if (cp >= 0x0d00 && cp <= 0x0d7f) return 18;
        if (cp >= 0x0d80 && cp <= 0x0dff) return 19;
        if (cp >= 0x0e80 && cp <= 0x0eff) return 20;
        if (cp >= 0x0f00 && cp <= 0x0fff) return 21;
        if (cp >= 0x1000 && cp <= 0x109f) return 22;
        if ((cp >= 0x10a0 && cp <= 0x10ff) || (cp >= 0x1c90 && cp <= 0x1cbf) ||
            (cp >= 0x2d00 && cp <= 0x2d2f)) return 23;
        if ((cp >= 0x1200 && cp <= 0x139f) || (cp >= 0x2d80 && cp <= 0x2ddf) ||
            (cp >= 0xab00 && cp <= 0xab2f) || (cp >= 0x1e7e0 && cp <= 0x1e7ff)) return 24;
        if ((cp >= 0x13a0 && cp <= 0x13ff) || (cp >= 0xab70 && cp <= 0xabbf)) return 25;
        if ((cp >= 0x1400 && cp <= 0x167f) || (cp >= 0x18b0 && cp <= 0x18ff)) return 26;
        if ((cp >= 0x1780 && cp <= 0x17ff) || (cp >= 0x19e0 && cp <= 0x19ff)) return 27;
        if (cp >= 0x1800 && cp <= 0x18af) return 28;
        if ((cp >= 0x0700 && cp <= 0x074f) || (cp >= 0x0860 && cp <= 0x086f)) return 29;
        if (cp >= 0x0780 && cp <= 0x07bf) return 30;
        if (cp >= 0x07c0 && cp <= 0x07ff) return 31;
        if (cp >= 0x2d30 && cp <= 0x2d7f) return 32;
        if (cp >= 0xa500 && cp <= 0xa63f) return 33;
        if (cp >= 0xa000 && cp <= 0xa4cf) return 34;
        if (cp >= 0x1e900 && cp <= 0x1e95f) return 35;
        if (cp >= 0x104b0 && cp <= 0x104ff) return 36;
        if (cp >= 0x1c50 && cp <= 0x1c7f) return 37;
        // Recognized writing-system blocks without a dedicated category stay
        // visible as Other rather than being dropped.
        if ((cp >= 0x2c00 && cp <= 0x2cff) || (cp >= 0xa800 && cp <= 0xa82f) ||
            (cp >= 0xa840 && cp <= 0xa87f) || (cp >= 0xa880 && cp <= 0xa8df) ||
            (cp >= 0xa900 && cp <= 0xa95f) || (cp >= 0xa980 && cp <= 0xa9df) ||
            (cp >= 0xaa00 && cp <= 0xaa5f) || (cp >= 0xaa80 && cp <= 0xaaff) ||
            (cp >= 0x1e100 && cp <= 0x1e14f) || (cp >= 0x1e290 && cp <= 0x1e2bf) ||
            (cp >= 0x1e800 && cp <= 0x1e8df)) return 38;
        return std::nullopt;
    };
    for (std::size_t at = 0; at < text.size();) {
        const auto first = static_cast<unsigned char>(text[at]);
        std::uint32_t cp = 0;
        std::size_t length = 0;
        if (first < 0x80) { cp = first; length = 1; }
        else if (first >= 0xc2 && first <= 0xdf) { cp = first & 0x1f; length = 2; }
        else if (first >= 0xe0 && first <= 0xef) { cp = first & 0x0f; length = 3; }
        else if (first >= 0xf0 && first <= 0xf4) { cp = first & 0x07; length = 4; }
        else return StringScript::unknown;
        if (length > text.size() - at) return StringScript::unknown;
        for (std::size_t i = 1; i < length; ++i) {
            const auto next = static_cast<unsigned char>(text[at + i]);
            if ((next & 0xc0) != 0x80) return StringScript::unknown;
            cp = (cp << 6) | (next & 0x3f);
        }
        if ((length == 2 && cp < 0x80) || (length == 3 && cp < 0x800) ||
            (length == 4 && cp < 0x10000) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
            return StringScript::unknown;
        if (const auto index = category(cp)) ++counts[*index];
        at += length;
    }
    std::size_t found = counts.size(), found_count = 0;
    for (std::size_t i = 0; i < counts.size(); ++i) {
        if (!counts[i]) continue;
        if (found != counts.size()) return StringScript::mixed;
        found = i;
        ++found_count;
    }
    if (!found_count) return StringScript::unknown;
    return scripts[found];
}
std::string_view string_script_name(StringScript script) noexcept {
    switch (script) {
    case StringScript::unknown: return "unknown";
    case StringScript::latin: return "Latin";
    case StringScript::cyrillic: return "Cyrillic";
    case StringScript::greek: return "Greek";
    case StringScript::hebrew: return "Hebrew";
    case StringScript::arabic: return "Arabic";
    case StringScript::thai: return "Thai";
    case StringScript::han: return "Han";
    case StringScript::kana: return "Kana";
    case StringScript::hangul: return "Hangul";
    case StringScript::other: return "Other";
    case StringScript::mixed: return "Mixed";
    case StringScript::armenian: return "Armenian";
    case StringScript::devanagari: return "Devanagari";
    case StringScript::bengali: return "Bengali";
    case StringScript::gurmukhi: return "Gurmukhi";
    case StringScript::gujarati: return "Gujarati";
    case StringScript::odia: return "Odia";
    case StringScript::tamil: return "Tamil";
    case StringScript::telugu: return "Telugu";
    case StringScript::kannada: return "Kannada";
    case StringScript::malayalam: return "Malayalam";
    case StringScript::sinhala: return "Sinhala";
    case StringScript::lao: return "Lao";
    case StringScript::tibetan: return "Tibetan";
    case StringScript::myanmar: return "Myanmar";
    case StringScript::georgian: return "Georgian";
    case StringScript::ethiopic: return "Ethiopic";
    case StringScript::cherokee: return "Cherokee";
    case StringScript::canadian_aboriginal: return "Canadian Aboriginal";
    case StringScript::khmer: return "Khmer";
    case StringScript::mongolian: return "Mongolian";
    case StringScript::syriac: return "Syriac";
    case StringScript::thaana: return "Thaana";
    case StringScript::nko: return "N'Ko";
    case StringScript::tifinagh: return "Tifinagh";
    case StringScript::vai: return "Vai";
    case StringScript::yi: return "Yi";
    case StringScript::adlam: return "Adlam";
    case StringScript::osage: return "Osage";
    case StringScript::ol_chiki: return "Ol Chiki";
    }
    return "unknown";
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
