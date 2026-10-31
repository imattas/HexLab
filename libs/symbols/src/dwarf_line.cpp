#include "hexlab/symbols/dwarf.hpp"

#include <algorithm>

namespace hexlab::symbols {
namespace {
using hexlab::Error;
using hexlab::ErrorCode;
template<class T> using R = hexlab::Result<T>;
Error bad(const char *s) { return {ErrorCode::malformed, s}; }
class Reader {
public:
    Reader(std::span<const std::uint8_t> b, bool little, std::size_t p=0, std::size_t e=SIZE_MAX)
        : b_(b), little_(little), p_(p), e_(std::min(e,b.size())) {}
    std::size_t pos() const { return p_; }
    bool done() const { return p_==e_; }
    bool can(std::size_t n) const { return p_<=e_ && n<=e_-p_; }
    R<std::uint64_t> fixed(std::size_t n) {
        if(n>8||!can(n)) return Error{ErrorCode::malformed,"truncated DWARF line-table field at byte "+std::to_string(p_)+" of "+std::to_string(e_)};
        std::uint64_t v=0;
        for(std::size_t i=0;i<n;++i) v|=std::uint64_t(b_[p_++])<<(8*(little_?i:n-1-i));
        return v;
    }
    R<std::uint64_t> uleb() {
        std::uint64_t v=0; unsigned shift=0;
        for(unsigned i=0;i<10;++i) { if(!can(1)) return Error{ErrorCode::malformed,"truncated DWARF line ULEB128 at byte "+std::to_string(p_)+" of "+std::to_string(e_)}; auto x=b_[p_++];
            if(shift==63&&(x&0x7e)) return bad("DWARF line ULEB128 overflow");
            v|=std::uint64_t(x&0x7f)<<shift; if(!(x&0x80)) return v; shift+=7; }
        return bad("DWARF line ULEB128 exceeds 10 bytes");
    }
    R<std::int64_t> sleb() {
        std::uint64_t v=0; unsigned shift=0; std::uint8_t x=0;
        for(unsigned i=0;i<10;++i) { if(!can(1)) return bad("truncated DWARF line SLEB128"); x=b_[p_++];
            if(i==9&&((x&0x80)||((x&0x7f)!=0&&(x&0x7f)!=0x7f))) return bad("DWARF line SLEB128 overflow");
            v|=std::uint64_t(x&0x7f)<<shift; shift+=7; if(!(x&0x80)) { if(shift<64&&(x&0x40)) v|=(~std::uint64_t{0})<<shift; return static_cast<std::int64_t>(v); } }
        return bad("DWARF line SLEB128 exceeds 10 bytes");
    }
    R<std::string> cstring() {
        auto begin=p_; while(p_<e_&&b_[p_]) { if(p_-begin>=1024*1024) return Error{ErrorCode::resource_limit,"DWARF line path exceeds 1 MiB"}; ++p_; }
        if(p_==e_) return bad("unterminated DWARF line path");
        std::string s(reinterpret_cast<const char*>(b_.data()+begin),p_-begin); ++p_; return s;
    }
private: std::span<const std::uint8_t> b_; bool little_; std::size_t p_,e_;
};
bool add(std::uint64_t &v,std::uint64_t n) { if(n>UINT64_MAX-v)return false; v+=n; return true; }
}

static R<std::vector<DwarfLineUnit>> import_dwarf_line_impl(const DwarfLineSections &s, std::uint64_t max_version) {
    if(s.source_id.empty()||s.line.empty()) return Error{ErrorCode::invalid_argument,"DWARF line source id and .debug_line are required"};
    if(s.line.size()>256u*1024u*1024u) return Error{ErrorCode::resource_limit,".debug_line exceeds 256 MiB limit"};
    if(s.address_size!=4&&s.address_size!=8) return Error{ErrorCode::invalid_argument,"DWARF line address size must be 4 or 8"};
    Reader all(s.line,s.little_endian); std::vector<DwarfLineUnit> units; std::size_t rows=0, paths=0;
    while(!all.done()) {
        if(s.stop.stop_requested())return Error{ErrorCode::canceled,"DWARF line import canceled"};
        const auto start=all.pos(); if(units.size()>=65536)return Error{ErrorCode::resource_limit,"DWARF line unit count exceeds 65,536"}; auto len=all.fixed(4); if(!len)return len.error();
        std::uint8_t offset_size=4;
        if(len.value()==0xffffffffu){auto wide=all.fixed(8);if(!wide)return wide.error();len=wide.value();offset_size=8;}
        if(len.value()<2+offset_size||len.value()>s.line.size()-all.pos())return bad("invalid DWARF line unit length");
        const auto end=all.pos()+static_cast<std::size_t>(len.value()); auto ver=all.fixed(2); if(!ver)return ver.error();
        if(ver.value()<2||ver.value()>max_version)return Error{ErrorCode::unsupported,"unsupported DWARF line-table version"};
        if(ver.value()==5){auto as=all.fixed(1),ss=all.fixed(1);if(!as)return as.error();if(!ss)return ss.error();if(as.value()!=s.address_size||ss.value()!=0)return bad("invalid DWARF v5 line address/segment size");}
        auto hlen=all.fixed(offset_size); if(!hlen)return hlen.error(); if(hlen.value()>end-all.pos())return bad("DWARF line prologue exceeds unit");
        const auto hend=all.pos()+static_cast<std::size_t>(hlen.value()); Reader p(s.line,s.little_endian,all.pos(),hend);
        auto minlen=p.fixed(1); if(!minlen)return minlen.error(); std::uint64_t maxops=1;
        if(ver.value()>=4) { auto m=p.fixed(1); if(!m)return m.error(); maxops=m.value(); }
        auto stmt=p.fixed(1), lb=p.fixed(1), range=p.fixed(1), base=p.fixed(1);
        if(!stmt)return stmt.error(); if(!lb)return lb.error(); if(!range)return range.error(); if(!base)return base.error();
        if(!minlen.value()||!maxops||!range.value()||!base.value()||stmt.value()>1)return bad("invalid DWARF line prologue parameters");
        const auto linebase=static_cast<std::int8_t>(lb.value());
        auto default_stmt=stmt.value(); auto opcode_base=base.value();
        std::vector<std::uint8_t> stdlen; for(std::uint64_t i=1;i<opcode_base;++i){auto x=p.fixed(1);if(!x)return x.error();stdlen.push_back(static_cast<std::uint8_t>(x.value()));}
        DwarfLineUnit unit; unit.version=static_cast<std::uint16_t>(ver.value());
        unit.source_id=s.source_id;
        if(start>UINT64_MAX-s.section_offset)return Error{ErrorCode::overflow,"DWARF line source offset overflow"};
        unit.section_offset=s.section_offset+start;
        if(ver.value()==5){
            auto read_table=[&](bool files)->R<bool>{auto nf=p.fixed(1);if(!nf)return nf.error();if(nf.value()>64)return Error{ErrorCode::resource_limit,"too many DWARF v5 line table formats"};std::vector<std::pair<std::uint64_t,std::uint64_t>> fm;for(std::uint64_t i=0;i<nf.value();++i){auto c=p.uleb(),f=p.uleb();if(!c)return c.error();if(!f)return f.error();fm.push_back({c.value(),f.value()});}auto count=p.uleb();if(!count)return count.error();if(count.value()>65536)return Error{ErrorCode::resource_limit,"too many DWARF line table entries"};for(std::uint64_t j=0;j<count.value();++j){std::string name;std::uint64_t dir=0,time=0,size=0;bool gotpath=false;for(auto [content,form]:fm){R<std::uint64_t> n=std::uint64_t{0};if(form==0x08){auto v=p.cstring();if(!v)return v.error();if(content==1){name=std::move(v.value());gotpath=true;}}else if(form==0x0e||form==0x1f){auto off=p.fixed(offset_size);if(!off)return off.error();const auto table=form==0x0e?s.strings:s.line_strings;if(table.empty())return Error{ErrorCode::unsupported,form==0x0e?"DW_FORM_strp line entry requires .debug_str":"DW_FORM_line_strp line entry requires .debug_line_str"};if(off.value()>=table.size())return bad("DWARF v5 line-table string offset is out of bounds");Reader string_reader(table,s.little_endian,static_cast<std::size_t>(off.value()),table.size());auto v=string_reader.cstring();if(!v)return v.error();if(content==1){name=std::move(v.value());gotpath=true;}}else if(form==0x0b||form==0x05||form==0x06||form==0x07||form==0x0f){n=form==0x0f?p.uleb():p.fixed(form==0x0b?1:form==0x05?2:form==0x06?4:8);if(!n)return n.error();if(content==2)dir=n.value();else if(content==3)time=n.value();else if(content==4)size=n.value();}else return Error{ErrorCode::unsupported,"unsupported DWARF v5 line table form"};}if(!gotpath)return bad("DWARF v5 line table has no path field");if(++paths>1'000'000)return Error{ErrorCode::resource_limit,"DWARF line path count exceeds one million"};if(files){if(dir>unit.directories.size())return bad("DWARF line file refers to an unknown directory");unit.files.push_back({std::move(name),dir,time,size});}else unit.directories.push_back(std::move(name));}return true;};
            auto d=read_table(false);if(!d)return d.error();auto f=read_table(true);if(!f)return f.error();
        } else {
        for(;;){auto d=p.cstring();if(!d)return d.error();if(d.value().empty())break;if(++paths>1'000'000)return Error{ErrorCode::resource_limit,"DWARF line path count exceeds one million"};unit.directories.push_back(std::move(d.value()));if(unit.directories.size()>65536)return Error{ErrorCode::resource_limit,"too many DWARF line directories"};}
        for(;;){auto name=p.cstring();if(!name)return name.error();if(name.value().empty())break;auto dir=p.uleb(),time=p.uleb(),size=p.uleb();if(!dir)return dir.error();if(!time)return time.error();if(!size)return size.error();if(dir.value()>unit.directories.size())return bad("DWARF line file refers to an unknown directory");if(++paths>1'000'000)return Error{ErrorCode::resource_limit,"DWARF line path count exceeds one million"};unit.files.push_back({std::move(name.value()),dir.value(),time.value(),size.value()});if(unit.files.size()>65536)return Error{ErrorCode::resource_limit,"too many DWARF line files"};}
        }
        if(!p.done())return Error{ErrorCode::malformed,"DWARF line prologue header length mismatch at byte "+std::to_string(p.pos())+" of "+std::to_string(hend)};
        Reader r(s.line,s.little_endian,hend,end); std::uint64_t address=0,file=1,column=0,opindex=0; std::int64_t line=1; bool is_stmt=default_stmt!=0;
        const auto max_address=s.address_size==4?UINT64_C(0xffffffff):UINT64_MAX;
        auto emit=[&](bool endseq)->R<bool>{if(rows>=s.max_rows)return Error{ErrorCode::resource_limit,"DWARF line row limit exceeded"};if(!file||file>unit.files.size())return bad("DWARF line row refers to an unknown file number");unit.rows.push_back({address,file,line,column,endseq});++rows;return true;};
        auto advance=[&](std::uint64_t ops)->bool { if(ops>UINT64_MAX-opindex)return false;const auto total=opindex+ops;const auto instructions=total/maxops;opindex=total%maxops;if(instructions>UINT64_MAX/minlen.value()||!add(address,instructions*minlen.value()))return false;return address<=max_address;};
        auto skip_operands=[&](std::uint64_t n)->R<bool>{for(std::uint64_t i=0;i<n;++i){auto v=r.uleb();if(!v)return v.error();}return true;};
        while(!r.done()) {
            if(s.stop.stop_requested())return Error{ErrorCode::canceled,"DWARF line import canceled"};
            auto ov=r.fixed(1);if(!ov)return ov.error();auto op=ov.value();
            if(op==0){auto n=r.uleb();if(!n)return n.error();if(!n.value())return bad("zero-length extended DWARF line opcode");
                if(n.value()>end-r.pos())return bad("extended DWARF line opcode exceeds unit");const auto xe=r.pos()+static_cast<std::size_t>(n.value());auto sv=r.fixed(1);if(!sv)return sv.error();auto sub=sv.value();
                if(sub==1){auto e=emit(true);if(!e)return e.error();address=0;file=1;line=1;column=0;opindex=0;is_stmt=default_stmt!=0;}
                else if(sub==2){if(n.value()!=1+s.address_size)return bad("DW_LNE_set_address has invalid size");auto v=r.fixed(s.address_size);if(!v)return v.error();address=v.value();if(address>max_address)return bad("DWARF set_address exceeds target address width");opindex=0;}
                else if(sub==3){auto name=r.cstring();if(!name)return name.error();auto d=r.uleb(),t=r.uleb(),z=r.uleb();if(!d)return d.error();if(!t)return t.error();if(!z)return z.error();if(d.value()>unit.directories.size())return bad("DWARF define_file refers to an unknown directory");if(unit.files.size()>=65536||++paths>1'000'000)return Error{ErrorCode::resource_limit,"DWARF line file limit exceeded"};unit.files.push_back({std::move(name.value()),d.value(),t.value(),z.value()});}
                else { /* reserved extended opcodes are safely skipped */ }
                if(r.pos()>xe)return bad("DWARF extended opcode overread"); Reader consume(s.line,s.little_endian,r.pos(),xe); while(!consume.done()){auto ignored=consume.fixed(1);if(!ignored)return ignored.error();} r=Reader(s.line,s.little_endian,xe,end);
            } else if(op<opcode_base) {
                switch(op){case 1:{auto e=emit(false);if(!e)return e.error();break;}case 2:{auto v=r.uleb();if(!v)return v.error();if(!advance(v.value()))return Error{ErrorCode::overflow,"DWARF line address overflow"};break;}case 3:{auto v=r.sleb();if(!v)return v.error();if((v.value()>0&&line>INT64_MAX-v.value())||(v.value()<0&&line<INT64_MIN-v.value()))return Error{ErrorCode::overflow,"DWARF line number overflow"};line+=v.value();break;}case 4:{auto v=r.uleb();if(!v)return v.error();file=v.value();break;}case 5:{auto v=r.uleb();if(!v)return v.error();column=v.value();break;}case 6:is_stmt=!is_stmt;break;case 8:if(!advance((255-opcode_base)/range.value()))return Error{ErrorCode::overflow,"DWARF line address overflow"};break;case 9:{auto v=r.fixed(2);if(!v)return v.error();if(!add(address,v.value())||address>max_address)return Error{ErrorCode::overflow,"DWARF line address overflow"};opindex=0;break;}default:{if(op-1>=stdlen.size())return bad("invalid standard DWARF line opcode");auto sk=skip_operands(stdlen[op-1]);if(!sk)return sk.error();break;}}
            } else {const auto adjusted=op-opcode_base;const auto opadvance=adjusted/range.value();if(!advance(opadvance))return Error{ErrorCode::overflow,"DWARF line address overflow"};const auto delta=static_cast<std::int64_t>(linebase)+static_cast<std::int64_t>(adjusted%range.value());if((delta>0&&line>INT64_MAX-delta)||(delta<0&&line<INT64_MIN-delta))return Error{ErrorCode::overflow,"DWARF line number overflow"};line+=delta;auto e=emit(false);if(!e)return e.error();}
        }
        units.push_back(std::move(unit)); all=Reader(s.line,s.little_endian,end,s.line.size()); if(all.pos()<=start)return bad("DWARF line parser made no progress");
    }
    return units;
}
R<std::vector<DwarfLineUnit>> import_dwarf_line_v2_v5(const DwarfLineSections &s) { return import_dwarf_line_impl(s,5); }
R<std::vector<DwarfLineUnit>> import_dwarf_line_v2_v4(const DwarfLineSections &s) { return import_dwarf_line_impl(s,4); }

std::optional<DwarfLineRow> dwarf_line_row_at(const DwarfLineUnit &unit, std::uint64_t address) noexcept {
    std::size_t begin = 0;
    while (begin < unit.rows.size()) {
        std::size_t end = begin;
        while (end < unit.rows.size() && !unit.rows[end].end_sequence) ++end;
        if (end == unit.rows.size()) return std::nullopt; // no exclusive range bound

        const auto sequence_end = unit.rows[end].address;
        bool ordered = true;
        for (std::size_t i = begin + 1; i <= end; ++i) {
            if (unit.rows[i].address < unit.rows[i - 1].address) {
                ordered = false;
                break;
            }
        }
        if (ordered && address < sequence_end) {
            std::optional<DwarfLineRow> result;
            for (std::size_t i = begin; i < end && unit.rows[i].address <= address; ++i)
                result = unit.rows[i];
            if (result) return result;
        }
        begin = end + 1;
    }
    return std::nullopt;
}
} // namespace hexlab::symbols
