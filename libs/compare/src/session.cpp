#include "hexlab/compare/session.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <set>

namespace hexlab::compare {
namespace {
constexpr std::array<char, 8> magic{'H','X','C','M','P','R','7','\0'};
constexpr std::array<char, 8> ignored_magic{'H','X','C','M','P','R','6','\0'};
constexpr std::array<char, 8> block_diff_magic{'H','X','C','M','P','R','5','\0'};
constexpr std::array<char, 8> block_magic{'H','X','C','M','P','R','4','\0'};
constexpr std::array<char, 8> body_magic{'H','X','C','M','P','R','3','\0'};
constexpr std::array<char, 8> evidence_magic{'H','X','C','M','P','R','2','\0'};
constexpr std::array<char, 8> legacy_magic{'H','X','C','M','P','R','1','\0'};
constexpr std::uint64_t max_file_size = 256ull * 1024 * 1024;
constexpr std::uint64_t max_records = 2'000'000;
constexpr std::uint32_t max_string = 1u * 1024 * 1024;

struct Writer {
    std::ostream &out;
    bool bytes(const void *p, std::size_t n) { out.write(static_cast<const char *>(p), static_cast<std::streamsize>(n)); return bool(out); }
    bool u8(std::uint8_t v) { return bytes(&v, 1); }
    bool u32(std::uint32_t v) { for (int i=0;i<4;++i) if (!u8(static_cast<std::uint8_t>(v >> (i*8)))) return false; return true; }
    bool u64(std::uint64_t v) { for (int i=0;i<8;++i) if (!u8(static_cast<std::uint8_t>(v >> (i*8)))) return false; return true; }
    bool string(const std::string &s) { return s.size() <= max_string && u32(static_cast<std::uint32_t>(s.size())) && bytes(s.data(), s.size()); }
};
struct Reader {
    std::istream &in;
    bool bytes(void *p, std::size_t n) { in.read(static_cast<char *>(p), static_cast<std::streamsize>(n)); return bool(in); }
    bool u8(std::uint8_t &v) { return bytes(&v, 1); }
    bool u32(std::uint32_t &v) { v=0; std::uint8_t b; for(int i=0;i<4;++i){if(!u8(b))return false;v|=std::uint32_t(b)<<(i*8);}return true; }
    bool u64(std::uint64_t &v) { v=0; std::uint8_t b; for(int i=0;i<8;++i){if(!u8(b))return false;v|=std::uint64_t(b)<<(i*8);}return true; }
    bool string(std::string &s) { std::uint32_t n; if(!u32(n)||n>max_string)return false; s.resize(n); return bytes(s.data(),n); }
};
Error invalid(const char *message) { return {ErrorCode::invalid_argument, message}; }
bool optional_u64(Writer &w, const std::optional<std::uint64_t> &v) { return w.u8(v.has_value()) && (!v || w.u64(*v)); }
bool optional_u64(Reader &r, std::optional<std::uint64_t> &v) { std::uint8_t has; if(!r.u8(has)||has>1)return false; if(!has){v.reset();return true;} std::uint64_t x; if(!r.u64(x))return false;v=x;return true; }
bool valid_instruction_diff(const FunctionInstructionDiff &diff) {
    std::uint64_t equal = 0, changed = 0, removed = 0, added = 0;
    for (const auto &run : diff.runs) {
        if (run.kind > InstructionDiffKind::added || !run.old_count && !run.new_count ||
            run.old_count > UINT64_MAX - run.old_start || run.new_count > UINT64_MAX - run.new_start)
            return false;
        switch (run.kind) {
        case InstructionDiffKind::equal:
            if (!run.old_count || run.old_count != run.new_count || run.old_count > UINT64_MAX - equal) return false;
            equal += run.old_count;
            break;
        case InstructionDiffKind::changed: {
            if (!run.old_count || !run.new_count) return false;
            const auto paired = std::min(run.old_count, run.new_count);
            const auto old_tail = run.old_count - paired, new_tail = run.new_count - paired;
            if (paired > UINT64_MAX - changed || old_tail > UINT64_MAX - removed || new_tail > UINT64_MAX - added) return false;
            changed += paired; removed += old_tail; added += new_tail;
            break;
        }
        case InstructionDiffKind::removed:
            if (!run.old_count || run.new_count || run.old_count > UINT64_MAX - removed) return false;
            removed += run.old_count;
            break;
        case InstructionDiffKind::added:
            if (run.old_count || !run.new_count || run.new_count > UINT64_MAX - added) return false;
            added += run.new_count;
            break;
        }
    }
    return equal == diff.equal_instructions && changed == diff.changed_instructions &&
           removed == diff.removed_instructions && added == diff.added_instructions;
}
bool write_instruction_diff(Writer &w, const FunctionInstructionDiff &diff) {
    if (!valid_instruction_diff(diff) || diff.runs.size() > max_records) return false;
    bool ok = w.u64(diff.equal_instructions) && w.u64(diff.changed_instructions) &&
              w.u64(diff.removed_instructions) && w.u64(diff.added_instructions) &&
              w.u64(diff.runs.size());
    for (const auto &run : diff.runs)
        ok = ok && w.u8(static_cast<std::uint8_t>(run.kind)) && w.u64(run.old_start) &&
             w.u64(run.new_start) && w.u64(run.old_count) && w.u64(run.new_count);
    return ok;
}
bool read_instruction_diff(Reader &r, FunctionInstructionDiff &diff, std::uint64_t &remaining_runs) {
    std::uint64_t count = 0;
    if (!r.u64(diff.equal_instructions) || !r.u64(diff.changed_instructions) ||
        !r.u64(diff.removed_instructions) || !r.u64(diff.added_instructions) ||
        !r.u64(count) || count > remaining_runs) return false;
    remaining_runs -= count;
    diff.runs.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        InstructionDiffRun run;
        std::uint8_t kind = 0;
        if (!r.u8(kind) || kind > static_cast<std::uint8_t>(InstructionDiffKind::added) ||
            !r.u64(run.old_start) || !r.u64(run.new_start) ||
            !r.u64(run.old_count) || !r.u64(run.new_count)) return false;
        run.kind = static_cast<InstructionDiffKind>(kind);
        diff.runs.push_back(run);
    }
    return valid_instruction_diff(diff);
}
bool valid_block_evidence(const BlockCorrespondence& row) {
    const auto& evidence = row.instruction_evidence;
    return evidence.fingerprint_similarity <= 100 && evidence.adjacency_similarity <= 100 &&
        (evidence.available || (!evidence.adjacency_available && !evidence.fingerprint_similarity && !evidence.adjacency_similarity)) &&
        (evidence.adjacency_available || !evidence.adjacency_similarity) &&
        (!evidence.available || row.kind == BlockMatchKind::matched);
}
}

Result<bool> save_session(const std::filesystem::path &path, const Session &s) {
    if(s.report.runs.size()>max_records||s.functions.size()>max_records||s.function_body_diffs.size()>max_records)
        return invalid("comparison session has too many records");
    std::uint64_t total_body_runs = 0;
    std::uint64_t total_block_diff_runs = 0;
    std::uint64_t total_block_rows = 0;
    for (const auto &body : s.function_body_diffs) {
        if (!valid_instruction_diff(body.diff) || body.diff.runs.size() > max_records - total_body_runs)
            return invalid("comparison session has invalid or excessive function body diffs");
        total_body_runs += body.diff.runs.size();
        const auto &blocks=body.block_correspondence;
        if(blocks.blocks.size()>max_records-total_block_rows)return invalid("comparison session has too many block correspondence rows");
        total_block_rows+=blocks.blocks.size();
        std::uint64_t matched=0,added=0,removed=0,ambiguous=0;std::set<std::uint32_t> old_indexes,new_indexes;
        for(const auto &row:blocks.blocks){
            if(row.kind>BlockMatchKind::ambiguous||row.confidence>100||!valid_block_evidence(row)||
               (row.old_block&&!old_indexes.insert(*row.old_block).second)||
               (row.new_block&&!new_indexes.insert(*row.new_block).second)||
               (row.kind==BlockMatchKind::matched&&(!row.old_block||!row.new_block))||
               (row.kind==BlockMatchKind::added&&(row.old_block||!row.new_block))||
               (row.kind==BlockMatchKind::removed&&(!row.old_block||row.new_block))||
               (row.kind==BlockMatchKind::ambiguous&&(!row.old_block&&!row.new_block))||
               (row.kind!=BlockMatchKind::matched&&(row.confidence||row.supporting_neighbors)))
                return invalid("comparison session has invalid block correspondence rows");
            if ((row.instruction_diff_available &&
                 (row.kind == BlockMatchKind::ambiguous || row.instruction_diff_budget_exhausted ||
                  !valid_instruction_diff(row.instruction_diff))) ||
                (row.instruction_diff_budget_exhausted &&
                 (row.kind == BlockMatchKind::ambiguous || !blocks.instruction_diff_budget_exhausted)) ||
                (!row.instruction_diff_available &&
                 (row.instruction_diff.equal_instructions || row.instruction_diff.changed_instructions ||
                  row.instruction_diff.removed_instructions || row.instruction_diff.added_instructions ||
                  !row.instruction_diff.runs.empty())) ||
                row.instruction_diff.runs.size() > max_records - total_block_diff_runs)
                return invalid("comparison session has invalid block instruction diffs");
            if (row.instruction_diff_available) total_block_diff_runs += row.instruction_diff.runs.size();
            switch(row.kind){case BlockMatchKind::matched:++matched;break;case BlockMatchKind::added:++added;break;case BlockMatchKind::removed:++removed;break;case BlockMatchKind::ambiguous:++ambiguous;break;}
        }
        if(matched!=blocks.matched||added!=blocks.added||removed!=blocks.removed||ambiguous!=blocks.ambiguous)
            return invalid("comparison session has inconsistent block correspondence totals");
    }
    auto temp=path; temp += ".tmp";
    std::ofstream f(temp,std::ios::binary|std::ios::trunc);
    if(!f) return invalid("cannot create comparison session");
    Writer w{f};
    bool ok=w.bytes(magic.data(),magic.size())&&w.string(s.old_name)&&w.string(s.new_name);
    const auto &x=s.report.summary;
    for(auto v:{x.compared_bytes,x.equal_bytes,x.changed_bytes,x.added_bytes,x.removed_bytes,x.matched_regions,x.added_regions,x.removed_regions}) ok=ok&&w.u64(v);
    ok = ok && w.u64(x.ignored_bytes);
    ok=ok&&w.u64(s.report.runs.size());
    for(const auto &run:s.report.runs) ok=ok&&w.u8(static_cast<std::uint8_t>(run.kind))&&w.string(run.region_key)&&optional_u64(w,run.old_address)&&optional_u64(w,run.new_address)&&w.u64(run.size);
    ok=ok&&w.u64(s.functions.size());
    for(const auto &m:s.functions) ok=ok&&w.u8(static_cast<std::uint8_t>(m.kind))&&optional_u64(w,m.old_entry)&&optional_u64(w,m.new_entry)&&w.u32(m.confidence)&&w.u32(m.old_space)&&w.u32(m.new_space)&&w.string(m.old_name)&&w.string(m.new_name)&&w.u32(m.evidence.base_confidence)&&w.u64(m.evidence.supporting_call_neighbors)&&w.u32(m.evidence.call_graph_round);
    ok=ok&&w.u64(s.function_body_diffs.size());
    for (const auto &body : s.function_body_diffs) {
        const auto &diff = body.diff;
        ok=ok&&w.u64(body.old_entry)&&w.u64(body.new_entry)&&w.u32(body.old_space)&&w.u32(body.new_space)&&
            w.u64(diff.equal_instructions)&&w.u64(diff.changed_instructions)&&
            w.u64(diff.removed_instructions)&&w.u64(diff.added_instructions)&&w.u64(diff.runs.size());
        for (const auto &run : diff.runs)
            ok=ok&&w.u8(static_cast<std::uint8_t>(run.kind))&&w.u64(run.old_start)&&w.u64(run.new_start)&&
                w.u64(run.old_count)&&w.u64(run.new_count);
        const auto &blocks=body.block_correspondence;
        ok=ok&&w.u64(blocks.matched)&&w.u64(blocks.added)&&w.u64(blocks.removed)&&w.u64(blocks.ambiguous)&&
           w.u8(blocks.budget_exhausted)&&w.u8(blocks.instruction_diff_budget_exhausted)&&
           w.u64(blocks.blocks.size());
        for(const auto &row:blocks.blocks){
            const std::optional<std::uint64_t> old_index=row.old_block?std::optional<std::uint64_t>(*row.old_block):std::nullopt;
            const std::optional<std::uint64_t> new_index=row.new_block?std::optional<std::uint64_t>(*row.new_block):std::nullopt;
            ok=ok&&w.u8(static_cast<std::uint8_t>(row.kind))&&optional_u64(w,old_index)&&optional_u64(w,new_index)&&
               w.u32(row.confidence)&&w.u32(row.supporting_neighbors)&&
               w.u8(row.instruction_diff_available)&&w.u8(row.instruction_diff_budget_exhausted);
            if (row.instruction_diff_available) ok = ok && write_instruction_diff(w, row.instruction_diff);
            const auto& evidence = row.instruction_evidence;
            ok = ok && w.u8(evidence.available) && w.u8(evidence.adjacency_available) &&
                w.u32(evidence.fingerprint_similarity) && w.u32(evidence.adjacency_similarity);
        }
    }
    f.flush(); ok=ok&&bool(f); f.close();
    if(!ok){std::error_code ec;std::filesystem::remove(temp,ec);return invalid("failed writing comparison session");}
    std::error_code ec; std::filesystem::rename(temp,path,ec);
    if(ec){std::filesystem::remove(temp);return invalid("cannot finalize comparison session");}
    return true;
}

Result<Session> load_session(const std::filesystem::path &path) {
    std::error_code ec; const auto size=std::filesystem::file_size(path,ec);
    if(ec||size>max_file_size) return invalid("comparison session is missing or exceeds the size limit");
    std::ifstream f(path,std::ios::binary); if(!f)return invalid("cannot open comparison session");
    Reader r{f}; std::array<char,8> got{}; Session s;
    if(!r.bytes(got.data(),got.size())||(got!=magic&&got!=ignored_magic&&got!=block_diff_magic&&got!=block_magic&&got!=body_magic&&got!=evidence_magic&&got!=legacy_magic)||!r.string(s.old_name)||!r.string(s.new_name))return invalid("invalid comparison session header");
    const bool has_ignored_summary = got == magic||got==ignored_magic;
    const bool has_evidence = got != legacy_magic;
    const bool has_body_diffs = got == magic||got==ignored_magic||got==block_diff_magic||got==block_magic||got==body_magic;
    const bool has_block_correspondence = got == magic||got==ignored_magic||got==block_diff_magic||got==block_magic;
    const bool has_block_instruction_diffs = got == magic||got==ignored_magic||got==block_diff_magic;
    const bool has_block_evidence = got == magic;
    auto &x=s.report.summary;
    for(auto *v:{&x.compared_bytes,&x.equal_bytes,&x.changed_bytes,&x.added_bytes,&x.removed_bytes,&x.matched_regions,&x.added_regions,&x.removed_regions}) if(!r.u64(*v))return invalid("truncated comparison summary");
    if (has_ignored_summary && !r.u64(x.ignored_bytes)) return invalid("truncated comparison ignored-byte summary");
    std::uint64_t n; if(!r.u64(n)||n>max_records)return invalid("invalid comparison run count");
    s.report.runs.reserve(static_cast<std::size_t>(n));
    for(std::uint64_t i=0;i<n;++i){ ChangeRun v{}; std::uint8_t k; if(!r.u8(k)||k>static_cast<std::uint8_t>(ChangeKind::changed)||!r.string(v.region_key)||!optional_u64(r,v.old_address)||!optional_u64(r,v.new_address)||!r.u64(v.size))return invalid("invalid comparison run"); v.kind=static_cast<ChangeKind>(k); if(!v.size||v.region_key.empty())return invalid("invalid comparison run fields"); s.report.runs.push_back(std::move(v)); }
    if(!r.u64(n)||n>max_records)return invalid("invalid function match count");
    s.functions.reserve(static_cast<std::size_t>(n));
    for(std::uint64_t i=0;i<n;++i){
        FunctionMatch v; std::uint8_t k;
        if(!r.u8(k)||k>static_cast<std::uint8_t>(FunctionMatchKind::ambiguous)||!optional_u64(r,v.old_entry)||!optional_u64(r,v.new_entry)||!r.u32(v.confidence)||!r.u32(v.old_space)||!r.u32(v.new_space)||!r.string(v.old_name)||!r.string(v.new_name)||v.confidence>100)return invalid("invalid comparison function match");
        v.kind=static_cast<FunctionMatchKind>(k);
        if(has_evidence) {
            if(!r.u32(v.evidence.base_confidence)||!r.u64(v.evidence.supporting_call_neighbors)||
               !r.u32(v.evidence.call_graph_round)||v.evidence.base_confidence>100||
               ((v.evidence.call_graph_round==0)!=(v.evidence.supporting_call_neighbors==0))||
               (v.evidence.call_graph_round!=0&&v.kind!=FunctionMatchKind::matched))
                return invalid("invalid comparison function evidence");
        }
        s.functions.push_back(std::move(v));
    }
    if (has_body_diffs) {
        if (!r.u64(n)||n>max_records)return invalid("invalid function body diff count");
        s.function_body_diffs.reserve(static_cast<std::size_t>(n));
        std::uint64_t total_body_runs = 0;
        std::uint64_t remaining_block_diff_runs = max_records;
        std::uint64_t total_block_rows = 0;
        for (std::uint64_t i=0;i<n;++i) {
            FunctionBodyDiff body;
            auto &diff=body.diff;
            std::uint64_t run_count=0;
            if(!r.u64(body.old_entry)||!r.u64(body.new_entry)||!r.u32(body.old_space)||!r.u32(body.new_space)||
               !r.u64(diff.equal_instructions)||!r.u64(diff.changed_instructions)||
               !r.u64(diff.removed_instructions)||!r.u64(diff.added_instructions)||!r.u64(run_count)||
               run_count>max_records-total_body_runs)
                return invalid("invalid function body diff record");
            total_body_runs+=run_count;
            diff.runs.reserve(static_cast<std::size_t>(run_count));
            for (std::uint64_t run_index=0;run_index<run_count;++run_index) {
                InstructionDiffRun run;
                std::uint8_t kind=0;
                if(!r.u8(kind)||kind>static_cast<std::uint8_t>(InstructionDiffKind::added)||
                   !r.u64(run.old_start)||!r.u64(run.new_start)||!r.u64(run.old_count)||!r.u64(run.new_count))
                    return invalid("invalid function instruction diff run");
                run.kind=static_cast<InstructionDiffKind>(kind);
                diff.runs.push_back(run);
            }
            if(has_block_correspondence){
                auto &blocks=body.block_correspondence;std::uint8_t budget=0;std::uint64_t block_count=0;
                std::uint8_t instruction_budget = 0;
                if(!r.u64(blocks.matched)||!r.u64(blocks.added)||!r.u64(blocks.removed)||!r.u64(blocks.ambiguous)||
                   !r.u8(budget)||budget>1||
                   (has_block_instruction_diffs && (!r.u8(instruction_budget)||instruction_budget>1))||
                   !r.u64(block_count)||block_count>max_records-total_block_rows)
                    return invalid("invalid function block correspondence header");
                blocks.budget_exhausted=budget!=0;
                blocks.instruction_diff_budget_exhausted=instruction_budget!=0;
                total_block_rows+=block_count;
                blocks.blocks.reserve(static_cast<std::size_t>(block_count));
                std::uint64_t matched=0,added=0,removed=0,ambiguous=0;std::set<std::uint32_t> old_indexes,new_indexes;
                for(std::uint64_t block_index=0;block_index<block_count;++block_index){
                    BlockCorrespondence row;std::uint8_t kind=0;std::optional<std::uint64_t> old_index,new_index;
                    if(!r.u8(kind)||kind>static_cast<std::uint8_t>(BlockMatchKind::ambiguous)||
                       !optional_u64(r,old_index)||!optional_u64(r,new_index)||!r.u32(row.confidence)||
                       !r.u32(row.supporting_neighbors)||row.confidence>100||
                       (old_index&&*old_index>UINT32_MAX)||(new_index&&*new_index>UINT32_MAX))
                        return invalid("invalid function block correspondence row");
                    row.kind=static_cast<BlockMatchKind>(kind);
                    if(old_index)row.old_block=static_cast<std::uint32_t>(*old_index);
                    if(new_index)row.new_block=static_cast<std::uint32_t>(*new_index);
                    if((row.old_block&&!old_indexes.insert(*row.old_block).second)||
                       (row.new_block&&!new_indexes.insert(*row.new_block).second)||
                       (row.kind==BlockMatchKind::matched&&(!row.old_block||!row.new_block))||
                       (row.kind==BlockMatchKind::added&&(row.old_block||!row.new_block))||
                       (row.kind==BlockMatchKind::removed&&(!row.old_block||row.new_block))||
                       (row.kind==BlockMatchKind::ambiguous&&(!row.old_block&&!row.new_block))||
                       (row.kind!=BlockMatchKind::matched&&(row.confidence||row.supporting_neighbors)))
                        return invalid("inconsistent function block correspondence fields");
                    if (has_block_instruction_diffs) {
                        std::uint8_t has_diff = 0, budget_limited = 0;
                        if (!r.u8(has_diff) || has_diff > 1 || !r.u8(budget_limited) || budget_limited > 1 ||
                            (has_diff && (row.kind == BlockMatchKind::ambiguous || budget_limited)) ||
                            (has_diff && !read_instruction_diff(r, row.instruction_diff, remaining_block_diff_runs)))
                            return invalid("invalid block instruction diff");
                        row.instruction_diff_available = has_diff != 0;
                        row.instruction_diff_budget_exhausted = budget_limited != 0;
                        if (row.instruction_diff_budget_exhausted && !blocks.instruction_diff_budget_exhausted)
                            return invalid("inconsistent block instruction diff budget status");
                    }
                    if (has_block_evidence) {
                        auto& evidence = row.instruction_evidence;
                        std::uint8_t available = 0, adjacency_available = 0;
                        if (!r.u8(available) || available > 1 || !r.u8(adjacency_available) || adjacency_available > 1 ||
                            !r.u32(evidence.fingerprint_similarity) || !r.u32(evidence.adjacency_similarity))
                            return invalid("invalid block instruction similarity evidence");
                        evidence.available = available != 0;
                        evidence.adjacency_available = adjacency_available != 0;
                        if (!valid_block_evidence(row)) return invalid("inconsistent block instruction similarity evidence");
                    }
                    switch(row.kind){case BlockMatchKind::matched:++matched;break;case BlockMatchKind::added:++added;break;case BlockMatchKind::removed:++removed;break;case BlockMatchKind::ambiguous:++ambiguous;break;}
                    blocks.blocks.push_back(row);
                }
                if(matched!=blocks.matched||added!=blocks.added||removed!=blocks.removed||ambiguous!=blocks.ambiguous)
                    return invalid("inconsistent function block correspondence totals");
            }
            if(!valid_instruction_diff(diff))return invalid("inconsistent function instruction diff totals");
            s.function_body_diffs.push_back(std::move(body));
        }
    }
    if(f.peek()!=std::char_traits<char>::eof())return invalid("trailing data in comparison session");
    return s;
}
} // namespace hexlab::compare
