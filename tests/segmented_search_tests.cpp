#include "hexlab/workspace/search.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
void alias_paging() {
    auto storage = std::make_shared<MemoryStorage>(bytes({0xb0, 0x7f, 0xc3}));
    ImageLayout layout{
        {{7}, 16, 1, ByteOrder::little},
        Architecture::x86,
        ExecutionMode::x86_16,
        {{"16", {{7}, 0x1000}, 3, {0}, 3, true, false, true}, {"32", {{2}, 0x1000}, 3, {0}, 3, true, false, true}},
        {{{7}, 0x1000}, {{2}, 0x1000}}};
    layout.domains = {{{{2}, 32, 1, ByteOrder::little}, {Architecture::x86, ExecutionMode::x86_32}}};
    auto image = take(Image::create(storage, std::move(layout)));
    AnalysisKey key;
    key.input = {storage->size(), take(hash_source(*storage, {}))};
    key.engine_fingerprint = function_engine_fingerprint();
    auto facts = take(recover_functions(*image, {}, {}, {}, key, {}));
    auto reversed = std::make_shared<FunctionSnapshot>(*facts);
    std::reverse(reversed->instructions.begin(), reversed->instructions.end());
    SearchSource source{storage, image, reversed, key};
    const SearchQuery query = ImmediateQuery{"127", 8, ImmediateInterpretation::unsigned_value};
    const SearchLimits limit{1, 100, 100};
    auto first = take(search(source, query, {}, limit, {}));
    check(first.matches.size() == 1 && first.matches[0].instruction_address == Address{{2}, 0x1000} && first.next,
          "aliased immediate page orders equal offsets by domain independently of fact order");
    check(!first.matches[0].address && search_match_location(first.matches[0]) == Location{Address{{2}, 0x1000}},
          "known instruction provenance selects its domain while reverse file mapping remains ambiguous");
    auto reordered = source;
    reordered.functions = facts;
    auto second = take(search(reordered, query, first.next, limit, {}));
    check(second.matches.size() == 1 && second.matches[0].instruction_address == Address{{7}, 0x1000} &&
              second.complete,
          "continuation retains the second logical alias without duplication or domain loss");
    SearchHistory history;
    take(history.begin(key, query));
    take(history.append(std::make_shared<const SearchPage>(first)));
    take(history.append(std::make_shared<const SearchPage>(second)));
    check(search_match_location(*history.next()) == Location{Address{{2}, 0x1000}} &&
              search_match_location(*history.next()) == Location{Address{{7}, 0x1000}} &&
              search_match_location(*history.previous()) == Location{Address{{2}, 0x1000}},
          "search history preserves each immediate hit's logical domain");
    auto byte = take(search(source, BytePattern{"7F"}, {}, {}, {}));
    check(byte.matches.size() == 1 && !byte.matches[0].address && !byte.matches[0].instruction_address &&
              search_match_location(byte.matches[0]) == Location{FileOffset{1}},
          "byte search retains canonical file identity without choosing an alias");
}
void split_backing() {
    auto storage = std::make_shared<MemoryStorage>(bytes({0xb0, 0x90, 0x90, 0xff, 0xc3}));
    ImageLayout layout{
        {{7}, 16, 1, ByteOrder::little},
        Architecture::x86,
        ExecutionMode::x86_16,
        {{"start", {{7}, 0x1000}, 1, {0}, 1, true, false, true}, {"rest", {{7}, 0x1001}, 2, {3}, 2, true, false, true}},
        {{{7}, 0x1000}}};
    auto image = take(Image::create(storage, std::move(layout)));
    AnalysisKey key;
    key.input = {storage->size(), take(hash_source(*storage, {}))};
    key.engine_fingerprint = function_engine_fingerprint();
    auto functions = take(recover_functions(*image, {}, {}, {}, key, {}));
    auto page = take(search(SearchSource{storage, image, functions, key},
                            ImmediateQuery{"255", 8, ImmediateInterpretation::unsigned_value}, {}, {}, {}));
    check(page.matches.size() == 1 && !page.matches[0].address && page.matches[0].file_ranges.size() == 2 &&
              page.matches[0].instruction_address == Address{{7}, 0x1000} &&
              search_match_location(page.matches[0]) == Location{Address{{7}, 0x1000}},
          "split file backing preserves actual instruction origin separately from contiguous reverse mapping");
}
} // namespace
int main() {
    return run([] {
        alias_paging();
        split_backing();
    });
}
