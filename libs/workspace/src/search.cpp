#include "hexlab/workspace/search.hpp"
#include "hexlab/workspace/project_analysis.hpp"
#include "project_internal.hpp"
namespace hexlab {
Result<SearchPage> search(const ProjectSnapshot &snapshot, const SearchQuery &query, std::optional<SearchCursor> cursor,
                          const SearchLimits &limits, std::stop_token stop) {
    return project_detail::guarded([&]() -> Result<SearchPage> {
        project_detail::require(bool(snapshot.state), "Search requires a project state");
        auto key = project_detail::take(project_analysis_key(snapshot, snapshot.analysis_options));
        if (std::holds_alternative<ImmediateQuery>(query))
            project_detail::require(snapshot.derived_key == key, "Immediate search requires current decoded facts",
                                    ErrorCode::conflict);
        return search(SearchSource{snapshot.effective,
                                   snapshot.loaded && snapshot.loaded->image->storage() == snapshot.effective
                                       ? snapshot.loaded->image : nullptr,
                                   snapshot.functions, key},
                      query, std::move(cursor), limits, stop);
    });
}
Result<bool> SearchHistory::begin(const AnalysisKey &key, SearchQuery query) {
    return project_detail::guarded([&]() -> Result<bool> {
        auto fingerprint = project_detail::take(search_query_fingerprint(query));
        clear();
        key_ = key;
        fingerprint_ = fingerprint;
        query_ = std::move(query);
        return true;
    });
}
Result<bool> SearchHistory::append(std::shared_ptr<const SearchPage> page) {
    return project_detail::guarded([&]() -> Result<bool> {
        project_detail::require(query_ && page && page->source_key == key_ && page->query_fingerprint == fingerprint_,
                                "Search page belongs to another document revision/query", ErrorCode::conflict);
        project_detail::require((pages_.empty() && !page->start) ||
                                    (!pages_.empty() && pages_.back()->next && page->start == pages_.back()->next),
                                "Search page does not continue retained results", ErrorCode::conflict);
        project_detail::require(page->matches.size() <= 100000 - count_ && pages_.size() < 4096,
                                "Retained search result budget reached", ErrorCode::resource_limit);
        pages_.push_back(std::move(page));
        count_ += pages_.back()->matches.size();
        return true;
    });
}
void SearchHistory::clear() {
    pages_.clear();
    query_.reset();
    count_ = 0;
    selected_.reset();
}
std::optional<SearchMatch> SearchHistory::at(std::size_t index) const {
    for (auto &page : pages_) {
        if (index < page->matches.size())
            return page->matches[index];
        index -= page->matches.size();
    }
    return {};
}
std::optional<SearchMatch> SearchHistory::next() {
    if (!count_ || (selected_ && *selected_ + 1 >= count_))
        return {};
    selected_ = selected_ ? *selected_ + 1 : 0;
    return at(*selected_);
}
std::optional<SearchMatch> SearchHistory::previous() {
    if (!selected_ || !*selected_)
        return {};
    --*selected_;
    return at(*selected_);
}
std::optional<SearchMatch> SearchHistory::select(std::size_t index) {
    if (index >= count_)
        return {};
    selected_ = index;
    return at(index);
}
} // namespace hexlab
