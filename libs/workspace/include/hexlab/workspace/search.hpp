#pragma once
#include "hexlab/workspace/project.hpp"
#include "hexlab/analysis/search.hpp"
namespace hexlab {
HEXLAB_WORKSPACE_EXPORT Result<SearchPage> search(const ProjectSnapshot&,const SearchQuery&,std::optional<SearchCursor> = {},const SearchLimits& = {},std::stop_token = {});
// Each document owns its history; pages retain immutable, revision-bound locations.
class SearchHistory {
public:
    HEXLAB_WORKSPACE_EXPORT Result<bool> begin(const AnalysisKey&,SearchQuery);
    HEXLAB_WORKSPACE_EXPORT Result<bool> append(std::shared_ptr<const SearchPage>);
    HEXLAB_WORKSPACE_EXPORT std::optional<SearchMatch> next();
    HEXLAB_WORKSPACE_EXPORT std::optional<SearchMatch> previous();
    HEXLAB_WORKSPACE_EXPORT std::optional<SearchMatch> select(std::size_t);
    HEXLAB_WORKSPACE_EXPORT void clear();
    const std::optional<SearchQuery>& query()const noexcept{return query_;}
    std::optional<SearchCursor> continuation()const{return pages_.empty()?std::optional<SearchCursor>{}:pages_.back()->next;}
    std::size_t size()const noexcept{return count_;}
    std::optional<std::size_t> selected_index()const noexcept{return selected_;}
    std::span<const std::shared_ptr<const SearchPage>> pages()const noexcept{return pages_;}
private:
    std::optional<SearchMatch> at(std::size_t)const;
    AnalysisKey key_;Sha256Digest fingerprint_{};std::optional<SearchQuery> query_;
    std::vector<std::shared_ptr<const SearchPage>> pages_;std::size_t count_=0;std::optional<std::size_t> selected_;
};
}
