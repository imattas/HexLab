#pragma once
#include "hexlab/workspace/analysis_pool.hpp"
namespace hexlab::workspace_testing {
enum class ActorPhase {writer_started,before_open,before_command,after_saved,analysis_started,analysis_computed,before_cache,writer_closed,before_import,before_analysis_submit,search_started,search_computed,listing_started,listing_computed,graph_started,graph_computed};
struct ActorCheckpoint {SessionKey session;ActorPhase phase;std::uint64_t operation=0;std::optional<AnalysisKey> source;std::optional<std::filesystem::path> working_file;};
#ifdef HEXLAB_WORKSPACE_TESTING
HEXLAB_WORKSPACE_EXPORT void set_actor_hook(SessionKey,std::function<void(const ActorCheckpoint&)>);
HEXLAB_WORKSPACE_EXPORT void clear_actor_hook(SessionKey);
HEXLAB_WORKSPACE_EXPORT void actor_checkpoint(const ActorCheckpoint&);
#else
inline void actor_checkpoint(const ActorCheckpoint&){}
#endif
}
