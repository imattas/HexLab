#include "project_testing.hpp"
#include <map>
#include <mutex>
namespace hexlab::workspace_testing {
namespace {std::mutex hooks_mutex;std::map<std::pair<uint64_t,uint64_t>,std::function<void(const ActorCheckpoint&)>> hooks;}
void set_actor_hook(SessionKey key,std::function<void(const ActorCheckpoint&)> hook){std::lock_guard lock(hooks_mutex);hooks.insert_or_assign({key.document.value,key.epoch},std::move(hook));}
void clear_actor_hook(SessionKey key){std::function<void(const ActorCheckpoint&)> retired;{std::lock_guard lock(hooks_mutex);auto found=hooks.find({key.document.value,key.epoch});if(found!=hooks.end()){retired=std::move(found->second);hooks.erase(found);}}}
void actor_checkpoint(const ActorCheckpoint& point){std::function<void(const ActorCheckpoint&)> hook;{std::lock_guard lock(hooks_mutex);auto found=hooks.find({point.session.document.value,point.session.epoch});if(found!=hooks.end())hook=found->second;}if(hook)hook(point);}
}
