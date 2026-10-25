#include "hexlab/workspace/jobs.hpp"
#include <condition_variable>
#include <mutex>
#include <thread>

namespace hexlab {
struct DocumentJobs::Impl {
    struct Work {OpenRequest request;OpenTicket ticket;std::stop_source stop;};
    struct State {
        std::mutex mutex;
        std::condition_variable_any changed;
        std::optional<Work> pending;
        std::optional<DocumentCompletion> ready;
        std::stop_source active;
        bool running=false;
    } state;
    std::jthread worker;
    Impl():worker([this](std::stop_token stop){run(stop);}){}
    ~Impl(){cancel();worker.request_stop();state.changed.notify_all();if(worker.joinable())worker.join();}
    void cancel() {
        std::stop_source active{std::nostopstate};
        {std::lock_guard lock(state.mutex);active=state.active;state.pending.reset();}
        active.request_stop();state.changed.notify_all();
    }
    void run(std::stop_token stop) {
        for(;;) {
            std::optional<Work> work;
            {
                std::unique_lock lock(state.mutex);
                if(!state.changed.wait(lock,stop,[this]{return state.pending.has_value();}) || stop.stop_requested())return;
                work=std::move(state.pending);state.pending.reset();state.active=work->stop;state.running=true;
            }
            auto result=[&]() -> Result<std::shared_ptr<const DocumentSnapshot>> {
                try{return load_document(work->request,work->ticket,work->stop.get_token());}
                catch(const std::exception& error){return Error{ErrorCode::io,std::string("Background analysis failed: ")+error.what()};}
            }();
            std::optional<DocumentCompletion> previous;
            {
                std::lock_guard lock(state.mutex);
                previous=std::move(state.ready);
                state.ready=DocumentCompletion{work->ticket,std::move(result)};
                state.running=false;
            }
            // Release a potentially large previous snapshot outside the lock.
        }
    }
};
DocumentJobs::DocumentJobs():impl_(std::make_unique<Impl>()){}
DocumentJobs::~DocumentJobs()=default;
void DocumentJobs::submit(OpenRequest request,OpenTicket ticket) {
    Impl::Work work{std::move(request),ticket,{}};
    std::stop_source previous{std::nostopstate};
    {
        std::lock_guard lock(impl_->state.mutex);previous=impl_->state.active;impl_->state.pending=std::move(work);
    }
    previous.request_stop();impl_->state.changed.notify_all();
}
void DocumentJobs::cancel(){impl_->cancel();}
bool DocumentJobs::busy() const {
    std::lock_guard lock(impl_->state.mutex);return impl_->state.running || impl_->state.pending.has_value();
}
std::optional<DocumentCompletion> DocumentJobs::take_completed() {
    std::lock_guard lock(impl_->state.mutex);auto result=std::move(impl_->state.ready);impl_->state.ready.reset();return result;
}
}
