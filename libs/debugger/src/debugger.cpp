#include "hexlab/debugger/debugger.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <functional>
#include <set>
#include <string_view>
#include <utility>

namespace hexlab::debugger {
namespace {
Error invalid_state(const char* operation) {
    return {ErrorCode::invalid_argument, std::string(operation) + " is invalid in the current debugger state"};
}
constexpr std::size_t max_breakpoint_event_ids = 4096;
constexpr std::size_t max_debug_event_message_bytes = 4096;
constexpr std::string_view truncated_text = "...[truncated]";
void append_bounded(std::string& destination, std::string_view text) {
    if (destination.size() >= max_debug_event_message_bytes) return;
    const auto remaining = max_debug_event_message_bytes - destination.size();
    if (text.size() <= remaining) {
        destination.append(text);
        return;
    }
    const auto content_limit = remaining > truncated_text.size() ? remaining - truncated_text.size() : 0;
    auto count = std::min(content_limit, text.size());
    while (count && count < text.size() &&
           (static_cast<unsigned char>(text[count]) & 0xc0u) == 0x80u)
        --count;
    destination.append(text.substr(0, count));
    if (remaining >= truncated_text.size()) destination.append(truncated_text);
}

class ConditionParser {
public:
    using MemoryRead = std::function<Result<std::uint64_t>(std::uint64_t, std::size_t)>;
    ConditionParser(std::string_view source, const std::vector<RegisterValue>& registers, MemoryRead memory_read,
                    std::string_view label = "condition")
        : source_(source), registers_(registers), memory_read_(std::move(memory_read)), label_(label) {}
    Result<std::uint64_t> evaluate() {
        if (source_.size() > 256) return Error{ErrorCode::resource_limit, std::string(label_) + " exceeds 256 characters"};
        auto value = parse_or(0);
        skip();
        if (!value) return value.error();
        if (pos_ != source_.size()) return syntax("unexpected trailing token");
        return value.value();
    }
private:
    std::string_view source_;
    const std::vector<RegisterValue>& registers_;
    MemoryRead memory_read_;
    std::string_view label_;
    std::size_t pos_ = 0, tokens_ = 0;
    void skip() { while (pos_ < source_.size() && std::isspace(static_cast<unsigned char>(source_[pos_]))) ++pos_; }
    Error syntax(const char* message) const { return {ErrorCode::invalid_argument, std::string(label_) + ": " + message}; }
    bool take(std::string_view token) { skip(); if (source_.substr(pos_, token.size()) == token) { pos_ += token.size(); return true; } return false; }
    bool take_single(char token) {
        skip();
        if (pos_ >= source_.size() || source_[pos_] != token ||
            (pos_ + 1 < source_.size() && source_[pos_ + 1] == token))
            return false;
        ++pos_;
        return true;
    }
    Result<std::uint64_t> parse_or(unsigned depth) {
        auto lhs=parse_and(depth); if(!lhs)return lhs.error();
        while(take("||")){ auto rhs=parse_and(depth); if(!rhs)return rhs.error(); lhs=std::uint64_t(lhs.value()!=0 || rhs.value()!=0); }
        return lhs;
    }
    Result<std::uint64_t> parse_and(unsigned depth) {
        auto lhs=parse_compare(depth); if(!lhs)return lhs.error();
        while(take("&&")){ auto rhs=parse_compare(depth); if(!rhs)return rhs.error(); lhs=std::uint64_t(lhs.value()!=0 && rhs.value()!=0); }
        return lhs;
    }
    Result<std::uint64_t> parse_compare(unsigned depth) {
        auto lhs=parse_bitwise_or(depth); if(!lhs)return lhs.error();
        skip();
        for (auto op : {std::string_view("=="), std::string_view("!="), std::string_view("<="), std::string_view(">="), std::string_view("<"), std::string_view(">")}) {
            if (take(op)) { auto rhs=parse_bitwise_or(depth); if(!rhs)return rhs.error();
                const auto a=lhs.value(), b=rhs.value();
                if(op=="==") lhs=std::uint64_t(a==b); else if(op=="!=") lhs=std::uint64_t(a!=b);
                else if(op=="<") lhs=std::uint64_t(a<b); else if(op==">") lhs=std::uint64_t(a>b);
                else if(op=="<=") lhs=std::uint64_t(a<=b); else lhs=std::uint64_t(a>=b);
                return lhs;
            }
        }
        return lhs;
    }
    Result<std::uint64_t> parse_bitwise_or(unsigned depth) {
        auto lhs = parse_bitwise_xor(depth); if (!lhs) return lhs.error();
        while (take_single('|')) { auto rhs = parse_bitwise_xor(depth); if (!rhs) return rhs.error(); lhs = lhs.value() | rhs.value(); }
        return lhs;
    }
    Result<std::uint64_t> parse_bitwise_xor(unsigned depth) {
        auto lhs = parse_bitwise_and(depth); if (!lhs) return lhs.error();
        while (take("^")) { auto rhs = parse_bitwise_and(depth); if (!rhs) return rhs.error(); lhs = lhs.value() ^ rhs.value(); }
        return lhs;
    }
    Result<std::uint64_t> parse_bitwise_and(unsigned depth) {
        auto lhs = parse_shift(depth); if (!lhs) return lhs.error();
        while (take_single('&')) { auto rhs = parse_shift(depth); if (!rhs) return rhs.error(); lhs = lhs.value() & rhs.value(); }
        return lhs;
    }
    Result<std::uint64_t> parse_shift(unsigned depth) {
        auto lhs=parse_add(depth); if(!lhs)return lhs.error();
        for (;;) {
            if (take("<<")) {
                auto rhs=parse_add(depth); if(!rhs)return rhs.error();
                if (rhs.value() >= 64) return syntax("shift count must be less than 64");
                lhs=lhs.value() << rhs.value();
            } else if (take(">>")) {
                auto rhs=parse_add(depth); if(!rhs)return rhs.error();
                if (rhs.value() >= 64) return syntax("shift count must be less than 64");
                lhs=lhs.value() >> rhs.value();
            } else return lhs;
        }
    }
    Result<std::uint64_t> parse_add(unsigned depth) {
        auto lhs=parse_multiply(depth); if(!lhs)return lhs.error();
        for (;;) {
            if (take("+")) { auto rhs=parse_multiply(depth); if(!rhs)return rhs.error(); lhs=lhs.value()+rhs.value(); }
            else if (take("-")) { auto rhs=parse_multiply(depth); if(!rhs)return rhs.error(); lhs=lhs.value()-rhs.value(); }
            else return lhs;
        }
    }
    Result<std::uint64_t> parse_multiply(unsigned depth) {
        auto lhs=parse_unary(depth); if(!lhs)return lhs.error();
        for (;;) {
            if (take("*")) { auto rhs=parse_unary(depth); if(!rhs)return rhs.error(); lhs=lhs.value()*rhs.value(); }
            else if (take("/")) {
                auto rhs=parse_unary(depth); if(!rhs)return rhs.error();
                if (!rhs.value()) return syntax("division by zero");
                lhs=lhs.value()/rhs.value();
            } else if (take("%")) {
                auto rhs=parse_unary(depth); if(!rhs)return rhs.error();
                if (!rhs.value()) return syntax("remainder by zero");
                lhs=lhs.value()%rhs.value();
            } else return lhs;
        }
    }
    Result<std::uint64_t> parse_unary(unsigned depth) {
        if (depth > 16) return Error{ErrorCode::resource_limit, std::string(label_) + " nesting exceeds 16 levels"};
        if (++tokens_ > 64) return Error{ErrorCode::resource_limit, std::string(label_) + " exceeds 64 parsed operands"};
        if(take("!")){auto v=parse_unary(depth+1);if(!v)return v.error();return std::uint64_t(v.value()==0);}
        if(take("~")){auto v=parse_unary(depth+1);if(!v)return v.error();return ~v.value();}
        if(take("(")){auto v=parse_or(depth+1);if(!v)return v.error();if(!take(")"))return syntax("missing closing parenthesis");return v;}
        skip(); const auto start=pos_;
        if(pos_<source_.size() && std::isdigit(static_cast<unsigned char>(source_[pos_]))) {
            int base=10; if(source_.substr(pos_,2)=="0x" || source_.substr(pos_,2)=="0X"){base=16;pos_+=2;}
            const auto digits=pos_; while(pos_<source_.size() && (std::isxdigit(static_cast<unsigned char>(source_[pos_])) && (base==16 || std::isdigit(static_cast<unsigned char>(source_[pos_])))))++pos_;
            if(digits==pos_)return syntax("invalid integer literal");
            std::uint64_t n=0; for(auto c:source_.substr(digits,pos_-digits)){const unsigned d=std::isdigit(static_cast<unsigned char>(c))?c-'0':std::tolower(static_cast<unsigned char>(c))-'a'+10;if(n>(UINT64_MAX-d)/base)return syntax("integer literal overflows 64 bits");n=n*base+d;} return n;
        }
        if(pos_<source_.size() && (std::isalpha(static_cast<unsigned char>(source_[pos_])) || source_[pos_]=='_')) {
            ++pos_; while(pos_<source_.size() && (std::isalnum(static_cast<unsigned char>(source_[pos_])) || source_[pos_]=='_'))++pos_;
            std::string name(source_.substr(start,pos_-start));
            std::size_t width = 0;
            if (name == "mem8") width = 1;
            else if (name == "mem16") width = 2;
            else if (name == "mem32") width = 4;
            else if (name == "mem64") width = 8;
            if (width) {
                if (!take("(")) return syntax("memory reads use mem8(address), mem16(address), mem32(address), or mem64(address)");
                auto address = parse_or(depth + 1);
                if (!address) return address.error();
                if (!take(")")) return syntax("missing closing parenthesis after memory address");
                if (!memory_read_) return Error{ErrorCode::unsupported, std::string(label_) + ": target memory is unavailable"};
                return memory_read_(address.value(), width);
            }
            auto reg=std::find_if(registers_.begin(),registers_.end(),[&](const auto& r){if(r.name.size()!=name.size())return false;for(std::size_t i=0;i<name.size();++i)if(std::tolower(static_cast<unsigned char>(r.name[i]))!=std::tolower(static_cast<unsigned char>(name[i])))return false;return true;});
            if(reg==registers_.end())return Error{ErrorCode::invalid_argument,std::string(label_)+": unknown register '"+name+"'"};
            if(reg->bytes.empty() || reg->bytes.size()>8)return Error{ErrorCode::unsupported,std::string(label_)+": register '"+name+"' is not a scalar of at most 64 bits"};
            if(!reg->byte_order)return Error{ErrorCode::unsupported,std::string(label_)+": byte order is unknown for register '"+name+"'"};
            std::uint64_t value=0; for(std::size_t i=0;i<reg->bytes.size();++i){const auto index=*reg->byte_order==ByteOrder::little?reg->bytes.size()-1-i:i;value=(value<<8)|std::to_integer<unsigned>(reg->bytes[index]);} return value;
        }
        return syntax("expected a register, integer, !, or parenthesized expression");
    }
};
}

struct DebugSession::Impl {
    explicit Impl(std::unique_ptr<Backend> value) : backend(std::move(value)) {}
    std::unique_ptr<Backend> backend;
    SessionState state = SessionState::idle;
    std::optional<ProcessInfo> process;
    std::optional<std::string> last_diagnostic;
    std::optional<std::uint64_t> pending_event;
    std::optional<EventKind> pending_event_kind;
    bool notification_ack_pending = false;
    bool interrupt_requested = false;
    std::vector<Breakpoint> breakpoints;
    // Retained only across a running interval, so ignored/conditional/logpoint
    // hits cannot silently turn a filtered continuation into a global one.
    std::optional<std::vector<ThreadResumeAction>> resume_filter;
    bool step_resume = false;
};

DebugSession::DebugSession(std::unique_ptr<Backend> backend) : impl_(std::make_unique<Impl>(std::move(backend))) {}
DebugSession::~DebugSession() { if (impl_ && impl_->backend && impl_->process) (void)detach(); }
DebugSession::DebugSession(DebugSession&&) noexcept = default;
DebugSession& DebugSession::operator=(DebugSession&&) noexcept = default;
SessionState DebugSession::state() const noexcept { return impl_->state; }
const std::optional<ProcessInfo>& DebugSession::process() const noexcept { return impl_->process; }
const std::optional<std::string>& DebugSession::last_diagnostic() const noexcept { return impl_->last_diagnostic; }
Result<std::vector<ProcessInfo>> DebugSession::processes() {
    if (!impl_->backend) return invalid_state("process enumeration");
    auto result = impl_->backend->processes();
    if (result && result.value().size() > max_inspection_processes)
        return Error{ErrorCode::resource_limit, "process enumeration exceeds the inspection limit"};
    return result;
}

Result<ProcessInfo> DebugSession::launch(const Target& target) {
    if ((impl_->state != SessionState::idle && impl_->state != SessionState::detached) || !impl_->backend)
        return invalid_state("launch");
    auto result = impl_->backend->launch(target);
    if (result) { impl_->resume_filter.reset(); impl_->step_resume = false; }
    if (result) { impl_->process = result.value(); impl_->state = SessionState::running; impl_->pending_event.reset(); impl_->pending_event_kind.reset(); impl_->notification_ack_pending = false; impl_->interrupt_requested = false; impl_->breakpoints.clear(); }
    return result;
}
Result<ProcessInfo> DebugSession::attach(ProcessId id) {
    if ((impl_->state != SessionState::idle && impl_->state != SessionState::detached) || !impl_->backend || id == 0)
        return invalid_state("attach");
    auto result = impl_->backend->attach(id);
    if (result) { impl_->resume_filter.reset(); impl_->step_resume = false; }
    if (result) { impl_->process = result.value(); impl_->state = SessionState::running; impl_->pending_event.reset(); impl_->pending_event_kind.reset(); impl_->notification_ack_pending = false; impl_->interrupt_requested = false; impl_->breakpoints.clear(); }
    return result;
}
Result<ProcessInfo> DebugSession::connect_remote(std::string_view host, std::uint16_t port) {
    if ((impl_->state != SessionState::idle && impl_->state != SessionState::detached) || !impl_->backend || host.empty() || port == 0)
        return invalid_state("connect_remote");
    auto result = impl_->backend->connect_remote(host, port);
    if (result) { impl_->resume_filter.reset(); impl_->step_resume = false; }
    if (result) { impl_->process = result.value(); impl_->state = SessionState::running; impl_->pending_event.reset(); impl_->pending_event_kind.reset(); impl_->notification_ack_pending = false; impl_->interrupt_requested = false; impl_->breakpoints.clear(); }
    return result;
}
Result<ProcessInfo> DebugSession::attach_remote_process(ProcessId process) {
    if (!impl_->backend || process == 0 ||
        (impl_->state != SessionState::running && impl_->state != SessionState::stopped &&
         impl_->state != SessionState::exited &&
         !(impl_->state == SessionState::detached && !impl_->process)))
        return invalid_state("remote process attach");
    auto result = impl_->backend->attach_remote_process(process);
    if (result) {
        impl_->resume_filter.reset();
        impl_->step_resume = false;
        impl_->process = result.value();
        // vAttach supplies a fresh initial stop for the newly selected inferior.
        impl_->pending_event.reset();
        impl_->pending_event_kind.reset();
        impl_->notification_ack_pending = false;
        impl_->interrupt_requested = false;
        impl_->breakpoints.clear();
        impl_->state = SessionState::running;
    }
    return result;
}
Status DebugSession::detach_remote_process(ProcessId process) {
    if (!impl_->backend || !impl_->process || process == 0 || process == impl_->process->id ||
        (impl_->state != SessionState::running && impl_->state != SessionState::stopped &&
         impl_->state != SessionState::exited))
        return invalid_state("secondary remote process detach");
    return impl_->backend->detach_remote_process(process);
}
Status DebugSession::terminate() {
    if (!impl_->backend || !impl_->process ||
        (impl_->state != SessionState::running && impl_->state != SessionState::stopped))
        return invalid_state("terminate");
    auto result = impl_->backend->terminate();
    if (result) {
        impl_->pending_event.reset();
        impl_->pending_event_kind.reset();
        impl_->notification_ack_pending = false;
        impl_->interrupt_requested = false;
        impl_->breakpoints.clear();
        impl_->state = SessionState::exited;
    }
    return result;
}
Status DebugSession::detach() {
    if (!impl_->backend || !impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped && impl_->state != SessionState::exited))
        return invalid_state("detach");
    impl_->last_diagnostic.reset();
    if (impl_->backend->supports_remote_current_process_detach() && impl_->breakpoints.empty()) {
        const auto current = impl_->process->id;
        auto listed = impl_->backend->processes();
        if (listed) {
            const auto next = std::find_if(listed.value().begin(), listed.value().end(),
                [current](const ProcessInfo& p) { return p.id != current; });
            if (next != listed.value().end()) {
                const auto next_id = next->id;
                auto detached = impl_->backend->detach_remote_current_process(current);
                if (detached) {
                    impl_->process.reset(); impl_->pending_event.reset(); impl_->pending_event_kind.reset(); impl_->notification_ack_pending = false; impl_->interrupt_requested = false;
                    impl_->breakpoints.clear(); impl_->state = SessionState::detached;
                    auto attached = attach_remote_process(next_id);
                    if (attached) return std::monostate{};
                    // The old inferior is already detached. End the RSP connection
                    // if selecting the remaining one fails, avoiding an orphaned session.
                    auto cleanup = impl_->backend->detach();
                    impl_->last_diagnostic = cleanup
                        ? "selected inferior detached, but attaching the remaining inferior failed; remote session was closed"
                        : "selected inferior detached and attaching the remaining inferior failed; remote cleanup also failed, so the connection may remain available for another attach";
                    return attached.error();
                }
                if (detached.error().code != ErrorCode::unsupported) return detached;
                impl_->last_diagnostic = "server rejected PID-specific detach; detached the whole remote session, including remaining inferiors";
            } else {
                impl_->last_diagnostic = "no other listed inferior remained; detached the remote session";
            }
        } else {
            impl_->last_diagnostic = "remote process list unavailable; detached the whole remote session";
        }
    } else if (impl_->backend->supports_remote_current_process_detach() && !impl_->breakpoints.empty()) {
        impl_->last_diagnostic = "session breakpoints prevent selecting another inferior; detached the remote session";
    }
    auto result = impl_->backend->detach();
    if (!result && impl_->last_diagnostic &&
        impl_->last_diagnostic->find("server rejected PID-specific detach") == 0)
        *impl_->last_diagnostic += "; whole-session detach failed: " + result.error().message;
    if (result) { impl_->process.reset(); impl_->pending_event.reset(); impl_->pending_event_kind.reset(); impl_->notification_ack_pending = false; impl_->interrupt_requested = false; impl_->breakpoints.clear(); impl_->state = SessionState::detached; }
    return result;
}
Status DebugSession::request_interrupt() {
    if (!impl_->backend || !impl_->process || impl_->state != SessionState::running || impl_->pending_event)
        return invalid_state("request_interrupt");
    if (impl_->interrupt_requested)
        return Error{ErrorCode::busy, "a target interrupt is already pending"};
    auto result = impl_->backend->request_interrupt();
    if (result) impl_->interrupt_requested = true;
    return result;
}
Result<DebugEvent> DebugSession::wait_event(std::chrono::milliseconds timeout) {
    const bool queued_notification = impl_->state == SessionState::stopped && impl_->notification_ack_pending;
    if (!impl_->backend || (impl_->state != SessionState::running && !queued_notification) || impl_->pending_event)
        return invalid_state("wait_event");
    const auto started = std::chrono::steady_clock::now();
    auto remaining = timeout;
    for (;;) {
        auto result = impl_->backend->wait_event(remaining);
        if (!result) return result;
        impl_->notification_ack_pending = false;
        impl_->interrupt_requested = false;
        auto event = std::move(result.value());
        if (event.message.size() > max_debug_event_message_bytes) {
            event.message.resize(max_debug_event_message_bytes - truncated_text.size());
            event.message += truncated_text;
        }
        bool suppress = event.kind == EventKind::breakpoint && !event.breakpoint_ids.empty();
        bool matched_logpoint = false;
        std::string log_message;
        std::set<BreakpointId> seen;
        bool owned_hit = false;
        if (suppress) {
            if (event.breakpoint_ids.size() > max_breakpoint_event_ids) {
                suppress = false;
                append_bounded(event.message,
                    " [too many breakpoint IDs; condition/logpoint processing skipped]");
            }
            for (const auto id : event.breakpoint_ids) {
                if (!suppress) break;
                if (!seen.insert(id).second) continue;
                const auto found = std::find_if(impl_->breakpoints.begin(), impl_->breakpoints.end(),
                    [id](const Breakpoint& bp) { return bp.id == id; });
                if (found == impl_->breakpoints.end()) { suppress = false; continue; }
                owned_hit = true;
                if (found->hit_count != UINT64_MAX) ++found->hit_count;
                bool passes = found->hit_count > found->ignore_count;
                if (passes && !found->condition.empty()) {
                    auto regs = impl_->backend->read_registers(event.thread);
                    if (!regs) { append_bounded(event.message, " [condition unavailable: " + regs.error().message + "]"); suppress = false; continue; }
                    const auto byte_order_register = std::find_if(regs.value().begin(), regs.value().end(),
                        [](const auto& reg) { return reg.byte_order.has_value(); });
                    const auto target_byte_order = byte_order_register == regs.value().end()
                        ? std::optional<ByteOrder>{} : byte_order_register->byte_order;
                    ConditionParser parser(found->condition, regs.value(),
                        [this, target_byte_order](std::uint64_t address, std::size_t width) -> Result<std::uint64_t> {
                            if (!target_byte_order)
                                return Error{ErrorCode::unsupported, "condition: target byte order is unknown for memory reads"};
                            auto bytes = impl_->backend->read_memory(address, width);
                            if (!bytes) return Error{bytes.error().code, "condition memory read failed: " + bytes.error().message};
                            if (bytes.value().size() != width)
                                return Error{ErrorCode::io, "condition memory read returned fewer bytes than requested"};
                            std::uint64_t value = 0;
                            for (std::size_t i = 0; i < width; ++i) {
                                const auto index = *target_byte_order == ByteOrder::little ? width - 1 - i : i;
                                value = (value << 8) | std::to_integer<unsigned>(bytes.value()[index]);
                            }
                            return value;
                        });
                    auto value = parser.evaluate();
                    if (!value) { append_bounded(event.message, " [condition error: " + value.error().message + "]"); suppress = false; continue; }
                    passes = value.value() != 0;
                }
                if (passes && found->logpoint) {
                    matched_logpoint = true;
                    if (!found->log_message.empty()) {
                        if (!log_message.empty()) append_bounded(log_message, " | ");
                        append_bounded(log_message, found->log_message);
                    }
                }
                else if (passes) suppress = false;
            }
            suppress = suppress && owned_hit;
        }
        if (matched_logpoint && !suppress) append_bounded(event.message, " [matching logpoint also fired]");
        if (suppress && impl_->step_resume) {
            // A breakpoint encountered by a user step is still a stopping
            // instruction. Reissuing the step could execute an extra one.
            suppress = false;
            append_bounded(event.message, " [breakpoint retained at the end of a step]");
        }
        if (suppress) {
            // This was one of the configured ignored hits. Consume the stop
            // through the exact backend event token and continue waiting.
            Status resumed = std::monostate{};
            if (impl_->resume_filter) {
                const auto &filter = *impl_->resume_filter;
                resumed = impl_->backend->resume_threads_event(event.sequence, filter);
                if (!resumed && resumed.error().code == ErrorCode::unsupported && filter.size() == 1 &&
                    filter.front().thread == event.thread && filter.front().kind == ThreadResumeKind::continue_execution)
                    resumed = impl_->backend->continue_thread_event(event.sequence, event.thread, ContinueStatus::handled);
            } else resumed = impl_->backend->continue_event(event.sequence, ContinueStatus::handled);
            if (!resumed) {
                // Keep the owned event visible and retryable. In particular,
                // never retry a rejected exact schedule as global continue.
                append_bounded(event.message, " [automatic breakpoint continuation failed: " + resumed.error().message + "]");
            } else {
                if (matched_logpoint) {
                    event.kind = EventKind::output;
                    if (log_message.empty()) {
                        event.message = "Logpoint at 0x";
                        static constexpr char digits[] = "0123456789ABCDEF";
                        char address[17]{}; auto value=event.address; int at=16; do { address[--at]=digits[value&15]; value>>=4; } while(value && at>0);
                        event.message += address+at;
                        if (!event.breakpoint_ids.empty()) event.message += " (IDs " + std::to_string(event.breakpoint_ids.front()) + ")";
                    } else {
                        event.message = std::move(log_message);
                    }
                    impl_->state = SessionState::running;
                    return event;
                }
                if (timeout != std::chrono::milliseconds::max()) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - started);
                    remaining = elapsed >= timeout ? std::chrono::milliseconds::zero() : timeout - elapsed;
                }
                continue;
            }
        }
        impl_->resume_filter.reset();
        impl_->step_resume = false;
        impl_->pending_event = event.sequence;
        impl_->pending_event_kind = event.kind;
        impl_->state = event.kind == EventKind::process_exited ? SessionState::exited : SessionState::stopped;
        return event;
    }
}
Status DebugSession::continue_execution(std::uint64_t sequence, ContinueStatus status) {
    if (!impl_->backend || !impl_->pending_event || *impl_->pending_event != sequence || impl_->state == SessionState::detached)
        return invalid_state("continue");
    auto result = impl_->backend->continue_event(sequence, status);
    if (result) {
        impl_->resume_filter.reset();
        impl_->step_resume = false;
        const bool keep_stopped = impl_->pending_event_kind &&
            impl_->backend->acknowledgement_keeps_target_stopped(*impl_->pending_event_kind);
        impl_->pending_event.reset();
        impl_->pending_event_kind.reset();
        if (impl_->state == SessionState::exited) impl_->breakpoints.clear();
        if (impl_->state == SessionState::stopped) {
            impl_->state = keep_stopped ? SessionState::stopped : SessionState::running;
            impl_->notification_ack_pending = keep_stopped;
        }
    }
    return result;
}
Status DebugSession::continue_thread_execution(std::uint64_t sequence, ThreadId thread, ContinueStatus status) {
    if (!impl_->backend || !impl_->pending_event || *impl_->pending_event != sequence ||
        impl_->state != SessionState::stopped || thread == 0)
        return invalid_state("thread-qualified continue");
    std::vector<ThreadResumeAction> filter{{thread, ThreadResumeKind::continue_execution}};
    auto result = impl_->backend->continue_thread_event(sequence, thread, status);
    if (result) {
        impl_->resume_filter = std::move(filter);
        impl_->step_resume = false;
        const bool keep_stopped = impl_->pending_event_kind &&
            impl_->backend->acknowledgement_keeps_target_stopped(*impl_->pending_event_kind);
        impl_->pending_event.reset();
        impl_->pending_event_kind.reset();
        impl_->state = keep_stopped ? SessionState::stopped : SessionState::running;
        impl_->notification_ack_pending = keep_stopped;
    }
    return result;
}
Status DebugSession::single_step_execution(std::uint64_t sequence, ContinueStatus status) {
    if (!impl_->backend || !impl_->pending_event || *impl_->pending_event != sequence ||
        impl_->state != SessionState::stopped)
        return invalid_state("single_step");
    auto result = impl_->backend->single_step_event(sequence, status);
    if (result) {
        impl_->resume_filter.reset();
        impl_->step_resume = true;
        impl_->pending_event.reset();
        impl_->pending_event_kind.reset();
        impl_->notification_ack_pending = false;
        impl_->state = SessionState::running;
    }
    return result;
}
Status DebugSession::resume_threads(std::uint64_t sequence, std::span<const ThreadResumeAction> actions) {
    if (!impl_->backend || !impl_->pending_event || *impl_->pending_event != sequence ||
        impl_->state != SessionState::stopped)
        return invalid_state("thread resume schedule");
    if (actions.empty() || actions.size() > max_inspection_threads)
        return Error{ErrorCode::invalid_argument, "thread resume schedule must contain 1 to 4096 actions"};
    std::set<ThreadId> threads;
    bool resumes_any_thread = false;
    for (const auto& action : actions) {
        if (action.thread == 0 || !threads.insert(action.thread).second)
            return Error{ErrorCode::invalid_argument, "thread resume schedule contains an invalid or duplicate thread"};
        if (action.kind != ThreadResumeKind::continue_execution &&
            action.kind != ThreadResumeKind::single_step && action.kind != ThreadResumeKind::stop)
            return Error{ErrorCode::invalid_argument, "thread resume schedule contains an unknown action"};
        resumes_any_thread = resumes_any_thread || action.kind != ThreadResumeKind::stop;
    }
    if (!resumes_any_thread)
        return Error{ErrorCode::invalid_argument, "thread resume schedule must resume or step at least one thread"};
    std::vector<ThreadResumeAction> filter(actions.begin(), actions.end());
    const bool stepping = std::any_of(actions.begin(), actions.end(), [](const auto &action) {
        return action.kind == ThreadResumeKind::single_step;
    });
    auto result = impl_->backend->resume_threads_event(sequence, actions);
    if (result) {
        const bool keep_stopped = impl_->pending_event_kind &&
            impl_->backend->acknowledgement_keeps_target_stopped(*impl_->pending_event_kind);
        impl_->resume_filter = std::move(filter);
        impl_->step_resume = stepping;
        impl_->pending_event.reset();
        impl_->pending_event_kind.reset();
        impl_->notification_ack_pending = keep_stopped;
        impl_->state = keep_stopped ? SessionState::stopped : SessionState::running;
    }
    return result;
}
Result<std::vector<std::byte>> DebugSession::read_memory(std::uint64_t address, std::size_t size) {
    if (!impl_->backend || !impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped)) return invalid_state("read_memory");
    if (size > max_inspection_read || address > UINT64_MAX - size)
        return Error{ErrorCode::invalid_argument, "memory inspection range exceeds the 1 MiB limit or wraps the address space"};
    return impl_->backend->read_memory(address, size);
}
Status DebugSession::write_memory(std::uint64_t address, std::span<const std::byte> bytes) {
    if (!impl_->backend || !impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped)) return invalid_state("write_memory");
    return impl_->backend->write_memory(address, bytes);
}
Result<MemorySearchReport> DebugSession::search_memory(const MemorySearchPattern& pattern,
    const MemorySearchOptions& options, std::stop_token cancellation) {
    return debugger::search_memory(*this, pattern, options, cancellation);
}
Result<std::vector<ThreadInfo>> DebugSession::threads() {
    if (!impl_->backend || !impl_->process || impl_->state == SessionState::detached || impl_->state == SessionState::idle) return invalid_state("threads");
    auto result = impl_->backend->threads();
    if (result && result.value().size() > max_inspection_threads)
        return Error{ErrorCode::resource_limit, "thread enumeration exceeds the inspection limit"};
    return result;
}
Result<std::vector<ThreadRunState>> DebugSession::thread_run_states() {
    if (!impl_->backend || !impl_->process || impl_->state == SessionState::detached || impl_->state == SessionState::idle)
        return invalid_state("thread run-state snapshot");
    auto result = impl_->backend->thread_run_states();
    if (result && result.value().size() > max_inspection_threads)
        return Error{ErrorCode::resource_limit, "thread run-state snapshot exceeds the inspection limit"};
    return result;
}
Result<std::vector<ModuleInfo>> DebugSession::modules() {
    if (!impl_->backend || !impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped)) return invalid_state("modules");
    auto result = impl_->backend->modules();
    if (result && result.value().size() > max_inspection_modules)
        return Error{ErrorCode::invalid_argument, "backend returned more than 4096 modules"};
    return result;
}
Result<std::vector<MemoryRegion>> DebugSession::memory_regions() {
    if (!impl_->backend || !impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped)) return invalid_state("memory_regions");
    auto result = impl_->backend->memory_regions();
    if (result && result.value().size() > max_inspection_memory_regions)
        return Error{ErrorCode::invalid_argument, "backend returned more than 65536 memory regions"};
    return result;
}
Result<std::vector<RegisterValue>> DebugSession::read_registers(ThreadId thread) {
    if (!impl_->backend || !impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped)) return invalid_state("read_registers");
    return impl_->backend->read_registers(thread);
}
Result<std::uint64_t> DebugSession::evaluate_expression(ThreadId thread, std::string_view expression) {
    if (!impl_->backend || !impl_->process || impl_->state != SessionState::stopped)
        return invalid_state("evaluate_expression");
    if (!thread) return Error{ErrorCode::invalid_argument, "expression requires a nonzero thread id"};
    if (expression.size() > 256) return Error{ErrorCode::resource_limit, "expression exceeds 256 characters"};
    auto run_states = thread_run_states();
    if (run_states) {
        const auto selected = std::find_if(run_states.value().begin(), run_states.value().end(),
            [thread](const auto &state) { return state.thread == thread; });
        if (selected == run_states.value().end())
            return Error{ErrorCode::invalid_argument, "expression thread is not present in the current run-state snapshot"};
        if (selected->state != ThreadState::stopped)
            return Error{ErrorCode::invalid_argument, "expression requires a stopped thread"};
    } else if (run_states.error().code != ErrorCode::unsupported) {
        return run_states.error();
    }
    auto registers = impl_->backend->read_registers(thread);
    if (!registers) return registers.error();
    const auto byte_order_register = std::find_if(registers.value().begin(), registers.value().end(),
        [](const auto &reg) { return reg.byte_order.has_value(); });
    const auto target_byte_order = byte_order_register == registers.value().end()
        ? std::optional<ByteOrder>{} : byte_order_register->byte_order;
    ConditionParser parser(expression, registers.value(),
        [this, target_byte_order](std::uint64_t address, std::size_t width) -> Result<std::uint64_t> {
            if (!target_byte_order)
                return Error{ErrorCode::unsupported, "expression: target byte order is unknown for memory reads"};
            auto bytes = read_memory(address, width);
            if (!bytes) return Error{bytes.error().code, "expression memory read failed: " + bytes.error().message};
            if (bytes.value().size() != width)
                return Error{ErrorCode::io, "expression memory read returned fewer bytes than requested"};
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < width; ++i) {
                const auto index = *target_byte_order == ByteOrder::little ? width - 1 - i : i;
                value = (value << 8) | std::to_integer<unsigned>(bytes.value()[index]);
            }
            return value;
        }, "expression");
    return parser.evaluate();
}
Status DebugSession::write_registers(ThreadId thread, std::span<const RegisterValue> registers) {
    if (!impl_->backend || !impl_->process || impl_->state != SessionState::stopped) return invalid_state("write_registers");
    return impl_->backend->write_registers(thread, registers);
}
Result<Breakpoint> DebugSession::add_breakpoint(std::uint64_t address, BreakpointKind kind, std::uint8_t size) {
    if (!impl_->backend || !impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped)) return invalid_state("add_breakpoint");
    Result<Breakpoint> result = (kind == BreakpointKind::execute || kind == BreakpointKind::read ||
        kind == BreakpointKind::write || kind == BreakpointKind::access)
        ? impl_->backend->add_hardware_breakpoint(address, kind, size)
        : impl_->backend->add_breakpoint(address, kind);
    if (result) impl_->breakpoints.push_back(result.value());
    return result;
}
Status DebugSession::remove_breakpoint(BreakpointId id) {
    if (!impl_->backend || !impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped)) return invalid_state("remove_breakpoint");
    const auto found = std::find_if(impl_->breakpoints.begin(), impl_->breakpoints.end(),
        [id](const Breakpoint& breakpoint) { return breakpoint.id == id; });
    if (found == impl_->breakpoints.end())
        return Error{ErrorCode::invalid_argument, "breakpoint id is not owned by this debug session"};
    auto result = impl_->backend->remove_breakpoint(id);
    if (result) impl_->breakpoints.erase(found);
    return result;
}
Status DebugSession::set_breakpoint_enabled(BreakpointId id, bool enabled) {
    if (!impl_->backend || !impl_->process ||
        (impl_->state != SessionState::running && impl_->state != SessionState::stopped))
        return invalid_state("set_breakpoint_enabled");
    const auto found = std::find_if(impl_->breakpoints.begin(), impl_->breakpoints.end(),
        [id](const Breakpoint& breakpoint) { return breakpoint.id == id; });
    if (found == impl_->breakpoints.end())
        return Error{ErrorCode::invalid_argument, "breakpoint id is not owned by this debug session"};
    if (found->enabled == enabled) return std::monostate{};
    auto result = impl_->backend->set_breakpoint_enabled(id, enabled);
    if (result) found->enabled = enabled;
    return result;
}
Status DebugSession::set_breakpoint_ignore_count(BreakpointId id, std::uint64_t count) {
    if (!impl_->process || (impl_->state != SessionState::running && impl_->state != SessionState::stopped))
        return invalid_state("set_breakpoint_ignore_count");
    const auto found = std::find_if(impl_->breakpoints.begin(), impl_->breakpoints.end(),
        [id](const Breakpoint& breakpoint) { return breakpoint.id == id; });
    if (found == impl_->breakpoints.end())
        return Error{ErrorCode::invalid_argument, "breakpoint id is not owned by this debug session"};
    found->ignore_count = count;
    return std::monostate{};
}
Status DebugSession::set_breakpoint_hit_count(BreakpointId id, std::uint64_t count) {
    const auto found = std::find_if(impl_->breakpoints.begin(), impl_->breakpoints.end(),
        [id](const Breakpoint& breakpoint) { return breakpoint.id == id; });
    if (found == impl_->breakpoints.end())
        return Error{ErrorCode::invalid_argument, "breakpoint id is not owned by this debug session"};
    found->hit_count = count;
    return std::monostate{};
}
Status DebugSession::set_breakpoint_condition(BreakpointId id, std::string condition) {
    if (condition.size() > 256) return Error{ErrorCode::resource_limit, "condition exceeds 256 characters"};
    const auto found=std::find_if(impl_->breakpoints.begin(),impl_->breakpoints.end(),[id](const auto& bp){return bp.id==id;});
    if(found==impl_->breakpoints.end())return Error{ErrorCode::invalid_argument,"breakpoint id is not owned by this debug session"};
    found->condition=std::move(condition); return std::monostate{};
}
Status DebugSession::set_breakpoint_logpoint(BreakpointId id, bool enabled) {
    const auto found=std::find_if(impl_->breakpoints.begin(),impl_->breakpoints.end(),[id](const auto& bp){return bp.id==id;});
    if(found==impl_->breakpoints.end())return Error{ErrorCode::invalid_argument,"breakpoint id is not owned by this debug session"};
    found->logpoint=enabled; return std::monostate{};
}
Status DebugSession::set_breakpoint_logpoint(BreakpointId id, bool enabled, std::string message) {
    if (message.size() > 1024) return Error{ErrorCode::resource_limit, "logpoint message exceeds 1024 bytes"};
    if (!impl_->backend || impl_->state == SessionState::detached) return invalid_state("set_breakpoint_logpoint");
    const auto found = std::find_if(impl_->breakpoints.begin(), impl_->breakpoints.end(),
        [id](const Breakpoint& breakpoint) { return breakpoint.id == id; });
    if (found == impl_->breakpoints.end()) return Error{ErrorCode::invalid_argument, "unknown breakpoint ID"};
    found->logpoint = enabled;
    found->log_message = std::move(message);
    return std::monostate{};
}
std::vector<Breakpoint> DebugSession::breakpoints() const { return impl_->breakpoints; }
} // namespace hexlab::debugger
