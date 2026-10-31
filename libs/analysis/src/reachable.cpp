#include "hexlab/analysis/analysis.hpp"
// Keep this translation unit rebuilt when the shared instruction-flow policy changes.
#include "instruction_flow.hpp"
#include "control_target.hpp"
#include "dex_switch_internal.hpp"
#include "hexlab/analysis/relocations.hpp"
#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <tuple>

namespace hexlab {
namespace {
constexpr std::size_t native_instruction_window = 15;
constexpr std::size_t wasm_instruction_window = 32;
std::size_t instruction_window(DecodeContext context) noexcept {
    return context.architecture == Architecture::wasm && context.mode == ExecutionMode::wasm32
        ? wasm_instruction_window : native_instruction_window;
}
bool arm_predicate_can_skip(const Instruction &instruction) {
    return instruction.arm && (instruction.arm->predicate == ArmPredicate::condition ||
                               instruction.arm->predicate == ArmPredicate::unknown_it);
}

struct FixupFailure {
    Error error;
};
struct DomainAddressLess {
    bool operator()(Address a, Address b) const noexcept {
        return a.space.value < b.space.value || (a.space == b.space && a.offset < b.offset);
    }
};
struct WorkItem {
    Address address;
    ThumbITState thumb_it;
};
struct WorkItemLess {
    bool operator()(const WorkItem &a, const WorkItem &b) const noexcept {
        return std::tie(a.address.space.value, a.address.offset, a.thumb_it.known, a.thumb_it.bits) <
               std::tie(b.address.space.value, b.address.offset, b.thumb_it.known, b.thumb_it.bits);
    }
};
bool backed_executable(const Image &image, Address address) {
    const auto *segment = image.segment_at(address);
    return segment && segment->executable && address.offset - segment->begin.offset < segment->file_size;
}
std::optional<Address> dex_direct_call_target(const Instruction &instruction, const Image &image,
                                              const ImageMetadata &metadata) {
    if (instruction.context.architecture != Architecture::dex || instruction.flow != FlowKind::call ||
        !metadata.dex)
        return {};
    const auto bytes = instruction.encoded_bytes();
    if (bytes.size() < 4)
        return {};
    const auto opcode = std::to_integer<std::uint8_t>(bytes[0]);
    // Virtual/interface dispatch depends on the receiver; invoke-super also
    // requires class lookup. Only direct and static method IDs resolve here.
    if (opcode != 0x70 && opcode != 0x71 && opcode != 0x76 && opcode != 0x77)
        return {};
    const auto method_index = static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[2])) |
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[3])) << 8);
    const auto &methods = metadata.dex->code;
    const auto method = std::lower_bound(methods.begin(), methods.end(), method_index,
        [](const DexMethodCode &candidate, std::uint32_t index) { return candidate.method_index < index; });
    if (method == methods.end() || method->method_index != method_index || method_index == UINT32_MAX)
        return {};
    const Address target{AddressSpaceId{method_index + 1}, 0};
    const auto *segment = image.segment_at(target);
    const auto context = image.context_at(target);
    if (!segment || !segment->executable || !context || context.value().architecture != Architecture::dex ||
        context.value().mode != ExecutionMode::dex)
        return {};
    return target;
}
class InstructionByteCache {
  public:
    explicit InstructionByteCache(const Image &image, std::size_t window_capacity = 15)
        : image_(image), window_capacity_(window_capacity) {}

    Result<std::size_t> read(Address address, std::span<std::byte> bytes) {
        std::size_t copied = 0;
        while (copied < bytes.size()) {
            const auto at = advance(address, copied);
            if (!at)
                break;
            const auto *segment = image_.segment_at(at.value());
            if (!segment || !segment->executable)
                break;
            const auto relative = at.value().offset - segment->begin.offset;
            if (relative >= segment->file_size)
                break;
            const auto file_offset = segment->file_begin.value + relative;
            if (file_offset < window_begin_ || file_offset - window_begin_ >= window_.bytes.size()) {
                const auto request = static_cast<std::size_t>(std::min<std::uint64_t>(
                    window_capacity_, segment->file_size - relative));
                // Prefetch only through the next policy boundary. A cached read
                // must never make encrypted, excluded, zero-fill, or adjacent
                // segment bytes available to the decoder.
                const auto safe = static_cast<std::size_t>(image_.code_window(at.value(), request));
                if (!safe)
                    break;
                auto input = image_.storage()->read_at({file_offset}, safe);
                if (!input)
                    return input.error();
                if (input.value().bytes.size() != safe)
                    return Error{ErrorCode::io, "Instruction backing returned a short read"};
                window_ = std::move(input.value());
                window_begin_ = file_offset;
            }
            const auto in_window = static_cast<std::size_t>(file_offset - window_begin_);
            const auto available = std::min<std::size_t>(bytes.size() - copied, window_.bytes.size() - in_window);
            // A window loaded for another virtual alias may have different code
            // policy; cap every use at this address's own permitted boundary.
            const auto permitted = static_cast<std::size_t>(image_.code_window(at.value(), available));
            const auto amount = std::min(available, permitted);
            if (!amount)
                break;
            std::copy_n(window_.bytes.begin() + static_cast<std::ptrdiff_t>(in_window), amount,
                        bytes.begin() + static_cast<std::ptrdiff_t>(copied));
            copied += amount;
        }
        return copied;
    }

  private:
    const Image &image_;
    std::size_t window_capacity_;
    std::uint64_t window_begin_ = 0;
    ByteView window_{};
};
} // namespace
Result<DecodeResult> decode_analysis_instruction(DecodeContext context, std::span<const std::byte> bytes,
                                                 Address address, const AnalysisOptions& options) {
    auto builtin = decode_instruction(context, bytes, address);
    if (builtin.status != DecodeStatus::unsupported || builtin.instruction || !options.semantic_decoder ||
        context.mode == ExecutionMode::thumb || context.mode == ExecutionMode::a32)
        return builtin;
    auto extension = options.semantic_decoder(context, address, bytes);
    if (!extension) return extension.error();
    if (!extension.value()) return builtin;
    auto instruction = std::move(*extension.value());
    if (instruction.context != context || instruction.address != address || instruction.opcode != Opcode::opaque ||
        instruction.length == 0 || instruction.length > bytes.size() || instruction.length != instruction.encoded_bytes().size() ||
        instruction.operands.size() > 16 || instruction.operands.size() != instruction.access.size() ||
        instruction.register_reads.size() > 64 || instruction.register_writes.size() > 64 ||
        static_cast<unsigned>(instruction.flow) > static_cast<unsigned>(FlowKind::data) ||
        !std::equal(instruction.encoded_bytes().begin(), instruction.encoded_bytes().end(), bytes.begin()))
        return Error{ErrorCode::integrity, "Semantic decoder returned an invalid instruction record"};
    for (const auto access : instruction.access)
        if (static_cast<unsigned>(access) > static_cast<unsigned>(OperandAccess::address))
            return Error{ErrorCode::integrity, "Semantic decoder returned an invalid operand effect"};
    return DecodeResult{DecodeStatus::decoded, std::move(instruction), {}, true};
}
Result<DecodeResult> decode_at(const Image &image, Address address) {
    auto context = image.context_at(address);
    if (!context)
        return context.error();
    if (!processor_capabilities(context.value()).can_decode)
        return Error{ErrorCode::unsupported, "CPU mode has no enabled decoder"};
    if (!backed_executable(image, address))
        return Error{ErrorCode::out_of_bounds, "Location has no initialized executable bytes"};
    const auto window = instruction_window(context.value());
    std::array<std::byte, wasm_instruction_window> input{};
    InstructionByteCache byte_cache(image, window);
    const auto count = byte_cache.read(address, std::span(input).first(window));
    if (!count)
        return count.error();
    return decode_instruction(context.value(), std::span<const std::byte>(input).first(count.value()), address);
}
Result<AnalysisSnapshot> analyze(const Image &image, const AnalysisOptions &options, std::stop_token stop) {
    return analyze(image, ImageMetadata{}, options, stop);
}
Result<AnalysisSnapshot> analyze(const Image &image, const ImageMetadata &metadata, const AnalysisOptions &options,
                                 std::stop_token stop) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Analysis canceled"};
    const bool arm_profile_flow = image.layout().arm_profile &&
        std::any_of(image.layout().arm_profile->ranges.begin(), image.layout().arm_profile->ranges.end(),
                    [](const auto &range) { return range.kind == ArmCodeKind::a32 || range.kind == ArmCodeKind::thumb; });
    if (!analysis_detail::supports_automatic_flow(image) && !arm_profile_flow)
        return Error{ErrorCode::unsupported, "Reachable instruction analysis requires a supported processor mode"};
    try {
        auto relocation_index = RelocationResolver::create(image, metadata, stop);
        if (!relocation_index)
            return relocation_index.error();
        const auto code_allowed = [&](Address at) {
            if (!backed_executable(image, at) || !image.code_window(at, 1))
                return false;
            const auto allowed = relocation_index.value().code_start(at, stop);
            if (!allowed)
                throw FixupFailure{allowed.error()};
            return allowed.value();
        };
        AnalysisSnapshot output;
        auto terminate = [&](Address address, StopReason reason, const std::string &detail, bool incomplete = true) {
            output.stops.push_back({address, reason, detail});
            if (incomplete) {
                output.code_complete = false;
                output.diagnostics.push_back({DiagnosticSeverity::warning, detail, address});
            }
        };
        std::deque<WorkItem> pending;
        // A single page bounds sparse-root overfetch while still batching the
        // many sequential instruction reads in ordinary code paths.
        InstructionByteCache byte_cache(image, 4 * 1024);
        std::set<WorkItem, WorkItemLess> visited;
        std::map<Address, ThumbITState, DomainAddressLess> arm_it_at;
        const auto root_it_state = [&](Address at) {
            if (!image.layout().arm_profile)
                return ThumbITState{};
            const auto found = std::find_if(image.layout().arm_profile->roots.begin(),
                                            image.layout().arm_profile->roots.end(),
                                            [&](const auto &root) { return root.at == at; });
            return found != image.layout().arm_profile->roots.end() && found->mode == ExecutionMode::thumb &&
                           found->known_thumb_it_clear
                       ? ThumbITState{true, 0}
                       : ThumbITState{};
        };
        const auto queue_root = [&](Address at) { pending.push_back({at, root_it_state(at)}); };
        for (auto entry : image.layout().entries) {
            queue_root(entry);
            if (code_allowed(entry))
                output.candidates.push_back(entry);
        }
        if (image.layout().arm_profile)
            for (const auto &root : image.layout().arm_profile->roots) {
                queue_root(root.at);
                if (code_allowed(root.at))
                    output.candidates.push_back(root.at);
            }
        // PE exports are public callable entry points even when stripped
        // symbol/debug metadata provides no other root for the function.
        // Forwarded exports have no local address and are intentionally
        // absent from this image's reachable code.
        for (const auto &symbol : metadata.exports) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Reachable PE export analysis canceled"};
            if (symbol.address && code_allowed(*symbol.address)) {
                queue_root(*symbol.address);
                output.candidates.push_back(*symbol.address);
            }
        }
        if (metadata.dex)
            for (const auto &method : metadata.dex->code) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Reachable DEX method analysis canceled"};
                if (method.method_index == UINT32_MAX)
                    continue;
                const Address entry{AddressSpaceId{method.method_index + 1}, 0};
                if (code_allowed(entry)) {
                    queue_root(entry);
                    output.candidates.push_back(entry);
                }
            }
        if (metadata.elf)
            for (const auto &symbol : metadata.elf->symbols) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Reachable ELF analysis canceled"};
                if (symbol.type == 2 && symbol.state == ElfSymbolState::defined && symbol.address &&
                    code_allowed(*symbol.address)) {
                    queue_root(*symbol.address);
                    output.candidates.push_back(*symbol.address);
                }
            }
        if (metadata.macho) {
            for (const auto &symbol : metadata.macho->dyld_exports) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Reachable Mach-O export analysis canceled"};
                if (!symbol.is_definition())
                    continue;
                for (const auto at : {symbol.address, symbol.resolver_address})
                    if (at && code_allowed(*at)) {
                        queue_root(*at);
                        output.candidates.push_back(*at);
                    }
            }
            for (const auto &symbol : metadata.macho->symbols) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Reachable Mach-O analysis canceled"};
                if (symbol.code && symbol.address && code_allowed(*symbol.address)) {
                    queue_root(*symbol.address);
                    output.candidates.push_back(*symbol.address);
                }
            }
            for (const auto &start : metadata.macho->function_starts) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Reachable Mach-O analysis canceled"};
                if (start.address && code_allowed(*start.address)) {
                    queue_root(*start.address);
                    output.candidates.push_back(*start.address);
                }
            }
        }
        // TLS callbacks execute independently of the PE entry point. Match
        // function discovery's load-base translation so entry-seeded
        // reachable analysis includes those loader-invoked code roots too.
        if (metadata.pe && metadata.pe->tls) {
            auto load_base = metadata.preferred_base;
            for (const auto &segment : image.layout().segments)
                if (segment.name == "headers") {
                    load_base = segment.begin.offset;
                    break;
                }
            for (const auto &callback : metadata.pe->tls->callbacks) {
                if (stop.stop_requested())
                    return Error{ErrorCode::canceled, "Reachable PE TLS callback analysis canceled"};
                if (callback.rva > UINT64_MAX - load_base)
                    continue;
                const Address at{image.layout().space.id, load_base + callback.rva};
                if (code_allowed(at)) {
                    queue_root(at);
                    output.candidates.push_back(at);
                }
            }
        }
        if (pending.empty())
            terminate({image.layout().space.id, 0}, StopReason::no_entry, "No executable entry points are available");
        while (!pending.empty()) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Reachable analysis canceled"};
            const auto work = pending.front();
            pending.pop_front();
            const auto address = work.address;
            if (visited.contains(work))
                continue;
            if (output.instructions.size() >= options.instruction_budget) {
                terminate(address, StopReason::budget, "Instruction budget reached");
                break;
            }
            visited.insert(work);
            const auto *segment = image.segment_at(address);
            if (!segment) {
                terminate(address, StopReason::unmapped, "Control flow reaches unmapped memory");
                continue;
            }
            if (!segment->executable) {
                terminate(address, StopReason::non_executable, "Control flow reaches non-executable data");
                continue;
            }
            if (address.offset - segment->begin.offset >= segment->file_size) {
                terminate(address, StopReason::uninitialized, "Control flow reaches uninitialized bytes");
                continue;
            }
            if (!image.code_window(address, 1)) {
                terminate(address, StopReason::image_exclusion, "Declared data/encrypted bytes cannot be decoded");
                continue;
            }
            const auto start_allowed = relocation_index.value().code_start(address, stop);
            if (!start_allowed)
                return start_allowed.error();
            if (!start_allowed.value()) {
                terminate(address, StopReason::macho_dyld, "Runtime fixup storage is not an instruction start");
                continue;
            }
            auto context = image.context_at(address);
            if (!context)
                return context.error();
            const bool arm_mode = context.value().architecture == Architecture::arm &&
                                  (context.value().mode == ExecutionMode::a32 ||
                                   context.value().mode == ExecutionMode::thumb);
            if (arm_mode && context.value().mode == ExecutionMode::thumb) {
                const auto [state, inserted] = arm_it_at.emplace(address, work.thumb_it);
                if (!inserted && state->second != work.thumb_it) {
                    terminate(address, StopReason::unsupported,
                              "Thumb address is reached with conflicting IT states");
                    continue;
                }
            }
            if (!analysis_detail::supports_automatic_flow(context.value()) && !arm_mode) {
                terminate(address, StopReason::unsupported, "Address domain has no enabled decoder");
                continue;
            }
            if (arm_mode && context.value().mode == ExecutionMode::thumb && !work.thumb_it.known) {
                terminate(address, StopReason::unsupported,
                          "Thumb control flow has no source-backed clear IT root or propagated IT state");
                continue;
            }
            const auto decode_window = instruction_window(context.value());
            std::array<std::byte, wasm_instruction_window> input{};
            const auto available = byte_cache.read(address, std::span(input).first(decode_window));
            if (!available)
                return available.error();
            DecodeResult decoded;
            if (arm_mode && context.value().mode == ExecutionMode::thumb) {
                decoded = decode_thumb(std::span<const std::byte>(input).first(available.value()), address,
                                       work.thumb_it);
            } else {
                auto analysis_decode = decode_analysis_instruction(
                    context.value(), std::span<const std::byte>(input).first(available.value()), address, options);
                if (!analysis_decode)
                    return analysis_decode.error();
                decoded = std::move(analysis_decode.value());
            }
            if (!decoded.instruction) {
                terminate(address,
                    decoded.status == DecodeStatus::truncated &&
                                  available.value() == image.code_window(address, decode_window) &&
                                  available.value() < decode_window
                              ? StopReason::image_exclusion
                          : decoded.status == DecodeStatus::unsupported ? StopReason::unsupported
                          : decoded.status == DecodeStatus::invalid     ? StopReason::invalid
                                                                        : StopReason::truncated,
                          decoded.reason);
                continue;
            }
            auto &instruction = *decoded.instruction;
            if (instruction.opcode == Opcode::dex_switch) {
                auto table = function_detail::populate_dex_switch_table(image, instruction, nullptr, stop);
                if (!table && table.error().code == ErrorCode::canceled)
                    return table.error();
                if (!table) {
                    output.complete = false;
                    terminate(address, StopReason::unsupported,
                              "DEX switch payload rejected: " + table.error().message);
                }
            }
            output.instructions.push_back(instruction);
            std::optional<Address> mips_slot;
            if (analysis_detail::has_delay_slot(instruction)) {
                auto slot_at = analysis_detail::delay_slot_address(instruction);
                if (!slot_at) {
                    terminate(address, StopReason::target_overflow, "MIPS delay slot exceeds address model");
                    continue;
                }
                if (!code_allowed(slot_at.value())) {
                    const auto *slot_segment = image.segment_at(slot_at.value());
                    const auto reason = !slot_segment ? StopReason::unmapped
                        : !slot_segment->executable ? StopReason::non_executable
                        : slot_at.value().offset - slot_segment->begin.offset >= slot_segment->file_size
                            ? StopReason::uninitialized : StopReason::image_exclusion;
                    terminate(slot_at.value(), reason,
                              "MIPS control transfer has no permitted initialized delay slot");
                    continue;
                }
                std::optional<Instruction> slot_instruction;
                const auto prior_slot = std::find_if(output.instructions.begin(), output.instructions.end(),
                    [&](const auto &candidate) { return candidate.address == slot_at.value(); });
                if (prior_slot != output.instructions.end()) {
                    if (prior_slot->context != instruction.context) {
                        terminate(slot_at.value(), StopReason::unsupported,
                                  "Previously decoded MIPS delay slot has a conflicting execution context");
                        continue;
                    }
                    slot_instruction = *prior_slot;
                } else {
                    if (output.instructions.size() >= options.instruction_budget) {
                        terminate(address, StopReason::budget, "Instruction budget reached before MIPS delay slot");
                        continue;
                    }
                    std::array<std::byte, 15> slot_input{};
                    auto slot_bytes = byte_cache.read(slot_at.value(), slot_input);
                    if (!slot_bytes) return slot_bytes.error();
                    auto slot_decoded = decode_instruction(instruction.context,
                        std::span<const std::byte>(slot_input).first(slot_bytes.value()), slot_at.value());
                if (!slot_decoded.instruction) {
                        terminate(slot_at.value(), slot_decoded.status == DecodeStatus::truncated ? StopReason::truncated :
                                  slot_decoded.status == DecodeStatus::invalid ? StopReason::invalid : StopReason::unsupported,
                                  "MIPS delay slot: " + slot_decoded.reason);
                        continue;
                }
                slot_instruction = std::move(*slot_decoded.instruction);
                if (slot_instruction->opcode == Opcode::opaque || slot_instruction->opcode == Opcode::x86_opaque) {
                    terminate(slot_at.value(), StopReason::unsupported,
                              "Opaque delay-slot instruction has no trusted control-flow semantics");
                    continue;
                }
            }
                if (slot_instruction->flow != FlowKind::fallthrough || slot_instruction->delay_slots) {
                    terminate(slot_at.value(), StopReason::unsupported,
                              "Control transfer in a MIPS delay slot is unsupported");
                    continue;
                }
                const auto slot_opaque = relocation_index.value().instruction_fixup(*slot_instruction, stop);
                if (!slot_opaque) return slot_opaque.error();
                if (slot_opaque.value()) {
                    terminate(slot_at.value(), StopReason::macho_dyld,
                              "Runtime fixup affects MIPS delay-slot instruction bytes");
                    continue;
                }
                if (prior_slot == output.instructions.end())
                    output.instructions.push_back(*slot_instruction);
                mips_slot = slot_at.value();
                visited.insert(WorkItem{*mips_slot, {}});
                output.edges.push_back({address, *mips_slot, EdgeKind::delay_slot});
            }
            if (instruction.opcode == Opcode::x86_opaque ||
                (instruction.opcode == Opcode::opaque && instruction.operands.empty())) {
                terminate(address, StopReason::unsupported,
                          "Instruction length is known, but typed operand/control-flow semantics are unavailable");
                continue;
            }
            const bool unmodeled_arm_pc_write = arm_mode && instruction.arm && instruction.arm->writes_pc &&
                                                instruction.flow == FlowKind::fallthrough;
            if (unmodeled_arm_pc_write) {
                terminate(address, StopReason::unsupported,
                          "ARM instruction writes PC without a modeled control-flow edge");
            }
            const auto opaque = relocation_index.value().instruction_fixup(instruction, stop);
            if (!opaque)
                return opaque.error();
            if (opaque.value()) {
                terminate(address, StopReason::macho_dyld, "Runtime fixup affects instruction opcode bytes");
                continue;
            }
            const auto next = arm_mode ? advance(address, instruction.length)
                                       : analysis_detail::continuation_address(instruction);
            auto fallthrough = [&] {
                if (next) {
                    if (arm_mode) {
                        const auto next_context = image.context_at(next.value());
                        if (!next_context || next_context.value().mode != instruction.context.mode) {
                            terminate(address, StopReason::unsupported,
                                      "ARM fallthrough crosses a declared code-state boundary without an interworking branch");
                            return;
                        }
                        pending.push_back({next.value(), instruction.context.mode == ExecutionMode::thumb
                                                             ? instruction.arm->it_after
                                                             : ThumbITState{}});
                        const auto source = analysis_detail::is_mips_branch_likely(instruction) &&
                                                    instruction.flow == FlowKind::conditional_branch
                                                ? address : mips_slot.value_or(address);
                        output.edges.push_back({source, next.value(), EdgeKind::fallthrough});
                        return;
                    }
                    const auto source = analysis_detail::is_mips_branch_likely(instruction) &&
                                                instruction.flow == FlowKind::conditional_branch
                                            ? address : mips_slot.value_or(address);
                    output.edges.push_back({source, next.value(), EdgeKind::fallthrough});
                    pending.push_back({next.value(), {}});
                } else
                    terminate(address, StopReason::target_overflow, "Instruction fallthrough exceeds address model");
            };
            if (instruction.flow == FlowKind::ret) {
                terminate(address, StopReason::ret, "Return", false);
                if (arm_mode && arm_predicate_can_skip(instruction))
                    fallthrough();
                continue;
            }
            if (instruction.flow == FlowKind::trap) {
                terminate(address, StopReason::trap, "Trap", false);
                if (arm_mode && arm_predicate_can_skip(instruction))
                    fallthrough();
                continue;
            }
            if (instruction.flow == FlowKind::data) {
                terminate(address, StopReason::invalid, "Instruction stream reached non-executable data", false);
                continue;
            }
            if (instruction.flow == FlowKind::fallthrough) {
                if (unmodeled_arm_pc_write) {
                    if (arm_predicate_can_skip(instruction))
                        fallthrough();
                } else
                    fallthrough();
                continue;
            }
            if (instruction.flow == FlowKind::switch_dispatch) {
                if (instruction.context.architecture != Architecture::dex || !instruction.dex_switch ||
                    !instruction.dex_switch->validated) {
                    output.edges.push_back({address, {}, EdgeKind::unresolved_jump});
                    if (instruction.dex_switch == std::nullopt)
                        terminate(address, StopReason::unsupported, "Switch dispatch has no validated case table");
                    fallthrough();
                    continue;
                }
                for (const auto &item : instruction.dex_switch->cases) {
                    if (!code_allowed(item.target)) {
                        terminate(item.target, StopReason::unmapped,
                                  "DEX switch case has no permitted initialized executable target");
                        output.edges.push_back({address, {}, EdgeKind::unresolved_jump});
                        continue;
                    }
                    output.edges.push_back({address, item.target, EdgeKind::branch});
                    pending.push_back({item.target, {}});
                }
                fallthrough();
                continue;
            }
            std::optional<Address> resolved_target;
            if (instruction.context.architecture == Architecture::dex && instruction.flow == FlowKind::call) {
                resolved_target = instruction.direct_target
                    ? instruction.direct_target
                    : dex_direct_call_target(instruction, image, metadata);
            } else {
                const auto resolved = relocation_index.value().control_target(image, instruction, stop);
                if (!resolved)
                    return resolved.error();
                resolved_target = resolved.value();
            }
            if (resolved_target) {
                const auto target = *resolved_target;
                ThumbITState target_it{};
                if (arm_mode) {
                    if (!instruction.arm || (!instruction.arm->target_mode &&
                                             !analysis_detail::is_arm_literal_pc_load(instruction))) {
                        terminate(address, StopReason::unsupported,
                                  "ARM control target has no decoded execution-state transition");
                        continue;
                    }
                    const auto target_context = image.context_at(target);
                    const auto expected_mode = instruction.arm->target_mode
                                                   ? instruction.arm->target_mode
                                                   : target_context ? std::optional{target_context.value().mode}
                                                                    : std::nullopt;
                    if (!target_context || !expected_mode || target_context.value().mode != *expected_mode) {
                        terminate(address, StopReason::unsupported,
                                  "ARM control target conflicts with source-backed execution-state metadata");
                        continue;
                    }
                    if (*expected_mode == ExecutionMode::thumb) {
                        target_it = instruction.context.mode == ExecutionMode::thumb
                                        ? instruction.arm->it_after
                                        : ThumbITState{true, 0};
                    }
                }
                output.edges.push_back(
                    {mips_slot.value_or(address), target, instruction.flow == FlowKind::call ? EdgeKind::call : EdgeKind::branch});
                pending.push_back({target, target_it});
                if (instruction.flow == FlowKind::call && code_allowed(target))
                    output.candidates.push_back(target);
            } else {
                output.edges.push_back(
                    {mips_slot.value_or(address),
                     {},
                     instruction.flow == FlowKind::call ? EdgeKind::unresolved_call : EdgeKind::unresolved_jump});
                const bool relative =
                    std::any_of(instruction.operands.begin(), instruction.operands.end(),
                                [](const Operand &op) { return std::holds_alternative<RelativeOperand>(op); });
                const auto relocated = instruction.operands.empty()
                                           ? Result<OperandResolution>{OperandResolution{}}
                                           : relocation_index.value().operand(instruction, 0, stop);
                if (!relocated)
                    return relocated.error();
                terminate(
                    address,
                    relocated.value().dyld ? StopReason::macho_dyld
                    : relocated.value().relocated()
                        ? (relocation_index.value().format() == RelocationFormat::macho ? StopReason::macho_relocation
                                                                                        : StopReason::elf_relocation)
                    : relative ? StopReason::target_overflow
                               : StopReason::indirect,
                    relocated.value().dyld          ? "Mach-O dyld control value remains unresolved"
                    : relocated.value().relocated() ? (relocation_index.value().format() == RelocationFormat::macho
                                                           ? "Mach-O control relocation remains unresolved"
                                                           : "ELF control relocation remains unresolved")
                    : relative                      ? "Relative target exceeds address model"
                                                    : "Indirect target remains unresolved");
            }
            if (instruction.flow == FlowKind::call || instruction.flow == FlowKind::conditional_branch)
                fallthrough();
        }
        auto strings = find_strings(image, options, stop);
        if (!strings)
            return strings.error();
        output.strings = std::move(strings.value());
        output.complete = output.code_complete && output.strings.complete;
        std::sort(output.instructions.begin(), output.instructions.end(),
                  [](const auto &a, const auto &b) { return DomainAddressLess{}(a.address, b.address); });
        std::sort(output.stops.begin(), output.stops.end(),
                  [](const auto &a, const auto &b) { return DomainAddressLess{}(a.address, b.address); });
        std::sort(output.candidates.begin(), output.candidates.end(), DomainAddressLess{});
        output.candidates.erase(std::unique(output.candidates.begin(), output.candidates.end()),
                                output.candidates.end());
        return output;
    } catch (const FixupFailure &failure) {
        return failure.error;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Cannot allocate analysis results"};
    }
}
} // namespace hexlab
