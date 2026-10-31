#include "hexlab/analysis/stack.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <deque>
#include <map>
#include <set>
#include <tuple>

namespace hexlab {
namespace {

struct FlowValue {
    bool known = false;
    std::int64_t value = 0;
    bool operator==(const FlowValue &) const = default;
};

struct FlowState {
    bool reachable = false;
    FlowValue stack_depth;
    FlowValue frame_depth;
    bool supported = true;
    bool ambiguous = false;
    int frame_register = -1;
    bool arm64_frame_pointer = false;
    // A bounded set of exact RISC-V temporary pointers derived from SP, s0,
    // or another tracked temporary. Each value is entry-SP depth (not an
    // absolute address), so direct memory operands can reuse the slot model.
    std::array<FlowValue, 32> riscv_stack_alias_depths{};
    // MIPS32 temporary bases derived from the entry-relative $sp/$fp value.
    std::array<FlowValue, 32> mips32_stack_alias_depths{};
    // Equivalent fixed-width relation for AArch64 temporary base registers.
    std::array<FlowValue, 31> arm64_stack_alias_depths{};
    // Independently tracked NMOS 6502 copies of a TSX snapshot in A, X, or Y.
    // Each delta is relative to frame_depth, the stack depth sampled by TSX.
    std::array<FlowValue, 3> m6502_stack_alias_deltas{};
    // Carry is only tracked when explicitly set by CLC/SEC. ADC/SBC can use
    // it to preserve a stack-derived accumulator offset through immediate
    // arithmetic, then invalidate it because their result carry is unknown.
    bool m6502_carry_known = false;
    bool m6502_carry_set = false;
    // Decimal mode changes NMOS 6502 ADC/SBC results, so stack-derived A
    // arithmetic is usable only after CLD proves binary mode.
    bool m6502_decimal_known = false;
    bool m6502_decimal_set = false;
    // For the NMOS 6502 TSX/$0100,X convention, track a small signed
    // displacement from the sampled S value. Values outside +/-127 are
    // intentionally discarded because 8-bit index wrap makes linear slot
    // identities ambiguous over a complete page traversal.
    FlowValue frame_register_delta;
};

bool add_checked(std::int64_t left, std::int64_t right, std::int64_t &result) {
    if ((right > 0 && left > INT64_MAX - right) || (right < 0 && left < INT64_MIN - right))
        return false;
    result = left + right;
    return true;
}

bool subtract_checked(std::int64_t left, std::int64_t right, std::int64_t &result) {
    if ((right > 0 && left < INT64_MIN + right) || (right < 0 && left > INT64_MAX + right))
        return false;
    result = left - right;
    return true;
}

bool m6502_slot_offset_unambiguous(std::int64_t offset) noexcept {
    // Keep any two modeled offsets inside one signed page window. Outside
    // this range, the 8-bit stack/index arithmetic can wrap to a cell already
    // represented by a different linear offset.
    return offset >= -127 && offset <= 127;
}

bool add(FlowValue &value, std::int64_t delta) {
    if (!value.known)
        return true;
    std::int64_t updated = 0;
    if (!add_checked(value.value, delta, updated))
        return false;
    value.value = updated;
    return true;
}

std::optional<RegisterOperand> register_at(const Instruction &instruction, std::size_t index) {
    if (index >= instruction.operands.size())
        return {};
    if (const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[index]))
        return *reg;
    return {};
}

bool is_gpr(const std::optional<RegisterOperand> &value, std::uint8_t index) {
    return value && value->bank == RegisterBank::gpr && value->index == index;
}

std::optional<std::int64_t> immediate_value(const Instruction &instruction, std::size_t index) {
    if (index >= instruction.operands.size())
        return {};
    const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[index]);
    if (!immediate || immediate->effective_width == 0 || immediate->effective_width > 64)
        return {};
    std::uint64_t bits = immediate->value;
    const unsigned width = immediate->effective_width;
    if (width < 64)
        bits &= (UINT64_C(1) << width) - 1;
    if (immediate->is_signed && width < 64 && (bits & (UINT64_C(1) << (width - 1))))
        bits |= ~((UINT64_C(1) << width) - 1);
    if (!immediate->is_signed && bits > static_cast<std::uint64_t>(INT64_MAX))
        return {};
    return std::bit_cast<std::int64_t>(bits);
}

std::int64_t pointer_bytes(const Instruction &instruction) {
    switch (instruction.context.mode) {
    case ExecutionMode::x86_16: return 2;
    case ExecutionMode::x86_32: return 4;
    case ExecutionMode::x86_64: return 8;
    case ExecutionMode::a32:
    case ExecutionMode::thumb:
    case ExecutionMode::mips32: return 4;
    case ExecutionMode::mips64: return 8;
    case ExecutionMode::ppc32: return 4;
    case ExecutionMode::ppc64: return 8;
    case ExecutionMode::rv32: return 4;
    case ExecutionMode::rv64:
    case ExecutionMode::rv64c: return 8;
    default: return 0;
    }
}

bool merge_value(FlowValue &current, FlowValue incoming) {
    if (!current.known)
        return false;
    if (!incoming.known || current.value != incoming.value) {
        current = {};
        return true;
    }
    return false;
}

bool merge(FlowState &current, const FlowState &incoming) {
    if (!incoming.reachable)
        return false;
    if (!current.reachable) {
        current = incoming;
        return true;
    }
    const bool previously_supported = current.supported;
    const bool previously_ambiguous = current.ambiguous;
    const int previous_frame_register = current.frame_register;
    const bool previous_arm64_frame_pointer = current.arm64_frame_pointer;
    current.supported = current.supported && incoming.supported;
    current.ambiguous = current.ambiguous || incoming.ambiguous;
    const bool stack_changed = merge_value(current.stack_depth, incoming.stack_depth);
    const bool frame_changed = merge_value(current.frame_depth, incoming.frame_depth);
    bool m6502_carry_changed = false;
    if (current.m6502_carry_known &&
        (!incoming.m6502_carry_known || current.m6502_carry_set != incoming.m6502_carry_set)) {
        current.m6502_carry_known = false;
        m6502_carry_changed = true;
    } else if (!current.m6502_carry_known && incoming.m6502_carry_known) {
        current.ambiguous = true;
    }
    bool m6502_decimal_changed = false;
    if (current.m6502_decimal_known &&
        (!incoming.m6502_decimal_known || current.m6502_decimal_set != incoming.m6502_decimal_set)) {
        current.m6502_decimal_known = false;
        m6502_decimal_changed = true;
    } else if (!current.m6502_decimal_known && incoming.m6502_decimal_known) {
        current.ambiguous = true;
    }
    bool frame_register_delta_changed = false;
    if (current.frame_register >= 0 && incoming.frame_register == current.frame_register) {
        if (current.frame_register_delta.known && incoming.frame_register_delta.known) {
            frame_register_delta_changed = merge_value(current.frame_register_delta, incoming.frame_register_delta);
        } else if (current.frame_register_delta.known != incoming.frame_register_delta.known) {
            current.frame_register_delta = {};
            frame_register_delta_changed = true;
        }
    }
    if (current.frame_register != incoming.frame_register) {
        current.frame_register = -1;
        current.frame_depth = {};
        current.frame_register_delta = {};
        current.ambiguous = true;
    }
    bool riscv_alias_changed = false;
    for (std::size_t index = 1; index < current.riscv_stack_alias_depths.size(); ++index) {
        auto &alias = current.riscv_stack_alias_depths[index];
        const auto incoming_alias = incoming.riscv_stack_alias_depths[index];
        if (!alias.known && incoming_alias.known) {
            current.ambiguous = true;
        } else if (alias.known && (!incoming_alias.known || alias.value != incoming_alias.value)) {
            alias = {};
            riscv_alias_changed = true;
            current.ambiguous = true;
        }
    }
    bool mips32_alias_changed = false;
    for (std::size_t index = 1; index < current.mips32_stack_alias_depths.size(); ++index) {
        auto &alias = current.mips32_stack_alias_depths[index];
        const auto incoming_alias = incoming.mips32_stack_alias_depths[index];
        if (!alias.known && incoming_alias.known) {
            current.ambiguous = true;
        } else if (alias.known && (!incoming_alias.known || alias.value != incoming_alias.value)) {
            alias = {};
            mips32_alias_changed = true;
            current.ambiguous = true;
        }
    }
    bool arm64_alias_changed = false;
    for (std::size_t index = 0; index < current.arm64_stack_alias_depths.size(); ++index) {
        auto &alias = current.arm64_stack_alias_depths[index];
        const auto incoming_alias = incoming.arm64_stack_alias_depths[index];
        if (!alias.known && incoming_alias.known) {
            current.ambiguous = true;
        } else if (alias.known && (!incoming_alias.known || alias.value != incoming_alias.value)) {
            alias = {};
            arm64_alias_changed = true;
            current.ambiguous = true;
        }
    }
    bool m6502_alias_changed = false;
    for (std::size_t index = 0; index < current.m6502_stack_alias_deltas.size(); ++index) {
        auto &alias = current.m6502_stack_alias_deltas[index];
        const auto incoming_alias = incoming.m6502_stack_alias_deltas[index];
        if (!alias.known && incoming_alias.known) {
            current.ambiguous = true;
        } else if (alias.known && (!incoming_alias.known || alias.value != incoming_alias.value)) {
            alias = {};
            m6502_alias_changed = true;
            current.ambiguous = true;
        }
    }
    if (current.arm64_frame_pointer != incoming.arm64_frame_pointer) {
        current.arm64_frame_pointer = false;
        current.frame_depth = {};
        current.ambiguous = true;
    }
    if (stack_changed || frame_changed)
        current.ambiguous = true;
    return stack_changed || frame_changed || previously_supported != current.supported ||
           previously_ambiguous != current.ambiguous || previous_frame_register != current.frame_register ||
           previous_arm64_frame_pointer != current.arm64_frame_pointer || frame_register_delta_changed ||
           riscv_alias_changed || mips32_alias_changed || arm64_alias_changed || m6502_alias_changed || m6502_carry_changed ||
           m6502_decimal_changed;
}

bool arm32_register(const std::optional<RegisterOperand> &value, std::uint8_t index) {
    return value && value->bank == RegisterBank::arm32_gpr && value->index == index;
}

bool mips_register(const std::optional<RegisterOperand> &value, std::uint8_t index) {
    return value && value->bank == RegisterBank::mips_gpr && value->index == index;
}

bool mips_stack_adjust(const Instruction &instruction) {
    if (instruction.context.architecture == Architecture::mips32)
        return instruction.opcode == Opcode::mips_addiu || instruction.opcode == Opcode::mips_addi;
    if (instruction.context.architecture == Architecture::mips64)
        return instruction.opcode == Opcode::mips64_daddi || instruction.opcode == Opcode::mips64_daddiu;
    return false;
}

bool riscv_register(const std::optional<RegisterOperand> &value, std::uint8_t index) {
    return value && value->bank == RegisterBank::riscv_gpr && value->index == index;
}

// RV32I/RV64I logical operations are XLEN-wide. Only these zero identities
// preserve a pointer; a word-sized result or any other mask is not a copy.
std::optional<RegisterOperand> riscv_bitwise_copy_source(const Instruction &instruction) {
    const bool rv32 = instruction.context.architecture == Architecture::riscv32 &&
                      instruction.context.mode == ExecutionMode::rv32;
    const bool rv64 = instruction.context.architecture == Architecture::riscv64 &&
                      (instruction.context.mode == ExecutionMode::rv64 ||
                       instruction.context.mode == ExecutionMode::rv64c);
    const bool register_form = instruction.opcode == Opcode::rv_or || instruction.opcode == Opcode::rv_xor;
    const bool immediate_form = instruction.opcode == Opcode::rv_ori || instruction.opcode == Opcode::rv_xori;
    if ((!rv32 && !rv64) || (!register_form && !immediate_form) || instruction.operands.size() != 3 ||
        instruction.access != std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read,
                                                        OperandAccess::read} ||
        instruction.flow != FlowKind::fallthrough || instruction.delay_slots ||
        instruction.memory_read || instruction.memory_write || instruction.csr_read || instruction.csr_write ||
        instruction.writes_fflags || instruction.reads_fflags || instruction.reads_frm)
        return {};
    const auto width = static_cast<std::uint16_t>(rv32 ? 32 : 64);
    const auto full_gpr = [width](const std::optional<RegisterOperand> &reg) {
        return reg && reg->bank == RegisterBank::riscv_gpr && reg->index < 32 &&
               reg->width == width && !reg->high_byte;
    };
    const auto destination = register_at(instruction, 0);
    auto source = register_at(instruction, 1);
    if (!full_gpr(destination) || destination->index == 0 || !full_gpr(source))
        return {};
    if (register_form) {
        const auto third = register_at(instruction, 2);
        if (!full_gpr(third) || (source->index != 0 && third->index != 0))
            return {};
        if (source->index == 0)
            source = third;
    } else {
        const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands[2]);
        if (!immediate || immediate->value != 0 || immediate->encoded_width != 12 ||
            immediate->effective_width != width || !immediate->is_signed)
            return {};
    }
    const auto expected_reads = source->index == 0 ? std::vector<RegisterOperand>{}
                                                  : std::vector<RegisterOperand>{*source};
    if (instruction.register_reads != expected_reads ||
        instruction.register_writes != std::vector<RegisterOperand>{*destination})
        return {};
    return source;
}

bool ppc_register(const std::optional<RegisterOperand> &value, std::uint8_t index) {
    return value && value->bank == RegisterBank::ppc_gpr && value->index == index;
}

bool record_slot_access(StackSlot &slot, bool read, bool written, bool address_taken, Address site,
                        std::size_t &detail_count) {
    if (std::find(slot.accesses.begin(), slot.accesses.end(), site) == slot.accesses.end())
        slot.accesses.push_back(site);
    const StackSlotAccess detail{site, read, written, address_taken};
    if (std::find(slot.access_details.begin(), slot.access_details.end(), detail) != slot.access_details.end())
        return true;
    if (detail_count >= 1'000'000)
        return false;
    slot.access_details.push_back(detail);
    ++detail_count;
    return true;
}

bool record_stack_slot(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                       bool read, bool written, bool address_taken, Address site, std::size_t &detail_count) {
    if (address_taken) {
        std::size_t matches = 0;
        StackSlot *match = nullptr;
        for (auto &slot : result.slots)
            if (slot.offset_from_entry_sp == offset && slot.width != 0) {
                ++matches;
                match = &slot;
            }
        if (matches == 1) {
            match->address_taken = true;
            return record_slot_access(*match, false, false, true, site, detail_count);
        }
        if (matches > 1)
            result.complete = false;
        auto unknown = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &slot) {
            return slot.offset_from_entry_sp == offset && slot.width == 0;
        });
        if (unknown == result.slots.end()) {
            if (result.slots.size() >= 100000)
                return false;
            result.slots.push_back({offset, 0, false, false, {}, true});
            unknown = std::prev(result.slots.end());
        }
        unknown->address_taken = true;
        return record_slot_access(*unknown, false, false, true, site, detail_count);
    }

    auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot == result.slots.end()) {
        if (result.slots.size() >= 100000)
            return false;
        result.slots.push_back({offset, width, false, false, {}});
        slot = std::prev(result.slots.end());
    }
    auto slot_index = static_cast<std::size_t>(slot - result.slots.begin());
    auto unknown = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == 0 && candidate.address_taken;
    });
    if (unknown != result.slots.end() && static_cast<std::size_t>(unknown - result.slots.begin()) != slot_index) {
        const auto unknown_index = static_cast<std::size_t>(unknown - result.slots.begin());
        auto &known = result.slots[slot_index];
        known.address_taken = true;
        // Re-coalescing moves already-budgeted details. Keep the unique-site
        // budget exact, subtracting a duplicate when both slots recorded the
        // same instruction semantics.
        for (const auto address : unknown->accesses)
            if (std::find(known.accesses.begin(), known.accesses.end(), address) == known.accesses.end())
                known.accesses.push_back(address);
        for (const auto &detail : unknown->access_details) {
            if (std::find(known.access_details.begin(), known.access_details.end(), detail) ==
                known.access_details.end()) {
                known.access_details.push_back(detail);
            } else if (detail_count != 0) {
                --detail_count;
            }
        }
        result.slots.erase(unknown);
        if (unknown_index < slot_index)
            --slot_index;
    }
    auto &known = result.slots[slot_index];
    known.read = known.read || read;
    known.written = known.written || written;
    return record_slot_access(known, read, written, false, site, detail_count);
}

void mark_incoming_x86_32_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                   std::optional<std::uint16_t> callee_cleanup_bytes) {
    if (offset < 4) return; // Entry-SP+0 is the near-call return address.
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        const auto slot_end = width % 8 == 0 && width != 0 &&
            offset <= INT64_MAX - static_cast<std::int64_t>(width / 8)
                ? offset + static_cast<std::int64_t>(width / 8) : INT64_MAX;
        const auto cleanup_end = callee_cleanup_bytes
            ? std::int64_t{4} + *callee_cleanup_bytes : std::int64_t{4};
        slot->incoming_argument_abi = callee_cleanup_bytes && *callee_cleanup_bytes != 0 &&
            slot_end <= cleanup_end ? StackArgumentAbi::x86_32_callee_cleanup
                                    : StackArgumentAbi::x86_32_near_call;
    }
}

std::optional<std::uint16_t> x86_32_callee_cleanup_bytes(
    const FunctionRecord &function,
    const std::map<std::uint64_t, std::shared_ptr<const BasicBlock>> &blocks) {
    if (!function.complete) return {};
    std::optional<std::uint16_t> cleanup;
    bool saw_return = false;
    for (const auto id : function.blocks) {
        const auto block = blocks.find(id.value);
        if (block == blocks.end() || !block->second) return {};
        for (const auto &fact : block->second->instructions) {
            if (!fact) return {};
            const auto &instruction = fact->instruction;
            if (instruction.context.architecture != Architecture::x86 ||
                instruction.context.mode != ExecutionMode::x86_32 || instruction.flow != FlowKind::ret)
                continue;
            if (instruction.opcode != Opcode::ret || instruction.operands.size() > 1) return {};
            std::uint16_t bytes = 0;
            if (!instruction.operands.empty()) {
                const auto *immediate = std::get_if<ImmediateOperand>(&instruction.operands.front());
                if (!immediate || immediate->encoded_width != 16 || immediate->effective_width != 16 ||
                    immediate->is_signed || immediate->value > UINT16_MAX)
                    return {};
                bytes = static_cast<std::uint16_t>(immediate->value);
            }
            if (cleanup && *cleanup != bytes) return {};
            cleanup = bytes;
            saw_return = true;
        }
    }
    return saw_return && cleanup && *cleanup != 0 ? cleanup : std::nullopt;
}

void mark_incoming_aarch64_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                    bool read) {
    if (offset < 0 || !read) return;
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        slot->incoming_argument_abi = StackArgumentAbi::aapcs64;
    }
}

void mark_incoming_aapcs32_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                    bool read) {
    // AAPCS32 places overflow arguments at the entry stack pointer after r0-r3.
    if (offset < 0 || !read) return;
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        slot->incoming_argument_abi = StackArgumentAbi::aapcs32;
    }
}

void mark_incoming_mips_o32_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                     bool read) {
    // O32 reserves four 32-bit argument home words; overflow arguments begin at entry SP + 16.
    if (offset < 16 || !read) return;
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        slot->incoming_argument_abi = StackArgumentAbi::mips_o32;
    }
}

void mark_incoming_mips_n64_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                     bool read) {
    // N64 overflow arguments are placed at the callee's entry SP after A0-A7.
    // The classifier's first stack argument is at +0; writes alone do not
    // establish that a slot contains an incoming value.
    if (offset < 0 || !read) return;
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        slot->incoming_argument_abi = StackArgumentAbi::mips_n64;
    }
}

void mark_incoming_mips_n32_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                     bool read) {
    // N32 uses eight argument slots; overflow begins at the entry stack pointer.
    if (offset < 0 || !read) return;
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        slot->incoming_argument_abi = StackArgumentAbi::mips_n32;
    }
}

void mark_incoming_ppc64_elfv2_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                       bool read) {
    // ELFv2's parameter save area starts at entry SP+32 and reserves eight
    // doublewords for r3-r10; overflow argument locations begin at +96.
    if (offset < 96 || !read) return;
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        slot->incoming_argument_abi = StackArgumentAbi::ppc64le_elfv2;
    }
}

void mark_incoming_riscv_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                  bool read, ExecutionMode mode) {
    // The base integer psABI places overflow arguments at the callee's entry
    // SP, after the a0-a7 register argument bank. A negative offset is local
    // storage; a write-only access is not evidence of an incoming value.
    if (offset < 0 || !read) return;
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        slot->incoming_argument_abi = mode == ExecutionMode::rv32
            ? StackArgumentAbi::riscv32 : StackArgumentAbi::riscv64;
    }
}

void mark_incoming_x86_64_argument(StackFrameAnalysis &result, std::int64_t offset, std::uint16_t width,
                                   bool read, CallingConvention convention) {
    if (!read) return;
    const std::int64_t first_argument_offset = convention == CallingConvention::windows_x64 ? 40 : 8;
    if (offset < first_argument_offset) return;
    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
        return candidate.offset_from_entry_sp == offset && candidate.width == width;
    });
    if (slot != result.slots.end()) {
        slot->incoming_argument = true;
        slot->incoming_argument_abi = convention == CallingConvention::windows_x64
            ? StackArgumentAbi::windows_x64 : StackArgumentAbi::sysv_x86_64;
    }
}

// Transfer only the x86 stack operations whose meaning is explicit in the
// decoded operands. Any other write to SP/BP invalidates that register's
// symbolic relation instead of guessing from mnemonic text.
bool transfer(const Instruction &instruction, FlowState &state) {
    const auto first = register_at(instruction, 0);
    const auto second = register_at(instruction, 1);
    if (instruction.context.architecture == Architecture::mos6502) {
        const auto has_register = [](const std::vector<RegisterOperand> &registers, std::uint8_t index) {
            return std::find(registers.begin(), registers.end(),
                             RegisterOperand{RegisterBank::mos6502, index, 8, false}) != registers.end();
        };
        if (instruction.opcode == Opcode::m6502_clc || instruction.opcode == Opcode::m6502_sec) {
            state.m6502_carry_known = instruction.flow == FlowKind::fallthrough &&
                                      has_register(instruction.register_writes, 3);
            state.m6502_carry_set = instruction.opcode == Opcode::m6502_sec;
            return true;
        }
        if (instruction.opcode == Opcode::m6502_cld || instruction.opcode == Opcode::m6502_sed) {
            state.m6502_decimal_known = instruction.flow == FlowKind::fallthrough &&
                                        has_register(instruction.register_writes, 3);
            state.m6502_decimal_set = instruction.opcode == Opcode::m6502_sed;
            return true;
        }
        if (instruction.opcode == Opcode::m6502_adc || instruction.opcode == Opcode::m6502_sbc) {
            const auto operand = immediate_value(instruction, 0);
            const bool valid = instruction.flow == FlowKind::fallthrough && operand && *operand >= 0 && *operand <= 255 &&
                has_register(instruction.register_reads, 0) && has_register(instruction.register_writes, 0) &&
                has_register(instruction.register_writes, 3);
            auto &accumulator = state.m6502_stack_alias_deltas[0];
            if (valid && state.m6502_carry_known && state.m6502_decimal_known &&
                !state.m6502_decimal_set && accumulator.known) {
                const auto delta = instruction.opcode == Opcode::m6502_adc
                    ? *operand + static_cast<std::int64_t>(state.m6502_carry_set)
                    : -*operand - static_cast<std::int64_t>(!state.m6502_carry_set);
                std::int64_t updated = 0;
                if (add_checked(accumulator.value, delta, updated) && m6502_slot_offset_unambiguous(updated))
                    accumulator.value = updated;
                else
                    accumulator = {};
            } else {
                accumulator = {};
            }
            state.m6502_carry_known = false;
            return true;
        }
        if (std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                        [](const RegisterOperand &reg) {
                            return reg.bank == RegisterBank::mos6502 && reg.index == 3;
                        }))
            state.m6502_carry_known = false;
        switch (instruction.opcode) {
        case Opcode::m6502_jsr:
            // A callee may overwrite any general register. Keep the caller's
            // entry-relative S depth (JSR/RTS is balanced), but do not let a
            // stale TSX snapshot in X or a transferred A/Y alias justify a
            // later TXS restore.
            state.frame_depth = {};
            state.frame_register = -1;
            state.frame_register_delta = {};
            state.m6502_stack_alias_deltas = {};
            state.m6502_carry_known = false;
            state.m6502_decimal_known = false;
            return true;
        case Opcode::m6502_rts:
            return true;
        case Opcode::m6502_rti:
            state.m6502_decimal_known = false;
            return true;
        case Opcode::m6502_tsx:
            // TSX gives X a stable, byte-wide snapshot of the hardware stack
            // pointer. Keep its entry-relative depth as a frame base until X
            // is overwritten.
            if (instruction.flow != FlowKind::fallthrough || !has_register(instruction.register_reads, 4) ||
                !has_register(instruction.register_writes, 1)) {
                state.frame_depth = {};
                state.frame_register = -1;
                state.frame_register_delta = {};
                state.m6502_stack_alias_deltas = {};
                state.supported = false;
                return true;
            }
            state.frame_depth = state.stack_depth;
            state.frame_register = -1;
            state.frame_register_delta = {};
            state.m6502_stack_alias_deltas = {};
            state.m6502_stack_alias_deltas[1] = {true, 0};
            if (!state.frame_depth.known || state.frame_depth.value < -127 || state.frame_depth.value > 127) {
                state.frame_depth = {};
                state.m6502_stack_alias_deltas = {};
                state.supported = false;
            }
            return true;
        case Opcode::m6502_txs:
            // TXS copies the X snapshot back to S. If TSX established X as a
            // stack snapshot and X has not been clobbered, this restores the
            // exact previously observed stack depth (even after intervening
            // pushes and pulls).
            if (instruction.flow == FlowKind::fallthrough && has_register(instruction.register_reads, 1) &&
                has_register(instruction.register_writes, 4) && state.frame_depth.known &&
                state.m6502_stack_alias_deltas[1].known) {
                std::int64_t restored_depth = 0;
                if (subtract_checked(state.frame_depth.value, state.m6502_stack_alias_deltas[1].value, restored_depth) &&
                    restored_depth >= -127 && restored_depth <= 127) {
                    state.stack_depth = {true, restored_depth};
                    return true;
                }
            }
            state.stack_depth = {};
            state.supported = false;
            return true;
        case Opcode::m6502_inx:
        case Opcode::m6502_dex:
        case Opcode::m6502_iny:
        case Opcode::m6502_dey:
            {
                const bool updates_x = instruction.opcode == Opcode::m6502_inx ||
                                       instruction.opcode == Opcode::m6502_dex;
                const auto index = static_cast<std::size_t>(updates_x ? 1 : 2);
                auto &alias = state.m6502_stack_alias_deltas[index];
                if (!alias.known) break;
                if (instruction.flow != FlowKind::fallthrough || !has_register(instruction.register_reads, index) ||
                    !has_register(instruction.register_writes, index)) {
                    alias = {};
                    state.supported = false;
                    return true;
                }
                const auto delta = instruction.opcode == Opcode::m6502_inx ||
                                           instruction.opcode == Opcode::m6502_iny ? 1 : -1;
                if (add_checked(alias.value, delta, alias.value) &&
                    alias.value >= -127 && alias.value <= 127)
                    return true;
                alias = {};
                state.supported = false;
                return true;
            }
        case Opcode::m6502_tax:
        case Opcode::m6502_tay:
        case Opcode::m6502_txa:
        case Opcode::m6502_tya: {
            const int source = instruction.opcode == Opcode::m6502_tax || instruction.opcode == Opcode::m6502_tay
                                   ? 0
                                   : instruction.opcode == Opcode::m6502_txa ? 1 : 2;
            const int destination = instruction.opcode == Opcode::m6502_tax || instruction.opcode == Opcode::m6502_txa
                                        ? 1
                                        : instruction.opcode == Opcode::m6502_tay ? 2 : 0;
            const auto source_index = static_cast<std::size_t>(source);
            const auto destination_index = static_cast<std::size_t>(destination);
            const RegisterOperand source_register{RegisterBank::mos6502, static_cast<std::uint8_t>(source), 8, false};
            const RegisterOperand destination_register{RegisterBank::mos6502,
                static_cast<std::uint8_t>(destination), 8, false};
            if (instruction.flow != FlowKind::fallthrough ||
                std::find(instruction.register_reads.begin(), instruction.register_reads.end(), source_register) ==
                    instruction.register_reads.end() ||
                std::find(instruction.register_writes.begin(), instruction.register_writes.end(), destination_register) ==
                    instruction.register_writes.end()) {
                state.m6502_stack_alias_deltas[destination_index] = {};
                state.supported = false;
                return true;
            }
            // These instructions copy rather than move; preserve the source
            // alias and independently carry or clear the destination alias.
            state.m6502_stack_alias_deltas[destination_index] =
                state.m6502_stack_alias_deltas[source_index];
            return true;
        }
        case Opcode::m6502_pha:
        case Opcode::m6502_php:
            return add(state.stack_depth, 1);
        case Opcode::m6502_pla:
            state.m6502_stack_alias_deltas[0] = {};
            return add(state.stack_depth, -1);
        case Opcode::m6502_plp:
            state.m6502_decimal_known = false;
            return add(state.stack_depth, -1);
        default:
            break;
        }
    }
    const bool riscv_instruction = instruction.context.architecture == Architecture::riscv32 ||
                                   instruction.context.architecture == Architecture::riscv64;
    if (riscv_instruction && instruction.opcode != Opcode::rv_addi) {
        if (instruction.flow == FlowKind::call) {
            for (auto &alias : state.riscv_stack_alias_depths) alias = {};
        } else {
            const auto copy_source = riscv_bitwise_copy_source(instruction);
            const bool preserves_alias = copy_source && copy_source->index != 0 &&
                (copy_source->index == 2 ||
                 (copy_source->index == 8 && state.frame_register == 8) ||
                 state.riscv_stack_alias_depths[copy_source->index].known);
            const auto invalidate_alias = [&](const RegisterOperand &reg) {
                if (!preserves_alias && reg.bank == RegisterBank::riscv_gpr && reg.index != 0 && reg.index < 32)
                    state.riscv_stack_alias_depths[reg.index] = {};
            };
            for (const auto &reg : instruction.register_writes) invalidate_alias(reg);
            for (std::size_t index = 0; index < instruction.operands.size(); ++index) {
                if (index >= instruction.access.size() ||
                    (instruction.access[index] != OperandAccess::write &&
                     instruction.access[index] != OperandAccess::read_write))
                    continue;
                if (const auto reg = register_at(instruction, index)) invalidate_alias(*reg);
            }
        }
    }
    if ((instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) &&
        instruction.flow == FlowKind::ret)
        return true;
    // A recovered near call pushes a return address and a normally returning
    // callee removes it. Keep the caller-visible depth unchanged at the call
    // boundary; outgoing arguments remain present until caller cleanup.
    if ((instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) &&
        instruction.flow == FlowKind::call)
        return true;
    if ((instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) &&
        (instruction.opcode == Opcode::pusha || instruction.opcode == Opcode::popa)) {
        const auto bytes = static_cast<std::int64_t>(instruction.stack_value_width / 8);
        if (bytes <= 0 || instruction.stack_slot_count != 8) {
            state.stack_depth = {};
            state.supported = false;
            return true;
        }
        return add(state.stack_depth, (instruction.opcode == Opcode::pusha ? 8 : -8) * bytes);
    }
    const bool x86_push = instruction.opcode == Opcode::push || instruction.opcode == Opcode::pushf;
    const bool x86_pop = instruction.opcode == Opcode::pop || instruction.opcode == Opcode::popf;
    if (x86_push || x86_pop) {
        std::int64_t bytes = instruction.stack_value_width / 8;
        if (!bytes && first)
            bytes = first->width / 8;
        if (!bytes)
            bytes = pointer_bytes(instruction);
        if (!bytes)
            return true;
        if (instruction.opcode == Opcode::pop && first && first->bank == RegisterBank::gpr && first->index == 4) {
            state.stack_depth = {};
            state.supported = false;
            return true;
        }
        if (instruction.opcode == Opcode::pop && first && first->bank == RegisterBank::gpr && first->index == 5) {
            state.frame_depth = {};
            state.frame_register = -1;
        }
        return add(state.stack_depth, x86_push ? bytes : -bytes);
    }
    if ((instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) &&
        instruction.opcode == Opcode::enter) {
        const auto allocation = immediate_value(instruction, 0);
        const auto encoded_level = immediate_value(instruction, 1);
        if (!allocation || !encoded_level || *encoded_level < 0 || instruction.stack_value_width == 0) {
            state.stack_depth = {};
            state.frame_depth = {};
            state.frame_register = -1;
            state.supported = false;
            return true;
        }
        const auto level = static_cast<std::uint8_t>(*encoded_level) & 0x1fu;
        const auto expected_slots = static_cast<std::uint8_t>(level ? level + 1 : 1);
        const auto word_bytes = static_cast<std::int64_t>(instruction.stack_value_width / 8);
        if (instruction.stack_slot_count != expected_slots || word_bytes <= 0) {
            state.stack_depth = {};
            state.frame_depth = {};
            state.frame_register = -1;
            state.supported = false;
            return true;
        }
        const auto saved_bytes = static_cast<std::int64_t>(expected_slots) * word_bytes;
        if (!add(state.stack_depth, saved_bytes))
            return false;
        state.frame_depth = state.stack_depth;
        state.frame_register = 5;
        if (!add(state.stack_depth, *allocation))
            return false;
        if (!state.frame_depth.known)
            state.supported = false;
        return true;
    }
    if (instruction.opcode == Opcode::leave) {
        const auto bytes = instruction.stack_value_width
                               ? static_cast<std::int64_t>(instruction.stack_value_width / 8)
                               : pointer_bytes(instruction);
        if (bytes <= 0) {
            state.stack_depth = {};
            state.frame_depth = {};
            state.frame_register = -1;
            state.supported = false;
            return true;
        }
        if (!state.frame_depth.known)
            state.stack_depth = {};
        else {
            state.stack_depth = state.frame_depth;
            if (!add(state.stack_depth, -bytes))
                return false;
        }
        state.frame_depth = {};
        state.frame_register = -1;
        return true;
    }
    // At x86-64 function entry, the call ABI guarantees RSP is 8 mod 16.
    // Model common low-bit clearing masks when this determines the exact
    // resulting entry-relative depth.
    if (instruction.context.architecture == Architecture::x86_64 &&
        instruction.context.mode == ExecutionMode::x86_64 &&
        instruction.opcode == Opcode::bit_and && is_gpr(first, 4) && first->width == 64 &&
        instruction.operands.size() == 2) {
        const auto mask = immediate_value(instruction, 1);
        std::int64_t alignment = 0;
        if (mask) {
            switch (*mask) {
            case -2: alignment = 2; break;
            case -4: alignment = 4; break;
            case -8: alignment = 8; break;
            case -16: alignment = 16; break;
            default: break;
            }
        }
        if (!alignment || !state.stack_depth.known) {
            state.stack_depth = {};
            state.supported = false;
            return true;
        }
        auto remainder = (8 % alignment - state.stack_depth.value % alignment) % alignment;
        if (remainder < 0) remainder += alignment;
        if (!add(state.stack_depth, remainder)) return false;
        return true;
    }
    const auto stack_pointer_width = static_cast<std::uint8_t>(pointer_bytes(instruction) * 8);
    const bool full_width_x86 =
        (instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) &&
        stack_pointer_width != 0 && first && second &&
        first->width == stack_pointer_width && second->width == stack_pointer_width;
    if (full_width_x86 && instruction.opcode == Opcode::mov && is_gpr(first, 5) && is_gpr(second, 4)) {
        state.frame_depth = state.stack_depth;
        state.frame_register = 5;
        return true;
    }
    if (full_width_x86 && instruction.opcode == Opcode::mov && is_gpr(first, 4) && is_gpr(second, 5)) {
        state.stack_depth = state.frame_depth;
        return true;
    }
    if (mips_stack_adjust(instruction) && instruction.operands.size() >= 3) {
        const auto immediate = immediate_value(instruction, 2);
        const bool dst_stack = mips_register(first, 29);
        const bool dst_frame = mips_register(first, 30);
        const bool src_stack = mips_register(second, 29);
        const bool src_frame = mips_register(second, 30);
        const bool mips32_form = instruction.context.architecture == Architecture::mips32 &&
            instruction.context.mode == ExecutionMode::mips32 && instruction.operands.size() == 3 &&
            first && second && first->bank == RegisterBank::mips_gpr && second->bank == RegisterBank::mips_gpr &&
            first->index < 32 && second->index < 32 && first->width == 32 && second->width == 32 &&
            instruction.access == std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read,
                                                              OperandAccess::read} &&
            instruction.flow == FlowKind::fallthrough && !instruction.delay_slots &&
            !instruction.memory_read && !instruction.memory_write &&
            std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *first) !=
                instruction.register_writes.end() &&
            std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *second) !=
                instruction.register_reads.end();
        if (mips32_form && immediate) {
            FlowValue base;
            bool stack_derived = false;
            if (src_stack) { base = state.stack_depth; stack_derived = true; }
            else if (src_frame && state.frame_register == 30) { base = state.frame_depth; stack_derived = true; }
            else if (second->index != 0 && state.mips32_stack_alias_depths[second->index].known) {
                base = state.mips32_stack_alias_depths[second->index];
                stack_derived = true;
            }
            auto relation = base;
            if (relation.known && !subtract_checked(relation.value, *immediate, relation.value)) return false;
            if (dst_stack) {
                state.stack_depth = stack_derived ? relation : FlowValue{};
                if (!stack_derived || !relation.known) state.supported = false;
                return true;
            }
            if (dst_frame) {
                state.frame_depth = stack_derived ? relation : FlowValue{};
                state.frame_register = 30;
                if (!stack_derived || !relation.known) state.supported = false;
                return true;
            }
            if (first->index != 0) {
                state.mips32_stack_alias_depths[first->index] = stack_derived ? relation : FlowValue{};
                if (stack_derived && !relation.known) state.supported = false;
                return true;
            }
        }
        if (instruction.context.architecture == Architecture::mips64 && immediate &&
            ((dst_stack && (src_stack || src_frame)) || (dst_frame && (src_stack || src_frame)))) {
            FlowValue relation = src_stack ? state.stack_depth : state.frame_depth;
            if (!subtract_checked(relation.value, *immediate, relation.value)) return false;
            if (!relation.known) state.supported = false;
            if (dst_stack) state.stack_depth = relation;
            else { state.frame_depth = relation; state.frame_register = 30; }
            return true;
        }
        if (instruction.context.architecture == Architecture::mips32 && first &&
            first->bank == RegisterBank::mips_gpr && first->index != 0 && first->index < 32)
            state.mips32_stack_alias_depths[first->index] = {};
    }
    if ((instruction.context.architecture == Architecture::riscv32 ||
         instruction.context.architecture == Architecture::riscv64) &&
        instruction.opcode == Opcode::rv_addi && instruction.operands.size() >= 3) {
        const auto immediate = immediate_value(instruction, 2);
        const auto width = static_cast<std::uint8_t>(pointer_bytes(instruction) * 8);
        const bool valid_form = first && second && first->bank == RegisterBank::riscv_gpr &&
            second->bank == RegisterBank::riscv_gpr && first->index < 32 && second->index < 32 &&
            first->width == width && second->width == width && instruction.flow == FlowKind::fallthrough &&
            instruction.access == std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read,
                                                              OperandAccess::read};
        if (valid_form && immediate) {
            FlowValue base;
            bool stack_derived = false;
            if (riscv_register(second, 2)) {
                base = state.stack_depth;
                stack_derived = true;
            } else if (riscv_register(second, 8) && state.frame_register == 8) {
                base = state.frame_depth;
                stack_derived = true;
            } else if (second->index != 0 && state.riscv_stack_alias_depths[second->index].known) {
                base = state.riscv_stack_alias_depths[second->index];
                stack_derived = true;
            }
            FlowValue relation = base;
            if (relation.known && !subtract_checked(relation.value, *immediate, relation.value)) {
                state.riscv_stack_alias_depths[first->index] = {};
                return false;
            }
            if (riscv_register(first, 2)) {
                if (!relation.known) state.supported = false;
                state.stack_depth = relation;
                return true;
            }
            if (riscv_register(first, 8)) {
                if (!relation.known) state.supported = false;
                state.frame_depth = relation;
                state.frame_register = 8;
                return true;
            }
            if (first->index != 0) {
                state.riscv_stack_alias_depths[first->index] = relation;
                if (stack_derived && !relation.known) state.supported = false;
                return true;
            }
        }
        if (first && first->bank == RegisterBank::riscv_gpr && first->index != 0 && first->index < 32)
            state.riscv_stack_alias_depths[first->index] = {};
    }
    if (instruction.context.architecture == Architecture::powerpc &&
        instruction.opcode == Opcode::ppc_addi && instruction.operands.size() >= 3) {
        const auto immediate = immediate_value(instruction, 2);
        const bool dst_stack = ppc_register(first, 1);
        const bool dst_frame = ppc_register(first, 31);
        const bool src_stack = ppc_register(second, 1);
        const bool src_frame = ppc_register(second, 31);
        if (immediate && ((dst_stack && (src_stack || src_frame)) ||
                          (dst_frame && (src_stack || src_frame)))) {
            auto relation = src_stack ? state.stack_depth : state.frame_depth;
            if (!subtract_checked(relation.value, *immediate, relation.value)) return false;
            if (!relation.known) state.supported = false;
            if (dst_stack) state.stack_depth = relation;
            else { state.frame_depth = relation; state.frame_register = 31; }
            return true;
        }
    }
    if (instruction.context.architecture == Architecture::powerpc &&
        instruction.opcode == Opcode::ppc_or && instruction.operands.size() >= 3 &&
        ppc_register(first, 31) && ppc_register(second, 1) &&
        ppc_register(register_at(instruction, 2), 1)) {
        state.frame_depth = state.stack_depth;
        state.frame_register = 31;
        return true;
    }
    if (instruction.context.architecture == Architecture::powerpc &&
        instruction.operands.size() >= 2 &&
        (instruction.opcode == Opcode::ppc_stwu || instruction.opcode == Opcode::ppc_stdu ||
         instruction.opcode == Opcode::ppc_stbu || instruction.opcode == Opcode::ppc_sthu ||
         instruction.opcode == Opcode::ppc_lwzu || instruction.opcode == Opcode::ppc_lbzu ||
         instruction.opcode == Opcode::ppc_lhzu || instruction.opcode == Opcode::ppc_lhau ||
         instruction.opcode == Opcode::ppc_ldu)) {
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        if (memory && memory->base && ppc_register(std::optional{*memory->base}, 1) &&
            memory->displacement != INT64_MIN) {
            if (!add(state.stack_depth, -memory->displacement)) return false;
            return true;
        }
    }
    if (instruction.context.architecture == Architecture::powerpc &&
        instruction.opcode == Opcode::ppc_or && instruction.operands.size() >= 3 &&
        ppc_register(first, 1) && ppc_register(second, 31) &&
        ppc_register(register_at(instruction, 2), 31) && state.frame_register == 31) {
        state.stack_depth = state.frame_depth;
        return true;
    }
    if ((instruction.context.architecture == Architecture::riscv32 ||
         instruction.context.architecture == Architecture::riscv64) &&
        instruction.opcode == Opcode::rv_andi && instruction.operands.size() >= 3 &&
        riscv_register(first, 2) && riscv_register(second, 2)) {
        const auto immediate = immediate_value(instruction, 2);
        // RISC-V procedure entry SP is 16-byte aligned. Recognize the common
        // low-bit clearing masks up to that ABI alignment; broader or
        // nonstandard masks cannot be modeled from an entry-relative depth.
        std::int64_t alignment = 0;
        if (immediate) {
            switch (*immediate) {
            case -2: alignment = 2; break;
            case -4: alignment = 4; break;
            case -8: alignment = 8; break;
            case -16: alignment = 16; break;
            default: break;
            }
        }
        if (!alignment) {
            state.stack_depth = {};
            state.supported = false;
            return true;
        }
        if (!state.stack_depth.known) {
            state.supported = false;
            return true;
        }
        const auto remainder = state.stack_depth.value % alignment;
        const auto adjustment = remainder > 0 ? alignment - remainder : -remainder;
        if (!add_checked(state.stack_depth.value, adjustment, state.stack_depth.value))
            return false;
        return true;
    }
    if ((instruction.context.architecture == Architecture::riscv32 ||
         instruction.context.architecture == Architecture::riscv64) &&
        (instruction.opcode == Opcode::rv_add || instruction.opcode == Opcode::rv_sub) &&
        instruction.operands.size() >= 3 &&
        ((instruction.opcode == Opcode::rv_add &&
          (riscv_register(second, 0) || riscv_register(register_at(instruction, 2), 0))) ||
         (instruction.opcode == Opcode::rv_sub && riscv_register(register_at(instruction, 2), 0)))) {
        const auto source = instruction.opcode == Opcode::rv_sub || riscv_register(second, 0)
            ? second : register_at(instruction, 2);
        if (riscv_register(first, 2) && riscv_register(source, 8) && state.frame_register == 8) {
            state.stack_depth = state.frame_depth;
            return true;
        }
        if (riscv_register(first, 8) && riscv_register(source, 2)) {
            state.frame_depth = state.stack_depth;
            state.frame_register = 8;
            return true;
        }
    }
    if (const auto source = riscv_bitwise_copy_source(instruction)) {
        if (first->index == source->index && (first->index == 2 || first->index == 8))
            return true;
        if (first->index == 2 && source->index == 8) {
            state.stack_depth = state.frame_register == 8 ? state.frame_depth : FlowValue{};
            state.supported = state.supported && state.stack_depth.known;
            return true;
        }
        if (first->index == 8 && source->index == 2) {
            state.frame_depth = state.stack_depth;
            state.frame_register = 8;
            state.supported = state.supported && state.frame_depth.known;
            return true;
        }
        // Preserve an exact stack relation through the XLEN-wide logical
        // copy identities accepted above. The source relation can come from
        // SP, the established frame pointer, or an earlier ADDI-derived
        // temporary. The helper has already validated the complete register
        // effects, so do not infer this from operands alone.
        if (first->index != 0 && first->index != 2 && first->index != 8) {
            FlowValue relation;
            bool stack_derived = false;
            if (source->index == 2) {
                relation = state.stack_depth;
                stack_derived = true;
            } else if (source->index == 8 && state.frame_register == 8) {
                relation = state.frame_depth;
                stack_derived = true;
            } else if (source->index != 0) {
                relation = state.riscv_stack_alias_depths[source->index];
                stack_derived = relation.known;
            }
            if (stack_derived)
                state.riscv_stack_alias_depths[first->index] = relation;
            return true;
        }
    }
    if ((instruction.context.architecture == Architecture::mips32 ||
         instruction.context.architecture == Architecture::mips64) &&
        (instruction.opcode == Opcode::mips_addu || instruction.opcode == Opcode::mips_add ||
         instruction.opcode == Opcode::mips_or || instruction.opcode == Opcode::mips64_dadd ||
         instruction.opcode == Opcode::mips64_daddu) &&
        instruction.operands.size() >= 3 &&
        (mips_register(second, 0) || mips_register(register_at(instruction, 2), 0))) {
        const auto source = mips_register(second, 0) ? register_at(instruction, 2) : second;
        const bool exact_mips32_copy = instruction.context.architecture == Architecture::mips32 &&
            instruction.context.mode == ExecutionMode::mips32 && instruction.operands.size() == 3 &&
            first && source && first->bank == RegisterBank::mips_gpr && source->bank == RegisterBank::mips_gpr &&
            first->index < 32 && source->index < 32 && first->width == 32 && source->width == 32 &&
            instruction.access == std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read,
                                                              OperandAccess::read} &&
            instruction.flow == FlowKind::fallthrough && !instruction.delay_slots &&
            !instruction.memory_read && !instruction.memory_write &&
            std::find(instruction.register_writes.begin(), instruction.register_writes.end(), *first) !=
                instruction.register_writes.end() &&
            std::find(instruction.register_reads.begin(), instruction.register_reads.end(), *source) !=
                instruction.register_reads.end() &&
            std::find(instruction.register_reads.begin(), instruction.register_reads.end(),
                      RegisterOperand{RegisterBank::mips_gpr, 0, 32, false}) != instruction.register_reads.end();
        const bool recognized_mips32 = instruction.context.architecture != Architecture::mips32 || exact_mips32_copy;
        if (recognized_mips32 && mips_register(first, 29) && mips_register(source, 30) && state.frame_register == 30) {
            state.stack_depth = state.frame_depth;
            return true;
        }
        if (recognized_mips32 && mips_register(first, 30) && mips_register(source, 29)) {
            state.frame_depth = state.stack_depth;
            state.frame_register = 30;
            return true;
        }
        if (exact_mips32_copy && first->index != 0 && first->index != 29 && first->index != 30) {
            FlowValue relation;
            if (mips_register(source, 29)) relation = state.stack_depth;
            else if (mips_register(source, 30) && state.frame_register == 30) relation = state.frame_depth;
            else if (source->index != 0) relation = state.mips32_stack_alias_depths[source->index];
            state.mips32_stack_alias_depths[first->index] = relation;
            return true;
        }
    }
    if ((instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) &&
        instruction.opcode == Opcode::lea && first && first->bank == RegisterBank::gpr &&
        (first->index == 4 || first->index == 5) && first->width == pointer_bytes(instruction) * 8 &&
        instruction.operands.size() > 1) {
        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[1]);
        if (memory && memory->base && memory->base->bank == RegisterBank::gpr &&
            (memory->base->index == 4 || memory->base->index == 5) &&
            memory->base->width == first->width && memory->address_width == first->width &&
            !memory->index && !memory->ip_relative && !memory->segment) {
            auto relation = memory->base->index == 4 ? state.stack_depth : state.frame_depth;
            if (!relation.known) {
                if (first->index == 4)
                    state.stack_depth = {};
                else
                    state.frame_depth = {};
                state.supported = false;
                return true;
            }
            std::int64_t adjusted = 0;
            if (!subtract_checked(relation.value, memory->displacement, adjusted))
                return false;
            relation.value = adjusted;
            if (first->index == 4)
                state.stack_depth = relation;
            else
                state.frame_depth = relation;
            return true;
        }
    }
    if (instruction.context.architecture == Architecture::arm) {
        const auto arm_first = register_at(instruction, 0);
        const auto arm_second = register_at(instruction, 1);
        const bool sp_destination = arm32_register(arm_first, 13);
        if ((instruction.opcode == Opcode::a32_add || instruction.opcode == Opcode::a32_sub) &&
            sp_destination && arm32_register(arm_second, 13) && instruction.operands.size() >= 3) {
            const auto immediate = immediate_value(instruction, 2);
            if (!immediate) return false;
            if (instruction.opcode == Opcode::a32_sub) return add(state.stack_depth, *immediate);
            if (*immediate == INT64_MIN) return false;
            return add(state.stack_depth, -*immediate);
        }
        if (instruction.opcode == Opcode::a32_mov && arm_first && arm32_register(arm_second, 13) &&
            (arm_first->index == 7 || arm_first->index == 11)) {
            state.frame_depth = state.stack_depth;
            state.frame_register = arm_first->index;
            return true;
        }
        if ((instruction.opcode == Opcode::a32_add || instruction.opcode == Opcode::a32_sub) &&
            arm_first && arm_first->bank == RegisterBank::arm32_gpr &&
            (arm_first->index == 7 || arm_first->index == 11) && instruction.operands.size() >= 3) {
            const bool source_is_stack = arm32_register(arm_second, 13);
            const bool source_is_frame = arm_second && arm_second->bank == RegisterBank::arm32_gpr &&
                                         state.frame_register >= 0 && arm_second->index == state.frame_register;
            if (source_is_stack || source_is_frame) {
                const auto immediate = immediate_value(instruction, 2);
                if (!immediate) return false;
                auto relation = source_is_stack ? state.stack_depth : state.frame_depth;
                if (instruction.opcode == Opcode::a32_sub) {
                    if (!add(relation, *immediate)) return false;
                } else {
                    if (*immediate == INT64_MIN) return false;
                    if (!add(relation, -*immediate)) return false;
                }
                state.frame_depth = relation;
                state.frame_register = arm_first->index;
                if (!relation.known) state.supported = false;
                return true;
            }
        }        if (instruction.opcode == Opcode::a32_mov && sp_destination && arm_second &&
            arm_second->bank == RegisterBank::arm32_gpr && arm_second->index == state.frame_register &&
            state.frame_register >= 0) {
            state.stack_depth = state.frame_depth;
            return true;
        }
        if (instruction.opcode == Opcode::a32_stm || instruction.opcode == Opcode::a32_ldm) {
            const auto *list = instruction.operands.size() > 1
                                   ? std::get_if<ArmRegisterListOperand>(&instruction.operands[1])
                                   : nullptr;
            if (list && arm32_register(arm_first, 13) && instruction.arm && instruction.arm->writeback) {
                const auto bytes = static_cast<std::int64_t>(std::popcount(list->mask)) * 4;
                const auto mode = instruction.arm->multiple_mode;
                const bool adjusted = mode == ArmMultipleMode::ia || mode == ArmMultipleMode::ib
                                          ? add(state.stack_depth, -bytes)
                                          : add(state.stack_depth, bytes);
                if (instruction.opcode == Opcode::a32_ldm && state.frame_register >= 0 &&
                    (list->mask & (1u << state.frame_register))) {
                    state.frame_depth = {};
                    state.frame_register = -1;
                }
                return adjusted;
            }
            if (list && state.frame_register >= 0 &&
                arm32_register(arm_first, static_cast<std::uint8_t>(state.frame_register)) &&
                instruction.arm && instruction.arm->writeback) {
                const auto bytes = static_cast<std::int64_t>(std::popcount(list->mask)) * 4;
                const auto mode = instruction.arm->multiple_mode;
                auto adjusted = mode == ArmMultipleMode::ia || mode == ArmMultipleMode::ib
                                    ? add(state.frame_depth, -bytes)
                                    : add(state.frame_depth, bytes);
                if (instruction.opcode == Opcode::a32_ldm && (list->mask & (1u << state.frame_register))) {
                    state.frame_depth = {};
                    state.frame_register = -1;
                    state.supported = false;
                }
                return adjusted;
            }
        }
        if (const auto *memory = instruction.operands.size() > 1
                                     ? std::get_if<ArmMemoryOperand>(&instruction.operands[1])
                                     : nullptr;
            memory && arm32_register(std::optional{memory->base}, 13) && memory->writeback) {
            const auto *offset = std::get_if<std::uint32_t>(&memory->offset);
            if (!offset) return false;
            const auto delta = static_cast<std::int64_t>(*offset);
            return add(state.stack_depth, memory->add ? -delta : delta);
        }
    }
    if ((instruction.opcode == Opcode::add || instruction.opcode == Opcode::sub) && is_gpr(first, 4)) {
        const auto immediate = immediate_value(instruction, 1);
        if (immediate) {
            if (instruction.opcode == Opcode::sub)
                return add(state.stack_depth, *immediate);
            if (*immediate == INT64_MIN)
                return false;
            return add(state.stack_depth, -*immediate);
        }
    }

    const auto arm64_sp = [](const std::optional<RegisterOperand> &reg) {
        return reg && reg->bank == RegisterBank::arm64_sp;
    };
    if (instruction.context.architecture == Architecture::arm64 &&
        (instruction.opcode == Opcode::a64_add || instruction.opcode == Opcode::a64_sub) &&
        instruction.operands.size() >= 3) {
        const auto immediate = immediate_value(instruction, 2);
        const bool destination_is_sp = arm64_sp(first);
        const bool destination_is_gpr = first && first->bank == RegisterBank::arm64_gpr && first->index < 31;
        const bool valid_form = immediate && first && second &&
            (destination_is_sp || destination_is_gpr) && first->width == 64 && second->width == 64 &&
            instruction.flow == FlowKind::fallthrough &&
            instruction.access == std::vector<OperandAccess>{OperandAccess::write, OperandAccess::read,
                                                              OperandAccess::read};
        if (valid_form) {
            FlowValue base;
            bool stack_derived = false;
            if (arm64_sp(second)) {
                base = state.stack_depth;
                stack_derived = true;
            } else if (second->bank == RegisterBank::arm64_gpr && second->index == 29 &&
                       state.arm64_frame_pointer) {
                base = state.frame_depth;
                stack_derived = true;
            } else if (second->bank == RegisterBank::arm64_gpr && second->index < 31 &&
                       state.arm64_stack_alias_depths[second->index].known) {
                base = state.arm64_stack_alias_depths[second->index];
                stack_derived = true;
            }
            FlowValue relation = base;
            if (relation.known) {
                const auto delta = instruction.opcode == Opcode::a64_sub ? *immediate : -*immediate;
                if (!add(relation, delta)) {
                    if (destination_is_sp) state.stack_depth = {};
                    else if (first->index == 29) {
                        state.frame_depth = {};
                        state.arm64_frame_pointer = false;
                    } else state.arm64_stack_alias_depths[first->index] = {};
                    return false;
                }
            }
            if (destination_is_sp) {
                if (!stack_derived || !relation.known) state.supported = false;
                state.stack_depth = relation;
                return true;
            }
            if (first->index == 29) {
                state.frame_depth = relation;
                state.arm64_frame_pointer = stack_derived && relation.known;
                if (stack_derived && !relation.known) state.supported = false;
                return true;
            }
            state.arm64_stack_alias_depths[first->index] = stack_derived ? relation : FlowValue{};
            if (stack_derived && !relation.known) state.supported = false;
            return true;
        }
        if (first && first->bank == RegisterBank::arm64_gpr && first->index < 31 && first->index != 29)
            state.arm64_stack_alias_depths[first->index] = {};
    }

    // Pair and scalar load/store writeback through SP is a common AArch64
    // prologue/epilogue form (for example STP/LDP x29,x30,[sp,#-16]!). The
    // memory operand carries the exact architectural writeback amount; track
    // it in entry-SP coordinates instead of treating the SP write as unknown.
    if (instruction.context.architecture == Architecture::arm64) {
        const MemoryOperand *stack_writeback = nullptr;
        bool alias_writeback = false;
        for (const auto &operand : instruction.operands) {
            const auto *memory = std::get_if<MemoryOperand>(&operand);
            if (!memory || !memory->base || !memory->writeback)
                continue;
            const bool stack_base = memory->base->bank == RegisterBank::arm64_sp;
            const bool alias_base = memory->base->bank == RegisterBank::arm64_gpr &&
                                    memory->base->index < state.arm64_stack_alias_depths.size() &&
                                    state.arm64_stack_alias_depths[memory->base->index].known;
            if (!stack_base && !alias_base) continue;
            if (stack_writeback || memory->address_width != 64 || memory->index || memory->scale != 1) {
                state.stack_depth = {};
                state.supported = false;
                return true;
            }
            stack_writeback = memory;
            alias_writeback = alias_base;
        }
        if (stack_writeback) {
            FlowValue *depth = &state.stack_depth;
            if (alias_writeback) {
                depth = &state.arm64_stack_alias_depths[stack_writeback->base->index];
                const auto base_index = stack_writeback->base->index;
                bool destination_overlap = false;
                for (std::size_t index = 0; index < instruction.operands.size() &&
                     index < instruction.access.size(); ++index) {
                    const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[index]);
                    if (reg && instruction.access[index] != OperandAccess::read &&
                        reg->bank == RegisterBank::arm64_gpr && reg->index == base_index) {
                        destination_overlap = true;
                        break;
                    }
                }
                if (destination_overlap) {
                    *depth = {};
                    state.supported = false;
                    return true;
                }
            }
            if (stack_writeback->writeback_displacement == INT64_MIN ||
                !add(*depth, -stack_writeback->writeback_displacement))
                return false;
            for (const auto &reg : instruction.register_writes)
                if (reg.bank == RegisterBank::arm64_gpr && reg.index < state.arm64_stack_alias_depths.size() &&
                    (!alias_writeback || reg.index != stack_writeback->base->index))
                    state.arm64_stack_alias_depths[reg.index] = {};
            if (std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                    [](const RegisterOperand &reg) {
                        return reg.bank == RegisterBank::arm64_gpr && reg.index == 29;
                    })) {
                state.frame_depth = {};
                state.arm64_frame_pointer = false;
            }
            return true;
        }
    }

    if (instruction.context.architecture == Architecture::arm64) {
        if (instruction.flow == FlowKind::call) {
            for (auto &alias : state.arm64_stack_alias_depths) alias = {};
        } else {
            for (const auto &reg : instruction.register_writes)
                if (reg.bank == RegisterBank::arm64_gpr && reg.index < state.arm64_stack_alias_depths.size())
                    state.arm64_stack_alias_depths[reg.index] = {};
            for (std::size_t index = 0; index < instruction.operands.size() &&
                 index < instruction.access.size(); ++index) {
                const auto *reg = std::get_if<RegisterOperand>(&instruction.operands[index]);
                if (reg && instruction.access[index] != OperandAccess::read &&
                    reg->bank == RegisterBank::arm64_gpr && reg->index < state.arm64_stack_alias_depths.size())
                    state.arm64_stack_alias_depths[reg->index] = {};
            }
        }
    }

    if (instruction.context.architecture == Architecture::mips32 &&
        instruction.context.mode == ExecutionMode::mips32) {
        if (instruction.flow == FlowKind::call) {
            for (auto &alias : state.mips32_stack_alias_depths) alias = {};
        } else {
            const auto invalidate_alias = [&](const RegisterOperand &reg) {
                if (reg.bank == RegisterBank::mips_gpr && reg.index != 0 && reg.index < 32)
                    state.mips32_stack_alias_depths[reg.index] = {};
            };
            for (const auto &reg : instruction.register_writes) invalidate_alias(reg);
            for (std::size_t index = 0; index < instruction.operands.size() && index < instruction.access.size(); ++index) {
                if (instruction.access[index] == OperandAccess::write ||
                    instruction.access[index] == OperandAccess::read_write) {
                    if (const auto reg = register_at(instruction, index)) invalidate_alias(*reg);
                }
            }
        }
    }

    bool wrote_stack = false;
    bool wrote_frame = false;
    for (const auto &reg : instruction.register_writes) {
        if (reg.bank == RegisterBank::gpr && reg.index == 4)
            wrote_stack = true;
        if (reg.bank == RegisterBank::arm64_sp)
            wrote_stack = true;
        if (reg.bank == RegisterBank::gpr && reg.index == 5)
            wrote_frame = true;
        if (reg.bank == RegisterBank::arm32_gpr && reg.index == 13)
            wrote_stack = true;
        if (reg.bank == RegisterBank::arm32_gpr && state.frame_register >= 0 &&
            reg.index == state.frame_register)
            wrote_frame = true;
        if (reg.bank == RegisterBank::arm64_gpr && reg.index == 29)
            wrote_frame = true;
        if ((instruction.context.architecture == Architecture::mips32 ||
             instruction.context.architecture == Architecture::mips64) && reg.bank == RegisterBank::mips_gpr) {
            if (reg.index == 29) wrote_stack = true;
            if (reg.index == 30) wrote_frame = true;
        }
        if ((instruction.context.architecture == Architecture::riscv32 ||
             instruction.context.architecture == Architecture::riscv64) && reg.bank == RegisterBank::riscv_gpr) {
            if (reg.index == 2) wrote_stack = true;
            if (reg.index == 8) wrote_frame = true;
        }
        if (instruction.context.architecture == Architecture::powerpc && reg.bank == RegisterBank::ppc_gpr) {
            if (reg.index == 1) wrote_stack = true;
            if (state.frame_register == 31 && reg.index == 31) wrote_frame = true;
        }
        if (instruction.context.architecture == Architecture::mos6502 &&
            reg.bank == RegisterBank::mos6502 && reg.index < state.m6502_stack_alias_deltas.size())
            state.m6502_stack_alias_deltas[reg.index] = {};
    }
    for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
        if (i >= instruction.access.size() ||
            (instruction.access[i] != OperandAccess::write && instruction.access[i] != OperandAccess::read_write))
            continue;
        const auto reg = register_at(instruction, i);
        wrote_stack = wrote_stack || is_gpr(reg, 4);
        wrote_stack = wrote_stack || arm64_sp(reg);
        wrote_frame = wrote_frame || is_gpr(reg, 5);
        wrote_frame = wrote_frame || (reg && reg->bank == RegisterBank::arm64_gpr && reg->index == 29);
        wrote_stack = wrote_stack || arm32_register(reg, 13);
        wrote_frame = wrote_frame || (reg && reg->bank == RegisterBank::arm32_gpr &&
                                      state.frame_register >= 0 && reg->index == state.frame_register);
        if ((instruction.context.architecture == Architecture::mips32 ||
             instruction.context.architecture == Architecture::mips64) && reg &&
            reg->bank == RegisterBank::mips_gpr) {
            wrote_stack = wrote_stack || reg->index == 29;
            wrote_frame = wrote_frame || (state.frame_register >= 0 && reg->index == 30);
        }
        if ((instruction.context.architecture == Architecture::riscv32 ||
             instruction.context.architecture == Architecture::riscv64) && reg &&
            reg->bank == RegisterBank::riscv_gpr) {
            wrote_stack = wrote_stack || reg->index == 2;
            wrote_frame = wrote_frame || (state.frame_register == 8 && reg->index == 8);
        }
        if (instruction.context.architecture == Architecture::powerpc && reg &&
            reg->bank == RegisterBank::ppc_gpr) {
            wrote_stack = wrote_stack || reg->index == 1;
            wrote_frame = wrote_frame || (state.frame_register == 31 && reg->index == 31);
        }
        if (instruction.context.architecture == Architecture::mos6502 && reg &&
            reg->bank == RegisterBank::mos6502 && reg->index < state.m6502_stack_alias_deltas.size())
            state.m6502_stack_alias_deltas[reg->index] = {};
    }
    if (wrote_stack) {
        state.stack_depth = {};
        state.supported = false;
    }
    if (wrote_frame) {
        state.frame_depth = {};
        state.frame_register = -1;
        state.frame_register_delta = {};
        state.arm64_frame_pointer = false;
    }
    return true;
}

} // namespace

std::optional<CallingConvention> default_stack_calling_convention(const ImageMetadata &metadata) {
    if (metadata.pe) return CallingConvention::windows_x64;
    if (metadata.elf) {
        constexpr std::uint16_t em_ppc64 = 21;
        constexpr std::uint32_t ppc64_abi_mask = 0x3;
        const auto &header = metadata.elf->header;
        constexpr std::uint16_t em_mips = 8;
        constexpr std::uint32_t ef_mips_abi2 = 0x20;
        constexpr std::uint32_t ef_mips_abi_mask = 0xf000;
        // Linux N32 uses ELF32 plus EF_MIPS_ABI2. Restrict automatic selection
        // to generic Linux/SysV OSABI and no conflicting ABI selector.
        if (header.machine == em_mips && !header.is_64 &&
            (header.flags & ef_mips_abi2) != 0 && (header.flags & ef_mips_abi_mask) == 0 &&
            (header.os_abi == 0 || header.os_abi == 3))
            return CallingConvention::mips_n32;
        // N64 is the ELF64 MIPS ABI with neither the N32 marker nor a
        // conflicting explicit ABI selector. Accept only generic SysV/Linux
        // OSABI metadata; other MIPS environments have independent rules.
        if (header.machine == em_mips && header.is_64 &&
            (header.flags & (ef_mips_abi2 | ef_mips_abi_mask)) == 0 &&
            (header.os_abi == 0 || header.os_abi == 3))
            return CallingConvention::mips_n64;
        if (header.machine == em_ppc64 && header.is_64 && header.order == ByteOrder::little &&
            (header.flags & ppc64_abi_mask) == 2)
            return CallingConvention::ppc64le_elfv2;
        return CallingConvention::sysv_x86_64;
    }
    if (metadata.macho) return CallingConvention::sysv_x86_64;
    return {};
}

Result<StackFrameAnalysis> analyze_stack_frame(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                               std::stop_token stop,
                                               std::optional<CallingConvention> image_default_convention) {
    if (stop.stop_requested())
        return Error{ErrorCode::canceled, "Stack analysis canceled"};
    if (function.blocks.empty())
        return Error{ErrorCode::invalid_argument, "Function has no recovered blocks"};
    if (snapshot.blocks.size() > 1000000)
        return Error{ErrorCode::resource_limit, "Stack analysis block budget exceeded"};

    std::map<std::uint64_t, std::shared_ptr<const BasicBlock>> blocks;
    std::set<std::uint64_t> owned;
    for (const auto id : function.blocks)
        owned.insert(id.value);
    for (const auto &block : snapshot.blocks)
        if (block)
            blocks.emplace(block->id.value, block);
    auto entry = blocks.end();
    for (const auto id : function.blocks) {
        const auto candidate = blocks.find(id.value);
        if (candidate != blocks.end() && candidate->second->begin == function.entry) {
            entry = candidate;
            break;
        }
    }
    if (entry == blocks.end())
        return Error{ErrorCode::invalid_argument, "Function entry block is missing"};
    const auto x86_32_cleanup = x86_32_callee_cleanup_bytes(function, blocks);

    std::map<std::uint64_t, FlowState> inputs;
    inputs[entry->first] = {true, {true, 0}, {}, true, false};
    std::deque<std::uint64_t> pending{entry->first};
    std::size_t iterations = 0;
    while (!pending.empty()) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Stack analysis canceled"};
        if (++iterations > 4000000)
            return Error{ErrorCode::resource_limit, "Stack analysis flow budget exceeded"};
        const auto id = pending.front();
        pending.pop_front();
        const auto block = blocks.find(id);
        if (block == blocks.end())
            continue;
        auto output = inputs[id];
        for (const auto &fact : block->second->instructions)
            if (fact && !transfer(fact->instruction, output)) {
                output.stack_depth = {};
                output.supported = false;
            }
        for (const auto &successor : block->second->successors) {
            if (!successor.block || !owned.contains(successor.block->value) || !blocks.contains(successor.block->value))
                continue;
            const auto id_to = successor.block->value;
            if (merge(inputs[id_to], output))
                pending.push_back(id_to);
        }
    }

    StackFrameAnalysis result;
    result.complete = function.complete;
    std::size_t access_detail_count = 0;
    bool stack_extent_known = function.complete;
    std::uint64_t maximum_stack_allocation = 0;
    std::size_t stack_call_argument_detail_count = 0;
    const auto observe_stack_depth = [&](FlowValue depth, bool wrapping_page_stack = false) {
        if (!depth.known || depth.value < 0) {
            stack_extent_known = false;
            return;
        }
        if (wrapping_page_stack && depth.value > 256) {
            result.complete = false;
            depth.value = 256;
        }
        maximum_stack_allocation = std::max(maximum_stack_allocation,
                                             static_cast<std::uint64_t>(depth.value));
    };
    for (const auto id : function.blocks) {
        const auto block = blocks.find(id.value);
        const auto state = inputs.find(id.value);
        if (block == blocks.end() || state == inputs.end() || !state->second.reachable)
            stack_extent_known = false;
    }
    for (const auto &[id, state] : inputs) {
        (void)id;
        if (state.reachable && (!state.supported || state.ambiguous))
            result.complete = false;
    }
    for (const auto id : function.blocks) {
        if (stop.stop_requested())
            return Error{ErrorCode::canceled, "Stack analysis canceled"};
        const auto block = blocks.find(id.value);
        const auto input = inputs.find(id.value);
        if (block == blocks.end() || input == inputs.end() || !input->second.reachable)
            continue;
        auto state = input->second;
        const bool m6502_block = !block->second->instructions.empty() && block->second->instructions.front() &&
            block->second->instructions.front()->instruction.context.architecture == Architecture::mos6502;
        observe_stack_depth(state.stack_depth, m6502_block);
        struct PendingX86Push {
            std::int64_t offset = 0;
            std::uint16_t width = 0;
            Address instruction;
        };
        std::vector<PendingX86Push> pending_x86_pushes;
        bool pending_x86_pushes_valid = true;
        struct PendingArm64Store {
            std::int64_t offset = 0;
            std::uint16_t width = 0;
            Address instruction;
        };
        std::vector<PendingArm64Store> pending_arm64_stores;
        struct PendingRiscvStore {
            std::int64_t offset = 0;
            std::int64_t stack_depth = 0;
            std::uint16_t width = 0;
            Address instruction;
        };
        std::vector<PendingRiscvStore> pending_riscv_stores;
        struct PendingPowerPCStore {
            std::int64_t offset = 0;
            std::int64_t stack_depth = 0;
            std::uint16_t width = 0;
            Address instruction;
        };
        std::vector<PendingPowerPCStore> pending_powerpc_stores;
        struct PendingMipsStore {
            std::int64_t offset = 0;
            std::int64_t stack_depth = 0;
            std::uint16_t width = 0;
            Address instruction;
        };
        std::vector<PendingMipsStore> pending_mips_stores;
        struct PendingArm32Store {
            std::int64_t offset = 0;
            std::int64_t stack_depth = 0;
            std::uint16_t width = 0;
            Address instruction;
        };
        std::vector<PendingArm32Store> pending_arm32_stores;
        struct PendingWindowsOutgoingStore {
            std::int64_t offset = 0;
            std::int64_t stack_depth = 0;
            std::uint16_t width = 0;
            Address instruction;
        };
        std::vector<PendingWindowsOutgoingStore> pending_windows_outgoing_stores;
        for (std::size_t instruction_index = 0;
             instruction_index < block->second->instructions.size(); ++instruction_index) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Stack analysis canceled"};
            const auto &fact = block->second->instructions[instruction_index];
            if (!fact) {
                pending_x86_pushes.clear();
                pending_x86_pushes_valid = true;
                pending_arm64_stores.clear();
                pending_riscv_stores.clear();
                pending_powerpc_stores.clear();
                pending_mips_stores.clear();
                pending_arm32_stores.clear();
                pending_windows_outgoing_stores.clear();
                continue;
            }
            const auto &instruction = fact->instruction;
            const auto stack_depth_before_instruction = state.stack_depth;
            const bool windows_x64_abi = instruction.context.architecture == Architecture::x86_64 &&
                instruction.context.mode == ExecutionMode::x86_64 && image_default_convention &&
                *image_default_convention == CallingConvention::windows_x64;
            if (windows_x64_abi && instruction.flow == FlowKind::call) {
                for (const auto &store : pending_windows_outgoing_stores) {
                    if (!state.stack_depth.known || store.stack_depth != state.stack_depth.value) continue;
                    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
                        return candidate.offset_from_entry_sp == store.offset && candidate.width == store.width;
                    });
                    if (slot == result.slots.end()) continue;
                    const StackSlotCallArgument provenance{store.instruction, instruction.address,
                        StackCallArgumentSourceKind::windows_x64_outgoing_store};
                    if (std::find(slot->outgoing_call_arguments.begin(), slot->outgoing_call_arguments.end(),
                                  provenance) != slot->outgoing_call_arguments.end()) continue;
                    if (stack_call_argument_detail_count >= 1'000'000) { result.complete = false; break; }
                    slot->outgoing_call_arguments.push_back(provenance);
                    ++stack_call_argument_detail_count;
                }
                pending_windows_outgoing_stores.clear();
            } else if (!windows_x64_abi || instruction.flow != FlowKind::fallthrough) {
                pending_windows_outgoing_stores.clear();
            } else {
                if (std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                    [](const auto &reg) { return reg.bank == RegisterBank::gpr && reg.index == 4 && reg.width == 64; }))
                    pending_windows_outgoing_stores.clear();
                bool captured_store = false;
                if (instruction.memory_write && state.stack_depth.known && state.stack_depth.value >= 32) {
                    for (std::size_t operand_index = 0; operand_index < instruction.operands.size(); ++operand_index) {
                        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[operand_index]);
                        if (!memory || operand_index >= instruction.access.size() ||
                            instruction.access[operand_index] != OperandAccess::write || !memory->base ||
                            memory->base->bank != RegisterBank::gpr || memory->base->index != 4 ||
                            memory->base->width != 64 || memory->address_width != 64 || memory->index ||
                            memory->ip_relative || memory->writeback || memory->post_index ||
                            memory->displacement < 0 || memory->displacement > 4096 ||
                            !memory->data_width || memory->data_width > 64 || memory->data_width % 8) continue;
                        const auto width_bytes = static_cast<std::int64_t>(memory->data_width / 8);
                        const auto store_end = memory->displacement + width_bytes;
                        const bool shadow_store = memory->displacement < 32 && store_end <= 32;
                        const bool stack_argument_store = memory->displacement >= 32 &&
                            memory->displacement % 8 == 0 && width_bytes <= 8 &&
                            store_end <= state.stack_depth.value;
                        if (!shadow_store && !stack_argument_store) continue;
                        std::int64_t offset = 0;
                        if (!subtract_checked(memory->displacement, state.stack_depth.value, offset)) continue;
                        if (pending_windows_outgoing_stores.size() >= 1024) {
                            pending_windows_outgoing_stores.clear();
                            break;
                        }
                        std::int64_t end = 0;
                        if (!add_checked(offset, width_bytes, end)) continue;
                        std::erase_if(pending_windows_outgoing_stores, [&](const auto &previous) {
                            std::int64_t previous_end = 0;
                            if (!add_checked(previous.offset, previous.width / 8, previous_end)) return true;
                            return offset < previous_end && previous.offset < end;
                        });
                        pending_windows_outgoing_stores.push_back({offset, state.stack_depth.value,
                            memory->data_width, instruction.address});
                        captured_store = true;
                    }
                }
                if (!captured_store && (instruction.memory_write || instruction.memory_read))
                    pending_windows_outgoing_stores.clear();
            }
            if (instruction.context.architecture == Architecture::arm64 &&
                instruction.opcode == Opcode::a64_bl && instruction.flow == FlowKind::call) {
                for (const auto &store : pending_arm64_stores) {
                    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
                        return candidate.offset_from_entry_sp == store.offset && candidate.width == store.width;
                    });
                    if (slot == result.slots.end()) continue;
                    const StackSlotCallArgument provenance{store.instruction, instruction.address,
                                                           StackCallArgumentSourceKind::aarch64_store};
                    if (std::find(slot->outgoing_call_arguments.begin(), slot->outgoing_call_arguments.end(),
                                  provenance) != slot->outgoing_call_arguments.end())
                        continue;
                    if (stack_call_argument_detail_count >= 1'000'000) {
                        result.complete = false;
                        break;
                    }
                    slot->outgoing_call_arguments.push_back(provenance);
                    ++stack_call_argument_detail_count;
                }
                pending_arm64_stores.clear();
            } else if (instruction.context.architecture == Architecture::arm64 &&
                       instruction.flow != FlowKind::fallthrough) {
                pending_arm64_stores.clear();
            } else if (instruction.context.architecture == Architecture::arm64) {
                const bool pair_store = instruction.opcode == Opcode::a64_stp;
                const bool scalar_store = instruction.opcode == Opcode::a64_str ||
                    instruction.opcode == Opcode::a64_strb || instruction.opcode == Opcode::a64_strh;
                const std::size_t memory_index = pair_store ? 2 : 1;
                const auto *memory = pair_store || scalar_store
                    ? (memory_index < instruction.operands.size()
                        ? std::get_if<MemoryOperand>(&instruction.operands[memory_index]) : nullptr)
                    : nullptr;
                const bool store_access = memory && memory_index < instruction.access.size() &&
                    instruction.access[memory_index] == OperandAccess::write;
                FlowValue base_depth;
                if (memory && memory->base) {
                    if (memory->base->bank == RegisterBank::arm64_sp)
                        base_depth = state.stack_depth;
                    else if (memory->base->bank == RegisterBank::arm64_gpr && memory->base->index == 29 &&
                             state.arm64_frame_pointer)
                        base_depth = state.frame_depth;
                    else if (memory->base->bank == RegisterBank::arm64_gpr &&
                             memory->base->index < state.arm64_stack_alias_depths.size())
                        base_depth = state.arm64_stack_alias_depths[memory->base->index];
                }
                if (store_access && base_depth.known && state.stack_depth.known &&
                    !memory->index && !memory->ip_relative && !memory->writeback && !memory->post_index &&
                    memory->address_width == 64 && memory->data_width > 0 && memory->data_width % 8 == 0) {
                    const auto width = memory->data_width;
                    const auto element_bytes = static_cast<std::int64_t>(width / 8);
                    const auto count = pair_store ? 2 : 1;
                    for (int element = 0; element < count; ++element) {
                        std::int64_t displacement = memory->displacement;
                        std::int64_t offset = 0;
                        std::int64_t current_sp_displacement = 0;
                        if ((element && !add_checked(displacement, element_bytes, displacement)) ||
                            !subtract_checked(displacement, base_depth.value, offset) ||
                            !add_checked(offset, state.stack_depth.value, current_sp_displacement) ||
                            current_sp_displacement < 0) {
                            pending_arm64_stores.clear();
                            break;
                        }
                        if (pending_arm64_stores.size() >= 1024) {
                            pending_arm64_stores.clear();
                            break;
                        }
                        std::int64_t new_end = 0;
                        if (!add_checked(offset, element_bytes, new_end)) {
                            pending_arm64_stores.clear();
                            break;
                        }
                        std::erase_if(pending_arm64_stores, [&](const auto &previous) {
                            std::int64_t previous_end = 0;
                            if (!add_checked(previous.offset, previous.width / 8, previous_end))
                                return true;
                            return offset < previous_end && previous.offset < new_end;
                        });
                        pending_arm64_stores.push_back({offset, width, instruction.address});
                    }
                } else if (instruction.memory_write || instruction.memory_read) {
                    // Do not carry candidate outgoing stores across other memory traffic.
                    pending_arm64_stores.clear();
                }
            }
            const bool riscv_stack_context =
                (instruction.context.architecture == Architecture::riscv32 &&
                 instruction.context.mode == ExecutionMode::rv32) ||
                (instruction.context.architecture == Architecture::riscv64 &&
                 (instruction.context.mode == ExecutionMode::rv64 ||
                  instruction.context.mode == ExecutionMode::rv64c));
            if (riscv_stack_context && instruction.flow == FlowKind::call) {
                for (const auto &store : pending_riscv_stores) {
                    if (!state.stack_depth.known || state.stack_depth.value != store.stack_depth) continue;
                    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
                        return candidate.offset_from_entry_sp == store.offset && candidate.width == store.width;
                    });
                    if (slot == result.slots.end()) continue;
                    const StackSlotCallArgument provenance{store.instruction, instruction.address,
                        StackCallArgumentSourceKind::riscv_store};
                    if (std::find(slot->outgoing_call_arguments.begin(), slot->outgoing_call_arguments.end(),
                                  provenance) != slot->outgoing_call_arguments.end()) continue;
                    if (stack_call_argument_detail_count >= 1'000'000) { result.complete = false; break; }
                    slot->outgoing_call_arguments.push_back(provenance);
                    ++stack_call_argument_detail_count;
                }
                pending_riscv_stores.clear();
            } else if (!riscv_stack_context || instruction.flow != FlowKind::fallthrough) {
                pending_riscv_stores.clear();
            } else {
                const auto width = static_cast<std::uint16_t>(instruction.context.mode == ExecutionMode::rv32 ? 32 : 64);
                if (std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                    [&](const auto &reg) { return reg.bank == RegisterBank::riscv_gpr && reg.index == 2 &&
                                                  reg.width == width; }))
                    pending_riscv_stores.clear();
                bool captured_store = false;
                const auto expected_store = width == 32 ? Opcode::rv_sw : Opcode::rv_sd;
                if (instruction.memory_write && instruction.opcode == expected_store && state.stack_depth.known) {
                    for (std::size_t operand_index = 0; operand_index < instruction.operands.size(); ++operand_index) {
                        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[operand_index]);
                        if (!memory || operand_index >= instruction.access.size() ||
                            instruction.access[operand_index] != OperandAccess::write || !memory->base ||
                            memory->base->bank != RegisterBank::riscv_gpr || memory->base->index != 2 ||
                            memory->base->width != width || memory->address_width != width || memory->index ||
                            memory->ip_relative || memory->writeback || memory->post_index ||
                            memory->displacement < 0 || memory->data_width != width) continue;
                        std::int64_t offset = 0;
                        if (!subtract_checked(memory->displacement, state.stack_depth.value, offset)) continue;
                        if (pending_riscv_stores.size() >= 1024) {
                            pending_riscv_stores.clear();
                            break;
                        }
                        std::int64_t end = 0;
                        if (!add_checked(offset, width / 8, end)) continue;
                        std::erase_if(pending_riscv_stores, [&](const auto &previous) {
                            std::int64_t previous_end = 0;
                            if (!add_checked(previous.offset, previous.width / 8, previous_end)) return true;
                            return offset < previous_end && previous.offset < end;
                        });
                        pending_riscv_stores.push_back({offset, state.stack_depth.value, width, instruction.address});
                        captured_store = true;
                    }
                }
                if (!captured_store && (instruction.memory_write || instruction.memory_read))
                    pending_riscv_stores.clear();
            }
            const bool powerpc_stack_context = instruction.context.architecture == Architecture::powerpc &&
                (instruction.context.mode == ExecutionMode::ppc32 || instruction.context.mode == ExecutionMode::ppc64);
            if (powerpc_stack_context && instruction.flow == FlowKind::call) {
                for (const auto &store : pending_powerpc_stores) {
                    if (!state.stack_depth.known || state.stack_depth.value != store.stack_depth) continue;
                    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
                        return candidate.offset_from_entry_sp == store.offset && candidate.width == store.width;
                    });
                    if (slot == result.slots.end()) continue;
                    const StackSlotCallArgument provenance{store.instruction, instruction.address,
                        StackCallArgumentSourceKind::powerpc_store};
                    if (std::find(slot->outgoing_call_arguments.begin(), slot->outgoing_call_arguments.end(),
                                  provenance) != slot->outgoing_call_arguments.end()) continue;
                    if (stack_call_argument_detail_count >= 1'000'000) { result.complete = false; break; }
                    slot->outgoing_call_arguments.push_back(provenance);
                    ++stack_call_argument_detail_count;
                }
                pending_powerpc_stores.clear();
            } else if (!powerpc_stack_context || instruction.flow != FlowKind::fallthrough) {
                pending_powerpc_stores.clear();
            } else {
                const auto width = static_cast<std::uint16_t>(instruction.context.mode == ExecutionMode::ppc32 ? 32 : 64);
                if (std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                    [&](const auto &reg) { return reg.bank == RegisterBank::ppc_gpr && reg.index == 1 &&
                                                  reg.width == width; }))
                    pending_powerpc_stores.clear();
                bool captured_store = false;
                if (instruction.memory_write && state.stack_depth.known &&
                    (instruction.opcode == Opcode::ppc_stw || instruction.opcode == Opcode::ppc_std)) {
                    for (std::size_t operand_index = 0; operand_index < instruction.operands.size(); ++operand_index) {
                        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[operand_index]);
                        if (!memory || operand_index >= instruction.access.size() ||
                            instruction.access[operand_index] != OperandAccess::write || !memory->base ||
                            memory->base->bank != RegisterBank::ppc_gpr || memory->base->index != 1 ||
                            memory->base->width != width || memory->address_width != width || memory->index ||
                            memory->ip_relative || memory->writeback || memory->post_index ||
                            memory->displacement < 0 || !memory->data_width || memory->data_width % 8) continue;
                        const auto expected_width = instruction.opcode == Opcode::ppc_std ? 64 : 32;
                        if (memory->data_width != expected_width) continue;
                        const auto byte_width = static_cast<std::int64_t>(memory->data_width / 8);
                        std::int64_t offset = 0;
                        if (!subtract_checked(memory->displacement, state.stack_depth.value, offset)) continue;
                        if (pending_powerpc_stores.size() >= 1024) {
                            pending_powerpc_stores.clear();
                            break;
                        }
                        std::int64_t end = 0;
                        if (!add_checked(offset, byte_width, end)) continue;
                        std::erase_if(pending_powerpc_stores, [&](const auto &previous) {
                            std::int64_t previous_end = 0;
                            if (!add_checked(previous.offset, previous.width / 8, previous_end)) return true;
                            return offset < previous_end && previous.offset < end;
                        });
                        pending_powerpc_stores.push_back({offset, state.stack_depth.value,
                                                          memory->data_width, instruction.address});
                        captured_store = true;
                    }
                }
                if (!captured_store && (instruction.memory_write || instruction.memory_read))
                    pending_powerpc_stores.clear();
            }
            const bool mips_stack_context =
                (instruction.context.architecture == Architecture::mips32 && instruction.context.mode == ExecutionMode::mips32) ||
                (instruction.context.architecture == Architecture::mips64 && instruction.context.mode == ExecutionMode::mips64);
            if (mips_stack_context && instruction.flow == FlowKind::call) {
                for (const auto &store : pending_mips_stores) {
                    if (!state.stack_depth.known || state.stack_depth.value != store.stack_depth) continue;
                    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
                        return candidate.offset_from_entry_sp == store.offset && candidate.width == store.width;
                    });
                    if (slot == result.slots.end()) continue;
                    const StackSlotCallArgument provenance{store.instruction, instruction.address,
                        StackCallArgumentSourceKind::mips_store};
                    if (std::find(slot->outgoing_call_arguments.begin(), slot->outgoing_call_arguments.end(),
                                  provenance) != slot->outgoing_call_arguments.end()) continue;
                    if (stack_call_argument_detail_count >= 1'000'000) { result.complete = false; break; }
                    slot->outgoing_call_arguments.push_back(provenance);
                    ++stack_call_argument_detail_count;
                }
                pending_mips_stores.clear();
            } else if (!mips_stack_context || instruction.flow != FlowKind::fallthrough) {
                pending_mips_stores.clear();
            } else {
                const auto width = static_cast<std::uint16_t>(instruction.context.mode == ExecutionMode::mips32 ? 32 : 64);
                if (std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                    [&](const auto &reg) { return reg.bank == RegisterBank::mips_gpr && reg.index == 29 &&
                                                  reg.width == width; }))
                    pending_mips_stores.clear();
                bool captured_store = false;
                const auto expected_store = width == 32 ? Opcode::mips_sw : Opcode::mips64_sd;
                if (instruction.memory_write && instruction.opcode == expected_store && state.stack_depth.known) {
                    for (std::size_t operand_index = 0; operand_index < instruction.operands.size(); ++operand_index) {
                        const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[operand_index]);
                        if (!memory || operand_index >= instruction.access.size() ||
                            instruction.access[operand_index] != OperandAccess::write || !memory->base ||
                            memory->base->bank != RegisterBank::mips_gpr || memory->base->index != 29 ||
                            memory->base->width != width || memory->address_width != width || memory->index ||
                            memory->ip_relative || memory->writeback || memory->post_index ||
                            memory->displacement < 0 || memory->data_width != width) continue;
                        const auto byte_width = static_cast<std::int64_t>(width / 8);
                        std::int64_t offset = 0;
                        if (!subtract_checked(memory->displacement, state.stack_depth.value, offset)) continue;
                        if (pending_mips_stores.size() >= 1024) {
                            pending_mips_stores.clear();
                            break;
                        }
                        std::int64_t end = 0;
                        if (!add_checked(offset, byte_width, end)) continue;
                        std::erase_if(pending_mips_stores, [&](const auto &previous) {
                            std::int64_t previous_end = 0;
                            if (!add_checked(previous.offset, previous.width / 8, previous_end)) return true;
                            return offset < previous_end && previous.offset < end;
                        });
                        pending_mips_stores.push_back({offset, state.stack_depth.value, width, instruction.address});
                        captured_store = true;
                    }
                }
                if (!captured_store && (instruction.memory_write || instruction.memory_read))
                    pending_mips_stores.clear();
            }
            const bool arm32_stack_context = instruction.context.architecture == Architecture::arm &&
                (instruction.context.mode == ExecutionMode::a32 || instruction.context.mode == ExecutionMode::thumb);
            if (arm32_stack_context && instruction.flow == FlowKind::call && instruction.condition == 14) {
                for (const auto &store : pending_arm32_stores) {
                    if (!state.stack_depth.known || state.stack_depth.value != store.stack_depth) continue;
                    const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
                        return candidate.offset_from_entry_sp == store.offset && candidate.width == store.width;
                    });
                    if (slot == result.slots.end()) continue;
                    const StackSlotCallArgument provenance{store.instruction, instruction.address,
                        StackCallArgumentSourceKind::aapcs32_store};
                    if (std::find(slot->outgoing_call_arguments.begin(), slot->outgoing_call_arguments.end(),
                                  provenance) != slot->outgoing_call_arguments.end()) continue;
                    if (stack_call_argument_detail_count >= 1'000'000) { result.complete = false; break; }
                    slot->outgoing_call_arguments.push_back(provenance);
                    ++stack_call_argument_detail_count;
                }
                pending_arm32_stores.clear();
            } else if (!arm32_stack_context || instruction.flow != FlowKind::fallthrough) {
                pending_arm32_stores.clear();
            } else {
                if (std::any_of(instruction.register_writes.begin(), instruction.register_writes.end(),
                    [](const auto &reg) { return reg.bank == RegisterBank::arm32_gpr && reg.index == 13; }))
                    pending_arm32_stores.clear();
                bool captured_store = false;
                if (instruction.memory_write && state.stack_depth.known && instruction.condition == 14 &&
                    (instruction.opcode == Opcode::a32_str || instruction.opcode == Opcode::a32_strb ||
                     instruction.opcode == Opcode::a32_strh)) {
                    for (std::size_t operand_index = 0; operand_index < instruction.operands.size(); ++operand_index) {
                        const auto *memory = std::get_if<ArmMemoryOperand>(&instruction.operands[operand_index]);
                        if (!memory || operand_index >= instruction.access.size() ||
                            instruction.access[operand_index] != OperandAccess::write ||
                            memory->base.bank != RegisterBank::arm32_gpr || memory->base.index != 13 ||
                            !memory->add || !memory->pre_index || memory->writeback) continue;
                        const auto *displacement = std::get_if<std::uint32_t>(&memory->offset);
                        if (!displacement) continue;
                        const auto expected_width = instruction.opcode == Opcode::a32_str ? 32 :
                            instruction.opcode == Opcode::a32_strh ? 16 : 8;
                        if (memory->data_width != expected_width) continue;
                        const auto byte_width = static_cast<std::int64_t>(memory->data_width / 8);
                        std::int64_t offset = 0;
                        if (!subtract_checked(static_cast<std::int64_t>(*displacement), state.stack_depth.value, offset))
                            continue;
                        if (pending_arm32_stores.size() >= 1024) {
                            pending_arm32_stores.clear();
                            break;
                        }
                        std::int64_t end = 0;
                        if (!add_checked(offset, byte_width, end)) continue;
                        std::erase_if(pending_arm32_stores, [&](const auto &previous) {
                            std::int64_t previous_end = 0;
                            if (!add_checked(previous.offset, previous.width / 8, previous_end)) return true;
                            return offset < previous_end && previous.offset < end;
                        });
                        pending_arm32_stores.push_back({offset, state.stack_depth.value,
                                                        memory->data_width, instruction.address});
                        captured_store = true;
                    }
                }
                if (!captured_store && (instruction.memory_write || instruction.memory_read))
                    pending_arm32_stores.clear();
            }
            const bool x86_16_abi = instruction.context.architecture == Architecture::x86 &&
                                    instruction.context.mode == ExecutionMode::x86_16;
            const bool x86_32_abi = instruction.context.architecture == Architecture::x86 &&
                                    instruction.context.mode == ExecutionMode::x86_32;
            const bool x86_64_abi = instruction.context.architecture == Architecture::x86_64 &&
                                    instruction.context.mode == ExecutionMode::x86_64 &&
                                    image_default_convention &&
                                    (*image_default_convention == CallingConvention::sysv_x86_64 ||
                                     *image_default_convention == CallingConvention::windows_x64);
            const bool x86_stack_abi = x86_16_abi || x86_32_abi || x86_64_abi;
            if (x86_stack_abi && instruction.opcode == Opcode::push) {
                auto width = instruction.stack_value_width;
                if (!width) {
                    const auto pushed = register_at(instruction, 0);
                    if (pushed) width = pushed->width;
                    if (!width) width = static_cast<std::uint16_t>(pointer_bytes(instruction) * 8);
                }
                const auto bytes = static_cast<std::int64_t>(width / 8);
                std::int64_t depth = state.stack_depth.value;
                std::int64_t offset = 0;
                const bool exact_push = pending_x86_pushes_valid && state.stack_depth.known && bytes > 0 &&
                    width % 8 == 0 && instruction.flow == FlowKind::fallthrough &&
                    add_checked(depth, bytes, depth) && subtract_checked(0, depth, offset) &&
                    pending_x86_pushes.size() < 1024;
                if (exact_push) {
                    pending_x86_pushes.push_back({offset, width, instruction.address});
                } else {
                    pending_x86_pushes.clear();
                    pending_x86_pushes_valid = false;
                }
            } else if (x86_stack_abi && instruction.flow == FlowKind::call) {
                std::int64_t pushed_bytes = 0;
                bool exact_cleanup = false;
                if (pending_x86_pushes_valid && !pending_x86_pushes.empty() &&
                    instruction_index + 1 < block->second->instructions.size()) {
                    for (const auto &push : pending_x86_pushes)
                        if (!add_checked(pushed_bytes, push.width / 8, pushed_bytes)) {
                            pushed_bytes = -1;
                            break;
                        }
                    const auto &cleanup_fact = block->second->instructions[instruction_index + 1];
                    if (pushed_bytes > 0 && cleanup_fact &&
                        cleanup_fact->instruction.context.architecture == instruction.context.architecture &&
                        cleanup_fact->instruction.context.mode == instruction.context.mode &&
                        cleanup_fact->instruction.opcode == Opcode::add &&
                        cleanup_fact->instruction.flow == FlowKind::fallthrough) {
                        const auto cleanup_stack = register_at(cleanup_fact->instruction, 0);
                        const auto cleanup_bytes = immediate_value(cleanup_fact->instruction, 1);
                        const auto stack_width = static_cast<std::uint16_t>(x86_64_abi ? 64 : x86_32_abi ? 32 : 16);
                        exact_cleanup = cleanup_stack && cleanup_stack->bank == RegisterBank::gpr &&
                            cleanup_stack->index == 4 &&
                            cleanup_stack->width == stack_width && cleanup_bytes &&
                            *cleanup_bytes == pushed_bytes;
                    }
                }
                if (pending_x86_pushes_valid && exact_cleanup) {
                    for (const auto &push : pending_x86_pushes) {
                        const auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
                            return candidate.offset_from_entry_sp == push.offset && candidate.width == push.width;
                        });
                        if (slot == result.slots.end()) continue;
                        const StackSlotCallArgument provenance{push.instruction, instruction.address,
                                                               StackCallArgumentSourceKind::x86_push};
                        if (std::find(slot->outgoing_call_arguments.begin(), slot->outgoing_call_arguments.end(),
                                      provenance) != slot->outgoing_call_arguments.end())
                            continue;
                        if (stack_call_argument_detail_count >= 1'000'000) {
                            result.complete = false;
                            break;
                        }
                        slot->outgoing_call_arguments.push_back(provenance);
                        ++stack_call_argument_detail_count;
                    }
                }
                pending_x86_pushes.clear();
                pending_x86_pushes_valid = true;
            } else {
                pending_x86_pushes.clear();
                pending_x86_pushes_valid = true;
            }
            const bool stack_architecture = instruction.context.architecture == Architecture::x86 ||
                instruction.context.architecture == Architecture::x86_64 ||
                instruction.context.architecture == Architecture::mos6502 ||
                instruction.context.architecture == Architecture::arm64 ||
                instruction.context.architecture == Architecture::arm ||
                instruction.context.architecture == Architecture::mips32 ||
                instruction.context.architecture == Architecture::mips64 ||
                instruction.context.architecture == Architecture::riscv32 ||
                instruction.context.architecture == Architecture::riscv64 ||
                instruction.context.architecture == Architecture::powerpc;
            if (!stack_architecture) {
                result.complete = false;
                stack_extent_known = false;
            }
            // Address formation from the current stack or frame base is the
            // non-x86 equivalent of LEA. Retain its source location as an
            // address-taken slot even when the resulting pointer is later
            // passed to an opaque call or stored elsewhere.
            bool forms_stack_address = false;
            FlowValue address_base;
            std::int64_t address_displacement = 0;
            const auto address_destination = register_at(instruction, 0);
            const auto address_source = register_at(instruction, 1);
            if (instruction.context.architecture == Architecture::arm64 &&
                (instruction.opcode == Opcode::a64_add || instruction.opcode == Opcode::a64_sub) &&
                instruction.operands.size() >= 3 && address_destination && address_source &&
                address_destination->bank == RegisterBank::arm64_gpr && address_destination->index != 29) {
                if (address_source->bank == RegisterBank::arm64_sp) {
                    address_base = state.stack_depth;
                    forms_stack_address = true;
                } else if (address_source->bank == RegisterBank::arm64_gpr && address_source->index == 29 &&
                           state.arm64_frame_pointer) {
                    address_base = state.frame_depth;
                    forms_stack_address = true;
                }
                if (forms_stack_address) {
                    const auto immediate = immediate_value(instruction, 2);
                    if (!immediate) {
                        result.complete = false;
                        forms_stack_address = false;
                    } else if (instruction.opcode == Opcode::a64_sub) {
                        if (*immediate == INT64_MIN) {
                            result.complete = false;
                            forms_stack_address = false;
                        } else {
                            address_displacement = -*immediate;
                        }
                    } else {
                        address_displacement = *immediate;
                    }
                }
            } else if (instruction.context.architecture == Architecture::arm &&
                       (instruction.opcode == Opcode::a32_add || instruction.opcode == Opcode::a32_sub) &&
                       instruction.operands.size() >= 3 && address_destination && address_source &&
                       address_destination->bank == RegisterBank::arm32_gpr && address_destination->index != 13 &&
                       address_destination->index != state.frame_register) {
                if (arm32_register(address_source, 13)) {
                    address_base = state.stack_depth;
                    forms_stack_address = true;
                } else if (state.frame_register >= 0 && arm32_register(address_source, state.frame_register)) {
                    address_base = state.frame_depth;
                    forms_stack_address = true;
                }
                if (forms_stack_address) {
                    const auto immediate = immediate_value(instruction, 2);
                    if (!immediate) {
                        result.complete = false;
                        forms_stack_address = false;
                    } else if (instruction.opcode == Opcode::a32_sub) {
                        if (*immediate == INT64_MIN) {
                            result.complete = false;
                            forms_stack_address = false;
                        } else {
                            address_displacement = -*immediate;
                        }
                    } else address_displacement = *immediate;
                }
            } else if (mips_stack_adjust(instruction) &&
                       instruction.operands.size() >= 3 && address_destination && address_source &&
                       address_destination->bank == RegisterBank::mips_gpr &&
                       address_destination->index != 29 && address_destination->index != 30) {
                if (mips_register(address_source, 29)) {
                    address_base = state.stack_depth;
                    forms_stack_address = true;
                } else if (mips_register(address_source, 30) && state.frame_register == 30) {
                    address_base = state.frame_depth;
                    forms_stack_address = true;
                }
                if (forms_stack_address) {
                    const auto immediate = immediate_value(instruction, 2);
                    if (immediate) address_displacement = *immediate;
                    else {
                        result.complete = false;
                        forms_stack_address = false;
                    }
                }
            } else if ((instruction.context.architecture == Architecture::riscv32 ||
                        instruction.context.architecture == Architecture::riscv64) &&
                       instruction.opcode == Opcode::rv_addi && instruction.operands.size() >= 3 &&
                       address_destination && address_source && address_destination->bank == RegisterBank::riscv_gpr &&
                       address_destination->index != 2 && address_destination->index != 8) {
                if (riscv_register(address_source, 2)) {
                    address_base = state.stack_depth;
                    forms_stack_address = true;
                } else if (riscv_register(address_source, 8) && state.frame_register == 8) {
                    address_base = state.frame_depth;
                    forms_stack_address = true;
                }
                if (forms_stack_address) {
                    const auto immediate = immediate_value(instruction, 2);
                    if (immediate) address_displacement = *immediate;
                    else {
                        result.complete = false;
                        forms_stack_address = false;
                    }
                }
            } else if ((instruction.context.architecture == Architecture::riscv32 ||
                        instruction.context.architecture == Architecture::riscv64) &&
                       (instruction.opcode == Opcode::rv_add || instruction.opcode == Opcode::rv_sub) &&
                       instruction.operands.size() >= 3 && address_destination &&
                       address_destination->bank == RegisterBank::riscv_gpr &&
                       address_destination->index != 2 && address_destination->index != 8) {
                const auto third = register_at(instruction, 2);
                const bool zero_second = riscv_register(address_source, 0);
                const bool zero_third = riscv_register(third, 0);
                const bool valid_copy = instruction.opcode == Opcode::rv_add
                    ? (zero_second || zero_third) : zero_third;
                auto base = address_source;
                if (instruction.opcode == Opcode::rv_add &&
                    !(riscv_register(base, 2) || riscv_register(base, 8)))
                    base = third;
                const auto expected_width = static_cast<std::uint8_t>(pointer_bytes(instruction) * 8);
                if (base && base->bank == RegisterBank::riscv_gpr && base->width == expected_width &&
                    (base->index == 2 || (base->index == 8 && state.frame_register == 8))) {
                    forms_stack_address = true;
                    address_base = base->index == 2 ? state.stack_depth : state.frame_depth;
                    if (!valid_copy || address_destination->width != expected_width) {
                        result.complete = false;
                        forms_stack_address = false;
                    }
                }
            } else if (const auto source = riscv_bitwise_copy_source(instruction);
                       source && address_destination->index != 2 && address_destination->index != 8) {
                if (source->index == 2 || (source->index == 8 && state.frame_register == 8)) {
                    forms_stack_address = true;
                    address_base = source->index == 2 ? state.stack_depth : state.frame_depth;
                }
            } else if (instruction.context.architecture == Architecture::powerpc &&
                       instruction.opcode == Opcode::ppc_addi && instruction.operands.size() >= 3 &&
                       address_destination && address_source && address_destination->bank == RegisterBank::ppc_gpr &&
                       address_destination->index != 1 && address_destination->index != 31) {
                if (ppc_register(address_source, 1)) {
                    address_base = state.stack_depth;
                    forms_stack_address = true;
                } else if (ppc_register(address_source, 31) && state.frame_register == 31) {
                    address_base = state.frame_depth;
                    forms_stack_address = true;
                }
                if (forms_stack_address) {
                    const auto immediate = immediate_value(instruction, 2);
                    if (immediate) address_displacement = *immediate;
                    else {
                        result.complete = false;
                        forms_stack_address = false;
                    }
                }
            }
            if (forms_stack_address) {
                std::int64_t offset = 0;
                if (!address_base.known || !subtract_checked(address_displacement, address_base.value, offset)) {
                    result.complete = false;
                } else if (!record_stack_slot(result, offset, 0, false, false, true,
                                              instruction.address, access_detail_count)) {
                    return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                }
            }
            // AArch64 pair transfers have one memory operand but access two
            // adjacent cells of the element width. Recover both stack slots
            // only when the base is a tracked SP or frame pointer.
            const bool arm64_pair = instruction.context.architecture == Architecture::arm64 &&
                (instruction.opcode == Opcode::a64_ldp || instruction.opcode == Opcode::a64_stp);
            const auto *pair_memory = arm64_pair
                && instruction.operands.size() > 2
                ? std::get_if<MemoryOperand>(&instruction.operands[2]) : nullptr;
            const bool pair_sp = pair_memory && pair_memory->base &&
                                 pair_memory->base->bank == RegisterBank::arm64_sp;
            const bool pair_fp = pair_memory && pair_memory->base &&
                                 pair_memory->base->bank == RegisterBank::arm64_gpr &&
                                 pair_memory->base->index == 29;
            const bool pair_alias = pair_memory && pair_memory->base &&
                                    pair_memory->base->bank == RegisterBank::arm64_gpr &&
                                    pair_memory->base->index < state.arm64_stack_alias_depths.size() &&
                                    state.arm64_stack_alias_depths[pair_memory->base->index].known;
            if (arm64_pair && (!pair_memory || !pair_memory->base)) {
                result.complete = false;
            } else if (pair_sp || pair_fp || pair_alias) {
                if (pair_memory->data_width == 0 || pair_memory->data_width % 8 != 0 ||
                    pair_memory->index || pair_memory->ip_relative || pair_memory->address_width != 64 ||
                    instruction.access.size() <= 2) {
                    result.complete = false;
                } else {
                    const auto base = pair_alias ? state.arm64_stack_alias_depths[pair_memory->base->index]
                        : pair_fp ? state.frame_depth : state.stack_depth;
                    const auto access = instruction.access[2];
                    const bool read = access == OperandAccess::read || access == OperandAccess::read_write;
                    const bool written = access == OperandAccess::write || access == OperandAccess::read_write;
                    if (!base.known || (!read && !written)) {
                        result.complete = false;
                    } else {
                        const auto element_bytes = static_cast<std::int64_t>(pair_memory->data_width / 8);
                        std::int64_t first_offset = 0;
                        if (!subtract_checked(pair_memory->displacement, base.value, first_offset)) {
                            result.complete = false;
                        } else {
                            for (int element = 0; element < 2; ++element) {
                                std::int64_t offset = first_offset;
                                if (element && !add_checked(offset, element_bytes, offset)) {
                                    result.complete = false;
                                    continue;
                                }
                                if (!record_stack_slot(result, offset, pair_memory->data_width, read, written,
                                                       false, instruction.address, access_detail_count))
                                    return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                                mark_incoming_aarch64_argument(result, offset, pair_memory->data_width, read);
                            }
                        }
                    }
                }
            }
            // PUSH/POP and PUSHF/POPF access the stack implicitly. Preserve
            // the cell's entry-SP offset before transfer() updates SP.
            if ((instruction.context.architecture == Architecture::x86 ||
                 instruction.context.architecture == Architecture::x86_64) &&
                (instruction.opcode == Opcode::push || instruction.opcode == Opcode::pop ||
                 instruction.opcode == Opcode::pushf || instruction.opcode == Opcode::popf)) {
                const bool push = instruction.opcode == Opcode::push || instruction.opcode == Opcode::pushf;
                const bool pop = instruction.opcode == Opcode::pop || instruction.opcode == Opcode::popf;
                auto width = instruction.stack_value_width;
                if (!width) {
                    const auto value = register_at(instruction, 0);
                    if (value)
                        width = value->width;
                    if (!width)
                        width = static_cast<std::uint16_t>(pointer_bytes(instruction) * 8);
                }
                const auto bytes = static_cast<std::int64_t>(width / 8);
                if (!state.stack_depth.known || bytes <= 0 || width % 8 != 0) {
                    result.complete = false;
                } else {
                    std::int64_t offset = 0;
                    auto depth = state.stack_depth.value;
                    if ((push && !add_checked(depth, bytes, depth)) ||
                        !subtract_checked(0, depth, offset)) {
                        result.complete = false;
                    } else if (!record_stack_slot(result, offset, width,
                                                  pop, push, false,
                                                  instruction.address, access_detail_count)) {
                        return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                    }
                }
            }
            // NMOS 6502 pushes write at the current page-one stack address and
            // then decrement S; pulls increment S before reading. Map both
            // sides to the same entry-SP-relative cell for balanced pairs.
            if (instruction.context.architecture == Architecture::mos6502 &&
                (instruction.opcode == Opcode::m6502_pha || instruction.opcode == Opcode::m6502_php ||
                 instruction.opcode == Opcode::m6502_pla || instruction.opcode == Opcode::m6502_plp)) {
                if (!state.stack_depth.known) {
                    result.complete = false;
                } else {
                    const bool push = instruction.opcode == Opcode::m6502_pha ||
                                      instruction.opcode == Opcode::m6502_php;
                    std::int64_t cell_depth = state.stack_depth.value;
                    if (!push && !add_checked(cell_depth, -1, cell_depth)) {
                        result.complete = false;
                    } else {
                        std::int64_t offset = 0;
                        if (!subtract_checked(0, cell_depth, offset)) {
                            result.complete = false;
                        } else if (!m6502_slot_offset_unambiguous(offset)) {
                            result.complete = false;
                        } else if (!record_stack_slot(result, offset, 8, !push, push, false,
                                                      instruction.address, access_detail_count)) {
                            return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                        }
                    }
                }
            }
            if (instruction.context.architecture == Architecture::mos6502 &&
                (instruction.opcode == Opcode::m6502_jsr || instruction.opcode == Opcode::m6502_rts ||
                 instruction.opcode == Opcode::m6502_rti)) {
                // JSR writes the return address high byte at the current S,
                // then the low byte at S-1. RTS consumes those two bytes
                // above its entry S. RTI additionally consumes the status
                // byte at entry S+1. These are implicit accesses; the
                // interprocedural call itself remains stack-balanced in the
                // flow state below.
                if (instruction.opcode == Opcode::m6502_jsr) {
                    if (!state.stack_depth.known) {
                        result.complete = false;
                    } else {
                        for (std::int64_t byte = 0; byte < 2; ++byte) {
                            std::int64_t cell_depth = 0;
                            std::int64_t offset = 0;
                            if (!add_checked(state.stack_depth.value, byte, cell_depth) ||
                                !subtract_checked(0, cell_depth, offset)) {
                                result.complete = false;
                                break;
                            }
                            if (!m6502_slot_offset_unambiguous(offset)) {
                                result.complete = false;
                                continue;
                            }
                            if (!record_stack_slot(result, offset, 8, false, true, false,
                                                   instruction.address, access_detail_count))
                                return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                        }
                        std::int64_t transient_depth = 0;
                        if (!add_checked(state.stack_depth.value, 2, transient_depth) || transient_depth < 0) {
                            result.complete = false;
                        } else {
                            if (transient_depth > 256) result.complete = false;
                            maximum_stack_allocation = std::max(
                                maximum_stack_allocation,
                                static_cast<std::uint64_t>(std::min<std::int64_t>(transient_depth, 256)));
                        }
                    }
                } else {
                    const std::int64_t frame_bytes = instruction.opcode == Opcode::m6502_rti ? 3 : 2;
                    for (std::int64_t byte = 1; byte <= frame_bytes; ++byte) {
                        if (!record_stack_slot(result, byte, 8, true, false, false,
                                               instruction.address, access_detail_count))
                            return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                    }
                }
            }
            // NMOS 6502 has no explicit stack-base addressing mode, but the
            // common TSX / $0100,index idiom addresses the byte currently named
            // by S. Since the index is an 8-bit snapshot and the base is exactly the
            // stack-page origin, the effective byte cannot leave page one.
            // Other page-one bases can cross into page two and remain opaque.
            if (instruction.context.architecture == Architecture::mos6502) {
                for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
                    const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[i]);
                    if (!memory || !memory->index || memory->index->bank != RegisterBank::mos6502 ||
                        (memory->index->index != 1 && memory->index->index != 2) ||
                        memory->index->width != 8 || memory->address_width != 16 || memory->ip_relative ||
                        memory->base || memory->scale != 1 || memory->displacement < 0x0100 ||
                        memory->displacement > 0x01ff)
                        continue;
                    const auto index = static_cast<std::size_t>(memory->index->index);
                    const auto delta = state.m6502_stack_alias_deltas[index];
                    if (i >= instruction.access.size() || memory->data_width != 8 ||
                        memory->displacement != 0x0100 || !state.frame_depth.known || !delta.known) {
                        result.complete = false;
                        continue;
                    }
                    std::int64_t offset = 0;
                    if (!subtract_checked(delta.value, state.frame_depth.value, offset)) {
                        result.complete = false;
                        continue;
                    }
                    const auto access = instruction.access[i];
                    const bool address_taken = access == OperandAccess::address;
                    const bool read = access == OperandAccess::read || access == OperandAccess::read_write;
                    const bool written = access == OperandAccess::write || access == OperandAccess::read_write;
                    if ((address_taken || read || written) &&
                        !record_stack_slot(result, offset, address_taken ? 0 : memory->data_width,
                                           read, written, address_taken, instruction.address,
                                           access_detail_count))
                        return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                }
            }
            for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
                if (arm64_pair && i == 2)
                    continue; // Both cells were recorded above.
                const auto *memory = std::get_if<MemoryOperand>(&instruction.operands[i]);
                if (!memory || !memory->base)
                    continue;
                const auto address_destination = register_at(instruction, 0);
                if (instruction.opcode == Opcode::lea && i == 1 && address_destination &&
                    address_destination->bank == RegisterBank::gpr &&
                    (address_destination->index == 4 || address_destination->index == 5))
                    continue;
                const bool arm64_stack = instruction.context.architecture == Architecture::arm64 &&
                                         memory->base->bank == RegisterBank::arm64_sp;
                const bool arm64_frame = instruction.context.architecture == Architecture::arm64 &&
                                         memory->base->bank == RegisterBank::arm64_gpr &&
                                         memory->base->index == 29;
                const bool arm64_alias = instruction.context.architecture == Architecture::arm64 &&
                                         memory->base->bank == RegisterBank::arm64_gpr &&
                                         memory->base->index < state.arm64_stack_alias_depths.size() &&
                                         state.arm64_stack_alias_depths[memory->base->index].known;
                const bool x86_stack = (instruction.context.architecture == Architecture::x86 ||
                                        instruction.context.architecture == Architecture::x86_64) &&
                                       memory->base->bank == RegisterBank::gpr &&
                                       (memory->base->index == 4 || memory->base->index == 5);
                const bool mips_stack = (instruction.context.architecture == Architecture::mips32 ||
                                         instruction.context.architecture == Architecture::mips64) &&
                                        memory->base->bank == RegisterBank::mips_gpr && memory->base->index == 29;
                const bool mips_frame = (instruction.context.architecture == Architecture::mips32 ||
                                         instruction.context.architecture == Architecture::mips64) &&
                                        memory->base->bank == RegisterBank::mips_gpr && memory->base->index == 30;
                const bool mips32_alias = instruction.context.architecture == Architecture::mips32 &&
                                          instruction.context.mode == ExecutionMode::mips32 &&
                                          memory->base->bank == RegisterBank::mips_gpr &&
                                          memory->base->index != 0 && memory->base->index != 29 &&
                                          memory->base->index != 30 && memory->base->index < 32 &&
                                          state.mips32_stack_alias_depths[memory->base->index].known;
                const bool riscv_stack = (instruction.context.architecture == Architecture::riscv32 ||
                                          instruction.context.architecture == Architecture::riscv64) &&
                                         memory->base->bank == RegisterBank::riscv_gpr && memory->base->index == 2;
                const bool riscv_frame = (instruction.context.architecture == Architecture::riscv32 ||
                                          instruction.context.architecture == Architecture::riscv64) &&
                                         memory->base->bank == RegisterBank::riscv_gpr && memory->base->index == 8;
                const bool riscv_alias = (instruction.context.architecture == Architecture::riscv32 ||
                                          instruction.context.architecture == Architecture::riscv64) &&
                                         memory->base->bank == RegisterBank::riscv_gpr &&
                                         memory->base->index != 0 && memory->base->index != 2 &&
                                         memory->base->index != 8 && memory->base->index < 32 &&
                                         state.riscv_stack_alias_depths[memory->base->index].known;
                const bool ppc_stack = instruction.context.architecture == Architecture::powerpc &&
                                       memory->base->bank == RegisterBank::ppc_gpr && memory->base->index == 1;
                const bool ppc_frame = instruction.context.architecture == Architecture::powerpc &&
                                       memory->base->bank == RegisterBank::ppc_gpr && memory->base->index == 31;
                if (!arm64_stack && !arm64_frame && !arm64_alias && !x86_stack && !mips_stack && !mips_frame &&
                    !mips32_alias &&
                    !riscv_stack && !riscv_frame && !riscv_alias && !ppc_stack && !ppc_frame)
                    continue;
                const bool from_frame = arm64_frame || mips_frame || riscv_frame ||
                                        ppc_frame || (x86_stack && memory->base->index == 5);
                const bool stack_segment = instruction.context.architecture == Architecture::mips32 ||
                    instruction.context.architecture == Architecture::mips64 ||
                    instruction.context.architecture == Architecture::riscv32 ||
                    instruction.context.architecture == Architecture::riscv64 || !memory->segment ||
                    (memory->segment->bank == RegisterBank::segment && memory->segment->index == 2);
                if (memory->ip_relative || memory->index || !stack_segment || i >= instruction.access.size()) {
                    result.complete = false;
                    continue;
                }
                const auto base = arm64_alias ? state.arm64_stack_alias_depths[memory->base->index]
                    : mips32_alias ? state.mips32_stack_alias_depths[memory->base->index]
                    : riscv_alias ? state.riscv_stack_alias_depths[memory->base->index]
                    : from_frame ? state.frame_depth : state.stack_depth;
                const bool access_address = instruction.access[i] == OperandAccess::address;
                const bool ppc_memory = ppc_stack || ppc_frame;
                const bool address_taken = access_address &&
                    (!ppc_memory || (!instruction.memory_read && !instruction.memory_write));
                if (!base.known || (!address_taken && memory->data_width == 0)) {
                    result.complete = false;
                    continue;
                }
                std::int64_t offset = 0;
                if (!subtract_checked(memory->displacement, base.value, offset)) {
                    result.complete = false;
                    continue;
                }
                const auto access = instruction.access[i];
                const bool read = access == OperandAccess::read || access == OperandAccess::read_write ||
                                  (ppc_stack || ppc_frame) && access_address && instruction.memory_read;
                const bool written = access == OperandAccess::write || access == OperandAccess::read_write ||
                                     (ppc_stack || ppc_frame) && access_address && instruction.memory_write;
                if (address_taken || read || written) {
                    const auto width = address_taken ? 0 : memory->data_width;
                    if (!record_stack_slot(result, offset, width, read, written, address_taken,
                                           instruction.address, access_detail_count))
                        return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                    if (instruction.context.architecture == Architecture::x86 &&
                        instruction.context.mode == ExecutionMode::x86_32)
                        mark_incoming_x86_32_argument(result, offset, width, x86_32_cleanup);
                    if (instruction.context.architecture == Architecture::x86_64 &&
                        instruction.context.mode == ExecutionMode::x86_64 && read && image_default_convention &&
                        (*image_default_convention == CallingConvention::sysv_x86_64 ||
                         *image_default_convention == CallingConvention::windows_x64))
                        mark_incoming_x86_64_argument(result, offset, width, read, *image_default_convention);
                    if (instruction.context.architecture == Architecture::arm64)
                        mark_incoming_aarch64_argument(result, offset, width, read);
                    if (instruction.context.architecture == Architecture::arm &&
                        (instruction.context.mode == ExecutionMode::a32 ||
                         instruction.context.mode == ExecutionMode::thumb))
                        mark_incoming_aapcs32_argument(result, offset, width, read);
                    if (instruction.context.architecture == Architecture::mips32 &&
                        instruction.context.mode == ExecutionMode::mips32)
                        mark_incoming_mips_o32_argument(result, offset, width, read);
                    if (instruction.context.architecture == Architecture::mips64 &&
                        instruction.context.mode == ExecutionMode::mips64 && image_default_convention &&
                        *image_default_convention == CallingConvention::mips_n64)
                        mark_incoming_mips_n64_argument(result, offset, width, read);
                    if (instruction.context.architecture == Architecture::mips64 &&
                        instruction.context.mode == ExecutionMode::mips64 && image_default_convention &&
                        *image_default_convention == CallingConvention::mips_n32)
                        mark_incoming_mips_n32_argument(result, offset, width, read);
                    if (instruction.context.architecture == Architecture::powerpc &&
                        instruction.context.mode == ExecutionMode::ppc64 && image_default_convention &&
                        *image_default_convention == CallingConvention::ppc64le_elfv2)
                        mark_incoming_ppc64_elfv2_argument(result, offset, width, read);
                    if (instruction.context.architecture == Architecture::riscv32 ||
                        instruction.context.architecture == Architecture::riscv64)
                        mark_incoming_riscv_argument(result, offset, width, read, instruction.context.mode);
                }
            }
        // PUSHA/POPA have implicit memory operands. Their decoded width and
        // slot count let us recover the eight stack cells without inferring
        // register values or inventing explicit operands.
        if ((instruction.context.architecture == Architecture::x86 ||
             instruction.context.architecture == Architecture::x86_64) &&
            (instruction.opcode == Opcode::pusha || instruction.opcode == Opcode::popa)) {
            const auto bytes = static_cast<std::int64_t>(instruction.stack_value_width / 8);
            if (!state.stack_depth.known || bytes <= 0 || instruction.stack_slot_count != 8) {
                result.complete = false;
            } else {
                const auto width = instruction.stack_value_width;
                for (std::int64_t index = 0; index < 8; ++index) {
                    // POPA advances over the saved-SP cell without reading it.
                    if (instruction.opcode == Opcode::popa && index == 3)
                        continue;
                    std::int64_t offset = 0;
                    if (instruction.opcode == Opcode::pusha) {
                        if (!subtract_checked(0, state.stack_depth.value, offset) ||
                            !subtract_checked(offset, (index + 1) * bytes, offset)) {
                            result.complete = false;
                            continue;
                        }
                    } else {
                        if (!subtract_checked(0, state.stack_depth.value, offset) ||
                            !add_checked(offset, index * bytes, offset)) {
                            result.complete = false;
                            continue;
                        }
                    }
                    if (!record_stack_slot(result, offset, width, instruction.opcode == Opcode::popa,
                                           instruction.opcode == Opcode::pusha, false,
                                           instruction.address, access_detail_count))
                        return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                }
            }
        }
            if (instruction.context.architecture == Architecture::arm) {
                if (instruction.opcode == Opcode::a32_stm || instruction.opcode == Opcode::a32_ldm) {
                    const auto base = register_at(instruction, 0);
                    const auto *list = instruction.operands.size() > 1
                                           ? std::get_if<ArmRegisterListOperand>(&instruction.operands[1])
                                           : nullptr;
                    const bool stack_base = arm32_register(base, 13);
                    const bool frame_base = state.frame_register >= 0 &&
                        arm32_register(base, static_cast<std::uint8_t>(state.frame_register));
                    if ((stack_base || frame_base) && list) {
                        const unsigned count = std::popcount(list->mask);
                        const auto base_depth = stack_base ? state.stack_depth : state.frame_depth;
                        std::int64_t base_offset = 0;
                        if ((!instruction.memory_read && !instruction.memory_write) ||
                            !base_depth.known || !subtract_checked(0, base_depth.value, base_offset) ||
                            !instruction.arm || !count) {
                            result.complete = false;
                        } else {
                            const auto mode = instruction.arm->multiple_mode;
                            const std::int64_t before = mode == ArmMultipleMode::ib ? 4
                                : mode == ArmMultipleMode::da ? -static_cast<std::int64_t>(count - 1) * 4
                                : mode == ArmMultipleMode::db ? -static_cast<std::int64_t>(count) * 4 : 0;
                            std::int64_t start = 0;
                            if (!add_checked(base_offset, before, start)) {
                                result.complete = false;
                            } else {
                                const bool read = instruction.memory_read;
                                const bool written = instruction.memory_write;
                                for (unsigned reg_index = 0; reg_index < 16; ++reg_index) {
                                    if (!(list->mask & (1u << reg_index)) || (!read && !written)) continue;
                                    std::int64_t offset = 0;
                                    if (!add_checked(start, static_cast<std::int64_t>(std::popcount(
                                            static_cast<std::uint16_t>(list->mask & ((1u << reg_index) - 1)))) * 4,
                                                     offset)) {
                                        result.complete = false;
                                        continue;
                                    }
                                    auto slot = std::find_if(result.slots.begin(), result.slots.end(), [&](const auto &candidate) {
                                        return candidate.offset_from_entry_sp == offset && candidate.width == 32;
                                    });
                                    if (slot == result.slots.end()) {
                                        if (result.slots.size() >= 100000)
                                            return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                                        result.slots.push_back({offset, 32, false, false, {}});
                                        slot = std::prev(result.slots.end());
                                    }
                                    slot->read = slot->read || read; slot->written = slot->written || written;
                                    if (!record_slot_access(*slot, read, written, false, instruction.address,
                                                            access_detail_count))
                                        return Error{ErrorCode::resource_limit,
                                                     "Stack analysis access provenance budget exceeded"};
                                }
                            }
                        }
                    } else if (base && base->bank == RegisterBank::arm32_gpr &&
                               (base->index == 7 || base->index == 11)) {
                        result.complete = false;
                    }
                }
                for (std::size_t i = 0; i < instruction.operands.size(); ++i) {
                    const auto *memory = std::get_if<ArmMemoryOperand>(&instruction.operands[i]);
                    if (!memory) continue;
                    const bool stack_base = memory->base.index == 13;
                    const bool frame_base = state.frame_register >= 0 && memory->base.index == state.frame_register;
                    if (memory->base.bank != RegisterBank::arm32_gpr || (!stack_base && !frame_base)) {
                        if (memory->base.bank == RegisterBank::arm32_gpr &&
                            (memory->base.index == 7 || memory->base.index == 11)) result.complete = false;
                        continue;
                    }
                    const auto *immediate = std::get_if<std::uint32_t>(&memory->offset);
                    if (!immediate || i >= instruction.access.size() || memory->data_width == 0) {
                        result.complete = false;
                        continue;
                    }
                    const auto access = instruction.access[i];
                    const bool address_taken = access == OperandAccess::address;
                    const auto base_depth = stack_base ? state.stack_depth : state.frame_depth;
                    if (!base_depth.known || (!address_taken && memory->data_width == 0)) {
                        result.complete = false;
                        continue;
                    }
                    std::int64_t displacement = 0;
                    if (memory->pre_index) {
                        displacement = static_cast<std::int64_t>(*immediate);
                        if (!memory->add) displacement = -displacement;
                    }
                    std::int64_t offset = 0;
                    if (!subtract_checked(displacement, base_depth.value, offset)) { result.complete = false; continue; }
                    const bool read = access == OperandAccess::read || access == OperandAccess::read_write;
                    const bool written = access == OperandAccess::write || access == OperandAccess::read_write;
                    if (address_taken || read || written) {
                        if (!m6502_slot_offset_unambiguous(offset)) {
                            result.complete = false;
                            continue;
                        }
                        if (!record_stack_slot(result, offset, address_taken ? 0 : memory->data_width,
                                               read, written, address_taken, instruction.address,
                                               access_detail_count))
                            return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                    }
                }
            }
            if (instruction.context.architecture == Architecture::mos6502 &&
                instruction.opcode == Opcode::m6502_brk) {
                // BRK writes the return PC and status byte to the NMOS 6502
                // page-one stack before transferring control to the IRQ
                // vector. These are known implicit accesses even though the
                // interrupt handler is outside this function's CFG.
                if (!state.stack_depth.known) {
                    result.complete = false;
                    state.stack_depth = {};
                    state.supported = false;
                } else {
                    for (std::int64_t byte = 0; byte < 3; ++byte) {
                        std::int64_t depth = 0;
                        std::int64_t offset = 0;
                        if (!add_checked(state.stack_depth.value, byte, depth) ||
                            !subtract_checked(0, depth, offset)) {
                            result.complete = false;
                            state.stack_depth = {};
                            state.supported = false;
                            break;
                        }
                        if (!m6502_slot_offset_unambiguous(offset)) {
                            result.complete = false;
                            continue;
                        }
                        if (!record_stack_slot(result, offset, 8, false, true, false,
                                               instruction.address, access_detail_count))
                            return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                    }
                    if (state.stack_depth.known && !add(state.stack_depth, 3)) {
                        result.complete = false;
                        state.stack_depth = {};
                        state.supported = false;
                    }
                }
            } else if (!transfer(instruction, state)) {
                state.stack_depth = {};
                state.supported = false;
            }
            if (!pending_arm64_stores.empty() &&
                (!stack_depth_before_instruction.known || !state.stack_depth.known ||
                 stack_depth_before_instruction.value != state.stack_depth.value))
                pending_arm64_stores.clear();
            observe_stack_depth(state.stack_depth,
                                instruction.context.architecture == Architecture::mos6502);
            if (!state.supported)
                result.complete = false;
        }
    }
    if (stack_extent_known)
        result.maximum_stack_allocation_bytes = maximum_stack_allocation;
    std::sort(result.slots.begin(), result.slots.end(), [](const auto &left, const auto &right) {
        return std::tie(left.offset_from_entry_sp, left.width) < std::tie(right.offset_from_entry_sp, right.width);
    });
    for (auto &slot : result.slots) {
        std::sort(slot.accesses.begin(), slot.accesses.end(), [](const Address &left, const Address &right) {
            return std::tie(left.space.value, left.offset) < std::tie(right.space.value, right.offset);
        });
        slot.accesses.erase(std::unique(slot.accesses.begin(), slot.accesses.end()), slot.accesses.end());
        std::sort(slot.access_details.begin(), slot.access_details.end(), [](const auto &left, const auto &right) {
            return std::tie(left.instruction.space.value, left.instruction.offset, left.read, left.written,
                            left.address_taken) <
                   std::tie(right.instruction.space.value, right.instruction.offset, right.read, right.written,
                            right.address_taken);
        });
        slot.access_details.erase(std::unique(slot.access_details.begin(), slot.access_details.end()),
                                  slot.access_details.end());
    }
    return result;
}

} // namespace hexlab
