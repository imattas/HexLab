#include "hexlab/analysis/stack.hpp"

#include <algorithm>
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
    if (current.frame_register != incoming.frame_register) {
        current.frame_register = -1;
        current.frame_depth = {};
        current.ambiguous = true;
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
           previous_arm64_frame_pointer != current.arm64_frame_pointer;
}

bool arm32_register(const std::optional<RegisterOperand> &value, std::uint8_t index) {
    return value && value->bank == RegisterBank::arm32_gpr && value->index == index;
}

bool mips_register(const std::optional<RegisterOperand> &value, std::uint8_t index) {
    return value && value->bank == RegisterBank::mips_gpr && value->index == index;
}

bool riscv_register(const std::optional<RegisterOperand> &value, std::uint8_t index) {
    return value && value->bank == RegisterBank::riscv_gpr && value->index == index;
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
        for (const auto address : unknown->accesses)
            if (std::find(known.accesses.begin(), known.accesses.end(), address) == known.accesses.end())
                known.accesses.push_back(address);
        for (const auto &detail : unknown->access_details)
            if (std::find(known.access_details.begin(), known.access_details.end(), detail) == known.access_details.end())
                known.access_details.push_back(detail);
        result.slots.erase(unknown);
        if (unknown_index < slot_index)
            --slot_index;
    }
    auto &known = result.slots[slot_index];
    known.read = known.read || read;
    known.written = known.written || written;
    return record_slot_access(known, read, written, false, site, detail_count);
}

// Transfer only the x86 stack operations whose meaning is explicit in the
// decoded operands. Any other write to SP/BP invalidates that register's
// symbolic relation instead of guessing from mnemonic text.
bool transfer(const Instruction &instruction, FlowState &state) {
    const auto first = register_at(instruction, 0);
    const auto second = register_at(instruction, 1);
    if ((instruction.context.architecture == Architecture::x86 ||
         instruction.context.architecture == Architecture::x86_64) &&
        instruction.flow == FlowKind::ret)
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
    if (instruction.opcode == Opcode::push || instruction.opcode == Opcode::pop) {
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
        return add(state.stack_depth, instruction.opcode == Opcode::push ? bytes : -bytes);
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
    if (instruction.opcode == Opcode::mov && is_gpr(first, 5) && is_gpr(second, 4)) {
        state.frame_depth = state.stack_depth;
        state.frame_register = 5;
        return true;
    }
    if (instruction.opcode == Opcode::mov && is_gpr(first, 4) && is_gpr(second, 5)) {
        state.stack_depth = state.frame_depth;
        return true;
    }
    if ((instruction.context.architecture == Architecture::mips32 ||
         instruction.context.architecture == Architecture::mips64) &&
        (instruction.opcode == Opcode::mips_addiu || instruction.opcode == Opcode::mips_addi ||
         instruction.opcode == Opcode::mips64_daddi || instruction.opcode == Opcode::mips64_daddiu) &&
        instruction.operands.size() >= 3) {
        const auto immediate = immediate_value(instruction, 2);
        const bool dst_stack = mips_register(first, 29);
        const bool dst_frame = mips_register(first, 30);
        const bool src_stack = mips_register(second, 29);
        const bool src_frame = mips_register(second, 30);
        if (immediate && ((dst_stack && (src_stack || src_frame)) || (dst_frame && (src_stack || src_frame)))) {
            FlowValue relation = src_stack ? state.stack_depth : state.frame_depth;
            if (!subtract_checked(relation.value, *immediate, relation.value)) return false;
            if (!relation.known) state.supported = false;
            if (dst_stack) state.stack_depth = relation;
            else { state.frame_depth = relation; state.frame_register = 30; }
            return true;
        }
    }
    if ((instruction.context.architecture == Architecture::riscv32 ||
         instruction.context.architecture == Architecture::riscv64) &&
        instruction.opcode == Opcode::rv_addi && instruction.operands.size() >= 3) {
        const auto immediate = immediate_value(instruction, 2);
        const bool dst_stack = riscv_register(first, 2);
        const bool dst_frame = riscv_register(first, 8);
        const bool src_stack = riscv_register(second, 2);
        const bool src_frame = riscv_register(second, 8);
        if (immediate && ((dst_stack && (src_stack || src_frame)) ||
                          (dst_frame && (src_stack || src_frame)))) {
            FlowValue relation = src_stack ? state.stack_depth : state.frame_depth;
            if (!subtract_checked(relation.value, *immediate, relation.value)) return false;
            if (!relation.known) state.supported = false;
            if (dst_stack) state.stack_depth = relation;
            else { state.frame_depth = relation; state.frame_register = 8; }
            return true;
        }
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
        (instruction.opcode == Opcode::rv_add || instruction.opcode == Opcode::rv_addw) &&
        instruction.operands.size() >= 3 &&
        (riscv_register(second, 0) || riscv_register(register_at(instruction, 2), 0))) {
        const auto source = riscv_register(second, 0) ? register_at(instruction, 2) : second;
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
    if ((instruction.context.architecture == Architecture::mips32 ||
         instruction.context.architecture == Architecture::mips64) &&
        (instruction.opcode == Opcode::mips_addu || instruction.opcode == Opcode::mips_add ||
         instruction.opcode == Opcode::mips_or || instruction.opcode == Opcode::mips64_dadd ||
         instruction.opcode == Opcode::mips64_daddu) &&
        instruction.operands.size() >= 3 &&
        (mips_register(second, 0) || mips_register(register_at(instruction, 2), 0))) {
        const auto source = mips_register(second, 0) ? register_at(instruction, 2) : second;
        if (mips_register(first, 29) && mips_register(source, 30) && state.frame_register == 30) {
            state.stack_depth = state.frame_depth;
            return true;
        }
        if (mips_register(first, 30) && mips_register(source, 29)) {
            state.frame_depth = state.stack_depth;
            state.frame_register = 30;
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
        instruction.operands.size() >= 3 &&
        ((arm64_sp(first) && arm64_sp(second)) ||
         (arm64_sp(first) && second && second->bank == RegisterBank::arm64_gpr && second->index == 29) ||
         (first && first->bank == RegisterBank::arm64_gpr && first->index == 29 && arm64_sp(second)))) {
        const auto immediate = immediate_value(instruction, 2);
        if (immediate) {
            const bool destination_is_sp = arm64_sp(first);
            const bool source_is_frame = second && second->bank == RegisterBank::arm64_gpr && second->index == 29;
            if (destination_is_sp && source_is_frame && !state.arm64_frame_pointer) {
                state.stack_depth = {};
                state.supported = false;
                return true;
            }
            FlowValue relation = destination_is_sp && source_is_frame ? state.frame_depth : state.stack_depth;
            if (instruction.opcode != Opcode::a64_sub && *immediate == INT64_MIN)
                return false;
            const auto delta = instruction.opcode == Opcode::a64_sub ? *immediate : -*immediate;
            if (!add(relation, delta))
                return false;
            if (destination_is_sp)
                state.stack_depth = relation;
            else {
                state.frame_depth = relation;
                state.arm64_frame_pointer = true;
            }
            return true;
        }
    }

    // Pair and scalar load/store writeback through SP is a common AArch64
    // prologue/epilogue form (for example STP/LDP x29,x30,[sp,#-16]!). The
    // memory operand carries the exact architectural writeback amount; track
    // it in entry-SP coordinates instead of treating the SP write as unknown.
    if (instruction.context.architecture == Architecture::arm64) {
        const MemoryOperand *stack_writeback = nullptr;
        for (const auto &operand : instruction.operands) {
            const auto *memory = std::get_if<MemoryOperand>(&operand);
            if (!memory || !memory->base || memory->base->bank != RegisterBank::arm64_sp || !memory->writeback)
                continue;
            if (stack_writeback || memory->address_width != 64 || memory->index || memory->scale != 1) {
                state.stack_depth = {};
                state.supported = false;
                return true;
            }
            stack_writeback = memory;
        }
        if (stack_writeback) {
            if (stack_writeback->writeback_displacement == INT64_MIN ||
                !add(state.stack_depth, -stack_writeback->writeback_displacement))
                return false;
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
    }
    if (wrote_stack) {
        state.stack_depth = {};
        state.supported = false;
    }
    if (wrote_frame) {
        state.frame_depth = {};
        state.frame_register = -1;
        state.arm64_frame_pointer = false;
    }
    return true;
}

} // namespace

Result<StackFrameAnalysis> analyze_stack_frame(const FunctionRecord &function, const FunctionSnapshot &snapshot,
                                               std::stop_token stop) {
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
    const auto observe_stack_depth = [&](FlowValue depth) {
        if (!depth.known || depth.value < 0) {
            stack_extent_known = false;
            return;
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
        observe_stack_depth(state.stack_depth);
        for (const auto &fact : block->second->instructions) {
            if (stop.stop_requested())
                return Error{ErrorCode::canceled, "Stack analysis canceled"};
            if (!fact)
                continue;
            const auto &instruction = fact->instruction;
            const bool stack_architecture = instruction.context.architecture == Architecture::x86 ||
                instruction.context.architecture == Architecture::x86_64 ||
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
            if (arm64_pair && (!pair_memory || !pair_memory->base)) {
                result.complete = false;
            } else if (pair_sp || pair_fp) {
                if (pair_memory->data_width == 0 || pair_memory->data_width % 8 != 0 ||
                    pair_memory->index || pair_memory->ip_relative || pair_memory->address_width != 64 ||
                    instruction.access.size() <= 2) {
                    result.complete = false;
                } else {
                    const auto base = pair_sp ? state.stack_depth : state.frame_depth;
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
                            }
                        }
                    }
                }
            }
            // PUSH and POP access the stack implicitly. Preserve the cell's
            // entry-SP offset before transfer() advances or restores SP.
            if ((instruction.context.architecture == Architecture::x86 ||
                 instruction.context.architecture == Architecture::x86_64) &&
                (instruction.opcode == Opcode::push || instruction.opcode == Opcode::pop)) {
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
                    if ((instruction.opcode == Opcode::push && !add_checked(depth, bytes, depth)) ||
                        !subtract_checked(0, depth, offset)) {
                        result.complete = false;
                    } else if (!record_stack_slot(result, offset, width,
                                                  instruction.opcode == Opcode::pop,
                                                  instruction.opcode == Opcode::push, false,
                                                  instruction.address, access_detail_count)) {
                        return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                    }
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
                const bool riscv_stack = (instruction.context.architecture == Architecture::riscv32 ||
                                          instruction.context.architecture == Architecture::riscv64) &&
                                         memory->base->bank == RegisterBank::riscv_gpr && memory->base->index == 2;
                const bool riscv_frame = (instruction.context.architecture == Architecture::riscv32 ||
                                          instruction.context.architecture == Architecture::riscv64) &&
                                         memory->base->bank == RegisterBank::riscv_gpr && memory->base->index == 8;
                const bool ppc_stack = instruction.context.architecture == Architecture::powerpc &&
                                       memory->base->bank == RegisterBank::ppc_gpr && memory->base->index == 1;
                const bool ppc_frame = instruction.context.architecture == Architecture::powerpc &&
                                       memory->base->bank == RegisterBank::ppc_gpr && memory->base->index == 31;
                if (!arm64_stack && !arm64_frame && !x86_stack && !mips_stack && !mips_frame &&
                    !riscv_stack && !riscv_frame && !ppc_stack && !ppc_frame)
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
                const auto base = from_frame ? state.frame_depth : state.stack_depth;
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
                if ((address_taken || read || written) &&
                    !record_stack_slot(result, offset, address_taken ? 0 : memory->data_width,
                                     read, written, address_taken, instruction.address, access_detail_count))
                    return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
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
                    if (arm32_register(base, 13) && list) {
                        const unsigned count = std::popcount(list->mask);
                        std::int64_t base_offset = 0;
                        if (!state.stack_depth.known || !subtract_checked(0, state.stack_depth.value, base_offset) ||
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
                                const auto access = instruction.access.size() > 1 ? instruction.access[1]
                                                                                  : OperandAccess::address;
                                const bool read = access == OperandAccess::read || access == OperandAccess::read_write;
                                const bool written = access == OperandAccess::write || access == OperandAccess::read_write;
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
                        if (!record_stack_slot(result, offset, address_taken ? 0 : memory->data_width,
                                               read, written, address_taken, instruction.address,
                                               access_detail_count))
                            return Error{ErrorCode::resource_limit, "Stack analysis slot budget exceeded"};
                    }
                }
            }
            if (!transfer(instruction, state)) {
                state.stack_depth = {};
                state.supported = false;
            }
            observe_stack_depth(state.stack_depth);
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
