#pragma once
#include "hexlab/compare/compare.hpp"
#include "hexlab/processors/instruction.hpp"
#include <cstdint>
#include <type_traits>
#include <variant>

namespace hexlab::app {
struct CompareFeatureHash {
    std::uint64_t value = UINT64_C(14695981039346656037);
    void add(std::uint64_t x) { for(unsigned i=0;i<8;++i){value^=static_cast<std::uint8_t>(x>>(i*8));value*=UINT64_C(1099511628211);} }
};
inline compare::InstructionSemanticFeature compare_semantic_feature(const Instruction &ins, std::uint64_t fingerprint) {
    CompareFeatureHash operands, effects;
    operands.add(ins.operands.size());
    for(const auto &op:ins.operands){
        operands.add(op.index());
        std::visit([&](const auto &v){using T=std::decay_t<decltype(v)>;
            if constexpr(std::is_same_v<T,RegisterOperand>){operands.add(static_cast<std::uint64_t>(v.bank));operands.add(v.width);operands.add(v.high_byte);}
            else if constexpr(std::is_same_v<T,MemoryOperand>){operands.add(v.data_width);operands.add(v.address_width);operands.add(v.scale);operands.add(v.ip_relative);operands.add(v.resolved_address.has_value());if(!v.ip_relative&&!v.resolved_address)operands.add(static_cast<std::uint64_t>(v.displacement));}
            else if constexpr(std::is_same_v<T,ImmediateOperand>){operands.add(v.value);operands.add(v.effective_width);operands.add(v.is_signed);}
            else if constexpr(std::is_same_v<T,RelativeOperand>){operands.add(v.effective_width);}
            else if constexpr(std::is_same_v<T,FarPointerOperand>){operands.add(v.selector);operands.add(v.offset_width);}
            else if constexpr(std::is_same_v<T,FarMemoryOperand>){operands.add(v.offset_width);operands.add(v.address.data_width);operands.add(v.address.address_width);}
            else if constexpr(std::is_same_v<T,ArmShiftedRegisterOperand>){operands.add(static_cast<std::uint64_t>(v.source.bank));operands.add(v.source.width);operands.add(static_cast<std::uint64_t>(v.shift));operands.add(v.amount);}
            else if constexpr(std::is_same_v<T,ArmMemoryOperand>){operands.add(static_cast<std::uint64_t>(v.base.bank));operands.add(v.base.width);operands.add(v.offset.index());operands.add(v.add);operands.add(v.pre_index);operands.add(v.data_width);}
            else if constexpr(std::is_same_v<T,ArmRegisterListOperand>)operands.add(v.mask);
            else if constexpr(std::is_same_v<T,ThumbRelativeOperand>){operands.add(static_cast<std::uint64_t>(v.displacement));operands.add(v.encoded_width);}
        },op);
    }
    for(auto access:ins.access) effects.add(static_cast<std::uint64_t>(access));
    effects.add(ins.memory_read);effects.add(ins.memory_write);effects.add(ins.lock_prefix);effects.add(ins.delay_slots);
    if(ins.arm){effects.add(static_cast<std::uint64_t>(ins.arm->predicate));effects.add(static_cast<std::uint64_t>(ins.arm->exchange));effects.add(ins.arm->flags_written);effects.add(ins.arm->flags_known);effects.add(ins.arm->q_flag_may_set);effects.add(ins.arm->writes_pc);effects.add(ins.arm->writeback);}
    return {fingerprint,static_cast<std::uint32_t>(ins.opcode),static_cast<std::uint32_t>(ins.flow),operands.value,effects.value};
}
inline bool attach_instruction_addresses(compare::FunctionInstructionDiff &diff,
                                         const compare::FunctionFeature &old_feature,
                                         const compare::FunctionFeature &new_feature,
                                         std::stop_token stop = {}) {
    const bool old_complete = old_feature.instruction_addresses.size() == old_feature.instruction_fingerprints.size();
    const bool new_complete = new_feature.instruction_addresses.size() == new_feature.instruction_fingerprints.size();
    for (std::size_t index = 0; index < diff.runs.size(); ++index) {
        if ((index & 0xffu) == 0 && stop.stop_requested()) return false;
        auto &run = diff.runs[index];
        if (run.old_count && old_complete && run.old_start < old_feature.instruction_addresses.size())
            run.old_address = old_feature.instruction_addresses[static_cast<std::size_t>(run.old_start)];
        if (run.new_count && new_complete && run.new_start < new_feature.instruction_addresses.size())
            run.new_address = new_feature.instruction_addresses[static_cast<std::size_t>(run.new_start)];
    }
    return !stop.stop_requested();
}
}
