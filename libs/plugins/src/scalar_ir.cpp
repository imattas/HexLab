#include "scalar_ir.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <tuple>

namespace hexlab::plugins::detail {
namespace {
using RegisterKey = std::tuple<RegisterBank, std::uint8_t, std::uint16_t, bool>;
RegisterKey key(RegisterOperand value) { return {value.bank,value.index,value.width,value.high_byte}; }
bool zero(const HexLabSemanticRegisterV2 &value) {
    return !value.bank&&!value.index&&!value.width&&!value.reserved;
}
bool native_scalar_context(DecodeContext context){
    switch(context.architecture){
    case Architecture::x86:return context.mode==ExecutionMode::x86_16||context.mode==ExecutionMode::x86_32;
    case Architecture::x86_64:return context.mode==ExecutionMode::x86_64;
    // Existing analysis dispatch does not delegate A32/Thumb decoding.
    case Architecture::arm:return false;
    case Architecture::arm64:return context.mode==ExecutionMode::a64;
    case Architecture::riscv32:return context.mode==ExecutionMode::rv32;
    case Architecture::riscv64:return context.mode==ExecutionMode::rv64||context.mode==ExecutionMode::rv64c;
    case Architecture::mips32:return context.mode==ExecutionMode::mips32;
    case Architecture::mips64:return context.mode==ExecutionMode::mips64;
    case Architecture::powerpc:return context.mode==ExecutionMode::ppc32||context.mode==ExecutionMode::ppc64;
    case Architecture::mos6502:return context.mode==ExecutionMode::m6502;
    default:return false;
    }
}
bool native_scalar_register(RegisterOperand reg, DecodeContext context) {
    if(reg.high_byte)return false;
    switch(reg.bank){
    case RegisterBank::gpr:
        return reg.width==(context.mode==ExecutionMode::x86_64?64:context.mode==ExecutionMode::x86_32?32:16)&&
               reg.index<(context.mode==ExecutionMode::x86_64?16:8);
    case RegisterBank::arm32_gpr: return reg.width==32&&reg.index<15;
    case RegisterBank::arm64_gpr: return reg.width==64&&reg.index<31;
    case RegisterBank::riscv_gpr:
        return reg.index>0&&reg.index<32&&reg.width==(context.mode==ExecutionMode::rv32?32:64);
    case RegisterBank::mips_gpr:
        return reg.index>0&&reg.index<32&&reg.width==(context.mode==ExecutionMode::mips32?32:64);
    case RegisterBank::ppc_gpr:
        return reg.index<32&&reg.width==(context.mode==ExecutionMode::ppc32?32:64);
    case RegisterBank::mos6502: return reg.width==8&&reg.index<3;
    default:return false;
    }
}
std::set<RegisterKey> register_set(const std::vector<RegisterOperand> &registers){
    std::set<RegisterKey> result;
    for(const auto reg:registers)result.insert(key(reg));
    return result;
}
}
std::optional<decompiler::Intrinsic> convert_scalar_ir(const HexLabInstructionIR &record,const Instruction &instruction,
                                                      ScalarRegisterConverter convert_register){
    using namespace decompiler;
    if(!convert_register||!native_scalar_context(instruction.context)||record.struct_size<sizeof(record)||record.api_version!=HEXLAB_SCALAR_IR_API_VERSION||
       record.reserved0||record.reserved1||!record.node_count||record.node_count>HEXLAB_SCALAR_IR_MAX_NODES||
       !record.output_count||record.output_count>HEXLAB_SCALAR_IR_MAX_OUTPUTS||
       record.semantic.memory_update_count||instruction.opcode!=Opcode::opaque||instruction.flow!=FlowKind::fallthrough||
       instruction.condition||instruction.delay_slots||instruction.direct_target||instruction.memory_read||instruction.memory_write||
       instruction.operands.empty())
        return {};
    for(const auto &operand:instruction.operands)
        if(!std::holds_alternative<RegisterOperand>(operand)&&!std::holds_alternative<ImmediateOperand>(operand))return {};
    for(const auto reg:instruction.register_reads)if(!native_scalar_register(reg,instruction.context))return {};
    for(const auto reg:instruction.register_writes)if(!native_scalar_register(reg,instruction.context))return {};
    std::array<ExpressionPtr,HEXLAB_SCALAR_IR_MAX_NODES> values{};
    std::array<std::uint32_t,HEXLAB_SCALAR_IR_MAX_NODES> costs{},depths{};
    std::set<RegisterKey> reads,writes;
    for(std::uint32_t i=0;i<record.node_count;++i){
        const auto &node=record.nodes[i];
        if(node.struct_size<sizeof(node)||node.reserved0||node.reserved1||node.is_signed>1||
           (node.width!=8&&node.width!=16&&node.width!=32&&node.width!=64))return {};
        const ValueType type{TypeKind::integer,static_cast<std::uint16_t>(node.width),node.is_signed!=0};
        costs[i]=1;depths[i]=1;
        if(node.operation==HEXLAB_SCALAR_IR_CONSTANT){
            if(!zero(node.reg)||node.left!=HEXLAB_SCALAR_IR_NO_NODE||node.right!=HEXLAB_SCALAR_IR_NO_NODE||
               (node.width<64&&(node.value>>node.width)))return {};
            values[i]=std::make_shared<Expression>(Expression{type,ConstantValue{node.value,type}});
        }else if(node.operation==HEXLAB_SCALAR_IR_REGISTER){
            if(node.value||node.left!=HEXLAB_SCALAR_IR_NO_NODE||node.right!=HEXLAB_SCALAR_IR_NO_NODE)return {};
            const auto reg=convert_register(instruction.context,node.reg);
            if(!reg||reg->width!=node.width||!native_scalar_register(*reg,instruction.context))return {};
            reads.insert(key(*reg));values[i]=std::make_shared<Expression>(Expression{type,RegisterValue{*reg}});
        }else{
            if(node.value||!zero(node.reg)||node.left>=i||values[node.left]->type!=type)return {};
            costs[i]+=costs[node.left];depths[i]+=depths[node.left];
            if(node.operation==HEXLAB_SCALAR_IR_NOT){
                if(node.right!=HEXLAB_SCALAR_IR_NO_NODE)return {};
                values[i]=std::make_shared<Expression>(Expression{type,UnaryValue{"bitnot",values[node.left]}});
            }else{
                if(node.right>=i||values[node.right]->type!=type)return {};
                const bool is_shift=node.operation==HEXLAB_SCALAR_IR_SHL||
                    node.operation==HEXLAB_SCALAR_IR_LSHR||node.operation==HEXLAB_SCALAR_IR_ASHR;
                if(is_shift&&record.nodes[node.right].operation==HEXLAB_SCALAR_IR_CONSTANT&&
                   record.nodes[node.right].value>=node.width)return {};
                const char *operation=nullptr;
                switch(node.operation){
                case HEXLAB_SCALAR_IR_ADD:operation="add";break;
                case HEXLAB_SCALAR_IR_SUB:operation="sub";break;
                case HEXLAB_SCALAR_IR_MUL:operation="mul";break;
                case HEXLAB_SCALAR_IR_AND:operation="and";break;
                case HEXLAB_SCALAR_IR_OR:operation="or";break;
                case HEXLAB_SCALAR_IR_XOR:operation="xor";break;
                case HEXLAB_SCALAR_IR_EQ:operation="eq";break;
                case HEXLAB_SCALAR_IR_NE:operation="ne";break;
                case HEXLAB_SCALAR_IR_ULT:operation="ult";break;
                case HEXLAB_SCALAR_IR_UGE:operation="uge";break;
                case HEXLAB_SCALAR_IR_ULE:operation="ule";break;
                case HEXLAB_SCALAR_IR_UGT:operation="ugt";break;
                case HEXLAB_SCALAR_IR_SLT:operation="slt";break;
                case HEXLAB_SCALAR_IR_SGE:operation="sge";break;
                case HEXLAB_SCALAR_IR_SLE:operation="sle";break;
                case HEXLAB_SCALAR_IR_SGT:operation="sgt";break;
                case HEXLAB_SCALAR_IR_SHL:operation="shl";break;
                case HEXLAB_SCALAR_IR_LSHR:operation="shr";break;
                case HEXLAB_SCALAR_IR_ASHR:operation="sar";break;
                default:return {};
                }
                costs[i]+=costs[node.right];depths[i]=1+std::max(depths[node.left],depths[node.right]);
                values[i]=std::make_shared<Expression>(Expression{type,BinaryValue{operation,values[node.left],values[node.right]}});
            }
        }
        if(costs[i]>HEXLAB_SCALAR_IR_MAX_EXPANDED_NODES||depths[i]>HEXLAB_SCALAR_IR_MAX_DEPTH)return {};
    }
    Intrinsic effect{"plugin_scalar_"+instruction.mnemonic_override,{},IntrinsicMemoryEffect::none};
    std::array<bool,HEXLAB_SCALAR_IR_MAX_NODES> reachable{};
    std::uint32_t expanded=0;
    for(std::uint32_t i=0;i<record.output_count;++i){
        const auto &output=record.outputs[i];
        if(output.struct_size<sizeof(output)||output.reserved0||output.reserved1||output.node_index>=record.node_count)return {};
        const auto reg=convert_register(instruction.context,output.destination);
        if(!reg||!native_scalar_register(*reg,instruction.context)||reg->width!=values[output.node_index]->type.bits||
           !writes.insert(key(*reg)).second)return {};
        expanded+=costs[output.node_index];
        if(expanded>HEXLAB_SCALAR_IR_MAX_EXPANDED_NODES)return {};
        reachable[output.node_index]=true;
        effect.register_writes.push_back(*reg);effect.register_output_values.push_back(values[output.node_index]);
    }
    for(std::uint32_t i=record.node_count;i-- >0;)if(reachable[i]){
        const auto &node=record.nodes[i];
        if(node.left!=HEXLAB_SCALAR_IR_NO_NODE)reachable[node.left]=true;
        if(node.right!=HEXLAB_SCALAR_IR_NO_NODE)reachable[node.right]=true;
    }
    if(std::find(reachable.begin(),reachable.begin()+record.node_count,false)!=reachable.begin()+record.node_count||
       reads!=register_set(instruction.register_reads)||writes!=register_set(instruction.register_writes))return {};
    if(effect.register_output_values.size()==1)effect.result_type=effect.register_output_values.front()->type;
    return effect;
}
bool same_scalar_instruction(const Instruction &a,const Instruction &b){
    if(a.context!=b.context||a.address!=b.address||a.length!=b.length||a.opcode!=b.opcode||
       a.mnemonic_override!=b.mnemonic_override||a.operands.size()!=b.operands.size()||a.access!=b.access||
       register_set(a.register_reads)!=register_set(b.register_reads)||register_set(a.register_writes)!=register_set(b.register_writes)||
       a.flow!=b.flow||a.condition!=b.condition||a.delay_slots!=b.delay_slots||a.direct_target!=b.direct_target||
       a.memory_read!=b.memory_read||a.memory_write!=b.memory_write||!a.extended_bytes.empty()||
       a.dex_switch||a.jvm_switch||a.x86_condition||a.x86_loop_condition||a.x86_loop_counter_width||
       a.x86_repeat!=X86RepeatPrefix::none||a.x86_evex||a.x86_opmask||a.x86_opmask_zeroing||a.stack_value_width||
       a.stack_slot_count||a.x87_stack_delta||a.lock_prefix||a.arm||a.atomic_aq||a.atomic_rl||a.csr_read||a.csr_write||
       a.rounding_mode||a.writes_fflags||a.riscv_vector_masked||a.vector_bits||a.vector_element_bits)return false;
    for(std::size_t i=0;i<a.operands.size();++i){
        if(const auto *reg=std::get_if<RegisterOperand>(&a.operands[i])){
            const auto *other=std::get_if<RegisterOperand>(&b.operands[i]);if(!other||*reg!=*other)return false;
        }else if(const auto *immediate=std::get_if<ImmediateOperand>(&a.operands[i])){
            const auto *other=std::get_if<ImmediateOperand>(&b.operands[i]);
            if(!other||immediate->value!=other->value||immediate->encoded_width!=other->encoded_width||
               immediate->effective_width!=other->effective_width||immediate->is_signed!=other->is_signed||
               immediate->encoding!=other->encoding)return false;
        }else return false;
    }
    return std::equal(a.encoded_bytes().begin(),a.encoded_bytes().end(),b.encoded_bytes().begin(),b.encoded_bytes().end());
}
}
