#include "hexlab/processors/decoder.hpp"
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>

namespace hexlab {
namespace {
constexpr std::string_view names[]{
"nop","aconst_null","iconst_m1","iconst_0","iconst_1","iconst_2","iconst_3","iconst_4","iconst_5",
"lconst_0","lconst_1","fconst_0","fconst_1","fconst_2","dconst_0","dconst_1","bipush","sipush","ldc","ldc_w","ldc2_w",
"iload","lload","fload","dload","aload","iload_0","iload_1","iload_2","iload_3","lload_0","lload_1","lload_2","lload_3",
"fload_0","fload_1","fload_2","fload_3","dload_0","dload_1","dload_2","dload_3","aload_0","aload_1","aload_2","aload_3",
"iaload","laload","faload","daload","aaload","baload","caload","saload","istore","lstore","fstore","dstore","astore",
"istore_0","istore_1","istore_2","istore_3","lstore_0","lstore_1","lstore_2","lstore_3","fstore_0","fstore_1","fstore_2","fstore_3",
"dstore_0","dstore_1","dstore_2","dstore_3","astore_0","astore_1","astore_2","astore_3","iastore","lastore","fastore","dastore",
"aastore","bastore","castore","sastore","pop","pop2","dup","dup_x1","dup_x2","dup2","dup2_x1","dup2_x2","swap",
"iadd","ladd","fadd","dadd","isub","lsub","fsub","dsub","imul","lmul","fmul","dmul","idiv","ldiv","fdiv","ddiv",
"irem","lrem","frem","drem","ineg","lneg","fneg","dneg","ishl","lshl","ishr","lshr","iushr","lushr","iand","land",
"ior","lor","ixor","lxor","iinc","i2l","i2f","i2d","l2i","l2f","l2d","f2i","f2l","f2d","d2i","d2l","d2f",
"i2b","i2c","i2s","lcmp","fcmpl","fcmpg","dcmpl","dcmpg","ifeq","ifne","iflt","ifge","ifgt","ifle","if_icmpeq",
"if_icmpne","if_icmplt","if_icmpge","if_icmpgt","if_icmple","if_acmpeq","if_acmpne","goto","jsr","ret","tableswitch","lookupswitch",
"ireturn","lreturn","freturn","dreturn","areturn","return","getstatic","putstatic","getfield","putfield","invokevirtual","invokespecial",
"invokestatic","invokeinterface","invokedynamic","new","newarray","anewarray","arraylength","athrow","checkcast","instanceof",
"monitorenter","monitorexit","wide","multianewarray","ifnull","ifnonnull","goto_w","jsr_w","breakpoint","<reserved>"};
DecodeResult fail(DecodeStatus s, std::string message) { return {s, {}, std::move(message)}; }
std::int32_t s32(std::span<const std::byte> b, std::size_t p) {
    const auto v = (std::uint32_t(std::to_integer<std::uint8_t>(b[p])) << 24) |
                   (std::uint32_t(std::to_integer<std::uint8_t>(b[p+1])) << 16) |
                   (std::uint32_t(std::to_integer<std::uint8_t>(b[p+2])) << 8) |
                    std::uint32_t(std::to_integer<std::uint8_t>(b[p+3]));
    return static_cast<std::int32_t>(v);
}
std::uint16_t u16(std::span<const std::byte> b, std::size_t p) {
    return std::uint16_t((std::to_integer<std::uint8_t>(b[p]) << 8) | std::to_integer<std::uint8_t>(b[p+1]));
}
std::int16_t s16(std::span<const std::byte> b, std::size_t p) { return static_cast<std::int16_t>(u16(b,p)); }
bool target(Address from, std::int64_t delta, Address &to) {
    if (delta < 0) { const auto n = static_cast<std::uint64_t>(-(delta + 1)) + 1; if (n > from.offset) return false; to = {from.space, from.offset - n}; }
    else { const auto n = static_cast<std::uint64_t>(delta); if (n > UINT64_MAX - from.offset) return false; to = {from.space, from.offset + n}; }
    return true;
}
}
DecodeResult decode_jvm(std::span<const std::byte> b, Address at) {
    if (b.empty()) return fail(DecodeStatus::truncated, "truncated JVM opcode");
    const auto op = std::to_integer<std::uint8_t>(b[0]);
    if (op >= std::size(names) || op == 0xca || op >= 0xcb)
        return fail(DecodeStatus::unsupported, "reserved or implementation-dependent JVM opcode");
    std::size_t n = 1;
    std::vector<Operand> operands;
    FlowKind flow = FlowKind::fallthrough;
    std::optional<Address> direct;
    std::optional<JvmSwitchTable> switch_table;
    auto need = [&](std::size_t count) { return count <= b.size() - std::min(n,b.size()); };
    auto imm = [&](std::uint64_t value, unsigned width, bool sign=false) {
        operands.push_back(ImmediateOperand{value,static_cast<std::uint16_t>(width),static_cast<std::uint16_t>(width),sign,{}});
    };
    auto branch16 = [&]() -> bool {
        if (!need(2)) return false;
        const auto d=s16(b,n); operands.push_back(RelativeOperand{d,16,32,{}});
        Address dest{}; if (!target(at,d,dest)) return false; direct=dest;
        n+=2; return true;
    };
    auto branch32 = [&]() -> bool {
        if (!need(4)) return false;
        const auto d=s32(b,n); operands.push_back(RelativeOperand{d,32,32,{}});
        Address dest{}; if(!target(at,d,dest)) return false; direct=dest; n+=4; return true;
    };
    std::string mnemonic(names[op]);
    if (op==0x10) { if(!need(1)) return fail(DecodeStatus::truncated,"truncated bipush"); imm(static_cast<std::uint8_t>(b[n]),8,true); ++n; }
    else if (op==0x11) { if(!need(2)) return fail(DecodeStatus::truncated,"truncated sipush"); imm(static_cast<std::uint16_t>(s16(b,n)),16,true); n+=2; }
    else if (op>=0x12&&op<=0x14) { const auto width=op==0x12?1u:2u; if(!need(width)) return fail(DecodeStatus::truncated,"truncated ldc index"); const auto index=width==1?std::to_integer<std::uint8_t>(b[n]):u16(b,n); if(!index)return fail(DecodeStatus::invalid,"ldc constant-pool index must be nonzero"); imm(index,width*8); n+=width; }
    else if ((op>=0x15&&op<=0x19)||(op>=0x36&&op<=0x3a)||op==0xa9) { if(!need(1)) return fail(DecodeStatus::truncated,"truncated local index"); imm(std::to_integer<std::uint8_t>(b[n++]),8); }
    else if (op==0x84) { if(!need(2)) return fail(DecodeStatus::truncated,"truncated iinc"); imm(std::to_integer<std::uint8_t>(b[n]),8); imm(static_cast<std::uint8_t>(b[n+1]),8,true); n+=2; }
    else if (op>=0x99&&op<=0xa8) { if(!branch16()) return fail(need(2)?DecodeStatus::invalid:DecodeStatus::truncated,"invalid or truncated branch target"); flow=op==0xa7||op==0xa8?FlowKind::jump:FlowKind::conditional_branch; }
    else if (op==0xc6||op==0xc7) { if(!branch16()) return fail(need(2)?DecodeStatus::invalid:DecodeStatus::truncated,"invalid or truncated null branch"); flow=FlowKind::conditional_branch; }
    else if (op==0xc8||op==0xc9) { if(!branch32()) return fail(need(4)?DecodeStatus::invalid:DecodeStatus::truncated,"invalid or truncated wide branch"); flow=FlowKind::jump; }
    else if (op==0xaa||op==0xab) {
        const auto padding=(4-((at.offset+1)&3))&3;
        if(!need(padding+8)) return fail(DecodeStatus::truncated,"truncated switch header");
        for (std::size_t i = 0; i < padding; ++i)
            if (b[n + i] != std::byte{0}) return fail(DecodeStatus::invalid, "nonzero switch alignment padding");
        n+=padding; const auto dflt=s32(b,n); n+=4;
        Address dest{}; if(!target(at,dflt,dest)) return fail(DecodeStatus::invalid,"switch default target overflows method space");
        JvmSwitchTable parsed; parsed.dense = op == 0xaa; parsed.default_target = dest;
        if(op==0xaa) {
            if(!need(8)) return fail(DecodeStatus::truncated,"truncated tableswitch bounds");
            const auto low=s32(b,n), high=s32(b,n+4); n+=8;
            if(high<low) return fail(DecodeStatus::invalid,"tableswitch high bound precedes low bound");
            const auto count=std::uint64_t(std::int64_t(high)-low)+1;
            if (n > 65535 || count > (65535 - n) / 4)
                return fail(DecodeStatus::unsupported,"tableswitch exceeds the classfile Code extent limit");
            if(count>(b.size()-n)/4) return fail(DecodeStatus::truncated,"truncated tableswitch targets");
            parsed.cases.reserve(static_cast<std::size_t>(count));
            for(std::uint64_t k=0;k<count;++k){
                const auto d=s32(b,n); n+=4; Address case_target{};
                if(!target(at,d,case_target))return fail(DecodeStatus::invalid,"tableswitch case target overflows method space");
                const auto key=static_cast<std::int32_t>(std::int64_t(low)+static_cast<std::int64_t>(k));
                parsed.cases.push_back({key,case_target});
            }
        } else {
            const auto pairs=s32(b,n); n+=4;
            if(pairs<0) return fail(DecodeStatus::invalid,"negative lookupswitch pair count");
            if (n > 65535 || std::uint64_t(pairs) > (65535 - n) / 8)
                return fail(DecodeStatus::unsupported,"lookupswitch exceeds the classfile Code extent limit");
            if(std::uint64_t(pairs)>(b.size()-n)/8) return fail(DecodeStatus::truncated,"truncated lookupswitch pairs");
            parsed.cases.reserve(static_cast<std::size_t>(pairs));
            std::int32_t previous=INT32_MIN;
            for(std::int32_t k=0;k<pairs;++k){
                const auto key=s32(b,n), d=s32(b,n+4); n+=8;
                if(k&&key<=previous)return fail(DecodeStatus::invalid,"lookupswitch keys are not strictly increasing");
                previous=key; Address case_target{};
                if(!target(at,d,case_target))return fail(DecodeStatus::invalid,"lookupswitch case target overflows method space");
                parsed.cases.push_back({key,case_target});
            }
        }
        if (n > 65535) return fail(DecodeStatus::unsupported, "JVM switch exceeds the classfile Code extent limit");
        const auto inside_instruction = [&](Address target_address) {
            return target_address.space == at.space && target_address.offset >= at.offset &&
                   target_address.offset - at.offset < n;
        };
        if (inside_instruction(dest) || std::any_of(parsed.cases.begin(), parsed.cases.end(),
                [&](const auto &item) { return inside_instruction(item.target); }))
            return fail(DecodeStatus::invalid, "JVM switch target points into its own operand encoding");
        switch_table = std::move(parsed);
        direct=dest; flow=FlowKind::switch_dispatch;
    }
    else if (op>=0xb2&&op<=0xb8) { if(!need(2)) return fail(DecodeStatus::truncated,"truncated constant-pool index"); const auto index=u16(b,n); if(!index)return fail(DecodeStatus::invalid,"field or method constant-pool index must be nonzero"); imm(index,16); n+=2; }
    else if (op==0xb9||op==0xba) { if(!need(4)) return fail(DecodeStatus::truncated,"truncated invoke operand"); const auto index=u16(b,n); const auto count=std::to_integer<std::uint8_t>(b[n+2]); if(!index)return fail(DecodeStatus::invalid,"invoke constant-pool index must be nonzero"); if(op==0xb9&&(count==0||b[n+3]!=std::byte{0}))return fail(DecodeStatus::invalid,"invokeinterface count must be nonzero and its reserved operand must be zero"); if(op==0xba&&(b[n+2]!=std::byte{0}||b[n+3]!=std::byte{0}))return fail(DecodeStatus::invalid,"invokedynamic reserved operands must be zero"); imm(index,16); imm(count,8); imm(std::to_integer<std::uint8_t>(b[n+3]),8); n+=4; }
    else if (op==0xbb||op==0xbd||op==0xc0||op==0xc1) { if(!need(2)) return fail(DecodeStatus::truncated,"truncated type index"); const auto index=u16(b,n); if(!index)return fail(DecodeStatus::invalid,"type constant-pool index must be nonzero"); imm(index,16); n+=2; }
    else if (op==0xbc) {
        if(!need(1)) return fail(DecodeStatus::truncated,"truncated newarray type");
        const auto type = std::to_integer<std::uint8_t>(b[n]);
        if (type < 4 || type > 11) return fail(DecodeStatus::invalid,"newarray has an invalid primitive type code");
        imm(type,8); ++n;
    }
    else if (op==0xc5) { if(!need(3)) return fail(DecodeStatus::truncated,"truncated multianewarray"); const auto index=u16(b,n); const auto dimensions=std::to_integer<std::uint8_t>(b[n+2]); if(!index||!dimensions)return fail(DecodeStatus::invalid,"multianewarray requires a nonzero class index and dimension count"); imm(index,16); imm(dimensions,8); n+=3; }
    else if(op==0xc4) {
        if(!need(1)) return fail(DecodeStatus::truncated,"truncated wide opcode");
        const auto nested=std::to_integer<std::uint8_t>(b[n++]);
        if(!((nested>=0x15&&nested<=0x19)||(nested>=0x36&&nested<=0x3a)||nested==0x84||nested==0xa9)) return fail(DecodeStatus::invalid,"wide prefix applied to an illegal opcode");
        if(!need(nested==0x84?4:2)) return fail(DecodeStatus::truncated,"truncated wide operands");
        mnemonic=std::string("wide ")+std::string(names[nested]); imm(nested,8); imm(u16(b,n),16); n+=2;
        if(nested==0x84){imm(static_cast<std::uint16_t>(s16(b,n)),16,true);n+=2;}
        if(nested==0xa9)flow=FlowKind::jump;
    }
    if(op>=0xb6&&op<=0xba)flow=FlowKind::call;
    if(op==0xa9)flow=FlowKind::jump;
    if(op>=0xac&&op<=0xb1) flow=FlowKind::ret;
    if(op==0xbf) flow=FlowKind::trap;
    if(n>65535) return fail(DecodeStatus::unsupported,"JVM instruction exceeds the classfile Code extent limit");
    Instruction i; i.context={Architecture::jvm,ExecutionMode::jvm,ByteOrder::big}; i.address=at;
    i.length=static_cast<std::uint32_t>(n);
    std::copy_n(b.begin(),std::min(n,i.bytes.size()),i.bytes.begin());
    if(n>i.bytes.size())i.extended_bytes.assign(b.begin(),b.begin()+static_cast<std::ptrdiff_t>(n));
    i.opcode=Opcode::jvm; i.mnemonic_override=std::move(mnemonic); i.operands=std::move(operands); i.flow=flow; i.direct_target=direct;
    i.jvm_switch=std::move(switch_table);
    return {DecodeStatus::decoded,std::move(i),{}};
}
} // namespace hexlab
