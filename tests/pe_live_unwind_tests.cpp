#include "hexlab/image/pe_unwind.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace hexlab;
namespace {
int failures = 0;
void check(bool value, const char *message) { if (!value) { ++failures; std::cerr << "FAIL: " << message << '\n'; } }
std::vector<std::byte> le(std::uint64_t value, std::size_t size = 8) {
    std::vector<std::byte> result(size);
    for (std::size_t i = 0; i < size; ++i) result[i] = static_cast<std::byte>((value >> (8*i)) & 0xff);
    return result;
}
std::uint64_t get(const PeRegisterContext &context, const char *name) {
    std::uint64_t value = 0; auto it = context.registers.find(name);
    if (it == context.registers.end()) return UINT64_MAX;
    for (std::size_t i = 0; i < it->second.size() && i < 8; ++i) value |= std::uint64_t{std::to_integer<unsigned char>(it->second[i])} << (i*8);
    return value;
}
PeMemoryReader memory(std::map<std::uint64_t, std::vector<std::byte>> bytes) {
    return [bytes=std::move(bytes)](std::uint64_t address, std::size_t size) -> Result<std::vector<std::byte>> {
        auto found=bytes.find(address); if(found==bytes.end()) return Error{ErrorCode::out_of_bounds,"unmapped test address"};
        if(found->second.size()<size) return std::vector<std::byte>(found->second.begin(),found->second.begin()+static_cast<std::ptrdiff_t>(size-1));
        return std::vector<std::byte>(found->second.begin(),found->second.begin()+static_cast<std::ptrdiff_t>(size));
    };
}
void amd64_restores_stack_and_saved_registers_atomically() {
    PeMetadata metadata;
    PeUnwindInfo info;
    info.operations = {{PeUnwindOperationKind::allocate_stack, 5, 0, 32, 0, false, {}},
                       {PeUnwindOperationKind::save_nonvolatile, 1, 3, 0, 8, false, {}}};
    metadata.exception_functions.push_back({0x1000,0x1100,0,{},info});
    PeRegisterContext input; input.registers["rsp"]=le(0x7000); input.registers["rbx"]=le(0xdead);
    auto reader=memory({{0x7028,le(0x12345678)}, {0x7020,le(0x401234)}});
    auto caller=unwind_pe_frame(metadata,Architecture::x86_64,0x140000000,0x140001020,input,reader);
    check(caller && get(caller.value(),"rbx")==0x12345678 && get(caller.value(),"rsp")==0x7028 && get(caller.value(),"rip")==0x401234,
          "AMD64 unwinds saved nonvolatile register, frame allocation, return address, and caller stack");
    check(get(input,"rbx")==0xdead && get(input,"rsp")==0x7000,"AMD64 leaves input context unchanged");
}
void amd64_reports_short_reads_and_missing_registers() {
    PeMetadata metadata; PeUnwindInfo info; metadata.exception_functions.push_back({0x1000,0x1100,0,{},info});
    PeRegisterContext missing;
    auto fail=unwind_pe_frame(metadata,Architecture::x86_64,0x100000,0x101001,missing,memory({}));
    check(!fail && fail.error().code==ErrorCode::invalid_argument,"AMD64 missing RSP is explicit");
    PeRegisterContext context; context.registers["rsp"]=le(0x8000);
    auto short_read=unwind_pe_frame(metadata,Architecture::x86_64,0x100000,0x101001,context,memory({{0x8000,le(1,7)}}));
    check(!short_read && short_read.error().code==ErrorCode::out_of_bounds,"AMD64 short return-address read is bounded");
}
void amd64_restores_vector_register_and_chained_frame() {
    PeMetadata metadata; PeUnwindInfo chained; chained.operations={{PeUnwindOperationKind::push_nonvolatile,1,3,8,0,false,{}}};
    PeUnwindInfo top; top.operations={{PeUnwindOperationKind::save_xmm128,2,6,0,32,false,{}},
                                      {PeUnwindOperationKind::allocate_stack,5,0,16,0,false,{}}};
    auto chain=std::make_shared<PeChainedRuntimeFunction>(); chain->unwind_info=std::make_shared<PeUnwindInfo>(chained); top.chained_function=chain;
    metadata.exception_functions.push_back({0x1000,0x1100,0,{},top});
    PeRegisterContext input; input.registers["rsp"]=le(0x7000);
    auto xmm=le(0x1122334455667788,16); xmm[8]=std::byte{0x99};
    auto caller=unwind_pe_frame(metadata,Architecture::x86_64,0x100000,0x101020,input,
        memory({{0x7010,le(0x7777)},{0x7020,xmm},{0x7018,le(0x401000)}}));
    check(caller && get(caller.value(),"rbx")==0x7777 && get(caller.value(),"rsp")==0x7020 &&
              get(caller.value(),"rip")==0x401000 && caller.value().registers.at("xmm6")==xmm,
          "AMD64 chained unwind restores GPR/XMM state and advances caller stack");
}
void amd64_machine_frame_and_partial_prolog_are_bounded() {
    PeMetadata metadata; PeUnwindInfo machine; machine.size_of_prolog=4;
    machine.operations={{PeUnwindOperationKind::push_machine_frame,4,0,40,0,false,{}}};
    metadata.exception_functions.push_back({0x2000,0x2100,0,{},machine});
    PeRegisterContext context;context.registers["rsp"]=le(0x5000);
    auto trap=unwind_pe_frame(metadata,Architecture::x86_64,0x400000,0x402004,context,
        memory({{0x5000,le(0x401234)},{0x5028,le(0x6000)}}));
    check(trap && get(trap.value(),"rip")==0x401234 && get(trap.value(),"rsp")==0x5028,
          "AMD64 machine-frame unwind restores saved RIP and interrupt stack pointer");
    PeUnwindInfo prolog;prolog.size_of_prolog=8;
    prolog.operations={{PeUnwindOperationKind::allocate_stack,6,0,32,0,false,{}}};
    metadata.exception_functions[0]={0x2000,0x2100,0,{},prolog};
    auto partial=unwind_pe_frame(metadata,Architecture::x86_64,0x400000,0x402002,context,memory({{0x5000,le(0x4444)}}));
    check(partial && get(partial.value(),"rsp")==0x5008 && get(partial.value(),"rip")==0x4444,
          "AMD64 PC inside a prolog skips unwind operations whose instruction has not executed");
}
void arm64_packed_restores_frame_record() {
    PeMetadata metadata; PeArm64RuntimeFunction fn; fn.begin_rva=0x2000; fn.function_length=0x40;
    fn.kind=PeArm64UnwindKind::packed_single; fn.packed_unwind=PeArm64PackedUnwind{4,0,0,3,false,4};
    metadata.arm64_exception_functions.push_back(fn);
    PeRegisterContext input; input.registers["sp"]=le(0x9000); input.registers["fp"]=le(0); input.registers["lr"]=le(0xdead);
    auto caller=unwind_pe_frame(metadata,Architecture::arm64,0x180000000,0x180002008,input,memory({{0x9000,le(0xabc0)},{0x9008,le(0x180001234)}}));
    check(caller && get(caller.value(),"fp")==0xabc0 && get(caller.value(),"lr")==0x180001234 &&
              get(caller.value(),"pc")==0x180001234 && get(caller.value(),"sp")==0x9040,
          "ARM64 packed frame restores FP/LR and advances SP by encoded frame size");
}
void arm64_packed_restores_integer_fp_and_homed_layout() {
    PeMetadata metadata;PeArm64RuntimeFunction fn;fn.begin_rva=0x2400;fn.function_length=0x80;
    fn.packed_unwind=PeArm64PackedUnwind{8,1,2,1,true,8};metadata.arm64_exception_functions.push_back(fn);
    PeRegisterContext input;input.registers["sp"]=le(0xc000);input.registers["lr"]=le(0);
    auto caller=unwind_pe_frame(metadata,Architecture::arm64,0x180000000,0x180002404,input,
        memory({{0xc010,le(0x19)},{0xc018,le(0x20)},{0xc020,le(0x30)},{0xc028,le(0xd8)},{0xc030,le(0xd9)}}));
    check(caller && get(caller.value(),"x19")==0x19 && get(caller.value(),"x20")==0x20 &&
              get(caller.value(),"lr")==0x30 && caller.value().registers.at("d8")==le(0xd8) &&
              caller.value().registers.at("d9")==le(0xd9) && get(caller.value(),"sp")==0xc080,
          "ARM64 packed ABI offsets restore integer, link, FP registers and homed-argument area");
}
void arm64_xdata_restores_nonvolatile_register_fplr_and_stack() {
    PeMetadata metadata; PeArm64RuntimeFunction fn; fn.begin_rva=0x4000; fn.function_length=0x40;
    PeArm64Xdata x;
    x.unwind_codes={{0xe1,{0xe1},{}},{0xc8,{0xc8,0x1e},{}},{0x9f,{0x9f},{ }},{0xe4,{0xe4},{}}};
    fn.xdata=x; metadata.arm64_exception_functions.push_back(fn);
    PeRegisterContext input; input.registers["sp"]=le(0xa000); input.registers["fp"]=le(0xa000); input.registers["lr"]=le(0xdead);
    auto caller=unwind_pe_frame(metadata,Architecture::arm64,0x100000,0x104010,input,
        memory({{0xa0f0,le(0x1919)},{0xa0f8,le(0x2020)},{0xa000,le(0xf00d)},{0xa008,le(0x1234)}}));
    check(caller && get(caller.value(),"x19")==0x1919 && get(caller.value(),"x20")==0x2020 &&
              get(caller.value(),"fp")==0xf00d && get(caller.value(),"lr")==0x1234 && get(caller.value(),"sp")==0xa100,
          "ARM64 xdata restores GPR pair, FP/LR pair, and pre-indexed allocation");
}
void arm64_xdata_alloc_and_unsupported_are_precise() {
    PeMetadata metadata; PeArm64RuntimeFunction fn; fn.begin_rva=0x3000; fn.function_length=0x40;
    PeArm64Xdata x; x.unwind_codes.push_back({0x02,{0x02},{}}); // alloc_s: 32 bytes
    fn.xdata=x; metadata.arm64_exception_functions.push_back(fn);
    PeRegisterContext input; input.registers["sp"]=le(0xa000); input.registers["lr"]=le(0x4444);
    auto caller=unwind_pe_frame(metadata,Architecture::arm64,0x100000,0x103004,input,memory({}));
    check(caller && get(caller.value(),"sp")==0xa020 && get(caller.value(),"pc")==0x4444,
          "ARM64 xdata alloc_s restores caller stack from live LR");
    metadata.arm64_exception_functions[0].xdata->unwind_codes={{0xdf,{0xdf,0x01},{}}};
    auto unsupported=unwind_pe_frame(metadata,Architecture::arm64,0x100000,0x103004,input,memory({}));
    check(!unsupported && unsupported.error().code==ErrorCode::invalid_argument,"ARM64 SVE unwind reports a missing runtime vector length precisely");
}
void arm64_pdata_link_uses_parent_unwind_record() {
    PeMetadata metadata; PeArm64RuntimeFunction child; child.begin_rva=0x5000; child.function_length=0;
    child.kind=PeArm64UnwindKind::pdata_link; child.linked_record_index=1;
    PeArm64RuntimeFunction parent; parent.begin_rva=0x6000; parent.function_length=0x40; parent.kind=PeArm64UnwindKind::xdata;
    PeArm64Xdata x; x.unwind_codes={{0x01,{0x01},{}}}; parent.xdata=x;
    metadata.arm64_exception_functions={child,parent};
    PeRegisterContext input; input.registers["sp"]=le(0xb000); input.registers["lr"]=le(0x123456);
    auto result=unwind_pe_frame(metadata,Architecture::arm64,0x100000,0x105004,input,memory({}));
    check(result && get(result.value(),"sp")==0xb010 && get(result.value(),"pc")==0x123456,
          "ARM64 linked pdata record applies parent xdata unwind recipe");
}
void arm64_save_next_and_extended_registers_use_supplied_sve_length() {
    PeMetadata metadata; PeArm64RuntimeFunction fn; fn.begin_rva=0x7000; fn.function_length=0x200;
    PeArm64Xdata x; x.unwind_codes={
        {0xe7,{0xe7,0x53,0x00},{}}, {0xe6,{0xe6},{}},
        {0xe7,{0xe7,0x00,0x83},{}}, {0xe7,{0xe7,0x00,0xc3},{}},
        {0xe7,{0xe7,0x10,0xc8},{}}, {0xe7,{0xe7,0x14,0xca},{}},
        {0xdf,{0xdf,0x01},{}}, {0xe4,{0xe4},{}}};
    fn.xdata=x; metadata.arm64_exception_functions.push_back(fn);
    PeRegisterContext input; input.registers["sp"]=le(0xb000); input.registers["lr"]=le(0x7788); input.registers["sve_vl"]=le(16);
    std::vector<std::byte> vector(16,std::byte{0xaa});
    auto vg_sm=le(0x8000000000000002ull);
    auto pred=le(0x1234,2);
    auto caller=unwind_pe_frame(metadata,Architecture::arm64,0x100000,0x107100,input,
        memory({{0xb000,le(0x19)},{0xb008,le(0x20)},{0xb010,le(0x21)},{0xb018,le(0x22)},
                {0xb030,vector},{0xb040,vg_sm},{0xb014,pred}}));
    check(caller && get(caller.value(),"x19")==0x19 && get(caller.value(),"x20")==0x20 &&
              get(caller.value(),"x21")==0x21 && get(caller.value(),"x22")==0x22 &&
              caller.value().registers.at("q0").size()==16 && caller.value().registers.at("z8").size()==16 &&
              caller.value().registers.at("p4").size()==2 && get(caller.value(),"sm")==1 &&
              get(caller.value(),"vg")==2 && get(caller.value(),"sp")==0xb010,
          "ARM64 save_next, Q/Z/P and VG/SM saves use supplied vector length and exact memory extents");
}
void arm64_remaining_fixed_width_save_and_alloc_families_are_executed() {
    auto unwind = [](std::vector<std::uint8_t> encoding, std::map<std::uint64_t,std::vector<std::byte>> bytes,
                     std::uint64_t expected_sp, std::initializer_list<std::pair<const char*,std::uint64_t>> expected) {
        PeMetadata metadata;PeArm64RuntimeFunction fn;fn.begin_rva=0x9000;fn.function_length=0x100;
        PeArm64Xdata x;x.unwind_codes.push_back({encoding[0],encoding,{}});fn.xdata=x;metadata.arm64_exception_functions.push_back(fn);
        PeRegisterContext input;input.registers["sp"]=le(0xd000);input.registers["fp"]=le(0xd100);input.registers["lr"]=le(0);
        auto result=unwind_pe_frame(metadata,Architecture::arm64,0x100000,0x109040,input,memory(std::move(bytes)));
        if(!result){check(false,"ARM64 fixed-width opcode unexpectedly failed");return;}
        check(get(result.value(),"sp")==expected_sp,"ARM64 fixed-width opcode restores expected stack pointer");
        for(const auto &[name,value]:expected)check(get(result.value(),name)==value,"ARM64 fixed-width opcode restores expected register");
    };
    const auto pair_memory=std::map<std::uint64_t,std::vector<std::byte>>{{0xd000,le(0x19)},{0xd008,le(0x20)}};
    unwind({0x20},pair_memory,0xd000,{{"x19",0x19},{"x20",0x20}}); // save_r19r20_x
    unwind({0x40},pair_memory,0xd000,{{"fp",0x19},{"lr",0x20}}); // save_fplr
    unwind({0x80},pair_memory,0xd008,{{"fp",0x19},{"lr",0x20}}); // save_fplr_x
    unwind({0xc0,0x01},{},0xd010,{}); // alloc_m
    unwind({0xe0,0x00,0x00,0x01},{},0xd010,{}); // alloc_l
    unwind({0xc8,0x00},pair_memory,0xd000,{{"x19",0x19},{"x20",0x20}}); // save_regp
    unwind({0xcc,0x00},pair_memory,0xd008,{{"x19",0x19},{"x20",0x20}}); // save_regp_x
    unwind({0xd0,0x00},pair_memory,0xd000,{{"x19",0x19}}); // save_reg
    unwind({0xd4,0x00},pair_memory,0xd008,{{"x19",0x19}}); // save_reg_x
    unwind({0xd6,0x00},pair_memory,0xd000,{{"x19",0x19},{"lr",0x20}}); // save_lrpair
    unwind({0xd8,0x00},pair_memory,0xd000,{{"d8",0x19},{"d9",0x20}}); // save_fregp
    unwind({0xda,0x00},pair_memory,0xd008,{{"d8",0x19},{"d9",0x20}}); // save_fregp_x
    unwind({0xdc,0x00},pair_memory,0xd000,{{"d8",0x19}}); // save_freg
    unwind({0xde,0x00},pair_memory,0xd008,{{"d8",0x19}}); // save_freg_x
}
void address_overflow_is_rejected() {
    PeMetadata metadata; PeRuntimeFunction fn; fn.begin_rva=0; fn.end_rva=16; fn.unwind_info=PeUnwindInfo{}; metadata.exception_functions.push_back(fn);
    PeRegisterContext context; context.registers["rsp"]=le(UINT64_MAX-3);
    auto result=unwind_pe_frame(metadata,Architecture::x86_64,0,8,context,memory({{UINT64_MAX-3,le(1)}}));
    check(!result,"overflowing caller stack address is rejected");
}
}
int main() {
    amd64_restores_stack_and_saved_registers_atomically();
    amd64_reports_short_reads_and_missing_registers();
    amd64_restores_vector_register_and_chained_frame();
    amd64_machine_frame_and_partial_prolog_are_bounded();
    arm64_packed_restores_frame_record();
    arm64_packed_restores_integer_fp_and_homed_layout();
    arm64_xdata_restores_nonvolatile_register_fplr_and_stack();
    arm64_xdata_alloc_and_unsupported_are_precise();
    arm64_pdata_link_uses_parent_unwind_record();
    arm64_save_next_and_extended_registers_use_supplied_sve_length();
    arm64_remaining_fixed_width_save_and_alloc_families_are_executed();
    address_overflow_is_rejected();
    return failures ? 1 : 0;
}
