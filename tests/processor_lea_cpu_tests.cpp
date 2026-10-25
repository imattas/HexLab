#include "hexlab/processors/decoder.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <cstdint>
using namespace hexlab;
using namespace hexlab_test;
extern "C" std::uint64_t hexlab_lea_gs_absolute();
extern "C" std::uint64_t hexlab_lea_gs_base(std::uint64_t);
int main(){return run([]{
    const auto absolute=hexlab_lea_gs_absolute();
    check(absolute==0x30,"self-authored GS-prefixed LEA computes an offset without segment base");
    const auto decoded=decode_x64(bytes({0x65,0x48,0x8d,0x04,0x25,0x30,0,0,0}),{{0},0x1000});
    check(decoded.instruction.has_value(),"GS-prefixed absolute LEA decodes");
    if(decoded.instruction){
        const auto& memory=std::get<MemoryOperand>(decoded.instruction->operands[1]);
        check(!memory.segment && memory.resolved_address==Address{{0},absolute},"decoded effective address agrees with independent CPU execution");
        check(decoded.instruction->register_reads.empty(),"LEA has no GS read dependency");
    }
    check(hexlab_lea_gs_base(0x1234)==0x1244,"based LEA ignores GS base");
    check(hexlab_lea_gs_base(UINT64_MAX-7)==8,"based LEA preserves 64-bit arithmetic wrapping");
});}
