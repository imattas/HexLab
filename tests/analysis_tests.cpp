#include "hexlab/analysis/analysis.hpp"
#include "hexlab/analysis/strings.hpp"
#include "hexlab/loaders/raw.hpp"
#include "support/checks.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <iostream>
#include <chrono>
using namespace hexlab;
using namespace hexlab_test;

class ReadCountingStorage final : public ByteStorage {
  public:
    explicit ReadCountingStorage(std::shared_ptr<const ByteStorage> source) : source_(std::move(source)) {}
    std::uint64_t size() const noexcept override { return source_->size(); }
    Result<ByteView> read_at(FileOffset offset, std::size_t count) const override {
        ++read_calls;
        requested_bytes += count;
        largest_request = std::max(largest_request, count);
        if (count <= 15)
            small_reads += 1;
        return source_->read_at(offset, count);
    }
    mutable std::size_t read_calls = 0, requested_bytes = 0, largest_request = 0, small_reads = 0;
  private:
    std::shared_ptr<const ByteStorage> source_;
};

std::shared_ptr<const Image> raw_image(const std::vector<std::byte>& data,bool executable=true) {
    FixtureFile file(data);
    return load_raw(FileStorage::open(file.path).value(),{Architecture::x86_64,ExecutionMode::x86_64,{{0},0x1000},true,false,executable,{}},{}).value();
}
std::shared_ptr<const Image> mips_image(const std::vector<std::byte>& data,
                                        std::vector<Address> entries={Address{{0},0x1000}}) {
    auto source=std::make_shared<MemoryStorage>(data); Address entry{{0},0x1000};
    ImageLayout layout{{{0},32,1,ByteOrder::little},Architecture::mips32,ExecutionMode::mips32,
        {{"mips",entry,data.size(),{0},data.size(),true,false,true}},std::move(entries)};
    return Image::create(source,std::move(layout)).value();
}
std::shared_ptr<const Image> riscv_image(const std::vector<std::byte> &data, bool rv32) {
    auto source = std::make_shared<MemoryStorage>(data);
    const Address entry{{0}, 0x1000};
    const auto architecture = rv32 ? Architecture::riscv32 : Architecture::riscv64;
    const auto mode = rv32 ? ExecutionMode::rv32 : ExecutionMode::rv64;
    ImageLayout layout{{{0}, static_cast<std::uint8_t>(rv32 ? 32 : 64), 1, ByteOrder::little}, architecture, mode,
                       {{"riscv", entry, data.size(), {0}, data.size(), true, false, true}}, {entry}};
    return Image::create(source, std::move(layout)).value();
}
std::set<std::uint64_t> visited(const AnalysisSnapshot& snapshot) {
    std::set<std::uint64_t> result;for(const auto& i:snapshot.instructions)result.insert(i.address.offset);return result;
}
bool stopped(const AnalysisSnapshot& snapshot,StopReason reason) {
    return std::any_of(snapshot.stops.begin(),snapshot.stops.end(),[&](const auto& stop){return stop.reason==reason;});
}
void reachable_tests() {
    auto result=analyze(*raw_image(bytes({0xeb,0xfe})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000} && result.code_complete,"loop visited once");
    result=analyze(*raw_image(bytes({0x74,3,0x90,0xeb,1,0x90,0xc3})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000,0x1002,0x1003,0x1005,0x1006},"branch diamond reachable starts");
    result=analyze(*raw_image(bytes({0xe8,1,0,0,0,0xc3,0x90,0xc3})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000,0x1005,0x1006,0x1007},"call target and fallthrough explored");
    check(result.candidates==std::vector<Address>{{{0},0x1000},{{0},0x1006}},"entry and call candidates explicit");
    result=analyze(*raw_image(bytes({0xeb,2,0x0f,0x0b,0xc3})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000,0x1004},"unreachable bytes are not code");
    result=analyze(*raw_image(bytes({0xff,0xe0,0xc3})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000} && !result.code_complete && stopped(result,StopReason::indirect),"indirect jump terminates proven flow");
    result=analyze(*raw_image(bytes({0xff,0xd0,0xc3})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000,0x1002} && !result.code_complete,"indirect call preserves fallthrough");
    result=analyze(*raw_image(bytes({0xc5,0xf8,0x77,0xc3})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000} && result.instructions.size()==1 &&
              result.instructions[0].opcode==Opcode::x86_opaque && !result.code_complete &&
              stopped(result,StopReason::unsupported),
          "opaque decode retains its boundary but analysis never invents fallthrough semantics");
    result=analyze(*raw_image(bytes({0xe8,1})),{},{}).value();
    check(result.instructions.empty() && stopped(result,StopReason::truncated),"truncated instruction terminates path");
    AnalysisOptions options;options.instruction_budget=1;
    result=analyze(*raw_image(bytes({0x90,0xc3})),options,{}).value();
    check(result.instructions.size()==1 && !result.code_complete && stopped(result,StopReason::budget),"instruction budget reports incomplete result");
    FixtureFile file(bytes({0x90}));auto storage=FileStorage::open(file.path).value();
    ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,
        {{"code",{{0},0x1000},2,{0},1,true,false,true}},{{{0},0x1000}}};
    result=analyze(*Image::create(storage,layout).value(),{},{}).value();
    check(result.instructions.size()==1 && stopped(result,StopReason::uninitialized),"zero-filled tail is not invented code");
    layout.segments[0].executable=false;
    result=analyze(*Image::create(storage,layout).value(),{},{}).value();
    check(result.instructions.empty() && stopped(result,StopReason::non_executable),"non-executable seed rejected");
    std::stop_source stop;stop.request_stop();
    check(analyze(*raw_image(bytes({0x90})),{},stop.get_token()).error().code==ErrorCode::canceled,"analysis cancellation");
}
void large_linear_analysis_cache_test() {
    constexpr std::size_t code_bytes = 256 * 1024;
    std::vector<std::byte> bytes(code_bytes + 1, std::byte{0x90});
    bytes.back() = std::byte{0xc3};
    FixtureFile file(std::move(bytes));
    auto backing = FileStorage::open(file.path).value();
    auto storage = std::make_shared<ReadCountingStorage>(backing);
    const Address entry{{0},0x100000};
    ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,
                       {{"large-linear",entry,storage->size(),{0},storage->size(),true,false,true}},{entry}};
    auto image = Image::create(storage,std::move(layout)).value();
    const auto begin = std::chrono::steady_clock::now();
    const auto snapshot = analyze(*image,{},{}).value();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - begin).count();
    check(snapshot.code_complete && snapshot.instructions.size() == storage->size() &&
              snapshot.instructions.back().opcode == Opcode::ret,
          "large linear image decodes every instruction through the return");
    check(storage->read_calls < 256 && storage->small_reads < 32 && storage->largest_request >= 4 * 1024 &&
              storage->requested_bytes < storage->size() * 16,
          "linear reachable analysis batches instruction backing reads into bounded windows");
    const auto old_code_reads = snapshot.instructions.size();
    const auto old_code_bytes = 105 + 15 * (snapshot.instructions.size() - 14);
    std::cout << "large-image analysis: " << snapshot.instructions.size() << " instructions, "
              << storage->read_calls << " backing reads (" << storage->small_reads
              << " <=15-byte reads), " << storage->requested_bytes << " requested bytes, " << elapsed
              << " ms; prior instruction fetch: " << old_code_reads << " reads / " << old_code_bytes << " bytes\n";

    std::vector<std::byte> guarded_bytes(32,std::byte{0x90});
    guarded_bytes[20] = std::byte{0xc3};
    auto guarded_storage = std::make_shared<MemoryStorage>(guarded_bytes);
    const Address guarded_entry{{0},0x3000};
    ImageLayout guarded_layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,
                               {{"guarded",guarded_entry,guarded_storage->size(),{0},guarded_storage->size(),true,false,true}},
                               {guarded_entry,{{0},0x300c}}};
    guarded_layout.code_exclusions.push_back({{{0},0x3008},4});
    const auto guarded = analyze(*Image::create(guarded_storage,std::move(guarded_layout)).value(),{},{}).value();
    check(guarded.instructions.size() == 17 && guarded.instructions.front().address == guarded_entry &&
              guarded.instructions[8].address == Address{{0},0x300c} &&
              std::any_of(guarded.stops.begin(),guarded.stops.end(),[](const auto &stop) {
                  return stop.address == Address{{0},0x3008} && stop.reason == StopReason::image_exclusion;
              }) && guarded.instructions.back().opcode == Opcode::ret,
          "bounded byte windows stop at exclusions and refill safely at a later executable root");
}
void mips_reachable_tests() {
    auto result=analyze(*mips_image(bytes({0x01,0x00,0x00,0x10,0x08,0x00,0x08,0x24,
                                            0x08,0x00,0xe0,0x03,0x00,0x00,0x00,0x00})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000,0x1004,0x1008,0x100c} &&
              std::any_of(result.edges.begin(),result.edges.end(),[](const auto& e){return e.kind==EdgeKind::delay_slot;}),
          "reachable MIPS branch traverses its slot and PC+8 successors");
    result=analyze(*mips_image(bytes({0x04,0x04,0x00,0x08,0x08,0x00,0x08,0x24,
                                      0x08,0x00,0xe0,0x03,0x00,0x00,0x00,0x00,
                                      0x08,0x00,0xe0,0x03})),{},{}).value();
    if (visited(result)!=std::set<std::uint64_t>{0x1000,0x1004,0x1010}) { std::cerr << "MIPS jump visited:"; for(auto a:visited(result)) std::cerr << ' ' << std::hex << a; std::cerr << '\n'; }
    check(visited(result)==std::set<std::uint64_t>{0x1000,0x1004,0x1010},
          "reachable MIPS jump does not invent a PC+8 fallthrough");
    result=analyze(*mips_image(bytes({0x03,0x04,0x00,0x0c,0x08,0x00,0x08,0x24,
                                      0x08,0x00,0xe0,0x03,0x00,0x00,0x00,0x00,
                                      0x08,0x00,0xe0,0x03,0x00,0x00,0x00,0x00})),{},{}).value();
    if (!(visited(result).contains(0x1004) && result.candidates==std::vector<Address>{{{0},0x1000},{{0},0x100c}})) { std::cerr << "MIPS call candidates:"; for(auto a:result.candidates) std::cerr << ' ' << std::hex << a.offset; std::cerr << " visited:"; for(auto a:visited(result)) std::cerr << ' ' << a; std::cerr << '\n'; }
    check(visited(result).contains(0x1004) && result.candidates==std::vector<Address>{{{0},0x1000},{{0},0x100c}},
          "reachable MIPS call includes slot and promotes only its direct callee");
    const auto slot_first=mips_image(bytes({0x01,0x00,0x08,0x24,0x01,0x00,0x00,0x10,
                                             0x08,0x00,0x09,0x24,0x08,0x00,0xe0,0x03,
                                             0x00,0x00,0x00,0x00}),{{{0},0x1000},{{0},0x1008}});
    result=analyze(*slot_first,{},{}).value();
    check(result.instructions.size()==5 && visited(result).size()==5 &&
              std::count_if(result.instructions.begin(),result.instructions.end(),[](const auto& i){return i.address.offset==0x1008;})==1,
          "reachable MIPS reuses a slot decoded from an earlier independent root");
    AnalysisOptions constrained; constrained.instruction_budget=3;
    result=analyze(*slot_first,constrained,{}).value();
    check(result.instructions.size()==3 && stopped(result,StopReason::budget),
          "reused MIPS delay slot does not consume the instruction budget twice");
    result=analyze(*mips_image(bytes({0x02,0x10,0x00,0x08,0x08,0x00,0xe0,0x03})),{},{}).value();
    check(visited(result)==std::set<std::uint64_t>{0x1000} && stopped(result,StopReason::unsupported),
          "reachable MIPS slot control transfer is rejected");
}
std::shared_ptr<const Image> mixed_arm_image(std::vector<std::byte> code, bool thumb_root_clear = true,
                                             ArmCodeKind thumb_kind = ArmCodeKind::thumb) {
    auto source = std::make_shared<MemoryStorage>(std::move(code));
    const Address base{{0}, 0x1000};
    const ArmContextSource raw{ArmContextSourceKind::raw_declaration, 1, 1, {}};
    ImageLayout layout{{{0}, 32, 1, ByteOrder::little}, Architecture::arm, ExecutionMode::unknown,
                       {{"arm-code", base, source->size(), {0}, source->size(), true, false, true}}, {base}};
    std::vector<ArmCodeRoot> roots{{base, ExecutionMode::a32, false, {raw}}};
    if (thumb_kind == ArmCodeKind::thumb)
        roots.push_back({Address{{0}, 0x1008}, ExecutionMode::thumb, thumb_root_clear, {raw}});
    std::vector<ArmCodeRange> ranges{{base, 8, ArmCodeKind::a32, {raw}}};
    ranges.push_back({Address{{0}, 0x1008}, source->size() - 8, thumb_kind, {raw}});
    layout.arm_profile = ArmImageProfile{std::move(ranges), std::move(roots)};
    return Image::create(source, std::move(layout)).value();
}
void mixed_arm_reachable_tests() {
    // BLX from A32 at 0x1000 calls Thumb at 0x1008. The caller's A32 return
    // continuation remains independent, and each state is taken from the
    // address-bound image profile.
    const auto image = mixed_arm_image(bytes({0x00, 0x00, 0x00, 0xfa, 0x1e, 0xff, 0x2f, 0xe1,
                                              0x08, 0xbf, 0x00, 0x20, 0x70, 0x47}));
    const auto result = analyze(*image, {}, {}).value();
    std::map<std::uint64_t, ExecutionMode> modes;
    for (const auto &instruction : result.instructions)
        modes[instruction.address.offset] = instruction.context.mode;
    check(modes == std::map<std::uint64_t, ExecutionMode>{{0x1000, ExecutionMode::a32},
                                                          {0x1004, ExecutionMode::a32},
                                                          {0x1008, ExecutionMode::thumb},
                                                          {0x100a, ExecutionMode::thumb},
                                                          {0x100c, ExecutionMode::thumb}} &&
              result.code_complete,
          "reachable ARM follows declared A32-to-Thumb call and preserves both mode-specific continuations");
    check(result.candidates == std::vector<Address>{{{0}, 0x1000}, {{0}, 0x1008}} &&
              std::any_of(result.edges.begin(), result.edges.end(), [](const auto &edge) {
                  return edge.from == Address{{0}, 0x1000} && edge.to == Address{{0}, 0x1008} &&
                         edge.kind == EdgeKind::call;
              }),
          "only a state-validated direct ARM call target is promoted as a function candidate");
    const auto it_body = std::find_if(result.instructions.begin(), result.instructions.end(),
                                      [](const auto &instruction) { return instruction.address.offset == 0x100a; });
    check(it_body != result.instructions.end() && it_body->arm && it_body->arm->predicate == ArmPredicate::condition &&
              it_body->arm->it_before == ThumbITState{true, 0x08} &&
              it_body->arm->it_after == ThumbITState{true, 0},
          "Thumb IT state propagates across instructions and clears after the block");

    auto reverse_storage = std::make_shared<MemoryStorage>(bytes({0x00, 0xf0, 0x02, 0xe8, 0x70, 0x47,
                                                                  0x00, 0xbf, 0x00, 0xf0, 0x20, 0xe3,
                                                                  0x1e, 0xff, 0x2f, 0xe1}));
    const Address reverse_entry{{0}, 0x1000};
    const ArmContextSource reverse_raw{ArmContextSourceKind::raw_declaration, 2, 1, {}};
    ImageLayout reverse_layout{{{0}, 32, 1, ByteOrder::little}, Architecture::arm, ExecutionMode::unknown,
                               {{"mixed", reverse_entry, 16, {0}, 16, true, false, true}}, {reverse_entry}};
    reverse_layout.arm_profile = ArmImageProfile{
        {{reverse_entry, 8, ArmCodeKind::thumb, {reverse_raw}},
         {Address{{0}, 0x1008}, 8, ArmCodeKind::a32, {reverse_raw}}},
        {{reverse_entry, ExecutionMode::thumb, true, {reverse_raw}}}};
    const auto reverse_image = Image::create(reverse_storage, std::move(reverse_layout)).value();
    const auto reverse = analyze(*reverse_image, {}, {}).value();
    modes.clear();
    for (const auto &instruction : reverse.instructions)
        modes[instruction.address.offset] = instruction.context.mode;
    check(modes == std::map<std::uint64_t, ExecutionMode>{{0x1000, ExecutionMode::thumb},
                                                          {0x1004, ExecutionMode::thumb},
                                                          {0x1008, ExecutionMode::a32},
                                                          {0x100c, ExecutionMode::a32}} &&
              reverse.code_complete,
          "reachable ARM follows declared Thumb-to-A32 call while preserving the Thumb continuation");

    auto unknown_storage = std::make_shared<MemoryStorage>(bytes({0x00, 0x20, 0x70, 0x47}));
    const Address thumb_entry{{0}, 0x1000};
    const ArmContextSource raw{ArmContextSourceKind::raw_declaration, 1, 1, {}};
    ImageLayout unknown_layout{{{0}, 32, 1, ByteOrder::little}, Architecture::arm, ExecutionMode::unknown,
                               {{"thumb", thumb_entry, 4, {0}, 4, true, false, true}}, {thumb_entry}};
    unknown_layout.arm_profile = ArmImageProfile{
        {{thumb_entry, 4, ArmCodeKind::thumb, {raw}}},
        {{thumb_entry, ExecutionMode::thumb, false, {raw}}}};
    const auto unknown_it = Image::create(unknown_storage, std::move(unknown_layout)).value();
    const auto conservative = analyze(*unknown_it, {}, {}).value();
    check(std::none_of(conservative.instructions.begin(), conservative.instructions.end(),
                       [](const auto &instruction) { return instruction.context.mode == ExecutionMode::thumb; }) &&
              !conservative.code_complete && stopped(conservative, StopReason::unsupported),
          "Thumb roots without known-clear IT state stop without inventing predicates");

    const auto wrong_mode = mixed_arm_image(bytes({0x00, 0x00, 0x00, 0xfa, 0x1e, 0xff, 0x2f, 0xe1,
                                                   0x00, 0x20, 0x70, 0x47}), true, ArmCodeKind::a32);
    const auto rejected = analyze(*wrong_mode, {}, {}).value();
    check(std::none_of(rejected.instructions.begin(), rejected.instructions.end(),
                       [](const auto &instruction) { return instruction.address.offset >= 0x1008; }) &&
              !rejected.code_complete && stopped(rejected, StopReason::unsupported),
          "declared target-state conflicts stop before decoding bytes in a contradictory mode");
}
void riscv_pc_relative_calls_test() {
    const auto image = [&](bool rv32) {
        return riscv_image(bytes({0x97, 0x02, 0x00, 0x00, // auipc x5, 0
                                  0x93, 0x82, 0x02, 0x01, // addi x5, x5, 16
                                  0xe7, 0x80, 0x02, 0x00, // jalr x1, 0(x5)
                                  0x67, 0x80, 0x00, 0x00, // ret (caller continuation)
                                  0x67, 0x80, 0x00, 0x00}), // ret (callee)
                           rv32);
    };
    for (const bool rv32 : {true, false}) {
        const auto result = analyze(*image(rv32), {}, {}).value();
        check(visited(result) == std::set<std::uint64_t>{0x1000, 0x1004, 0x1008, 0x100c, 0x1010} &&
                  std::any_of(result.edges.begin(), result.edges.end(), [](const auto &edge) {
                      return edge.from == Address{{0}, 0x1008} && edge.to == Address{{0}, 0x1010} &&
                             edge.kind == EdgeKind::call;
                  }) &&
                  std::find(result.candidates.begin(), result.candidates.end(), Address{{0}, 0x1010}) !=
                      result.candidates.end() &&
                  result.code_complete,
              rv32 ? "RV32 analysis resolves AUIPC/ADDI/JALR into a call and discovers its callee"
                   : "RV64 analysis resolves AUIPC/ADDI/JALR into a call and discovers its callee");

        const auto direct = riscv_image(bytes({0x97, 0x02, 0x00, 0x00, // auipc x5, 0
                                               0xe7, 0x80, 0xc2, 0x00, // jalr x1, 12(x5)
                                               0x67, 0x80, 0x00, 0x00, // ret (continuation)
                                               0x67, 0x80, 0x00, 0x00}),
                                         rv32);
        const auto direct_result = analyze(*direct, {}, {}).value();
        check(std::any_of(direct_result.edges.begin(), direct_result.edges.end(), [](const auto &edge) {
                  return edge.from == Address{{0}, 0x1004} && edge.to == Address{{0}, 0x100c} &&
                         edge.kind == EdgeKind::call;
              }),
              rv32 ? "RV32 analysis resolves direct AUIPC/JALR call sequences"
                   : "RV64 analysis resolves direct AUIPC/JALR call sequences");
    }
}
void a32_conditional_return_test() {
    auto source = std::make_shared<MemoryStorage>(bytes({0x1e, 0xff, 0x2f, 0x11, 0x1e, 0xff, 0x2f, 0xe1}));
    const Address base{{0}, 0x1000};
    const ArmContextSource raw{ArmContextSourceKind::raw_declaration, 1, 1, {}};
    ImageLayout layout{{{0}, 32, 1, ByteOrder::little}, Architecture::arm, ExecutionMode::unknown,
                       {{"a32-code", base, source->size(), {0}, source->size(), true, false, true}}, {base}};
    layout.arm_profile = ArmImageProfile{{{base, source->size(), ArmCodeKind::a32, {raw}}},
                                         {{base, ExecutionMode::a32, false, {raw}}}};
    const auto result = analyze(*Image::create(source, std::move(layout)).value(), {}, {}).value();
    check(visited(result) == std::set<std::uint64_t>{0x1000, 0x1004} && stopped(result, StopReason::ret) &&
              std::any_of(result.edges.begin(), result.edges.end(), [](const auto &edge) {
                  return edge.from == Address{{0}, 0x1000} && edge.to == Address{{0}, 0x1004} &&
                         edge.kind == EdgeKind::fallthrough;
              }),
          "reachable A32 conditional return preserves its return and condition-false continuation");

    auto conditional_trap = std::make_shared<MemoryStorage>(bytes({0x23, 0x01, 0x00, 0x1f,
                                                                   0x1e, 0xff, 0x2f, 0xe1}));
    ImageLayout trap_layout{{{0}, 32, 1, ByteOrder::little}, Architecture::arm, ExecutionMode::a32,
                            {{"a32-conditional-trap", base, conditional_trap->size(), {0},
                              conditional_trap->size(), true, false, true}}, {base}};
    const auto trap_result = analyze(*Image::create(conditional_trap, std::move(trap_layout)).value(), {}, {}).value();
    check(visited(trap_result) == std::set<std::uint64_t>{0x1000, 0x1004} && stopped(trap_result, StopReason::trap) &&
              std::any_of(trap_result.edges.begin(), trap_result.edges.end(), [](const auto &edge) {
                  return edge.from == Address{{0}, 0x1000} && edge.to == Address{{0}, 0x1004} &&
                         edge.kind == EdgeKind::fallthrough;
              }),
          "reachable conditional A32 SVC retains the condition-false continuation beside its trap edge");
}
void a32_computed_pc_interworking_test() {
    // ADD pc, pc, #1 computes 0x1009 from architectural PC+8. The physical
    // target is 0x1008 (Thumb), while 0x1004..0x1007 is explicitly data.
    auto storage = std::make_shared<MemoryStorage>(bytes({0x01, 0xf0, 0x8f, 0xe2,
                                                          0x00, 0x00, 0x00, 0x00,
                                                          0x70, 0x47}));
    const Address a32{{0}, 0x1000}, thumb{{0}, 0x1008};
    const ArmContextSource raw{ArmContextSourceKind::raw_declaration, 1, 1, {}};
    ImageLayout layout{{{0}, 32, 1, ByteOrder::little}, Architecture::arm, ExecutionMode::unknown,
                       {{"mixed", a32, storage->size(), {0}, storage->size(), true, false, true}}, {a32}};
    layout.arm_profile = ArmImageProfile{
        {{a32, 4, ArmCodeKind::a32, {raw}},
         {Address{{0}, 0x1004}, 4, ArmCodeKind::data, {raw}},
         {thumb, 2, ArmCodeKind::thumb, {raw}}},
        {{a32, ExecutionMode::a32, false, {raw}}, {thumb, ExecutionMode::thumb, true, {raw}}}};
    const auto image = Image::create(storage, std::move(layout)).value();
    const auto result = analyze(*image, {}, {}).value();
    const auto edge = std::find_if(result.edges.begin(), result.edges.end(), [&](const auto &candidate) {
        return candidate.from == a32 && candidate.to == thumb && candidate.kind == EdgeKind::branch;
    });
    check(result.instructions.size() == 2 && edge != result.edges.end() &&
              result.instructions.front().arm->target_mode == ExecutionMode::thumb && result.code_complete,
          "profile-backed computed A32 PC target traverses to the canonical Thumb physical address");
}
const StringRecord* find(const StringScan& scan,StringEncoding encoding,std::uint64_t offset) {
    for(const auto& s:scan.records)if(s.encoding==encoding&&s.file_offset.value==offset)return &s;return nullptr;
}
void string_tests() {
    auto scan=find_strings(*raw_image(bytes({'A','B','C','D',0,'a','b','c',0}),false),{},{}).value();
    const auto* s=find(scan,StringEncoding::ascii,0);
    check(s && s->preview=="ABCD" && s->characters==4 && s->byte_length==4 && s->terminated,"ASCII minimum and terminator");
    check(!find(scan,StringEncoding::ascii,5),"short ASCII run below minimum");
    scan=find_strings(*raw_image(bytes({'A',0,'B',0,'C',0,'D',0,0,0}),false),{},{}).value();
    s=find(scan,StringEncoding::utf16le,0);
    check(s && s->preview=="ABCD" && s->characters==4 && s->byte_length==8 && s->terminated,"UTF16 string extent");
    scan=find_strings(*raw_image(bytes({'A',0,0x3d,0xd8,0,0xde,'B',0,'C',0,0,0}),false),{},{}).value();
    s=find(scan,StringEncoding::utf16le,0);
    check(s && s->characters==4 && s->byte_length==10 && s->preview==std::string("A")+"\xf0\x9f\x98\x80"+"BC","surrogate pair is one scalar character");
    scan=find_strings(*raw_image(bytes({'A',0,0,0xd8,'B',0,'C',0,'D',0,0,0}),false),{},{}).value();
    check(!find(scan,StringEncoding::utf16le,0),"invalid surrogate breaks candidate");
    scan=find_strings(*raw_image(bytes({0xc3,0xa9,0x20,0xe4,0xb8,0x96,0x20,0xf0,0x9f,0x8c,0x8d,0}),false),{},{}).value();
    s=find(scan,StringEncoding::utf8,0);
    check(s && s->preview=="\xc3\xa9 \xe4\xb8\x96 \xf0\x9f\x8c\x8d" && s->characters==5 && s->byte_length==11 && s->terminated,
          "strict UTF-8 scan counts Unicode scalars and preserves UTF-8 preview");
    scan=find_strings(*raw_image(bytes({0xc0,0xaf,'A','B','C','D',0}),false),{},{}).value();
    check(!find(scan,StringEncoding::utf8,0),"overlong UTF-8 sequences cannot join printable candidates");
    scan=find_strings(*raw_image(bytes({0, 'A',0,'B',0,'C',0,'D',0,0}),false),{},{}).value();
    s=find(scan,StringEncoding::utf16be,0);
    check(s && s->preview=="ABCD" && s->characters==4 && s->byte_length==8 && s->terminated,
          "UTF-16BE scan records aligned byte extent and terminator");
    scan=find_strings(*raw_image(bytes({0,0,0,'A',0,0,0,'B',0,0,0,'C',0,0,0,'D',0,0,0,0}),false),{},{}).value();
    s=find(scan,StringEncoding::utf32be,0);
    check(s && s->preview=="ABCD" && s->characters==4 && s->byte_length==16 && s->terminated,
          "UTF-32BE scan records aligned byte extent and terminator");
    scan=find_strings(*raw_image(bytes({'A',0,0,0,'B',0,0,0,'C',0,0,0,'D',0,0,0,0,0,0,0}),false),{},{}).value();
    s=find(scan,StringEncoding::utf32le,0);
    check(s && s->preview=="ABCD" && s->characters==4 && s->byte_length==16 && s->terminated,
          "UTF-32LE scan records aligned byte extent and terminator");
    scan=find_strings(*raw_image(bytes({'A','B','C','D'}),false),{},{}).value();
    check(find(scan,StringEncoding::ascii,0) && !find(scan,StringEncoding::ascii,0)->terminated,"range-ended string distinguished");
    std::vector<std::byte> chunked(65544);const auto hello=bytes({'H','E','L','L','O',0});std::copy(hello.begin(),hello.end(),chunked.begin()+65534);
    scan=find_strings(*raw_image(chunked,false),{},{}).value();s=find(scan,StringEncoding::ascii,65534);
    check(s && s->preview=="HELLO" && s->terminated,"ASCII spans storage chunk boundary");
    chunked.assign(65550,std::byte{0});const auto wide=bytes({0x3d,0xd8,0,0xde,'A',0,'B',0,'C',0,0,0});std::copy(wide.begin(),wide.end(),chunked.begin()+65534);
    scan=find_strings(*raw_image(chunked,false),{},{}).value();s=find(scan,StringEncoding::utf16le,65534);
    check(s && s->characters==4 && s->byte_length==10,"surrogate pair spans chunk boundary");
    chunked.assign(65560,std::byte{0});const auto wide_be=bytes({0,'A',0,'B',0,'C',0,'D',0,0});std::copy(wide_be.begin(),wide_be.end(),chunked.begin()+65534);
    scan=find_strings(*raw_image(chunked,false),{},{}).value();s=find(scan,StringEncoding::utf16be,65534);
    check(s && s->preview=="ABCD" && s->terminated,"UTF-16BE text spans chunk boundary");
    chunked.assign(65552,std::byte{0});const auto scalar_be=bytes({0,0,0,'A',0,0,0,'B',0,0,0,'C',0,0,0,'D',0,0,0,0});std::copy(scalar_be.begin(),scalar_be.end(),chunked.begin()+65532);
    scan=find_strings(*raw_image(chunked,false),{},{}).value();s=find(scan,StringEncoding::utf32be,65532);
    check(s && s->preview=="ABCD" && s->terminated,"UTF-32BE text spans chunk boundary");
    std::vector<std::byte> long_run(1025,std::byte{'A'});long_run.back()=std::byte{0};
    scan=find_strings(*raw_image(long_run,false),{},{}).value();s=find(scan,StringEncoding::ascii,0);
    check(s && s->characters==1024 && s->preview.size()==256,"large run has bounded preview and full extent");
    FixtureFile file(bytes({'A','B','C','D'}));auto storage=FileStorage::open(file.path).value();
    ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,
        {{"left",{{0},0x1000},2,{0},2,true,false,false},{"right",{{0},0x2000},2,{2},2,true,false,false}}, {}};
    scan=find_strings(*Image::create(storage,layout).value(),{},{}).value();
    check(!find(scan,StringEncoding::ascii,0),"string cannot bridge virtual gap between adjacent file ranges");
    layout.segments.clear();scan=find_strings(*Image::create(storage,layout).value(),{},{}).value();s=find(scan,StringEncoding::ascii,0);
    check(s && !s->address,"overlay string has no fabricated address");
    AnalysisOptions options;options.string_budget=1;
    scan=find_strings(*raw_image(bytes({'A','B','C','D',0,'E','F','G','H',0}),false),options,{}).value();
    check(scan.records.size()==1 && !scan.complete && !scan.diagnostics.empty(),"string budget retains partial result");
    options.min_string_characters=0;check(!find_strings(*raw_image(bytes({0}),false),options,{}),"zero minimum rejected");
    std::stop_source stop;stop.request_stop();check(find_strings(*raw_image(bytes({0}),false),{},stop.get_token()).error().code==ErrorCode::canceled,"string cancellation");
}
class ShortReadStorage final:public ByteStorage {
public:
    uint64_t size()const noexcept override{return 8;}
    Result<ByteView> read_at(FileOffset,size_t)const override{return ByteView{};}
};
void short_read_tests(){
    auto source=std::make_shared<ShortReadStorage>();ImageLayout layout{{{0},64,1,ByteOrder::little},Architecture::x86_64,ExecutionMode::x86_64,{}, {}};auto image=Image::create(source,layout).value();auto result=find_strings(*image,{},{});check(!result && result.error().code==ErrorCode::io,"short successful storage reads become checked string-scan I/O errors");
}
int main() {return run([]{reachable_tests();large_linear_analysis_cache_test();mips_reachable_tests();mixed_arm_reachable_tests();riscv_pc_relative_calls_test();a32_conditional_return_test();a32_computed_pc_interworking_test();string_tests();short_read_tests();});}
