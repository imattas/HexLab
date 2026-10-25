#include "debugger_locals.hpp"

#include "hexlab/analysis/functions.hpp"
#include "hexlab/loaders/elf_unwind.hpp"

#include <iostream>
#include <unordered_map>
#include <unordered_map>
#include <stdexcept>

using namespace hexlab;
using namespace hexlab::desktop;

namespace {
class TestStorage final : public ByteStorage {
  public:
    std::uint64_t size() const noexcept override { return 0x100; }
    Result<ByteView> read_at(FileOffset, std::size_t) const override {
        return ByteView{std::make_shared<int>(1), {}};
    }
};

void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}
}

int main() {
    try {
        const Address entry{{0}, 0x401000};
        ImageLayout layout;
        layout.space = {{0}, 64, 1, ByteOrder::little};
        layout.architecture = Architecture::x86_64;
        layout.mode = ExecutionMode::x86_64;
        layout.segments.push_back({"text", entry, 0x100, {0}, 0x100, true, false, true});
        auto created = Image::create(std::make_shared<TestStorage>(), std::move(layout));
        require(created.has_value(), "synthetic debug image creation failed");

        auto state = std::make_shared<database::ProjectState>();
        auto user = std::make_shared<database::UserState>();
        const auto u64 = types::Type::integer("u64", 8, 8, false);
        const auto u8 = types::Type::integer("u8", 1, 1, false);
        require(u64 && u8, "test scalar types create successfully");
        user->types.push_back({64, "u64", u64.value()});
        user->types.push_back({8, "u8", u8.value()});
        const auto blob16 = types::Type::integer("blob16", 16, 16, false);
        require(blob16.has_value(), "test 128-bit storage type creates successfully");
        user->types.push_back({128, "blob16", blob16.value()});
        database::DebugVariable parameter;
        parameter.id = 1; parameter.function_entry = entry; parameter.name = "arg"; parameter.is_parameter = true;
        parameter.type_id = 64;
        parameter.location_ranges.push_back({0x401000, 0x401100, {}, {{
            static_cast<std::uint8_t>(symbols::LocationOperationKind::register_location), 0, 0, 0, 0}}});
        user->debug_variables.push_back(parameter);
        database::DebugVariable local;
        local.id = 2; local.function_entry = entry; local.name = "counter";
        local.type_id = 8;
        local.location_ranges.push_back({0x401020, 0x401030, {}, {{
            static_cast<std::uint8_t>(symbols::LocationOperationKind::address), 0x500100, 0, 0, 0}}});
        user->debug_variables.push_back(local);
        database::DebugVariable wide_local;
        wide_local.id = 4; wide_local.function_entry = entry; wide_local.name = "wide_counter";
        wide_local.type_id = 128;
        wide_local.location_operations.push_back({
            static_cast<std::uint8_t>(symbols::LocationOperationKind::address), 0x500200, 0, 0, 0});
        user->debug_variables.push_back(wide_local);
        database::DebugVariable wide_register_local;
        wide_register_local.id = 5; wide_register_local.function_entry = entry; wide_register_local.name = "wide_register";
        wide_register_local.type_id = 128;
        wide_register_local.location_operations.push_back({
            static_cast<std::uint8_t>(symbols::LocationOperationKind::register_location), 0, 0, 0, 0});
        user->debug_variables.push_back(wide_register_local);
        database::DebugVariable expired;
        expired.id = 3; expired.function_entry = entry; expired.name = "expired";
        expired.location_ranges.push_back({0x401010, 0x401020, {}, {{
            static_cast<std::uint8_t>(symbols::LocationOperationKind::unsigned_constant), 7, 0, 0, 0}}});
        user->debug_variables.push_back(expired);
        state->user = user;

        auto functions = std::make_shared<FunctionSnapshot>();
        auto function = std::make_shared<FunctionRecord>();
        function->id = {1}; function->entry = entry;
        function->chunks.push_back({entry, 0x100, {}});
        functions->functions.push_back(function);
        ProjectSnapshot project;
        project.state = state;
        project.functions = functions;

        debugger::RegisterValue rax;
        rax.name = "RAX"; rax.bytes.resize(8);
        rax.bytes[0] = std::byte{0x34}; rax.bytes[1] = std::byte{0x12};
        std::vector<debugger::RegisterValue> registers{rax};
        const auto rows = debugger_locals_at(project, *created.value(), 0x700025, 0x700000,
            Architecture::x86_64, registers, [](std::uint64_t address, std::size_t count) -> Result<std::vector<std::byte>> {
                if (address == 0x500200) {
                    if (count != 16) return Error{ErrorCode::io, "wide variable read has incorrect size"};
                    std::vector<std::byte> bytes(count);
                    for (std::size_t i = 0; i < count; ++i) bytes[i] = std::byte(i + 1);
                    return bytes;
                }
                if (address != 0x500100) return Error{ErrorCode::io, "unexpected read address"};
                std::vector<std::byte> bytes(count, std::byte{0});
                if (count) bytes[0] = std::byte{0x5A};
                return bytes;
            });
        require(rows.size() == 4, "PC-scoped DWARF rows include only live locals and parameters");
        require(rows[0].name == "arg" && rows[0].kind == "parameter" &&
                    rows[0].location == "DWARF register 0" && rows[0].value == "0x1234",
                "native x86-64 register names map to DWARF register values");
        require(rows[1].name == "counter" && rows[1].location == "memory 0x500100" &&
                    rows[1].value == "0x5A",
                "address expressions resolve and display the stopped process memory value");
        require(rows[2].name == "wide_counter" && rows[2].location == "memory 0x500200" &&
                    rows[2].value == "bytes[16] 0x0102030405060708090A0B0C0D0E0F10",
                "wide imported variables display bounded type-sized bytes instead of an unknown-size placeholder");
        require(rows[3].name == "wide_register" && rows[3].location == "DWARF register 0" &&
                    rows[3].value == "<register too small>",
                "wide register-backed variables never over-read a narrower machine register");
        const auto outside = debugger_locals_at(project, *created.value(), 0x700040, 0x700000,
            Architecture::x86_64, registers, {});
        require(outside.size() == 3 && outside[0].name == "arg" && outside[1].name == "wide_counter" &&
                    outside[2].name == "wide_register",
                "location-list rows expire at their half-open PC boundary");

        PeMetadata pe_unwind;
        PeRuntimeFunction pe_function;
        pe_function.begin_rva = 0x20; pe_function.end_rva = 0x100;
        pe_function.unwind_info = PeUnwindInfo{};
        pe_function.unwind_info->size_of_prolog = 4;
        pe_function.unwind_info->operations.push_back({PeUnwindOperationKind::allocate_stack, 1, 0, 32});
        pe_unwind.exception_functions.push_back(pe_function);
        std::vector<debugger::RegisterValue> pe_live;
        for (const auto &[name, value] : std::vector<std::pair<std::string, std::uint64_t>>{
                 {"RIP", 0x700025}, {"RSP", 0x701000}, {"RBX", 0x1234}}) {
            debugger::RegisterValue reg;
            reg.name = name; reg.bytes.resize(8); reg.byte_order = ByteOrder::little;
            for (unsigned i = 0; i < 8; ++i) reg.bytes[i] = std::byte((value >> (8 * i)) & 0xff);
            pe_live.push_back(std::move(reg));
        }
        const auto pe_frames = debugger_stack_frames_at(*created.value(), 0x700025, 0x700000,
            0x1000, Architecture::x86_64, pe_live, nullptr,
            [](std::uint64_t address, std::size_t count) -> Result<std::vector<std::byte>> {
                if (address != 0x701020 || count != 8) return Error{ErrorCode::io, "unexpected PE unwind read"};
                std::vector<std::byte> bytes(8);
                const std::uint64_t value = 0x700055;
                for (unsigned i = 0; i < 8; ++i) bytes[i] = std::byte((value >> (8 * i)) & 0xff);
                return bytes;
            }, 64, 0x401000, nullptr, &pe_unwind);
        require(pe_frames.size() == 2 && pe_frames[0].call_frame_cfa == 0x701028 &&
                    pe_frames[1].runtime_pc == 0x700055,
                "PE AMD64 unwind recipe produces a bounded selectable frame and CFA");
        const auto pe_rbx = std::find_if(pe_frames[1].registers.begin(), pe_frames[1].registers.end(),
            [](const auto &reg) { return reg.name == "RBX"; });
        std::uint64_t pe_rbx_value = 0;
        if (pe_rbx != pe_frames[1].registers.end())
            for (std::size_t i = 0; i < pe_rbx->bytes.size() && i < 8; ++i)
                pe_rbx_value |= std::uint64_t(std::to_integer<std::uint8_t>(pe_rbx->bytes[i])) << (8 * i);
        require(pe_rbx != pe_frames[1].registers.end() && pe_rbx_value == 0x1234,
                "PE caller registers are exposed in the selected frame context");
        const auto pe_outside_module = debugger_stack_frames_at(*created.value(), 0x700025, 0x700000,
            0x1000, Architecture::x86_64, pe_live, nullptr,
            [](std::uint64_t, std::size_t count) -> Result<std::vector<std::byte>> {
                std::vector<std::byte> bytes(count);
                const std::uint64_t value = 0x800000;
                for (unsigned i = 0; i < 8; ++i) bytes[i] = std::byte((value >> (8 * i)) & 0xff);
                return bytes;
            }, 64, 0x401000, nullptr, &pe_unwind);
        require(pe_outside_module.size() == 1 && pe_outside_module[0].call_frame_cfa == 0x701028,
                "PE caller walk keeps the recovered CFA but does not add an out-of-module return PC");
        user->debug_variables.clear();
        database::DebugVariable pe_cfa_local;
        pe_cfa_local.id = 5; pe_cfa_local.function_entry = entry; pe_cfa_local.name = "pe_cfa_local";
        pe_cfa_local.type_id = 8;
        pe_cfa_local.location_operations.push_back({
            static_cast<std::uint8_t>(symbols::LocationOperationKind::call_frame_cfa), 0, 0, 0, 0});
        user->debug_variables.push_back(pe_cfa_local);
        const auto pe_caller_rows = debugger_locals_at(project, *created.value(), pe_frames[0].runtime_pc,
            0x700000, Architecture::x86_64, pe_frames[0].registers, {}, pe_frames[0].call_frame_cfa);
        require(pe_caller_rows.size() == 1 && pe_caller_rows[0].location == "memory 0x701028",
                "PE caller CFA is available to the frame-scoped local evaluator");

        PeMetadata pe_arm64_unwind;
        PeArm64RuntimeFunction pe_arm64_function;
        pe_arm64_function.begin_rva = 0x20; pe_arm64_function.function_length = 0xe0;
        pe_arm64_function.kind = PeArm64UnwindKind::packed_single;
        pe_arm64_function.packed_unwind = PeArm64PackedUnwind{4, 0, 0, 3, false, 4};
        pe_arm64_unwind.arm64_exception_functions.push_back(pe_arm64_function);
        std::vector<debugger::RegisterValue> pe_arm64_live;
        for (const auto &[name, value] : std::vector<std::pair<std::string, std::uint64_t>>{
                 {"PC", 0x700025}, {"SP", 0x8000}, {"X29", 0x1111}, {"X30", 0x2222}, {"X19", 0x1919}}) {
            debugger::RegisterValue reg;
            reg.name = name; reg.bytes.resize(8); reg.byte_order = ByteOrder::little;
            for (unsigned i = 0; i < 8; ++i) reg.bytes[i] = std::byte((value >> (8 * i)) & 0xff);
            pe_arm64_live.push_back(std::move(reg));
        }
        const auto pe_arm64_frames = debugger_stack_frames_at(*created.value(), 0x700025, 0x700000,
            0x1000, Architecture::arm64, pe_arm64_live, nullptr,
            [](std::uint64_t address, std::size_t count) -> Result<std::vector<std::byte>> {
                const auto value = address == 0x8000 ? 0x3333ULL : address == 0x8008 ? 0x700066ULL : 0ULL;
                std::vector<std::byte> bytes(count);
                for (std::size_t i = 0; i < count && i < 8; ++i) bytes[i] = std::byte((value >> (8 * i)) & 0xff);
                return bytes;
            }, 64, 0x401000, nullptr, &pe_arm64_unwind);
        require(pe_arm64_frames.size() == 2 && pe_arm64_frames[0].call_frame_cfa == 0x8040 &&
                    pe_arm64_frames[1].runtime_pc == 0x700066,
                "PE ARM64 frame recipe recovers caller PC and stack CFA");
        const auto pe_arm64_fp = std::find_if(pe_arm64_frames[1].registers.begin(), pe_arm64_frames[1].registers.end(),
            [](const auto &reg) { return reg.name == "FP"; });
        const auto pe_arm64_x19 = std::find_if(pe_arm64_frames[1].registers.begin(), pe_arm64_frames[1].registers.end(),
            [](const auto &reg) { return reg.name == "X19"; });
        auto read_register = [](const debugger::RegisterValue &reg) {
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < reg.bytes.size() && i < 8; ++i)
                value |= std::uint64_t(std::to_integer<std::uint8_t>(reg.bytes[i])) << (8 * i);
            return value;
        };
        require(pe_arm64_fp != pe_arm64_frames[1].registers.end() && read_register(*pe_arm64_fp) == 0x3333 &&
                    pe_arm64_x19 != pe_arm64_frames[1].registers.end() && read_register(*pe_arm64_x19) == 0x1919,
                "PE ARM64 aliases frame-pointer registers and preserves the saved caller GPR bank");

        MachOMetadata unwind;
        MachOSlice unwind_slice;
        unwind_slice.header.cpu_type = 0x01000007u;
        unwind.container.slices.push_back(unwind_slice);
        unwind.compact_unwind_functions.push_back({3, 0, 0, 0x01000000u, 0x240, 0,
            Address{{0}, 0x401000}});
        unwind.compact_unwind_functions.push_back({3, 0, 1, 0, 0x248, 0x100,
            Address{{0}, 0x401100}});
        std::vector<debugger::RegisterValue> live;
        for (const auto &[name, value] : std::vector<std::pair<std::string, std::uint64_t>>{
                 {"RIP", 0x700025}, {"RSP", 0x700ff0}, {"RBP", 0x701000}}) {
            debugger::RegisterValue reg;
            reg.name = name; reg.bytes.resize(8);
            for (unsigned i = 0; i < 8; ++i) reg.bytes[i] = std::byte((value >> (8 * i)) & 0xff);
            live.push_back(std::move(reg));
        }
        user->debug_variables.clear();
        database::DebugVariable caller_local;
        caller_local.id = 4; caller_local.function_entry = entry; caller_local.name = "caller_cfa_local";
        caller_local.type_id = 8;
        caller_local.location_operations.push_back({
            static_cast<std::uint8_t>(symbols::LocationOperationKind::call_frame_cfa), 0, 0, 0, 0});
        user->debug_variables.push_back(caller_local);
        const auto frames = debugger_stack_frames_at(*created.value(), 0x700025, 0x700000, 0x1000,
            Architecture::x86_64, live, &unwind,
            [](std::uint64_t address, std::size_t count) -> Result<std::vector<std::byte>> {
                const std::uint64_t value = address == 0x701000 ? 0x701020 :
                    address == 0x701008 ? 0x700055 : address == 0x701020 ? 0x701040 :
                    address == 0x701028 ? 0x700200 : 0;
                std::vector<std::byte> bytes(count);
                for (std::size_t i = 0; i < count; ++i) bytes[i] = std::byte((value >> (8 * i)) & 0xff);
                return bytes;
            });
        require(frames.size() == 3 && frames[0].runtime_pc == 0x700025 &&
                    frames[0].call_frame_cfa == 0x701010 && frames[1].runtime_pc == 0x700055 &&
                    frames[1].call_frame_cfa == 0x701030,
                "Mach-O unwind metadata recovers a selectable caller PC and its CFA");
        const auto caller_rows = debugger_locals_at(project, *created.value(), frames[1].runtime_pc,
            0x700000, Architecture::x86_64, frames[1].registers, {}, frames[1].call_frame_cfa);
        require(caller_rows.size() == 1 && caller_rows[0].location == "memory 0x701030",
                "caller-frame DWARF CFA expressions use the selected frame unwind result");

        ElfMetadata elf_unwind;
        elf_unwind.header.is_64 = true;
        elf_unwind.header.machine = 62;
        ElfEhFrameFunction elf_fde;
        elf_fde.section = 2; elf_fde.file_offset = 0x500; elf_fde.begin = entry; elf_fde.size = 0x100;
        elf_fde.code_alignment = 1; elf_fde.data_alignment = -8; elf_fde.return_register = 16;
        elf_fde.cie_instructions = {std::byte{0x0c}, std::byte{7}, std::byte{8}};
        elf_fde.instructions = {std::byte{0x90}, std::byte{1}};
        elf_unwind.eh_frame_functions.push_back(elf_fde);
        const auto elf_frames = debugger_stack_frames_at(*created.value(), 0x700025, 0x700000,
            0x1000, Architecture::x86_64, live, nullptr,
            [](std::uint64_t address, std::size_t count) -> Result<std::vector<std::byte>> {
                const std::uint64_t value = address == 0x700ff0 ? 0x700055 :
                    address == 0x700ff8 ? 0x700200 : 0;
                std::vector<std::byte> bytes(count);
                for (std::size_t i = 0; i < count; ++i) bytes[i] = std::byte((value >> (8 * i)) & 0xff);
                return bytes;
            }, 64, 0x401000, &elf_unwind);
        require(elf_frames.size() == 3 && elf_frames[0].runtime_pc == 0x700025 &&
                    elf_frames[0].call_frame_cfa == 0x700ff8 && elf_frames[1].runtime_pc == 0x700055 &&
                    elf_frames[1].call_frame_cfa == 0x701000 && elf_frames[2].runtime_pc == 0x700200,
                "ELF x86-64 CFI produces bounded caller frames with monotonic per-frame CFA");
        const auto caller_rip = std::find_if(elf_frames[1].registers.begin(), elf_frames[1].registers.end(),
            [](const auto &reg) { return reg.name == "RIP"; });
        const auto caller_rsp = std::find_if(elf_frames[1].registers.begin(), elf_frames[1].registers.end(),
            [](const auto &reg) { return reg.name == "RSP"; });
        const auto reg_scalar = [](const debugger::RegisterValue &reg) {
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < reg.bytes.size() && i < 8; ++i)
                value |= std::uint64_t(std::to_integer<std::uint8_t>(reg.bytes[i])) << (8 * i);
            return value;
        };
        require(caller_rip != elf_frames[1].registers.end() && caller_rsp != elf_frames[1].registers.end() &&
                    reg_scalar(*caller_rip) == 0x700055 && reg_scalar(*caller_rsp) == 0x700ff8,
                "ELF caller DWARF registers convert back to native x86-64 register values");
        const auto elf_caller_rows = debugger_locals_at(project, *created.value(),
            elf_frames[1].runtime_pc, 0x700000, Architecture::x86_64,
            elf_frames[1].registers, {}, elf_frames[1].call_frame_cfa);
        require(elf_caller_rows.size() == 1 && elf_caller_rows[0].location == "memory 0x701000",
                "selected ELF caller frame evaluates DWARF call_frame_cfa using its recovered CFA");
        const auto elf_repeated_pc = debugger_stack_frames_at(*created.value(), 0x700025, 0x700000,
            0x1000, Architecture::x86_64, live, nullptr,
            [](std::uint64_t, std::size_t count) -> Result<std::vector<std::byte>> {
                std::vector<std::byte> bytes(count);
                for (std::size_t i = 0; i < count; ++i) bytes[i] = std::byte((0x700025ULL >> (8 * i)) & 0xff);
                return bytes;
            }, 64, 0x401000, &elf_unwind);
        require(elf_repeated_pc.size() == 1,
                "ELF caller walk stops on a repeated PC instead of looping through the stack");
        const auto elf_outside_module = debugger_stack_frames_at(*created.value(), 0x700025, 0x700000,
            0x1000, Architecture::x86_64, live, nullptr,
            [](std::uint64_t, std::size_t count) -> Result<std::vector<std::byte>> {
                std::vector<std::byte> bytes(count);
                for (std::size_t i = 0; i < count; ++i) bytes[i] = std::byte((0x800000ULL >> (8 * i)) & 0xff);
                return bytes;
            }, 64, 0x401000, &elf_unwind);
        require(elf_outside_module.size() == 1 && elf_outside_module[0].call_frame_cfa == 0x700ff8,
                "ELF caller walk retains current CFA and stops before adding an out-of-module PC");

        const auto arm64_registers = [](std::initializer_list<std::pair<std::string, std::uint64_t>> values) {
            std::vector<debugger::RegisterValue> result;
            for (const auto &[name, value] : values) {
                debugger::RegisterValue reg;
                reg.name = name; reg.bytes.resize(8); reg.byte_order = ByteOrder::little;
                for (unsigned i = 0; i < 8; ++i) reg.bytes[i] = std::byte((value >> (8 * i)) & 0xff);
                result.push_back(std::move(reg));
            }
            return result;
        };
        const auto memory_reader = [](std::unordered_map<std::uint64_t, std::uint64_t> memory) {
            return [memory = std::move(memory)](std::uint64_t address, std::size_t count)
                -> Result<std::vector<std::byte>> {
                std::vector<std::byte> bytes(count, std::byte{0});
                const auto found = memory.find(address);
                if (found == memory.end()) return Error{ErrorCode::io, "missing synthetic unwind word"};
                for (std::size_t i = 0; i < count && i < 8; ++i)
                    bytes[i] = std::byte((found->second >> (8 * i)) & 0xff);
                return bytes;
            };
        };
        MachOMetadata arm64_unwind;
        MachOSlice arm64_slice;
        arm64_slice.header.cpu_type = 0x0100000cu;
        arm64_unwind.container.slices.push_back(arm64_slice);
        arm64_unwind.compact_unwind_functions.push_back({3, 0, 0, 0x04000000u, 0x340, 0,
            Address{{0}, 0x401000}});
        arm64_unwind.compact_unwind_functions.push_back({3, 0, 1, 0x04000000u, 0x348, 0x50,
            Address{{0}, 0x401050}});
        arm64_unwind.compact_unwind_functions.push_back({3, 0, 2, 0, 0x350, 0x100,
            Address{{0}, 0x401100}});
        user->debug_variables.clear();
        database::DebugVariable arm64_cfa_local;
        arm64_cfa_local.id = 5; arm64_cfa_local.function_entry = entry; arm64_cfa_local.name = "arm64_cfa";
        arm64_cfa_local.type_id = 8;
        arm64_cfa_local.location_operations.push_back({
            static_cast<std::uint8_t>(symbols::LocationOperationKind::call_frame_cfa), 0, 0, 0, 0});
        user->debug_variables.push_back(arm64_cfa_local);
        database::DebugVariable arm64_lr_local;
        arm64_lr_local.id = 6; arm64_lr_local.function_entry = entry; arm64_lr_local.name = "arm64_lr";
        arm64_lr_local.type_id = 64;
        arm64_lr_local.location_operations.push_back({
            static_cast<std::uint8_t>(symbols::LocationOperationKind::register_location), 30, 0, 0, 0});
        user->debug_variables.push_back(arm64_lr_local);
        database::DebugVariable arm64_d8_local;
        arm64_d8_local.id = 7; arm64_d8_local.function_entry = entry; arm64_d8_local.name = "arm64_d8";
        arm64_d8_local.type_id = 64;
        arm64_d8_local.location_operations.push_back({
            static_cast<std::uint8_t>(symbols::LocationOperationKind::register_location), 72, 0, 0, 0});
        user->debug_variables.push_back(arm64_d8_local);
        auto arm64_fp_registers = arm64_registers({{"PC", 0x700025}, {"SP", 0x700ff0},
            {"X29", 0x701000}, {"X30", 0x700066}, {"D8", 0xd8d8}});
        const auto arm64_fp_frames = debugger_stack_frames_at(*created.value(), 0x700025, 0x700000,
            0x1000, Architecture::arm64, arm64_fp_registers, &arm64_unwind,
            memory_reader({{0x701000, 0x701020}, {0x701008, 0x700055},
                           {0x701020, 0x701040}, {0x701028, 0x700200}}), 64, 0x401000);
        require(arm64_fp_frames.size() == 3 && arm64_fp_frames[0].runtime_pc == 0x700025 &&
                    arm64_fp_frames[0].call_frame_cfa == 0x701010 &&
                    arm64_fp_frames[1].runtime_pc == 0x700055 &&
                    arm64_fp_frames[1].call_frame_cfa == 0x701030,
                "Mach-O arm64 frame-pointer records recover caller frames and per-frame CFA");
        const auto arm64_fp_locals = debugger_locals_at(project, *created.value(),
            arm64_fp_frames[1].runtime_pc, 0x700000, Architecture::arm64,
            arm64_fp_frames[1].registers, {}, arm64_fp_frames[1].call_frame_cfa);
        require(arm64_fp_locals.size() == 3 && arm64_fp_locals[0].location == "memory 0x701030" &&
                    arm64_fp_locals[1].location == "DWARF register 30" &&
                    arm64_fp_locals[1].value == "0x700055" &&
                    arm64_fp_locals[2].location == "DWARF register 72" &&
                    arm64_fp_locals[2].value == "0xD8D8",
                "AArch64 X30 and D8 DWARF locations use the recovered caller register context");

        arm64_unwind.compact_unwind_functions[0].encoding = 0x02000000u | (3u << 12) | 1u | (1u << 8);
        arm64_unwind.compact_unwind_functions[1].encoding = 0x04000000u;
        auto arm64_frameless_registers = arm64_registers({{"PC", 0x700025}, {"SP", 0x700ff0},
            {"X29", 0x701020}, {"X30", 0x700055}, {"X19", 0x1919}, {"X20", 0x2020},
            {"D8", 0xd8d8}, {"D9", 0xd9d9}});
        const auto arm64_frameless_frames = debugger_stack_frames_at(*created.value(), 0x700025,
            0x700000, 0x1000, Architecture::arm64, arm64_frameless_registers, &arm64_unwind,
            memory_reader({{0x701018, 0x1919}, {0x701010, 0x2020}, {0x701008, 0xd8d8},
                           {0x701000, 0xd9d9}, {0x701020, 0x701040}, {0x701028, 0x700200}}),
            64, 0x401000);
        require(arm64_frameless_frames.size() == 3 &&
                    arm64_frameless_frames[0].call_frame_cfa == 0x701000 &&
                    arm64_frameless_frames[1].runtime_pc == 0x700055 &&
                    arm64_frameless_frames[1].call_frame_cfa == 0x701030,
                "Mach-O arm64 frameless records restore LR, saved registers, and continue into caller frames");
        const auto arm64_frameless_locals = debugger_locals_at(project, *created.value(),
            arm64_frameless_frames[1].runtime_pc, 0x700000, Architecture::arm64,
            arm64_frameless_frames[1].registers, {}, arm64_frameless_frames[1].call_frame_cfa);
        require(arm64_frameless_locals.size() == 3 && arm64_frameless_locals[1].value == "0x700055" &&
                    arm64_frameless_locals[2].value == "0xD8D8",
                "frameless caller values preserve recovered X30 and D8 for DWARF register expressions");

        auto arm64_unsupported = arm64_unwind;
        arm64_unsupported.compact_unwind_functions[0].encoding = 0x03000000u;
        const auto unsupported_arm64_frames = debugger_stack_frames_at(*created.value(), 0x700025,
            0x700000, 0x1000, Architecture::arm64, arm64_fp_registers, &arm64_unsupported,
            memory_reader({}), 64, 0x401000);
        require(unsupported_arm64_frames.size() == 1 &&
                    !unsupported_arm64_frames[0].call_frame_cfa,
                "unsupported arm64 unwind recipes leave only the live frame without fabricated CFA");
        auto arm64_out_of_range_unwind = arm64_unwind;
        arm64_out_of_range_unwind.compact_unwind_functions[0].encoding = 0x04000000u;
        const auto unmapped_arm64_frames = debugger_stack_frames_at(*created.value(), 0x700025,
            0x700000, 0x100, Architecture::arm64, arm64_fp_registers, &arm64_out_of_range_unwind,
            memory_reader({{0x701000, 0x701020}, {0x701008, 0x700200}}), 64, 0x401000);
        require(unmapped_arm64_frames.size() == 1 &&
                    unmapped_arm64_frames[0].call_frame_cfa == 0x701010,
                "arm64 caller PCs outside the matched module stop after preserving the current-frame CFA");
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
