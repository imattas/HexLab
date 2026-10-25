#include "hexlab/loaders/macho_unwind.hpp"
#include <iostream>
#include <stdexcept>
#include <unordered_map>

using namespace hexlab;

namespace {
void check(bool ok, const char *message) { if (!ok) throw std::runtime_error(message); }
MachOMetadata metadata(std::uint32_t cpu, std::uint32_t encoding, Address function = {{0}, 0x1000}) {
    MachOMetadata m;
    MachOSlice slice;
    slice.header.cpu_type = cpu;
    m.container.slices.push_back(slice);
    m.compact_unwind_functions.push_back({3, 0, 0, encoding, 0x240, 0, function});
    m.compact_unwind_functions.push_back({3, 0, 1, 0, 0x248, 0x100,
                                          Address{function.space, function.offset + 0x100}});
    return m;
}
std::uint64_t evaluate(MachOMetadata m, const MachOUnwindContext &context,
                       const std::unordered_map<std::uint64_t, std::uint64_t> &memory,
                       MachOUnwindResult *out = nullptr) {
    auto read = [&](std::uint64_t at, std::uint8_t width) -> std::optional<std::uint64_t> {
        if (width != 8) return std::nullopt;
        const auto it = memory.find(at);
        return it == memory.end() ? std::nullopt : std::optional<std::uint64_t>(it->second);
    };
    auto result = evaluate_macho_unwind(m, {{0}, 0x1000}, context, read);
    if (!result) throw std::runtime_error(result.error().message);
    if (out) *out = result.value();
    return result.value().cfa;
}
void positives() {
    MachOUnwindResult result;
    const auto rbp = MachOUnwindRegister::x86_64_rbp;
    const auto rsp = MachOUnwindRegister::x86_64_rsp;
    const auto rip = MachOUnwindRegister::x86_64_rip;
    auto m = metadata(0x01000007u, 0x01000000u);
    check(evaluate(m, {{rbp, 0x2000}}, {{0x2000, 0x1900}, {0x2008, 0x1555}}, &result) == 0x2010,
          "x86_64 RBP CFA");
    check(result.caller.at(rbp) == 0x1900 && result.caller.at(rip) == 0x1555 &&
          result.caller.at(rsp) == 0x2010 && result.record_file_offset == 0x240,
          "x86_64 RBP caller state and provenance");
    auto inside = evaluate_macho_unwind(m, {{0}, 0x1004}, {{rbp, 0x2000}},
        [](std::uint64_t at, std::uint8_t) -> std::optional<std::uint64_t> {
            if (at == 0x2000) return 0x1900;
            if (at == 0x2008) return 0x1555;
            return std::nullopt;
        });
    check(inside && inside.value().function == Address{{0}, 0x1000},
          "PC inside a bounded indexed function uses the preceding recipe");

    m = metadata(0x01000007u, 0x01000000u | (2u << 16) | 1u | (2u << 3));
    check(evaluate(m, {{rbp, 0x2000}}, {{0x1ff0, 0xbbbb}, {0x1ff8, 0xcccc},
                                        {0x2000, 0x1900}, {0x2008, 0x1555}}, &result) == 0x2010,
          "x86_64 RBP frame with saved nonvolatile registers");
    check(result.caller.at(MachOUnwindRegister::x86_64_rbx) == 0xbbbb &&
          result.caller.at(MachOUnwindRegister::x86_64_r12) == 0xcccc,
          "x86_64 RBP saved-register locations");

    m = metadata(0x01000007u, 0x02000000u | (3u << 16));
    check(evaluate(m, {{rsp, 0x3000}}, {{0x3010, 0x2222}}, &result) == 0x3018,
          "x86_64 immediate stack CFA");
    check(result.caller.at(rip) == 0x2222 && result.caller.at(rsp) == 0x3018,
          "x86_64 immediate stack caller state");
    m = metadata(0x01000007u, 0x02000000u | (4u << 16) | (1u << 10));
    check(evaluate(m, {{rsp, 0x3000}}, {{0x3010, 0xbbbb}, {0x3018, 0x2444}}, &result) == 0x3020,
          "x86_64 immediate stack with saved register");
    check(result.caller.at(MachOUnwindRegister::x86_64_rbx) == 0xbbbb &&
          result.caller.at(rip) == 0x2444, "x86_64 frameless save and return locations");
    m = metadata(0x01000007u, 0x02000000u | (2u << 16) | (1u << 10) | 5u);
    check(evaluate(m, {{rsp, 0x3000}}, {{0x3000, 0x2b2b}, {0x3008, 0x2555}}, &result) == 0x3010 &&
          result.caller.at(rbp) == 0x2b2b && result.caller.at(rip) == 0x2555,
          "x86_64 frameless permutation restores RBP");

    const auto fp = MachOUnwindRegister::arm64_x29;
    const auto sp = MachOUnwindRegister::arm64_sp;
    const auto pc = MachOUnwindRegister::arm64_pc;
    const auto x19 = MachOUnwindRegister::arm64_x19;
    const auto x20 = MachOUnwindRegister::arm64_x20;
    m = metadata(0x0100000cu, 0x04000000u | 1u | (1u << 8));
    check(evaluate(m, {{fp, 0x4000}}, {{0x3ff8, 0x1919}, {0x3ff0, 0x2020},
                                        {0x3fe8, 0xd8d8}, {0x3fe0, 0xd9d9},
                                        {0x4000, 0x3900}, {0x4008, 0x4567}}, &result) == 0x4010,
          "arm64 frame CFA with x19/x20 pair");
    check(result.caller.at(x19) == 0x1919 && result.caller.at(x20) == 0x2020 &&
          result.caller.at(fp) == 0x3900 && result.caller.at(pc) == 0x4567 &&
          result.caller.at(sp) == 0x4010, "arm64 restored register pairs and caller state");
    check(result.caller.at(MachOUnwindRegister::arm64_d8) == 0xd8d8 &&
          result.caller.at(MachOUnwindRegister::arm64_d9) == 0xd9d9,
          "arm64 frame restores D8/D9 pair");
    const auto lr = MachOUnwindRegister::arm64_x30;
    m = metadata(0x0100000cu, 0x02000000u | (4u << 12) | 1u | (1u << 8));
    check(evaluate(m, {{sp, 0x5000}, {lr, 0x7777}}, {{0x5038, 0x1919}, {0x5030, 0x2020},
                                                      {0x5028, 0xd8d8}, {0x5020, 0xd9d9}}, &result) == 0x5020,
          "arm64 frameless stack and saved-register pair");
    check(result.caller.at(x19) == 0x1919 && result.caller.at(x20) == 0x2020 &&
          result.caller.at(pc) == 0x7777, "arm64 frameless pair and link register recovery");
    check(result.caller.at(MachOUnwindRegister::arm64_d8) == 0xd8d8 &&
          result.caller.at(MachOUnwindRegister::arm64_d9) == 0xd9d9,
          "arm64 frameless restores D8/D9 pair");
}
void eh_frame_runtime() {
    auto m = metadata(0x01000007u, 0);
    m.compact_unwind_functions.clear();
    MachOEhFrameFunction fde;
    fde.section = 7;
    fde.record_file_offset = 0x340;
    fde.size = 0x40;
    fde.address = Address{{0}, 0x1000};
    fde.code_alignment = 1;
    fde.data_alignment = -8;
    fde.return_register = 16;
    fde.cie_instructions = {std::byte{0x0c}, std::byte{7}, std::byte{8}}; // CFA = RSP + 8
    fde.instructions = {std::byte{0x90}, std::byte{1}, std::byte{0x86}, std::byte{2}};
    m.eh_frame_functions.push_back(fde);
    const auto rsp = MachOUnwindRegister::x86_64_rsp;
    const auto rip = MachOUnwindRegister::x86_64_rip;
    const auto rbp = MachOUnwindRegister::x86_64_rbp;
    MachOUnwindResult result;
    const auto outcome = evaluate_macho_unwind(m, {{0}, 0x1008}, {{rsp, 0x3000}},
          [](std::uint64_t at, std::uint8_t width) -> std::optional<std::uint64_t> {
              if (width != 8) return std::nullopt;
              if (at == 0x3000) return 0xfeed;
              if (at == 0x2ff8) return 0xbeef;
              return std::nullopt;
          });
    if (!outcome) throw std::runtime_error(outcome.error().message);
    check(outcome.value().cfa == 0x3008 && outcome.value().function.offset == 0x1000 &&
              outcome.value().record_file_offset == 0x340 && outcome.value().caller.at(rip) == 0xfeed &&
              outcome.value().caller.at(rbp) == 0xbeef && outcome.value().caller.at(rsp) == 0x3008,
          "eh_frame CFI restores caller PC, CFA stack pointer, and saved registers");

    auto value_offset_fde = fde;
    value_offset_fde.instructions = {std::byte{0x14}, std::byte{16}, std::byte{1}, // RIP = CFA - 8
                                     std::byte{0x15}, std::byte{6}, std::byte{2}}; // RBP = CFA - 16
    auto value_offset_metadata = metadata(0x01000007u, 0);
    value_offset_metadata.compact_unwind_functions.clear();
    value_offset_metadata.eh_frame_functions.push_back(value_offset_fde);
    const auto value_offset_result = evaluate_macho_unwind(
        value_offset_metadata, {{0}, 0x1008}, {{rsp, 0x3000}},
        [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return std::nullopt; });
    check(value_offset_result && value_offset_result.value().caller.at(rip) == 0x3000 &&
              value_offset_result.value().caller.at(rbp) == 0x2ff8,
          "CFI val_offset and val_offset_sf restore register values without reading stack memory");
    auto overflow_value_offset = value_offset_fde;
    overflow_value_offset.instructions = {std::byte{0x15}, std::byte{16}};
    for (unsigned i = 0; i < 9; ++i) overflow_value_offset.instructions.push_back(std::byte{0x80});
    overflow_value_offset.instructions.push_back(std::byte{0x7f}); // INT64_MIN * data alignment overflows
    value_offset_metadata.eh_frame_functions.front() = overflow_value_offset;
    const auto overflow_value_offset_result = evaluate_macho_unwind(
        value_offset_metadata, {{0}, 0x1008}, {{rsp, 0x3000}},
        [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return std::nullopt; });
    check(!overflow_value_offset_result && overflow_value_offset_result.error().code == ErrorCode::overflow,
          "CFI val_offset_sf rejects scaled-offset overflow");

    // A temporary epilog rule applies only at PCs before the restore_state.
    fde.instructions = {std::byte{0x90}, std::byte{1}, // RIP = CFA - 8
                        std::byte{0x86}, std::byte{2}, // RBP = CFA - 16
                        std::byte{0x44},               // advance_loc 4
                        std::byte{0x0a},               // remember_state
                        std::byte{0x08}, std::byte{6}, // RBP is unchanged
                        std::byte{0x44},               // advance_loc 4
                        std::byte{0x0b}};              // restore_state
    m.eh_frame_functions.clear();
    m.eh_frame_functions.push_back(fde);
    const auto epilog_context = MachOUnwindContext{{rsp, 0x3000}, {rbp, 0x7777}};
    const auto temporary_rule = evaluate_macho_unwind(m, {{0}, 0x1006}, epilog_context,
        [](std::uint64_t at, std::uint8_t width) -> std::optional<std::uint64_t> {
            if (width == 8 && at == 0x2ff8) return 0xfeed;
            if (width == 8 && at == 0x3000) return 0xfeed;
            return std::nullopt;
        });
    check(temporary_rule && temporary_rule.value().caller.at(rbp) == 0x7777,
          "CFI remember_state keeps the temporary epilog rule at the requested PC");
    const auto restored_rule = evaluate_macho_unwind(m, {{0}, 0x1008}, epilog_context,
        [](std::uint64_t at, std::uint8_t width) -> std::optional<std::uint64_t> {
            if (width == 8 && at == 0x2ff8) return 0xbeef;
            if (width == 8 && at == 0x3000) return 0xfeed;
            return std::nullopt;
        });
    check(restored_rule && restored_rule.value().caller.at(rbp) == 0xbeef,
          "CFI restore_state reinstates the prior saved-register rule");

    auto arm = metadata(0x0100000cu, 0);
    arm.compact_unwind_functions.clear();
    fde.address = Address{{0}, 0x8000};
    fde.record_file_offset = 0x440;
    fde.return_register = 30;
    fde.cie_instructions = {std::byte{0x0c}, std::byte{31}, std::byte{16}}; // CFA = SP + 16
    fde.instructions = {std::byte{0x9e}, std::byte{1}, std::byte{0x9d}, std::byte{2},
                       std::byte{5}, std::byte{72}, std::byte{3}, // D8 at CFA-24
                       std::byte{5}, std::byte{79}, std::byte{4}}; // D15 at CFA-32
    arm.eh_frame_functions.push_back(fde);
    const auto arm_outcome = evaluate_macho_unwind(arm, {{0}, 0x8004},
        {{MachOUnwindRegister::arm64_sp, 0x3ff0}},
        [](std::uint64_t at, std::uint8_t width) -> std::optional<std::uint64_t> {
            if (width != 8) return std::nullopt;
            if (at == 0x3ff8) return 0xabc;
            if (at == 0x3ff0) return 0xdef;
            if (at == 0x3fe8) return 0xd8d8;
            if (at == 0x3fe0) return 0xd15d;
            return std::nullopt;
        });
    check(arm_outcome && arm_outcome.value().cfa == 0x4000 &&
              arm_outcome.value().caller.at(MachOUnwindRegister::arm64_x29) == 0xdef &&
              arm_outcome.value().caller.at(MachOUnwindRegister::arm64_x30) == 0xabc &&
              arm_outcome.value().caller.at(MachOUnwindRegister::arm64_d8) == 0xd8d8 &&
              arm_outcome.value().caller.at(MachOUnwindRegister::arm64_d15) == 0xd15d &&
              arm_outcome.value().caller.at(MachOUnwindRegister::arm64_pc) == 0xabc &&
              arm_outcome.value().caller.at(MachOUnwindRegister::arm64_sp) == 0x4000,
          "arm64 eh_frame CFI restores LR, frame pointer, PC, and SP");
    auto malformed = m.eh_frame_functions.front();
    malformed.instructions = {std::byte{0x10}}; // unsupported set_loc/expression family member
    auto unsupported = metadata(0x01000007u, 0);
    unsupported.compact_unwind_functions.clear();
    unsupported.eh_frame_functions.push_back(malformed);
    const auto unsupported_result = evaluate_macho_unwind(unsupported, {{0}, 0x1000}, {{rsp, 0x3000}},
        [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return 1; });
    check(!unsupported_result && unsupported_result.error().code == ErrorCode::unsupported,
          "unsupported eh_frame CFI opcodes fail explicitly");
    malformed = fde;
    malformed.address = Address{{0}, 0x1000};
    malformed.return_register = 16;
    malformed.instructions = {std::byte{0x0b}}; // restore_state without a matching remember_state
    unsupported = metadata(0x01000007u, 0);
    unsupported.compact_unwind_functions.clear();
    unsupported.eh_frame_functions.push_back(malformed);
    const auto unbalanced_state = evaluate_macho_unwind(unsupported, {{0}, 0x1000}, {{rsp, 0x3000}},
        [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return 1; });
    check(!unbalanced_state && unbalanced_state.error().code == ErrorCode::malformed,
          "CFI restore_state without a saved state is malformed");
    malformed.instructions.assign(1025, std::byte{0x0a});
    unsupported.eh_frame_functions.front() = malformed;
    const auto excessive_state = evaluate_macho_unwind(unsupported, {{0}, 0x1000}, {{rsp, 0x3000}},
        [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return 1; });
    check(!excessive_state && excessive_state.error().code == ErrorCode::resource_limit,
          "CFI remember_state nesting is bounded");
}
void negatives() {
    auto m = metadata(0x01000007u, 0x01000000u);
    auto read = [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return 7; };
    auto result = evaluate_macho_unwind(m, {{0}, 0x1200}, {{MachOUnwindRegister::x86_64_rbp, 0x2000}}, read);
    check(!result && result.error().code == ErrorCode::out_of_bounds, "PC after the last known boundary has no proven recipe interval");
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {}, read);
    check(!result && result.error().code == ErrorCode::malformed, "missing frame register rejected");
    auto no_memory = [](std::uint64_t, std::uint8_t) -> std::optional<std::uint64_t> { return std::nullopt; };
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {{MachOUnwindRegister::x86_64_rbp, 0x2000}}, no_memory);
    check(!result && result.error().code == ErrorCode::out_of_bounds, "failed stack read rejected");
    m = metadata(0x01000007u, 0x04000000u);
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {}, read);
    check(!result && result.error().code == ErrorCode::unsupported &&
          result.error().message.find("DWARF FDE") != std::string::npos,
          "DWARF FDE mode has a precise unsupported result");
    m = metadata(0x01000007u, 0x01000001u);
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {{MachOUnwindRegister::x86_64_rbp, 0x2000}}, read);
    check(!result && result.error().code == ErrorCode::malformed, "RBP save area cannot overlap frame record");
    m = metadata(0x01000007u, 0x02000000u | (1u << 10) | 0x3ffu);
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {{MachOUnwindRegister::x86_64_rsp, 0x2000}}, read);
    check(!result && result.error().code == ErrorCode::malformed, "invalid frameless permutation rejected");
    m = metadata(0x01000007u, 0x03000000u);
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {{MachOUnwindRegister::x86_64_rsp, 0x2000}}, read);
    check(!result && result.error().code == ErrorCode::unsupported &&
          result.error().message.find("mode") != std::string::npos,
          "x86_64 indirect stack mode remains unsupported without instruction memory");
    m = metadata(0x01000007u, 0x02000000u | (1u << 13));
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {{MachOUnwindRegister::x86_64_rsp, 0x2000}}, read);
    check(!result && result.error().code == ErrorCode::malformed, "immediate stack reserved adjustment rejected");
    m = metadata(0x01000007u, 0x01000000u);
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {{MachOUnwindRegister::x86_64_rbp, UINT64_MAX - 4}}, read);
    check(!result && result.error().code == ErrorCode::overflow, "CFA overflow rejected");
    m = metadata(0x0100000cu, 0x04000000u | (1u << 7));
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {{MachOUnwindRegister::arm64_x29, 0x4000}}, read);
    check(!result && result.error().code == ErrorCode::malformed, "reserved frame encoding bits rejected");
    m = metadata(0x0100000cu, 0x03000000u | 4u);
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {}, read);
    check(!result && result.error().code == ErrorCode::unsupported &&
          result.error().message.find("DWARF FDE") != std::string::npos,
          "arm64 DWARF FDE mode has a precise unsupported result");
    m = metadata(0x0100000cu, 0x05000000u);
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {}, read);
    check(!result && result.error().code == ErrorCode::unsupported &&
          result.error().message.find("pointer-authenticated") != std::string::npos,
          "arm64e authenticated-LR mode is rejected explicitly");
    m.selected_slice = 1;
    result = evaluate_macho_unwind(m, {{0}, 0x1000}, {}, read);
    check(!result && result.error().code == ErrorCode::malformed, "invalid selected slice rejected");
}
}
int main() {
    try { positives(); eh_frame_runtime(); negatives(); }
    catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
    std::cout << "Mach-O runtime unwind checks passed\n";
    return 0;
}
