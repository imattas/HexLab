#include "hexlab/analysis/references.hpp"
#include "hexlab/image/file_storage.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include <algorithm>
#include <set>
using namespace hexlab;
using namespace hexlab_test;
std::shared_ptr<const ReferenceIndex> roundtrip(const ReferenceIndex &index) {
    auto encoded = encode_reference_index(index, {}).value();
    auto decoded = decode_reference_index(encoded, {});
    if (!decoded)
        throw std::runtime_error(decoded.error().message);
    check(encode_reference_index(*decoded.value(), {}).value() == encoded,
          "all typed target/expression variants have canonical round trips");
    return decoded.value();
}
std::vector<std::byte> memory_reference_fixture() {
    auto data = bytes({0x48, 0x8d, 0x05, 0x39, 0, 0, 0,    0x48, 0x8b, 0x0d, 0x32, 0, 0, 0, 0x48,
                       0x89, 0x0d, 0x2b, 0,    0, 0, 0x48, 0x83, 0x05, 0x23, 0,    0, 0, 1, 0xc3});
    data.resize(128);
    return data;
}
void memory_tests() {
    auto functions = recover_functions(*memory_image(memory_reference_fixture()), {}, {}, {}, {}).value();
    auto references = derive_references(*functions, {}, {}, {}).value();
    auto incoming = references->incoming(Address{{0}, 0x1040}, {}).value();
    std::set<ReferenceKind> kinds;
    for (const auto &reference : incoming.rows)
        kinds.insert(reference.kind);
    check(incoming.total == 4 &&
              kinds == std::set<ReferenceKind>{ReferenceKind::memory_address, ReferenceKind::memory_read,
                                               ReferenceKind::memory_write, ReferenceKind::memory_read_write},
          "LEA read write and read-write have distinct numeric references");
    auto page = references->incoming(Address{{0}, 0x1040}, {1, 2}).value();
    check(page.total == 4 && page.rows.size() == 2 && page.rows[0].source == Location{Address{{0}, 0x1007}} &&
              page.rows[1].source == Location{Address{{0}, 0x100e}} && page.next_offset == uint64_t{3},
          "incoming references page in deterministic source order");
    check(references->incoming(Address{{0}, 0x1040}, {4, 2}).value().rows.empty() &&
              !references->incoming(Address{{0}, 0x1040}, {0, 0}),
          "page end is empty and zero page size is rejected");
    const auto interior_result = references->incoming_range(Address{{0}, 0x103f}, 3, {});
    const auto interior_page = references->incoming_range(Address{{0}, 0x1040}, 1, {1, 2});
    check(bool(interior_result) && interior_result.value().total == 4 && interior_result.value().rows.size() == 4 &&
              interior_result.value().rows.front().source == Location{Address{{0}, 0x1000}} &&
              bool(interior_page) && interior_page.value().rows.size() == 2,
          "incoming data-range query finds xrefs to interior addresses and preserves source-ordered paging");
    const auto other_space = references->incoming_range(Address{{1}, 0x103f}, 3, {});
    check(bool(other_space) && other_space.value().total == 0 &&
              !references->incoming_range(Address{{0}, UINT64_MAX}, 2, {}),
          "incoming data-range queries stay within an address space and reject overflow");
    auto outgoing = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(outgoing.total == 1 && outgoing.rows[0].operand_index == 1u &&
              outgoing.rows[0].access == OperandAccess::address,
          "source and operand identify the LEA address use");
    Reference associated{{0}, Address{{0}, 0x1000}, 0u, ExternalIdentity{"fixture.dll", "entry", {}},
                         ReferenceKind::imported_call, OperandAccess::address,
                         {ReferenceProvenanceKind::import_slot, 1, 0}, Location{Address{{0}, 0x1040}}};
    auto associated_index = ReferenceIndex::create({associated}, {}, true, {}).value();
    const auto association_page = associated_index->incoming_range(Address{{0}, 0x1040}, 1, {}).value();
    check(association_page.total == 1 && association_page.rows[0].association == Location{Address{{0}, 0x1040}},
          "incoming data-range query includes import-slot associations when the target is external");
}
void x86_indirect_target_tests() {
    // movabs rax, 0x1010; call rax; ret; ... ret at the proven target.
    auto code = bytes({0x48, 0xb8, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0xff, 0xd0, 0xc3});
    code.resize(17, std::byte{0x90});
    code[16] = std::byte{0xc3};
    const auto image = memory_image(std::move(code));
    const auto functions = recover_functions(*image, {}, {}, {}, {}).value();
    const auto references = derive_references(*image, *functions, {}, {}, {}).value();
    const auto outgoing = references->outgoing(Address{{0}, 0x100a}, {}).value();
    const auto *target = outgoing.rows.empty() ? nullptr : std::get_if<Location>(&outgoing.rows[0].target);
    check(outgoing.total == 1 && outgoing.rows[0].kind == ReferenceKind::call && target &&
              *target == Location{Address{{0}, 0x1010}},
          "x86-64 indirect register call resolves from a bounded same-block movabs constant");

    auto lea_jump = bytes({0x48, 0x8d, 0x05, 0x09, 0x00, 0x00, 0x00, 0xff, 0xe0});
    lea_jump.resize(17, std::byte{0x90});
    lea_jump[16] = std::byte{0xc3};
    const auto lea_image = memory_image(std::move(lea_jump));
    const auto lea_functions = recover_functions(*lea_image, {}, {}, {}, {}).value();
    const auto lea_references = derive_references(*lea_image, *lea_functions, {}, {}, {}).value();
    const auto jump = lea_references->outgoing(Address{{0}, 0x1007}, {}).value();
    const auto *jump_target = jump.rows.empty() ? nullptr : std::get_if<Location>(&jump.rows[0].target);
    check(jump.total == 1 && jump.rows[0].kind == ReferenceKind::jump && jump_target &&
              *jump_target == Location{Address{{0}, 0x1010}},
          "x86-64 RIP-relative LEA resolves a following register-indirect jump");

    // A later write destroys the value before the indirect call.
    auto clobbered = bytes({0x48, 0xb8, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x48, 0x31, 0xc0, 0xff, 0xd0, 0xc3});
    const auto clobber_image = memory_image(std::move(clobbered));
    const auto clobber_functions = recover_functions(*clobber_image, {}, {}, {}, {}).value();
    const auto clobber_references = derive_references(*clobber_image, *clobber_functions, {}, {}, {}).value();
    const auto unresolved = clobber_references->outgoing(Address{{0}, 0x100d}, {}).value();
    check(unresolved.total == 1 && std::holds_alternative<UnresolvedTarget>(unresolved.rows[0].target),
          "x86-64 register writes invalidate prior indirect-call address facts");

    // Values survive a CFG edge only if its predecessor proves them. The
    // destination register copy and address arithmetic happen after the jump.
    auto cross_block = bytes({0x48, 0xb8, 0x30, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0xeb, 0x00,                         // jmp to the next basic block
                              0x48, 0x89, 0xc3,                   // mov rbx, rax
                              0x48, 0x83, 0xc3, 0x08,             // add rbx, 8
                              0xff, 0xd3, 0xc3});                 // call rbx; ret
    cross_block.resize(0x39, std::byte{0x90});
    cross_block[0x38] = std::byte{0xc3};
    const auto cross_block_image = memory_image(std::move(cross_block));
    const auto cross_block_functions = recover_functions(*cross_block_image, {}, {}, {}, {}).value();
    const auto cross_block_references = derive_references(*cross_block_image, *cross_block_functions, {}, {}, {}).value();
    const auto copied_call = cross_block_references->outgoing(Address{{0}, 0x1013}, {}).value();
    const auto *copied_target = copied_call.rows.empty() ? nullptr : std::get_if<Location>(&copied_call.rows[0].target);
    check(copied_call.total == 1 && copied_target && *copied_target == Location{Address{{0}, 0x1038}},
          "x86-64 register copies and word-width immediate arithmetic propagate across a CFG edge");

    // Distinct values from two branches must not be collapsed at a join.
    auto disagreeing_merge = bytes({0x48, 0xb8, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x85, 0xc0,       // test eax,eax
                                    0x74, 0x0c,       // jz to the join
                                    0x48, 0xb8, 0x40, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0xeb, 0x00,       // jump to the join
                                    0xff, 0xd0, 0xc3}); // call rax; ret
    disagreeing_merge.resize(0x41, std::byte{0x90});
    disagreeing_merge[0x38] = std::byte{0xc3};
    disagreeing_merge[0x40] = std::byte{0xc3};
    const auto merge_image = memory_image(std::move(disagreeing_merge));
    const auto merge_functions = recover_functions(*merge_image, {}, {}, {}, {}).value();
    const auto merge_references = derive_references(*merge_image, *merge_functions, {}, {}, {}).value();
    const auto merged_call = merge_references->outgoing(Address{{0}, 0x101a}, {}).value();
    check(merged_call.total == 1 && std::holds_alternative<UnresolvedTarget>(merged_call.rows[0].target),
          "x86-64 indirect targets are rejected when predecessor register values disagree");

    auto call_clobber = bytes({0x48, 0xb8, 0x38, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0xe8, 0x21, 0x00, 0x00, 0x00, // call 0x1030
                               0xff, 0xe0});                // jmp rax
    call_clobber.resize(0x31, std::byte{0x90});
    call_clobber[0x30] = std::byte{0xc3};
    const auto call_clobber_image = memory_image(std::move(call_clobber));
    const auto call_clobber_functions = recover_functions(*call_clobber_image, {}, {}, {}, {}).value();
    const auto call_clobber_references =
        derive_references(*call_clobber_image, *call_clobber_functions, {}, {}, {}).value();
    const auto after_call = call_clobber_references->outgoing(Address{{0}, 0x100f}, {}).value();
    check(after_call.total == 1 && std::holds_alternative<UnresolvedTarget>(after_call.rows[0].target),
          "unknown x86-64 calls invalidate caller-saved indirect target facts");

    // A register-indirect jump through a readable pointer slot is resolved
    // only when both the slot and the decoded destination are mapped safely.
    auto pointer_slot = bytes({0x48, 0xb8, 0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x48, 0xb9, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x48, 0x8b, 0x14, 0xc8, 0xff, 0xe2, 0xc3}); // mov rdx,[rax+rcx*8]; jmp rdx
    pointer_slot.resize(0x39, std::byte{0x90});
    const std::uint64_t slot_target = 0x1038;
    for (unsigned i = 0; i < 8; ++i)
        pointer_slot[0x28 + i] = std::byte((slot_target >> (i * 8)) & 0xff);
    pointer_slot[0x38] = std::byte{0xc3};
    const auto pointer_slot_image = memory_image(std::move(pointer_slot));
    const auto pointer_slot_functions = recover_functions(*pointer_slot_image, {}, {}, {}, {}).value();
    const auto pointer_slot_references = derive_references(*pointer_slot_image, *pointer_slot_functions, {}, {}, {}).value();
    const auto load_reference = pointer_slot_references->outgoing(Address{{0}, 0x1014}, {}).value();
    const auto *slot_location = load_reference.rows.empty() ? nullptr : std::get_if<Location>(&load_reference.rows[0].target);
    const auto indirect_jump = pointer_slot_references->outgoing(Address{{0}, 0x1018}, {}).value();
    const auto *slot_target_location = indirect_jump.rows.empty() ? nullptr : std::get_if<Location>(&indirect_jump.rows[0].target);
    check(load_reference.total == 1 && slot_location && *slot_location == Location{Address{{0}, 0x1028}} &&
              indirect_jump.total == 1 && slot_target_location && *slot_target_location == Location{Address{{0}, 0x1038}},
          "x86-64 readable pointer slots resolve memory references and indirect jumps with mapped executable targets");
}
std::shared_ptr<const Image> riscv_reference_image(unsigned xlen, bool data_readable = true,
                                                   bool data_writable = true, std::uint32_t high = 1) {
    const auto word = [](std::uint32_t value) {
        return bytes({value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, value >> 24});
    };
    std::vector<std::byte> data;
    const auto append = [&](std::uint32_t value) {
        auto encoded = word(value);
        data.insert(data.end(), encoded.begin(), encoded.end());
    };
    append((high << 12) | (5u << 7) | 0x17u); // auipc x5, high
    append((5u << 15) | (5u << 7) | 0x13u); // addi x5, x5, 0
    if (xlen == 64) {
        append(0x0082b303u); // ld x6, 8(x5)
        append(0x00c2b823u); // sd x6, 16(x5)
    } else {
        append(0x0082a303u); // lw x6, 8(x5)
        append(0x0062a823u); // sw x6, 16(x5)
    }
    append(0x00008067u); // ret
    data.resize(36);
    auto storage = std::make_shared<MemoryStorage>(std::move(data));
    const auto architecture = xlen == 64 ? Architecture::riscv64 : Architecture::riscv32;
    const auto mode = xlen == 64 ? ExecutionMode::rv64 : ExecutionMode::rv32;
    const Address entry{{0}, 0x1000};
    ImageLayout layout{{{0}, static_cast<std::uint8_t>(xlen), 1, ByteOrder::little}, architecture, mode,
        {{"text", entry, 20, {0}, 20, true, false, true},
         {"data", {{0}, 0x2000}, 32, {20}, 16, data_readable, data_writable, false}}, {entry}};
    return Image::create(storage, std::move(layout)).value();
}
void riscv_data_reference_tests() {
    for (const auto xlen : {32u, 64u}) {
        const auto image = riscv_reference_image(xlen);
        const auto functions = recover_functions(*image, {}, {}, {}, {}).value();
        const auto references = derive_references(*image, *functions, {}, {}, {}).value();
        const auto expected_load = Address{{0}, 0x2008};
        const auto expected_store = Address{{0}, 0x2010};
        const auto incoming = references->incoming(expected_load, {}).value();
        const auto outgoing = references->outgoing(Address{{0}, 0x1008}, {}).value();
        check(references->all().size() == 4 && references->complete(),
              "RISC-V PC-relative address formation and memory accesses produce complete typed references");
        check(references->incoming(Address{{0}, 0x2000}, {}).value().total == 2,
              "AUIPC and ADDI address formation are indexed at their mapped PC-relative target");
        check(incoming.total == 1 && incoming.rows[0].kind == ReferenceKind::memory_read &&
                  incoming.rows[0].source == Location{Address{{0}, 0x1008}} &&
                  outgoing.total == 1 && std::get<Location>(outgoing.rows[0].target) == Location{expected_load},
              "RISC-V load resolves through its block-local AUIPC/ADDI chain and indexes the data target");
        const auto store = references->outgoing(Address{{0}, 0x100c}, {}).value();
        check(store.total == 1 && store.rows[0].kind == ReferenceKind::memory_write &&
                  std::get<Location>(store.rows[0].target) == Location{expected_store} &&
                  references->incoming(expected_store, {}).value().total == 1,
              "RISC-V store resolves and indexes a separate writable data target");
        check(roundtrip(*references)->incoming(expected_load, {}).value().total == 1,
              "RISC-V indexed references survive canonical cache roundtrip");
    }
    auto readonly = riscv_reference_image(64, true, false);
    auto functions = recover_functions(*readonly, {}, {}, {}, {}).value();
    auto references = derive_references(*readonly, *functions, {}, {}, {}).value();
    const auto store = references->outgoing(Address{{0}, 0x100c}, {}).value();
    check(store.total == 1 && std::holds_alternative<UnresolvedTarget>(store.rows[0].target),
          "RISC-V store into read-only mapped data is preserved as unresolved, not a validated target");
    auto writeonly = riscv_reference_image(64, false, true);
    functions = recover_functions(*writeonly, {}, {}, {}, {}).value();
    references = derive_references(*writeonly, *functions, {}, {}, {}).value();
    const auto load = references->outgoing(Address{{0}, 0x1008}, {}).value();
    check(load.total == 1 && std::holds_alternative<UnresolvedTarget>(load.rows[0].target),
          "RISC-V load from unreadable mapped data remains unresolved");
    auto unmapped = riscv_reference_image(64, true, true, 2);
    functions = recover_functions(*unmapped, {}, {}, {}, {}).value();
    references = derive_references(*unmapped, *functions, {}, {}, {}).value();
    check(references->incoming(Address{{0}, 0x3000}, {}).value().total == 0 &&
              std::holds_alternative<UnresolvedTarget>(references->outgoing(Address{{0}, 0x1008}, {}).value().rows[0].target),
          "RISC-V PC-relative calculations outside declared mappings never fabricate incoming references");
    auto nonexec = riscv_reference_image(64);
    const auto source = nonexec->storage()->read_at({0}, 36).value().bytes;
    auto storage = std::make_shared<MemoryStorage>(std::vector<std::byte>(source.begin(), source.end()));
    auto layout = nonexec->layout();
    layout.segments[0].executable = false;
    nonexec = Image::create(storage, std::move(layout)).value();
    functions = recover_functions(*nonexec, {}, {}, {}, {}).value();
    references = derive_references(*nonexec, *functions, {}, {}, {}).value();
    check(references->all().empty(), "RISC-V references are not recovered from non-executable source bytes");
}
std::shared_ptr<const Image> architecture_image(Architecture architecture, ExecutionMode mode, std::uint8_t width,
                                                std::vector<std::byte> code, Address entry,
                                                Address data_address, std::vector<std::byte> data,
                                                bool readable = true, bool writable = true) {
    const auto code_size = code.size();
    const auto data_size = data.size();
    code.insert(code.end(), data.begin(), data.end());
    auto storage = std::make_shared<MemoryStorage>(std::move(code));
    ImageLayout layout{{{0}, width, 1, ByteOrder::little}, architecture, mode,
                       {{"text", entry, code_size, {0}, code_size, true, false, true},
                        {"data", data_address, data_size, {code_size}, data_size, readable, writable, false}},
                       {entry}};
    return Image::create(storage, std::move(layout)).value();
}
void additional_architecture_reference_tests() {
    // A64 ADRP x0, #0x1000; ADD x0, x0, #8; LDR x1, [x0]; RET.
    auto image = architecture_image(Architecture::arm64, ExecutionMode::a64, 64,
                                    bytes({0, 0, 0, 0xb0, 0, 0x20, 0, 0x91, 1, 0, 0x40, 0xf9,
                                           0xc0, 0x03, 0x5f, 0xd6}),
                                    {{0}, 0x1000}, {{0}, 0x2000},
                                    bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));
    auto functions = recover_functions(*image, {}, {}, {}, {}).value();
    auto references = derive_references(*image, *functions, {}, {}, {}).value();
    auto outgoing = references->outgoing(Address{{0}, 0x1008}, {}).value();
    check(outgoing.total == 1 && outgoing.rows[0].kind == ReferenceKind::memory_read &&
              std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x2008}},
          "A64 ADRP-derived base resolves a mapped load target");
    image = architecture_image(Architecture::arm64, ExecutionMode::a64, 64,
                               bytes({0, 0, 0, 0xb0, 1, 0, 0, 0x14, 0, 0x20, 0, 0x91,
                                      1, 0, 0x40, 0xf9, 0xc0, 3, 0x5f, 0xd6}),
                               {{0}, 0x1000}, {{0}, 0x2000},
                               bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x100c}, {}).value();
    check(outgoing.total == 1 && outgoing.rows[0].kind == ReferenceKind::memory_read &&
              std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x2008}},
          "A64 ADRP/ADD address propagation crosses an unconditional basic-block edge");
    image = architecture_image(Architecture::arm64, ExecutionMode::a64, 64,
                               bytes({0, 0, 0, 0xb0, 0x61, 0, 0, 0xb4, 0x1f, 0x20, 3, 0xd5,
                                      2, 0, 0, 0x14, 0x1f, 0x20, 3, 0xd5, 2, 0, 0x40, 0xf9,
                                      0xc0, 3, 0x5f, 0xd6}),
                               {{0}, 0x1000}, {{0}, 0x2000},
                               bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1014}, {}).value();
    check(outgoing.total == 1 && outgoing.rows[0].kind == ReferenceKind::memory_read &&
              std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x2000}},
          "A64 register values that agree at a control-flow merge resolve subsequent loads");
    image = architecture_image(Architecture::arm64, ExecutionMode::a64, 64,
                               bytes({0, 0, 0, 0xb0, 0x61, 0, 0, 0xb4, 0x1f, 0x20, 3, 0xd5,
                                      2, 0, 0, 0x14, 0, 0, 0, 0xd0, 2, 0, 0x40, 0xf9,
                                      0xc0, 3, 0x5f, 0xd6}),
                               {{0}, 0x1000}, {{0}, 0x2000},
                               bytes({1, 2, 3, 4, 5, 6, 7, 8}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1014}, {}).value();
    check(outgoing.total == 1 && std::holds_alternative<UnresolvedTarget>(outgoing.rows[0].target),
          "A64 register values that disagree at a control-flow merge remain unresolved");
    auto unavailable = architecture_image(
        Architecture::arm64, ExecutionMode::a64, 64,
        bytes({0, 0, 0, 0xb0, 0, 0x20, 0, 0x91, 1, 0, 0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6}),
        {{0}, 0x1000}, {{0}, 0x2000}, bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
        false, true);
    functions = recover_functions(*unavailable, {}, {}, {}, {}).value();
    references = derive_references(*unavailable, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1008}, {}).value();
    check(outgoing.total == 1 && std::holds_alternative<UnresolvedTarget>(outgoing.rows[0].target),
          "A64 load into unreadable data remains unresolved");

    // LUI t0, 1; ADDIU t0, t0, 0x1000; LW t1, 8(t0); JR ra; delay-slot NOP.
    image = architecture_image(Architecture::mips32, ExecutionMode::mips32, 32,
                               bytes({1, 0, 0x05, 0x3c, 0, 0x10, 0xa5, 0x24, 8, 0, 0xa6, 0x8c,
                                      8, 0, 0xe0, 0x03, 0, 0, 0, 0}),
                               {{0}, 0x1000}, {{0}, 0x11000}, bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));
    auto recovered = recover_functions(*image, {}, {}, {}, {});
    if (!recovered) {
        std::cerr << "MIPS recover: " << recovered.error().message << '\n';
        check(false, "MIPS32 reference fixture recovers");
        return;
    }
    functions = recovered.value();
    auto derived = derive_references(*image, *functions, {}, {}, {});
    if (!derived) {
        std::cerr << "MIPS references: " << derived.error().message << '\n';
        check(false, "MIPS32 references derive");
        return;
    }
    references = derived.value();
    outgoing = references->outgoing(Address{{0}, 0x1008}, {}).value();
    check(outgoing.total == 1 && outgoing.rows[0].kind == ReferenceKind::memory_read &&
              std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x11008}},
          "MIPS32 LUI/ADDIU-derived base resolves a mapped load target");
    check(roundtrip(*references)->all().size() == references->all().size(),
          "MIPS GPR expressions and derived references survive reference-index roundtrip");
    // Address construction remains valid through a branch and its delay slot.
    // The target block is only resolvable if its predecessor output is carried
    // across the CFG edge (the current block-local pass loses the LUI value).
    image = architecture_image(Architecture::mips32, ExecutionMode::mips32, 32,
                               bytes({1, 0, 0x05, 0x3c, 0, 0x10, 0xa5, 0x24,
                                      1, 0, 0, 0x10, 0, 0, 0, 0,
                                      8, 0, 0xa6, 0x8c, 8, 0, 0xe0, 0x03, 0, 0, 0, 0}),
                               {{0}, 0x1000}, {{0}, 0x11000},
                               bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1010}, {}).value();
    check(outgoing.total == 1 && std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x11008}} &&
              references->incoming(Address{{0}, 0x11008}, {}).value().total == 1,
          "MIPS32 pointer facts cross a recovered branch edge and populate the incoming index");
    unavailable = architecture_image(
        Architecture::mips32, ExecutionMode::mips32, 32,
        bytes({1, 0, 0x05, 0x3c, 0, 0x10, 0xa5, 0x24, 8, 0, 0xa6, 0x8c, 8, 0, 0xe0, 0x03, 0, 0, 0, 0}),
        {{0}, 0x1000}, {{0}, 0x11000}, bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
        false, true);
    functions = recover_functions(*unavailable, {}, {}, {}, {}).value();
    references = derive_references(*unavailable, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1008}, {}).value();
    check(outgoing.total == 1 && std::holds_alternative<UnresolvedTarget>(outgoing.rows[0].target),
          "MIPS32 load into unreadable data remains unresolved");

    // A32 LDR r0, [pc, #0]; BX lr. The effective PC is instruction address + 8.
    image = architecture_image(Architecture::arm, ExecutionMode::a32, 32,
                               bytes({0, 0, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1}),
                               {{0}, 0x1000}, {{0}, 0x1008}, bytes({1, 2, 3, 4}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(outgoing.total == 1 && outgoing.rows[0].kind == ReferenceKind::memory_read &&
              std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x1008}},
          "A32 PC-relative load produces a mapped data reference");
    check(roundtrip(*references)->all().size() == references->all().size(),
          "A32 register-indirect control expressions survive reference-index roundtrip");

    // Thumb LDR r0, [pc, #4]; BX lr. Literal base is Align(PC+4, 4).
    auto thumb_bytes = bytes({0x01, 0x48, 0x70, 0x47, 1, 2, 3, 4});
    auto thumb_storage = std::make_shared<MemoryStorage>(std::move(thumb_bytes));
    const ArmContextSource thumb_source{ArmContextSourceKind::raw_declaration, 1, 1, {}};
    ImageLayout thumb_layout{{{0}, 32, 1, ByteOrder::little}, Architecture::arm, ExecutionMode::unknown,
                             {{"thumb-text", {{0}, 0x1000}, 4, {0}, 4, true, false, true},
                              {"thumb-data", {{0}, 0x1008}, 4, {4}, 4, true, false, false}},
                             {{{0}, 0x1000}}};
    thumb_layout.arm_profile = ArmImageProfile{
        {ArmCodeRange{Address{{0}, 0x1000}, 4, ArmCodeKind::thumb, {thumb_source}}},
        {ArmCodeRoot{Address{{0}, 0x1000}, ExecutionMode::thumb, true, {thumb_source}}}};
    image = Image::create(thumb_storage, std::move(thumb_layout)).value();
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(outgoing.total == 1 && outgoing.rows[0].kind == ReferenceKind::memory_read &&
              std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x1008}},
          "Thumb PC-relative literal load produces a mapped data reference");

    image = architecture_image(Architecture::arm, ExecutionMode::a32, 32,
                               bytes({0x04, 0x10, 0x8f, 0xe2, 0x00, 0x00, 0x91, 0xe5,
                                      0x1e, 0xff, 0x2f, 0xe1}),
                               {{0}, 0x1000}, {{0}, 0x100c}, bytes({1, 2, 3, 4}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1004}, {}).value();
    check(outgoing.total == 1 && std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x100c}},
          "A32 ADR-style ADD propagates PC+8 through a base register into a mapped load");
    image = architecture_image(Architecture::arm, ExecutionMode::a32, 32,
                               bytes({0x08, 0x10, 0x8f, 0xe2, 0x00, 0x10, 0xa0, 0xe3,
                                      0x00, 0x00, 0x91, 0xe5, 0x1e, 0xff, 0x2f, 0xe1}),
                               {{0}, 0x1000}, {{0}, 0x1010}, bytes({1, 2, 3, 4}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    outgoing = references->outgoing(Address{{0}, 0x1008}, {}).value();
    check(outgoing.total == 1 && std::holds_alternative<UnresolvedTarget>(outgoing.rows[0].target),
          "unsupported A32 writes kill tracked address values instead of fabricating a target");

    auto propagated_thumb = bytes({0x01, 0xa1, 0x08, 0x68, 0x70, 0x47});
    const auto propagated_data = bytes({1, 2, 3, 4});
    propagated_thumb.insert(propagated_thumb.end(), propagated_data.begin(), propagated_data.end());
    auto propagated_storage = std::make_shared<MemoryStorage>(std::move(propagated_thumb));
    ImageLayout propagated_layout{{{0}, 32, 1, ByteOrder::little}, Architecture::arm, ExecutionMode::unknown,
                                  {{"thumb-text", {{0}, 0x1000}, 6, {0}, 6, true, false, true},
                                   {"thumb-data", {{0}, 0x1008}, 4, {6}, 4, true, false, false}},
                                  {{{0}, 0x1000}}};
    propagated_layout.arm_profile = ArmImageProfile{
        {ArmCodeRange{Address{{0}, 0x1000}, 6, ArmCodeKind::thumb, {thumb_source}}},
        {ArmCodeRoot{Address{{0}, 0x1000}, ExecutionMode::thumb, true, {thumb_source}}}};
    const auto propagated_image = Image::create(propagated_storage, std::move(propagated_layout));
    check(bool(propagated_image), propagated_image ? "Thumb propagation image fixture is valid"
                                                  : propagated_image.error().message.c_str());
    if (!propagated_image)
        return;
    image = propagated_image.value();
    const auto propagated_functions = recover_functions(*image, {}, {}, {}, {});
    check(bool(propagated_functions), "Thumb propagation function recovery succeeds");
    if (!propagated_functions)
        return;
    functions = propagated_functions.value();
    const auto propagated_references = derive_references(*image, *functions, {}, {}, {});
    check(bool(propagated_references), "Thumb propagation reference analysis succeeds");
    if (!propagated_references)
        return;
    references = propagated_references.value();
    outgoing = references->outgoing(Address{{0}, 0x1002}, {}).value();
    check(outgoing.total == 1 && std::holds_alternative<Location>(outgoing.rows[0].target) &&
              std::get<Location>(outgoing.rows[0].target) == Location{Address{{0}, 0x1008}},
          "Thumb ADR propagates its aligned PC-relative target through a base register");

    // 6502 LDA $2000; STA $2001; RTS.
    image = architecture_image(Architecture::mos6502, ExecutionMode::m6502, 16,
                               bytes({0xad, 0, 0x20, 0x8d, 1, 0x20, 0x60}),
                               {{0}, 0x1000}, {{0}, 0x2000}, bytes({0, 0}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    const auto load = references->outgoing(Address{{0}, 0x1000}, {}).value();
    const auto store = references->outgoing(Address{{0}, 0x1003}, {}).value();
    check(load.total == 1 && load.rows[0].kind == ReferenceKind::memory_read &&
              std::holds_alternative<Location>(load.rows[0].target) &&
              std::get<Location>(load.rows[0].target) == Location{Address{{0}, 0x2000}} &&
              store.total == 1 && store.rows[0].kind == ReferenceKind::memory_write &&
              std::holds_alternative<Location>(store.rows[0].target) &&
              std::get<Location>(store.rows[0].target) == Location{Address{{0}, 0x2001}},
          "6502 absolute load/store references retain their memory access direction");
    image = architecture_image(Architecture::mos6502, ExecutionMode::m6502, 16,
                               bytes({0xbd, 0, 0x20, 0x60}), {{0}, 0x1000}, {{0}, 0x2000}, bytes({0, 0}));
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    const auto indexed = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(indexed.total == 1 && std::holds_alternative<UnresolvedTarget>(indexed.rows[0].target),
          "6502 indexed absolute address is retained as unresolved without register-value proof");
}
std::shared_ptr<const Image> x86_data_reference_image(bool readable, bool writable, std::uint64_t data_size = 8,
                                                       std::uint64_t displacement = 0xff9,
                                                       std::uint64_t code_base = 0x1000, bool store = false) {
    std::vector<std::byte> code = bytes({0x48u, store ? 0x89u : 0x8bu, 0x05u, static_cast<unsigned>(displacement & 0xff),
                                         static_cast<unsigned>((displacement >> 8) & 0xff),
                                         static_cast<unsigned>((displacement >> 16) & 0xff),
                                         static_cast<unsigned>((displacement >> 24) & 0xff), 0xc3u});
    auto storage = std::make_shared<MemoryStorage>(std::move(code));
    ImageLayout layout{{{0}, 64, 1, ByteOrder::little}, Architecture::x86_64, ExecutionMode::x86_64,
        {{"text", {{0}, code_base}, 8, {0}, 8, true, false, true},
         {"data", {{0}, 0x2000}, data_size, {0}, 0, readable, writable, false}}, {{{0}, code_base}}};
    return Image::create(storage, std::move(layout)).value();
}
void x86_checked_memory_target_tests() {
    auto image = x86_data_reference_image(true, false);
    auto functions = recover_functions(*image, {}, {}, {}, {}).value();
    auto references = derive_references(*image, *functions, {}, {}, {}).value();
    auto row = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(row.total == 1 && std::get<Location>(row.rows[0].target) == Location{Address{{0}, 0x2000}},
          "x86 RIP-relative load resolves across a complete readable target range");
    image = x86_data_reference_image(false, true, 8, 0xff9, 0x1000, true);
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    row = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(row.total == 1 && std::get<Location>(row.rows[0].target) == Location{Address{{0}, 0x2000}},
          "x86 RIP-relative store resolves across a complete writable target range");
    image = x86_data_reference_image(true, false, 8, 0xff9, 0x1000, true);
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    row = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(row.total == 1 && std::holds_alternative<UnresolvedTarget>(row.rows[0].target),
          "x86 store into read-only mapped data remains unresolved");
    image = x86_data_reference_image(false, true);
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    row = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(row.total == 1 && std::holds_alternative<UnresolvedTarget>(row.rows[0].target),
          "x86 load into unreadable mapped data remains unresolved");
    image = x86_data_reference_image(true, false, 7);
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    row = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(row.total == 1 && std::holds_alternative<UnresolvedTarget>(row.rows[0].target),
          "x86 load crossing the mapped range boundary remains unresolved");
    image = x86_data_reference_image(true, true, 8, 0x1ff9);
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    row = references->outgoing(Address{{0}, 0x1000}, {}).value();
    check(row.total == 1 && std::holds_alternative<UnresolvedTarget>(row.rows[0].target),
          "x86 load into an unmapped address remains unresolved");
    const auto near_limit = UINT64_MAX - 10;
    image = x86_data_reference_image(true, true, 8, 8, near_limit);
    functions = recover_functions(*image, {}, {}, {}, {}).value();
    references = derive_references(*image, *functions, {}, {}, {}).value();
    row = references->outgoing(Address{{0}, near_limit}, {}).value();
    check(row.total == 1 && std::holds_alternative<UnresolvedTarget>(row.rows[0].target),
          "x86 RIP-relative addition overflow never wraps into a fabricated target");
}
void flow_tests() {
    auto functions = recover_functions(*memory_image(bytes({0xe8, 1, 0, 0, 0, 0xc3, 0xc3})), {}, {}, {}, {}).value();
    auto references = derive_references(*functions, {}, {}, {}).value();
    auto target = references->incoming(Address{{0}, 0x1006}, {}).value();
    check(target.total == 1 && target.rows[0].kind == ReferenceKind::call &&
              target.rows[0].source == Location{Address{{0}, 0x1000}},
          "direct call reference points at callee entry");
    functions = recover_functions(*memory_image(bytes({0x74, 3, 0x90, 0xeb, 1, 0x90, 0xc3})), {}, {}, {}, {}).value();
    references = derive_references(*functions, {}, {}, {}).value();
    check(references->all().size() == 2 &&
              references->outgoing(Address{{0}, 0x1000}, {}).value().rows[0].kind == ReferenceKind::conditional_jump &&
              references->outgoing(Address{{0}, 0x1003}, {}).value().rows[0].kind == ReferenceKind::jump,
          "conditional and unconditional transfers remain distinct without implicit-flow noise");
    functions = recover_functions(*memory_image(bytes({0xff, 0xe0})), {}, {}, {}, {}).value();
    references = derive_references(*functions, {}, {}, {}).value();
    check(references->all().size() == 1 && std::holds_alternative<UnresolvedTarget>(references->all()[0].target) &&
              references->unresolved_count() == 1,
          "register-indirect jump retains an unresolved expression");
}
void segment_tests() {
    auto data = bytes({0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,    0x65, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x64,
                       0x48, 0x8d, 0x04, 0x25, 0,    0, 0, 0, 0x48, 0xb8, 0x40, 0x10, 0,    0,    0, 0, 0, 0, 0xc3});
    auto functions = recover_functions(*memory_image(data), {}, {}, {}, {}).value();
    auto references = derive_references(*functions, {}, {}, {}).value();
    check(references->all().size() == 3 && references->unresolved_count() == 2,
          "FS and GS loads remain unresolved and a large immediate creates no pointer reference");
    check(roundtrip(*references)->unresolved_count() == 2, "segment-dependent unresolved cache records survive reload");
    auto lea = references->incoming(Address{{0}, 0}, {}).value();
    check(lea.total == 1 && lea.rows[0].kind == ReferenceKind::memory_address &&
              lea.rows[0].source == Location{Address{{0}, 0x1012}},
          "ignored LEA segment prefix preserves the corrected absolute-address dependency");
    functions = recover_functions(*memory_image(bytes({0x0f, 0x1f, 0x05, 0, 0, 0, 0, 0xc3})), {}, {}, {}, {}).value();
    references = derive_references(*functions, {}, {}, {}).value();
    check(references->all().empty(), "syntactic memory operand of multi-byte NOP creates no memory/address reference");
}
void import_and_user_tests() {
    auto data = bytes({0xff, 0x15, 0x3a, 0, 0, 0, 0xc3});
    data.resize(128);
    ImageMetadata metadata;
    metadata.imports.push_back({"fixture.dll", "Target", {}, {{0}, 0x1040}, {{0}, 0x1040}});
    auto functions = recover_functions(*memory_image(data), metadata, {}, {}, {}).value();
    auto references = derive_references(*functions, metadata, {}, {}).value();
    auto outgoing = references->outgoing(Address{{0}, 0x1000}, {}).value();
    auto imported = std::find_if(outgoing.rows.begin(), outgoing.rows.end(),
                                 [](const auto &value) { return value.kind == ReferenceKind::imported_call; });
    check(outgoing.total == 2 && imported != outgoing.rows.end() &&
              std::holds_alternative<ExternalIdentity>(imported->target),
          "imported call identifies an external symbol separately from the IAT memory read");
    if (imported != outgoing.rows.end())
        check(references->incoming_external(std::get<ExternalIdentity>(imported->target), {}).value().total == 1 &&
                  references->incoming(Address{{0}, 0x1040}, {}).value().total == 2,
              "external and IAT-associated incoming indexes retain the same control reference");
    AnalysisDecisions decisions;
    decisions.references = {{10, FileOffset{0}, Address{{0}, 0x1040}, UserReferenceKind::data},
                            {11, Address{{0}, 0x1000}, Address{{0}, 0x1040}, UserReferenceKind::address}};
    references = derive_references(*functions, metadata, decisions, {}).value();
    check(references->outgoing(FileOffset{0}, {}).value().total == 1 &&
              references->outgoing(Address{{0}, 0}, {}).value().total == 0,
          "user file-offset sources retain their domain without fabricated virtual addresses");
    check(references->incoming(Address{{0}, 0x1040}, {}).value().total == 4,
          "repeated targets preserve independent decoded import and user evidence");
    check(roundtrip(*references)->outgoing(FileOffset{0}, {}).value().total == 1,
          "external and explicit file-domain records survive reload");
    metadata.imports[0].name.reset();
    metadata.imports[0].ordinal = uint16_t{7};
    references = derive_references(*functions, metadata, {}, {}).value();
    ExternalIdentity ordinal{"fixture.dll", {}, uint16_t{7}};
    check(roundtrip(*references)->incoming_external(ordinal, {}).value().total == 1,
          "ordinal import identity round trips without a fabricated symbol name");
    metadata.imports.push_back({"other.dll", "Different", {}, {{0}, 0x1040}, {{0}, 0x1040}});
    references = derive_references(*functions, metadata, {}, {}).value();
    check(references->unresolved_count() == 1 && references->incoming_external(ordinal, {}).value().total == 0,
          "conflicting IAT declarations do not arbitrarily select one external target");
    (void)roundtrip(*references);
}
void codec_tests() {
    auto functions = recover_functions(*memory_image(memory_reference_fixture()), {}, {}, {}, {}).value();
    auto references = derive_references(*functions, {}, {}, {}).value();
    auto encoded = encode_reference_index(*references, {}).value();
    auto restored = decode_reference_index(encoded, {}).value();
    check(encode_reference_index(*restored, {}).value() == encoded &&
              restored->incoming(Address{{0}, 0x1040}, {}).value().total == 4,
          "reference cache codec round trips canonical records and indexes");
    for (size_t i = 0; i < encoded.size(); ++i)
        check(!decode_reference_index(std::span(encoded).first(i), {}),
              "every truncated reference payload is rejected");
    auto bad = encoded;
    bad[0] = std::byte{99};
    check(!decode_reference_index(bad, {}), "unknown reference payload version rejected");
    bad = encoded;
    bad.push_back(std::byte{0});
    check(!decode_reference_index(bad, {}), "trailing reference payload rejected");
    auto hostile = bytes({2, 0, 0, 1, 255, 255, 255, 255});
    Sha256 checksum;
    check(bool(checksum.update(hostile)), "hostile-count checksum constructed independently");
    auto digest = checksum.digest();
    hostile.insert(hostile.end(), digest.begin(), digest.end());
    check(!decode_reference_index(hostile, {}), "valid checksum cannot bypass a hostile record count bound");
    std::vector<Reference> invalid(references->all().begin(), references->all().end());
    invalid[0].kind = static_cast<ReferenceKind>(99);
    check(!ReferenceIndex::create(std::move(invalid), {}, true, {}), "unknown reference kind rejected before indexing");
    invalid.assign(references->all().begin(), references->all().end());
    invalid[0].id = {0};
    invalid[0].association = Location{FileOffset{7}};
    check(!ReferenceIndex::create(std::move(invalid), {}, true, {}),
          "data reference cannot acquire an unrelated indirect-control slot association");
    std::stop_source stop;
    stop.request_stop();
    check(!derive_references(*functions, {}, {}, stop.get_token()) &&
              !decode_reference_index(encoded, stop.get_token()),
          "reference derivation and decoding observe cancellation");
    functions = recover_functions(*memory_image(bytes({0xff, 0xe0})), {}, {}, {}, {}).value();
    references = derive_references(*functions, {}, {}, {}).value();
    (void)roundtrip(*references);
    functions = recover_functions(*memory_image(bytes({0xeb, 0x7f}), UINT64_MAX - 16), {}, {}, {}, {}).value();
    references = derive_references(*functions, {}, {}, {}).value();
    check(roundtrip(*references)->unresolved_count() == 1,
          "overflowing relative targets retain their signed expression");
    MemoryOperand memory;
    memory.data_width = 64;
    memory.base = RegisterOperand{RegisterBank::gpr, 0, 64, false};
    memory.displacement = INT64_MIN;
    std::vector<Reference> extremes{{{0},
                                     Address{{0}, 0x1000},
                                     0u,
                                     UnresolvedTarget{UnresolvedReason::memory_address, memory},
                                     ReferenceKind::memory_read,
                                     OperandAccess::read,
                                     {ReferenceProvenanceKind::decoded, 1, 0},
                                     {}},
                                    {{0},
                                     FileOffset{UINT64_MAX},
                                     {},
                                     Location{Address{{UINT32_MAX}, UINT64_MAX}},
                                     ReferenceKind::user_data,
                                     OperandAccess::address,
                                     {ReferenceProvenanceKind::user, 0, 23},
                                     {}}};
    references = ReferenceIndex::create(std::move(extremes), {}, true, {}).value();
    auto restored_extremes = roundtrip(*references);
    const auto extreme_page = restored_extremes->outgoing(Address{{0}, 0x1000}, {}).value();
    const auto &expression = std::get<UnresolvedTarget>(extreme_page.rows[0].target);
    check(std::get<MemoryOperand>(expression.expression).displacement == INT64_MIN &&
              restored_extremes->incoming(Address{{UINT32_MAX}, UINT64_MAX}, {}).value().total == 1,
          "full unsigned locations and minimum signed displacement preserve exact bits");
}
void context_expression_tests() {
    Reference relative{
        {0},
        Address{{0}, 0x1000},
        0u,
        UnresolvedTarget{UnresolvedReason::relative_overflow, RelativeOperand{-4, 32, 64, EncodedField{2, 4}}},
        ReferenceKind::jump,
        OperandAccess::address,
        {ReferenceProvenanceKind::decoded, 1, 0},
        {}};
    auto source = ReferenceIndex::create({relative}, {}, false, {});
    check(bool(source), "explicit relative context fixture is valid");
    if (!source)
        return;
    auto restored = roundtrip(*source.value());
    auto expression = std::get<UnresolvedTarget>(restored->all()[0].target).expression;
    check(std::get<RelativeOperand>(expression).effective_width == 64,
          "reference codec preserves effective relative width instead of losing it to unknown");
    check(std::get<RelativeOperand>(expression).encoding == EncodedField{2, 4},
          "reference codec retains relative expression encoding provenance");
    MemoryOperand memory;
    memory.data_width = 32;
    memory.address_width = 16;
    memory.base = RegisterOperand{RegisterBank::gpr, 3, 16, false};
    memory.index = RegisterOperand{RegisterBank::gpr, 6, 16, false};
    memory.displacement_encoding = EncodedField{3, 2};
    relative.id = {0};
    relative.target = UnresolvedTarget{UnresolvedReason::memory_value, memory};
    relative.kind = ReferenceKind::call;
    relative.access = OperandAccess::address;
    auto legacy = ReferenceIndex::create({relative}, {}, false, {});
    check(bool(legacy), "16-bit effective-address expression is accepted in a legacy-32 reference");
    if (legacy) {
        auto again = roundtrip(*legacy.value());
        auto m = std::get<MemoryOperand>(std::get<UnresolvedTarget>(again->all()[0].target).expression);
        check(m.address_width == 16 && m.base == memory.base && m.index == memory.index,
              "legacy-32 address override survives canonical reference serialization");
        check(m.displacement_encoding == memory.displacement_encoding,
              "reference codec retains memory displacement encoding provenance");
    }
    relative.target = UnresolvedTarget{UnresolvedReason::far_selector,
                                       FarPointerOperand{8, 0x12345678, 32, EncodedField{1, 4}, EncodedField{5, 2}}};
    auto far = ReferenceIndex::create({relative}, {}, false, {}).value();
    auto pointer = std::get<FarPointerOperand>(std::get<UnresolvedTarget>(roundtrip(*far)->all()[0].target).expression);
    check(pointer.offset_encoding == EncodedField{1, 4} && pointer.selector_encoding == EncodedField{5, 2},
          "reference codec retains both far immediate field spans");
    memory.displacement_encoding = EncodedField{15, 1};
    relative.target = UnresolvedTarget{UnresolvedReason::memory_value, memory};
    check(!ReferenceIndex::create({relative}, {}, false, {}),
          "reference expression field cannot exceed architectural instruction length");
}
void ordinary_identity_tests(const std::filesystem::path &path) {
    const auto source = FileStorage::open(path).value();
    check(source->size() == 101, "genuine prior ordinary reference payload retains original extent");
    const auto old = source->read_at({0}, 101).value();
    Sha256 hash;
    hash.update(old.bytes).value();
    check(digest_hex(hash.digest()) == "7904c4517c648d670da47d2447e45bc99ad7d0bcd3949d0ac08390d3a4b1a4cb" &&
              old.bytes[0] == std::byte{3},
          "genuine prior payload3 reference fixture matches captured producer bytes");
    check(!decode_reference_index(old.bytes, {}),
          "old reference schema requires recomputation instead of interpreting new provenance records");
    auto image = memory_image(bytes({0xe8, 1, 0, 0, 0, 0xc3, 0xc3}));
    auto functions = recover_functions(*image, {}, {}, {}, {}).value();
    auto index = derive_references(*image, *functions, {}, {}, {}).value();
    check(index->all().size() == 1 && index->all()[0].id.value == UINT64_C(0x824defe0d5a68707),
          "adding ELF origins preserves actual prior stable identity for ordinary decoded references");
    const auto wire = encode_reference_index(*index, {}).value();
    check(wire.size() == old.bytes.size() && std::equal(wire.begin() + 2, wire.end() - 32, old.bytes.begin() + 2),
          "ordinary record bytes remain unchanged across the new envelope version");
}
int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    return run([&] {
        memory_tests();
        x86_indirect_target_tests();
        riscv_data_reference_tests();
        additional_architecture_reference_tests();
        x86_checked_memory_target_tests();
        flow_tests();
        segment_tests();
        import_and_user_tests();
        codec_tests();
        context_expression_tests();
        ordinary_identity_tests(std::filesystem::u8path(argv[1]));
    });
}
