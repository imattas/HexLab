#include "hexlab/loaders/elf.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/elf_relocations.hpp"
#include "hexlab/analysis/references.hpp"
#include "hexlab/workspace/listing.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/processors/format.hpp"
#include "support/elf_metadata_fixture.hpp"
#include "support/elf_fixture.hpp"
#include "support/elf_retained_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::elf_metadata_fixture;
namespace {
std::vector<std::byte> fixture(bool wide, bool rela, std::uint32_t type = 2, std::uint32_t index = 1) {
    auto data = relocatable(wide, rela);
    const auto stride = (rela ? 3u : 2u) * (wide ? 8u : 4u);
    section(data, wide, 7, 0, rela ? 4 : 9, 0, 0, relocations_at, stride, wide ? 8 : 4);
    links(data, wide, false, 7, 5, 1, stride);
    symbol(data, wide, false, 4, 21, 0x12, 1, 0, 6);
    relocation(data, wide, rela, false, 0, 1, type, index, UINT64_MAX - 3);
    return data;
}
LoadedImage load(std::vector<std::byte> data) {
    auto result = load_elf(std::make_shared<MemoryStorage>(std::move(data)), {});
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
void recovery() {
    for (bool wide : {false, true})
        for (bool rela : {false, true}) {
            auto loaded = load(fixture(wide, rela));
            auto result = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
            auto call = std::find_if(result->calls.begin(), result->calls.end(),
                                     [](const auto &row) { return row.source == Address{{1}, 0}; });
            check(call != result->calls.end() && call->target == Address{{2}, 0},
                  "defined PC-relative CALL resolves S+A+instruction-end-minus-P in its symbol section domain");
            check(std::none_of(result->functions.begin(), result->functions.end(),
                               [](const auto &row) { return row->entry == Address{{1}, 1}; }),
                  "unlinked CALL displacement cannot seed a false interior function");
            const auto decoded = decode_at(*loaded.image, {{1}, 0}).value().instruction.value();
            check(decoded.direct_target == Address{{1}, 1} && decoded.bytes[1] == std::byte{0xfc},
                  "relocation-aware analysis preserves pure decoder placeholder facts and original bytes");
            for (auto [type, index] : {std::pair{2u, 2u}, std::pair{4u, 1u}, std::pair{254u, 1u}}) {
                loaded = load(fixture(wide, rela, type, index));
                result = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
                call = std::find_if(result->calls.begin(), result->calls.end(),
                                    [](const auto &row) { return row.source == Address{{1}, 0}; });
                check(call != result->calls.end() && !call->target,
                      "undefined, PLT and unknown relocations suppress numeric placeholder call targets");
                check(std::none_of(result->functions.begin(), result->functions.end(),
                                   [](const auto &row) { return row->entry == Address{{1}, 1}; }),
                      "unresolved relocation cannot create a bogus function root");
            }
        }
}
void riscv_elf_flow() {
    auto rv32_data = elf_fixture::executable(false);
    elf_fixture::put(rv32_data, 18, 243, 2); // EM_RISCV
    elf_fixture::put(rv32_data, 24, 0x10000, 4); // ELF32 entry point
    elf_fixture::program(rv32_data, false, 0, 1, 256, 0x10000, 12, 12, 5, 256);
    const auto rv32_code = bytes({0x93, 0x00, 0x50, 0x00, // addi x1, x0, 5
                                  0x63, 0x84, 0x20, 0x00, // beq x1, x2, +8
                                  0x73, 0x00, 0x10, 0x00}); // ebreak
    std::copy(rv32_code.begin(), rv32_code.end(), rv32_data.begin() + 256);
    auto rv32_loaded = load_elf(std::make_shared<MemoryStorage>(rv32_data), {});
    check(rv32_loaded && rv32_loaded.value().image->decode_context() ==
                             DecodeContext{Architecture::riscv32, ExecutionMode::rv32, ByteOrder::little},
          "ELF32 machine 243 selects RV32I mode");
    if (rv32_loaded) {
        const auto rv32_analysis = analyze(*rv32_loaded.value().image, rv32_loaded.value().metadata, {}, {}).value();
        check(rv32_analysis.instructions.size() == 3 && rv32_analysis.instructions[0].opcode == Opcode::rv_addi &&
                  rv32_analysis.instructions[1].opcode == Opcode::rv_beq &&
                  rv32_analysis.instructions[1].direct_target == Address{{0}, 0x1000c},
              "RV32I ELF instructions and direct branch edges enter reachable analysis");
    }
    auto rv32_rvc_data = elf_fixture::executable(false);
    elf_fixture::put(rv32_rvc_data, 18, 243, 2);
    elf_fixture::put(rv32_rvc_data, 24, 0x400000, 4);
    elf_fixture::put(rv32_rvc_data, 36, 1, 4); // EF_RISCV_RVC in ELF32
    auto rv32_rvc = load_elf(std::make_shared<MemoryStorage>(rv32_rvc_data), {});
    check(rv32_rvc && rv32_rvc.value().image->decode_context().architecture == Architecture::riscv32 &&
              rv32_rvc.value().image->decode_context().mode == ExecutionMode::unknown,
          "ELF32 advertising RVC is not misdecoded by the fixed-width RV32I path");
    auto data = elf_fixture::executable(true);
    elf_fixture::put(data, 18, 243, 2); // EM_RISCV
    elf_fixture::program(data, true, 0, 1, 256, 0x400000, 20, 20, 5, 256);
    const auto code = bytes({0x93, 0x00, 0x50, 0x00, // addi x1, x0, 5
                             0x83, 0xb1, 0x00, 0x00, // ld x3, 0(x1)
                             0x63, 0x84, 0x20, 0x00, // beq x1, x2, +8
                             0x73, 0x00, 0x10, 0x00, // ebreak
                             0x67, 0x80, 0x00, 0x00}); // ret
    std::copy(code.begin(), code.end(), data.begin() + 256);
    auto loaded = load_elf(std::make_shared<MemoryStorage>(data), {});
    check(loaded && loaded.value().image->decode_context() ==
                        DecodeContext{Architecture::riscv64, ExecutionMode::rv64, ByteOrder::little},
          "ELF machine 243 selects RV64 mode in the loaded project image");
    if (!loaded)
        return;
    const auto analyzed = analyze(*loaded.value().image, loaded.value().metadata, {}, {}).value();
    check(analyzed.instructions.size() == 5 && analyzed.instructions[0].opcode == Opcode::rv_addi &&
              analyzed.instructions[1].opcode == Opcode::rv_ld && analyzed.instructions[2].opcode == Opcode::rv_beq,
          "RV64 instructions participate in reachable traversal");
    check(analyzed.instructions.size() > 2 && analyzed.instructions[2].direct_target == Address{{0}, 0x400010} &&
              std::any_of(analyzed.edges.begin(), analyzed.edges.end(), [](const auto &edge) {
                  return edge.from == Address{{0}, 0x400008} && edge.kind == EdgeKind::branch &&
                         edge.to == Address{{0}, 0x400010};
              }),
          "RV64 conditional traversal retains the target edge");
    DocumentSnapshot document;
    document.image = loaded.value().image;
    document.metadata = loaded.value().metadata;
    const auto listing = make_listing_page(document, Address{{0}, 0x400000}, 5).value();
    check(listing.rows.size() == 5 && listing.rows[0].instruction &&
              format_instruction(*listing.rows[0].instruction) == "addi x1, x0, 0x5" &&
              listing.rows[1].instruction && format_instruction(*listing.rows[1].instruction) == "ld x3, 0x0(x1)" &&
              listing.rows[2].instruction && listing.rows[2].control_target == Address{{0}, 0x400010},
          "project listing decodes RV64 text and exposes its computed branch target");
    auto compressed_data = elf_fixture::executable(true);
    elf_fixture::put(compressed_data, 18, 243, 2);
    elf_fixture::put(compressed_data, 48, 1, 4); // EF_RISCV_RVC
    elf_fixture::program(compressed_data, true, 0, 1, 256, 0x400000, 8, 8, 5, 256);
    const auto mixed = bytes({0x01, 0x00,             // c.nop
                              0x93, 0x00, 0x50, 0x00, // addi x1, x0, 5
                              0x02, 0x90});           // c.ebreak
    std::copy(mixed.begin(), mixed.end(), compressed_data.begin() + 256);
    auto compressed = load_elf(std::make_shared<MemoryStorage>(compressed_data), {});
    check(compressed && compressed.value().image->decode_context().mode == ExecutionMode::rv64c,
          "EF_RISCV_RVC selects the halfword-aligned RV64IC mode");
    if (compressed) {
        const auto mixed_analysis = analyze(*compressed.value().image, compressed.value().metadata, {}, {}).value();
        check(mixed_analysis.instructions.size() == 3 && mixed_analysis.instructions[0].length == 2 &&
                  mixed_analysis.instructions[1].address.offset == 0x400002 &&
                  mixed_analysis.instructions[1].length == 4 && mixed_analysis.instructions[2].address.offset == 0x400006,
              "reachable traversal advances across mixed 16-bit and 32-bit instructions");
        AnalysisKey compressed_key;
        compressed_key.input = {compressed.value().image->storage()->size(),
                                hash_source(*compressed.value().image->storage(), {}).value()};
        compressed_key.engine_fingerprint = function_engine_fingerprint();
        const auto compressed_proposal = analyze_derived(
            compressed.value().image, std::make_shared<const ImageMetadata>(compressed.value().metadata), {}, {},
            compressed_key, {}).value();
        const auto compressed_wire = encode_derived(compressed_proposal, {}).value();
        const auto compressed_roundtrip = decode_derived(compressed_wire, *compressed.value().image,
                                                         compressed.value().metadata, {}, {}, compressed_key, {});
        check(compressed_roundtrip && compressed_roundtrip.value().context.mode == ExecutionMode::rv64c,
              "derived cache round trip retains the ELF-selected RV64IC execution mode");
    }
    const auto functions = recover_functions(*loaded.value().image, loaded.value().metadata, {}, {}, {}).value();
    const auto references = derive_references(*loaded.value().image, *functions, loaded.value().metadata, {}, {}).value();
    const auto reference_wire = encode_reference_index(*references, {}).value();
    const auto reference_roundtrip = decode_reference_index(reference_wire, {}).value();
    check(encode_reference_index(*reference_roundtrip, {}).value() == reference_wire,
          "RISC-V register and memory expressions pass the validated reference-index round trip");
    AnalysisKey key;
    key.input = {loaded.value().image->storage()->size(), hash_source(*loaded.value().image->storage(), {}).value()};
    key.engine_fingerprint = function_engine_fingerprint();
    const auto proposal = analyze_derived(loaded.value().image,
                                         std::make_shared<const ImageMetadata>(loaded.value().metadata), {}, {}, key, {})
                              .value();
    const auto cache_wire = encode_derived(proposal, {}).value();
    check(bool(decode_derived(cache_wire, *loaded.value().image, loaded.value().metadata, {}, {}, key, {})),
          "project derived-cache source-context validation accepts persisted RV64 instruction facts");
}
void resolver_contract() {
    for (bool wide : {false, true})
        for (bool rela : {false, true}) {
            auto loaded = load(fixture(wide, rela));
            auto resolver = ElfRelocationResolver::create(loaded.metadata, {}).value();
            auto instruction = decode_at(*loaded.image, {{1}, 0}).value().instruction.value();
            auto value = resolver.operand(instruction, 0, {}).value();
            check(value.reason == ElfResolutionReason::resolved && value.address == Address{{2}, 0} &&
                      value.relocations == std::vector<std::uint64_t>{0},
                  "shared resolver returns exact canonical relocation row provenance");
            check(resolve_control_target(*loaded.image, loaded.metadata, instruction, {}).value() == Address{{2}, 0},
                  "one-shot control query shares relocation-aware resolver semantics");
            auto data = fixture(wide, rela);
            const auto stride = (rela ? 3u : 2u) * (wide ? 8u : 4u);
            section(data, wide, 7, 0, rela ? 4 : 9, 0, 0, relocations_at, 2 * stride, wide ? 8 : 4);
            links(data, wide, false, 7, 5, 1, stride);
            relocation(data, wide, rela, false, 1, 1, 2, 2, UINT64_MAX - 3);
            auto ambiguous = load(data);
            auto aliases = ElfRelocationResolver::create(ambiguous.metadata, {}).value();
            value = aliases.operand(instruction, 0, {}).value();
            check(value.reason == ElfResolutionReason::ambiguous && !value.address &&
                      value.relocations == std::vector<std::uint64_t>{0, 1},
                  "multiple independent relocations on one field retain both origins and cannot choose a target");
            data = fixture(wide, rela);
            relocation(data, wide, rela, false, 0, 2, wide ? 13 : 21, 1, 0);
            auto partial = load(data);
            value = ElfRelocationResolver::create(partial.metadata, {}).value().operand(instruction, 0, {}).value();
            check(value.reason == ElfResolutionReason::field_mismatch && !value.address,
                  "partial relocation overlap suppresses a placeholder without pretending it covers the operand");
            std::stop_source stop;
            stop.request_stop();
            check(!ElfRelocationResolver::create(loaded.metadata, stop.get_token()) &&
                      !resolver.operand(instruction, 0, stop.get_token()),
                  "resolver construction and lookup both honor cancellation");
            auto shared = loaded.metadata;
            shared.elf->header.object_type = 3;
            shared.elf->sections[7].flags |= 2; // Runtime relocation, not a retained static SYMTAB record.
            auto dynamic = ElfRelocationResolver::create(shared, {}).value();
            value = dynamic.operand(instruction, 0, {}).value();
            check(value.reason == ElfResolutionReason::preemptible_symbol && !value.address,
                  "shared-object default global definition does not claim guaranteed runtime binding");
            shared.elf->symbols[1].visibility = 2;
            auto hidden = ElfRelocationResolver::create(shared, {}).value();
            check(hidden.operand(instruction, 0, {}).value().address == Address{{2}, 0},
                  "nonpreemptible hidden definition retains its declared symbolic target");
        }
}
void coarse_references_and_listing() {
    for (bool wide : {false, true})
        for (bool rela : {false, true})
            for (bool defined : {false, true}) {
                auto loaded = load(fixture(wide, rela, 2, defined ? 1 : 2));
                const auto functions = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
                for (bool with_image : {false, true}) {
                    const auto references =
                        with_image ? derive_references(*loaded.image, *functions, loaded.metadata, {}, {}).value()
                                   : derive_references(*functions, loaded.metadata, {}, {}).value();
                    auto outgoing = references->outgoing(Address{{1}, 0}, {}).value();
                    check(outgoing.rows.size() == 1,
                          "CALL retains one control reference after relocation-aware recovery");
                    if (outgoing.rows.size() != 1)
                        continue;
                    if (defined)
                        check(std::get<Location>(outgoing.rows[0].target) == Location{Address{{2}, 0}},
                              "both reference entrypoints share declared cross-section control targets");
                    else
                        check(std::holds_alternative<UnresolvedTarget>(outgoing.rows[0].target) &&
                                  std::get<UnresolvedTarget>(outgoing.rows[0].target).reason ==
                                      UnresolvedReason::elf_relocation,
                              "unresolved relocation reference is distinguished from arithmetic overflow");
                }
                const auto coarse = analyze(*loaded.image, loaded.metadata, {}, {}).value();
                auto call = std::find_if(coarse.edges.begin(), coarse.edges.end(),
                                         [](const auto &edge) { return edge.from == Address{{1}, 0}; });
                check(
                    call != coarse.edges.end() &&
                        call->to == (defined ? std::optional<Address>{Address{{2}, 0}} : std::nullopt),
                    "metadata-aware coarse analysis seeds ELF functions and shares resolved/unresolved flow semantics");
                check(std::none_of(coarse.instructions.begin(), coarse.instructions.end(),
                                   [](const auto &instruction) { return instruction.address == Address{{1}, 1}; }),
                      "coarse traversal does not decode an unlinked displacement as a bogus entry");
                if (!defined)
                    check(std::any_of(coarse.stops.begin(), coarse.stops.end(),
                                      [](const auto &stop) {
                                          return stop.address == Address{{1}, 0} &&
                                                 stop.reason == StopReason::elf_relocation;
                                      }),
                          "coarse relocation stop is not mislabeled as arithmetic target overflow");
                DocumentSnapshot document;
                document.image = loaded.image;
                document.metadata = loaded.metadata;
                const auto page = make_listing_page(document, Address{{1}, 0}, 1).value();
                check(page.rows.size() == 1 && page.rows[0].instruction &&
                          page.rows[0].control_target ==
                              (defined ? std::optional<Address>{Address{{2}, 0}} : std::nullopt),
                      "manual listing carries a relocation-aware Follow target computed with its source bytes");
            }
}
void memory_fields() {
    for (bool rela : {false, true}) {
        auto data = fixture(true, rela);
        symbol(data, true, false, 1, 1, 0x11, 3, 0, 4);
        symbol(data, true, false, 4, 21, 0x12, 1, 0, 11);
        const auto code = bytes({0xc7, 0x05, 0xfc, 0xff, 0xff, 0xff, 1, 0, 0, 0, 0xc3});
        std::copy(code.begin(), code.end(), data.begin() + 256);
        relocation(data, true, rela, false, 0, 2, 2, 1, UINT64_MAX - 3);
        auto loaded = load(data);
        auto instruction = decode_at(*loaded.image, {{1}, 0}).value().instruction.value();
        auto resolver = ElfRelocationResolver::create(loaded.metadata, {}).value();
        const auto resolution = resolver.operand(instruction, 0, {}).value();
        check(resolution.address == Address{{3}, 4},
              "RIP-relative relocation bias includes a following immediate, not just displacement width");
        auto functions = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
        auto references = derive_references(*loaded.image, *functions, loaded.metadata, {}, {}).value();
        check(references->incoming(Address{{3}, 4}, {}).value().total == 1 &&
                  references->incoming(Address{{1}, 6}, {}).value().total == 0,
              "relocated memory access references declared BSS address rather than placeholder bytes");
        check(std::get<MemoryOperand>(instruction.operands[0]).resolved_address == Address{{1}, 6},
              "reference derivation keeps pure decoder memory expression unchanged");
    }
    for (bool wide : {false, true})
        for (bool rela : {false, true}) {
            auto data = fixture(wide, rela);
            symbol(data, wide, false, 1, 1, 0x11, 3, 0, 4);
            symbol(data, wide, false, 4, 21, 0x12, 1, 0, 7);
            const auto code =
                wide ? bytes({0xff, 0x15, 0xfc, 0xff, 0xff, 0xff, 0xc3}) : bytes({0xff, 0x15, 0, 0, 0, 0, 0xc3});
            std::copy(code.begin(), code.end(), data.begin() + 256);
            relocation(data, wide, rela, false, 0, 2, wide ? 2 : 1, 1, wide ? UINT64_MAX - 3 : 0);
            auto loaded = load(data);
            auto functions = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
            auto references = derive_references(*loaded.image, *functions, loaded.metadata, {}, {}).value();
            auto rows = references->outgoing(Address{{1}, 0}, {}).value();
            const auto call = std::find_if(rows.rows.begin(), rows.rows.end(),
                                           [](const auto &reference) { return reference.kind == ReferenceKind::call; });
            check(
                call != rows.rows.end() && std::holds_alternative<UnresolvedTarget>(call->target) &&
                    std::get<UnresolvedTarget>(call->target).reason == UnresolvedReason::memory_value &&
                    call->association == Location{Address{{3}, 0}},
                "relocated indirect CALL retains pointer-slot association without claiming the slot is a code target");
            check(std::all_of(functions->calls.begin(), functions->calls.end(),
                              [](const auto &call) { return !call.target; }),
                  "resolved storage address never becomes a direct callee");
            const auto payload = encode_reference_index(*references, {}).value();
            check(encode_reference_index(*decode_reference_index(payload, {}).value(), {}).value() == payload,
                  "indirect relocated memory association roundtrips canonically");
        }
}
void cache_binding() {
    for (bool defined : {false, true}) {
        auto loaded = load(fixture(true, true, 2, defined ? 1 : 2));
        AnalysisKey key;
        key.input = {loaded.image->storage()->size(), hash_source(*loaded.image->storage(), {}).value()};
        key.engine_fingerprint = function_engine_fingerprint();
        const auto proposal =
            analyze_derived(loaded.image, std::make_shared<const ImageMetadata>(loaded.metadata), {}, {}, key, {})
                .value();
        const auto wire = encode_derived(proposal, {}).value();
        check(bool(decode_derived(wire, *loaded.image, loaded.metadata, {}, {}, key, {})),
              "relocation-aware functions, stops and references roundtrip in the canonical cache");
        auto changed = loaded.metadata;
        changed.elf->relocations[0].symbol_index = defined ? 2 : 1;
        check(!decode_derived(wire, *loaded.image, changed, {}, {}, key, {}),
              "valid cache checksum cannot substitute another authoritative relocation symbol");
        changed = loaded.metadata;
        changed.elf->relocations.clear();
        check(!decode_derived(wire, *loaded.image, changed, {}, {}, key, {}),
              "cache cannot retain resolved or suppressed control facts after relocation provenance disappears");
    }
}
void branch_variants_and_shared_budget() {
    for (bool wide : {false, true})
        for (bool rela : {false, true})
            for (bool conditional : {false, true})
                for (bool short_form : {false, true}) {
                    auto data = fixture(wide, rela);
                    const auto code = short_form    ? bytes({conditional ? 0x75u : 0xebu, 0xff, 0xc3})
                                      : conditional ? bytes({0x0f, 0x85, 0xfc, 0xff, 0xff, 0xff, 0xc3})
                                                    : bytes({0xe9, 0xfc, 0xff, 0xff, 0xff, 0xc3});
                    std::copy(code.begin(), code.end(), data.begin() + 256);
                    symbol(data, wide, false, 4, 21, 0x12, 1, 0, code.size());
                    const auto field = conditional && !short_form ? 2u : 1u;
                    const auto type = short_form ? (wide ? 15u : 23u) : 2u;
                    relocation(data, wide, rela, false, 0, field, type, 1, short_form ? UINT64_MAX : UINT64_MAX - 3);
                    const auto loaded = load(data);
                    const auto instruction = decode_at(*loaded.image, {{1}, 0}).value().instruction.value();
                    const auto resolver = ElfRelocationResolver::create(loaded.metadata, {}).value();
                    check(resolver.control_target(*loaded.image, instruction, {}).value() == Address{{2}, 0},
                          "near and short JMP/Jcc relocation targets use exact decoded field coordinates and "
                          "instruction bias");
                    const auto functions = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
                    const auto references =
                        derive_references(*loaded.image, *functions, loaded.metadata, {}, {}).value();
                    const auto rows = references->outgoing(Address{{1}, 0}, {}).value();
                    check(rows.rows.size() == 1 &&
                              rows.rows[0].kind ==
                                  (conditional ? ReferenceKind::conditional_jump : ReferenceKind::jump) &&
                              std::get<Location>(rows.rows[0].target) == Location{Address{{2}, 0}} &&
                              rows.rows[0].provenance.elf,
                          "branch reference preserves control kind and declared relocation origin across both ELF "
                          "classes and addend forms");
                }
    const auto loaded = load(fixture(true, true));
    const auto instruction = decode_at(*loaded.image, {{1}, 0}).value().instruction.value();
    auto bounded = ElfRelocationResolver::create(loaded.metadata, ElfResolutionLimits{1, 4096}, {}).value();
    check(bounded.operand(instruction, 0, {}).value().address == Address{{2}, 0},
          "one-node lookup consumes exactly the available operation budget");
    auto copy = bounded;
    const auto exhausted = copy.operand(instruction, 0, {});
    check(!exhausted && exhausted.error().code == ErrorCode::resource_limit,
          "copied resolvers share the aggregate budget instead of resetting it on each query");
    auto underflow = load(fixture(true, true));
    underflow.metadata.elf->relocations[0].addend = -8;
    const auto checked =
        ElfRelocationResolver::create(underflow.metadata, {}).value().operand(instruction, 0, {}).value();
    check(checked.reason == ElfResolutionReason::overflow && !checked.address,
          "PC-relative address-domain underflow remains unresolved rather than becoming an invented wrapped domain "
          "address");
}
} // namespace
int main() {
    return run([] {
        for (bool wide : {false, true})
            for (bool rela : {false, true}) {
                auto loaded = load(retained(wide, rela));
                const Address source{{0}, 0x400000}, target{{0}, 0x400006};
                auto recovered = recover_functions(*loaded.image, loaded.metadata, {}, {}, {}).value();
                auto call = std::find_if(recovered->calls.begin(), recovered->calls.end(),
                                         [&](const auto &row) { return row.source == source; });
                check(call != recovered->calls.end() && call->target == target,
                      "retained static relocation preserves linked CALL target rather than linking twice");
                check(std::none_of(recovered->functions.begin(), recovered->functions.end(),
                                   [](const auto &row) { return row->entry == Address{{0}, 0x40000b}; }),
                      "retained relocation cannot fabricate a function from linked displacement");
                DocumentSnapshot document;
                document.image = loaded.image;
                document.metadata = loaded.metadata;
                const auto page = make_listing_page(document, source, 1).value();
                check(page.rows.size() == 1 && page.rows[0].control_target == target,
                      "manual Follow uses actual linked target with retained relocations");
                auto refs = derive_references(*loaded.image, *recovered, loaded.metadata, {}, {}).value();
                const auto outgoing = refs->outgoing(source, {}).value();
                check(std::any_of(outgoing.rows.begin(), outgoing.rows.end(),
                                  [&](const auto &row) {
                                      const auto *at = std::get_if<Location>(&row.target);
                                      return at && *at == Location{target};
                                  }),
                      "linked control references retain the actual callee");
            }
        recovery();
        riscv_elf_flow();
        resolver_contract();
        coarse_references_and_listing();
        memory_fields();
        cache_binding();
        branch_variants_and_shared_budget();
    });
}
