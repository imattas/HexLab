#include "hexlab/analysis/macho_relocations.hpp"
#include "hexlab/loaders/macho.hpp"
#include "support/macho_relocation_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> r) {
    if (!r)
        throw std::runtime_error(r.error().message);
    return std::move(r.value());
}
LoadedImage load(std::vector<std::byte> data) {
    return take(load_macho(std::make_shared<MemoryStorage>(std::move(data)), {}, {}));
}
void calls() {
    for (bool wide : {false, true}) {
        auto loaded = load(relocated(wide));
        auto resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
        const auto decoded = take(decode_at(*loaded.image, {{1}, 0}));
        const auto instruction = *decoded.instruction;
        const auto resolved = take(resolver.operand(instruction, 0, {}));
        check(resolved.reason == MachOResolutionReason::resolved && resolved.address == Address{{2}, 0} &&
                  resolved.relocations == std::vector<std::uint64_t>{0} && !resolved.constant,
              "object CALL resolves actual symbol section despite equal nonzero original section addresses");
        check(take(resolver.control_target(*loaded.image, instruction, {})) == Address{{2}, 0},
              "control target uses Mach-O association");
        check(resolver.symbol(0) && resolver.symbol(0)->index == 1 && !resolver.symbol(99),
              "symbol lookup preserves nlist namespace and rejects invalid row");
        for (const auto index : {2u, 4u, 5u, 6u, 8u}) {
            auto data = relocated(wide);
            relocation(data, false, 0, 1, index, wide ? 2 : 0, 2, true, true);
            auto partial = load(data);
            auto query = take(MachORelocationResolver::create(partial.metadata, {}));
            const auto value = take(query.operand(instruction, 0, {}));
            check(value.relocated() && !value.address && !take(query.control_target(*partial.image, instruction, {})),
                  "undefined/common/indirect/debug/weak cannot expose decoded placeholder as a callee");
        }
        auto mismatch = instruction;
        std::get<RelativeOperand>(mismatch.operands[0]).encoding = EncodedField{2, 3};
        check(take(resolver.operand(mismatch, 0, {})).reason == MachOResolutionReason::field_mismatch,
              "partial field overlap is unresolved rather than guessed");
        auto ambiguous = loaded.metadata;
        ambiguous.macho->relocations.push_back(ambiguous.macho->relocations[0]);
        auto duplicate = take(MachORelocationResolver::create(ambiguous, {}));
        check(take(duplicate.operand(instruction, 0, {})).reason == MachOResolutionReason::ambiguous,
              "independent overlapping records remain ambiguous");
        auto data = relocated(wide);
        relocation(data, false, 0, 1, 2, wide ? 1 : 0, 2, true, false);
        put(data, 769, 0xfffffffb, 4, false);
        auto local = load(data);
        auto local_query = take(MachORelocationResolver::create(local.metadata, {}));
        check(take(local_query.operand(instruction, 0, {})).address == Address{{2}, 0},
              "local PC relocation subtracts original target section base exactly once");
        auto linked = load(macho_fixture::symbols(wide, false, false));
        linked.metadata.macho->relocations = loaded.metadata.macho->relocations;
        linked.metadata.macho->relocation_tables = loaded.metadata.macho->relocation_tables;
        linked.metadata.macho->relocations[0].retained = true;
        auto retained = take(MachORelocationResolver::create(linked.metadata, {}));
        check(!take(retained.operand(instruction, 0, {})).relocated() &&
                  take(retained.control_target(*linked.image, instruction, {})) == instruction.direct_target,
              "retained linked records leave actual decoder target authoritative");
        std::stop_source stopped;
        stopped.request_stop();
        check(!MachORelocationResolver::create(loaded.metadata, stopped.get_token()) &&
                  !resolver.operand(instruction, 0, stopped.get_token()),
              "index creation and lookup honor cancellation");
        auto limited = take(MachORelocationResolver::create(loaded.metadata, MachOResolutionLimits{0, 4096}, {}));
        const auto exhausted = limited.operand(instruction, 0, {});
        check(!exhausted && exhausted.error().code == ErrorCode::resource_limit,
              "lookup work budget cannot silently degrade to an ordinary placeholder");
    }
}
void data_and_pairs() {
    auto data = relocated(true);
    relocation(data, false, 0, 0, 1, 0, 3, false, true);
    put(data, 768, 2, 8, false);
    auto loaded = load(data);
    auto resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
    check(take(resolver.data(0, {})).address == Address{{2}, 2},
          "unsigned pointer association uses symbol offset plus original bits");
    auto unsupported_context = loaded.metadata;
    unsupported_context.macho->container.slices[0].header.is_64 = false;
    auto unknown_query = take(MachORelocationResolver::create(unsupported_context, {}));
    check(take(unknown_query.data(0, {})).reason == MachOResolutionReason::unsupported,
          "CPU/class mismatch remains inspectable without inheriting a guessed relocation context");
    auto narrow = loaded.metadata;
    narrow.macho->relocations[0].length = 2;
    narrow.macho->relocations[0].field_size = 4;
    narrow.macho->relocations[0].encoded_value = 0;
    narrow.macho->symbols[1].address = Address{{2}, UINT64_C(0x100000000)};
    auto narrow_query = take(MachORelocationResolver::create(narrow, {}));
    check(take(narrow_query.data(0, {})).reason == MachOResolutionReason::overflow,
          "32-bit unsigned field cannot represent a wider object-domain address");
    narrow.macho->symbols[1].address = Address{{2}, 0};
    narrow.macho->relocations[0].length = 1;
    narrow.macho->relocations[0].field_size = 2;
    narrow_query = take(MachORelocationResolver::create(narrow, {}));
    check(take(narrow_query.data(0, {})).reason == MachOResolutionReason::unsupported,
          "x64 unsigned two-byte field is preserved but not assigned an invented architecture formula");
    auto retained_alias = loaded.metadata;
    retained_alias.macho->relocations.push_back(retained_alias.macho->relocations[0]);
    retained_alias.macho->relocations[1].retained = true;
    auto retained_query = take(MachORelocationResolver::create(retained_alias, {}));
    check(take(retained_query.data(1, {})).reason == MachOResolutionReason::retained &&
              !take(retained_query.data(1, {})).address,
          "raw retained row query cannot resolve through unrelated overlapping object record");
    relocation_count(data, true, false, 2);
    relocation(data, false, 0, 0, 0, 5, 3, false, true);
    relocation(data, false, 1, 0, 8, 0, 3, false, true);
    symbol(data, true, false, 8, 52, 0x0f, 1, 0, 0x102);
    put(data, 768, 10, 8, false);
    loaded = load(data);
    resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
    const auto value = take(resolver.data(0, {}));
    check(value.reason == MachOResolutionReason::resolved && value.constant == 12 && !value.address &&
              value.relocations == std::vector<std::uint64_t>{0, 1},
          "same-domain subtractor pair yields a constant, never a fabricated pointer");
    check(take(resolver.data(1, {})).relocations == value.relocations,
          "querying auxiliary pair resolves the same ordered compound source");
    relocation(data, false, 1, 0, 1, 0, 3, false, true);
    loaded = load(data);
    resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
    check(take(resolver.data(0, {})).reason == MachOResolutionReason::different_domains,
          "subtractor cannot subtract unknown linker placement of distinct object domains");
    auto raw = relocated(false);
    relocation(raw, false, 0, 0, 0, 0, 2, false, false);
    put(raw, 768, 0x100, 4, false);
    loaded = load(raw);
    resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
    check(take(resolver.data(0, {})).constant == 0x100 && !take(resolver.data(0, {})).address,
          "R_ABS scalar alone does not prove a mapped process pointer");
}
void encoded_memory() {
    for (const auto type : {1u, 6u, 8u}) {
        const auto tail = type == 6 ? 1u : 4u;
        auto data = relocated(true);
        put(data, 32 + 72 + 40, 16, 8, false);
        data[768] = std::byte(tail == 1 ? 0xc6 : 0xc7);
        data[769] = std::byte{0x05};
        put(data, 770, UINT32_MAX - tail + 1, 4, false);
        put(data, 774, 0x12, tail, false);
        relocation(data, false, 0, 2, 1, static_cast<std::uint8_t>(type), 2, true, true);
        auto loaded = load(data);
        auto resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
        auto instruction = *take(decode_at(*loaded.image, {{1}, 0})).instruction;
        const auto memory = take(resolver.operand(instruction, 0, {}));
        check(instruction.length == 6 + tail && memory.address == Address{{2}, 0},
              "RIP memory addend accounts for instruction bytes after displacement without double bias");
        check(!take(resolver.control_target(*loaded.image, instruction, {})),
              "memory relocation association is never itself a control target");
        auto context = loaded.metadata;
        context.macho->relocations[0].kind = MachORelocationKind::got;
        auto got = take(MachORelocationResolver::create(context, {}));
        check(take(got.operand(instruction, 0, {})).reason == MachOResolutionReason::unsupported,
              "GOT slot is not replaced by symbol address");
    }
    auto loaded = load(relocated(true));
    const auto instruction = *take(decode_at(*loaded.image, {{1}, 0})).instruction;
    loaded.metadata.macho->relocations[0].encoded_value = 4;
    auto resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
    check(take(resolver.operand(instruction, 0, {})).address == Address{{2}, 4},
          "external x64 branch addend has no ELF-style negative-four adjustment");
    loaded.metadata.macho->relocation_tables[0].kind = MachORelocationSource::external;
    resolver = take(MachORelocationResolver::create(loaded.metadata, {}));
    check(take(resolver.operand(instruction, 0, {})).reason == MachOResolutionReason::runtime_binding &&
              !take(resolver.control_target(*loaded.image, instruction, {})),
          "classic runtime table cannot claim statically bound callee");
}
} // namespace
int main() {
    return run([] {
        calls();
        data_and_pairs();
        encoded_memory();
    });
}
