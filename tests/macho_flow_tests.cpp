#include "hexlab/loaders/macho.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/workspace/listing.hpp"
#include "support/macho_relocation_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
using namespace hexlab_test::macho_fixture;
namespace {
template <class T> T take(Result<T> value) {
    if (!value)
        throw std::runtime_error(value.error().message);
    return std::move(value.value());
}
LoadedImage load(std::vector<std::byte> data) {
    return take(load_macho(std::make_shared<MemoryStorage>(std::move(data)), {}, {}));
}
std::vector<std::byte> flow_fixture(bool wide) {
    auto data = relocated(wide);
    // The general symbol fixture has an alternate label at text+2. That is
    // inside this fixture's CALL encoding, so move the weak definition onto
    // the real second-section entry to isolate relocation flow from overlaps.
    symbol(data, wide, false, 8, 52, 0x0f, 2, 0x80, 0x100);
    return data;
}
void calls() {
    for (bool wide : {false, true})
        for (const auto symbol_index : {1u, 2u, 4u, 5u, 6u, 8u}) {
            auto data = flow_fixture(wide);
            relocation(data, false, 0, 1, symbol_index, wide ? 2 : 0, 2, true, true);
            auto loaded = load(data);
            const std::optional<Address> expected = symbol_index == 1 ? std::optional{Address{{2}, 0}} : std::nullopt;
            const auto recovered = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
            const auto call = std::find_if(recovered->calls.begin(), recovered->calls.end(),
                                           [](const auto &row) { return row.source == Address{{1}, 0}; });
            check(recovered->conflicts.empty(), "flow fixture has no incidental interior symbol/decode overlaps");
            check(call != recovered->calls.end() && call->target == expected,
                  "shared recovery resolves declared Mach-O callee or suppresses unlinked placeholder");
            check(std::none_of(recovered->functions.begin(), recovered->functions.end(),
                               [](const auto &row) { return row->entry == Address{{1}, 5}; }),
                  "unlinked x64 zero displacement cannot create an interior callee root");
            const auto coarse = take(analyze(*loaded.image, loaded.metadata, {}, {}));
            const auto edge = std::find_if(coarse.edges.begin(), coarse.edges.end(),
                                           [](const auto &row) { return row.from == Address{{1}, 0}; });
            check(edge != coarse.edges.end() && edge->to == expected,
                  "coarse reachability uses the same Mach-O relocation equations as recovery");
            if (!expected) {
                check(std::any_of(coarse.stops.begin(), coarse.stops.end(),
                                  [](const auto &stop) {
                                      return stop.address == Address{{1}, 0} &&
                                             stop.reason == StopReason::macho_relocation;
                                  }),
                      "coarse unresolved Mach-O relocation is not mislabeled as ELF or arithmetic overflow");
                check(std::any_of(recovered->functions.begin(), recovered->functions.end(),
                                  [](const auto &function) {
                                      return std::any_of(function->stops.begin(), function->stops.end(),
                                                         [](const auto &stop) {
                                                             return stop.address == Address{{1}, 0} &&
                                                                    stop.reason == FunctionStopReason::macho_relocation;
                                                         });
                                  }),
                      "function recovery preserves a distinct Mach-O unresolved stop");
            }
            DocumentSnapshot document;
            document.image = loaded.image;
            document.metadata = loaded.metadata;
            const auto page = take(make_listing_page(document, Address{{1}, 0}, 1));
            check(page.rows.size() == 1 && page.rows[0].control_target == expected,
                  "manual listing Follow resolves with original source/section namespace");
            check(page.rows[0].instruction && page.rows[0].instruction->bytes[0] == std::byte{0xe8} &&
                      page.rows[0].instruction->direct_target != expected,
                  "pure decoded instruction bytes and placeholder target are preserved");
        }
}
void cache_binding() {
    for (bool defined : {false, true}) {
        auto data = flow_fixture(true);
        relocation(data, false, 0, 1, defined ? 1 : 2, 2, 2, true, true);
        auto loaded = load(data);
        AnalysisKey key;
        key.input = {loaded.image->storage()->size(), take(hash_source(*loaded.image->storage(), {}))};
        key.engine_fingerprint = function_engine_fingerprint();
        const auto proposal = take(
            analyze_derived(loaded.image, std::make_shared<const ImageMetadata>(loaded.metadata), {}, {}, key, {}));
        const auto wire = take(encode_derived(proposal, {}));
        check(bool(decode_derived(wire, *loaded.image, loaded.metadata, {}, {}, key, {})),
              "relocation-aware Mach-O function facts roundtrip in source-bound derived cache");
        auto changed = loaded.metadata;
        changed.macho->relocations[0].symbol_number = defined ? 2 : 1;
        check(!decode_derived(wire, *loaded.image, changed, {}, {}, key, {}),
              "valid checksum cannot substitute another authoritative Mach-O relocation symbol");
        changed = loaded.metadata;
        changed.macho->relocations.clear();
        changed.macho->relocation_tables.clear();
        check(!decode_derived(wire, *loaded.image, changed, {}, {}, key, {}),
              "source-bound cache rejects control facts after authoritative relocation disappears");
    }
}
void branches_and_retained() {
    for (bool wide : {false, true}) {
        for (bool conditional : {false, true})
            for (bool defined : {false, true}) {
                auto data = flow_fixture(wide);
                const auto field = conditional ? 2u : 1u;
                if (conditional) {
                    data[768] = std::byte{0x0f};
                    data[769] = std::byte{0x85};
                } else
                    data[768] = std::byte{0xe9};
                put(data, 768 + field, wide ? 0 : UINT64_C(0x100000000) - 0x100 - field - 4, 4, false);
                data[768 + field + 4] = std::byte{0xc3};
                relocation(data, false, 0, field, defined ? 1 : 2, wide ? 2 : 0, 2, true, true);
                const auto loaded = load(data);
                const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
                const std::optional<Address> expected = defined ? std::optional{Address{{2}, 0}} : std::nullopt;
                bool found = false;
                for (const auto &block : functions->blocks)
                    for (const auto &edge : block->successors)
                        if (edge.source == Address{{1}, 0} && edge.kind != BlockEdgeKind::conditional_false) {
                            found = true;
                            check(edge.target == expected,
                                  "conditional and unconditional Mach-O branches share relocation resolution");
                        }
                check(found, "branch fixture produces authoritative successor facts");
            }
        auto data = macho_fixture::symbols(wide, false, false);
        const auto base = wide ? UINT64_C(0x100000000) : UINT64_C(0x1000);
        symbol(data, wide, false, 8, 52, 0x0f, 2, 0x80, base + 8);
        relocation_count(data, wide, false, 1);
        relocation(data, false, 0, 1, 2, wide ? 2 : 0, 2, true, true);
        data[768] = std::byte{0xe8};
        put(data, 769, 3, 4, false);
        data[773] = std::byte{0xc3};
        const auto loaded = load(data);
        const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
        check(std::any_of(functions->calls.begin(), functions->calls.end(),
                          [&](const auto &call) {
                              return call.source == Address{{0}, base} && call.target == Address{{0}, base + 8};
                          }),
              "retained linked relocation cannot override actual CALL bytes with undefined symbol");
        DocumentSnapshot document;
        document.image = loaded.image;
        document.metadata = loaded.metadata;
        const auto page = take(make_listing_page(document, Address{{0}, base}, 1));
        check(page.rows.size() == 1 && page.rows[0].control_target == Address{{0}, base + 8},
              "manual Follow preserves linked call semantics with retained records");
    }
}
} // namespace
int main() {
    return run([] {
        calls();
        cache_binding();
        branches_and_retained();
    });
}
