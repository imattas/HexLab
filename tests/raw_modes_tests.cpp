#include "hexlab/loaders/recipe.hpp"
#include "hexlab/workspace/project.hpp"
#include "support/analysis_fixture.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
using namespace hexlab;
using namespace hexlab_test;
namespace {
RawOptions raw32(uint64_t base = 0x1000) {
    return {Architecture::x86, ExecutionMode::x86_32, {{0}, base}, true, false, true, {}};
}
void loader_tests() {
    auto storage = std::make_shared<MemoryStorage>(bytes({0x40, 0xc3}));
    auto options = raw32();
    auto loaded = load_raw(storage, options, {});
    check(loaded && loaded.value()->layout().space.width_bits == 32 &&
              loaded.value()->decode_context() ==
                  DecodeContext{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little},
          "raw32 maps explicit flat 32-bit context");
    check(bool(load_raw(std::make_shared<MemoryStorage>(bytes({0xc3})), raw32(UINT32_MAX), {})),
          "raw32 final byte is mappable");
    check(!load_raw(storage, raw32(UINT32_MAX), {}), "raw32 extent cannot cross address ceiling");
    auto empty = std::make_shared<MemoryStorage>(std::vector<std::byte>{});
    check(!load_raw(empty, raw32(uint64_t{UINT32_MAX} + 1), {}), "empty raw32 cannot conceal invalid base");
    auto empty_loaded = load_raw(empty, raw32(UINT32_MAX), {});
    check(empty_loaded && empty_loaded.value()->layout().entries.empty(), "empty raw32 has no implicit entry");
    for (auto entry : {Address{{0}, 0x1002}, Address{{1}, 0x1000}, Address{{0}, 0x100000000ULL}, Address{{0}, 0xfff}}) {
        options = raw32();
        options.entry = entry;
        check(!load_raw(storage, options, {}), "raw32 rejects invalid entry domain or extent");
    }
    for (auto context : {DecodeContext{Architecture::x86_64, ExecutionMode::x86_32},
                         DecodeContext{Architecture::x86, ExecutionMode::x86_64},
                         DecodeContext{Architecture::x86, ExecutionMode::x86_16}, DecodeContext{}}) {
        options = raw32();
        options.architecture = context.architecture;
        options.mode = context.mode;
        check(!load_raw(storage, options, {}), "raw rejects unsupported context pair");
    }
}
void recipe_tests() {
    auto raw = raw32();
    raw.entry = Address{{0}, 0x1001};
    LoadRecipe recipe{Format::raw, raw};
    const auto literal =
        bytes({1, 0, 1, 1, 2, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 1});
    auto encoded = encode_recipe(recipe);
    check(encoded && encoded.value() == literal,
          "raw32 canonical recipe uses existing version and explicit legacy enum values");
    auto decoded = decode_recipe(literal);
    check(decoded && encode_recipe(decoded.value()).value() == literal, "raw32 durable recipe roundtrip");
    raw.base.offset = 0x100000000ULL;
    check(!encode_recipe({Format::raw, raw}), "raw32 recipe rejects out-of-domain base before persistence");
    auto forged = literal;
    forged[10] = std::byte{1};
    check(!decode_recipe(forged), "raw32 reader rejects oversized serialized base");
    raw = raw32();
    raw.mode = ExecutionMode::x86_64;
    check(!encode_recipe({Format::raw, raw}), "recipe rejects architecture/mode mismatch");
    forged = literal;
    forged[4] = std::byte{3};
    check(!decode_recipe(forged), "recipe reader rejects architecture/mode mismatch");
    RawOptions old{Architecture::x86_64,
                   ExecutionMode::x86_64,
                   {{0xffffffff}, 0xfffffffffffff000ULL},
                   true,
                   false,
                   true,
                   Address{{0xffffffff}, 0xfffffffffffff001ULL}};
    check(encode_recipe({Format::raw, old}).value() ==
              bytes({1,   0, 1, 2,   3,   5,   255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                     240, 0, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 240, 1}),
          "existing x64 recipe bytes remain identical");
}
void reopen_tests() {
    FixtureFile input(bytes({0x40, 0xc3})), marker(std::span<const std::byte>{});
    auto path = marker.path.wstring() + L".raw32.hxproj";
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code ignored;
            for (auto suffix : {L"", L"-wal", L"-shm"}) {
                auto side = path;
                side += suffix;
                std::filesystem::remove(side, ignored);
            }
        }
    } cleanup{path};
    auto store = database::ProjectStore::create(path, {}).value();
    auto imported = store->import_input(*FileStorage::open(input.path).value(), {Format::raw, raw32()}, input.path, {});
    check(bool(imported), "raw32 project persists canonical recipe");
    if (!imported)
        return;
    auto session = ProjectSession::attach(store, {}, {}).value();
    auto initial = session->snapshot();
    check(initial->functions && initial->functions->instructions.size() == 2 &&
              initial->functions->instructions[0]->instruction.opcode == Opcode::inc,
          "raw32 project analyzes original legacy code");
    session->execute(Rename{Address{{0}, 0x1000}, "legacy_entry"}, 0, {}).value();
    session.reset();
    store.reset();
    std::filesystem::remove(input.path);
    store = database::ProjectStore::open(path, database::ProjectMode::read_only, {}).value();
    session = ProjectSession::attach(store, {}, {}).value();
    check(session->snapshot()->functions->instructions.size() == 2 &&
              presentation_name(*session->snapshot(), Address{{0}, 0x1000}) == "legacy_entry",
          "raw32 source-missing readonly reopen preserves original code and annotations");
}
void persistent_decision_tests() {
    FixtureFile marker(std::span<const std::byte>{});
    std::filesystem::path path = marker.path.wstring() + L".decisions.hxproj";
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code ignored;
            for (auto suffix : {L"", L"-wal", L"-shm"}) {
                auto side = path;
                side += suffix;
                std::filesystem::remove(side, ignored);
            }
        }
    } cleanup{path};
    auto store = database::ProjectStore::create(path, {}).value();
    MemoryStorage input(bytes({0x40, 0xc3, 0x90, 0xc3}));
    store->import_input(input, {Format::raw, raw32()}, {}, {}).value();
    auto session = ProjectSession::attach(store, {}, {}).value();
    const auto apply = [&](ProjectCommand command) {
        session->execute(command, 0, {}).value();
        return session->refresh_analysis({}).value();
    };
    auto data = apply(DefineRegion{Address{{0}, 0x1000}, 1, RegionKind::data});
    check(data->functions->instructions.empty() && data->state->user->decisions.regions[0].kind == RegionKind::data,
          "persisted raw32 data decision blocks rooted code");
    auto code = apply(DefineRegion{Address{{0}, 0x1000}, 1, RegionKind::code});
    check(code->functions->instructions.size() == 2 && code->state->user->decisions.regions[0].kind == RegionKind::code,
          "raw32 code conversion restores actual decode");
    auto defined = apply(DefineFunction{Address{{0}, 0x1002}});
    check(defined->functions->functions.size() == 2, "raw32 explicit function creates separate rooted ownership");
    auto chunks = apply(SetFunctionChunks{Address{{0}, 0x1002}, {{Address{{0}, 0x1002}, 2}}});
    check(chunks->state->user->decisions.functions[0].chunks == std::vector<DecisionRange>{{Address{{0}, 0x1002}, 2}},
          "raw32 explicit chunks persist exact typed ranges");
    auto suppressed = apply(SuppressFunction{Address{{0}, 0x1002}, true});
    check(suppressed->functions->functions.size() == 1, "raw32 suppression removes only explicit root");
    apply(SuppressFunction{Address{{0}, 0x1002}, false});
    session->undo({}).value();
    auto undone = session->refresh_analysis({}).value();
    check(undone->state->user->decisions.functions[0].suppressed && undone->functions->functions.size() == 1,
          "raw32 decision undo restores persisted suppression");
    session->redo({}).value();
    session->refresh_analysis({}).value();
    session.reset();
    store.reset();
    store = database::ProjectStore::open(path, database::ProjectMode::read_write, {}).value();
    session = ProjectSession::attach(store, {}, {}).value();
    auto reopened = session->snapshot();
    const auto &decisions = reopened->state->user->decisions;
    check(reopened->loaded->image->decode_context().mode == ExecutionMode::x86_32 &&
              reopened->state->revisions.edit == 8 && decisions.regions.size() == 1 &&
              decisions.regions[0].kind == RegionKind::code && decisions.functions.size() == 1 &&
              !decisions.functions[0].suppressed && decisions.functions[0].chunks.size() == 1 &&
              reopened->functions->functions.size() == 2,
          "raw32 reopen preserves mode code chunks suppression and full decision history");
    session->undo({}).value();
    auto after_reopen = session->refresh_analysis({}).value();
    check(after_reopen->state->user->decisions.functions[0].suppressed &&
              after_reopen->functions->functions.size() == 1,
          "raw32 undo remains usable after close/reopen");
    session->redo({}).value();
    check(session->refresh_analysis({}).value()->functions->functions.size() == 2,
          "raw32 redo remains usable after close/reopen");
}
} // namespace
int main() {
    return run([] {
        loader_tests();
        recipe_tests();
        reopen_tests();
        persistent_decision_tests();
    });
}
