#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/processors/format.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include "support/analysis_fixture.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
struct Fixture {
    std::shared_ptr<const Image> image;
    std::shared_ptr<const ImageMetadata> metadata;
    AnalysisDecisions decisions;
    AnalysisOptions options;
    AnalysisKey key;
    DerivedProposal derived;
    explicit Fixture(std::vector<std::byte> data, ImageMetadata symbols = {}, AnalysisOptions limits = {})
        : image(memory_image(std::move(data))), metadata(std::make_shared<const ImageMetadata>(std::move(symbols))),
          options(limits) {
        key.input = {image->storage()->size(), hash_source(*image->storage(), {}).value()};
        key.engine_fingerprint = function_engine_fingerprint(options);
        derived = analyze_derived(image, metadata, decisions, options, key, {}).value();
    }
    Result<DerivedProposal> decode(std::span<const std::byte> payload) const {
        return decode_derived(payload, *image, *metadata, decisions, options, key, {});
    }
};
DerivedProposal restore(const Fixture &fixture) {
    auto encoded = encode_derived(fixture.derived, {});
    if (!encoded)
        throw std::runtime_error("Cache encode: " + encoded.error().message);
    auto decoded = fixture.decode(encoded.value());
    if (!decoded)
        throw std::runtime_error("Cache decode: " + decoded.error().message);
    return std::move(decoded.value());
}
void checksum(std::vector<std::byte> &payload) {
    Sha256 hash;
    check(bool(hash.update(std::span(payload).first(payload.size() - 32))), "hostile cache fixture checksum computes");
    auto digest = hash.digest();
    std::copy(digest.begin(), digest.end(), payload.end() - 32);
}
void roundtrip_tests() {
    Fixture fixture(bytes({0xf0, 0x48, 0x01, 0x18, 0x64, 0x48, 0x8b, 0x00, 0x48, 0x8d, 0x05, 0,    0,   0,
                           0,    0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0x75, 2,    0x90, 0xc3, 0xcc}));
    auto payload = encode_derived(fixture.derived, {}).value();
    auto restored = fixture.decode(payload).value();
    check(restored.source_key == fixture.key && restored.functions->key == fixture.key &&
              restored.references->key() == fixture.key,
          "cached derived layers retain one exact source key");
    check(restored.functions->instructions.size() == fixture.derived.functions->instructions.size() &&
              restored.functions->blocks.size() == fixture.derived.functions->blocks.size() &&
              restored.functions->functions.size() == fixture.derived.functions->functions.size(),
          "instruction/block/function counts survive canonical cache roundtrip");
    bool lock = false, segment = false, immediate = false;
    for (size_t i = 0; i < restored.functions->instructions.size(); ++i) {
        auto &fact = *restored.functions->instructions[i];
        auto &original = *fixture.derived.functions->instructions[i];
        check(fact.id == original.id &&
                  format_instruction(fact.instruction) == format_instruction(original.instruction),
              "cached instruction identity and presentation equal source facts");
        lock = lock || fact.instruction.lock_prefix;
        for (auto &operand : fact.instruction.operands) {
            if (auto memory = std::get_if<MemoryOperand>(&operand))
                segment = segment || memory->segment.has_value();
            if (auto value = std::get_if<ImmediateOperand>(&operand))
                immediate = immediate || (value->is_signed && value->effective_width == 64);
        }
    }
    check(lock && segment && immediate,
          "cache preserves lock prefix segment expressions and sign-extended immediate typing");
    check(encode_derived(restored, {}).value() == payload, "derived cache has a stable canonical encoding");
    check(restored.counters.cache_validation_decodes >= restored.functions->instructions.size(),
          "decoder checks used to validate cached typed operands are explicitly counted");
    for (auto &block : restored.functions->blocks)
        for (auto &fact : block->instructions) {
            auto found = std::find_if(restored.functions->instructions.begin(), restored.functions->instructions.end(),
                                      [&](auto &value) { return value->id == fact->id; });
            check(found != restored.functions->instructions.end() && *found == fact,
                  "cached blocks and listing share interned immutable instruction facts");
        }
}
void context_tests(const std::filesystem::path &legacy_path) {
    static_assert(derived_cache_version == 12, "Function unwind seed provenance requires a new cache version");
    const DecodeContext x64{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::little};
    const DecodeContext x32{Architecture::x86, ExecutionMode::x86_32, ByteOrder::little};
    Fixture fixture(bytes({0xe8, 1, 0, 0, 0, 0xc3, 0xc3}));
    auto payload = encode_derived(fixture.derived, {}).value();
    auto restored = fixture.decode(payload).value();
    check(fixture.derived.context == x64 && restored.context == x64,
          "proposal and cache envelope retain authoritative image context");
    check(restored.mapping_fingerprint == fixture.image->mapping_fingerprint({}).value() &&
              restored.domain_contexts == std::vector<DomainContext>{{{0}, x64}},
          "cache binds the full source mapping and domain table");
    for (auto &fact : restored.functions->instructions) {
        check(fact->instruction.context == x64, "every cached fact retains its explicit processor context");
        if (fact->instruction.flow == FlowKind::call)
            check(fact->instruction.stack_value_width == 64 &&
                      std::get<RelativeOperand>(fact->instruction.operands[0]).effective_width == 64,
                  "cache preserves hidden stack and relative target widths");
    }
    // Primary context5, mapping digest32, count4, one id4/context5 domain.
    constexpr std::size_t context = 126, first_instruction = 209;
    check(payload.size() > first_instruction + 3 + 32 &&
              payload[context] == std::byte(static_cast<unsigned>(Architecture::x86_64)) &&
              payload[first_instruction] == payload[context],
          "literal v4 envelope and instruction context positions are canonical");
    check(payload[context + 3] == std::byte{0} && payload[first_instruction + 3] == std::byte{0},
          "explicit stack attribute is present in envelope and instruction records");
    // Context5 + address12 + absent-ARM-info1 + length1 + bytes5 + opcode2 + operand-count1 +
    // operand-tag1 + displacement8 + encoded/effective widths2+2.
    constexpr auto relative_field = first_instruction + 5 + 12 + 1 + 1 + 5 + 2 + 1 + 1 + 8 + 2 + 2;
    check(payload[relative_field] == std::byte{1} && payload[relative_field + 1] == std::byte{1} &&
              payload[relative_field + 2] == std::byte{4} &&
              std::get<RelativeOperand>(restored.functions->instructions[0]->instruction.operands[0]).encoding ==
                  EncodedField{1, 4},
          "v4 literal encoding span and restored operand both identify the actual CALL displacement");
    auto field_forgery = payload;
    field_forgery[relative_field + 1] = std::byte{0};
    checksum(field_forgery);
    check(!fixture.decode(field_forgery),
          "checksum-valid operand field forgery cannot replace decoded source coordinates");
    auto forged = payload;
    forged[131] ^= std::byte{1};
    checksum(forged);
    auto wrong_mapping = fixture.decode(forged);
    check(!wrong_mapping && wrong_mapping.error().message.find("mapping") != std::string::npos,
          "checksum-valid mapping fingerprint forgery is rejected");
    forged = payload;
    forged[175] = std::byte{1};
    checksum(forged);
    auto wrong_domain = fixture.decode(forged);
    check(!wrong_domain && wrong_domain.error().message.find("domain") != std::string::npos,
          "checksum-valid per-domain context forgery is rejected");
    forged = payload;
    forged[context] = std::byte(static_cast<unsigned>(Architecture::x86));
    forged[context + 1] = std::byte(static_cast<unsigned>(ExecutionMode::x86_32));
    checksum(forged);
    check(!fixture.decode(forged), "checksum-valid cache cannot select another processor context for current image");
    forged = payload;
    forged[first_instruction] = std::byte(static_cast<unsigned>(Architecture::x86));
    forged[first_instruction + 1] = std::byte(static_cast<unsigned>(ExecutionMode::x86_32));
    checksum(forged);
    check(!fixture.decode(forged), "individual fact context cannot differ from its envelope and image");
    for (auto invalid : std::vector<DecodeContext>{
             DecodeContext{}, DecodeContext{Architecture::x86_64, ExecutionMode::x86_64, ByteOrder::big},
             DecodeContext{Architecture::x86, ExecutionMode::unknown, ByteOrder::little}}) {
        auto copy = fixture.derived;
        copy.context = invalid;
        check(!encode_derived(copy, {}), "unsupported producer context cannot become a persistent derived cache");
    }
    auto inconsistent = fixture.derived;
    inconsistent.context = x32;
    check(!encode_derived(inconsistent, {}), "producer envelope context must match every encoded instruction");
    auto mutate = [&](auto change) {
        auto copy = fixture.derived;
        auto functions = std::make_shared<FunctionSnapshot>(*copy.functions);
        auto original = functions->instructions[0];
        auto replacement = std::make_shared<InstructionFact>(*original);
        change(replacement->instruction);
        functions->instructions[0] = replacement;
        for (auto &block : functions->blocks) {
            auto editable = std::make_shared<BasicBlock>(*block);
            for (auto &fact : editable->instructions)
                if (fact->id == original->id)
                    fact = replacement;
            block = editable;
        }
        for (auto &conflict : functions->conflicts) {
            if (conflict.first_fact && conflict.first_fact->id == original->id)
                conflict.first_fact = replacement;
            if (conflict.second_fact && conflict.second_fact->id == original->id)
                conflict.second_fact = replacement;
        }
        copy.functions = functions;
        return copy;
    };
    check(!encode_derived(mutate([](Instruction &i) { i.stack_value_width = 32; }), {}),
          "wrong typed return-slot width cannot enter cache even when all fact aliases agree");
    check(!encode_derived(mutate([](Instruction &i) { i.stack_slot_count = 2; }), {}),
          "wrong total return slot count cannot enter a canonical cache");
    check(!encode_derived(mutate([](Instruction &i) { i.arm.emplace(); }), {}),
          "ARM execution metadata cannot be injected into a canonical x86 instruction");
    check(!encode_derived(mutate([](Instruction &i) { std::get<RelativeOperand>(i.operands[0]).effective_width = 32; }),
                          {}),
          "wrong typed relative width cannot enter cache even when raw bytes are unchanged");
    check(
        !encode_derived(
            mutate([](Instruction &i) { std::get<RelativeOperand>(i.operands[0]).encoding = EncodedField{0, 4}; }), {}),
        "forged operand encoding range cannot enter cache even when raw bytes are unchanged");
    check(
        !encode_derived(mutate([](Instruction &i) { std::get<RelativeOperand>(i.operands[0]).encoding.reset(); }), {}),
        "missing decoded operand encoding cannot silently enter a canonical cache");
    auto storage = FileStorage::open(legacy_path).value();
    check(storage->size() == 991 && digest_hex(hash_source(*storage, {}).value()) ==
                                        "2718f208c3d0a1d57fcac7511ede5609b43948d177604605eccc3d09eb97de44",
          "genuine v1 fixture matches independently recorded bytes/hash");
    auto old = storage->read_at({0}, 991).value();
    auto key = inspect_derived_key(old.bytes, {});
    check(!key && key.error().code == ErrorCode::unsupported,
          "genuine pre-context v1 cache is incompatible rather than interpreted as new records");
    auto decoded = fixture.decode(old.bytes);
    check(!decoded && decoded.error().code == ErrorCode::unsupported,
          "old payload rejection precedes mode/source reconstruction");
}
void hostile_tests() {
    Fixture fixture(bytes({0x90, 0xc3}));
    auto payload = encode_derived(fixture.derived, {}).value();
    auto damaged = payload;
    damaged[10] ^= std::byte{1};
    check(!fixture.decode(damaged), "damaged derived checksum is a cache miss candidate");
    // Source-bound flat header places completeness at176 and first fact count193.
    auto count = payload;
    check(count.size() > 197 + 32, "cache fixture includes a counted fact table");
    for (size_t i = 193; i < 197; ++i)
        count[i] = std::byte{0xff};
    checksum(count);
    check(!fixture.decode(count), "checksum-valid hostile fact count is rejected before allocation");
    auto version = payload;
    version[5] = std::byte{99};
    checksum(version);
    check(!fixture.decode(version), "unknown derived payload version rejected");
    auto false_complete = payload;
    false_complete[176] = std::byte{0};
    checksum(false_complete);
    check(!fixture.decode(false_complete),
          "checksum-valid fabricated completeness cannot pass rooted derivation validation");
    auto key = fixture.key;
    ++key.byte_revision;
    check(!decode_derived(payload, *fixture.image, *fixture.metadata, fixture.decisions, fixture.options, key, {}),
          "cached payload cannot substitute an older source revision");
    auto different = memory_image(bytes({0xcc, 0xc3}));
    check(!decode_derived(payload, *different, *fixture.metadata, fixture.decisions, fixture.options, fixture.key, {}),
          "cached instruction bytes are checked against effective input");
    auto invalid = fixture.derived;
    auto snapshot = std::make_shared<FunctionSnapshot>(*invalid.functions);
    auto fact = std::make_shared<InstructionFact>(*snapshot->instructions[0]);
    fact->instruction.opcode = Opcode::ret;
    snapshot->instructions[0] = fact;
    invalid.functions = snapshot;
    check(!encode_derived(invalid, {}), "typed instruction inconsistent with raw bytes cannot enter cache");
    for (size_t size = 0; size < std::min<size_t>(payload.size(), 128); ++size)
        check(!fixture.decode(std::span(payload).first(size)),
              "truncated cache rejects without partially publishing models");
    std::stop_source stop;
    stop.request_stop();
    check(!encode_derived(fixture.derived, stop.get_token()) &&
              !decode_derived(payload, *fixture.image, *fixture.metadata, fixture.decisions, fixture.options,
                              fixture.key, stop.get_token()),
          "encode/decode cancellation publishes no partial cache");
}
void conflict_and_shared_tests() {
    ImageMetadata metadata;
    metadata.exports.push_back({1, "overlap", Address{{0}, 0x1001}, {}});
    Fixture overlap(bytes({0x48, 0x89, 0xd8, 0xc3}), metadata);
    check(!overlap.derived.functions->conflicts.empty() && !overlap.derived.complete,
          "conflicting-stream fixture is explicitly incomplete");
    auto restored = restore(overlap);
    check(restored.functions->conflicts.size() == overlap.derived.functions->conflicts.size() &&
              restored.functions->conflicts[0].first_fact && restored.functions->conflicts[0].second_fact &&
              !restored.complete,
          "cache retains untrusted conflict facts and incomplete state");
    auto data = std::vector<std::byte>(17);
    data[0] = std::byte{0xeb};
    data[1] = std::byte{14};
    data[8] = std::byte{0xeb};
    data[9] = std::byte{6};
    data[16] = std::byte{0xc3};
    metadata = {};
    metadata.exports.push_back({1, "shared", Address{{0}, 0x1008}, {}});
    Fixture shared(data, metadata);
    restored = restore(shared);
    check(std::any_of(restored.functions->blocks.begin(), restored.functions->blocks.end(),
                      [](auto &block) { return block->owners.size() == 2; }),
          "persisted shared tail retains both function owners");
    AnalysisOptions budget;
    budget.instruction_budget = 1;
    Fixture partial(bytes({0x90, 0xc3}), {}, budget);
    restored = restore(partial);
    check(!restored.complete && !restored.functions->complete && !restored.functions->functions[0]->stops.empty(),
          "budget-limited cache retains explicit stop reasons");
    Fixture strings(bytes({0xc3, 'h', 'e', 'l', 'l', 'o', 0, 0, 'A', 0, 'B', 0, 'C', 0, 'D', 0, 0, 0,
                          0xc3, 0xa9, ' ', 0xe4, 0xb8, 0x96, ' ', 0xf0, 0x9f, 0x8c, 0x8d, 0}));
    restored = restore(strings);
    check(restored.strings->records.size() == strings.derived.strings->records.size() &&
              std::any_of(
                  restored.strings->records.begin(), restored.strings->records.end(),
                  [](auto &record) { return record.encoding == StringEncoding::ascii && record.preview == "hello"; }) &&
              std::any_of(restored.strings->records.begin(), restored.strings->records.end(), [](auto &record) {
                  return record.encoding == StringEncoding::utf8 && record.characters == 5 && record.byte_length == 11;
              }),
          "persisted legacy and UTF-8 string records and previews validate against actual bytes");
}
void unwind_seed_provenance_tests() {
    ImageMetadata metadata;
    ElfMetadata elf;
    elf.unwind_ranges.push_back({2, 1041, 17, Address{{0}, 0x1002}, 2});
    metadata.elf = std::move(elf);
    Fixture fixture(bytes({0x90, 0xc3, 0x90, 0xc3}), std::move(metadata));
    auto restored = restore(fixture);
    const auto find_unwind = [](const FunctionSnapshot &snapshot) -> const FunctionSeed * {
        for (const auto &function : snapshot.functions)
            for (const auto &seed : function->seeds)
                if (seed.kind == FunctionSeedKind::unwind) return &seed;
        return nullptr;
    };
    const auto *seed = find_unwind(*restored.functions);
    check(seed && seed->entry == Address{{0}, 0x1002} &&
              seed->unwind_evidence == FunctionSeedUnwindEvidence{2, 1041, 17},
          "derived cache roundtrip preserves the FDE source provenance attached to an unwind root");
}
} // namespace
int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    return run([&] {
        roundtrip_tests();
        context_tests(std::filesystem::path(argv[1]));
        hostile_tests();
        conflict_and_shared_tests();
        unwind_seed_provenance_tests();
    });
}
