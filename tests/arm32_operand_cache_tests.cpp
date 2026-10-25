#include "hexlab/analysis/references.hpp"
#include "hexlab/analysis/derived_cache.hpp"
#include "hexlab/core/sha256.hpp"
#include "support/checks.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
RegisterOperand reg(unsigned n) { return {RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false}; }
void packed() {
    const auto create = [](RelativeOperand value) {
        Reference r{{0},
                    Address{{9}, 0xfffffffc},
                    0,
                    UnresolvedTarget{UnresolvedReason::relative_overflow, value},
                    ReferenceKind::jump,
                    OperandAccess::address,
                    {ReferenceProvenanceKind::decoded, 77, 0},
                    {}};
        return ReferenceIndex::create({r}, {}, true, {});
    };
    check(bool(create({4, 24, 32, {}})) && bool(create({2, 25, 32, {}})),
          "packed A32 B and BLX relative fields validate without fake byte ranges");
    for (auto value :
         {RelativeOperand{2, 24, 32, {}}, RelativeOperand{1, 25, 32, {}}, RelativeOperand{INT64_C(1) << 25, 24, 32, {}},
          RelativeOperand{4, 24, 64, {}}, RelativeOperand{4, 24, 32, EncodedField{0, 3}}})
        check(!create(value), "A32 packed displacement bounds/alignment/width/field evidence are enforced");
}
void thumb_references() {
    const auto create = [](ThumbRelativeOperand value) {
        Reference r{{0},
                    Address{{9}, 0xfffffffc},
                    0,
                    UnresolvedTarget{UnresolvedReason::relative_overflow, value},
                    ReferenceKind::jump,
                    OperandAccess::address,
                    {ReferenceProvenanceKind::decoded, 77, 0},
                    {}};
        return ReferenceIndex::create({r}, {}, true, {});
    };
    for (auto value : {ThumbRelativeOperand{126, 6}, ThumbRelativeOperand{-256, 8}, ThumbRelativeOperand{254, 8},
                       ThumbRelativeOperand{-2048, 11}, ThumbRelativeOperand{2046, 11},
                       ThumbRelativeOperand{-(INT64_C(1) << 20), 20}, ThumbRelativeOperand{(INT64_C(1) << 24) - 4, 23},
                       ThumbRelativeOperand{(INT64_C(1) << 24) - 2, 24}}) {
        const auto index = create(value);
        check(bool(index), "Thumb relative sign/scaling boundary validates independently of A32");
        if (!index)
            continue;
        const auto wire = encode_reference_index(*index.value(), {});
        check(wire && decode_reference_index(wire.value(), {}), "Thumb relative expression roundtrips");
    }
    for (auto value : {ThumbRelativeOperand{-2, 6}, ThumbRelativeOperand{128, 6}, ThumbRelativeOperand{256, 8},
                       ThumbRelativeOperand{2048, 11}, ThumbRelativeOperand{1, 20}, ThumbRelativeOperand{2, 23},
                       ThumbRelativeOperand{INT64_C(1) << 24, 24}, ThumbRelativeOperand{0, 25}})
        check(!create(value), "Thumb-specific alignment/range/field-width errors reject");
    const auto index = create({2, 24}).value();
    const auto encoded = encode_reference_index(*index, {}).value();
    for (unsigned version : {7, 8}) {
        auto forged = encoded;
        forged[0] = std::byte(version);
        Sha256 h;
        h.update(std::span(forged).first(forged.size() - 32));
        const auto digest = h.digest();
        std::copy(digest.begin(), digest.end(), forged.end() - 32);
        check(!decode_reference_index(forged, {}), "checksum-valid old reference wire cannot carry Thumb relative tag");
    }
}
template <class E> void references() {
    if constexpr (requires(E e, ArmMemoryOperand m) { e = m; }) {
        ArmMemoryOperand m{reg(1)};
        m.offset = ArmShiftedRegisterOperand{reg(2), ArmShift::rrx, 1, {}};
        m.add = false;
        m.pre_index = false;
        m.writeback = true;
        m.data_width = 8;
        m.sign_extend = true;
        const auto create = [&](ArmMemoryOperand memory) {
            Reference r{{0},
                        Address{{9}, 0x1000},
                        1,
                        UnresolvedTarget{UnresolvedReason::memory_address, E{memory}},
                        ReferenceKind::memory_read,
                        OperandAccess::read,
                        {ReferenceProvenanceKind::decoded, 77, 0},
                        {}};
            return ReferenceIndex::create({r}, {}, true, {});
        };
        const auto index = create(m);
        check(bool(index), "ARM memory reference expression validates");
        if (!index)
            return;
        const auto encoded = encode_reference_index(*index.value(), {});
        check(encoded && encoded.value()[0] == std::byte{9}, "Thumb expressions advance standalone wire to9");
        if (!encoded)
            return;
        const auto restored = decode_reference_index(encoded.value(), {});
        check(restored && restored.value()->all()[0].id == index.value()->all()[0].id &&
                  std::get<ArmMemoryOperand>(
                      std::get<UnresolvedTarget>(restored.value()->all()[0].target).expression) == m,
              "ARM memory expression/indexing/shift roundtrips without flattening");
        auto forged = encoded.value();
        forged[0] = std::byte{7};
        Sha256 hash;
        check(bool(hash.update(std::span(forged).first(forged.size() - 32))),
              "forged reference checksum input accepted");
        const auto digest = hash.digest();
        std::copy(digest.begin(), digest.end(), forged.end() - 32);
        check(!decode_reference_index(forged, {}),
              "checksum-valid legacy wire7 cannot smuggle a new ARM memory expression");
        auto bad = m;
        bad.base = reg(16);
        check(!create(bad), "out-of-range ARM memory base rejected");
        bad = m;
        std::get<ArmShiftedRegisterOperand>(bad.offset).amount_register = reg(3);
        check(!create(bad), "memory offsets cannot carry register-controlled shifts");
        bad = m;
        bad.pre_index = true;
        bad.writeback = false;
        bad.resolved_address = Address{{9}, 0x1000};
        check(!create(bad), "register-dependent memory cannot claim a resolved address");
        bad = m;
        bad.writeback = false;
        check(!create(bad), "post-index memory always writes back");
    } else
        check(false, "ARM memory reference expression exists");
}
void instructions() {
    const auto encode = [](const Instruction &i) {
        DerivedProposal p;
        p.context = i.context;
        p.domain_contexts = {DomainContext{i.address.space, i.context}};
        p.mapping_fingerprint = Sha256Digest{};
        p.complete = true;
        auto f = std::make_shared<FunctionSnapshot>();
        f->key = p.source_key;
        f->instructions.push_back(std::make_shared<InstructionFact>(InstructionFact{1, i, {}}));
        p.functions = f;
        auto refs = ReferenceIndex::create({}, p.source_key, true, {});
        if (!refs)
            throw std::runtime_error(refs.error().message);
        p.references = refs.value();
        auto strings = std::make_shared<StringScan>();
        strings->complete = true;
        p.strings = strings;
        return encode_derived(p, {});
    };
    for (auto word : {0xe1b00211u, 0xe5b10004u, 0xe92d4010u}) {
        const std::array raw{std::byte(word), std::byte(word >> 8), std::byte(word >> 16), std::byte(word >> 24)};
        auto decoded =
            decode_instruction({Architecture::arm, ExecutionMode::a32, ByteOrder::little}, raw, {{9}, 0x1000});
        check(decoded.instruction.has_value(), "canonical operand codec input decodes");
        if (!decoded.instruction)
            continue;
        const auto original = *decoded.instruction;
        check(bool(encode(original)), "low-level instruction encoder retains source-canonical ARM operand shapes");
        auto changed = original;
        for (auto &operand : changed.operands) {
            if (auto shifted = std::get_if<ArmShiftedRegisterOperand>(&operand))
                shifted->amount_register = reg(3);
            if (auto memory = std::get_if<ArmMemoryOperand>(&operand))
                memory->add = !memory->add;
            if (auto list = std::get_if<ArmRegisterListOperand>(&operand))
                list->mask ^= 1;
        }
        check(!encode(changed), "typed shift/address/list alteration cannot survive canonical source-word validation");
        changed = original;
        changed.arm->flags_written ^= 1;
        check(!encode(changed), "forged ARM flag effects cannot enter a canonical instruction record");
    }
    const std::array thumb_bytes{std::byte{1}, std::byte{0x20}};
    for (auto state : {ThumbITState{true, 0}, ThumbITState{true, 0x0c}, ThumbITState{true, 0x18}, ThumbITState{}}) {
        const auto decoded = decode_thumb(thumb_bytes, {{9}, 0x1000}, state);
        check(decoded.instruction.has_value(), "Thumb state codec input decodes");
        if (!decoded.instruction)
            continue;
        check(bool(encode(*decoded.instruction)), "canonical Thumb instruction uses explicit incoming IT state");
        auto forged = *decoded.instruction;
        forged.arm->it_after = {true, 0x18};
        if (forged.arm->it_after == decoded.instruction->arm->it_after)
            forged.arm->it_after = {true, 0};
        check(!encode(forged), "forged IT successor state cannot survive canonical decoding");
    }
    for (const auto half : {0xbf0cu, 0xe000u, 0xb100u}) {
        const std::array raw{std::byte(half), std::byte(half >> 8)};
        const auto decoded = decode_thumb(raw, {{9}, 0x1000}, {true, 0});
        check(decoded.instruction && encode(*decoded.instruction),
              "canonical Thumb IT/control forms preserve typed payload");
    }
}
} // namespace
int main() {
    return run([] {
        packed();
        thumb_references();
        references<ReferenceExpression>();
        instructions();
    });
}
