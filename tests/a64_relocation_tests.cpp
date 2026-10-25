#include "hexlab/loaders/elf.hpp"
#include "hexlab/loaders/macho.hpp"
#include "hexlab/analysis/functions.hpp"
#include "hexlab/analysis/references.hpp"
#include "hexlab/analysis/relocations.hpp"
#include "support/checks.hpp"
#include "support/analysis_fixture.hpp"
#include "support/elf_fixture.hpp"
#include <algorithm>
using namespace hexlab;
using namespace hexlab_test;
namespace {
template <class T> T take(Result<T> result) {
    if (!result)
        throw std::runtime_error(result.error().message);
    return std::move(result.value());
}
void object(const std::filesystem::path &path, bool macho) {
    const auto storage = take(FileStorage::open(path));
    const auto loaded = macho ? take(load_macho(storage, {}, {})) : take(load_elf(storage, {}));
    const auto resolver = take(RelocationResolver::create(*loaded.image, loaded.metadata, {}));
    const auto count = macho ? loaded.metadata.macho->relocations.size() : loaded.metadata.elf->relocations.size();
    check(count == (macho ? 4u : 6u), "actual compiler emits expected original ARM relocation records");
    if (!macho) {
        const auto raw = take(storage->read_at({0}, static_cast<std::size_t>(storage->size())));
        std::vector<std::byte> rel(raw.bytes.begin(), raw.bytes.end());
        const auto &m = *loaded.metadata.elf;
        for (const auto &table : m.relocation_tables)
            elf_fixture::put(rel, m.header.sections.offset + *table.source.section * m.header.sections.stride + 4, 9,
                             4);
        const auto unsupported = take(load_elf(std::make_shared<MemoryStorage>(std::move(rel)), {}));
        for (const auto &row : unsupported.metadata.elf->relocations)
            if (row.type == 282 || row.type == 283)
                check(!row.explicit_addend && !row.addend && !unsupported.metadata.elf->relocations_complete,
                      "unsupported packed REL form cannot mistake instruction opcode word for a scalar addend");
    }
    unsigned defined = 0, unresolved = 0, packed = 0;
    for (std::uint64_t n = 0; n < count; ++n) {
        const auto place =
            macho ? loaded.metadata.macho->relocations[n].place : loaded.metadata.elf->relocations[n].place;
        check(place.has_value(), "compiler relocation has canonical section-domain source");
        if (!place)
            continue;
        const auto decoded = take(decode_at(*loaded.image, *place));
        check(decoded.instruction.has_value(), "original packed relocation source instruction decodes");
        if (!decoded.instruction)
            continue;
        const auto &i = *decoded.instruction;
        std::uint32_t operand = 0;
        for (std::uint32_t k = 0; k < i.operands.size(); ++k)
            if (std::holds_alternative<RelativeOperand>(i.operands[k]) ||
                std::holds_alternative<MemoryOperand>(i.operands[k]) ||
                std::holds_alternative<ImmediateOperand>(i.operands[k]))
                operand = k;
        const auto value = take(resolver.operand(i, operand, {}));
        check(value.relocated() &&
                  std::find(value.relocations.begin(), value.relocations.end(), n) != value.relocations.end(),
              "packed instruction word associates original relocation without fake byte field");
        const auto *es = macho ? nullptr : resolver.elf_symbol(n);
        const auto *ms = macho ? resolver.macho_symbol(n) : nullptr;
        const bool callee = (es && es->name == "callee") || (ms && ms->name == "_callee");
        if (callee) {
            const auto expected = macho ? ms->address : es->address;
            check(expected && value.address == expected &&
                      take(resolver.control_target(*loaded.image, i, {})) == expected,
                  "defined ARM CALL26 uses symbol-plus-addend without x86 PC bias");
            ++defined;
            if (macho) {
                auto encrypted = loaded.metadata;
                const auto file = *encrypted.macho->relocations[n].file_place;
                MachOEncryption declaration;
                declaration.offset = file;
                declaration.raw_offset = static_cast<std::uint32_t>(file.value);
                declaration.size = 4;
                declaration.cryptid = 1;
                encrypted.macho->encryption.push_back(declaration);
                const auto pure = take(MachORelocationResolver::create(encrypted, {}));
                check(!take(pure.operand(i, operand, {})).address,
                      "pure ARM branch resolver cannot derive a pointer from encrypted source word");
                auto noncanonical = loaded.metadata;
                *noncanonical.macho->relocations[n].encoded_value |= 1;
                auto nonzero = i;
                nonzero.bytes[0] |= std::byte{1};
                const auto other = take(MachORelocationResolver::create(noncanonical, {}));
                check(!take(other.operand(nonzero, operand, {})).address,
                      "MachO branch immediate bits are not an implicit scalar addend; explicit ADDEND is required");
            }
        } else {
            check(!value.address, "unknown import/page formula cannot fabricate a target");
            if (i.flow == FlowKind::call || i.flow == FlowKind::jump || i.flow == FlowKind::conditional_branch)
                check(!take(resolver.control_target(*loaded.image, i, {})),
                      "relocation placeholder cannot become decoded numeric callee");
            ++unresolved;
        }
        if (operand)
            ++packed;
    }
    check(defined == 1 && unresolved == (macho ? 3u : 5u) && packed > 0,
          "defined, unresolved and nonfirst packed operand cases all exercised");
    const auto functions = take(recover_functions(*loaded.image, loaded.metadata, {}, {}, {}));
    const auto references = take(derive_references(*loaded.image, *functions, loaded.metadata, {}, {}));
    bool nonfirst = false;
    unsigned unresolved_macho_origins = 0;
    for (const auto &ref : references->all()) {
        if (ref.kind == ReferenceKind::conditional_jump)
            nonfirst = nonfirst || (ref.operand_index && *ref.operand_index > 0 &&
                                    std::holds_alternative<UnresolvedTarget>(ref.target));
        if (macho && ref.provenance.macho &&
            (ref.provenance.macho->resolution != MachOResolutionReason::resolved || ref.provenance.macho->constant)) {
            ++unresolved_macho_origins;
            const auto *target = std::get_if<UnresolvedTarget>(&ref.target);
            check(target && target->reason == UnresolvedReason::macho_relocation && !ref.association,
                  "unresolved Mach-O relocation is never promoted to a dataflow pointer target");
        }
    }
    check(macho || nonfirst, "conditional ARM relocation reference retains its nonfirst relative operand index");
    check(!macho || unresolved_macho_origins > 0,
          "Mach-O reference fixture exposes unresolved relocations to the reference index");
    const auto encoded = take(encode_reference_index(*references, {}));
    check(take(decode_reference_index(encoded, {}))->all().size() == references->all().size(),
          "original ARM source provenance round-trips");
}
} // namespace
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    return run([&] {
        object(argv[1], false);
        object(argv[2], true);
    });
}
