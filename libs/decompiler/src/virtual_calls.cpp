#include "hexlab/decompiler/virtual_calls.hpp"

#include <utility>

namespace hexlab::decompiler {
namespace {
bool same_type(const types::TypePtr &left, const types::TypePtr &right, unsigned depth = 0) {
    if (!left || !right || depth > 64 || left->kind() != right->kind()) return false;
    switch (left->kind()) {
    case types::Kind::function:
        if (left->function_convention() != right->function_convention() ||
            left->variadic() != right->variadic() ||
            left->parameters().size() != right->parameters().size() ||
            !same_type(left->result_type(), right->result_type(), depth + 1)) return false;
        for (std::size_t i = 0; i < left->parameters().size(); ++i)
            if (!same_type(left->parameters()[i].type, right->parameters()[i].type, depth + 1))
                return false;
        return true;
    case types::Kind::pointer:
        return left->size() == right->size() && left->alignment() == right->alignment() &&
               same_type(left->element(), right->element(), depth + 1);
    case types::Kind::array:
    case types::Kind::vector:
        return left->count() == right->count() && left->size() == right->size() &&
               left->alignment() == right->alignment() &&
               same_type(left->element(), right->element(), depth + 1);
    case types::Kind::qualified:
        return left->qualifiers() == right->qualifiers() && left->size() == right->size() &&
               left->alignment() == right->alignment() &&
               same_type(left->element(), right->element(), depth + 1);
    default:
        return left->id() == right->id();
    }
}

bool exact_type(const types::TypePtr &left, const types::TypePtr &right) {
    return left && right && left->kind() == types::Kind::function &&
           right->kind() == types::Kind::function && same_type(left, right);
}
}

VirtualCallAnalysis analyze_virtual_call(const VirtualCallEvidence &evidence) {
    VirtualCallAnalysis result;
    const auto &receiver = evidence.receiver_class;
    if ((evidence.pointer_bytes != 4 && evidence.pointer_bytes != 8) ||
        evidence.slot_byte_offset % evidence.pointer_bytes != 0 ||
        !receiver || (receiver->kind() != types::Kind::structure &&
                      receiver->kind() != types::Kind::union_type) ||
        !evidence.exact_signature ||
        evidence.exact_signature->kind() != types::Kind::function)
        return result;

    for (const auto &method : receiver->methods()) {
        if (!method.signature || !exact_type(method.signature, evidence.exact_signature))
            continue;
        const types::VTableSlot *matched_slot = nullptr;
        if (evidence.vftable_pointer_offset) {
            const auto slot_index = evidence.slot_byte_offset / evidence.pointer_bytes;
            for (const auto &slot : method.vtable_slots) {
                if (slot.vfptr_offset == *evidence.vftable_pointer_offset &&
                    slot.slot_index == slot_index && slot.method_name == method.name) {
                    matched_slot = &slot;
                    break;
                }
            }
            if (!matched_slot) continue;
        } else if (!method.introducing_vtable_offset ||
                   *method.introducing_vtable_offset != evidence.slot_byte_offset) {
            continue;
        }
        auto provenance = evidence.provenance;
        if (matched_slot) {
            if (!provenance.empty()) provenance += "; ";
            provenance += "CodeView LF_VFTABLE " + matched_slot->table_name +
                " at TPI type 0x";
            constexpr char digits[] = "0123456789abcdef";
            const auto append_hex = [&](std::uint32_t value) {
                for (int shift = 28; shift >= 0; shift -= 4)
                    provenance.push_back(digits[(value >> shift) & 0xf]);
            };
            append_hex(matched_slot->source_type_index);
            provenance += " record+0x";
            append_hex(matched_slot->source_record_offset);
            provenance += " slot#" + std::to_string(matched_slot->slot_index);
        }
        result.candidates.push_back({method.name, method.declaration_ordinal,
                                     evidence.slot_byte_offset, method.signature,
                                     std::move(provenance)});
    }
    result.ambiguous = result.candidates.size() > 1;
    result.uniquely_typed = result.candidates.size() == 1;
    return result;
}
} // namespace hexlab::decompiler
