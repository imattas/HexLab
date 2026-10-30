#include "hexlab/types/layout.hpp"

#include <algorithm>
#include <limits>
#include <unordered_set>

namespace hexlab::types {
namespace {
using hexlab::Error;
using hexlab::ErrorCode;

Error unsupported(std::string message) { return {ErrorCode::unsupported, std::move(message)}; }
Error overflow(std::string message) { return {ErrorCode::overflow, std::move(message)}; }

std::uint64_t maximum_alignment(Abi abi) noexcept {
    switch (abi) {
    case Abi::x86_32: return 4;
    case Abi::x86_64: return 16;
    case Abi::aarch64: return 16;
    case Abi::aarch32: return 8;
    }
    return 1;
}

bool align_up(std::uint64_t value, std::uint64_t alignment, std::uint64_t &result) noexcept {
    if (!alignment || (alignment & (alignment - 1)) != 0)
        return false;
    const auto padding = (alignment - (value & (alignment - 1))) & (alignment - 1);
    if (padding > std::numeric_limits<std::uint64_t>::max() - value)
        return false;
    result = value + padding;
    return true;
}

struct Calculator {
    Abi abi;
    std::uint64_t alignment_limit;
    BitfieldLayoutPolicy bitfield_policy;
    const NamedTypeResolver &resolve_named_type;
    std::unordered_set<const Type *> active;
    std::unordered_set<std::string> active_names;

    hexlab::Result<TypeLayout> calculate(const Type &type) {
        if (!active.insert(&type).second)
            return unsupported("recursive by-value type graph cannot be laid out");
        struct Erase {
            std::unordered_set<const Type *> &set;
            const Type *value;
            ~Erase() { set.erase(value); }
        } erase{active, &type};

        TypeLayout result;
        result.pointer_size = types::pointer_size(abi);
        const auto cap = maximum_alignment(abi);
        switch (type.kind()) {
        case Kind::qualified:
            if (!type.element()) return unsupported("qualified type has no base type");
            return calculate(*type.element());
        case Kind::pointer:
            result.size = result.pointer_size;
            result.alignment = std::min(type.alignment(), cap);
            return result;
        case Kind::boolean:
        case Kind::integer:
        case Kind::floating:
            if (!type.size() || !*type.size() || !type.alignment())
                return unsupported("scalar type has no complete size and alignment");
            result.size = *type.size();
            result.alignment = std::min(type.alignment(), cap);
            return result;
        case Kind::vector: {
            if (!type.element() || !type.count() || !type.size())
                return unsupported("vector type has no complete lane shape");
            auto lane = calculate(*type.element());
            if (!lane) return lane.error();
            if (lane.value().size > std::numeric_limits<std::uint64_t>::max() / type.count() ||
                lane.value().size * type.count() != *type.size())
                return overflow("vector size does not match its lane shape");
            result.size = *type.size();
            result.alignment = std::min({type.alignment(), cap, alignment_limit});
            return result;
        }
        case Kind::enumeration: {
            if (!type.element())
                return unsupported("enumeration has no underlying type");
            auto underlying = calculate(*type.element());
            if (!underlying)
                return underlying.error();
            if (type.element()->kind() != Kind::integer)
                return unsupported("only integer-backed enumerations are supported");
            result.size = underlying.value().size;
            result.alignment = underlying.value().alignment;
            return result;
        }
        case Kind::array: {
            if (!type.element() || !type.count())
                return unsupported("array type is incomplete");
            auto element = calculate(*type.element());
            if (!element)
                return element.error();
            const auto stride = type.array_stride() ? type.array_stride() : element.value().size;
            if (stride < element.value().size || type.count() - 1 >
                (std::numeric_limits<std::uint64_t>::max() - element.value().size) / stride)
                return overflow("array size overflows 64-bit layout");
            result.size = (type.count() - 1) * stride + element.value().size;
            result.alignment = element.value().alignment;
            return result;
        }
        case Kind::structure: {
            if (!type.size())
                return unsupported("incomplete structure has no object layout");
            if (type.members().empty()) {
                // With no members there is no placement to recompute. Preserve
                // the complete extent/alignment recorded by the source type
                // producer (for example DWARF or CodeView) rather than
                // guessing an ABI-specific empty-class rule.
                result.size = *type.size();
                result.alignment = type.alignment();
                return result;
            }
            std::uint64_t cursor = 0;
            std::uint64_t aggregate_alignment = 1;
            const auto aggregate_cap = type.packing_alignment()
                ? std::min(alignment_limit, *type.packing_alignment()) : alignment_limit;
            std::optional<std::uint64_t> bitfield_source_offset;
            std::uint64_t bitfield_storage_size = 0;
            std::uint64_t bitfield_layout_offset = 0;
            struct MicrosoftBitfieldUnit {
                std::uint64_t size = 0;
                std::uint64_t alignment = 1;
                std::uint64_t offset = 0;
                std::uint64_t used = 0;
            };
            std::optional<MicrosoftBitfieldUnit> microsoft_bitfield_unit;
            result.members.reserve(type.members().size());
            for (const auto &member : type.members()) {
                if (member.virtual_base)
                    return unsupported("virtual base offset requires runtime vbptr/vbtable evaluation");
                if (!member.type)
                    return unsupported("structure member has no type");
                const Type *member_base = member.type.get();
                while (member_base && member_base->kind() == Kind::qualified)
                    member_base = member_base->element().get();
                const bool flexible_array = member_base && member_base->kind() == Kind::array &&
                                            member_base->count() == 0 && !member_base->size();
                auto child = [&]() -> hexlab::Result<TypeLayout> {
                    if (flexible_array && member_base->element()) {
                        auto element = calculate(*member_base->element());
                        if (!element) return element.error();
                        auto tail = element.value();
                        tail.size = 0;
                        return tail;
                    }
                    return calculate(*member.type);
                }();
                if (!child)
                    return child.error();
                const auto declared_alignment = member.effective_alignment.value_or(child.value().alignment);
                // A recorded effective member alignment is exact: it can
                // lower natural alignment through packing or raise it through
                // an explicit aligned attribute. Only unannotated members use
                // the aggregate and caller packing caps here.
                const auto capped_natural_alignment = std::min({child.value().alignment, cap, aggregate_cap});
                const auto member_alignment = member.effective_alignment
                    ? declared_alignment : capped_natural_alignment;
                std::uint64_t offset = 0;
                if (member.bit_width && *member.bit_width == 0) {
                    // A zero-width unnamed bitfield has no occupied bits, but
                    // ends the current allocation unit. In recorded mode its
                    // byte offset is explicit source metadata; inferring a new
                    // allocation-unit boundary would require target rules.
                    if (bitfield_policy == BitfieldLayoutPolicy::recorded) {
                        offset = member.offset;
                        if (offset < cursor)
                            return unsupported("recorded zero-width bitfield boundary precedes occupied structure data");
                    } else if (!align_up(cursor, member_alignment, offset)) {
                        return overflow("zero-width bitfield barrier offset overflows 64-bit layout");
                    }
                    if (offset > cursor)
                        result.padding.push_back({cursor, offset - cursor});
                    result.members.push_back({member.name, offset, 0, member_alignment,
                                              member.bit_width, member.bit_offset, false});
                    cursor = offset;
                    bitfield_source_offset.reset();
                    bitfield_storage_size = 0;
                    microsoft_bitfield_unit.reset();
                    aggregate_alignment = std::max(aggregate_alignment, member_alignment);
                    continue;
                }
                if (member.bit_width && (bitfield_policy == BitfieldLayoutPolicy::microsoft ||
                                         bitfield_policy == BitfieldLayoutPolicy::itanium)) {
                    if (child.value().size != 1 && child.value().size != 2 && child.value().size != 4 &&
                        (bitfield_policy == BitfieldLayoutPolicy::microsoft || child.value().size != 8))
                        return unsupported(bitfield_policy == BitfieldLayoutPolicy::microsoft
                            ? "Microsoft bitfield layout supports only 1-, 2-, and 4-byte allocation units"
                            : "Itanium bitfield layout supports only 1-, 2-, 4-, and 8-byte allocation units");
                    const auto storage_bits = child.value().size * 8;
                    const auto width = static_cast<std::uint64_t>(*member.bit_width);
                    if (!width || width > storage_bits)
                        return unsupported("bitfield width does not fit its allocation unit");
                    const bool can_share = microsoft_bitfield_unit &&
                        microsoft_bitfield_unit->size == child.value().size &&
                        microsoft_bitfield_unit->alignment == member_alignment &&
                        width <= storage_bits - microsoft_bitfield_unit->used;
                    std::uint32_t bit_offset = 0;
                    if (can_share) {
                        offset = microsoft_bitfield_unit->offset;
                        bit_offset = static_cast<std::uint32_t>(microsoft_bitfield_unit->used);
                        microsoft_bitfield_unit->used += width;
                    } else {
                        if (!align_up(cursor, member_alignment, offset))
                            return overflow("Microsoft bitfield allocation offset overflows 64-bit layout");
                        if (offset > cursor)
                            result.padding.push_back({cursor, offset - cursor});
                        if (child.value().size > std::numeric_limits<std::uint64_t>::max() - offset)
                            return overflow("Microsoft bitfield allocation extent overflows 64-bit layout");
                        cursor = offset + child.value().size;
                        microsoft_bitfield_unit = MicrosoftBitfieldUnit{
                            child.value().size, member_alignment, offset, width};
                    }
                    result.members.push_back({member.name, offset, child.value().size, member_alignment,
                                              member.bit_width, bit_offset, false});
                    aggregate_alignment = std::max(aggregate_alignment, member_alignment);
                    continue;
                }
                if (member.bit_width && bitfield_policy == BitfieldLayoutPolicy::recorded) {
                    // The immutable record carries both the allocation-unit
                    // byte offset and the LSB-relative bit range. Honor those
                    // coordinates directly; do not infer compiler allocation
                    // units from the selected architecture.
                    offset = member.offset;
                    const bool shares_recorded_unit = bitfield_source_offset &&
                        *bitfield_source_offset == member.offset &&
                        bitfield_storage_size == child.value().size;
                    if (!shares_recorded_unit) {
                        if (offset < cursor)
                            return unsupported("recorded bitfield allocation unit overlaps preceding structure data");
                        if (offset > cursor)
                            result.padding.push_back({cursor, offset - cursor});
                        if (child.value().size > std::numeric_limits<std::uint64_t>::max() - offset)
                            return overflow("recorded bitfield allocation extent overflows 64-bit layout");
                        cursor = offset + child.value().size;
                        bitfield_layout_offset = offset;
                    }
                    result.members.push_back({member.name, offset, child.value().size, member_alignment,
                                              member.bit_width, member.bit_offset, false});
                    bitfield_source_offset = member.offset;
                    bitfield_storage_size = child.value().size;
                    aggregate_alignment = std::max(aggregate_alignment, member_alignment);
                    continue;
                }
                if (!member.bit_width)
                    microsoft_bitfield_unit.reset();
                const bool shares_bitfield_unit = member.bit_width && bitfield_source_offset &&
                    *bitfield_source_offset == member.offset && bitfield_storage_size == child.value().size;
                if (shares_bitfield_unit) {
                    offset = bitfield_layout_offset;
                } else {
                    if (!align_up(cursor, member_alignment, offset))
                        return overflow("structure member offset overflows 64-bit layout");
                    if (offset > cursor)
                        result.padding.push_back({cursor, offset - cursor});
                    if (child.value().size > std::numeric_limits<std::uint64_t>::max() - offset)
                        return overflow("structure size overflows 64-bit layout");
                    cursor = offset + child.value().size;
                }
                result.members.push_back({member.name, offset, child.value().size, member_alignment,
                                          member.bit_width, member.bit_offset, flexible_array});
                if (member.bit_width) {
                    bitfield_source_offset = member.offset;
                    bitfield_storage_size = child.value().size;
                    bitfield_layout_offset = offset;
                } else {
                    bitfield_source_offset.reset();
                    bitfield_storage_size = 0;
                }
                aggregate_alignment = std::max(aggregate_alignment, member_alignment);
            }
            // The aggregate's recorded alignment can include an explicit
            // over-alignment attribute; member placement remains ABI/pack
            // capped above, while the final object alignment must be honored.
            aggregate_alignment = std::max(aggregate_alignment, type.alignment());
            if (!align_up(cursor, aggregate_alignment, result.size))
                return overflow("structure tail padding overflows 64-bit layout");
            if (result.size > cursor)
                result.padding.push_back({cursor, result.size - cursor});
            result.alignment = aggregate_alignment;
            return result;
        }
        case Kind::union_type: {
            if (!type.size())
                return unsupported("incomplete union has no object layout");
            if (type.members().empty())
                return unsupported("empty unions are unsupported");
            std::uint64_t maximum_size = 0;
            std::uint64_t aggregate_alignment = 1;
            const auto aggregate_cap = type.packing_alignment()
                ? std::min(alignment_limit, *type.packing_alignment()) : alignment_limit;
            result.members.reserve(type.members().size());
            for (const auto &member : type.members()) {
                if (member.virtual_base)
                    return unsupported("virtual base offset requires runtime vbptr/vbtable evaluation");
                if (!member.type)
                    return unsupported("union member has no type");
                auto child = calculate(*member.type);
                if (!child)
                    return child.error();
                const auto declared_alignment = member.effective_alignment.value_or(child.value().alignment);
                const auto capped_natural_alignment = std::min({child.value().alignment, cap, aggregate_cap});
                const auto member_alignment = member.effective_alignment
                    ? declared_alignment : capped_natural_alignment;
                const auto member_size = member.bit_width && *member.bit_width == 0 ? 0 : child.value().size;
                maximum_size = std::max(maximum_size, member_size);
                aggregate_alignment = std::max(aggregate_alignment, member_alignment);
                if (member.bit_width && (bitfield_policy == BitfieldLayoutPolicy::microsoft ||
                                         bitfield_policy == BitfieldLayoutPolicy::itanium) &&
                    *member.bit_width > 0 && child.value().size != 1 && child.value().size != 2 &&
                    child.value().size != 4 &&
                    (bitfield_policy == BitfieldLayoutPolicy::microsoft || child.value().size != 8))
                    return unsupported(bitfield_policy == BitfieldLayoutPolicy::microsoft
                        ? "Microsoft bitfield layout supports only 1-, 2-, and 4-byte allocation units"
                        : "Itanium bitfield layout supports only 1-, 2-, 4-, and 8-byte allocation units");
                result.members.push_back({member.name, 0, member_size, member_alignment,
                                          member.bit_width,
                                          member.bit_width && (bitfield_policy == BitfieldLayoutPolicy::microsoft ||
                                                               bitfield_policy == BitfieldLayoutPolicy::itanium)
                                              ? std::optional<std::uint32_t>{0} : member.bit_offset,
                                          false});
            }
            aggregate_alignment = std::max(aggregate_alignment, type.alignment());
            if (!align_up(maximum_size, aggregate_alignment, result.size))
                return overflow("union tail padding overflows 64-bit layout");
            if (result.size > maximum_size)
                result.padding.push_back({maximum_size, result.size - maximum_size});
            result.alignment = aggregate_alignment;
            return result;
        }
        case Kind::void_type:
            return unsupported("void has no object layout");
        case Kind::function:
            return unsupported("function types do not have object layout");
        case Kind::named_reference: {
            if (!resolve_named_type)
                return unsupported("named type reference requires a project definition resolver");
            if (!active_names.insert(type.name()).second)
                return unsupported("recursive by-value named type graph cannot be laid out: " + type.name());
            struct EraseName {
                std::unordered_set<std::string> &set;
                const std::string &value;
                ~EraseName() { set.erase(value); }
            } erase_name{active_names, type.name()};
            auto resolved = resolve_named_type(type.name());
            if (!resolved)
                return resolved.error();
            if (!resolved.value())
                return Error{ErrorCode::malformed, "named type resolver returned an empty definition for '" + type.name() + "'"};
            return calculate(*resolved.value());
        }
        }
        return unsupported("unknown type kind");
    }
};
} // namespace

std::uint64_t pointer_size(Abi abi) noexcept {
    switch (abi) {
    case Abi::x86_32: return 4;
    case Abi::x86_64:
    case Abi::aarch64: return 8;
    case Abi::aarch32: return 4;
    }
    return 0;
}

hexlab::Result<TypeLayout> layout(const Type &type, Abi abi, LayoutOptions options) {
    const auto pack = options.maximum_member_alignment;
    if (pack && ((pack & (pack - 1)) != 0 || pack > 16))
        return Error{ErrorCode::invalid_argument, "maximum member alignment must be a power of two no greater than 16"};
    const auto abi_cap = maximum_alignment(abi);
    const auto alignment_limit = pack ? std::min(pack, abi_cap) : abi_cap;
    if (options.bitfield_policy != BitfieldLayoutPolicy::recorded &&
        options.bitfield_policy != BitfieldLayoutPolicy::microsoft &&
        options.bitfield_policy != BitfieldLayoutPolicy::itanium)
        return Error{ErrorCode::invalid_argument, "unknown bitfield layout policy"};
    return Calculator{abi, alignment_limit, options.bitfield_policy, options.resolve_named_type}.calculate(type);
}

} // namespace hexlab::types
