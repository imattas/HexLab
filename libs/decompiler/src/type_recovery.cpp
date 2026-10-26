#include "hexlab/decompiler/type_recovery.hpp"
#include "hexlab/analysis/abi.hpp"
#include "hexlab/types/layout.hpp"
#include "expression_type_context.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <functional>
#include <iterator>
#include <map>
#include <limits>
#include <new>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <type_traits>

namespace hexlab::decompiler {
namespace {
using Key = std::tuple<unsigned, unsigned, unsigned, bool, std::uint32_t, bool>;
Key key(RegisterOperand r, std::optional<std::uint32_t> v = {}) {
    return {static_cast<unsigned>(r.bank), r.index, r.width, r.high_byte, v.value_or(0), v.has_value()};
}
struct Fact {
    RegisterOperand reg;
    std::optional<std::uint32_t> version;
    std::uint16_t bits=0;
    bool sign=false;
    bool sign_ambiguous=false;
    bool pointer=false;
    // Different access widths at one byte offset can indicate a union, a
    // partial field access, or a bad alias hypothesis. Do not publish a
    // guessed aggregate for that pointer fact.
    bool object_layout_ambiguous=false;
    bool constrained=false;
    types::TypePtr exact_type;
    bool exact_type_ambiguous = false;
    bool floating=false;
    bool floating_ambiguous=false;
    // Byte widths observed through constant-offset accesses on this pointer.
    std::map<std::uint64_t, std::uint16_t> object_fields;
    // A field is classified as a pointer only when a pointer-valued load/store
    // at that exact offset supplies independent evidence.
    std::set<std::uint64_t> pointer_fields;
    // Pointer-valued member loads that provide candidate pointee facts. The
    // layouts are materialized after direct pointer-field evidence converges.
    std::map<std::uint64_t, std::set<Key>> nested_children;
    std::map<std::uint64_t, std::shared_ptr<const struct AggregateLayout>> nested_fields;
    std::set<std::uint64_t> nested_fields_ambiguous;
    // Element width established by a dynamic index whose scale equals the
    // access width. No array bound is inferred from one dynamic access.
    std::optional<std::uint16_t> indexed_element_bits;
    bool indexed_element_ambiguous = false;
    types::TypePtr vector_type;
    bool vector_evidence = false;
    bool vector_ambiguous = false;
};
struct AggregateLayout {
    std::map<std::uint64_t, std::uint16_t> fields;
    std::set<std::uint64_t> pointer_fields;
    std::map<std::uint64_t, std::shared_ptr<const AggregateLayout>> nested_fields;
    std::set<std::uint64_t> nested_fields_ambiguous;
};
constexpr std::size_t aggregate_layout_work_limit = 1'000'000;

struct KnownTypedRegister {
    RegisterValue value;
    types::TypePtr type;
};

bool equal_layout(const AggregateLayout &left, const AggregateLayout &right,
                 std::size_t &work, bool &complete) {
    const auto spend = [&]() {
        if (work >= aggregate_layout_work_limit) {
            complete = false;
            return false;
        }
        ++work;
        return true;
    };
    if (!spend()) return false;
    if (left.fields.size() != right.fields.size() || left.pointer_fields.size() != right.pointer_fields.size() ||
        left.nested_fields_ambiguous.size() != right.nested_fields_ambiguous.size() ||
        left.nested_fields.size() != right.nested_fields.size()) return false;
    auto left_field = left.fields.begin(), right_field = right.fields.begin();
    while (left_field != left.fields.end()) {
        if (!spend()) return false;
        if (*left_field++ != *right_field++) return false;
    }
    auto left_pointer = left.pointer_fields.begin(), right_pointer = right.pointer_fields.begin();
    while (left_pointer != left.pointer_fields.end()) {
        if (!spend()) return false;
        if (*left_pointer++ != *right_pointer++) return false;
    }
    auto left_ambiguous = left.nested_fields_ambiguous.begin();
    auto right_ambiguous = right.nested_fields_ambiguous.begin();
    while (left_ambiguous != left.nested_fields_ambiguous.end()) {
        if (!spend()) return false;
        if (*left_ambiguous++ != *right_ambiguous++) return false;
    }
    for (const auto &[offset, nested] : left.nested_fields) {
        if (!spend()) return false;
        const auto found = right.nested_fields.find(offset);
        if (found == right.nested_fields.end() || !nested || !found->second ||
            !equal_layout(*nested, *found->second, work, complete)) return false;
    }
    return true;
}

types::TypePtr unqualified_type(types::TypePtr type) {
    while (type && type->kind() == types::Kind::qualified) type = type->element();
    return type;
}

std::optional<std::vector<types::TypePtr>> hfa_float_elements(types::TypePtr input) {
    const auto root = unqualified_type(std::move(input));
    if (!root || (root->kind() != types::Kind::structure && root->kind() != types::Kind::array) ||
        !root->size() || *root->size() == 0 || *root->size() > 64)
        return {};
    struct Element { std::uint64_t offset; types::TypePtr type; };
    std::vector<Element> elements;
    bool valid = true;
    const auto collect = [&](const types::TypePtr &candidate, std::uint64_t base, unsigned depth,
                             auto &&self) -> void {
        if (!valid || !candidate || depth > 4 || elements.size() > 4) { valid = false; return; }
        const auto type = unqualified_type(candidate);
        if (!type) { valid = false; return; }
        if (type->kind() == types::Kind::floating) {
            if (!type->size() || (*type->size() != 4 && *type->size() != 8 && *type->size() != 16) ||
                base > 64 || *type->size() > 64 - base || elements.size() == 4) {
                valid = false;
                return;
            }
            elements.push_back({base, type});
            return;
        }
        if (type->kind() == types::Kind::array) {
            if (!type->element() || !type->count() || type->count() > 4 || !type->size()) {
                valid = false;
                return;
            }
            const auto element = unqualified_type(type->element());
            if (!element || !element->size() || *element->size() == 0 ||
                type->count() > *type->size() / *element->size() ||
                *type->size() != type->count() * *element->size()) {
                valid = false;
                return;
            }
            for (std::uint64_t index = 0; index < type->count() && valid; ++index)
                self(type->element(), base + index * *element->size(), depth + 1, self);
            return;
        }
        if (type->kind() != types::Kind::structure || type->members().empty() ||
            type->members().size() > 4 || !type->size()) {
            valid = false;
            return;
        }
        for (const auto &member : type->members()) {
            if (member.virtual_base || member.bit_width || member.bit_offset || !member.type ||
                member.offset > *type->size() || base > 64 - member.offset) {
                valid = false;
                return;
            }
            self(member.type, base + member.offset, depth + 1, self);
        }
    };
    collect(root, 0, 0, collect);
    if (!valid || elements.empty() || elements.size() > 4 || !root->size()) return {};
    std::sort(elements.begin(), elements.end(), [](const Element &left, const Element &right) {
        return left.offset < right.offset;
    });
    const auto element_size = elements.front().type->size();
    if (!element_size || !*element_size) return {};
    std::uint64_t expected = 0;
    std::vector<types::TypePtr> result;
    result.reserve(elements.size());
    for (const auto &element : elements) {
        if (!element.type || !element.type->size() || *element.type->size() != *element_size ||
            element.offset != expected || expected > 64 - *element_size)
            return {};
        result.push_back(element.type);
        expected += *element_size;
    }
    if (expected != *root->size()) return {};
    return result;
}

struct Aapcs64Value {
    AbiValueClass value_class = AbiValueClass::integer;
    std::vector<types::TypePtr> floating_components;
    bool homogeneous_aggregate = false;
};

std::optional<Aapcs64Value> classify_aapcs64_value(types::TypePtr input) {
    const auto type = unqualified_type(std::move(input));
    if (!type) return {};
    switch (type->kind()) {
    case types::Kind::boolean:
    case types::Kind::integer:
    case types::Kind::enumeration:
    case types::Kind::pointer:
        return Aapcs64Value{AbiValueClass::integer, {}, false};
    case types::Kind::floating:
        if (!type->size() || (*type->size() != 4 && *type->size() != 8 && *type->size() != 16)) return {};
        return Aapcs64Value{AbiValueClass::floating, {type}, false};
    case types::Kind::vector:
        return Aapcs64Value{AbiValueClass::vector, {}, false};
    case types::Kind::array:
    case types::Kind::structure: {
        auto components = hfa_float_elements(type);
        if (!components) return {};
        return Aapcs64Value{AbiValueClass::floating, std::move(*components), true};
    }
    default:
        return {};
    }
}

std::shared_ptr<const AggregateLayout> observed_structure_layout(
    const types::TypePtr &structure, std::uint16_t pointer_bits,
    std::size_t &work, unsigned depth) {
    if (!structure || structure->kind() != types::Kind::structure || !structure->size() ||
        *structure->size() == 0 || *structure->size() > (1u << 20) || depth > 4)
        return {};
    if (work >= aggregate_layout_work_limit) return {};
    ++work;
    auto layout = std::make_shared<AggregateLayout>();
    const auto add_field = [&](std::uint64_t offset, const types::TypePtr &field_type,
                               unsigned nested_depth, auto &&self) -> bool {
        if (!field_type || work >= aggregate_layout_work_limit) return false;
        ++work;
        const auto type = unqualified_type(field_type);
        if (!type) return false;
        if (type->kind() == types::Kind::array) {
            const auto element = unqualified_type(type->element());
            if (!element || type->count() == 0 || type->count() > 4096 || !element->size() ||
                *element->size() == 0 || *element->size() > 8)
                return false;
            const auto element_size = *element->size();
            if (type->count() > ((1u << 20) - std::min<std::uint64_t>(offset, 1u << 20)) / element_size)
                return false;
            for (std::uint64_t index = 0; index < type->count(); ++index)
                if (!self(offset + index * element_size, element, nested_depth, self)) return false;
            return true;
        }
        if (type->kind() != types::Kind::boolean && type->kind() != types::Kind::integer &&
            type->kind() != types::Kind::enumeration && type->kind() != types::Kind::floating &&
            type->kind() != types::Kind::pointer)
            return false;
        if (!type->size() || *type->size() == 0 || *type->size() > 8 ||
            offset > (1u << 20) || *type->size() > (1u << 20) - offset)
            return false;
        const auto bits = static_cast<std::uint16_t>(*type->size() * 8);
        auto [field, inserted] = layout->fields.emplace(offset, bits);
        if (!inserted) field->second = std::max(field->second, bits);
        if (type->kind() != types::Kind::pointer) return true;
        if (!pointer_bits || bits != pointer_bits) return false;
        layout->pointer_fields.insert(offset);
        const auto pointee = unqualified_type(type->element());
        if (!pointee || pointee->kind() != types::Kind::structure || nested_depth >= 4) return true;
        const auto nested = observed_structure_layout(pointee, pointer_bits, work, nested_depth + 1);
        if (!nested || nested->fields.empty()) return true;
        auto found = layout->nested_fields.find(offset);
        if (found == layout->nested_fields.end()) {
            layout->nested_fields.emplace(offset, nested);
        } else {
            bool complete = true;
            if (!equal_layout(*found->second, *nested, work, complete) || !complete) {
                layout->nested_fields.erase(found);
                layout->nested_fields_ambiguous.insert(offset);
            }
        }
        return true;
    };
    for (const auto &member : structure->members()) {
        if (work >= aggregate_layout_work_limit) return {};
        ++work;
        if (member.virtual_base || member.bit_width || member.bit_offset) continue;
        if (!add_field(member.offset, member.type, depth, add_field)) {
            if (work >= aggregate_layout_work_limit) return {};
            continue;
        }
    }
    if (layout->fields.empty()) return {};
    return layout;
}

std::shared_ptr<const AggregateLayout> observed_pointee_layout(
    const types::TypePtr &candidate, std::uint16_t pointer_bits, std::size_t &work) {
    const auto pointer = unqualified_type(candidate);
    if (!pointer || pointer->kind() != types::Kind::pointer || !pointer->size() ||
        (pointer_bits && *pointer->size() * 8 != pointer_bits))
        return {};
    const auto pointee = unqualified_type(pointer->element());
    return pointee && pointee->kind() == types::Kind::structure
        ? observed_structure_layout(pointee, pointer_bits, work, 0)
        : std::shared_ptr<const AggregateLayout>{};
}

bool merge_observed_layout(Fact &destination, const AggregateLayout &source,
                           std::size_t &work) {
    bool changed = false;
    for (const auto &[offset, bits] : source.fields) {
        auto &width = destination.object_fields[offset];
        if (width && width != bits) {
            if (!destination.object_layout_ambiguous) {
                destination.object_layout_ambiguous = true;
                changed = true;
            }
            continue;
        }
        const auto merged = std::max(width, bits);
        if (width != merged) { width = merged; changed = true; }
    }
    for (const auto offset : source.pointer_fields)
        changed |= destination.pointer_fields.insert(offset).second;
    for (const auto offset : source.nested_fields_ambiguous) {
        changed |= destination.nested_fields_ambiguous.insert(offset).second;
        changed |= destination.nested_fields.erase(offset) != 0;
    }
    for (const auto &[offset, nested] : source.nested_fields) {
        if (!nested || destination.nested_fields_ambiguous.contains(offset)) continue;
        const auto found = destination.nested_fields.find(offset);
        if (found == destination.nested_fields.end()) {
            destination.nested_fields.emplace(offset, nested);
            changed = true;
            continue;
        }
        bool complete = true;
        if (!equal_layout(*found->second, *nested, work, complete) || !complete) {
            destination.nested_fields.erase(found);
            destination.nested_fields_ambiguous.insert(offset);
            changed = true;
        }
    }
    return changed;
}
struct PointerAlias {
    Key source;
    Key destination;
    // address(destination) = address(source) + displacement
    std::int64_t displacement = 0;
};
std::optional<std::pair<Key, std::int64_t>> canonical_stack_address(
    const Key &start, const std::vector<PointerAlias> &aliases);
bool checked_add(std::int64_t left, std::int64_t right, std::int64_t &result);

std::optional<std::int64_t> integer_constant(const ExpressionPtr &expression) {
    if (!expression) return {};
    const auto *constant = std::get_if<ConstantValue>(&expression->value);
    if (!constant || !constant->type.bits || constant->type.bits > 64) return {};
    const auto bits = constant->type.bits;
    std::uint64_t value = constant->value;
    if (bits < 64) value &= (UINT64_C(1) << bits) - 1;
    if (constant->type.is_signed && (value & (UINT64_C(1) << (bits - 1)))) {
        if (bits < 64) value |= ~((UINT64_C(1) << bits) - 1);
        return std::bit_cast<std::int64_t>(value);
    }
    if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) return {};
    return static_cast<std::int64_t>(value);
}

std::optional<PointerAlias> pointer_alias(const Assign &assignment) {
    if (!assignment.value) return {};
    const Key destination = key(assignment.destination, assignment.destination_version);
    if (const auto *copy = std::get_if<RegisterValue>(&assignment.value->value))
        return PointerAlias{key(copy->reg, copy->version), destination, 0};
    const auto *binary = std::get_if<BinaryValue>(&assignment.value->value);
    if (!binary || (binary->operation != "add" && binary->operation != "sub")) return {};
    const auto *left = binary->left ? std::get_if<RegisterValue>(&binary->left->value) : nullptr;
    const auto right_constant = integer_constant(binary->right);
    if (left && right_constant) {
        if (binary->operation == "sub" && *right_constant == std::numeric_limits<std::int64_t>::min()) return {};
        const auto displacement = binary->operation == "sub" ? -*right_constant : *right_constant;
        return PointerAlias{key(left->reg, left->version), destination, displacement};
    }
    if (binary->operation == "add") {
        const auto *right = binary->right ? std::get_if<RegisterValue>(&binary->right->value) : nullptr;
        const auto left_constant = integer_constant(binary->left);
        if (right && left_constant)
            return PointerAlias{key(right->reg, right->version), destination, *left_constant};
    }
    return {};
}

std::optional<std::uint64_t> shifted_field(std::uint64_t offset, std::int64_t displacement) {
    constexpr std::uint64_t maximum = 1u << 20;
    if (displacement < 0) {
        const auto amount = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
        if (amount > offset) return {};
        return offset - amount;
    }
    const auto amount = static_cast<std::uint64_t>(displacement);
    if (amount > maximum - std::min(offset, maximum)) return {};
    const auto result = offset + amount;
    return result <= maximum ? std::optional<std::uint64_t>{result} : std::nullopt;
}

types::TypePtr recovered_object_type(
    const std::map<std::uint64_t, std::uint16_t> &fields,
    const std::set<std::uint64_t> &pointer_fields,
    const std::map<std::uint64_t, std::shared_ptr<const AggregateLayout>> &nested_fields,
    const std::set<std::uint64_t> &nested_fields_ambiguous,
    std::uint16_t pointer_bits, std::size_t &work, unsigned depth = 0) {
    constexpr unsigned maximum_nested_depth = 4;
    if (depth > maximum_nested_depth || work >= aggregate_layout_work_limit) return {};
    if (fields.empty()) return {};
    std::vector<types::Member> members;
    std::uint64_t size = 0, alignment = 1;
    for (auto field = fields.begin(); field != fields.end();) {
        if (work >= aggregate_layout_work_limit) return {};
        ++work;
        const auto offset = field->first;
        const auto bits = field->second;
        if (!bits || bits % 8 || bits > 64 || offset > (1u << 20)) return {};
        const bool pointer_field = pointer_fields.contains(offset);
        if (pointer_field && pointer_bits && bits != pointer_bits) return {};
        const auto bytes = static_cast<std::uint64_t>(bits / 8);
        if (bytes > (1u << 20) - offset) return {};
        const auto member_alignment = std::min<std::uint64_t>(8, std::bit_floor(bytes));
        types::TypePtr pointee = types::Type::void_type();
        if (pointer_field && !nested_fields_ambiguous.contains(offset)) {
            const auto nested = nested_fields.find(offset);
            if (nested != nested_fields.end() && nested->second) {
                const auto &child = *nested->second;
                auto inferred = recovered_object_type(child.fields, child.pointer_fields,
                    child.nested_fields, child.nested_fields_ambiguous, pointer_bits, work, depth + 1);
                if (inferred) pointee = std::move(inferred);
            }
        }
        auto member_type = pointer_field
            ? types::Type::pointer(std::move(pointee), bytes, member_alignment)
            : types::Type::integer("field", bytes, member_alignment, false);
        if (!member_type) return {};
        auto end = std::next(field);
        std::uint64_t count = 1;
        auto expected_offset = offset + bytes;
        while (!pointer_fields.contains(offset) && end != fields.end() &&
               end->second == bits && end->first == expected_offset && !pointer_fields.contains(end->first)) {
            if (work >= aggregate_layout_work_limit) return {};
            ++work;
            ++count;
            expected_offset += bytes;
            ++end;
        }
        types::TypePtr recovered_member = member_type.value();
        // Three adjacent accesses of one width are enough evidence for an
        // array shape. Shorter runs stay as independent fields to avoid
        // turning an ordinary two-field record into an array by default.
        if (count >= 3) {
            auto array_type = types::Type::array(member_type.value(), count);
            if (!array_type) return {};
            recovered_member = array_type.value();
        } else {
            end = std::next(field);
            count = 1;
        }
        members.push_back({"field_" + std::to_string(offset), recovered_member, offset});
        size = std::max(size, offset + bytes * count);
        alignment = std::max(alignment, member_alignment);
        field = end;
    }
    if (!size || size > (1u << 20)) return {};
    const auto remainder = size % alignment;
    if (remainder) size += alignment - remainder;
    auto object = types::Type::structure("recovered_object", std::move(members), size, alignment);
    return object ? object.value() : types::TypePtr{};
}

types::TypePtr make_type(const Fact &f, std::uint16_t pointer_bits, std::size_t &aggregate_work) {
    if (f.exact_type_ambiguous) return {};
    if (f.exact_type) return f.exact_type;
    if (f.vector_evidence) return f.vector_ambiguous ? types::TypePtr{} : f.vector_type;
    if (f.floating_ambiguous) return {};
    const auto bits = f.pointer ? (pointer_bits ? pointer_bits : f.bits) : f.bits;
    const std::uint64_t bytes = std::max<std::uint64_t>(1, (bits + 7u) / 8u);
    if (f.floating) { auto t=types::Type::floating("floating",bytes,bytes); return t ? t.value() : types::TypePtr{}; }
    if (f.pointer) {
        auto base = f.object_layout_ambiguous ? types::TypePtr{} : recovered_object_type(
            f.object_fields, f.pointer_fields, f.nested_fields,
            f.nested_fields_ambiguous, pointer_bits, aggregate_work);
        if (!base && !f.object_layout_ambiguous && !f.indexed_element_ambiguous &&
            f.indexed_element_bits && *f.indexed_element_bits &&
            *f.indexed_element_bits % 8 == 0) {
            const auto element_bytes = static_cast<std::uint64_t>(*f.indexed_element_bits / 8);
            auto element = types::Type::integer("element", element_bytes,
                std::max<std::uint64_t>(1, std::min<std::uint64_t>(8, std::bit_floor(element_bytes))), false);
            if (element) base = element.value();
        }
        if (!base) {
            auto byte = types::Type::integer("byte", 1, 1, false);
            if (!byte) return {};
            base = byte.value();
        }
        auto ptr = types::Type::pointer(std::move(base), bytes, bytes);
        return ptr ? ptr.value() : types::TypePtr{};
    }
    if (f.sign_ambiguous) return {};
    auto value = types::Type::integer(f.sign ? "signed" : "unsigned", bytes, bytes, f.sign);
    return value ? value.value() : types::TypePtr{};
}

bool is_pointer_type(const types::TypePtr &t) { return t && t->kind()==types::Kind::pointer; }
bool is_signed_type(const types::TypePtr &t) {
    if (!t) return false;
    return t->kind()==types::Kind::integer ? t->is_signed() :
           t->kind()==types::Kind::enumeration && t->element() && t->element()->is_signed();
}
std::uint16_t type_bits(const types::TypePtr &t) {
    return t && t->size() && *t->size()<=8191 ? static_cast<std::uint16_t>(*t->size()*8) : 0;
}
types::TypePtr vector_type_from_value(const ValueType &value) {
    if (value.kind != TypeKind::vector || !value.lanes || !value.element_bits ||
        value.element_bits % 8 || !value.bits || value.bits % 8 ||
        value.element_bits > UINT16_MAX / value.lanes ||
        static_cast<std::uint32_t>(value.element_bits) * value.lanes != value.bits)
        return {};
    const auto lane_bytes = static_cast<std::uint64_t>(value.element_bits / 8);
    const auto vector_bytes = static_cast<std::uint64_t>(value.bits / 8);
    const auto lane_alignment = std::max<std::uint64_t>(1,
        std::min<std::uint64_t>(8, std::bit_floor(lane_bytes)));
    types::TypePtr lane;
    if (value.element_kind == TypeKind::integer) {
        auto created = types::Type::integer(std::string(value.is_signed ? "i" : "u") +
            std::to_string(value.element_bits), lane_bytes, lane_alignment, value.is_signed);
        if (created) lane = std::move(created.value());
    } else if (value.element_kind == TypeKind::floating) {
        auto created = types::Type::floating("f" + std::to_string(value.element_bits), lane_bytes, lane_alignment);
        if (created) lane = std::move(created.value());
    }
    if (!lane) return {};
    const auto alignment = std::max<std::uint64_t>(1,
        std::min<std::uint64_t>(64, std::bit_floor(vector_bytes)));
    auto created = types::Type::vector(std::move(lane), value.lanes, alignment);
    return created ? created.value() : types::TypePtr{};
}
bool merge_vector_fact(Fact &destination, const Fact &source) {
    if (!source.vector_evidence) return false;
    if (!destination.vector_evidence) {
        destination.vector_evidence = true;
        destination.vector_type = source.vector_type;
        destination.vector_ambiguous = source.vector_ambiguous;
        return true;
    }
    if (destination.vector_ambiguous || source.vector_ambiguous) {
        if (destination.vector_ambiguous && !destination.vector_type) return false;
        destination.vector_ambiguous = true;
        destination.vector_type.reset();
        return true;
    } else if (!destination.vector_type && source.vector_type) {
        destination.vector_type = source.vector_type;
        return true;
    } else if (destination.vector_type && source.vector_type &&
               destination.vector_type->id() != source.vector_type->id()) {
        destination.vector_type.reset();
        destination.vector_ambiguous = true;
        return true;
    }
    return false;
}
bool merge_exact_type(Fact &destination, const types::TypePtr &type) {
    if (!type || destination.exact_type_ambiguous) return false;
    if (!destination.exact_type) {
        destination.exact_type = type;
        return true;
    }
    if (destination.exact_type->id() != type->id()) {
        destination.exact_type.reset();
        destination.exact_type_ambiguous = true;
        return true;
    }
    return false;
}
RegisterOperand gpr(unsigned index, unsigned width = 64) {
    return {RegisterBank::gpr, static_cast<std::uint8_t>(index), static_cast<std::uint16_t>(width), false};
}
RegisterOperand xmm(unsigned index) {
    return {RegisterBank::xmm, static_cast<std::uint8_t>(index), 128, false};
}
RegisterOperand arm64_simd(unsigned index) {
    return {RegisterBank::arm64_simd, static_cast<std::uint8_t>(index), 128, false};
}

std::optional<RegisterOperand> classified_register(std::string_view name) {
    const auto parse_index = [&](std::size_t prefix) -> std::optional<unsigned> {
        if (prefix >= name.size()) return {};
        unsigned index = 0;
        const auto *begin = name.data() + prefix;
        const auto *end = name.data() + name.size();
        const auto parsed = std::from_chars(begin, end, index);
        if (parsed.ec != std::errc{} || parsed.ptr != end) return {};
        return index;
    };
    if (name.starts_with("XMM")) {
        const auto index = parse_index(3);
        if (index && *index < 16) return RegisterOperand{RegisterBank::xmm, static_cast<std::uint8_t>(*index), 128, false};
        return {};
    }
    if (name.size() > 1 && (name[0] == 'X' || name[0] == 'W')) {
        const auto index = parse_index(1);
        if (index && *index < 31) return RegisterOperand{RegisterBank::arm64_gpr, static_cast<std::uint8_t>(*index), 64, false};
    }
    if (name.size() > 1 && (name[0] == 'H' || name[0] == 'S' || name[0] == 'D' || name[0] == 'Q')) {
        const auto index = parse_index(1);
        if (index && *index < 32) return arm64_simd(*index);
    }
    static constexpr std::array<std::array<std::string_view, 5>, 8> x86_aliases{{
        {{"RAX","EAX","AX","AL","AH"}}, {{"RCX","ECX","CX","CL","CH"}},
        {{"RDX","EDX","DX","DL","DH"}}, {{"RBX","EBX","BX","BL","BH"}},
        {{"RSP","ESP","SP","SPL",""}}, {{"RBP","EBP","BP","BPL",""}},
        {{"RSI","ESI","SI","SIL",""}}, {{"RDI","EDI","DI","DIL",""}}}};
    for (std::size_t i = 0; i < x86_aliases.size(); ++i)
        for (const auto alias : x86_aliases[i])
            if (!alias.empty() && name == alias)
                return RegisterOperand{RegisterBank::gpr, static_cast<std::uint8_t>(i), 64, false};
    if (name.size() >= 2 && name[0] == 'R' && name[1] >= '0' && name[1] <= '9') {
        std::size_t end = 1;
        while (end < name.size() && name[end] >= '0' && name[end] <= '9') ++end;
        unsigned index = 0;
        const auto parsed = std::from_chars(name.data() + 1, name.data() + end, index);
        if (parsed.ec == std::errc{} && parsed.ptr == name.data() + end && index < 16)
            return RegisterOperand{RegisterBank::gpr, static_cast<std::uint8_t>(index), 64, false};
    }
    return {};
}

std::optional<RegisterOperand> ppc64_classified_register(std::string_view name) {
    if (name.size() < 2 || (name[0] != 'R' && name[0] != 'F')) return {};
    unsigned index = 0;
    const auto parsed = std::from_chars(name.data() + 1, name.data() + name.size(), index);
    if (parsed.ec != std::errc{} || parsed.ptr != name.data() + name.size() || index >= 32) return {};
    return RegisterOperand{name[0] == 'R' ? RegisterBank::ppc_gpr : RegisterBank::ppc_fpr,
                           static_cast<std::uint8_t>(index), 64, false};
}

std::optional<RegisterOperand> mips_n32_classified_register(std::string_view name) {
    if (name.size() < 2) return {};
    const auto parse_index = [&](std::size_t prefix) -> std::optional<unsigned> {
        unsigned index = 0;
        const auto parsed = std::from_chars(name.data() + prefix, name.data() + name.size(), index);
        if (parsed.ec != std::errc{} || parsed.ptr != name.data() + name.size()) return {};
        return index;
    };
    if (name[0] == 'A') {
        const auto index = parse_index(1);
        if (index && *index < 8)
            return RegisterOperand{RegisterBank::mips_gpr, static_cast<std::uint8_t>(4 + *index), 64, false};
    } else if (name[0] == 'F') {
        const auto index = parse_index(1);
        if (index && (*index == 0 || (*index >= 12 && *index <= 19)))
            return RegisterOperand{RegisterBank::mips_fpr, static_cast<std::uint8_t>(*index), 64, false};
    } else if (name == "V0") {
        return RegisterOperand{RegisterBank::mips_gpr, 2, 64, false};
    }
    return {};
}

std::optional<CallingConvention> classifier_convention(const AbiDescription &abi) {
    if (abi.name == "x86-64 System V") return CallingConvention::sysv_x86_64;
    if (abi.name == "x86-64 Windows") return CallingConvention::windows_x64;
    if (abi.name == "AArch64 AAPCS64") return CallingConvention::aapcs64;
    if (abi.name == "PowerPC64 ELFv2") return CallingConvention::ppc64le_elfv2;
    if (abi.name == "MIPS N32 hard-float scalar profile") return CallingConvention::mips_n32;
    if (abi.name == "x86-32 cdecl") return CallingConvention::x86_32_cdecl;
    return {};
}

struct HiddenResultPointerInfo {
    RegisterOperand reg;
    types::TypePtr pointer_type;
};

std::optional<HiddenResultPointerInfo> hidden_result_pointer_info(
    const AbiDescription &abi, const types::TypePtr &result_type) {
    if (!result_type || (abi.name != "x86-64 System V" && abi.name != "AArch64 AAPCS64" &&
                         abi.name != "PowerPC64 ELFv2"))
        return {};
    const auto result = unqualified_type(result_type);
    if (!result || (result->kind() != types::Kind::structure && result->kind() != types::Kind::array) ||
        !result->size() || *result->size() == 0)
        return {};
    const auto convention = classifier_convention(abi);
    if (!convention) return {};
    auto signature = types::Type::function(result_type, {}, false);
    if (!signature) return {};
    const auto classified = classify_abi_signature(*convention, *signature.value());
    if (!classified.result.supported || !classified.result.indirect ||
        !classified.hidden_result_pointer.supported ||
        !classified.hidden_result_pointer.indirect ||
        classified.hidden_result_pointer.locations.size() != 1 || !classified.pointer_size)
        return {};
    const auto &location = classified.hidden_result_pointer.locations.front();
    if (location.kind != AbiLocationKind::register_ ||
        location.role != AbiLocationRole::hidden_result_argument || location.duplicate ||
        location.value_offset != 0 || location.size != classified.pointer_size ||
        (location.placement_size && location.placement_size != classified.pointer_size))
        return {};
    const auto reg = abi.name == "PowerPC64 ELFv2"
        ? ppc64_classified_register(location.register_name)
        : classified_register(location.register_name);
    if (!reg || reg->width != static_cast<std::uint16_t>(classified.pointer_size * 8)) return {};
    const auto pointer_type = types::Type::pointer(result_type, classified.pointer_size,
                                                    classified.pointer_size);
    if (!pointer_type) return {};
    return HiddenResultPointerInfo{*reg, pointer_type.value()};
}

std::vector<AbiArgumentSlot> aapcs64_prototype_slots(const types::TypePtr &prototype) {
    std::vector<AbiArgumentSlot> slots;
    if (!prototype || prototype->kind() != types::Kind::function || prototype->parameters().size() > 256)
        return slots;
    std::size_t next_integer = 0;
    std::size_t next_simd = 0;
    std::int64_t stack_offset = 0;
    for (std::size_t parameter_index = 0; parameter_index < prototype->parameters().size(); ++parameter_index) {
        const auto &parameter = prototype->parameters()[parameter_index];
        const auto classified = classify_aapcs64_value(parameter.type);
        if (!classified) break;
        const auto parameter_number = static_cast<std::uint16_t>(parameter_index);
        if (classified->value_class == AbiValueClass::integer) {
            if (next_integer < 8) {
                slots.push_back({AbiValueClass::integer,
                    RegisterOperand{RegisterBank::arm64_gpr, static_cast<std::uint8_t>(next_integer++), 64, false},
                    {}, parameter_number, {}});
                continue;
            }
        } else if (classified->value_class == AbiValueClass::floating) {
            if (classified->floating_components.size() <= 8 - next_simd) {
                for (std::size_t component = 0; component < classified->floating_components.size(); ++component) {
                    slots.push_back({AbiValueClass::floating, arm64_simd(static_cast<unsigned>(next_simd++)), {},
                        parameter_number, classified->homogeneous_aggregate
                            ? std::optional<std::uint8_t>{static_cast<std::uint8_t>(component)}
                            : std::nullopt});
                }
                continue;
            }
            // An HFA is allocated all-or-nothing. If its members do not fit
            // in the remaining SIMD argument registers, the aggregate is
            // stack-passed; the current register-slot IR cannot describe that
            // composite stack value, so stop before assigning later slots.
            if (classified->homogeneous_aggregate) break;
        } else if (classified->value_class == AbiValueClass::vector) {
            if (next_simd < 8) {
                slots.push_back({AbiValueClass::vector, arm64_simd(static_cast<unsigned>(next_simd++)), {},
                    parameter_number, {}});
                continue;
            }
        }

        const auto type = unqualified_type(parameter.type);
        if (!type || !type->size() || *type->size() == 0 || *type->size() > 16) break;
        const auto alignment = std::min<std::uint64_t>(16, std::max<std::uint64_t>(8, type->alignment()));
        const auto remainder = static_cast<std::uint64_t>(stack_offset) % alignment;
        if (remainder) stack_offset += static_cast<std::int64_t>(alignment - remainder);
        if (stack_offset < 0 || stack_offset > (1 << 20) - 16) break;
        slots.push_back({classified->value_class, {}, stack_offset, parameter_number, {}});
        const auto allocation = std::max<std::uint64_t>(8, (*type->size() + 7) & ~std::uint64_t{7});
        if (allocation > static_cast<std::uint64_t>((1 << 20) - stack_offset)) break;
        stack_offset += static_cast<std::int64_t>(allocation);
    }
    return slots;
}

std::vector<AbiArgumentSlot> ppc64_elfv2_prototype_slots(const types::TypePtr &prototype) {
    std::vector<AbiArgumentSlot> slots;
    if (!prototype || prototype->kind() != types::Kind::function || prototype->parameters().size() > 256)
        return slots;
    const auto classified = classify_abi_signature(CallingConvention::ppc64le_elfv2, *prototype);
    if (classified.arguments.size() != prototype->parameters().size()) return slots;
    for (std::size_t index = 0; index < classified.arguments.size(); ++index) {
        const auto &argument = classified.arguments[index];
        const auto &type = prototype->parameters()[index].type;
        const auto parameter_type = unqualified_type(type);
        const auto value_class = parameter_type && parameter_type->kind() == types::Kind::floating
            ? AbiValueClass::floating : AbiValueClass::integer;
        if (!argument.supported || argument.locations.size() != 1 || !type) continue;
        const auto &location = argument.locations.front();
        if (location.kind == AbiLocationKind::register_) {
            const auto reg = ppc64_classified_register(location.register_name);
            if (!reg) continue;
            slots.push_back({value_class, *reg, {}, static_cast<std::uint16_t>(index)});
        } else if (location.stack_offset <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            slots.push_back({value_class, {}, static_cast<std::int64_t>(location.stack_offset),
                             static_cast<std::uint16_t>(index)});
        }
    }
    return slots;
}

std::vector<AbiArgumentSlot> mips_n32_prototype_slots(const types::TypePtr &prototype) {
    std::vector<AbiArgumentSlot> slots;
    if (!prototype || prototype->kind() != types::Kind::function || prototype->parameters().size() > 256)
        return slots;
    const auto classified = classify_abi_signature(CallingConvention::mips_n32, *prototype);
    if (classified.arguments.size() != prototype->parameters().size()) return slots;
    for (std::size_t index = 0; index < classified.arguments.size(); ++index) {
        const auto &placement = classified.arguments[index];
        const auto type = index < prototype->parameters().size()
            ? unqualified_type(prototype->parameters()[index].type) : types::TypePtr{};
        const auto value_class = type && type->kind() == types::Kind::floating
            ? AbiValueClass::floating : AbiValueClass::integer;
        const auto parameter_index = static_cast<std::uint16_t>(index);
        if (!placement.supported || placement.locations.size() != 1) {
            slots.push_back({value_class, {}, {}, parameter_index, {}, {}, {}, false});
            continue;
        }
        const auto &location = placement.locations.front();
        if (location.kind == AbiLocationKind::register_) {
            const auto reg = mips_n32_classified_register(location.register_name);
            if (!reg) {
                slots.push_back({value_class, {}, {}, parameter_index, {}, {}, {}, false});
                continue;
            }
            slots.push_back({value_class, *reg, {}, parameter_index});
        } else if (location.kind == AbiLocationKind::stack &&
                   location.stack_offset <= static_cast<std::uint64_t>(INT64_MAX)) {
            slots.push_back({value_class, {}, static_cast<std::int64_t>(location.stack_offset), parameter_index});
        } else {
            slots.push_back({value_class, {}, {}, parameter_index, {}, {}, {}, false});
        }
    }
    return slots;
}

std::vector<AbiArgumentSlot> sysv64_prototype_slots(const types::TypePtr &prototype) {
    std::vector<AbiArgumentSlot> slots;
    if (!prototype || prototype->kind() != types::Kind::function || prototype->parameters().size() > 256)
        return slots;
    const auto classified = classify_abi_signature(CallingConvention::sysv_x86_64, *prototype);
    if (classified.arguments.size() != prototype->parameters().size()) return slots;
    for (std::size_t parameter_index = 0; parameter_index < classified.arguments.size(); ++parameter_index) {
        const auto &placement = classified.arguments[parameter_index];
        if (!placement.supported || placement.locations.empty()) {
            slots.push_back({AbiValueClass::integer, {}, {},
                static_cast<std::uint16_t>(parameter_index), {}, {}, {}, false});
            continue;
        }
        const auto parameter_type = unqualified_type(prototype->parameters()[parameter_index].type);
        const bool aggregate = parameter_type &&
            (parameter_type->kind() == types::Kind::structure || parameter_type->kind() == types::Kind::union_type);
        for (std::size_t component = 0; component < placement.locations.size(); ++component) {
            const auto &location = placement.locations[component];
            std::optional<RegisterOperand> reg;
            if (location.kind == AbiLocationKind::register_) reg = classified_register(location.register_name);
            if ((location.kind == AbiLocationKind::register_ && !reg) ||
                (location.kind == AbiLocationKind::stack &&
                 location.stack_offset > static_cast<std::uint64_t>(INT64_MAX))) {
                while (!slots.empty() && slots.back().parameter_index == parameter_index)
                    slots.pop_back();
                slots.push_back({AbiValueClass::integer, {}, {},
                    static_cast<std::uint16_t>(parameter_index), {}, {}, {}, false});
                break;
            }
            const auto value_class = parameter_type && parameter_type->kind() == types::Kind::vector
                ? AbiValueClass::vector
                : parameter_type && parameter_type->kind() == types::Kind::floating
                    ? AbiValueClass::floating
                    : (reg && reg->bank == RegisterBank::xmm) ? AbiValueClass::floating : AbiValueClass::integer;
            std::optional<std::uint8_t> offset, size;
            std::optional<std::uint8_t> component_index;
            if (aggregate) {
                if (location.value_offset > UINT8_MAX || location.size > UINT8_MAX) continue;
                offset = static_cast<std::uint8_t>(location.value_offset);
                size = static_cast<std::uint8_t>(location.size);
                if (component <= UINT8_MAX) component_index = static_cast<std::uint8_t>(component);
            }
            slots.push_back({value_class, reg,
                location.kind == AbiLocationKind::stack &&
                    location.stack_offset <= static_cast<std::uint64_t>(INT64_MAX)
                    ? std::optional<std::int64_t>{static_cast<std::int64_t>(location.stack_offset)}
                    : std::nullopt,
                static_cast<std::uint16_t>(parameter_index), component_index, offset, size});
        }
    }
    return slots;
}

std::optional<types::TypePtr> sysv64_component_type(const types::TypePtr &input,
    std::uint8_t component_offset, std::uint8_t component_size, AbiValueClass value_class) {
    const auto root = unqualified_type(input);
    if (!root || component_size == 0 || component_offset > root->size().value_or(0) ||
        component_size > root->size().value_or(0) - component_offset)
        return {};
    if (value_class == AbiValueClass::vector && root->kind() == types::Kind::vector &&
        component_offset == 0 && root->size() == component_size)
        return root;

    struct Leaf { std::uint64_t offset; types::TypePtr type; };
    std::vector<Leaf> leaves;
    std::size_t work = 0;
    bool valid = true;
    const auto collect = [&](const types::TypePtr &candidate, std::uint64_t base, unsigned depth,
                             auto &&self) -> void {
        if (!valid || !candidate || depth > 8 || work++ >= 256) { valid = false; return; }
        const auto type = unqualified_type(candidate);
        if (!type || !type->size() || !*type->size()) { valid = false; return; }
        if (type->kind() == types::Kind::floating || type->kind() == types::Kind::vector) {
            leaves.push_back({base, type});
            return;
        }
        if (type->kind() == types::Kind::array) {
            if (!type->element() || !type->count() || type->count() > 32) { valid = false; return; }
            const auto element = unqualified_type(type->element());
            if (!element || !element->size() || !*element->size() ||
                type->count() > *type->size() / *element->size() ||
                type->count() * *element->size() != *type->size()) { valid = false; return; }
            for (std::uint64_t index = 0; index < type->count(); ++index)
                self(type->element(), base + index * *element->size(), depth + 1, self);
            return;
        }
        if (type->kind() == types::Kind::structure) {
            const auto layout = types::layout(*type, types::Abi::x86_64);
            if (!layout || type->members().size() != layout.value().members.size()) { valid = false; return; }
            for (std::size_t index = 0; index < type->members().size(); ++index) {
                const auto &member = type->members()[index];
                if (!member.has_fixed_offset() || member.bit_width || member.bit_offset || !member.type) {
                    valid = false;
                    return;
                }
                self(member.type, base + layout.value().members[index].offset, depth + 1, self);
            }
            return;
        }
        valid = false;
    };
    collect(root, 0, 0, collect);
    if (!valid) return {};
    const auto begin = static_cast<std::uint64_t>(component_offset);
    const auto end = begin + component_size;
    std::vector<Leaf> members;
    for (const auto &leaf : leaves) {
        if (!leaf.type || !leaf.type->size()) return {};
        const auto leaf_end = leaf.offset + *leaf.type->size();
        if (leaf_end <= begin || leaf.offset >= end) continue;
        if (leaf.offset < begin || leaf_end > end) return {};
        members.push_back(leaf);
    }
    if (members.empty()) return {};
    std::sort(members.begin(), members.end(), [](const Leaf &left, const Leaf &right) {
        return left.offset < right.offset;
    });
    if (value_class == AbiValueClass::integer) {
        std::uint64_t cursor = begin;
        for (const auto &member : members) {
            if (member.offset != cursor || *member.type->size() > end - cursor) return {};
            cursor += *member.type->size();
        }
        if (cursor != end) return {};
        auto value = types::Type::integer("sysv_aggregate_piece", component_size, 1, false);
        return value ? std::optional<types::TypePtr>{value.value()} : std::nullopt;
    }
    if (members.size() == 1 && members.front().offset == begin &&
        *members.front().type->size() == component_size)
        return members.front().type;
    const auto lane = members.front().type;
    if (lane->kind() != types::Kind::floating || !lane->size() || !*lane->size()) return {};
    std::uint64_t cursor = begin;
    for (const auto &member : members) {
        if (member.type->kind() != types::Kind::floating || member.type->size() != lane->size() ||
            member.offset != cursor || *member.type->size() > end - cursor)
            return {};
        cursor += *member.type->size();
    }
    if (cursor != end) return {};
    const auto vector = types::Type::vector(lane, members.size(), component_size);
    return vector ? std::optional<types::TypePtr>{vector.value()} : std::nullopt;
}

struct Sysv64ReturnPiece {
    RegisterOperand reg;
    std::uint8_t offset = 0;
    std::uint8_t size = 0;
    types::TypePtr type;
};

std::optional<std::vector<Sysv64ReturnPiece>> sysv64_aggregate_return_pieces(
    const types::TypePtr &input) {
    const auto aggregate = unqualified_type(input);
    if (!aggregate || !aggregate->size() || *aggregate->size() == 0 || *aggregate->size() > 16 ||
        aggregate->kind() != types::Kind::structure)
        return {};
    const auto signature = types::Type::function(input, {}, false);
    if (!signature) return {};
    const auto classified = classify_abi_signature(CallingConvention::sysv_x86_64, *signature.value());
    const auto &result = classified.result;
    if (!result.supported || result.indirect || result.locations.size() != 2) return {};
    std::vector<Sysv64ReturnPiece> pieces;
    pieces.reserve(result.locations.size());
    std::set<std::tuple<unsigned, unsigned, unsigned, bool>> seen;
    for (const auto &location : result.locations) {
        if (location.kind != AbiLocationKind::register_ || location.role != AbiLocationRole::value ||
            location.value_offset > UINT8_MAX || location.size == 0 || location.size > UINT8_MAX)
            return {};
        const auto reg = classified_register(location.register_name);
        if (!reg || !reg->width || location.size > reg->width / 8 ||
            (reg->bank != RegisterBank::gpr && reg->bank != RegisterBank::xmm) ||
            !seen.emplace(static_cast<unsigned>(reg->bank), reg->index, reg->width, reg->high_byte).second)
            return {};
        const auto piece_class = reg->bank == RegisterBank::xmm ? AbiValueClass::floating
                                                                 : AbiValueClass::integer;
        const auto projected = sysv64_component_type(input,
            static_cast<std::uint8_t>(location.value_offset), static_cast<std::uint8_t>(location.size), piece_class);
        if (!projected) return {};
        pieces.push_back({*reg, static_cast<std::uint8_t>(location.value_offset),
                          static_cast<std::uint8_t>(location.size), *projected});
    }
    std::sort(pieces.begin(), pieces.end(), [](const auto &left, const auto &right) {
        return left.offset < right.offset;
    });
    std::uint64_t cursor = 0;
    for (const auto &piece : pieces) {
        if (piece.offset != cursor) return {};
        cursor += piece.size;
    }
    if (cursor != *aggregate->size()) return {};
    return pieces;
}

std::optional<std::vector<Sysv64ReturnPiece>> ppc64_aggregate_return_pieces(
    const types::TypePtr &input) {
    const auto aggregate = unqualified_type(input);
    if (!aggregate || aggregate->kind() != types::Kind::structure || !aggregate->size() ||
        *aggregate->size() != 16)
        return {};
    const auto signature = types::Type::function(input, {}, false);
    if (!signature) return {};
    const auto classified = classify_abi_signature(CallingConvention::ppc64le_elfv2, *signature.value());
    const auto &result = classified.result;
    if (!result.supported || result.indirect || result.locations.size() != 2) return {};

    std::vector<Sysv64ReturnPiece> pieces;
    pieces.reserve(2);
    for (std::size_t index = 0; index < result.locations.size(); ++index) {
        const auto &location = result.locations[index];
        if (location.kind != AbiLocationKind::register_ || location.role != AbiLocationRole::value ||
            location.value_offset != index * 8 || location.size != 8 ||
            location.register_name != "R" + std::to_string(3 + index))
            return {};
        const auto reg = ppc64_classified_register(location.register_name);
        if (!reg || reg->bank != RegisterBank::ppc_gpr || reg->width != 64) return {};

        std::vector<const types::Member *> members;
        const auto begin = static_cast<std::uint64_t>(location.value_offset);
        const auto end = begin + location.size;
        for (const auto &member : aggregate->members()) {
            if (!member.type || !member.has_fixed_offset() || member.bit_width || member.bit_offset ||
                !member.type->size() || member.offset > *aggregate->size() ||
                *member.type->size() > *aggregate->size() - member.offset)
                return {};
            const auto member_end = member.offset + *member.type->size();
            if (member_end <= begin || member.offset >= end) continue;
            if (member.offset < begin || member_end > end) return {};
            const auto type = unqualified_type(member.type);
            if (!type || (type->kind() != types::Kind::boolean && type->kind() != types::Kind::integer &&
                          type->kind() != types::Kind::enumeration && type->kind() != types::Kind::pointer))
                return {};
            members.push_back(&member);
        }
        std::sort(members.begin(), members.end(), [](const auto *left, const auto *right) {
            return left->offset < right->offset;
        });
        std::uint64_t cursor = begin;
        for (const auto *member : members) {
            if (member->offset != cursor) return {};
            cursor += *member->type->size();
        }
        if (cursor != end || members.empty()) return {};
        types::TypePtr piece_type;
        if (members.size() == 1 && members.front()->offset == begin &&
            *members.front()->type->size() == location.size) {
            piece_type = members.front()->type;
        } else {
            auto integer = types::Type::integer("ppc64_aggregate_piece", location.size, 1, false);
            if (!integer) return {};
            piece_type = integer.value();
        }
        pieces.push_back({*reg, static_cast<std::uint8_t>(begin),
                          static_cast<std::uint8_t>(location.size), std::move(piece_type)});
    }
    return pieces;
}

struct Aapcs64HfaReturnPiece {
    RegisterOperand reg;
    std::uint8_t offset = 0;
    std::uint8_t size = 0;
    types::TypePtr type;
};

std::optional<std::vector<Aapcs64HfaReturnPiece>> aapcs64_hfa_return_pieces(
    const types::TypePtr &input) {
    const auto aggregate = unqualified_type(input);
    if (!aggregate || (aggregate->kind() != types::Kind::structure &&
                       aggregate->kind() != types::Kind::array) ||
        !aggregate->size() || *aggregate->size() == 0 || *aggregate->size() > 64)
        return {};
    const auto components = hfa_float_elements(input);
    if (!components || components->size() < 2 || components->size() > 4) return {};
    const auto signature = types::Type::function(input, {}, false);
    if (!signature) return {};
    const auto classified = classify_abi_signature(CallingConvention::aapcs64, *signature.value());
    const auto &result = classified.result;
    if (!result.supported || result.indirect || result.locations.size() != components->size()) return {};

    std::vector<Aapcs64HfaReturnPiece> pieces;
    pieces.reserve(components->size());
    std::uint64_t offset = 0;
    std::set<unsigned> seen_registers;
    for (std::size_t index = 0; index < components->size(); ++index) {
        const auto &component = (*components)[index];
        const auto &location = result.locations[index];
        if (!component || !component->size() || !*component->size() ||
            offset > UINT8_MAX || *component->size() > UINT8_MAX ||
            location.kind != AbiLocationKind::register_ ||
            location.role != AbiLocationRole::value || location.value_offset != offset ||
            location.size != *component->size())
            return {};
        const auto reg = classified_register(location.register_name);
        if (!reg || reg->bank != RegisterBank::arm64_simd || reg->index != index ||
            !seen_registers.insert(reg->index).second || location.size > reg->width / 8)
            return {};
        pieces.push_back({*reg, static_cast<std::uint8_t>(offset),
                          static_cast<std::uint8_t>(*component->size()), component});
        offset += *component->size();
    }
    if (offset != *aggregate->size()) return {};
    return pieces;
}
} // namespace

AbiDescription x86_64_windows_abi() {
    AbiDescription a; a.name = "x86-64 Windows"; a.pointer_bits = 64;
    a.integer_argument_registers = {gpr(1), gpr(2), gpr(8), gpr(9)};
    a.caller_saved_registers = {gpr(0),gpr(1),gpr(2),gpr(8),gpr(9),gpr(10),gpr(11),
                                {RegisterBank::flags,0,64,false}};
    for (unsigned i=0;i<6;++i) a.caller_saved_registers.push_back(xmm(i));
    a.call_stack_adjustment = 8;
    a.integer_return_register = gpr(0);
    a.stack_argument_base = gpr(4);
    for (std::int64_t off = 40; off < 40 + 8 * 32; off += 8) a.stack_argument_offsets.push_back(off);
    for (unsigned i=0;i<4;++i) a.floating_argument_registers.push_back(xmm(i));
    a.floating_return_register=xmm(0);
    a.shared_integer_float_argument_positions=true;
    a.arguments = {{AbiValueClass::integer,gpr(1),{}}, {AbiValueClass::integer,gpr(2),{}},
                   {AbiValueClass::integer,gpr(8),{}}, {AbiValueClass::integer,gpr(9),{}}};
    for (unsigned i=0;i<4;++i) a.arguments.push_back({AbiValueClass::integer,{},40+static_cast<std::int64_t>(i)*8});
    return a;
}
AbiDescription x86_64_system_v_abi() {
    AbiDescription a; a.name = "x86-64 System V"; a.pointer_bits = 64;
    a.integer_argument_registers = {gpr(7),gpr(6),gpr(2),gpr(1),gpr(8),gpr(9)};
    a.caller_saved_registers = {gpr(0),gpr(1),gpr(2),gpr(6),gpr(7),gpr(8),gpr(9),gpr(10),gpr(11),
                                {RegisterBank::flags,0,64,false}};
    for (unsigned i=0;i<16;++i) a.caller_saved_registers.push_back(xmm(i));
    a.integer_return_register = gpr(0); a.stack_argument_base = gpr(4);
    a.call_stack_adjustment = 8;
    for (unsigned i=0;i<8;++i) a.floating_argument_registers.push_back(xmm(i));
    a.floating_return_register=xmm(0);
    for (std::int64_t off=8;off<8+8*32;off+=8) a.stack_argument_offsets.push_back(off);
    for (auto r:a.integer_argument_registers) a.arguments.push_back({AbiValueClass::integer,r,{}});
    for (std::int64_t off=8;off<8+8*32;off+=8) a.arguments.push_back({AbiValueClass::integer,{},off});
    return a;
}
AbiDescription x86_32_cdecl_abi() {
    AbiDescription a; a.name = "x86-32 cdecl"; a.pointer_bits = 32;
    a.integer_return_register = gpr(0, 32);
    a.stack_argument_base = gpr(4, 32);
    a.call_stack_adjustment = 4;
    a.caller_saved_registers = {gpr(0, 32), gpr(1, 32), gpr(2, 32),
                                {RegisterBank::flags, 0, 32, false}};
    // On entry, [ESP] is the return address; the first caller argument is at
    // ESP+4. Keep the ordered slots bounded while covering ordinary prototypes.
    for (std::int64_t offset = 4; offset < 4 + 4 * 32; offset += 4) {
        a.stack_argument_offsets.push_back(offset);
        a.arguments.push_back({AbiValueClass::integer, {}, offset});
    }
    return a;
}
AbiDescription aarch64_abi() {
    AbiDescription a; a.name = "AArch64 AAPCS64"; a.pointer_bits = 64;
    for(unsigned i=0;i<8;++i) a.integer_argument_registers.push_back({RegisterBank::arm64_gpr,static_cast<std::uint8_t>(i),64,false});
    a.integer_return_register = RegisterOperand{RegisterBank::arm64_gpr,0,64,false};
    for (unsigned i = 0; i < 8; ++i) {
        a.floating_argument_registers.push_back(arm64_simd(i));
        a.vector_argument_registers.push_back(arm64_simd(i));
    }
    a.floating_return_register = arm64_simd(0);
    a.vector_return_register = arm64_simd(0);
    a.stack_argument_base = RegisterOperand{RegisterBank::arm64_sp,0,64,false};
    a.call_stack_adjustment = 0;
    for(std::int64_t off=0;off<8*32;off+=8) a.stack_argument_offsets.push_back(off);
    for(auto r:a.integer_argument_registers) a.arguments.push_back({AbiValueClass::integer,r,{}});
    // Without a source prototype, the independently allocated register
    // classes have no recoverable interleaving. Keep a deterministic bank
    // order for the heuristic signature while prototype-driven recovery uses
    // the source parameter list and the separate class cursors above.
    for (auto r : a.floating_argument_registers) a.arguments.push_back({AbiValueClass::floating, r, {}});
    for(std::int64_t off=0;off<8*32;off+=8) a.arguments.push_back({AbiValueClass::integer,{},off});
    for (unsigned index = 0; index <= 18; ++index)
        if (index != 18) a.caller_saved_registers.push_back(
            {RegisterBank::arm64_gpr, static_cast<std::uint8_t>(index), 64, false});
    a.caller_saved_registers.push_back({RegisterBank::arm64_gpr, 30, 64, false});
    a.caller_saved_registers.push_back({RegisterBank::arm_flags, 0, 4, false});
    for (unsigned index = 0; index < 8; ++index) a.caller_saved_registers.push_back(arm64_simd(index));
    for (unsigned index = 16; index < 32; ++index) a.caller_saved_registers.push_back(arm64_simd(index));
    return a;
}

AbiDescription arm32_aapcs_abi() {
    AbiDescription a; a.name = "ARM32 AAPCS base PCS"; a.pointer_bits = 32;
    for (unsigned n = 0; n < 4; ++n)
        a.integer_argument_registers.push_back({RegisterBank::arm32_gpr, static_cast<std::uint8_t>(n), 32, false});
    a.integer_return_register = RegisterOperand{RegisterBank::arm32_gpr, 0, 32, false};
    a.stack_argument_base = RegisterOperand{RegisterBank::arm32_gpr, 13, 32, false};
    a.caller_saved_registers = a.integer_argument_registers;
    a.caller_saved_registers.push_back({RegisterBank::arm32_gpr, 12, 32, false});
    a.caller_saved_registers.push_back({RegisterBank::arm32_gpr, 14, 32, false});
    a.caller_saved_registers.push_back({RegisterBank::arm_flags, 0, 4, false});
    for (const auto reg : a.integer_argument_registers)
        a.arguments.push_back({AbiValueClass::integer, reg, {}});
    for (std::int64_t offset = 0; offset < 4 * 32; offset += 4) {
        a.stack_argument_offsets.push_back(offset);
        a.arguments.push_back({AbiValueClass::integer, {}, offset});
    }
    return a;
}

AbiDescription riscv32_ilp32_abi() {
    AbiDescription a; a.name = "RISC-V ILP32 integer-only register profile"; a.pointer_bits = 32;
    for (unsigned n = 10; n <= 17; ++n)
        a.integer_argument_registers.push_back({RegisterBank::riscv_gpr, static_cast<std::uint8_t>(n), 32, false});
    a.integer_return_register = RegisterOperand{RegisterBank::riscv_gpr, 10, 32, false};
    a.stack_argument_base = RegisterOperand{RegisterBank::riscv_gpr, 2, 32, false};
    a.caller_saved_registers = {
        {RegisterBank::riscv_gpr, 1, 32, false},
        {RegisterBank::riscv_gpr, 5, 32, false}, {RegisterBank::riscv_gpr, 6, 32, false},
        {RegisterBank::riscv_gpr, 7, 32, false},
        {RegisterBank::riscv_gpr, 28, 32, false}, {RegisterBank::riscv_gpr, 29, 32, false},
        {RegisterBank::riscv_gpr, 30, 32, false}, {RegisterBank::riscv_gpr, 31, 32, false}};
    a.caller_saved_registers.insert(a.caller_saved_registers.end(), a.integer_argument_registers.begin(),
                                    a.integer_argument_registers.end());
    for (const auto reg : a.integer_argument_registers)
        a.arguments.push_back({AbiValueClass::integer, reg, {}});
    for (std::int64_t offset = 0; offset < 4 * 32; offset += 4) {
        a.stack_argument_offsets.push_back(offset);
        a.arguments.push_back({AbiValueClass::integer, {}, offset});
    }
    return a;
}

AbiDescription riscv64_lp64_abi() {
    AbiDescription a; a.name = "RISC-V LP64 integer-only register profile"; a.pointer_bits = 64;
    for (unsigned n = 10; n <= 17; ++n)
        a.integer_argument_registers.push_back({RegisterBank::riscv_gpr, static_cast<std::uint8_t>(n), 64, false});
    a.integer_return_register = RegisterOperand{RegisterBank::riscv_gpr, 10, 64, false};
    a.stack_argument_base = RegisterOperand{RegisterBank::riscv_gpr, 2, 64, false};
    a.caller_saved_registers = {
        {RegisterBank::riscv_gpr, 1, 64, false},
        {RegisterBank::riscv_gpr, 5, 64, false}, {RegisterBank::riscv_gpr, 6, 64, false},
        {RegisterBank::riscv_gpr, 7, 64, false},
        {RegisterBank::riscv_gpr, 28, 64, false}, {RegisterBank::riscv_gpr, 29, 64, false},
        {RegisterBank::riscv_gpr, 30, 64, false}, {RegisterBank::riscv_gpr, 31, 64, false}};
    a.caller_saved_registers.insert(a.caller_saved_registers.end(), a.integer_argument_registers.begin(),
                                    a.integer_argument_registers.end());
    for (const auto reg : a.integer_argument_registers)
        a.arguments.push_back({AbiValueClass::integer, reg, {}});
    for (std::int64_t offset = 0; offset < 8 * 32; offset += 8) {
        a.stack_argument_offsets.push_back(offset);
        a.arguments.push_back({AbiValueClass::integer, {}, offset});
    }
    return a;
}

AbiDescription mips32_o32_abi() {
    AbiDescription a; a.name = "MIPS32 O32 integer-register profile"; a.pointer_bits = 32;
    for (unsigned n = 4; n <= 7; ++n)
        a.integer_argument_registers.push_back({RegisterBank::mips_gpr, static_cast<std::uint8_t>(n), 32, false});
    a.integer_return_register = RegisterOperand{RegisterBank::mips_gpr, 2, 32, false};
    a.stack_argument_base = RegisterOperand{RegisterBank::mips_gpr, 29, 32, false};
    for (unsigned n : {2u, 3u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u, 24u, 25u, 31u})
        a.caller_saved_registers.push_back({RegisterBank::mips_gpr, static_cast<std::uint8_t>(n), 32, false});
    a.caller_saved_registers.insert(a.caller_saved_registers.end(), a.integer_argument_registers.begin(),
                                    a.integer_argument_registers.end());
    a.caller_saved_registers.push_back({RegisterBank::mips_hilo, 0, 32, false});
    a.caller_saved_registers.push_back({RegisterBank::mips_hilo, 1, 32, false});
    for (const auto reg : a.integer_argument_registers)
        a.arguments.push_back({AbiValueClass::integer, reg, {}});
    // O32 reserves the first sixteen bytes of the caller's argument area as
    // register home space; stack arguments follow it.
    for (std::int64_t offset = 16; offset < 16 + 4 * 32; offset += 4) {
        a.stack_argument_offsets.push_back(offset);
        a.arguments.push_back({AbiValueClass::integer, {}, offset});
    }
    return a;
}

AbiDescription mips64_n64_abi() {
    AbiDescription a; a.name = "MIPS64 Linux N64 hard-float scalar profile"; a.pointer_bits = 64;
    for (unsigned n = 4; n <= 11; ++n)
        a.integer_argument_registers.push_back({RegisterBank::mips_gpr, static_cast<std::uint8_t>(n), 64, false});
    a.integer_return_register = RegisterOperand{RegisterBank::mips_gpr, 2, 64, false};
    a.floating_return_register = RegisterOperand{RegisterBank::mips_fpr, 0, 64, false};
    for (unsigned n = 12; n <= 19; ++n)
        a.floating_argument_registers.push_back({RegisterBank::mips_fpr, static_cast<std::uint8_t>(n), 64, false});
    a.shared_integer_float_argument_positions = true;
    a.stack_argument_base = RegisterOperand{RegisterBank::mips_gpr, 29, 64, false};
    for (unsigned n : {1u, 2u, 3u, 12u, 13u, 14u, 15u, 24u, 25u, 31u})
        a.caller_saved_registers.push_back({RegisterBank::mips_gpr, static_cast<std::uint8_t>(n), 64, false});
    a.caller_saved_registers.insert(a.caller_saved_registers.end(), a.integer_argument_registers.begin(),
                                    a.integer_argument_registers.end());
    a.caller_saved_registers.push_back({RegisterBank::mips_hilo, 0, 64, false});
    a.caller_saved_registers.push_back({RegisterBank::mips_hilo, 1, 64, false});
    for (unsigned n = 0; n <= 19; ++n)
        a.caller_saved_registers.push_back({RegisterBank::mips_fpr, static_cast<std::uint8_t>(n), 64, false});
    for (const auto reg : a.integer_argument_registers)
        a.arguments.push_back({AbiValueClass::integer, reg, {}});
    for (std::int64_t offset = 0; offset < 8 * 32; offset += 8) {
        a.stack_argument_offsets.push_back(offset);
        a.arguments.push_back({AbiValueClass::integer, {}, offset});
    }
    return a;
}

AbiDescription mips_n32_abi() {
    // N32 keeps 64-bit GPRs and eight-byte argument slots while pointers
    // remain 32-bit. Its scalar subset shares the N64 register convention.
    auto a = mips64_n64_abi();
    a.name = "MIPS N32 hard-float scalar profile";
    a.pointer_bits = 32;
    return a;
}

AbiDescription ppc64le_elfv2_abi() {
    AbiDescription a;
    a.name = "PowerPC64 ELFv2";
    a.pointer_bits = 64;
    for (unsigned index = 3; index <= 10; ++index)
        a.integer_argument_registers.push_back(
            {RegisterBank::ppc_gpr, static_cast<std::uint8_t>(index), 64, false});
    a.integer_return_register = RegisterOperand{RegisterBank::ppc_gpr, 3, 64, false};
    for (unsigned index = 1; index <= 13; ++index)
        a.floating_argument_registers.push_back(
            {RegisterBank::ppc_fpr, static_cast<std::uint8_t>(index), 64, false});
    a.floating_return_register = RegisterOperand{RegisterBank::ppc_fpr, 1, 64, false};
    a.stack_argument_base = RegisterOperand{RegisterBank::ppc_gpr, 1, 64, false};
    // The first eight doublewords are assigned to R3-R10. Stack locations in
    // the caller's parameter-save area follow the 32-byte linkage area.
    for (std::int64_t offset = 96; offset < 96 + 8 * 32; offset += 8)
        a.stack_argument_offsets.push_back(offset);

    for (unsigned index : {0u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u})
        a.caller_saved_registers.push_back(
            {RegisterBank::ppc_gpr, static_cast<std::uint8_t>(index), 64, false});
    for (unsigned index = 0; index <= 13; ++index)
        a.caller_saved_registers.push_back(
            {RegisterBank::ppc_fpr, static_cast<std::uint8_t>(index), 64, false});
    for (unsigned index = 0; index <= 19; ++index)
        a.caller_saved_registers.push_back(
            {RegisterBank::ppc_vr, static_cast<std::uint8_t>(index), 128, false});
    for (unsigned index : {0u, 1u, 5u, 6u, 7u})
        a.caller_saved_registers.push_back(
            {RegisterBank::ppc_cr, static_cast<std::uint8_t>(index), 4, false});
    a.caller_saved_registers.push_back({RegisterBank::ppc_lr, 0, 64, false});
    a.caller_saved_registers.push_back({RegisterBank::ppc_ctr, 0, 64, false});
    a.caller_saved_registers.push_back({RegisterBank::ppc_xer, 0, 64, false});
    return a;
}

static Result<TypeRecoveryResult> recover_types_impl(
    const LiftedFunction &fn, const AbiDescription &abi, types::TypePtr prototype,
    std::span<const types::TypePtr> parameter_constraints = {},
    std::span<const RegisterValue> known_call_inputs = {},
    std::span<const KnownTypedRegister> known_argument_types = {}) {
    if (fn.blocks.empty()) return Error{ErrorCode::invalid_argument, "type recovery requires at least one block"};
    if (prototype && prototype->kind()!=types::Kind::function)
        return Error{ErrorCode::invalid_argument, "type recovery prototype must be a function type"};
    std::map<Key, Fact> facts;
    std::map<Key, std::optional<bool>> division_signedness;
    // ABI snapshots describe liveness, not evidence that a callee consumes
    // every argument register. Only actual reads or known parameter uses count.
    std::set<Key> parameter_evidence;
    for (const auto &input : known_call_inputs) parameter_evidence.insert(key(input.reg, input.version));
    std::vector<PointerAlias> pointer_aliases;
    auto ensure=[&](RegisterOperand r,std::optional<std::uint32_t> v={}) -> Fact& {
        Fact initial;
        initial.reg = r;
        initial.version = v;
        initial.bits = r.width;
        auto [it,inserted]=facts.try_emplace(key(r,v),std::move(initial));
        (void)inserted; return it->second;
    };
    auto register_expr=[&](const ExpressionPtr &e, auto &&self)->void {
        if (!e) return;
        const auto record_division_operand = [&](const ExpressionPtr &operand, bool is_signed) {
            if (!operand) return;
            const auto *value = std::get_if<RegisterValue>(&operand->value);
            if (!value) return;
            const auto operand_key = key(value->reg, value->version);
            auto [found, inserted] = division_signedness.emplace(operand_key, is_signed);
            if (!inserted && found->second && *found->second != is_signed) found->second.reset();
        };
        std::visit([&](const auto &x) {
            using T=std::decay_t<decltype(x)>;
            if constexpr(std::is_same_v<T,RegisterValue>) {
                parameter_evidence.insert(key(x.reg, x.version));
                auto &fact = ensure(x.reg,x.version);
                if (e->type.kind == TypeKind::floating && !fact.floating_ambiguous) {
                    fact.floating = true;
                    if (e->type.bits) fact.bits = e->type.bits;
                }
                if (e->type.kind == TypeKind::vector) {
                    Fact vector_fact;
                    vector_fact.vector_evidence = true;
                    vector_fact.vector_type = vector_type_from_value(e->type);
                    merge_vector_fact(fact, vector_fact);
                }
            }
            else if constexpr(std::is_same_v<T,MemoryValue>) {
                if(x.base) {
                    parameter_evidence.insert(key(*x.base, x.base_version));
                    auto &base = ensure(*x.base,x.base_version);
                    base.pointer=true;
                    const auto access_bytes = static_cast<std::uint16_t>((x.type.bits + 7u) / 8u);
                    // ARM commonly represents a byte-scaled array index as
                    // `index << n` while leaving MemoryValue::scale at one.
                    // Treat that as equivalent to an explicit scale only for
                    // a plain LSL whose effective scale exactly matches the
                    // accessed element width.
                    const auto effective_scale = x.index_shift.empty()
                        ? static_cast<std::uint32_t>(x.scale)
                        : x.index_shift == "lsl" && x.index_shift_amount < 31 && x.scale <= (1u << 20) >> x.index_shift_amount
                            ? static_cast<std::uint32_t>(x.scale) << x.index_shift_amount
                            : 0u;
                    if (x.index && x.index_add && x.displacement == 0 &&
                        x.type.bits && x.type.bits % 8 == 0 && effective_scale == access_bytes) {
                        if (base.indexed_element_bits && *base.indexed_element_bits != x.type.bits) {
                            base.indexed_element_bits.reset();
                            base.indexed_element_ambiguous = true;
                        } else if (!base.indexed_element_ambiguous) base.indexed_element_bits = x.type.bits;
                    }
                    if (!x.index && !x.absolute && x.displacement >= 0 && x.type.bits && x.type.bits % 8 == 0) {
                        auto &field_bits = base.object_fields[static_cast<std::uint64_t>(x.displacement)];
                        if (field_bits && field_bits != x.type.bits) base.object_layout_ambiguous = true;
                        else field_bits = x.type.bits;
                    }
                }
                if(x.index) { parameter_evidence.insert(key(*x.index, x.index_version)); ensure(*x.index,x.index_version); }
            } else if constexpr(std::is_same_v<T,UnaryValue>) self(x.operand,self);
            else if constexpr(std::is_same_v<T,BinaryValue>) {
                if (x.operation == "sdiv" || x.operation == "srem" || x.operation == "a64_sdiv") {
                    record_division_operand(x.left, true);
                    record_division_operand(x.right, true);
                } else if (x.operation == "udiv" || x.operation == "urem" || x.operation == "a64_udiv") {
                    record_division_operand(x.left, false);
                    record_division_operand(x.right, false);
                }
                self(x.left,self); self(x.right,self);
            }
        },e->value);
    };
    for (const auto &b:fn.blocks) {
        for (const auto &p:b.phis) { auto &f=ensure(p.destination,p.version); for(auto i:p.inputs) ensure(p.destination,i.version); (void)f; }
        for (const auto &i:b.instructions) std::visit([&](const auto &s) {
            using T=std::decay_t<decltype(s)>;
            if constexpr(std::is_same_v<T,Assign>) {
                auto &f=ensure(s.destination,s.destination_version);
                f.bits=s.destination.width;
                register_expr(s.value,register_expr);
                if (auto alias=pointer_alias(s)) pointer_aliases.push_back(*alias);
            }
            else if constexpr(std::is_same_v<T,Store>) { register_expr(s.address,register_expr); register_expr(s.value,register_expr); }
            else if constexpr(std::is_same_v<T,Call>) {
                register_expr(s.indirect_target,register_expr);
                for (const auto &input : s.register_inputs) ensure(input.reg, input.version);
                for (std::size_t n = 0; n < s.register_writes.size(); ++n)
                    ensure(s.register_writes[n], n < s.register_output_versions.size()
                        ? std::optional<std::uint32_t>{s.register_output_versions[n]} : std::nullopt);
                if (s.return_register && s.return_version && s.result_type) {
                    auto &returned = ensure(*s.return_register, s.return_version);
                    returned.bits = type_bits(s.result_type);
                    returned.sign = is_signed_type(s.result_type);
                    returned.pointer = is_pointer_type(s.result_type);
                    returned.floating = s.result_type->kind() == types::Kind::floating;
                    returned.constrained = true;
                    merge_exact_type(returned, s.result_type);
                }
                const auto returned_aggregate = unqualified_type(s.result_type);
                if (s.result_type && !s.return_register && returned_aggregate &&
                    (returned_aggregate->kind() == types::Kind::structure ||
                     returned_aggregate->kind() == types::Kind::array)) {
                    const auto pieces = sysv64_aggregate_return_pieces(s.result_type);
                    const auto hfa_pieces = aapcs64_hfa_return_pieces(s.result_type);
                    const auto ppc_pieces = ppc64_aggregate_return_pieces(s.result_type);
                    const auto apply_piece = [&](const auto &piece) {
                        for (std::size_t n = 0; n < s.register_writes.size(); ++n) {
                            if (s.register_writes[n] != piece.reg || n >= s.register_output_versions.size()) continue;
                            auto &returned = ensure(piece.reg, s.register_output_versions[n]);
                            returned.bits = type_bits(piece.type);
                            returned.sign = is_signed_type(piece.type);
                            returned.pointer = is_pointer_type(piece.type);
                            returned.floating = piece.type->kind() == types::Kind::floating;
                            returned.constrained = true;
                            merge_exact_type(returned, piece.type);
                            break;
                        }
                    };
                    if (pieces) {
                        for (const auto &piece : *pieces) {
                            apply_piece(piece);
                        }
                    } else if (hfa_pieces) {
                        for (const auto &piece : *hfa_pieces) apply_piece(piece);
                    } else if (ppc_pieces) {
                        for (const auto &piece : *ppc_pieces) apply_piece(piece);
                    }
                }
            }
            else if constexpr(std::is_same_v<T,Return>) register_expr(s.value,register_expr);
            else if constexpr(std::is_same_v<T,Branch>) {
                register_expr(s.predicate,register_expr); register_expr(s.indirect_target,register_expr);
            }
            else if constexpr(std::is_same_v<T,Intrinsic>) {
                for(const auto &e:s.operands) register_expr(e,register_expr);
                if (s.result_type && s.result_type->kind == TypeKind::floating) {
                    for (std::size_t n = 0; n < s.register_writes.size(); ++n) {
                        const auto bank = s.register_writes[n].bank;
                        if (bank != RegisterBank::x87 && bank != RegisterBank::mips_fpr &&
                            bank != RegisterBank::riscv_fpr)
                            continue;
                        const auto version = n < s.register_output_versions.size()
                            ? std::optional<std::uint32_t>{s.register_output_versions[n]} : std::nullopt;
                        auto &destination = ensure(s.register_writes[n], version);
                        destination.bits = s.result_type->bits ? s.result_type->bits : destination.bits;
                        destination.floating = true;
                    }
                }
                if (s.result_type && s.result_type->kind == TypeKind::vector) {
                    Fact vector_fact;
                    vector_fact.bits = s.result_type->bits;
                    vector_fact.vector_evidence = true;
                    vector_fact.vector_type = vector_type_from_value(*s.result_type);
                    for (std::size_t n = 0; n < s.register_writes.size(); ++n) {
                        // RVV intrinsics also write scalar configuration state
                        // (vstart, for example). Keep those outputs independent
                        // of the vector or predicate destination's result type.
                        const auto bank = s.register_writes[n].bank;
                        if (bank == RegisterBank::riscv_vcsr || bank == RegisterBank::riscv_gpr) continue;
                        const auto version = n < s.register_output_versions.size()
                            ? std::optional<std::uint32_t>{s.register_output_versions[n]} : std::nullopt;
                        auto &destination = ensure(s.register_writes[n], version);
                        destination.bits = std::max(destination.bits, vector_fact.bits);
                        merge_vector_fact(destination, vector_fact);
                    }
                }
            }
        },i.statement);
    }
    for (const auto &block : fn.blocks)
        if (block.switch_dispatch) register_expr(block.switch_dispatch->selector, register_expr);
    // A real read of a phi result also reads its incoming values. An unused
    // phi created solely for call-output bookkeeping supplies no evidence.
    bool evidence_changed = true;
    while (evidence_changed) {
        evidence_changed = false;
        for (const auto &block : fn.blocks) for (const auto &phi : block.phis)
            if (parameter_evidence.contains(key(phi.destination, phi.version)))
                for (const auto &input : phi.inputs)
                    evidence_changed |= parameter_evidence.insert(key(phi.destination, input.version)).second;
    }
    // Seed ABI parameters only when those register variables actually occur.
    std::vector<Key> unversioned;
    for (const auto &[k,f]:facts) if(!f.version) unversioned.push_back(k);
    std::vector<types::Parameter> parameters = prototype ? prototype->parameters() : std::vector<types::Parameter>{};
    const auto unqualified_type = [](types::TypePtr type) {
        while (type && type->kind() == types::Kind::qualified) type = type->element();
        return type;
    };
    const auto parameter_class = [&](types::TypePtr type) -> std::optional<AbiValueClass> {
        type = unqualified_type(std::move(type));
        if (!type) return {};
        switch (type->kind()) {
        case types::Kind::boolean: case types::Kind::integer: case types::Kind::enumeration:
        case types::Kind::pointer: return AbiValueClass::integer;
        case types::Kind::floating: return AbiValueClass::floating;
        case types::Kind::vector: return AbiValueClass::vector;
        case types::Kind::array: case types::Kind::structure:
            if (abi.name == "AArch64 AAPCS64" && hfa_float_elements(type)) return AbiValueClass::floating;
            return {};
        default: return {};
        }
    };
    const auto constrain_register = [&](RegisterOperand reg, const types::TypePtr &param) {
        if (!param) return;
        const auto unqualified = unqualified_type(param);
        const auto value_class = parameter_class(param);
        for (auto &[k, fact] : facts) {
            (void)k;
            // In SSA form, incoming ABI values use version zero; pre-SSA IR
            // leaves the same register unversioned.
            const bool alias_register = fact.reg.bank == reg.bank && fact.reg.index == reg.index &&
                fact.reg.high_byte == reg.high_byte &&
                (reg.bank == RegisterBank::gpr || reg.bank == RegisterBank::arm64_gpr || fact.reg.width == reg.width);
            if (!alias_register || (fact.version && *fact.version != 0)) continue;
            fact.bits = type_bits(unqualified) ? type_bits(unqualified) : fact.bits;
            fact.sign = is_signed_type(unqualified);
            fact.pointer = is_pointer_type(unqualified);
            fact.floating = value_class == AbiValueClass::floating;
            fact.constrained = true;
            merge_exact_type(fact, param);
            if (value_class == AbiValueClass::vector) {
                fact.vector_evidence = true;
                fact.vector_type = unqualified;
            }
        }
    };
    const auto constrain_stack_slot = [&](std::int64_t offset, const types::TypePtr &param) {
        if (!param || !abi.stack_argument_base) return;
        const auto bits = type_bits(param);
        if (!bits) return;
        for (const auto &block : fn.blocks) for (const auto &instruction : block.instructions) {
            const auto *assignment = std::get_if<Assign>(&instruction.statement);
            const auto *memory = assignment && assignment->value
                ? std::get_if<MemoryValue>(&assignment->value->value) : nullptr;
            if (!memory || !memory->base || memory->index || memory->absolute || memory->type.bits != bits) continue;
            const auto canonical = canonical_stack_address(key(*memory->base, memory->base_version), pointer_aliases);
            std::int64_t actual_offset = 0;
            if (!canonical || (canonical->first != key(*abi.stack_argument_base) &&
                               canonical->first != key(*abi.stack_argument_base, 0)) ||
                !checked_add(canonical->second, memory->displacement, actual_offset) || actual_offset != offset)
                continue;
            auto fact = facts.find(key(assignment->destination, assignment->destination_version));
            if (fact == facts.end()) continue;
            fact->second.bits = bits;
            fact->second.sign = is_signed_type(param);
            fact->second.pointer = is_pointer_type(param);
            fact->second.floating = param->kind() == types::Kind::floating;
            fact->second.constrained = true;
            merge_exact_type(fact->second, param);
            if (param->kind() == types::Kind::vector) {
                fact->second.vector_evidence = true;
                fact->second.vector_type = param;
            }
        }
    };
    if (prototype) {
        if (const auto convention = classifier_convention(abi)) {
            const auto classified = classify_abi_signature(*prototype, *convention);
            if (classified.arguments.size() == parameters.size()) {
                for (std::size_t i = 0; i < parameters.size(); ++i) {
                    const auto &placement = classified.arguments[i];
                    const auto &parameter_type = parameters[i].type;
                    const auto unqualified_parameter = unqualified_type(parameter_type);
                    if (abi.name == "x86-64 System V" && unqualified_parameter &&
                        (unqualified_parameter->kind() == types::Kind::structure ||
                         unqualified_parameter->kind() == types::Kind::union_type))
                        continue;
                    // A single, proven placement can constrain the matching
                    // incoming value. Split aggregates require component type
                    // recovery and are intentionally left to the existing
                    // architecture-specific evidence path.
                    if (!placement.supported || placement.locations.size() != 1 || !parameter_type)
                        continue;
                    const auto &location = placement.locations.front();
                    auto constrained_type = parameter_type;
                    if (placement.indirect) {
                        const auto pointer = types::Type::pointer(parameter_type,
                            classified.pointer_size, classified.pointer_size);
                        if (!pointer) continue;
                        constrained_type = pointer.value();
                    }
                    if (location.kind == AbiLocationKind::register_) {
                        const auto reg = abi.name == "PowerPC64 ELFv2"
                            ? ppc64_classified_register(location.register_name)
                            : abi.name == "MIPS N32 hard-float scalar profile"
                                ? mips_n32_classified_register(location.register_name)
                                : classified_register(location.register_name);
                        if (reg)
                            constrain_register(*reg, constrained_type);
                    } else if (location.stack_offset <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                        constrain_stack_slot(static_cast<std::int64_t>(location.stack_offset), constrained_type);
                    }
                }
            }
        }
        if (abi.name == "x86-64 System V") {
            for (const auto &slot : sysv64_prototype_slots(prototype)) {
                if (!slot.parameter_index || *slot.parameter_index >= parameters.size()) continue;
                const auto &parameter_type = parameters[*slot.parameter_index].type;
                if (!parameter_type) continue;
                if (slot.reg) {
                    auto component_type = parameter_type;
                    if (slot.component_offset && slot.component_size) {
                        const auto projected = sysv64_component_type(parameter_type, *slot.component_offset,
                                                                     *slot.component_size, slot.value_class);
                        if (!projected) continue;
                        component_type = *projected;
                    }
                    constrain_register(*slot.reg, component_type);
                } else if (slot.stack_offset) {
                    constrain_stack_slot(*slot.stack_offset, parameter_type);
                }
            }
        } else if (abi.name == "AArch64 AAPCS64") {
            const auto slots = aapcs64_prototype_slots(prototype);
            std::vector<bool> mapped(parameters.size(), false);
            for (const auto &slot : slots) {
                if (!slot.parameter_index || *slot.parameter_index >= parameters.size()) continue;
                const auto parameter_index = static_cast<std::size_t>(*slot.parameter_index);
                const auto &parameter_type = parameters[parameter_index].type;
                if (slot.reg) {
                    auto component_type = parameter_type;
                    if (slot.component_index) {
                        const auto elements = hfa_float_elements(parameter_type);
                        if (!elements || *slot.component_index >= elements->size()) continue;
                        component_type = (*elements)[*slot.component_index];
                    }
                    constrain_register(*slot.reg, component_type);
                    mapped[parameter_index] = true;
                } else if (slot.stack_offset) {
                    constrain_stack_slot(*slot.stack_offset, parameter_type);
                    mapped[parameter_index] = true;
                }
            }
            // Unsupported trailing parameters remain unconstrained here; the
            // ABI slot map reports the same boundary to interprocedural recovery.
        } else if (abi.name == "PowerPC64 ELFv2") {
            for (const auto &slot : ppc64_elfv2_prototype_slots(prototype)) {
                if (!slot.parameter_index || *slot.parameter_index >= parameters.size()) continue;
                const auto &parameter_type = parameters[*slot.parameter_index].type;
                if (!parameter_type) continue;
                if (slot.reg) constrain_register(*slot.reg, parameter_type);
                else if (slot.stack_offset) constrain_stack_slot(*slot.stack_offset, parameter_type);
            }
        } else if (abi.shared_integer_float_argument_positions) {
            for (std::size_t position = 0; position < parameters.size(); ++position) {
                const auto &param = parameters[position].type;
                const auto value_class = parameter_class(param);
                if (!value_class) break;
                const std::vector<RegisterOperand> *registers = nullptr;
                if (*value_class == AbiValueClass::integer) registers = &abi.integer_argument_registers;
                else if (*value_class == AbiValueClass::floating) registers = &abi.floating_argument_registers;
                else registers = &abi.vector_argument_registers;
                if (position >= registers->size()) break;
                constrain_register((*registers)[position], param);
            }
        } else {
            std::array<std::size_t, 3> next{};
            for (const auto &parameter : parameters) {
                const auto value_class = parameter_class(parameter.type);
                if (!value_class) break;
                const auto class_index = static_cast<std::size_t>(*value_class);
                const std::vector<RegisterOperand> *registers = nullptr;
                if (*value_class == AbiValueClass::integer) registers = &abi.integer_argument_registers;
                else if (*value_class == AbiValueClass::floating) registers = &abi.floating_argument_registers;
                else registers = &abi.vector_argument_registers;
                if (next[class_index] >= registers->size()) break;
                constrain_register((*registers)[next[class_index]++], parameter.type);
            }
        }
    } else {
        for (std::size_t n = 0; n < abi.integer_argument_registers.size(); ++n) {
            types::TypePtr param;
            if (abi.arguments.empty() && abi.name != "PowerPC64 ELFv2" &&
                n < parameter_constraints.size()) param = parameter_constraints[n];
            if (param) constrain_register(abi.integer_argument_registers[n], param);
        }
    }
    if (!prototype && !abi.arguments.empty()) {
        for (std::size_t n = 0; n < abi.arguments.size() && n < parameter_constraints.size(); ++n) {
            const auto &slot = abi.arguments[n];
            if (!slot.reg || !parameter_constraints[n]) continue;
            const auto &param = parameter_constraints[n];
            for (auto &[fact_key, fact] : facts) {
                (void)fact_key;
                if (fact.reg != *slot.reg || (fact.version && *fact.version != 0)) continue;
                fact.bits = type_bits(param) ? type_bits(param) : fact.bits;
                fact.sign = is_signed_type(param);
                fact.pointer = is_pointer_type(param);
                fact.floating = param->kind() == types::Kind::floating;
                fact.constrained = true;
                merge_exact_type(fact, param);
                if (param->kind() == types::Kind::vector) {
                    fact.vector_evidence = true;
                    fact.vector_type = param;
                }
            }
        }
        for (std::size_t n = 0; n < abi.arguments.size() && n < parameter_constraints.size(); ++n)
            if (abi.arguments[n].stack_offset && parameter_constraints[n])
                constrain_stack_slot(*abi.arguments[n].stack_offset, parameter_constraints[n]);
    }
    if (!abi.arguments.empty()) {
        for (std::size_t n = 0; n < abi.arguments.size() && n < parameters.size(); ++n) {
            const auto &slot = abi.arguments[n];
            const auto param = n < parameters.size() ? parameters[n].type :
                (!prototype && n < parameter_constraints.size() ? parameter_constraints[n] : types::TypePtr{});
            if (slot.value_class != AbiValueClass::vector || !slot.reg || !param ||
                param->kind() != types::Kind::vector) continue;
            for (auto &[fact_key, fact] : facts) {
                (void)fact_key;
                if (fact.reg != *slot.reg || (fact.version && *fact.version != 0)) continue;
                fact.bits = type_bits(param) ? type_bits(param) : fact.bits;
                fact.vector_evidence = true;
                fact.vector_type = param;
                fact.constrained = true;
                merge_exact_type(fact, param);
            }
        }
    } else {
        for (std::size_t n = 0; n < abi.vector_argument_registers.size() && n < parameters.size(); ++n) {
            const auto param = n < parameters.size() ? parameters[n].type :
                (!prototype && n < parameter_constraints.size() ? parameter_constraints[n] : types::TypePtr{});
            if (!param || param->kind() != types::Kind::vector) continue;
            for (auto &[fact_key, fact] : facts) {
                (void)fact_key;
                if (fact.reg != abi.vector_argument_registers[n] || (fact.version && *fact.version != 0)) continue;
                fact.bits = type_bits(param) ? type_bits(param) : fact.bits;
                fact.vector_evidence = true;
                fact.vector_type = param;
                fact.constrained = true;
                merge_exact_type(fact, param);
            }
        }
    }
    std::size_t call_layout_work = 0;
    bool call_layout_budget_exhausted = false;
    bool applied_call_pointee_layout = false;
    if (known_argument_types.size() <= 4096) {
        for (const auto &known : known_argument_types) {
            auto found = facts.find(key(known.value.reg, known.value.version));
            if (found == facts.end()) continue;
            auto &fact = found->second;
            if (fact.constrained || fact.exact_type || fact.exact_type_ambiguous || fact.sign ||
                fact.sign_ambiguous || fact.floating || fact.floating_ambiguous || fact.vector_evidence)
                continue;
            const auto argument_type = unqualified_type(known.type);
            const auto pointee_type = argument_type && argument_type->kind() == types::Kind::pointer
                ? unqualified_type(argument_type->element()) : types::TypePtr{};
            if (argument_type && argument_type->kind() != types::Kind::pointer &&
                (argument_type->kind() == types::Kind::boolean || argument_type->kind() == types::Kind::integer ||
                 argument_type->kind() == types::Kind::enumeration || argument_type->kind() == types::Kind::floating ||
                 argument_type->kind() == types::Kind::vector)) {
                fact.bits = type_bits(argument_type) ? type_bits(argument_type) : fact.bits;
                fact.sign = is_signed_type(argument_type);
                fact.floating = argument_type->kind() == types::Kind::floating;
                if (argument_type->kind() == types::Kind::vector) {
                    fact.vector_evidence = true;
                    fact.vector_type = argument_type;
                }
                merge_exact_type(fact, known.type);
                continue;
            }
            if (argument_type && argument_type->kind() == types::Kind::pointer &&
                (!pointee_type || pointee_type->kind() != types::Kind::structure)) {
                if (fact.object_fields.empty() && fact.pointer_fields.empty() && fact.nested_children.empty()) {
                    fact.pointer = true;
                    fact.bits = type_bits(argument_type) ? type_bits(argument_type) : known.value.reg.width;
                    merge_exact_type(fact, known.type);
                }
                continue;
            }
            const auto layout = observed_pointee_layout(known.type, abi.pointer_bits, call_layout_work);
            if (!layout || layout->fields.empty()) {
                call_layout_budget_exhausted = call_layout_budget_exhausted ||
                    call_layout_work >= aggregate_layout_work_limit;
                continue;
            }
            fact.pointer = true;
            fact.bits = abi.pointer_bits ? abi.pointer_bits : known.value.reg.width;
            applied_call_pointee_layout = merge_observed_layout(fact, *layout, call_layout_work) ||
                                          applied_call_pointee_layout;
            call_layout_budget_exhausted = call_layout_budget_exhausted ||
                call_layout_work >= aggregate_layout_work_limit;
        }
    } else {
        call_layout_budget_exhausted = true;
    }
    // Signed comparisons and signed/unsigned division constrain the
    // interpretation of direct register operands. Conflicting evidence leaves
    // the integer type unknown rather than choosing whichever use came last.
    std::map<Key, std::uint8_t> comparison_signedness;
    const auto collect_comparison_operand = [&](const ExpressionPtr &expression, std::uint8_t evidence) {
        if (!expression) return;
        if (const auto *value = std::get_if<RegisterValue>(&expression->value))
            comparison_signedness[key(value->reg, value->version)] |= evidence;
    };
    for (const auto &[operand, interpretation] : division_signedness)
        comparison_signedness[operand] |= !interpretation ? 3 : *interpretation ? 1 : 2;
    const auto collect_comparisons = [&](const ExpressionPtr &expression, auto &&self) -> void {
        if (!expression) return;
        if (const auto *binary = std::get_if<BinaryValue>(&expression->value)) {
            if (binary->operation == "slt") {
                collect_comparison_operand(binary->left, 1);
                collect_comparison_operand(binary->right, 1);
            } else if (binary->operation == "ult") {
                collect_comparison_operand(binary->left, 2);
                collect_comparison_operand(binary->right, 2);
            }
            self(binary->left, self);
            self(binary->right, self);
        } else if (const auto *unary = std::get_if<UnaryValue>(&expression->value)) {
            self(unary->operand, self);
        }
    };
    for (const auto &block : fn.blocks) {
        for (const auto &instruction : block.instructions) std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Assign>) collect_comparisons(statement.value, collect_comparisons);
            else if constexpr (std::is_same_v<T, Store>) {
                collect_comparisons(statement.address, collect_comparisons);
                collect_comparisons(statement.value, collect_comparisons);
            } else if constexpr (std::is_same_v<T, Call>) {
                collect_comparisons(statement.indirect_target, collect_comparisons);
            } else if constexpr (std::is_same_v<T, Return>) collect_comparisons(statement.value, collect_comparisons);
            else if constexpr (std::is_same_v<T, Branch>) {
                collect_comparisons(statement.predicate, collect_comparisons);
                collect_comparisons(statement.indirect_target, collect_comparisons);
            } else if constexpr (std::is_same_v<T, Intrinsic>) {
                for (const auto &operand : statement.operands) collect_comparisons(operand, collect_comparisons);
                for (const auto &output : statement.register_output_values) collect_comparisons(output, collect_comparisons);
            }
        }, instruction.statement);
        if (block.switch_dispatch)
            collect_comparisons(block.switch_dispatch->selector, collect_comparisons);
    }
    for (std::size_t pass = 0; pass <= facts.size(); ++pass) {
        bool changed = false;
        for (const auto &alias : pointer_aliases) {
            if (alias.displacement != 0 || std::get<0>(alias.source) != std::get<0>(alias.destination) ||
                std::get<2>(alias.source) != std::get<2>(alias.destination)) continue;
            auto &source = comparison_signedness[alias.source];
            auto &destination = comparison_signedness[alias.destination];
            const auto combined = static_cast<std::uint8_t>(source | destination);
            if (source != combined || destination != combined) {
                source = combined;
                destination = combined;
                changed = true;
            }
        }
        if (!changed) break;
    }
    for (const auto &[fact_key, evidence] : comparison_signedness) {
        const auto fact = facts.find(fact_key);
        if (fact == facts.end() || fact->second.constrained || fact->second.exact_type) continue;
        if (evidence == 3) {
            fact->second.sign = false;
            fact->second.sign_ambiguous = true;
        } else if (evidence == 1) {
            fact->second.sign = true;
        }
    }

    // Carry type facts over SSA assignments to a fixed point. Signed extension
    // and arithmetic shifts also provide signedness evidence; address
    // expressions and pointer-plus-constant provide pointer evidence.
    auto infer_expr=[&](const ExpressionPtr &e, auto &&self)->Fact {
        Fact out{}; if(!e) return out; out.bits=e->type.bits;
        out.floating = e->type.kind == TypeKind::floating;
        if (e->type.kind == TypeKind::vector) {
            out.vector_evidence = true;
            out.vector_type = vector_type_from_value(e->type);
        }
        std::visit([&](const auto &x) {
            using T=std::decay_t<decltype(x)>;
            if constexpr(std::is_same_v<T,RegisterValue>) { auto it=facts.find(key(x.reg,x.version)); if(it!=facts.end()) { out.bits=it->second.bits; out.sign=it->second.sign; out.sign_ambiguous=it->second.sign_ambiguous; out.pointer=it->second.pointer; out.floating = out.floating || it->second.floating; out.floating_ambiguous = it->second.floating_ambiguous; out.object_fields=it->second.object_fields; out.object_layout_ambiguous=it->second.object_layout_ambiguous; out.pointer_fields=it->second.pointer_fields; out.indexed_element_bits=it->second.indexed_element_bits; out.indexed_element_ambiguous=it->second.indexed_element_ambiguous; if (it->second.exact_type) merge_exact_type(out, it->second.exact_type); if (it->second.exact_type_ambiguous) out.exact_type_ambiguous = true; if (it->second.vector_evidence) merge_vector_fact(out, it->second); } }
            else if constexpr(std::is_same_v<T,MemoryValue>) { out.bits=x.type.bits; out.floating=x.type.kind==TypeKind::floating; }
            else if constexpr(std::is_same_v<T,UnaryValue>) { out=self(x.operand,self); if(x.operation=="sext") { out.sign=true; out.sign_ambiguous=false; } if(x.operation=="zext") { out.sign=false; out.sign_ambiguous=false; } }
            else if constexpr(std::is_same_v<T,BinaryValue>) {
                if (e->type.kind == TypeKind::boolean) {
                    out.sign = false;
                    out.sign_ambiguous = false;
                } else {
                    auto l=self(x.left,self),r=self(x.right,self); out.bits=std::max(l.bits,r.bits); out.sign=l.sign||r.sign;
                    out.sign_ambiguous = l.sign_ambiguous || r.sign_ambiguous;
                    out.pointer=(x.operation=="lea") || ((x.operation=="add"||x.operation=="sub") && (l.pointer||r.pointer));
                    if(x.operation=="sar") { out.sign=true; out.sign_ambiguous=false; }
                    if(x.operation=="shr") { out.sign=false; out.sign_ambiguous=false; }
                }
            }
        },e->value);
        if (e->type.kind == TypeKind::floating && !out.floating_ambiguous) out.floating = true;
        return out;
    };
    bool changed=true; for(unsigned pass=0;changed && pass<facts.size()+1;++pass) {
        changed=false;
        for(const auto &b:fn.blocks) for(const auto &i:b.instructions) if(const auto *s=std::get_if<Assign>(&i.statement)) {
            auto &dst=ensure(s->destination,s->destination_version); auto src=infer_expr(s->value,infer_expr);
            if(!dst.constrained) {
                const auto merged_bits=std::max(dst.bits,src.bits);
                if(merged_bits!=dst.bits) {dst.bits=merged_bits;changed=true;}
                if(src.sign_ambiguous && !dst.sign_ambiguous) { dst.sign=false; dst.sign_ambiguous=true; changed=true; }
                if(src.sign&&!dst.sign&&!dst.sign_ambiguous) {dst.sign=true;changed=true;}
                if(src.pointer&&!dst.pointer) {dst.pointer=true;changed=true;}
                if (src.floating && !dst.floating && !dst.floating_ambiguous) { dst.floating=true; changed=true; }
                if (src.floating_ambiguous && !dst.floating_ambiguous) { dst.floating=false; dst.floating_ambiguous=true; changed=true; }
                if (merge_exact_type(dst, src.exact_type)) changed = true;
                if (src.exact_type_ambiguous && !dst.exact_type_ambiguous) {
                    dst.exact_type.reset(); dst.exact_type_ambiguous = true; changed = true;
                }
                if (merge_vector_fact(dst, src)) changed = true;
                if (src.object_layout_ambiguous && !dst.object_layout_ambiguous) {
                    dst.object_layout_ambiguous = true;
                    changed = true;
                }
                for (const auto &[offset, bits] : src.object_fields) {
                    if (dst.object_layout_ambiguous) break;
                    auto &width = dst.object_fields[offset];
                    if (width && width != bits) {
                        dst.object_layout_ambiguous = true;
                        changed = true;
                        break;
                    }
                    const auto merged = std::max(width, bits);
                    if (width != merged) { width=merged; changed=true; }
                }
                if (src.indexed_element_ambiguous && !dst.indexed_element_ambiguous) {
                    dst.indexed_element_bits.reset(); dst.indexed_element_ambiguous = true; changed = true;
                } else if (src.indexed_element_bits && !dst.indexed_element_bits && !dst.indexed_element_ambiguous) {
                    dst.indexed_element_bits = src.indexed_element_bits;
                    changed = true;
                }
            }
        }
        for(const auto &b:fn.blocks) for(const auto &p:b.phis) {
            auto &dst=ensure(p.destination,p.version);
            if(dst.constrained) continue;
            bool all_pointer_inputs = !p.inputs.empty();
            bool any_vector_input = false;
            bool all_vector_inputs = !p.inputs.empty();
            bool conflicting_vector_inputs = false;
            bool any_floating_input = false;
            bool all_floating_inputs = !p.inputs.empty();
            types::TypePtr common_vector_type;
            types::TypePtr common_exact_type;
            bool all_exact_inputs = !p.inputs.empty();
            bool conflicting_exact_inputs = false;
            for(auto in:p.inputs) {
                auto it=facts.find(key(p.destination,in.version));
                if(it==facts.end()) { all_pointer_inputs=false; all_vector_inputs=false; all_exact_inputs=false; continue; }
                if(it->second.sign_ambiguous && !dst.sign_ambiguous) { dst.sign=false; dst.sign_ambiguous=true; changed=true; }
                if(it->second.sign&&!dst.sign&&!dst.sign_ambiguous){dst.sign=true;changed=true;}
                const auto merged_bits=std::max(dst.bits,it->second.bits);
                if(merged_bits!=dst.bits) {dst.bits=merged_bits;changed=true;}
                all_pointer_inputs = all_pointer_inputs && it->second.pointer;
                any_floating_input = any_floating_input || it->second.floating;
                all_floating_inputs = all_floating_inputs && it->second.floating && !it->second.floating_ambiguous;
                any_vector_input = any_vector_input || it->second.vector_evidence;
                all_vector_inputs = all_vector_inputs && it->second.vector_evidence;
                all_exact_inputs = all_exact_inputs && static_cast<bool>(it->second.exact_type) &&
                                   !it->second.exact_type_ambiguous;
                if (it->second.exact_type_ambiguous) conflicting_exact_inputs = true;
                if (it->second.exact_type) {
                    if (common_exact_type && common_exact_type->id() != it->second.exact_type->id())
                        conflicting_exact_inputs = true;
                    else common_exact_type = it->second.exact_type;
                }
                if (it->second.vector_evidence) {
                    conflicting_vector_inputs = conflicting_vector_inputs || it->second.vector_ambiguous;
                    if (it->second.vector_type) {
                        if (common_vector_type && common_vector_type->id() != it->second.vector_type->id())
                            conflicting_vector_inputs = true;
                        else common_vector_type = it->second.vector_type;
                    }
                }
            }
            if (all_exact_inputs && !conflicting_exact_inputs) {
                if (merge_exact_type(dst, common_exact_type)) changed = true;
            } else if (conflicting_exact_inputs && !dst.exact_type_ambiguous) {
                dst.exact_type.reset(); dst.exact_type_ambiguous = true; changed = true;
            }
            // A pointer on one incoming edge is not sufficient evidence for a
            // pointer-valued phi. This keeps mixed integer/pointer joins
            // conservative while still propagating pointer facts when every
            // incoming SSA value is known to be a pointer.
            if (all_pointer_inputs) {
                if (!dst.pointer) { dst.pointer=true; changed=true; }
                for (auto in:p.inputs) {
                    const auto it=facts.find(key(p.destination,in.version));
                    if (it==facts.end()) continue;
                    if (it->second.object_layout_ambiguous && !dst.object_layout_ambiguous) {
                        dst.object_layout_ambiguous = true;
                        changed = true;
                    }
                    for (const auto &[offset, bits] : it->second.object_fields) {
                        if (dst.object_layout_ambiguous) break;
                        auto &width=dst.object_fields[offset];
                        if (width && width != bits) {
                            dst.object_layout_ambiguous = true;
                            changed = true;
                            break;
                        }
                        const auto merged=std::max(width,bits);
                        if(width!=merged) { width=merged; changed=true; }
                    }
                }
            }
            if (any_floating_input) {
                if (!all_floating_inputs) {
                    if (!dst.floating_ambiguous || dst.floating) {
                        dst.floating=false; dst.floating_ambiguous=true; changed=true;
                    }
                } else if (!dst.floating && !dst.floating_ambiguous) { dst.floating=true; changed=true; }
            }
            if (any_vector_input) {
                Fact vector_fact;
                vector_fact.vector_evidence = true;
                vector_fact.vector_type = all_vector_inputs && !conflicting_vector_inputs ? common_vector_type : nullptr;
                vector_fact.vector_ambiguous = !all_vector_inputs || conflicting_vector_inputs;
                if (merge_vector_fact(dst, vector_fact)) changed = true;
            }
        }
        for (const auto &alias : pointer_aliases) {
            auto source=facts.find(alias.source), destination=facts.find(alias.destination);
            if (source==facts.end() || destination==facts.end()) continue;
            if (source->second.pointer && !destination->second.pointer) {
                destination->second.pointer=true;
                changed=true;
            }
            if (destination->second.pointer && !source->second.pointer) {
                source->second.pointer=true;
                changed=true;
            }
            if (source->second.object_layout_ambiguous && !destination->second.object_layout_ambiguous) {
                destination->second.object_layout_ambiguous = true;
                changed = true;
            }
            if (destination->second.object_layout_ambiguous && !source->second.object_layout_ambiguous) {
                source->second.object_layout_ambiguous = true;
                changed = true;
            }
            auto merge_fields=[&](const Fact &from, Fact &to, std::int64_t delta) {
                if (to.object_layout_ambiguous) return;
                for (const auto &[offset,bits] : from.object_fields) {
                    const auto shifted=shifted_field(offset,delta);
                    if (!shifted) continue;
                    auto &width=to.object_fields[*shifted];
                    if (width && width != bits) {
                        to.object_layout_ambiguous = true;
                        changed = true;
                        return;
                    }
                    const auto merged=std::max(width,bits);
                    if (width!=merged) { width=merged; changed=true; }
                }
            };
            // A field at source+N appears at destination+(N-displacement).
            if (alias.displacement != std::numeric_limits<std::int64_t>::min())
                merge_fields(source->second,destination->second,-alias.displacement);
            merge_fields(destination->second,source->second,alias.displacement);
        }
    }
    const bool pointer_layout_nonconvergent = changed;
    if (pointer_layout_nonconvergent) {
        // A non-zero displacement around an alias cycle can keep generating
        // translated field offsets. The fixed-point pass is bounded by the
        // number of SSA facts; if it does not settle, discard aggregate layout
        // evidence rather than publishing a partial, cycle-dependent struct.
        for (auto &[fact_key, fact] : facts) {
            (void)fact_key;
            fact.object_fields.clear();
        }
    }
    if (!pointer_layout_nonconvergent) {
        const auto mark_pointer_field = [&](const MemoryValue &memory, bool pointer_value,
                                            std::uint16_t value_bits) {
            const auto pointer_width = abi.pointer_bits ? abi.pointer_bits : value_bits;
            if (!pointer_value || !memory.base || memory.index || memory.absolute || memory.displacement < 0 ||
                !memory.type.bits || memory.type.bits % 8 ||
                !pointer_width || memory.type.bits != pointer_width) return false;
            const auto base = facts.find(key(*memory.base, memory.base_version));
            if (base == facts.end() || !base->second.pointer) return false;
            const auto offset = static_cast<std::uint64_t>(memory.displacement);
            if (offset > (1u << 20) || !base->second.object_fields.contains(offset)) return false;
            return base->second.pointer_fields.insert(offset).second;
        };
        for (const auto &block : fn.blocks) for (const auto &instruction : block.instructions) {
            std::visit([&](const auto &statement) {
                using T = std::decay_t<decltype(statement)>;
                if constexpr (std::is_same_v<T, Assign>) {
                    const auto destination = facts.find(key(statement.destination, statement.destination_version));
                    if (destination == facts.end() || !destination->second.pointer || !statement.value) return;
                    if (const auto *memory = std::get_if<MemoryValue>(&statement.value->value))
                        (void)mark_pointer_field(*memory, true, destination->second.bits);
                } else if constexpr (std::is_same_v<T, Store>) {
                    const auto *address = statement.address ? std::get_if<MemoryValue>(&statement.address->value) : nullptr;
                    if (address) {
                        const auto value = infer_expr(statement.value, infer_expr);
                        (void)mark_pointer_field(*address, value.pointer, value.bits);
                    }
                }
            }, instruction.statement);
        }
        bool fields_changed = true;
        for (std::size_t pass = 0; fields_changed && pass <= facts.size(); ++pass) {
            fields_changed = false;
            for (const auto &alias : pointer_aliases) {
                const auto source = facts.find(alias.source), destination = facts.find(alias.destination);
                if (source == facts.end() || destination == facts.end()) continue;
                const auto transfer = [&](const Fact &from, Fact &to, std::int64_t displacement) {
                    for (const auto offset : from.pointer_fields) {
                        const auto shifted = shifted_field(offset, displacement);
                        if (shifted && to.object_fields.contains(*shifted) && to.pointer_fields.insert(*shifted).second)
                            fields_changed = true;
                    }
                };
                if (alias.displacement != std::numeric_limits<std::int64_t>::min())
                    transfer(source->second, destination->second, -alias.displacement);
                transfer(destination->second, source->second, alias.displacement);
            }
        }
        if (fields_changed)
            for (auto &[fact_key, fact] : facts) { (void)fact_key; fact.pointer_fields.clear(); }
    }
    // Associate pointer-valued member loads with the SSA facts that are later
    // dereferenced. Layouts are materialized recursively below, after all such
    // relationships are collected, so traversal order cannot select a shape.
    constexpr std::size_t nested_layout_work_limit = aggregate_layout_work_limit;
    std::size_t nested_layout_work = 0;
    if (!pointer_layout_nonconvergent) {
        bool observation_limit = false;
        for (const auto &block : fn.blocks) {
            for (const auto &instruction : block.instructions) {
                if (++nested_layout_work > nested_layout_work_limit) {
                    observation_limit = true;
                    break;
                }
                const auto *assignment = std::get_if<Assign>(&instruction.statement);
                if (!assignment || !assignment->value) continue;
                const auto *memory = std::get_if<MemoryValue>(&assignment->value->value);
                if (!memory || !memory->base || memory->index || memory->absolute || memory->displacement < 0) continue;
                const auto parent = facts.find(key(*memory->base, memory->base_version));
                const auto child = facts.find(key(assignment->destination, assignment->destination_version));
                if (parent == facts.end() || child == facts.end() || !parent->second.pointer || !child->second.pointer) continue;
                const auto offset = static_cast<std::uint64_t>(memory->displacement);
                if (parent->second.pointer_fields.contains(offset))
                    parent->second.nested_children[offset].insert(key(assignment->destination,
                                                                        assignment->destination_version));
            }
            if (observation_limit) break;
        }
        if (observation_limit) {
            for (auto &[fact_key, fact] : facts) {
                (void)fact_key;
                fact.nested_children.clear();
                fact.nested_fields_ambiguous.insert(fact.pointer_fields.begin(), fact.pointer_fields.end());
            }
        }
    }
    if (!pointer_layout_nonconvergent) {
        constexpr unsigned max_nested_levels = 5; // root fact plus four nested pointee layouts
        using LayoutKey = std::pair<Key, unsigned>;
        std::map<LayoutKey, std::shared_ptr<const AggregateLayout>> cache;
        std::set<Key> active;
        std::function<std::shared_ptr<const AggregateLayout>(const Key &, unsigned, bool &)> build_layout;
        build_layout = [&](const Key &fact_key, unsigned depth, bool &complete)
            -> std::shared_ptr<const AggregateLayout> {
            if (depth >= max_nested_levels || nested_layout_work >= nested_layout_work_limit) {
                complete = false;
                return {};
            }
            const LayoutKey layout_key{fact_key, depth};
            if (const auto found = cache.find(layout_key); found != cache.end()) return found->second;
            if (!active.insert(fact_key).second) {
                complete = false;
                return {};
            }
            ++nested_layout_work;
            const auto fact = facts.find(fact_key);
            if (fact == facts.end() || !fact->second.pointer || fact->second.object_layout_ambiguous ||
                fact->second.object_fields.empty()) {
                active.erase(fact_key);
                return {};
            }
            auto layout = std::make_shared<AggregateLayout>();
            const auto remaining = nested_layout_work_limit - nested_layout_work;
            if (fact->second.object_fields.size() > remaining ||
                fact->second.pointer_fields.size() > remaining - fact->second.object_fields.size()) {
                complete = false;
                active.erase(fact_key);
                return {};
            }
            nested_layout_work += fact->second.object_fields.size() + fact->second.pointer_fields.size();
            layout->fields = fact->second.object_fields;
            layout->pointer_fields = fact->second.pointer_fields;
            for (const auto &[offset, children] : fact->second.nested_children) {
                if (nested_layout_work >= nested_layout_work_limit) {
                    complete = false;
                    break;
                }
                ++nested_layout_work;
                if (!layout->pointer_fields.contains(offset)) continue;
                std::shared_ptr<const AggregateLayout> selected;
                bool conflict = children.empty();
                for (const auto &child : children) {
                    if (nested_layout_work >= nested_layout_work_limit) {
                        complete = false;
                        conflict = true;
                        break;
                    }
                    ++nested_layout_work;
                    bool child_complete = true;
                    const auto candidate = build_layout(child, depth + 1, child_complete);
                    complete = complete && child_complete;
                    if (!candidate) {
                        conflict = true;
                        continue;
                    }
                    if (!selected) selected = candidate;
                    else if (!equal_layout(*selected, *candidate, nested_layout_work, complete)) conflict = true;
                }
                if (conflict || !selected) layout->nested_fields_ambiguous.insert(offset);
                else layout->nested_fields.emplace(offset, std::move(selected));
            }
            active.erase(fact_key);
            if (complete) cache.emplace(layout_key, layout);
            return layout;
        };
        for (auto &[fact_key, fact] : facts) {
            if (nested_layout_work >= nested_layout_work_limit) break;
            ++nested_layout_work;
            if (!fact.pointer || fact.object_fields.empty()) continue;
            bool complete = true;
            const auto layout = build_layout(fact_key, 0, complete);
            if (layout) {
                auto seeded_nested_fields = std::move(fact.nested_fields);
                auto seeded_nested_ambiguous = std::move(fact.nested_fields_ambiguous);
                fact.nested_fields = layout->nested_fields;
                fact.nested_fields_ambiguous = layout->nested_fields_ambiguous;
                for (const auto offset : seeded_nested_ambiguous) {
                    fact.nested_fields.erase(offset);
                    fact.nested_fields_ambiguous.insert(offset);
                }
                for (const auto &[offset, nested] : seeded_nested_fields) {
                    if (!nested || fact.nested_fields_ambiguous.contains(offset)) continue;
                    const auto existing = fact.nested_fields.find(offset);
                    if (existing == fact.nested_fields.end()) {
                        fact.nested_fields.emplace(offset, nested);
                    } else {
                        bool equal_complete = true;
                        if (!equal_layout(*existing->second, *nested, nested_layout_work, equal_complete) ||
                            !equal_complete) {
                            fact.nested_fields.erase(existing);
                            fact.nested_fields_ambiguous.insert(offset);
                        }
                    }
                }
            }
        }
    }
    TypeRecoveryResult result;
    if (pointer_layout_nonconvergent)
        result.diagnostics.push_back("pointer alias field propagation did not converge; aggregate layouts suppressed");
    if (applied_call_pointee_layout)
        result.diagnostics.push_back("bounded pointee field evidence from compatible direct callees was applied to caller values");
    if (call_layout_budget_exhausted)
        result.diagnostics.push_back("direct-call pointee layout propagation reached its work limit; remaining caller layouts were left unchanged");
    auto parameter_index = [&](const Fact &fact) -> std::optional<std::size_t> {
        if (!fact.constrained && !parameter_evidence.contains(key(fact.reg, fact.version))) return {};
        if (!fact.version || *fact.version != 0) return {};
        if (prototype) {
            if (abi.name == "AArch64 AAPCS64") {
                for (const auto &slot : aapcs64_prototype_slots(prototype))
                    if (slot.reg && *slot.reg == fact.reg && slot.parameter_index)
                        return static_cast<std::size_t>(*slot.parameter_index);
            } else if (abi.name == "x86-64 System V") {
                for (const auto &slot : sysv64_prototype_slots(prototype))
                    if (slot.reg && slot.reg->bank == fact.reg.bank &&
                        slot.reg->index == fact.reg.index && slot.reg->high_byte == fact.reg.high_byte &&
                        (slot.reg->bank == RegisterBank::gpr || slot.reg->width == fact.reg.width) &&
                        slot.parameter_index)
                        return static_cast<std::size_t>(*slot.parameter_index);
            } else if (abi.shared_integer_float_argument_positions) {
                for (std::size_t position = 0; position < parameters.size(); ++position) {
                    const auto value_class = parameter_class(parameters[position].type);
                    if (!value_class) break;
                    const std::vector<RegisterOperand> *registers = *value_class == AbiValueClass::integer
                        ? &abi.integer_argument_registers
                        : *value_class == AbiValueClass::floating ? &abi.floating_argument_registers
                                                                  : &abi.vector_argument_registers;
                    if (position >= registers->size()) break;
                    if ((*registers)[position] == fact.reg) return position;
                }
            } else {
                std::array<std::size_t, 3> next{};
                for (std::size_t position = 0; position < parameters.size(); ++position) {
                    const auto value_class = parameter_class(parameters[position].type);
                    if (!value_class) break;
                    const auto class_index = static_cast<std::size_t>(*value_class);
                    const std::vector<RegisterOperand> *registers = *value_class == AbiValueClass::integer
                        ? &abi.integer_argument_registers
                        : *value_class == AbiValueClass::floating ? &abi.floating_argument_registers
                                                                  : &abi.vector_argument_registers;
                    if (next[class_index] >= registers->size()) break;
                    if ((*registers)[next[class_index]] == fact.reg) return position;
                    ++next[class_index];
                }
            }
            return {};
        }
        if (abi.name == "AArch64 AAPCS64") {
            std::size_t integer_position = 0, floating_position = 0;
            for (const auto &slot : abi.arguments) {
                if (slot.reg && *slot.reg == fact.reg)
                    return slot.value_class == AbiValueClass::integer ? integer_position : floating_position;
                if (slot.value_class == AbiValueClass::integer) ++integer_position;
                else if (slot.value_class == AbiValueClass::floating) ++floating_position;
            }
        } else if (!abi.arguments.empty()) {
            for (std::size_t n = 0; n < abi.arguments.size(); ++n)
                if (abi.arguments[n].reg && *abi.arguments[n].reg == fact.reg) return n;
        } else {
            for (std::size_t n = 0; n < abi.integer_argument_registers.size(); ++n)
                if (abi.integer_argument_registers[n] == fact.reg) return n;
        }
        return {};
    };
    for(const auto &[k,f]:facts) {
        (void)k;
        const auto parameter = parameter_index(f);
        std::string name;
        if (parameter) name = "arg" + std::to_string(*parameter);
        else {
            name = "value_r" + std::to_string(static_cast<unsigned>(f.reg.bank)) + "_" +
                   std::to_string(f.reg.index);
            if (f.version) name += "_" + std::to_string(*f.version);
        }
        result.variables.push_back({f.reg,f.version,make_type(f,abi.pointer_bits,nested_layout_work),f.constrained,
                                    std::move(name),parameter,
                                    f.constrained || parameter_evidence.contains(key(f.reg, f.version))});
    }
    if (auto named = recover_stack_variables(fn)) {
        std::map<std::string, RecoveredStackVariable> locals;
        std::map<std::string, Fact> local_facts;
        std::map<std::string, std::pair<bool, bool>> local_float_kinds;
        std::map<std::string, std::set<Key>> loaded_pointer_values;
        std::map<std::string, bool> stack_store_pointer_class;
        std::set<std::string> conflicting_local_layouts;
        std::set<std::string> mixed_stack_store_classes;
        std::set<std::string> stack_pointer_stores;
        const auto merge_pointer_evidence = [&](const std::string &name, Fact &destination, const Fact &source) {
            if (!source.pointer) return;
            destination.pointer = true;
            if (source.object_layout_ambiguous) destination.object_layout_ambiguous = true;
            for (const auto &[offset, bits] : source.object_fields) {
                auto [field, inserted] = destination.object_fields.emplace(offset, bits);
                if (!inserted && field->second != bits) conflicting_local_layouts.insert(name);
            }
            for (const auto offset : source.pointer_fields) {
                if (destination.object_fields.contains(offset) && source.object_fields.contains(offset))
                    destination.pointer_fields.insert(offset);
            }
            if (source.indexed_element_ambiguous) {
                destination.indexed_element_bits.reset();
                destination.indexed_element_ambiguous = true;
            } else if (source.indexed_element_bits && !destination.indexed_element_ambiguous) {
                if (destination.indexed_element_bits && destination.indexed_element_bits != source.indexed_element_bits) {
                    destination.indexed_element_bits.reset();
                    destination.indexed_element_ambiguous = true;
                } else destination.indexed_element_bits = source.indexed_element_bits;
            }
        };
        const auto collect = [&](const ExpressionPtr &expression, auto &&self) -> void {
            if (!expression) return;
            std::visit([&](const auto &value) {
                using T = std::decay_t<decltype(value)>;
                if constexpr (std::is_same_v<T, MemoryValue>) {
                    if (!value.stack_variable || !value.stack_frame_register || !value.stack_frame_offset ||
                        !value.type.bits || value.type.bits % 8) return;
                    const auto bytes = static_cast<std::uint64_t>(value.type.bits / 8);
                    const auto alignment = std::max<std::uint64_t>(1, std::min<std::uint64_t>(8, std::bit_floor(bytes)));
                    Fact observed;
                    observed.bits = value.type.bits;
                    observed.sign = value.type.is_signed;
                    observed.floating = value.type.kind == TypeKind::floating;
                    if (value.type.kind == TypeKind::vector) {
                        observed.vector_evidence = true;
                        observed.vector_type = vector_type_from_value(value.type);
                    }
                    types::TypePtr recovered_type;
                    if (observed.vector_evidence) recovered_type = make_type(observed, abi.pointer_bits, nested_layout_work);
                    else {
                        auto type = types::Type::integer("local", bytes, alignment, value.type.is_signed);
                        if (!type) return;
                        recovered_type = type.value();
                    }
                    RecoveredStackVariable local{*value.stack_variable, *value.stack_frame_register,
                                                 value.stack_frame_version, *value.stack_frame_offset,
                                                 value.type.bits, recovered_type};
                    auto local_name = local.name;
                    locals.try_emplace(std::move(local_name), std::move(local));
                    Fact initial_local;
                    initial_local.bits = value.type.bits;
                    initial_local.sign = value.type.is_signed;
                    auto [fact, inserted] = local_facts.try_emplace(*value.stack_variable, std::move(initial_local));
                    if (value.type.kind == TypeKind::floating) local_float_kinds[*value.stack_variable].first = true;
                    else if (value.type.kind == TypeKind::integer) local_float_kinds[*value.stack_variable].second = true;
                    merge_vector_fact(fact->second, observed);
                    if (observed.floating) {
                        if (fact->second.bits == value.type.bits && fact->second.bits &&
                            (fact->second.sign || fact->second.pointer || fact->second.vector_evidence))
                            fact->second.floating_ambiguous = true;
                        else if (!fact->second.floating_ambiguous)
                            fact->second.floating = true;
                    } else if (value.type.kind == TypeKind::integer && fact->second.floating &&
                               fact->second.bits == value.type.bits) {
                        fact->second.floating = false;
                        fact->second.floating_ambiguous = true;
                    }
                    if (!inserted && fact->second.bits == value.type.bits)
                        fact->second.sign = fact->second.sign || value.type.is_signed;
                } else if constexpr (std::is_same_v<T, UnaryValue>) self(value.operand, self);
                else if constexpr (std::is_same_v<T, BinaryValue>) {
                    self(value.left, self); self(value.right, self);
                }
            }, expression->value);
        };
        for (const auto &block : named.value().blocks) for (const auto &instruction : block.instructions)
            std::visit([&](const auto &statement) {
                using T = std::decay_t<decltype(statement)>;
                if constexpr (std::is_same_v<T, Assign>) {
                    collect(statement.value, collect);
                    const auto *slot = statement.value ? std::get_if<MemoryValue>(&statement.value->value) : nullptr;
                    if (slot && slot->stack_variable)
                        loaded_pointer_values[*slot->stack_variable].insert(key(statement.destination, statement.destination_version));
                }
                else if constexpr (std::is_same_v<T, Store>) {
                    collect(statement.address, collect); collect(statement.value, collect);
                    const auto *address = statement.address ? std::get_if<MemoryValue>(&statement.address->value) : nullptr;
                    if (address && address->stack_variable) {
                        auto fact = local_facts.find(*address->stack_variable);
                        if (fact != local_facts.end()) {
                            const auto stored = infer_expr(statement.value, infer_expr);
                            if (stored.bits == address->type.bits && stored.floating)
                                local_float_kinds[*address->stack_variable].first = true;
                            else if (stored.bits == address->type.bits && stored.bits)
                                local_float_kinds[*address->stack_variable].second = true;
                            const auto pointer_bits = abi.pointer_bits ? abi.pointer_bits : address->type.bits;
                            if (address->type.bits && address->type.bits == pointer_bits && stored.bits == pointer_bits) {
                                if (stored.pointer) stack_pointer_stores.insert(*address->stack_variable);
                                auto [slot_class, inserted] = stack_store_pointer_class.emplace(
                                    *address->stack_variable, stored.pointer);
                                if (!inserted && slot_class->second != stored.pointer)
                                    mixed_stack_store_classes.insert(*address->stack_variable);
                            }
                            merge_pointer_evidence(*address->stack_variable, fact->second, stored);
                            // A spill is also a provenance edge for exact ABI or
                            // prototype types. Keep it on the recovered slot so
                            // a reload in another block does not degrade, for
                            // example, `Node *` to an untyped byte pointer.
                            // merge_exact_type deliberately drops conflicting
                            // evidence rather than choosing whichever store was
                            // visited last.
                            if (stored.exact_type)
                                merge_exact_type(fact->second, stored.exact_type);
                            if (stored.exact_type_ambiguous && !fact->second.exact_type_ambiguous) {
                                fact->second.exact_type.reset();
                                fact->second.exact_type_ambiguous = true;
                            }
                            if (stored.floating && address->type.bits == stored.bits) {
                                if (fact->second.pointer || fact->second.sign || fact->second.vector_evidence)
                                    fact->second.floating_ambiguous = true;
                                else if (!fact->second.floating_ambiguous)
                                    fact->second.floating = true;
                            } else if (stored.bits && address->type.bits == stored.bits &&
                                       fact->second.floating && !stored.floating) {
                                fact->second.floating = false;
                                fact->second.floating_ambiguous = true;
                            }
                            if (stored.sign) fact->second.sign = true;
                            merge_vector_fact(fact->second, stored);
                            if (!fact->second.bits) fact->second.bits = stored.bits;
                        }
                    }
                }
                else if constexpr (std::is_same_v<T, Call>) collect(statement.indirect_target, collect);
                else if constexpr (std::is_same_v<T, Branch>) {
                    collect(statement.predicate, collect);
                    collect(statement.indirect_target, collect);
                }
                else if constexpr (std::is_same_v<T, Return>) collect(statement.value, collect);
                else if constexpr (std::is_same_v<T, Intrinsic>) {
                    for (const auto &operand : statement.operands) collect(operand, collect);
                    for (const auto &output : statement.register_output_values) collect(output, collect);
                }
            }, instruction.statement);
        // A pointer spilled to a stack slot and later reloaded has the same
        // pointee evidence as the register values that observed its accesses.
        // Require every observed reload to be pointer-classified before using
        // register-side layout facts for this stack variable.
        for (const auto &[name, loaded] : loaded_pointer_values) {
            auto local = local_facts.find(name);
            if (local == local_facts.end() || loaded.empty()) continue;
            bool all_pointer = true;
            bool saw_fact = false;
            std::vector<Fact> pointer_facts;
            for (const auto &register_key : loaded) {
                const auto value = facts.find(register_key);
                if (value == facts.end()) { all_pointer = false; continue; }
                saw_fact = true;
                if (!value->second.pointer) { all_pointer = false; continue; }
                pointer_facts.push_back(value->second);
            }
            const bool spilled_pointer = stack_store_pointer_class.contains(name) &&
                stack_store_pointer_class.at(name) && !mixed_stack_store_classes.contains(name);
            const bool all_reloads_pointer = all_pointer && saw_fact;
            if (all_reloads_pointer)
                for (const auto &pointer_fact : pointer_facts)
                    merge_pointer_evidence(name, local->second, pointer_fact);
            if (spilled_pointer) {
                // A full-width pointer store gives subsequent stack loads the
                // stored value's semantics, even when the reload itself has
                // not yet been dereferenced in the current function.
                local->second.pointer = true;
                for (const auto &register_key : loaded) {
                    auto value = facts.find(register_key);
                    if (value == facts.end()) continue;
                    value->second.pointer = true;
                    merge_pointer_evidence(name, value->second, local->second);
                }
            } else if (!all_reloads_pointer && !stack_pointer_stores.contains(name)) {
                // A mixed integer/pointer stack slot is not a reliable object
                // type even if one reload happened to be used as an address.
                local->second.pointer = false;
                local->second.object_fields.clear();
                local->second.pointer_fields.clear();
                local->second.indexed_element_bits.reset();
                local->second.indexed_element_ambiguous = true;
            }
        }
        for (const auto &name : mixed_stack_store_classes) {
            if (auto local = local_facts.find(name); local != local_facts.end()) {
                local->second.pointer = false;
                local->second.object_fields.clear();
                local->second.pointer_fields.clear();
                local->second.indexed_element_bits.reset();
                local->second.indexed_element_ambiguous = true;
            }
        }
        for (const auto &name : conflicting_local_layouts) {
            if (auto local = local_facts.find(name); local != local_facts.end()) {
                local->second.object_fields.clear();
                local->second.pointer_fields.clear();
                local->second.indexed_element_bits.reset();
                local->second.indexed_element_ambiguous = true;
            }
        }
        for (const auto &[name, kinds] : local_float_kinds) {
            if (kinds.first && kinds.second) {
                if (auto local = local_facts.find(name); local != local_facts.end()) {
                    local->second.floating = false;
                    local->second.floating_ambiguous = true;
                }
            }
        }
        for (auto &[name, local] : locals) {
            const auto fact = local_facts.find(name);
            if (fact != local_facts.end()) {
                auto type = make_type(fact->second, abi.pointer_bits, nested_layout_work);
                const auto exact_bits = type_bits(fact->second.exact_type);
                if (!fact->second.exact_type_ambiguous && fact->second.exact_type &&
                    exact_bits && (!fact->second.bits || exact_bits == fact->second.bits))
                    type = fact->second.exact_type;
                if (type) {
                    local.type = std::move(type);
                    if (local.type->kind() == types::Kind::integer && local.type->size()) {
                        const auto bits = *local.type->size() * 8;
                        auto named_type = types::Type::integer(
                            std::string(local.type->is_signed() ? "i" : "u") + std::to_string(bits),
                            *local.type->size(), local.type->alignment(), local.type->is_signed());
                        if (named_type) local.type = std::move(named_type.value());
                    }
                }
            }
            result.stack_variables.push_back(std::move(local));
        }
    }
    bool has_bare_return = false;
    bool has_value_return = false;
    for (const auto &b : fn.blocks) for (const auto &i : b.instructions) {
        if (const auto *ret = std::get_if<Return>(&i.statement)) {
            has_bare_return = has_bare_return || !ret->value;
            has_value_return = has_value_return || static_cast<bool>(ret->value);
        }
    }
    result.return_type=prototype ? prototype->result_type() : types::TypePtr{};
    bool return_ambiguous = !prototype && has_bare_return && has_value_return;
    if (return_ambiguous)
        result.diagnostics.push_back("mixed bare and value returns leave the inferred result type unknown");
    // An explicit bare return is evidence of a void result. Do not mistake
    // unrelated writes to the ABI return register for a returned value.
    if (!prototype && has_bare_return && !has_value_return)
        result.return_type = types::Type::void_type();
    if(!result.return_type && abi.integer_return_register) {
        std::optional<std::uint32_t> latest_version;
        const Fact *return_fact = nullptr;
        for (const auto &[fact_key, fact] : facts) {
            (void)fact_key;
            if (fact.reg != *abi.integer_return_register) continue;
            if (!return_fact || (fact.version && (!latest_version || *fact.version > *latest_version))) {
                return_fact = &fact;
                latest_version = fact.version;
            }
        }
        types::TypePtr observed_return_type;
        bool unknown_value_return = false;
        for (const auto &b : fn.blocks) for (const auto &i : b.instructions) {
            const auto *ret = std::get_if<Return>(&i.statement);
            if (!ret || !ret->value) continue;
            const auto value = infer_expr(ret->value, infer_expr);
            if (!value.bits && !value.exact_type && !value.pointer && !value.floating &&
                !value.vector_evidence) {
                unknown_value_return = true;
                continue;
            }
            auto type = make_type(value, abi.pointer_bits, nested_layout_work);
            if (!type) { unknown_value_return = true; continue; }
            if (!observed_return_type) observed_return_type = std::move(type);
            else if (observed_return_type->id() != type->id()) return_ambiguous = true;
        }
        if (observed_return_type && unknown_value_return) return_ambiguous = true;
        if (!return_ambiguous && observed_return_type) result.return_type = std::move(observed_return_type);
        if (return_ambiguous && !prototype)
            result.diagnostics.push_back("incompatible or incomplete value-return evidence leaves the inferred result type unknown");
        if (!result.return_type && !return_ambiguous && return_fact && return_fact->bits)
            result.return_type = make_type(*return_fact, abi.pointer_bits, nested_layout_work);
    }
    if (!prototype && !return_ambiguous && !result.return_type) {
        for (const auto &block : fn.blocks) for (const auto &instruction : block.instructions) {
            const auto *ret = std::get_if<Return>(&instruction.statement);
            if (!ret || !ret->value) continue;
            const auto returned = infer_expr(ret->value, infer_expr);
            if (!returned.vector_evidence) continue;
            result.return_type = make_type(returned, abi.pointer_bits, nested_layout_work);
            if (!result.return_type)
                result.diagnostics.push_back("vector return has no supported lane shape; return type left unknown");
            break;
        }
    }
    if (!prototype && !return_ambiguous && !result.return_type && abi.vector_return_register) {
        const Fact *return_fact = nullptr;
        for (const auto &[fact_key, fact] : facts) {
            (void)fact_key;
            if (fact.reg == *abi.vector_return_register && fact.vector_evidence) return_fact = &fact;
        }
        if (return_fact) result.return_type = make_type(*return_fact, abi.pointer_bits, nested_layout_work);
        if (!result.return_type)
            result.diagnostics.push_back("vector return register has no supported lane shape; return type left unknown");
    }
    if(!prototype && !return_ambiguous && !result.return_type && abi.floating_return_register) {
        for(const auto &[fk,fact]:facts) { (void)fk; if(fact.reg==*abi.floating_return_register && fact.bits) {
            Fact f=fact; f.floating=true; result.return_type=make_type(f,abi.pointer_bits,nested_layout_work); break;
        }}
        if(!result.return_type) result.diagnostics.push_back("floating return register has no width evidence; return type left unknown");
    }
    for (const auto vector_register : abi.vector_argument_registers) {
        const auto incoming = std::find_if(facts.begin(), facts.end(), [&](const auto &entry) {
            const auto &fact = entry.second;
            return fact.reg == vector_register && (!fact.version || *fact.version == 0);
        });
        if (incoming != facts.end() && !incoming->second.vector_type)
            result.diagnostics.push_back("vector ABI argument has no supported lane shape; argument type left unknown");
    }
    // Infer only a contiguous prefix of ABI argument registers that actually
    // occur in the lifted IR. A gap means the prototype arity is ambiguous;
    // stopping there avoids inventing a parameter for an unused slot.
    const bool has_return_statement = has_bare_return || has_value_return;
    if (prototype) {
        result.inferred_prototype = prototype;
    } else if (has_return_statement && result.return_type) {
        std::vector<types::Parameter> inferred_parameters;
        // A stack argument is admitted only when the function reads the exact
        // ABI slot after normalizing stack-pointer adjustments back to the
        // incoming ABI base. The loaded destination's observed width supplies
        // size; no slot is invented from offsets alone.
        auto stack_offset_from_entry = [&](const MemoryValue &memory) -> std::optional<std::int64_t> {
            if (!abi.stack_argument_base || !memory.base || memory.index || memory.absolute) return {};
            const auto canonical = canonical_stack_address(key(*memory.base, memory.base_version), pointer_aliases);
            if (!canonical || (canonical->first != key(*abi.stack_argument_base) &&
                               canonical->first != key(*abi.stack_argument_base, 0))) return {};
            std::int64_t offset = 0;
            if (!checked_add(canonical->second, memory.displacement, offset)) return {};
            return offset;
        };
        std::map<std::int64_t, const Fact *> stack_arguments;
        if (abi.stack_argument_base) for (const auto &b : fn.blocks) for (const auto &i : b.instructions) {
            const auto *assign=std::get_if<Assign>(&i.statement);
            if (!assign || !assign->value) continue;
            const auto *mem=std::get_if<MemoryValue>(&assign->value->value);
            if (!mem) continue;
            const auto normalized_offset = stack_offset_from_entry(*mem);
            if (!normalized_offset || *normalized_offset < 0) continue;
            auto slot=std::find(abi.stack_argument_offsets.begin(),abi.stack_argument_offsets.end(),*normalized_offset);
            if(slot==abi.stack_argument_offsets.end()) continue;
            auto fact=facts.find(key(assign->destination,assign->destination_version));
            if(fact!=facts.end() && fact->second.bits) stack_arguments[*normalized_offset]=&fact->second;
        }

        auto incoming_register_fact = [&](RegisterOperand reg) -> const Fact * {
            for (const auto &[fact_key, fact] : facts) {
                (void)fact_key;
                // Incoming ABI values use version zero in SSA; pre-SSA IR
                // leaves the register unversioned.
                if (fact.reg == reg && (!fact.version || *fact.version == 0) &&
                    (fact.constrained || parameter_evidence.contains(key(fact.reg, fact.version)))) return &fact;
            }
            return nullptr;
        };
        auto slot_fact = [&](const AbiArgumentSlot &slot) -> const Fact * {
            if (slot.reg) return incoming_register_fact(*slot.reg);
            if (slot.stack_offset) {
                const auto found = stack_arguments.find(*slot.stack_offset);
                return found == stack_arguments.end() ? nullptr : found->second;
            }
            return nullptr;
        };
        bool unresolved_argument_order = false;
        if (abi.name == "x86-64 Windows") {
            // Windows x64 assigns each of the first four source positions to
            // either its matching GPR or XMM register. Seeing both for one
            // position is contradictory; a missing position ends the
            // recoverable prefix because later observed slots cannot prove
            // the omitted parameter's type.
            const auto count = std::min<std::size_t>(4, abi.integer_argument_registers.size());
            const auto later_windows_argument = [&](std::size_t index) {
                for (std::size_t later = index + 1; later < count; ++later) {
                    if (incoming_register_fact(abi.integer_argument_registers[later])) return true;
                    if (later < abi.floating_argument_registers.size() &&
                        incoming_register_fact(abi.floating_argument_registers[later])) return true;
                }
                return !stack_arguments.empty();
            };
            bool register_prefix_complete = count == 0;
            for (std::size_t index = 0; index < count; ++index) {
                const auto *integer_fact = incoming_register_fact(abi.integer_argument_registers[index]);
                const Fact *floating_fact = index < abi.floating_argument_registers.size()
                    ? incoming_register_fact(abi.floating_argument_registers[index]) : nullptr;
                if (integer_fact && floating_fact) {
                    unresolved_argument_order = true;
                    result.diagnostics.push_back("Windows x64 positional argument has conflicting GPR and XMM evidence");
                    inferred_parameters.clear();
                    break;
                }
                if (!integer_fact && !floating_fact) {
                    if (later_windows_argument(index)) {
                        unresolved_argument_order = true;
                        inferred_parameters.clear();
                        result.diagnostics.push_back("Windows x64 argument evidence has a positional gap");
                    }
                    break;
                }
                Fact classified = floating_fact ? *floating_fact : *integer_fact;
                if (floating_fact) classified.floating = true;
                auto type = make_type(classified, abi.pointer_bits, nested_layout_work);
                if (!type) {
                    unresolved_argument_order = true;
                    inferred_parameters.clear();
                    result.diagnostics.push_back("Windows x64 observed argument slot has no representable type");
                    break;
                }
                inferred_parameters.push_back({"arg" + std::to_string(inferred_parameters.size()), std::move(type)});
                register_prefix_complete = index + 1 == count;
            }
            if (!unresolved_argument_order && register_prefix_complete) {
                for (std::size_t stack_index = 0; stack_index < abi.stack_argument_offsets.size(); ++stack_index) {
                    const auto offset = abi.stack_argument_offsets[stack_index];
                    const auto found = stack_arguments.find(offset);
                    if (found == stack_arguments.end()) {
                        bool later_argument = false;
                        for (std::size_t later = stack_index + 1; later < abi.stack_argument_offsets.size(); ++later)
                            later_argument = later_argument || stack_arguments.contains(abi.stack_argument_offsets[later]);
                        if (later_argument) {
                            unresolved_argument_order = true;
                            inferred_parameters.clear();
                            result.diagnostics.push_back("Windows x64 stack argument evidence has a positional gap");
                        }
                        break;
                    }
                    auto type = make_type(*found->second, abi.pointer_bits, nested_layout_work);
                    if (!type) {
                        unresolved_argument_order = true;
                        inferred_parameters.clear();
                        result.diagnostics.push_back("Windows x64 observed stack argument has no representable type");
                        break;
                    }
                    inferred_parameters.push_back({"arg" + std::to_string(inferred_parameters.size()), std::move(type)});
                }
            }
        } else if (abi.name == "x86-64 System V") {
            // SysV allocates integer and SSE arguments independently, so
            // observing both classes loses their original source ordering.
            // A single observed class still has a recoverable register prefix.
            std::vector<std::pair<RegisterOperand, Fact>> integer_facts, floating_facts;
            for (const auto reg : abi.integer_argument_registers)
                if (const auto *fact = incoming_register_fact(reg)) integer_facts.emplace_back(reg, *fact);
            for (const auto reg : abi.floating_argument_registers)
                if (const auto *fact = incoming_register_fact(reg)) floating_facts.emplace_back(reg, *fact);
            if (!stack_arguments.empty()) {
                unresolved_argument_order = true;
                result.diagnostics.push_back("System V AMD64 stack argument evidence is not classifiable without a prototype");
            }
            if (!integer_facts.empty() && !floating_facts.empty()) {
                unresolved_argument_order = true;
                result.diagnostics.push_back("System V AMD64 GPR and SSE arguments are both observed without a prototype; source parameter ordering is ambiguous");
            } else if (stack_arguments.empty()) {
                const auto &observed = integer_facts.empty() ? floating_facts : integer_facts;
                const auto &registers = integer_facts.empty() ? abi.floating_argument_registers
                                                              : abi.integer_argument_registers;
                for (std::size_t index = 0; index < observed.size(); ++index) {
                    if (index >= registers.size() || observed[index].first != registers[index]) {
                        inferred_parameters.clear();
                        unresolved_argument_order = true;
                        result.diagnostics.push_back("non-contiguous System V AMD64 argument register evidence leaves inferred parameters unknown");
                        break;
                    }
                    Fact classified = observed[index].second;
                    if (integer_facts.empty()) classified.floating = true;
                    auto type = make_type(classified, abi.pointer_bits, nested_layout_work);
                    if (!type) {
                        inferred_parameters.clear();
                        unresolved_argument_order = true;
                        result.diagnostics.push_back("System V AMD64 observed argument register has no representable type");
                        break;
                    }
                    inferred_parameters.push_back({"arg" + std::to_string(inferred_parameters.size()), std::move(type)});
                }
            }
        }
        if (abi.name == "MIPS N32 hard-float scalar profile") {
            bool observed_argument = !stack_arguments.empty();
            for (const auto reg : abi.integer_argument_registers)
                observed_argument = observed_argument || incoming_register_fact(reg) != nullptr;
            for (const auto reg : abi.floating_argument_registers)
                observed_argument = observed_argument || incoming_register_fact(reg) != nullptr;
            if (observed_argument) {
                unresolved_argument_order = true;
                inferred_parameters.clear();
                result.diagnostics.push_back(
                    "MIPS N32 register and stack reads do not establish ordered parameter declarations without a prototype");
            }
        } else if (abi.name == "AArch64 AAPCS64") {
            std::vector<std::pair<RegisterOperand, Fact>> integer_facts, floating_facts;
            for (const auto reg : abi.integer_argument_registers)
                if (const auto *fact = incoming_register_fact(reg)) integer_facts.emplace_back(reg, *fact);
            for (const auto reg : abi.floating_argument_registers)
                if (const auto *fact = incoming_register_fact(reg)) floating_facts.emplace_back(reg, *fact);
            if (!integer_facts.empty() && !floating_facts.empty()) {
                unresolved_argument_order = true;
                result.diagnostics.push_back("AAPCS64 argument classes are both observed without a prototype; source parameter ordering is ambiguous");
            } else {
                const auto &observed = integer_facts.empty() ? floating_facts : integer_facts;
                const auto &registers = integer_facts.empty() ? abi.floating_argument_registers
                                                              : abi.integer_argument_registers;
                bool contiguous = true;
                for (std::size_t index = 0; index < observed.size(); ++index) {
                    if (index >= registers.size() || observed[index].first != registers[index]) {
                        contiguous = false; break;
                    }
                    auto fact = observed[index].second;
                    if (integer_facts.empty()) fact.floating = true;
                    auto type = make_type(fact, abi.pointer_bits, nested_layout_work);
                    if (!type) { contiguous = false; break; }
                    inferred_parameters.push_back({"arg" + std::to_string(inferred_parameters.size()), std::move(type)});
                }
                if (!contiguous) {
                    inferred_parameters.clear();
                    unresolved_argument_order = true;
                    result.diagnostics.push_back("non-contiguous AAPCS64 argument register evidence leaves inferred parameters unknown");
                }
            }
        } else if (abi.name == "PowerPC64 ELFv2") {
            bool observed_argument = !stack_arguments.empty();
            for (const auto reg : abi.integer_argument_registers)
                observed_argument = observed_argument || incoming_register_fact(reg) != nullptr;
            for (const auto reg : abi.floating_argument_registers)
                observed_argument = observed_argument || incoming_register_fact(reg) != nullptr;
            if (observed_argument) {
                // ELFv2 assigns GPR and FPR arguments independently while
                // source order advances a separate parameter-save-area slot.
                // Reads alone cannot prove that earlier arguments were absent,
                // so register/stack use cannot be turned into ordered parameter
                // declarations without a prototype or call-site evidence.
                unresolved_argument_order = true;
                inferred_parameters.clear();
                result.diagnostics.push_back(
                    "PowerPC64 ELFv2 argument use does not establish source order without a prototype; inferred parameters are omitted");
            }
        } else if (abi.name != "x86-64 Windows" && abi.name != "x86-64 System V" && !abi.arguments.empty()) {
            // The explicit ordered slot map is the ABI's source of argument
            // order. It can describe interleaved register classes and stack
            // slots; stop at the first unobserved or unsupported slot instead
            // of skipping ahead and inventing a prototype arity.
            for (const auto &slot : abi.arguments) {
                const Fact *argument = slot_fact(slot);
                if (!argument) break;
                if (slot.value_class == AbiValueClass::vector &&
                    (!argument->vector_type || argument->vector_ambiguous)) {
                    result.diagnostics.push_back("observed vector ABI argument omitted because lane shape is unavailable or ambiguous");
                    break;
                }
                Fact classified = *argument;
                if (slot.value_class == AbiValueClass::floating) classified.floating = true;
                auto type = make_type(classified, abi.pointer_bits, nested_layout_work);
                if (!type) break;
                inferred_parameters.push_back({"arg" + std::to_string(inferred_parameters.size()), std::move(type)});
            }
        } else if (abi.name != "x86-64 Windows" && abi.name != "x86-64 System V") {
            // Compatibility path for caller-supplied ABI maps that predate
            // AbiDescription::arguments.
            for (std::size_t n = 0; n < abi.integer_argument_registers.size(); ++n) {
                const Fact *argument = incoming_register_fact(abi.integer_argument_registers[n]);
                if (!argument) break;
                auto type = make_type(*argument, abi.pointer_bits, nested_layout_work);
                if (!type) break;
                inferred_parameters.push_back({"arg" + std::to_string(n), std::move(type)});
            }
            for (auto offset : abi.stack_argument_offsets) {
                auto found=stack_arguments.find(offset); if(found==stack_arguments.end()) break;
                if (inferred_parameters.size()<abi.integer_argument_registers.size()) {
                    result.diagnostics.push_back("observed stack argument omitted from candidate signature because preceding register argument slots are not all observed");
                    break;
                }
                auto type=make_type(*found->second,abi.pointer_bits,nested_layout_work); if(!type) break;
                inferred_parameters.push_back({"arg"+std::to_string(inferred_parameters.size()),std::move(type)});
            }
        }
        if (!unresolved_argument_order) {
            auto inferred = types::Type::function(
                result.return_type ? result.return_type : types::Type::void_type(),
                std::move(inferred_parameters), false);
            if (inferred) result.inferred_prototype = inferred.value();
            else result.diagnostics.push_back("could not construct inferred function prototype: " + inferred.error().message);
        }
    } else if (has_return_statement) {
        result.diagnostics.push_back("return type is unresolved; no inferred function prototype was emitted");
    }
    if(abi.name.empty() && (!abi.integer_argument_registers.empty()||abi.integer_return_register))
        result.diagnostics.push_back("ABI register map supplied without a descriptive ABI name");
    return result;
}

Result<TypeRecoveryResult> recover_types(const LiftedFunction &fn, const AbiDescription &abi,
                                         types::TypePtr prototype) {
    return recover_types_impl(fn, abi, std::move(prototype));
}

namespace {
using FrameKey = std::tuple<unsigned, unsigned, unsigned, bool, std::uint32_t, bool>;
using FrameRegisterKey = std::tuple<unsigned, unsigned, unsigned, bool>;
using StackSlotKey = std::tuple<FrameKey, std::int64_t, std::uint16_t>;

FrameRegisterKey frame_register_key(RegisterOperand reg) {
    return {static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte};
}

FrameKey frame_key(RegisterOperand reg, std::optional<std::uint32_t> version) {
    return {static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte,
            version.value_or(0), version.has_value()};
}

bool recognized_frame_register(RegisterOperand reg) {
    return (reg.bank == RegisterBank::gpr && reg.index == 5) ||
           (reg.bank == RegisterBank::arm64_gpr && reg.index == 29) ||
           (reg.bank == RegisterBank::arm32_gpr && reg.index == 11) ||
           (reg.bank == RegisterBank::riscv_gpr && reg.index == 8) ||
           (reg.bank == RegisterBank::mips_gpr && reg.index == 30) ||
           (reg.bank == RegisterBank::ppc_gpr && (reg.index == 1 || reg.index == 31)) ||
           (reg.bank == RegisterBank::gpr && reg.index == 4) ||
           (reg.bank == RegisterBank::arm64_sp && reg.index == 0) ||
           (reg.bank == RegisterBank::arm32_gpr && reg.index == 13) ||
           (reg.bank == RegisterBank::riscv_gpr && reg.index == 2) ||
           (reg.bank == RegisterBank::mips_gpr && reg.index == 29);
}
bool is_stack_pointer(RegisterOperand reg) {
    return (reg.bank == RegisterBank::gpr && reg.index == 4) ||
           (reg.bank == RegisterBank::arm64_sp && reg.index == 0) ||
           (reg.bank == RegisterBank::arm32_gpr && reg.index == 13) ||
           (reg.bank == RegisterBank::riscv_gpr && reg.index == 2) ||
           (reg.bank == RegisterBank::mips_gpr && reg.index == 29) ||
           (reg.bank == RegisterBank::ppc_gpr && reg.index == 1);
}

bool checked_add(std::int64_t left, std::int64_t right, std::int64_t &result) {
    if ((right > 0 && left > std::numeric_limits<std::int64_t>::max() - right) ||
        (right < 0 && left < std::numeric_limits<std::int64_t>::min() - right)) return false;
    result = left + right;
    return true;
}
bool checked_subtract(std::int64_t left, std::int64_t right, std::int64_t &result) {
    if (right == std::numeric_limits<std::int64_t>::min()) {
        if (left >= 0) return false;
        result = left - right;
        return true;
    }
    return checked_add(left, -right, result);
}

std::optional<std::pair<FrameKey, std::int64_t>> canonical_stack_address(
    const FrameKey &start, const std::vector<PointerAlias> &aliases) {
    struct Node { FrameKey value; std::int64_t displacement; };
    std::vector<Node> pending{{start, 0}};
    std::map<FrameKey, std::int64_t> visited;
    std::optional<std::pair<FrameKey, std::int64_t>> answer;
    for (std::size_t cursor = 0; cursor < pending.size(); ++cursor) {
        const auto node = pending[cursor];
        if (const auto prior = visited.find(node.value); prior != visited.end()) {
            if (prior->second != node.displacement) return {};
            continue;
        }
        visited.emplace(node.value, node.displacement);
        const RegisterOperand reg{static_cast<RegisterBank>(std::get<0>(node.value)),
            static_cast<std::uint8_t>(std::get<1>(node.value)),
            static_cast<std::uint16_t>(std::get<2>(node.value)), std::get<3>(node.value)};
        const bool incoming_stack_pointer = is_stack_pointer(reg) &&
            (!std::get<5>(node.value) || std::get<4>(node.value) == 0);
        if (recognized_frame_register(reg) && (!is_stack_pointer(reg) || incoming_stack_pointer)) {
            const auto candidate = std::pair{node.value, node.displacement};
            if (answer && *answer != candidate) return {};
            answer = candidate;
            continue;
        }
        for (const auto &alias : aliases) {
            std::int64_t displacement = 0;
            if (alias.destination == node.value) {
                if (!checked_add(node.displacement, alias.displacement, displacement)) return {};
                pending.push_back({alias.source, displacement});
            }
            if (alias.source == node.value) {
                if (!checked_subtract(node.displacement, alias.displacement, displacement)) return {};
                pending.push_back({alias.destination, displacement});
            }
        }
    }
    return answer;
}

void visit_memory(const ExpressionPtr &expression, const auto &visitor) {
    if (!expression) return;
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) visitor(value);
        else if constexpr (std::is_same_v<T, UnaryValue>) visit_memory(value.operand, visitor);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            visit_memory(value.left, visitor);
            visit_memory(value.right, visitor);
        }
    }, expression->value);
}

void visit_statement_memory(const Statement &statement, const auto &visitor) {
    std::visit([&](const auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Assign>) visit_memory(value.value, visitor);
        else if constexpr (std::is_same_v<T, Store>) {
            visit_memory(value.address, visitor);
            visit_memory(value.value, visitor);
        } else if constexpr (std::is_same_v<T, Call>) visit_memory(value.indirect_target, visitor);
        else if constexpr (std::is_same_v<T, Branch>) {
            visit_memory(value.predicate, visitor);
            visit_memory(value.indirect_target, visitor);
        }
        else if constexpr (std::is_same_v<T, Return>) visit_memory(value.value, visitor);
        else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (const auto &operand : value.operands) visit_memory(operand, visitor);
            for (const auto &output : value.register_output_values) visit_memory(output, visitor);
        }
    }, statement);
}

void recover_expression(ExpressionPtr &expression, const std::map<StackSlotKey, std::string> &slots,
                        const std::vector<PointerAlias> &aliases) {
    if (!expression) return;
    auto copy = std::make_shared<Expression>(*expression);
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, MemoryValue>) {
            value.stack_variable.reset();
            value.stack_frame_register.reset();
            value.stack_frame_version.reset();
            value.stack_frame_offset.reset();
            if (value.base && !value.index && !value.absolute) {
                const auto canonical = canonical_stack_address(frame_key(*value.base, value.base_version), aliases);
                std::int64_t offset = 0;
                if (canonical && checked_add(canonical->second, value.displacement, offset)) {
                    const auto found = slots.find({canonical->first, offset, value.type.bits});
                    if (found != slots.end()) {
                        value.stack_variable = found->second;
                        value.stack_frame_register = RegisterOperand{
                            static_cast<RegisterBank>(std::get<0>(canonical->first)),
                            static_cast<std::uint8_t>(std::get<1>(canonical->first)),
                            static_cast<std::uint16_t>(std::get<2>(canonical->first)),
                            std::get<3>(canonical->first)};
                        if (std::get<5>(canonical->first))
                            value.stack_frame_version = std::get<4>(canonical->first);
                        value.stack_frame_offset = offset;
                    }
                }
            }
        } else if constexpr (std::is_same_v<T, UnaryValue>) recover_expression(value.operand, slots, aliases);
        else if constexpr (std::is_same_v<T, BinaryValue>) {
            recover_expression(value.left, slots, aliases);
            recover_expression(value.right, slots, aliases);
        }
    }, copy->value);
    expression = std::move(copy);
}

void recover_statement(Statement &statement, const std::map<StackSlotKey, std::string> &slots,
                       const std::vector<PointerAlias> &aliases) {
    std::visit([&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, Assign>) recover_expression(value.value, slots, aliases);
        else if constexpr (std::is_same_v<T, Store>) {
            recover_expression(value.address, slots, aliases);
            recover_expression(value.value, slots, aliases);
        } else if constexpr (std::is_same_v<T, Call>) recover_expression(value.indirect_target, slots, aliases);
        else if constexpr (std::is_same_v<T, Branch>) {
            recover_expression(value.predicate, slots, aliases);
            recover_expression(value.indirect_target, slots, aliases);
        }
        else if constexpr (std::is_same_v<T, Return>) recover_expression(value.value, slots, aliases);
        else if constexpr (std::is_same_v<T, Intrinsic>) {
            for (auto &operand : value.operands) recover_expression(operand, slots, aliases);
            for (auto &output : value.register_output_values) recover_expression(output, slots, aliases);
        }
    }, statement);
}

std::optional<std::string> local_name(std::int64_t displacement) {
    if (displacement >= 0) return {};
    const auto magnitude = static_cast<std::uint64_t>(-(displacement + 1)) + 1;
    return "local_" + std::to_string(magnitude);
}
} // namespace

Result<LiftedFunction> recover_stack_variables(const LiftedFunction &input) {
    if (input.blocks.empty())
        return Error{ErrorCode::invalid_argument, "stack variable recovery requires at least one block"};

    std::map<FrameKey, std::map<std::int64_t, std::uint16_t>> candidates;
    std::map<FrameKey, std::set<std::int64_t>> ambiguous_offsets;
    std::set<FrameKey> dynamic_frames;
    std::set<FrameKey> escaped_frames;
    std::map<FrameRegisterKey, std::set<FrameKey>> frame_versions;
    std::vector<PointerAlias> aliases;
    for (const auto &block : input.blocks) {
        for (const auto &phi : block.phis) {
            const auto destination = key(phi.destination, phi.version);
            for (const auto input_value : phi.inputs)
                aliases.push_back({key(phi.destination, input_value.version), destination, 0});
        }
        for (const auto &instruction : block.instructions)
        if (const auto *assignment = std::get_if<Assign>(&instruction.statement))
            if (auto alias = pointer_alias(*assignment)) aliases.push_back(*alias);
    }
    const auto mark_escaped_register = [&](RegisterOperand reg,
                                          std::optional<std::uint32_t> version) {
        const auto canonical = canonical_stack_address(frame_key(reg, version), aliases);
        if (canonical) escaped_frames.insert(canonical->first);
    };
    const auto mark_escaped = [&](const ExpressionPtr &expression, auto &&self) -> void {
        if (!expression) return;
        std::visit([&](const auto &value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, RegisterValue>) {
                mark_escaped_register(value.reg, value.version);
            } else if constexpr (std::is_same_v<T, UnaryValue>) self(value.operand, self);
            else if constexpr (std::is_same_v<T, BinaryValue>) {
                self(value.left, self); self(value.right, self);
            }
        }, expression->value);
    };
    for (const auto &block : input.blocks) for (const auto &instruction : block.instructions)
        std::visit([&](const auto &statement) {
            using T = std::decay_t<decltype(statement)>;
            if constexpr (std::is_same_v<T, Store>) mark_escaped(statement.value, mark_escaped);
            else if constexpr (std::is_same_v<T, Return>) mark_escaped(statement.value, mark_escaped);
            else if constexpr (std::is_same_v<T, Call>) {
                mark_escaped(statement.indirect_target, mark_escaped);
                // Call register snapshots are the only modeled direct-call
                // argument values. A frame-derived value passed in one may
                // escape even when the callee target itself is direct.
                for (const auto input : statement.register_inputs)
                    mark_escaped_register(input.reg, input.version);
            }
            else if constexpr (std::is_same_v<T, Intrinsic>) {
                for (const auto &operand : statement.operands) mark_escaped(operand, mark_escaped);
                for (const auto &output : statement.register_output_values) mark_escaped(output, mark_escaped);
            }
        }, instruction.statement);
    auto inspect = [&](const MemoryValue &memory) {
        if (!memory.base || memory.absolute) return;
        const auto canonical = canonical_stack_address(frame_key(*memory.base, memory.base_version), aliases);
        if (!canonical) return;
        const auto frame = canonical->first;
        const RegisterOperand root{static_cast<RegisterBank>(std::get<0>(frame)),
            static_cast<std::uint8_t>(std::get<1>(frame)),
            static_cast<std::uint16_t>(std::get<2>(frame)), std::get<3>(frame)};
        frame_versions[frame_register_key(root)].insert(frame);
        if (memory.index) {
            dynamic_frames.insert(frame);
            return;
        }
        std::int64_t offset = 0;
        if (!checked_add(canonical->second, memory.displacement, offset) || offset >= 0 ||
            !memory.type.bits || memory.type.bits % 8 || memory.type.bits > 64)
            return;
        auto [slot, inserted] = candidates[frame].try_emplace(offset, memory.type.bits);
        if (!inserted && slot->second != memory.type.bits) {
            // A width conflict makes this byte range ambiguous, not every
            // other local owned by the same canonical frame value.
            ambiguous_offsets[frame].insert(offset);
            slot->second = std::max(slot->second, memory.type.bits);
        }
    };
    for (const auto &block : input.blocks) {
        for (const auto &phi : block.phis) (void)phi;
        for (const auto &instruction : block.instructions)
            visit_statement_memory(instruction.statement, inspect);
        if (block.switch_dispatch) visit_memory(block.switch_dispatch->selector, inspect);
    }

    std::map<StackSlotKey, std::string> slots;
    for (const auto &[frame, offsets] : candidates) {
        const auto bank = std::get<0>(frame);
        const auto index = std::get<1>(frame);
        const auto width = std::get<2>(frame);
        const auto high_byte = std::get<3>(frame);
        const FrameRegisterKey physical{bank, index, width, high_byte};
        const auto versions = frame_versions.find(physical);
        if (dynamic_frames.contains(frame) || escaped_frames.contains(frame) ||
            versions == frame_versions.end() || versions->second.size() != 1)
            continue;

        // Resolve overlap per connected byte-range component. One reused or
        // partially overlapping slot makes that component ambiguous, but does
        // not invalidate unrelated locals elsewhere in the same frame.
        auto component = offsets.begin();
        while (component != offsets.end()) {
            auto end = std::next(component);
            auto component_end = component->first + static_cast<std::int64_t>(component->second / 8);
            bool overlaps = false;
            while (end != offsets.end() && end->first < component_end) {
                overlaps = true;
                component_end = std::max(component_end,
                    end->first + static_cast<std::int64_t>(end->second / 8));
                ++end;
            }
            if (!overlaps) {
                const auto offset = component->first;
                const auto ambiguous = ambiguous_offsets.find(frame);
                if (ambiguous == ambiguous_offsets.end() || !ambiguous->second.contains(offset)) {
                    const auto name = local_name(offset);
                    if (name) slots.emplace(StackSlotKey{frame, offset, component->second}, *name);
                }
            }
            component = end;
        }
    }

    // `local_8` is a useful source name while there is one proven frame base.
    // If independent recognized frame bases produce the same displacement,
    // keep their storage and type evidence separate with a deterministic
    // suffix instead of merging them by display name in later recovery.
    std::map<std::string, std::set<FrameKey>> frames_by_local_name;
    for (const auto &[slot, name] : slots)
        frames_by_local_name[name].insert(std::get<0>(slot));
    for (auto &[slot, name] : slots) {
        if (frames_by_local_name[name].size() < 2) continue;
        const auto &frame = std::get<0>(slot);
        name += "_r" + std::to_string(std::get<0>(frame)) + "_" +
                std::to_string(std::get<1>(frame)) + "_w" +
                std::to_string(std::get<2>(frame));
        if (std::get<3>(frame)) name += "_h";
        if (std::get<5>(frame)) name += "_v" + std::to_string(std::get<4>(frame));
    }

    LiftedFunction result = input;
    for (auto &block : result.blocks) {
        for (auto &instruction : block.instructions)
            recover_statement(instruction.statement, slots, aliases);
        if (block.switch_dispatch) recover_expression(block.switch_dispatch->selector, slots, aliases);
    }
    return result;
}

Result<std::string> format_pseudocode_with_types(const LiftedFunction &input,
                                                const AbiDescription &abi,
                                                types::TypePtr prototype) {
    return format_pseudocode_with_types(input, abi, std::move(prototype), {});
}

Result<std::string> format_pseudocode_with_types(const LiftedFunction &input,
                                                const AbiDescription &abi,
                                                types::TypePtr prototype,
                                                std::span<const StackLocalTypeEvidence> local_types) {
    auto named = recover_stack_variables(input);
    if (!named) return named.error();
    auto recovered = recover_types(named.value(), abi, std::move(prototype));
    if (!recovered) return recovered.error();

    auto declaration = [](const types::TypePtr &type, std::string name, auto &&self)
        -> std::optional<std::string> {
        if (!type || name.empty()) return {};
        switch (type->kind()) {
        case types::Kind::pointer: {
            if (!type->element()) return {};
            const auto pointee = type->element()->kind();
            if (pointee == types::Kind::void_type) return "void *" + name;
            if (pointee == types::Kind::array || pointee == types::Kind::function)
                name = "(*" + name + ")";
            else
                name = "*" + name;
            return self(type->element(), std::move(name), self);
        }
        case types::Kind::array:
            if (!type->element()) return {};
            return self(type->element(), name + "[" + std::to_string(type->count()) + "]", self);
        case types::Kind::function:
        case types::Kind::void_type:
            return {};
        case types::Kind::qualified:
            if (!type->element() || type->element()->kind() == types::Kind::function) return {};
            return types::format(*type) + " " + name;
        default:
            if (type->kind() == types::Kind::integer && type->size() &&
                (type->name() == "signed" || type->name() == "unsigned") && *type->size() <= 8) {
                const auto bits = *type->size() * 8;
                return std::string(type->is_signed() ? "int" : "uint") +
                       std::to_string(bits) + "_t " + name;
            }
            return types::format(*type) + " " + name;
        }
    };

    std::string rendered;
    {
        detail::ExpressionTypeScope expression_types(recovered.value().variables);
        rendered = format_structured_pseudocode(named.value()).text;
    }
    const auto body = rendered.find("{\n");
    if (body == std::string::npos)
        return Error{ErrorCode::invalid_argument, "formatted pseudocode has no function body"};
    std::string declarations;
    for (const auto &local : recovered.value().stack_variables) {
        auto type = local.type;
        types::TypePtr assigned_type;
        bool has_evidence = false, ambiguous_evidence = false;
        for (const auto &evidence : local_types) {
            if (evidence.name != local.name) continue;
            has_evidence = true;
            if (evidence.ambiguous || !evidence.type) {
                ambiguous_evidence = true;
                break;
            }
            if (!assigned_type) assigned_type = evidence.type;
            else if (assigned_type->id() != evidence.type->id()) {
                ambiguous_evidence = true;
                break;
            }
        }
        if (has_evidence && ambiguous_evidence) continue;
        if (assigned_type) type = assigned_type;
        const auto text = declaration(type, local.name, declaration);
        if (text) declarations += "    " + *text + ";\n";
    }
    if (!declarations.empty()) rendered.insert(body + 2, declarations);

    // The accepted prototype is the strongest available source for a
    // function declaration: explicit caller input wins, otherwise only the
    // conservative contiguous-prefix candidate is rendered. If a parameter
    // needs a declarator this formatter cannot express, retain the original
    // generic header rather than silently dropping or changing its type.
    const auto function_type = recovered.value().inferred_prototype;
    if (function_type && function_type->kind() == types::Kind::function &&
        function_type->result_type()) {
        const auto header_start = rendered.find("function ");
        const auto current_body = rendered.find("{\n");
        const auto argument_open = current_body == std::string::npos
            ? std::string::npos : rendered.rfind('(', current_body);
        if (header_start != std::string::npos && argument_open != std::string::npos &&
            argument_open >= header_start + 9) {
            const auto function_name = rendered.substr(header_start + 9,
                                                       argument_open - (header_start + 9));
            std::vector<std::string> parameters;
            parameters.reserve(function_type->parameters().size());
            bool supported = !function_name.empty() &&
                             (!function_type->variadic() || !function_type->parameters().empty());
            const auto convention = classifier_convention(abi);
            const auto placement = convention
                ? classify_abi_signature(*function_type, *convention)
                : AbiSignatureClassification{};
            for (std::size_t parameter_index = 0;
                 parameter_index < function_type->parameters().size(); ++parameter_index) {
                const auto &parameter = function_type->parameters()[parameter_index];
                const auto text = declaration(parameter.type, parameter.name, declaration);
                if (!text) { supported = false; break; }
                auto parameter_text = *text;
                if (parameter_index < placement.arguments.size()) {
                    const auto &where = placement.arguments[parameter_index];
                    if (where.supported && !where.locations.empty()) {
                        std::string label = " /* ABI: ";
                        if (where.indirect) label += "indirect via ";
                        for (std::size_t location_index = 0;
                             location_index < where.locations.size(); ++location_index) {
                            if (location_index) label += ", ";
                            const auto &location = where.locations[location_index];
                            if (location.kind == AbiLocationKind::register_)
                                label += location.register_name;
                            else {
                                std::ostringstream offset;
                                offset << "stack+0x" << std::hex << location.stack_offset;
                                label += offset.str();
                            }
                        }
                        label += " */";
                        parameter_text += label;
                    }
                }
                parameters.push_back(std::move(parameter_text));
            }
            if (supported) {
                if (function_type->variadic()) parameters.push_back("...");
                std::string arguments;
                for (std::size_t index = 0; index < parameters.size(); ++index) {
                    if (index) arguments += ", ";
                    arguments += parameters[index];
                }
                const auto callable_name = function_name + "(" + arguments + ")";
                std::optional<std::string> signature;
                if (function_type->result_type()->kind() == types::Kind::void_type)
                    signature = "void " + callable_name;
                else
                    signature = declaration(function_type->result_type(), callable_name, declaration);
                if (signature) {
                    if (signature->ends_with(';')) signature->pop_back();
                    rendered.replace(header_start, current_body - header_start,
                                     "function " + *signature + " ");
                }
            }
        }
    }
    return rendered;
}

Result<std::vector<TypeRecoveryResult>> recover_interprocedural_types(
    std::span<const LiftedFunction> functions, std::span<const AbiDescription> abis,
    std::span<const types::TypePtr> prototypes, std::uint32_t max_iterations) {
    return recover_interprocedural_types(functions, abis, prototypes,
                                         std::span<const ExternalFunctionPrototype>{}, max_iterations);
}

Result<std::vector<TypeRecoveryResult>> recover_interprocedural_types(
    std::span<const LiftedFunction> functions, std::span<const AbiDescription> abis,
    std::span<const types::TypePtr> prototypes,
    std::span<const ExternalFunctionPrototype> external_prototypes,
    std::uint32_t max_iterations) {
    if (functions.size() != abis.size() || (!prototypes.empty() && prototypes.size() != functions.size()))
        return Error{ErrorCode::invalid_argument, "Interprocedural recovery requires one ABI and optional prototype per function"};
    if (functions.size() > 4096 || external_prototypes.size() > 65536 ||
        max_iterations == 0 || max_iterations > 32)
        return Error{ErrorCode::resource_limit, "Interprocedural recovery exceeds its function or iteration budget"};
    if (functions.empty()) return std::vector<TypeRecoveryResult>{};

    try {

    using EntryKey = std::pair<std::uint32_t, std::uint64_t>;
    const auto entry_key = [](Address address) { return EntryKey{address.space.value, address.offset}; };
    const auto register_key = [](RegisterOperand reg) {
        return std::tuple{static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte};
    };
    const auto slots_for = [](const AbiDescription &abi, const types::TypePtr &prototype = {})
        -> std::vector<AbiArgumentSlot> {
        if (abi.name == "AArch64 AAPCS64" && prototype && prototype->kind() == types::Kind::function) {
            return aapcs64_prototype_slots(prototype);
        }
        if (abi.name == "x86-64 System V" && prototype && prototype->kind() == types::Kind::function) {
            return sysv64_prototype_slots(prototype);
        }
        if (abi.name == "PowerPC64 ELFv2")
            return prototype && prototype->kind() == types::Kind::function
                ? ppc64_elfv2_prototype_slots(prototype) : std::vector<AbiArgumentSlot>{};
        if (abi.name == "MIPS N32 hard-float scalar profile")
            return prototype && prototype->kind() == types::Kind::function
                ? mips_n32_prototype_slots(prototype) : std::vector<AbiArgumentSlot>{};
        if (abi.name == "MIPS64 Linux N64 hard-float scalar profile" &&
            prototype && prototype->kind() == types::Kind::function) {
            std::vector<AbiArgumentSlot> slots;
            const auto &parameters = prototype->parameters();
            for (std::size_t position = 0; position < parameters.size() && position < 8; ++position) {
                const auto type = parameters[position].type;
                const bool floating = type && type->kind() == types::Kind::floating;
                const auto reg = floating ? abi.floating_argument_registers[position]
                                          : abi.integer_argument_registers[position];
                slots.push_back({floating ? AbiValueClass::floating : AbiValueClass::integer,
                                 reg, {}, static_cast<std::uint16_t>(position), {}});
            }
            return slots;
        }
        if (!abi.arguments.empty()) return abi.arguments;
        std::vector<AbiArgumentSlot> slots;
        for (const auto reg : abi.integer_argument_registers)
            slots.push_back({AbiValueClass::integer, reg, {}});
        for (const auto offset : abi.stack_argument_offsets)
            slots.push_back({AbiValueClass::integer, {}, offset});
        return slots;
    };
    const auto same_abi = [&](const AbiDescription &left, const AbiDescription &right) {
        if (left.pointer_bits != right.pointer_bits || left.integer_argument_registers != right.integer_argument_registers ||
            left.floating_argument_registers != right.floating_argument_registers ||
            left.vector_argument_registers != right.vector_argument_registers ||
            left.integer_return_register != right.integer_return_register ||
            left.floating_return_register != right.floating_return_register ||
            left.vector_return_register != right.vector_return_register ||
            left.caller_saved_registers != right.caller_saved_registers ||
            left.shared_integer_float_argument_positions != right.shared_integer_float_argument_positions ||
            left.stack_argument_base != right.stack_argument_base ||
            left.call_stack_adjustment != right.call_stack_adjustment)
            return false;
        const auto lhs = slots_for(left), rhs = slots_for(right);
        if (lhs.size() != rhs.size()) return false;
        for (std::size_t i = 0; i < lhs.size(); ++i)
            if (lhs[i].value_class != rhs[i].value_class || lhs[i].reg != rhs[i].reg ||
                lhs[i].stack_offset != rhs[i].stack_offset || lhs[i].parameter_index != rhs[i].parameter_index ||
                lhs[i].component_index != rhs[i].component_index ||
                lhs[i].component_offset != rhs[i].component_offset ||
                lhs[i].component_size != rhs[i].component_size ||
                lhs[i].supported != rhs[i].supported) return false;
        return true;
    };
    const auto same_register_file = [&](const AbiDescription &left, const AbiDescription &right) {
        if (!left.pointer_bits || left.pointer_bits != right.pointer_bits) return false;
        std::set<unsigned> left_banks, right_banks;
        const auto collect_banks = [](const AbiDescription &abi, std::set<unsigned> &banks) {
            const auto add = [&](RegisterOperand reg) { banks.insert(static_cast<unsigned>(reg.bank)); };
            for (const auto reg : abi.integer_argument_registers) add(reg);
            for (const auto reg : abi.floating_argument_registers) add(reg);
            for (const auto reg : abi.vector_argument_registers) add(reg);
            for (const auto reg : abi.caller_saved_registers) add(reg);
            if (abi.integer_return_register) add(*abi.integer_return_register);
            if (abi.floating_return_register) add(*abi.floating_return_register);
            if (abi.vector_return_register) add(*abi.vector_return_register);
            if (abi.stack_argument_base) add(*abi.stack_argument_base);
            for (const auto &slot : abi.arguments) if (slot.reg) add(*slot.reg);
        };
        collect_banks(left, left_banks);
        collect_banks(right, right_banks);
        return left_banks == right_banks;
    };
    const auto returned_register = [](const AbiDescription &abi, const types::TypePtr &type)
        -> std::optional<RegisterOperand> {
        if (!type || type->kind() == types::Kind::void_type) return {};
        switch (type->kind()) {
        case types::Kind::boolean:
        case types::Kind::integer:
        case types::Kind::enumeration:
        case types::Kind::pointer: return abi.integer_return_register;
        case types::Kind::floating: return abi.floating_return_register;
        case types::Kind::vector: return abi.vector_return_register;
        default: break;
        }

        // A few native ABIs return small integer-class aggregates in one
        // integer result register. Model only the unambiguous one-register
        // subset; unions, bitfields, virtual bases, floating members, and
        // aggregates wider than the result register still need ABI-specific
        // multi-register/sret classification.
        const auto aggregate = unqualified_type(type);
        const auto result = abi.integer_return_register;
        if (!aggregate || !aggregate->size() || (*aggregate->size() == 0) ||
            (aggregate->kind() != types::Kind::structure && aggregate->kind() != types::Kind::array))
            return {};
        if (abi.name == "x86-64 System V" || abi.name == "PowerPC64 ELFv2") {
            const auto signature = types::Type::function(type, {}, false);
            if (!signature) return {};
            const auto convention = classifier_convention(abi);
            if (!convention) return {};
            const auto classified = classify_abi_signature(*convention, *signature.value());
            if (!classified.result.supported || classified.result.indirect ||
                classified.result.locations.size() != 1 ||
                classified.result.locations.front().role != AbiLocationRole::value)
                return {};
            return abi.name == "PowerPC64 ELFv2"
                ? ppc64_classified_register(classified.result.locations.front().register_name)
                : classified_register(classified.result.locations.front().register_name);
        }
        if (abi.name != "x86-64 Windows" && abi.name != "AArch64 AAPCS64") return {};
        if (abi.name == "AArch64 AAPCS64") {
            const auto hfa = hfa_float_elements(aggregate);
            if (hfa) return hfa->size() == 1 ? abi.floating_return_register
                                             : std::optional<RegisterOperand>{};
        }
        if (!result || !result->width || *aggregate->size() > result->width / 8) return {};

        std::size_t work = 0;
        const auto integer_only = [&](const types::TypePtr &candidate, unsigned depth,
                                      auto &&self) -> bool {
            if (!candidate || depth > 8 || work++ >= 256) return false;
            const auto value = unqualified_type(candidate);
            if (!value) return false;
            switch (value->kind()) {
            case types::Kind::boolean:
            case types::Kind::integer:
            case types::Kind::enumeration:
            case types::Kind::pointer:
                return value->size().has_value();
            case types::Kind::array:
                return value->size() && value->count() != 0 && value->element() &&
                    value->element()->size() && *value->element()->size() != 0 &&
                    value->count() <= *value->size() / *value->element()->size() &&
                    value->count() * *value->element()->size() == *value->size() &&
                    self(value->element(), depth + 1, self);
            case types::Kind::structure: {
                if (!value->size() || value->members().empty()) return false;
                std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
                ranges.reserve(value->members().size());
                for (const auto &member : value->members()) {
                    if (!member.has_fixed_offset() || member.bit_width || member.bit_offset ||
                        !member.type || !member.type->size() ||
                        member.offset > *value->size() ||
                        *member.type->size() > *value->size() - member.offset ||
                        !self(member.type, depth + 1, self)) return false;
                    ranges.emplace_back(member.offset, member.offset + *member.type->size());
                }
                std::sort(ranges.begin(), ranges.end());
                for (std::size_t index = 1; index < ranges.size(); ++index)
                    if (ranges[index].first < ranges[index - 1].second) return false;
                return true;
            }
            default:
                return false;
            }
        };
        return integer_only(aggregate, 0, integer_only) ? result : std::optional<RegisterOperand>{};
    };
    const auto matches_slot_class = [](AbiValueClass value_class, const types::TypePtr &type) {
        if (!type) return false;
        switch (value_class) {
        case AbiValueClass::integer:
            return type->kind() == types::Kind::boolean || type->kind() == types::Kind::integer ||
                   type->kind() == types::Kind::enumeration || type->kind() == types::Kind::pointer;
        case AbiValueClass::floating: return type->kind() == types::Kind::floating;
        case AbiValueClass::vector: return type->kind() == types::Kind::vector;
        }
        return false;
    };
    const auto same_type = [](const types::TypePtr &left, const types::TypePtr &right) {
        return left == right || (left && right && left->id() == right->id());
    };

    std::map<EntryKey, std::size_t> entries;
    std::vector<types::TypePtr> explicit_prototypes(functions.size());
    std::vector<std::vector<AbiArgumentSlot>> abi_slots(functions.size());
    std::set<std::tuple<unsigned, unsigned, unsigned, bool>> tracked_keys;
    std::vector<RegisterOperand> tracked_registers;
    std::size_t total_blocks = 0;
    std::size_t total_instructions = 0;
    std::size_t total_edges = 0;
    std::size_t total_phis = 0;
    std::size_t total_phi_inputs = 0;
    std::size_t total_switch_cases = 0;
    for (std::size_t i = 0; i < functions.size(); ++i) {
        if (functions[i].blocks.size() > 100000 - total_blocks)
            return Error{ErrorCode::resource_limit, "Interprocedural recovery exceeds its 100,000-block budget"};
        total_blocks += functions[i].blocks.size();
        for (const auto &block : functions[i].blocks) {
            if (block.instructions.size() > 500000 - total_instructions)
                return Error{ErrorCode::resource_limit, "Interprocedural recovery exceeds its 500,000-instruction budget"};
            total_instructions += block.instructions.size();
            for (const auto &instruction : block.instructions)
                if (const auto *call = std::get_if<Call>(&instruction.statement);
                    call && call->register_inputs.size() > 256)
                    return Error{ErrorCode::resource_limit, "Interprocedural input call snapshot exceeds 256 registers"};
            if (block.successors.size() > 1000000 - total_edges)
                return Error{ErrorCode::resource_limit, "Interprocedural recovery exceeds its one-million-CFG-edge budget"};
            total_edges += block.successors.size();
            if (block.phis.size() > 1000000 - total_phis)
                return Error{ErrorCode::resource_limit, "Interprocedural recovery exceeds its one-million-phi budget"};
            total_phis += block.phis.size();
            for (const auto &phi : block.phis) {
                if (phi.inputs.size() > 1000000 - total_phi_inputs)
                    return Error{ErrorCode::resource_limit, "Interprocedural recovery exceeds its one-million-phi-input budget"};
                total_phi_inputs += phi.inputs.size();
            }
            if (block.memory_phi) {
                if (block.memory_phi->inputs.size() > 1000000 - total_phi_inputs)
                    return Error{ErrorCode::resource_limit, "Interprocedural recovery exceeds its one-million-phi-input budget"};
                total_phi_inputs += block.memory_phi->inputs.size();
            }
            if (block.switch_dispatch) {
                if (block.switch_dispatch->cases.size() > 1000000 - total_switch_cases)
                    return Error{ErrorCode::resource_limit, "Interprocedural recovery exceeds its one-million-switch-case budget"};
                total_switch_cases += block.switch_dispatch->cases.size();
            }
        }
        if (!entries.emplace(entry_key(functions[i].entry), i).second)
            return Error{ErrorCode::conflict, "Interprocedural recovery contains duplicate function entries"};
        if (!prototypes.empty()) explicit_prototypes[i] = prototypes[i];
        if (explicit_prototypes[i] && explicit_prototypes[i]->kind() != types::Kind::function)
            return Error{ErrorCode::invalid_argument, "Interprocedural prototype is not a function type"};
        if (abis[i].call_stack_adjustment < 0 || abis[i].call_stack_adjustment > (1 << 20))
            return Error{ErrorCode::invalid_argument, "Interprocedural ABI call-stack adjustment is outside the supported bound"};
        if (abis[i].arguments.size() > 256 ||
            (abis[i].arguments.empty() &&
             (abis[i].integer_argument_registers.size() > 256 ||
              abis[i].stack_argument_offsets.size() > 256 - abis[i].integer_argument_registers.size())))
            return Error{ErrorCode::resource_limit, "Interprocedural ABI argument map exceeds 256 slots"};
        abi_slots[i] = slots_for(abis[i], explicit_prototypes[i]);
        if (abi_slots[i].size() > 256)
            return Error{ErrorCode::resource_limit, "Interprocedural ABI argument map exceeds 256 slots"};
        const auto add_register = [&](RegisterOperand reg) {
            if (!reg.width) return false;
            if (tracked_keys.insert(register_key(reg)).second) tracked_registers.push_back(reg);
            return tracked_registers.size() <= 256;
        };
        for (const auto &slot : abi_slots[i])
            if (slot.reg && !add_register(*slot.reg))
                return Error{ErrorCode::resource_limit, "Interprocedural ABI register map exceeds its 256-register budget"};
        for (const auto reg : abis[i].floating_argument_registers)
            if (!add_register(reg)) return Error{ErrorCode::resource_limit, "Interprocedural ABI register map exceeds its budget"};
        for (const auto reg : abis[i].vector_argument_registers)
            if (!add_register(reg)) return Error{ErrorCode::resource_limit, "Interprocedural ABI register map exceeds its budget"};
        if (abis[i].stack_argument_base && !add_register(*abis[i].stack_argument_base))
            return Error{ErrorCode::resource_limit, "Interprocedural ABI stack-base register exceeds its budget"};
        if (explicit_prototypes[i]) {
            const auto hidden = hidden_result_pointer_info(abis[i], explicit_prototypes[i]->result_type());
            if (hidden && !add_register(hidden->reg))
                return Error{ErrorCode::resource_limit, "Interprocedural hidden-result register map exceeds its budget"};
        }
    }

    struct ExternalCallee {
        AbiDescription abi;
        types::TypePtr prototype;
        std::vector<AbiArgumentSlot> slots;
        bool ambiguous = false;
    };
    std::map<EntryKey, ExternalCallee> external_entries;
    for (const auto &external : external_prototypes) {
        if (!external.prototype || external.prototype->kind() != types::Kind::function)
            return Error{ErrorCode::invalid_argument, "External call prototype must be a function type"};
        if (external.abi.call_stack_adjustment < 0 || external.abi.call_stack_adjustment > (1 << 20))
            return Error{ErrorCode::invalid_argument, "External call ABI stack adjustment is outside the supported bound"};
        if (external.abi.arguments.size() > 256 ||
            (external.abi.arguments.empty() &&
             (external.abi.integer_argument_registers.size() > 256 ||
              external.abi.stack_argument_offsets.size() >
                  256 - external.abi.integer_argument_registers.size())))
            return Error{ErrorCode::resource_limit, "External call ABI argument map exceeds 256 slots"};
        const auto address = entry_key(external.entry);
        // A recovered body takes precedence over an external declaration at
        // the same address; its current/inferred prototype is handled below.
        if (entries.contains(address)) continue;
        auto slots = slots_for(external.abi, external.prototype);
        if (slots.size() > 256)
            return Error{ErrorCode::resource_limit, "External call ABI argument map exceeds 256 slots"};
        auto [found, inserted] = external_entries.try_emplace(
            address, ExternalCallee{external.abi, external.prototype, std::move(slots), false});
        if (!inserted && (!same_abi(found->second.abi, external.abi) ||
                          !same_type(found->second.prototype, external.prototype))) {
            found->second.ambiguous = true;
            if (same_register_file(found->second.abi, external.abi)) {
                for (const auto reg : external.abi.caller_saved_registers)
                    if (std::find(found->second.abi.caller_saved_registers.begin(),
                                  found->second.abi.caller_saved_registers.end(), reg) ==
                        found->second.abi.caller_saved_registers.end())
                        found->second.abi.caller_saved_registers.push_back(reg);
                if (external.abi.name == "x86-64 Windows")
                    found->second.abi.name = "x86-64 Windows";
            }
        }
    }
    // Calls through another ABI on the same register file need the union of
    // its caller-saved registers and argument/return registers in the SSA set.
    for (const auto &[address, external] : external_entries) {
        (void)address;
        const auto add_external_register = [&](RegisterOperand reg) {
            if (!reg.width) return false;
            if (tracked_keys.insert(register_key(reg)).second) tracked_registers.push_back(reg);
            return tracked_registers.size() <= 256;
        };
        for (const auto &slot : external.slots)
            if (slot.reg && !add_external_register(*slot.reg))
                return Error{ErrorCode::resource_limit, "External call ABI register map exceeds its 256-register budget"};
        for (const auto reg : external.abi.caller_saved_registers)
            if (!add_external_register(reg))
                return Error{ErrorCode::resource_limit, "External call ABI register map exceeds its 256-register budget"};
        for (const auto result : {external.abi.integer_return_register, external.abi.floating_return_register,
                                  external.abi.vector_return_register})
            if (result && !add_external_register(*result))
                return Error{ErrorCode::resource_limit, "External call ABI register map exceeds its 256-register budget"};
        if (const auto hidden = hidden_result_pointer_info(external.abi,
                                                           external.prototype->result_type());
            hidden && !add_external_register(hidden->reg))
            return Error{ErrorCode::resource_limit, "External hidden-result register map exceeds its 256-register budget"};
    }

    // An indirect target is usable only when its value is proven to be one
    // exact pointer-width constant across every incoming path and that offset
    // identifies one callable entry across every represented address space.
    const auto constant_call_target = [&](const ExpressionPtr &expression,
            const AbiDescription &caller_abi) -> std::optional<EntryKey> {
        if (!expression || !caller_abi.pointer_bits) return {};
        const auto *constant = std::get_if<ConstantValue>(&expression->value);
        if (!constant || constant->type.bits != caller_abi.pointer_bits ||
            (constant->type.kind != TypeKind::pointer && constant->type.kind != TypeKind::integer)) return {};
        std::optional<EntryKey> match;
        for (const auto &[entry, index] : entries) {
            (void)index;
            if (entry.second != constant->value) continue;
            if (match && *match != entry) return {};
            match = entry;
        }
        for (const auto &[entry, external] : external_entries) {
            (void)external;
            if (entry.second != constant->value) continue;
            if (match && *match != entry) return {};
            match = entry;
        }
        return match;
    };
    const auto indirect_target_abi_compatible = [&](const EntryKey &entry,
            const AbiDescription &caller_abi) {
        if (const auto recovered = entries.find(entry); recovered != entries.end())
            return same_abi(caller_abi, abis[recovered->second]);
        const auto external = external_entries.find(entry);
        return external != external_entries.end() && !external->second.ambiguous &&
            same_abi(caller_abi, external->second.abi);
    };

    std::vector<LiftedFunction> raw(functions.begin(), functions.end());

    // For target-resolution SSA, conservatively model every candidate ABI
    // that uses the caller's register file. This prevents a target held in a
    // register from surviving a call that could clobber it under a different
    // convention. The normal analysis below later narrows call effects to
    // the resolved call graph.
    using RegisterFileKey = std::pair<std::uint16_t, std::vector<unsigned>>;
    const auto register_file_key = [](const AbiDescription &abi) {
        std::set<unsigned> banks;
        const auto add = [&](RegisterOperand reg) { banks.insert(static_cast<unsigned>(reg.bank)); };
        for (const auto reg : abi.integer_argument_registers) add(reg);
        for (const auto reg : abi.floating_argument_registers) add(reg);
        for (const auto reg : abi.vector_argument_registers) add(reg);
        for (const auto reg : abi.caller_saved_registers) add(reg);
        if (abi.integer_return_register) add(*abi.integer_return_register);
        if (abi.floating_return_register) add(*abi.floating_return_register);
        if (abi.vector_return_register) add(*abi.vector_return_register);
        if (abi.stack_argument_base) add(*abi.stack_argument_base);
        for (const auto &slot : abi.arguments) if (slot.reg) add(*slot.reg);
        return RegisterFileKey{abi.pointer_bits, std::vector<unsigned>(banks.begin(), banks.end())};
    };
    std::map<RegisterFileKey, std::map<std::tuple<unsigned, unsigned, unsigned, bool>, RegisterOperand>>
        target_clobbers_by_file;
    const auto add_target_clobbers = [&](const AbiDescription &abi) {
        if (!abi.pointer_bits) return;
        auto &registers = target_clobbers_by_file[register_file_key(abi)];
        for (const auto reg : abi.caller_saved_registers)
            if (reg.width)
                registers[{static_cast<unsigned>(reg.bank), reg.index, reg.width, reg.high_byte}] = reg;
    };
    for (const auto &abi : abis) add_target_clobbers(abi);
    for (const auto &[address, external] : external_entries) {
        (void)address;
        add_target_clobbers(external.abi);
    }
    std::vector<AbiDescription> target_call_effect_abis(abis.begin(), abis.end());
    for (std::size_t i = 0; i < abis.size(); ++i) {
        const auto clobbers = target_clobbers_by_file.find(register_file_key(abis[i]));
        if (clobbers == target_clobbers_by_file.end()) continue;
        if (clobbers->second.size() > 256)
            return Error{ErrorCode::resource_limit, "Indirect-call target analysis exceeds its 256-register clobber budget"};
        target_call_effect_abis[i].caller_saved_registers.clear();
        for (const auto &[clobber_key, reg] : clobbers->second) {
            (void)clobber_key;
            target_call_effect_abis[i].caller_saved_registers.push_back(reg);
        }
    }

    std::vector<std::vector<std::size_t>> call_graph(functions.size());
    std::vector<std::size_t> resolved_indirect_calls(functions.size());
    std::size_t call_count = 0;
    for (std::size_t caller = 0; caller < raw.size(); ++caller) {
        bool has_indirect_call = false;
        for (auto &block : raw[caller].blocks) for (auto &instruction : block.instructions)
            if (auto *call = std::get_if<Call>(&instruction.statement)) {
                call->register_inputs.clear();
                call->return_register.reset();
                call->return_version.reset();
                call->result_type.reset();
                has_indirect_call |= !call->direct_target && static_cast<bool>(call->indirect_target);
            }
        std::optional<LiftedFunction> target_ssa;
        if (has_indirect_call) {
            auto target_effects = prepare_call_effects(raw[caller], target_call_effect_abis[caller]);
            if (!target_effects) return target_effects.error();
            auto converted_targets = to_ssa(target_effects.value());
            if (!converted_targets) return converted_targets.error();
            target_ssa.emplace(std::move(converted_targets.value()));
        }

        std::map<Key, ExpressionPtr> target_definitions;
        std::map<Key, std::vector<std::uint32_t>> target_phi_inputs;
        std::size_t target_fact_count = 0;
        if (target_ssa) for (const auto &block : target_ssa->blocks) {
            for (const auto &phi : block.phis) {
                if (++target_fact_count > 500'000)
                    return Error{ErrorCode::resource_limit, "Indirect-call target analysis exceeds its 500,000-definition budget"};
                auto &inputs = target_phi_inputs[key(phi.destination, phi.version)];
                inputs.reserve(phi.inputs.size());
                for (const auto &input : phi.inputs) inputs.push_back(input.version);
            }
            for (const auto &instruction : block.instructions) {
                if (const auto *assignment = std::get_if<Assign>(&instruction.statement)) {
                    if (!assignment->destination_version) continue;
                    if (++target_fact_count > 500'000)
                        return Error{ErrorCode::resource_limit, "Indirect-call target analysis exceeds its 500,000-definition budget"};
                    target_definitions[key(assignment->destination, assignment->destination_version)] = assignment->value;
                }
            }
        }
        std::map<Key, std::optional<EntryKey>> target_cache;
        std::set<Key> target_active;
        std::function<std::optional<EntryKey>(const Key &, const RegisterOperand &, std::uint32_t)> resolve_target_value;
        resolve_target_value = [&](const Key &value_key, const RegisterOperand &reg,
                                   std::uint32_t depth) -> std::optional<EntryKey> {
            if (depth > 128 || target_active.contains(value_key)) return {};
            if (const auto cached = target_cache.find(value_key); cached != target_cache.end()) return cached->second;
            target_active.insert(value_key);
            std::optional<EntryKey> resolved;
            if (const auto definition = target_definitions.find(value_key); definition != target_definitions.end()) {
                const auto &expression = definition->second;
                if (const auto direct = constant_call_target(expression, abis[caller])) resolved = direct;
                else if (expression) {
                    if (const auto *source = std::get_if<RegisterValue>(&expression->value))
                        resolved = resolve_target_value(key(source->reg, source->version), source->reg, depth + 1);
                }
            } else if (const auto phi = target_phi_inputs.find(value_key);
                       phi != target_phi_inputs.end() && !phi->second.empty()) {
                bool all_same = true;
                for (const auto version : phi->second) {
                    const auto incoming = resolve_target_value(key(reg, version), reg, depth + 1);
                    if (!incoming || (resolved && *resolved != *incoming)) {
                        all_same = false;
                        break;
                    }
                    resolved = incoming;
                }
                if (!all_same) resolved.reset();
            }
            target_active.erase(value_key);
            target_cache.emplace(value_key, resolved);
            return resolved;
        };
        for (std::size_t block_index = 0; block_index < raw[caller].blocks.size(); ++block_index) {
            auto &raw_block = raw[caller].blocks[block_index];
            if (target_ssa && (block_index >= target_ssa->blocks.size() ||
                raw_block.instructions.size() != target_ssa->blocks[block_index].instructions.size()))
                return Error{ErrorCode::malformed, "SSA target analysis changed instruction ordering"};
            const LiftedBlock *ssa_block = target_ssa ? &target_ssa->blocks[block_index] : nullptr;
            for (std::size_t instruction_index = 0; instruction_index < raw_block.instructions.size(); ++instruction_index) {
                auto *call = std::get_if<Call>(&raw_block.instructions[instruction_index].statement);
                const auto *ssa_call = ssa_block
                    ? std::get_if<Call>(&ssa_block->instructions[instruction_index].statement) : nullptr;
                if (!call) continue;
                const bool was_indirect = !call->direct_target;
                if (!call->direct_target && ssa_call && ssa_call->indirect_target) {
                    const auto direct = constant_call_target(ssa_call->indirect_target, abis[caller]);
                    if (direct && indirect_target_abi_compatible(*direct, abis[caller]))
                        call->direct_target = Address{AddressSpaceId{direct->first}, direct->second};
                    else if (const auto *source = std::get_if<RegisterValue>(&ssa_call->indirect_target->value)) {
                        const auto resolved = resolve_target_value(key(source->reg, source->version), source->reg, 0);
                        if (resolved && indirect_target_abi_compatible(*resolved, abis[caller]))
                            call->direct_target = Address{AddressSpaceId{resolved->first}, resolved->second};
                    }
                }
                if (!call->direct_target) continue;
                if (was_indirect) ++resolved_indirect_calls[caller];
                const auto callee = entries.find(entry_key(*call->direct_target));
                if (callee == entries.end()) continue;
                if (++call_count > 250000)
                    return Error{ErrorCode::resource_limit, "Interprocedural call graph exceeds its 250,000-edge budget"};
                call_graph[caller].push_back(callee->second);
            }
        }
    }

    // A direct call follows the callee's calling convention. For a caller
    // that targets multiple conventions, use their union of volatile registers
    // so values never survive a call that its target may clobber. This can
    // discard extra facts when conventions differ, but remains conservative.
    std::vector<AbiDescription> call_effect_abis(abis.begin(), abis.end());
    for (std::size_t caller = 0; caller < raw.size(); ++caller) {
        std::map<std::tuple<unsigned, unsigned, unsigned, bool>, RegisterOperand> writes;
        for (const auto reg : call_effect_abis[caller].caller_saved_registers)
            writes[register_key(reg)] = reg;
        for (const auto callee : call_graph[caller]) {
            if (!same_register_file(abis[caller], abis[callee])) continue;
            for (const auto reg : abis[callee].caller_saved_registers)
                writes[register_key(reg)] = reg;
            if (abis[callee].name == "x86-64 Windows")
                call_effect_abis[caller].name = "x86-64 Windows";
        }
        for (const auto &block : raw[caller].blocks) for (const auto &instruction : block.instructions) {
            const auto *call = std::get_if<Call>(&instruction.statement);
            if (!call || !call->direct_target || entries.contains(entry_key(*call->direct_target))) continue;
            const auto external = external_entries.find(entry_key(*call->direct_target));
            if (external == external_entries.end() ||
                !same_register_file(abis[caller], external->second.abi)) continue;
            for (const auto reg : external->second.abi.caller_saved_registers)
                writes[register_key(reg)] = reg;
            if (external->second.abi.name == "x86-64 Windows")
                call_effect_abis[caller].name = "x86-64 Windows";
        }
        if (writes.size() > 256)
            return Error{ErrorCode::resource_limit, "Interprocedural target call-clobber union exceeds 256 registers"};
        call_effect_abis[caller].caller_saved_registers.clear();
        for (const auto &[reg_key, reg] : writes) {
            (void)reg_key;
            call_effect_abis[caller].caller_saved_registers.push_back(reg);
        }
    }

    // Tarjan SCCs let unknown values on recursive edges remain pending while
    // an external, observed call site supplies the seed type.
    const auto count = raw.size();
    std::vector<int> visit_index(count, -1), low_link(count, -1), component(count, -1);
    std::vector<std::size_t> stack;
    std::vector<bool> on_stack(count, false);
    std::vector<std::size_t> component_size;
    int next_index = 0;
    std::function<void(std::size_t)> strong_connect = [&](std::size_t node) {
        visit_index[node] = low_link[node] = next_index++;
        stack.push_back(node);
        on_stack[node] = true;
        for (const auto target : call_graph[node]) {
            if (visit_index[target] < 0) {
                strong_connect(target);
                low_link[node] = std::min(low_link[node], low_link[target]);
            } else if (on_stack[target]) low_link[node] = std::min(low_link[node], visit_index[target]);
        }
        if (low_link[node] != visit_index[node]) return;
        const auto id = static_cast<int>(component_size.size());
        std::size_t size = 0;
        for (;;) {
            const auto member = stack.back();
            stack.pop_back();
            on_stack[member] = false;
            component[member] = id;
            ++size;
            if (member == node) break;
        }
        component_size.push_back(size);
    };
    for (std::size_t i = 0; i < count; ++i) if (visit_index[i] < 0) strong_connect(i);
    const auto recursive_edge = [&](std::size_t caller, std::size_t callee) {
        return component[caller] == component[callee] &&
            (component_size[static_cast<std::size_t>(component[caller])] > 1 || caller == callee);
    };

    std::vector<std::vector<types::TypePtr>> constraints(count);
    std::vector<std::vector<types::TypePtr>> baseline_parameter_types(count);
    std::vector<TypeRecoveryResult> current(count);
    for (std::size_t i = 0; i < count; ++i) {
        auto effects = prepare_call_effects(raw[i], call_effect_abis[i]);
        if (!effects) return effects.error();
        auto converted = to_ssa(effects.value(), tracked_registers);
        if (!converted) return converted.error();
        auto recovered = recover_types_impl(converted.value(), abis[i], explicit_prototypes[i]);
        if (!recovered) return recovered.error();
        current[i] = std::move(recovered.value());
        constraints[i].resize(abi_slots[i].size());
        baseline_parameter_types[i].resize(abi_slots[i].size());
        for (std::size_t slot = 0; slot < abi_slots[i].size(); ++slot) {
            if (!abi_slots[i][slot].reg) {
                if (!abi_slots[i][slot].stack_offset) continue;
                const auto parameter = abi_slots[i][slot].parameter_index.value_or(static_cast<std::uint16_t>(slot));
                if (current[i].inferred_prototype && parameter < current[i].inferred_prototype->parameters().size())
                    baseline_parameter_types[i][slot] = current[i].inferred_prototype->parameters()[parameter].type;
                for (const auto &variable : current[i].stack_variables) {
                    if (variable.offset != *abi_slots[i][slot].stack_offset || !variable.type) continue;
                    auto &baseline = baseline_parameter_types[i][slot];
                    if (!baseline) baseline = variable.type;
                    else if (!same_type(baseline, variable.type)) baseline = types::Type::void_type();
                }
                continue;
            }
            const auto variable = std::find_if(current[i].variables.begin(), current[i].variables.end(),
                [&](const RecoveredVariable &value) {
                    return value.reg == *abi_slots[i][slot].reg && value.version && *value.version == 0 &&
                           value.parameter_index == static_cast<std::uint32_t>(slot);
                });
            if (variable != current[i].variables.end()) baseline_parameter_types[i][slot] = variable->type;
        }
    }

    struct StackCallArgument { RegisterValue value; std::uint16_t bits = 0; };
    const auto stack_call_argument_value = [&](const AbiDescription &caller_abi,
            const LiftedBlock &block, std::size_t call_position, const Call &call,
            const AbiArgumentSlot &slot) -> std::optional<StackCallArgument> {
        if (!slot.stack_offset || !caller_abi.stack_argument_base || !caller_abi.pointer_bits) return {};
        const auto base = *caller_abi.stack_argument_base;
        const auto stack_input = std::find_if(call.register_inputs.begin(), call.register_inputs.end(),
            [&](const RegisterValue &value) { return value.reg == base; });
        if (stack_input == call.register_inputs.end()) return {};
        std::vector<PointerAlias> aliases;
        for (std::size_t i = 0; i < call_position; ++i)
            if (const auto *assignment = std::get_if<Assign>(&block.instructions[i].statement))
                if (auto alias = pointer_alias(*assignment)) aliases.push_back(*alias);
        const auto stack_pointer = canonical_stack_address(key(base, stack_input->version), aliases);
        if (!stack_pointer || (stack_pointer->first != key(base) && stack_pointer->first != key(base, 0))) return {};
        std::int64_t outgoing_offset = 0;
        if (!checked_add(stack_pointer->second, *slot.stack_offset, outgoing_offset) ||
            !checked_subtract(outgoing_offset, caller_abi.call_stack_adjustment, outgoing_offset)) return {};

        for (std::size_t cursor = call_position; cursor > 0;) {
            const auto &statement = block.instructions[--cursor].statement;
            if (std::holds_alternative<Call>(statement)) return {};
            if (const auto *intrinsic = std::get_if<Intrinsic>(&statement)) {
                if (intrinsic->memory_effect == IntrinsicMemoryEffect::write ||
                    intrinsic->memory_effect == IntrinsicMemoryEffect::unknown) return {};
                continue;
            }
            const auto *store = std::get_if<Store>(&statement);
            if (!store) continue;
            const auto *address = store->address ? std::get_if<MemoryValue>(&store->address->value) : nullptr;
            if (!address || !address->base || address->index || address->absolute) return {};
            const auto canonical = canonical_stack_address(key(*address->base, address->base_version), aliases);
            std::int64_t store_offset = 0;
            if (!canonical || canonical->first != stack_pointer->first ||
                !checked_add(canonical->second, address->displacement, store_offset)) return {};
            const std::uint16_t store_bits = store->value ? store->value->type.bits : std::uint16_t{0};
            if (!store_bits || store_bits % 8) return {};
            const auto store_bytes = static_cast<std::int64_t>(store_bits / 8);
            std::int64_t store_end = 0, slot_end = 0;
            if (!checked_add(store_offset, store_bytes, store_end) ||
                !checked_add(outgoing_offset, store_bytes, slot_end)) return {};
            if (store_end <= outgoing_offset || slot_end <= store_offset) continue;
            if (store_offset != outgoing_offset) return {};
            const auto *value = store->value ? std::get_if<RegisterValue>(&store->value->value) : nullptr;
            return value ? std::optional<StackCallArgument>{StackCallArgument{*value, store_bits}}
                         : std::optional<StackCallArgument>{};
        }
        return {};
    };

    bool converged = false;
    for (std::uint32_t iteration = 0; iteration < max_iterations; ++iteration) {
        std::vector<LiftedFunction> prepared = raw;
        for (std::size_t caller = 0; caller < prepared.size(); ++caller) {
            for (auto &block : prepared[caller].blocks) for (auto &instruction : block.instructions) {
                auto *call = std::get_if<Call>(&instruction.statement);
                if (!call || !call->direct_target) continue;
                const auto target = entries.find(entry_key(*call->direct_target));
                types::TypePtr type;
                const AbiDescription *target_abi = nullptr;
                if (target != entries.end()) {
                    const auto callee = target->second;
                    if (!same_register_file(abis[caller], abis[callee])) continue;
                    type = current[callee].return_type;
                    target_abi = &abis[callee];
                } else {
                    const auto external = external_entries.find(entry_key(*call->direct_target));
                    if (external == external_entries.end() || external->second.ambiguous ||
                        !same_register_file(abis[caller], external->second.abi)) continue;
                    type = external->second.prototype->result_type();
                    target_abi = &external->second.abi;
                }
                const auto result_register = returned_register(*target_abi, type);
                if (result_register) {
                    call->return_register = result_register;
                    call->result_type = type;
                    continue;
                }
                if (target_abi->name == "x86-64 System V" && sysv64_aggregate_return_pieces(type))
                    call->result_type = type;
                else if (target_abi->name == "AArch64 AAPCS64" && aapcs64_hfa_return_pieces(type))
                    call->result_type = type;
                else if (target_abi->name == "PowerPC64 ELFv2" && ppc64_aggregate_return_pieces(type))
                    call->result_type = type;
                else if (hidden_result_pointer_info(*target_abi, type))
                    call->result_type = type;
            }
        }

        std::vector<LiftedFunction> current_ssa;
        std::vector<TypeRecoveryResult> recovered;
        current_ssa.reserve(count);
        recovered.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            auto effects = prepare_call_effects(prepared[i], call_effect_abis[i]);
            if (!effects) return effects.error();
            auto converted = to_ssa(effects.value(), tracked_registers);
            if (!converted) return converted.error();
            std::vector<RegisterValue> known_inputs;
            std::set<Key> known_input_keys;
            std::map<Key, KnownTypedRegister> typed_argument_candidates;
            std::set<Key> ambiguous_typed_arguments;
            bool typed_argument_budget_exhausted = false;
            if (explicit_prototypes[i]) {
                const auto hidden = hidden_result_pointer_info(
                    abis[i], explicit_prototypes[i]->result_type());
                if (hidden) {
                    const RegisterValue incoming{hidden->reg, 0};
                    const auto incoming_key = key(incoming.reg, incoming.version);
                    typed_argument_candidates.emplace(incoming_key,
                        KnownTypedRegister{incoming, hidden->pointer_type});
                    known_input_keys.insert(incoming_key);
                    known_inputs.push_back(incoming);
                }
            }
            for (const auto &block : converted.value().blocks) for (std::size_t instruction_index = 0;
                    instruction_index < block.instructions.size(); ++instruction_index) {
                const auto &instruction = block.instructions[instruction_index];
                const auto *call = std::get_if<Call>(&instruction.statement);
                if (!call || !call->direct_target) continue;
                const auto target = entries.find(entry_key(*call->direct_target));
                types::TypePtr signature;
                const std::vector<AbiArgumentSlot> *target_slots = nullptr;
                const AbiDescription *target_abi = nullptr;
                std::vector<AbiArgumentSlot> classified_target_slots;
                if (target != entries.end()) {
                    const auto callee = target->second;
                    if (!same_register_file(abis[i], abis[callee])) continue;
                    signature = explicit_prototypes[callee]
                        ? explicit_prototypes[callee] : current[callee].inferred_prototype;
                    if (abis[callee].name == "AArch64 AAPCS64" && signature) {
                        classified_target_slots = slots_for(abis[callee], signature);
                        target_slots = &classified_target_slots;
                    } else target_slots = &abi_slots[callee];
                    target_abi = &abis[callee];
                } else {
                    const auto external = external_entries.find(entry_key(*call->direct_target));
                    if (external == external_entries.end() || external->second.ambiguous ||
                        !same_register_file(abis[i], external->second.abi)) continue;
                    signature = external->second.prototype;
                    target_slots = &external->second.slots;
                    target_abi = &external->second.abi;
                }
                if (!target_slots || !target_abi) continue;
                for (std::size_t slot_index = 0; slot_index < target_slots->size(); ++slot_index) {
                    const auto &argument_slot = (*target_slots)[slot_index];
                    if (!argument_slot.supported) continue;
                    const auto parameter_index = argument_slot.parameter_index.value_or(static_cast<std::uint16_t>(slot_index));
                    if (signature && parameter_index >= signature->parameters().size()) continue;
                    if (!signature && argument_slot.component_index) continue;
                    if (!argument_slot.reg) {
                        // The outgoing stack store is interpreted using the
                        // callee's classified slot, not the caller's own ABI
                        // argument map. Different conventions can therefore
                        // share stack evidence when the target slot is exact
                        // and the caller's direct store proof below matches it.
                        if (!signature || !argument_slot.stack_offset) continue;
                        const auto &parameter_type = signature->parameters()[parameter_index].type;
                        if (!matches_slot_class(argument_slot.value_class, unqualified_type(parameter_type))) continue;
                        const auto stacked = stack_call_argument_value(abis[i], block, instruction_index,
                                                                       *call, argument_slot);
                        if (!stacked || !type_bits(parameter_type) || stacked->bits != type_bits(parameter_type)) continue;
                        const auto actual_key = key(stacked->value.reg, stacked->value.version);
                        if (known_input_keys.insert(actual_key).second) known_inputs.push_back(stacked->value);
                        if (!typed_argument_candidates.contains(actual_key) && typed_argument_candidates.size() >= 4096) {
                            typed_argument_budget_exhausted = true;
                            continue;
                        }
                        const auto [candidate, inserted] = typed_argument_candidates.emplace(
                            actual_key, KnownTypedRegister{stacked->value, parameter_type});
                        if (!inserted && !same_type(candidate->second.type, parameter_type))
                            ambiguous_typed_arguments.insert(actual_key);
                        continue;
                    }
                    const auto actual = std::find_if(call->register_inputs.begin(), call->register_inputs.end(),
                        [&](const RegisterValue &value) { return value.reg == *argument_slot.reg; });
                    if (actual == call->register_inputs.end()) continue;
                    const auto actual_key = key(actual->reg, actual->version);
                    if (known_input_keys.insert(actual_key).second) known_inputs.push_back(*actual);
                    if (!signature) continue;
                    auto parameter_type = signature->parameters()[parameter_index].type;
                    if (argument_slot.component_offset && argument_slot.component_size) {
                        const auto projected_component = sysv64_component_type(parameter_type,
                            *argument_slot.component_offset, *argument_slot.component_size,
                            argument_slot.value_class);
                        if (!projected_component) continue;
                        parameter_type = *projected_component;
                    } else if (argument_slot.component_index) {
                        const auto components = hfa_float_elements(parameter_type);
                        if (!components || *argument_slot.component_index >= components->size()) continue;
                        parameter_type = (*components)[*argument_slot.component_index];
                    }
                    const auto classified_component = unqualified_type(parameter_type);
                    const auto slot_class = argument_slot.component_offset && classified_component &&
                        classified_component->kind() == types::Kind::vector
                        ? AbiValueClass::vector : argument_slot.value_class;
                    if (!matches_slot_class(slot_class, classified_component)) continue;
                    if (!typed_argument_candidates.contains(actual_key) && typed_argument_candidates.size() >= 4096) {
                        typed_argument_budget_exhausted = true;
                        continue;
                    }
                    const auto [candidate, inserted] = typed_argument_candidates.emplace(
                        actual_key, KnownTypedRegister{*actual, parameter_type});
                    if (!inserted && !same_type(candidate->second.type, parameter_type))
                        ambiguous_typed_arguments.insert(actual_key);
                }
                if (signature) {
                    const auto hidden = hidden_result_pointer_info(*target_abi, signature->result_type());
                    if (hidden) {
                        const auto actual = std::find_if(call->register_inputs.begin(), call->register_inputs.end(),
                            [&](const RegisterValue &value) { return value.reg == hidden->reg; });
                        if (actual != call->register_inputs.end()) {
                            const auto actual_key = key(actual->reg, actual->version);
                            if (known_input_keys.insert(actual_key).second) known_inputs.push_back(*actual);
                            if (!typed_argument_candidates.contains(actual_key) &&
                                typed_argument_candidates.size() >= 4096) {
                                typed_argument_budget_exhausted = true;
                            } else {
                                const auto [candidate, inserted] = typed_argument_candidates.emplace(
                                    actual_key, KnownTypedRegister{*actual, hidden->pointer_type});
                                if (!inserted && !same_type(candidate->second.type, hidden->pointer_type))
                                    ambiguous_typed_arguments.insert(actual_key);
                            }
                        }
                    }
                }
            }
            std::vector<KnownTypedRegister> known_argument_types;
            known_argument_types.reserve(typed_argument_candidates.size());
            for (const auto &[argument_key, candidate] : typed_argument_candidates) {
                if (ambiguous_typed_arguments.contains(argument_key)) continue;
                known_argument_types.push_back(candidate);
                if (known_input_keys.insert(argument_key).second) known_inputs.push_back(candidate.value);
            }
            auto typed = recover_types_impl(converted.value(), abis[i], explicit_prototypes[i], constraints[i],
                                            known_inputs, known_argument_types);
            if (!typed) return typed.error();
            if (typed_argument_budget_exhausted)
                typed.value().diagnostics.push_back("direct-call parameter type propagation reached its 4,096-value per-function limit");
            current_ssa.push_back(std::move(converted.value()));
            recovered.push_back(std::move(typed.value()));
        }

        struct Consensus {
            bool saw_type = false;
            bool valid = true;
            types::TypePtr type;
        };
        std::vector<std::vector<Consensus>> consensus(count);
        for (std::size_t callee = 0; callee < count; ++callee)
            consensus[callee].resize(abi_slots[callee].size());
        // A stack slot in the ABI map is only a location candidate. Require
        // the callee body to load that exact entry-relative slot at one
        // consistent width before accepting caller evidence for it.
        const auto callee_stack_load_bits = [&](std::size_t callee, std::int64_t wanted)
                -> std::optional<std::uint16_t> {
            const auto &abi = abis[callee];
            if (!abi.stack_argument_base) return {};
            std::vector<PointerAlias> aliases;
            for (const auto &block : current_ssa[callee].blocks)
                for (const auto &instruction : block.instructions)
                    if (const auto *assignment = std::get_if<Assign>(&instruction.statement))
                        if (auto alias = pointer_alias(*assignment)) aliases.push_back(*alias);
            std::optional<std::uint16_t> observed;
            std::vector<std::pair<std::int64_t, std::uint16_t>> layout;
            for (const auto &block : current_ssa[callee].blocks)
                for (const auto &instruction : block.instructions) {
                    const auto *assignment = std::get_if<Assign>(&instruction.statement);
                    const auto *memory = assignment && assignment->value
                        ? std::get_if<MemoryValue>(&assignment->value->value) : nullptr;
                    if (!memory || !memory->base || memory->index || memory->absolute ||
                        !memory->type.bits || memory->type.bits % 8) continue;
                    const auto canonical = canonical_stack_address(
                        key(*memory->base, memory->base_version), aliases);
                    if (!canonical || (canonical->first != key(*abi.stack_argument_base) &&
                                       canonical->first != key(*abi.stack_argument_base, 0))) continue;
                    std::int64_t offset = 0;
                    if (!checked_add(canonical->second, memory->displacement, offset)) continue;
                    const auto bits = memory->type.bits;
                    layout.emplace_back(offset, bits);
                    if (offset != wanted) continue;
                    if (observed && *observed != bits) return {};
                    observed = bits;
                }
            if (!observed) return {};
            const auto bytes = static_cast<std::int64_t>(*observed / 8);
            for (const auto &[offset, bits] : layout) {
                if (offset == wanted || !bits || bits % 8) continue;
                std::int64_t end = 0, wanted_end = 0;
                if (!checked_add(offset, bits / 8, end) || !checked_add(wanted, bytes, wanted_end)) return {};
                if (offset < wanted_end && wanted < end) return {};
            }
            return observed;
        };
        const auto stack_call_argument_type = [&](std::size_t caller, const LiftedBlock &block,
                std::size_t call_position, const Call &call, const AbiArgumentSlot &slot) -> types::TypePtr {
            if (!slot.stack_offset || !abis[caller].stack_argument_base || !abis[caller].pointer_bits ||
                !call.direct_target) return {};
            const auto base = *abis[caller].stack_argument_base;
            const auto stack_input = std::find_if(call.register_inputs.begin(), call.register_inputs.end(),
                [&](const RegisterValue &value) { return value.reg == base; });
            if (stack_input == call.register_inputs.end()) return {};
            std::vector<PointerAlias> aliases;
            for (std::size_t i = 0; i < call_position; ++i)
                if (const auto *assignment = std::get_if<Assign>(&block.instructions[i].statement))
                    if (auto alias = pointer_alias(*assignment)) aliases.push_back(*alias);
            const auto stack_pointer = canonical_stack_address(key(base, stack_input->version), aliases);
            if (!stack_pointer || (stack_pointer->first != key(base) && stack_pointer->first != key(base, 0))) return {};
            std::int64_t outgoing_offset = 0;
            if (!checked_add(stack_pointer->second, *slot.stack_offset, outgoing_offset) ||
                !checked_subtract(outgoing_offset, abis[caller].call_stack_adjustment, outgoing_offset)) return {};

            for (std::size_t cursor = call_position; cursor > 0;) {
                const auto &statement = block.instructions[--cursor].statement;
                if (std::holds_alternative<Call>(statement)) return {};
                if (const auto *intrinsic = std::get_if<Intrinsic>(&statement)) {
                    if (intrinsic->memory_effect == IntrinsicMemoryEffect::write ||
                        intrinsic->memory_effect == IntrinsicMemoryEffect::unknown) return {};
                    continue;
                }
                const auto *store = std::get_if<Store>(&statement);
                if (!store) continue;
                const auto *address = store->address ? std::get_if<MemoryValue>(&store->address->value) : nullptr;
                if (!address || !address->base || address->index || address->absolute) return {};
                const auto canonical = canonical_stack_address(key(*address->base, address->base_version), aliases);
                std::int64_t store_offset = 0;
                if (!canonical || canonical->first != stack_pointer->first ||
                    !checked_add(canonical->second, address->displacement, store_offset)) return {};
                const auto store_bits = store->value ? store->value->type.bits : 0;
                if (!store_bits || store_bits % 8) return {};
                const auto store_bytes = static_cast<std::int64_t>(store_bits / 8);
                std::int64_t store_end = 0, slot_end = 0;
                if (!checked_add(store_offset, store_bytes, store_end) ||
                    !checked_add(outgoing_offset, store_bytes, slot_end)) return {};
                if (store_end <= outgoing_offset || slot_end <= store_offset) continue;
                if (store_offset != outgoing_offset || store_bits > UINT16_MAX) return {};
                const auto *value = std::get_if<RegisterValue>(&store->value->value);
                if (!value) return {};
                const auto recovered_value = std::find_if(recovered[caller].variables.begin(), recovered[caller].variables.end(),
                    [&](const RecoveredVariable &variable) {
                        return variable.reg == value->reg && variable.version == value->version;
                    });
                return recovered_value != recovered[caller].variables.end() &&
                       type_bits(recovered_value->type) == store_bits &&
                       matches_slot_class(slot.value_class, unqualified_type(recovered_value->type))
                    ? recovered_value->type : types::TypePtr{};
            }
            return {};
        };
        for (std::size_t caller = 0; caller < count; ++caller) {
            for (const auto &block : current_ssa[caller].blocks) for (std::size_t instruction_index = 0;
                    instruction_index < block.instructions.size(); ++instruction_index) {
                const auto &instruction = block.instructions[instruction_index];
                const auto *call = std::get_if<Call>(&instruction.statement);
                if (!call || !call->direct_target) continue;
                const auto target = entries.find(entry_key(*call->direct_target));
                if (target == entries.end()) continue;
                const auto callee = target->second;
                const bool cycle = recursive_edge(caller, callee);
                const bool register_file_match = same_register_file(abis[caller], abis[callee]);
                for (std::size_t slot_index = 0; slot_index < abi_slots[callee].size(); ++slot_index) {
                    auto &candidate = consensus[callee][slot_index];
                    const auto &callee_slot = abi_slots[callee][slot_index];
                    if (!callee_slot.reg) {
                        if (!callee_slot.stack_offset || !register_file_match) {
                            candidate.valid = false;
                            continue;
                        }
                        const auto loaded_bits = callee_stack_load_bits(callee, *callee_slot.stack_offset);
                        if (!loaded_bits) {
                            candidate.valid = false;
                            continue;
                        }
                        const auto type = stack_call_argument_type(caller, block, instruction_index, *call, callee_slot);
                        if (!type) {
                            if (!cycle) candidate.valid = false;
                            continue;
                        }
                        if (type_bits(type) != *loaded_bits) {
                            candidate.valid = false;
                            continue;
                        }
                        if (!candidate.type) candidate.type = type;
                        else if (!same_type(candidate.type, type)) candidate.valid = false;
                        candidate.saw_type = true;
                        continue;
                    }
                    if (!register_file_match) {
                        candidate.valid = false;
                        continue;
                    }
                    const auto input = std::find_if(call->register_inputs.begin(), call->register_inputs.end(),
                        [&](const RegisterValue &value) { return value.reg == *callee_slot.reg; });
                    const RecoveredVariable *value = nullptr;
                    if (input != call->register_inputs.end()) {
                        const auto found = std::find_if(recovered[caller].variables.begin(), recovered[caller].variables.end(),
                            [&](const RecoveredVariable &variable) {
                                return variable.reg == input->reg && variable.version == input->version;
                            });
                        if (found != recovered[caller].variables.end()) value = &*found;
                    }
                    // A captured width is not proof that this register is an
                    // argument. Otherwise snapshot-only incoming values seed
                    // constraints that become self-justifying on the next pass.
                    if (!value || !value->type || !value->argument_evidence) {
                        if (!cycle) candidate.valid = false;
                        continue;
                    }
                    if (!matches_slot_class(callee_slot.value_class, unqualified_type(value->type))) {
                        candidate.valid = false;
                        continue;
                    }
                    if (!candidate.type) candidate.type = value->type;
                    else if (!same_type(candidate.type, value->type)) candidate.valid = false;
                    candidate.saw_type = true;
                }
            }
        }

        std::vector<std::vector<types::TypePtr>> next_constraints(count);
        for (std::size_t callee = 0; callee < count; ++callee) {
            next_constraints[callee].resize(abi_slots[callee].size());
            if (explicit_prototypes[callee]) continue;
            for (std::size_t slot = 0; slot < abi_slots[callee].size(); ++slot) {
                const auto &value = consensus[callee][slot];
                if (value.valid && value.saw_type &&
                    (!baseline_parameter_types[callee][slot] ||
                     same_type(baseline_parameter_types[callee][slot], value.type)))
                    next_constraints[callee][slot] = value.type;
            }
        }
        bool constraints_stable = true;
        for (std::size_t i = 0; i < count; ++i) {
            if (constraints[i].size() != next_constraints[i].size()) { constraints_stable = false; break; }
            for (std::size_t n = 0; n < constraints[i].size(); ++n)
                if (!same_type(constraints[i][n], next_constraints[i][n])) { constraints_stable = false; break; }
        }
        bool returns_stable = true;
        for (std::size_t i = 0; i < count; ++i)
            if (!same_type(current[i].return_type, recovered[i].return_type) ||
                !same_type(current[i].inferred_prototype, recovered[i].inferred_prototype)) {
                returns_stable = false; break;
            }
        current = std::move(recovered);
        constraints = std::move(next_constraints);
        if (constraints_stable && returns_stable) { converged = true; break; }
    }
    if (!converged)
        for (auto &result : current)
            result.diagnostics.push_back("interprocedural type propagation reached its configured iteration limit");
    for (std::size_t i = 0; i < count; ++i) {
        if (std::any_of(constraints[i].begin(), constraints[i].end(), [](const auto &type) { return static_cast<bool>(type); }))
            current[i].diagnostics.push_back("unanimous ABI argument types from compatible direct callers were applied");
        if (resolved_indirect_calls[i])
            current[i].diagnostics.push_back("resolved " + std::to_string(resolved_indirect_calls[i]) +
                " indirect call target(s) through unanimous SSA constants, copies, or joins");
    }
    return current;
    } catch (const std::bad_alloc &) {
        return Error{ErrorCode::resource_limit, "Interprocedural recovery could not allocate its bounded working set"};
    } catch (const std::length_error &) {
        return Error{ErrorCode::resource_limit, "Interprocedural recovery working set exceeds container limits"};
    }
}
} // namespace hexlab::decompiler
