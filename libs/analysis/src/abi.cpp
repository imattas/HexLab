#include "hexlab/analysis/abi.hpp"
#include "hexlab/types/layout.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <set>

namespace hexlab {
namespace {

bool is_x86_32(CallingConvention convention) {
    return convention == CallingConvention::x86_32_cdecl ||
           convention == CallingConvention::x86_32_stdcall ||
           convention == CallingConvention::x86_32_fastcall ||
           convention == CallingConvention::x86_32_thiscall ||
           convention == CallingConvention::x86_32_vectorcall;
}

bool is_vectorcall(CallingConvention convention) {
    return convention == CallingConvention::x86_32_vectorcall ||
           convention == CallingConvention::windows_x64_vectorcall;
}

const types::Type &unqualified(const types::Type &type) {
    return type.kind() == types::Kind::qualified && type.element()
        ? unqualified(*type.element()) : type;
}

bool is_riscv(CallingConvention convention) {
    return convention == CallingConvention::riscv32 || convention == CallingConvention::riscv64;
}

struct Scalar {
    bool supported = false;
    bool floating = false;
    std::uint64_t size = 0;
    std::string reason;
};

Scalar scalar_type(const types::Type &type, std::uint64_t pointer_size) {
    if (type.kind() == types::Kind::qualified && type.element())
        return scalar_type(*type.element(), pointer_size);
    const auto size = type.size().value_or(0);
    switch (type.kind()) {
    case types::Kind::boolean:
    case types::Kind::integer:
    case types::Kind::enumeration:
        if (size == 1 || size == 2 || size == 4 || size == 8)
            return {true, false, size, {}};
        return {false, false, size, "integer width is not supported by this classifier"};
    case types::Kind::pointer:
        if (size == pointer_size)
            return {true, false, size, {}};
        return {false, false, size, "pointer width does not match the selected ABI"};
    case types::Kind::floating:
        if (size == 4 || size == 8)
            return {true, true, size, {}};
        return {false, true, size, "only 32-bit and 64-bit floating scalars are supported"};
    case types::Kind::void_type:
        return {false, false, 0, "void is only valid as a function result"};
    default:
        return {false, false, size, "aggregate, array/vector, function, or unresolved type is unsupported"};
    }
}

std::string integer_register(CallingConvention convention, std::size_t index, std::uint64_t size) {
    static constexpr std::array<const char *, 6> sysv64{"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
    static constexpr std::array<const char *, 4> win64{"RCX", "RDX", "R8", "R9"};
    const char *parent = nullptr;
    std::size_t max = 0;
    max = convention == CallingConvention::sysv_x86_64 ? sysv64.size() : win64.size();
    if (index >= max) return {};
    if (convention == CallingConvention::sysv_x86_64) {
        parent = sysv64[index];
    } else {
        parent = win64[index];
    }
    if (size == 8) return parent;
    // The conventional low aliases are sufficient for scalar register lanes.
    static constexpr std::array<const char *, 4> low32{"EDI", "ESI", "EDX", "ECX"};
    static constexpr std::array<const char *, 4> low16{"DI", "SI", "DX", "CX"};
    static constexpr std::array<const char *, 4> low8{"DIL", "SIL", "DL", "CL"};
    if (convention == CallingConvention::windows_x64) {
        static constexpr std::array<const char *, 4> win32{"ECX", "EDX", "R8D", "R9D"};
        static constexpr std::array<const char *, 4> win16{"CX", "DX", "R8W", "R9W"};
        static constexpr std::array<const char *, 4> win8{"CL", "DL", "R8B", "R9B"};
        return size == 4 ? win32[index] : size == 2 ? win16[index] : win8[index];
    }
    if (index >= 4) {
        if (size == 4) return index == 4 ? "R8D" : "R9D";
        if (size == 2) return index == 4 ? "R8W" : "R9W";
        return index == 4 ? "R8B" : "R9B";
    }
    return size == 4 ? low32[index] : size == 2 ? low16[index] : low8[index];
}

AbiLocation reg_location(std::string name, std::uint64_t size, std::uint64_t value_offset = 0,
                         std::uint64_t placement_size = 0,
                         AbiLocationRole role = AbiLocationRole::value) {
    const auto register_width = placement_size ? placement_size : size;
    return {AbiLocationKind::register_, std::move(name), 0, size,
            std::min<std::uint64_t>(register_width, 8), value_offset, placement_size, role};
}
AbiLocation stack_location(std::uint64_t offset, std::uint64_t size, std::uint64_t alignment,
                           std::uint64_t value_offset = 0, std::uint64_t placement_size = 0,
                           AbiLocationRole role = AbiLocationRole::value) {
    return {AbiLocationKind::stack, {}, offset, size, alignment, value_offset, placement_size, role};
}
AbiValueLocation unsupported(std::string reason) {
    return {false, std::move(reason), {}};
}

bool power_of_two(std::uint64_t value) {
    return value && (value & (value - 1)) == 0;
}

std::optional<AbiLocation> reserve_stack(std::uint64_t &cursor, std::uint64_t size,
                                         std::uint64_t alignment, std::uint64_t slot_alignment) {
    if (!power_of_two(alignment) || !power_of_two(slot_alignment) ||
        size > std::numeric_limits<std::uint64_t>::max() - (slot_alignment - 1))
        return std::nullopt;
    const auto aligned_cursor = cursor > std::numeric_limits<std::uint64_t>::max() - (alignment - 1)
        ? std::numeric_limits<std::uint64_t>::max()
        : (cursor + alignment - 1) & ~(alignment - 1);
    const auto slot_size = (size + slot_alignment - 1) & ~(slot_alignment - 1);
    if (aligned_cursor == std::numeric_limits<std::uint64_t>::max() ||
        slot_size > std::numeric_limits<std::uint64_t>::max() - aligned_cursor)
        return std::nullopt;
    const auto location = stack_location(aligned_cursor, size, alignment);
    cursor = aligned_cursor + slot_size;
    return location;
}

enum class SysvClass { none, integer, sse, sse_up, memory };

bool is_aggregate(const types::Type &type) {
    const auto &value = unqualified(type);
    return value.kind() == types::Kind::structure || value.kind() == types::Kind::union_type ||
           value.kind() == types::Kind::array;
}

std::optional<std::uint64_t> sysv_x64_vector_width(const types::Type &source) {
    const auto &type = unqualified(source);
    if (type.kind() != types::Kind::vector || !type.element() || !type.size()) return std::nullopt;
    const auto width = *type.size();
    const auto &lane = unqualified(*type.element());
    if ((width != 8 && width != 16) || type.alignment() != width ||
        (lane.kind() != types::Kind::integer && lane.kind() != types::Kind::floating) ||
        !lane.size() || (*lane.size() != 4 && *lane.size() != 8) ||
        !type.count() || type.count() != width / *lane.size()) return std::nullopt;
    return width;
}

bool windows_x64_vector_argument(const types::Type &source) {
    const auto &type = unqualified(source);
    if (type.kind() != types::Kind::vector || !type.element() || !type.size() || *type.size() != 16 ||
        type.alignment() != 16) return false;
    const auto &lane = unqualified(*type.element());
    return (lane.kind() == types::Kind::integer || lane.kind() == types::Kind::floating) &&
           lane.size() && (*lane.size() == 4 || *lane.size() == 8) && type.count() == 16 / *lane.size();
}

std::optional<std::uint64_t> aapcs64_vector_width(const types::Type &source) {
    const auto &type = unqualified(source);
    if (type.kind() != types::Kind::vector || !type.element() || !type.size()) return std::nullopt;
    const auto width = *type.size();
    const auto &lane = unqualified(*type.element());
    if ((width != 8 && width != 16) || type.alignment() != width ||
        (lane.kind() != types::Kind::integer && lane.kind() != types::Kind::floating) ||
        !lane.size() || (*lane.size() != 4 && *lane.size() != 8) ||
        !type.count() || type.count() != width / *lane.size()) return std::nullopt;
    return width;
}

struct VectorCallVector {
    std::uint64_t size = 0;
    std::uint64_t alignment = 0;
};

std::optional<VectorCallVector> vectorcall_vector(const types::Type &source) {
    const auto &type = unqualified(source);
    if (type.kind() == types::Kind::floating) {
        const auto size = type.size().value_or(0);
        if ((size == 4 || size == 8) && type.alignment() == size)
            return VectorCallVector{size, type.alignment()};
        return std::nullopt;
    }
    if (type.kind() != types::Kind::vector || !type.element() || !type.size())
        return std::nullopt;
    const auto size = *type.size();
    const auto lane = unqualified(*type.element()).size().value_or(0);
    if ((size != 8 && size != 16 && size != 32) || type.alignment() != size ||
        !lane || lane > size || type.count() != size / lane)
        return std::nullopt;
    return VectorCallVector{size, type.alignment()};
}

bool contains_vectorcall_component(const types::Type &source, unsigned depth = 0) {
    if (depth > 64) return true;
    const auto &type = unqualified(source);
    if (vectorcall_vector(type)) return true;
    if (type.kind() == types::Kind::array)
        return type.element() && contains_vectorcall_component(*type.element(), depth + 1);
    if (type.kind() == types::Kind::structure || type.kind() == types::Kind::union_type)
        for (const auto &member : type.members())
            if (member.type && contains_vectorcall_component(*member.type, depth + 1)) return true;
    return false;
}

bool same_vector_type(const types::Type &left_source, const types::Type &right_source) {
    const auto &left = unqualified(left_source);
    const auto &right = unqualified(right_source);
    if (left.kind() != right.kind() || left.size() != right.size() ||
        left.alignment() != right.alignment())
        return false;
    if (left.kind() == types::Kind::floating)
        return left.name() == right.name();
    if (left.kind() != types::Kind::vector || left.count() != right.count() ||
        !left.element() || !right.element())
        return false;
    const auto &left_lane = unqualified(*left.element());
    const auto &right_lane = unqualified(*right.element());
    return left_lane.kind() == right_lane.kind() && left_lane.name() == right_lane.name() &&
           left_lane.size() == right_lane.size() && left_lane.alignment() == right_lane.alignment() &&
           left_lane.is_signed() == right_lane.is_signed();
}

struct VectorCallHva {
    const types::Type *element_type = nullptr;
    VectorCallVector vector;
    std::vector<std::uint64_t> offsets;
};

bool gather_vectorcall_hva(const types::Type &source, std::uint64_t base,
                           const types::TypeLayout *layout, types::Abi abi,
                           VectorCallHva &out, unsigned depth = 0) {
    if (depth > 64) return false;
    const auto &type = unqualified(source);
    if (vectorcall_vector(type)) {
        if (out.offsets.size() >= 4) return false;
        if (out.element_type && !same_vector_type(*out.element_type, type)) return false;
        out.element_type = &type;
        out.vector = *vectorcall_vector(type);
        if (base > std::numeric_limits<std::uint64_t>::max() - out.vector.size) return false;
        out.offsets.push_back(base);
        return true;
    }
    if (type.kind() == types::Kind::array) {
        if (!type.element() || !type.count() || !type.element()->size() ||
            type.count() > 4 || out.offsets.size() + type.count() > 4)
            return false;
        const auto stride = *type.element()->size();
        for (std::uint64_t i = 0; i < type.count(); ++i) {
            if (i && stride > (std::numeric_limits<std::uint64_t>::max() - base) / i) return false;
            if (!gather_vectorcall_hva(*type.element(), base + i * stride, nullptr, abi, out, depth + 1))
                return false;
        }
        return true;
    }
    if (type.kind() != types::Kind::structure || type.members().empty()) return false;
    types::TypeLayout computed;
    if (!layout) {
        auto value = types::layout(type, abi);
        if (!value) return false;
        computed = std::move(value.value());
        layout = &computed;
    }
    if (layout->members.size() != type.members().size()) return false;
    for (std::size_t i = 0; i < type.members().size(); ++i) {
        const auto &member = type.members()[i];
        if (!member.type || member.bit_width ||
            layout->members[i].offset > std::numeric_limits<std::uint64_t>::max() - base ||
            !gather_vectorcall_hva(*member.type, base + layout->members[i].offset,
                                   nullptr, abi, out, depth + 1))
            return false;
    }
    return true;
}

std::optional<VectorCallHva> vectorcall_hva(const types::Type &type, types::Abi abi) {
    VectorCallHva result;
    if (!gather_vectorcall_hva(type, 0, nullptr, abi, result) || !result.element_type ||
        result.offsets.empty() || result.offsets.size() > 4 ||
        unqualified(type).alignment() != result.vector.alignment)
        return std::nullopt;
    return result;
}

struct SysvAggregate {
    bool supported = false;
    std::uint64_t size = 0;
    std::vector<SysvClass> classes;
    std::string reason;
};

void merge_class(std::vector<SysvClass> &classes, std::uint64_t offset, std::uint64_t size,
                 SysvClass value) {
    if (size == 0 || value == SysvClass::none) return;
    const auto first = static_cast<std::size_t>(offset / 8);
    const auto last = static_cast<std::size_t>((offset + size - 1) / 8);
    for (auto i = first; i <= last && i < classes.size(); ++i) {
        if (classes[i] == SysvClass::memory) continue;
        if (value == SysvClass::integer || classes[i] == SysvClass::none ||
            (value == SysvClass::sse && classes[i] == SysvClass::sse_up))
            classes[i] = value;
    }
}

bool classify_sysv_part(const types::Type &type, std::uint64_t base,
                        std::vector<SysvClass> &classes, std::string &reason) {
    const auto &value = unqualified(type);
    if (value.kind() == types::Kind::named_reference) {
        reason = "unresolved named type cannot be classified";
        return false;
    }
    if (value.kind() == types::Kind::array) {
        if (!value.element() || !value.count()) { reason = "incomplete array cannot be classified"; return false; }
        auto element_layout = types::layout(*value.element(), types::Abi::x86_64);
        if (!element_layout) { reason = element_layout.error().message; return false; }
        for (std::uint64_t i = 0; i < value.count(); ++i) {
            if (i && element_layout.value().size > (std::numeric_limits<std::uint64_t>::max() - base) / i) {
                reason = "array element offset overflows"; return false;
            }
            if (!classify_sysv_part(*value.element(), base + i * element_layout.value().size, classes, reason)) return false;
        }
        return true;
    }
    if (value.kind() == types::Kind::structure || value.kind() == types::Kind::union_type) {
        auto object_layout = types::layout(value, types::Abi::x86_64);
        if (!object_layout) { reason = object_layout.error().message; return false; }
        for (std::size_t i = 0; i < value.members().size(); ++i) {
            const auto &member = value.members()[i];
            if (!member.type) { reason = "aggregate member has no type"; return false; }
            if (member.bit_width) { reason = "aggregate bitfields are not yet classified"; return false; }
            const auto &placed = object_layout.value().members[i];
            if (placed.offset > std::numeric_limits<std::uint64_t>::max() - base) {
                reason = "aggregate member offset overflows"; return false;
            }
            const auto member_offset = base + placed.offset;
            if (placed.alignment > 1 && member_offset % placed.alignment != 0) {
                std::fill(classes.begin(), classes.end(), SysvClass::memory);
                return true;
            }
            if (!classify_sysv_part(*member.type, member_offset, classes, reason)) return false;
        }
        return true;
    }
    const auto size = value.size().value_or(0);
    if (value.kind() == types::Kind::floating) {
        if (size != 4 && size != 8) { reason = "aggregate contains an unsupported floating format"; return false; }
        merge_class(classes, base, size, SysvClass::sse);
        return true;
    }
    if (value.kind() == types::Kind::vector) {
        const auto width = sysv_x64_vector_width(value);
        if (!width) { reason = "aggregate contains a vector outside the baseline 8/16-byte SSE shapes"; return false; }
        if (*width == 16 && base % 16 != 0) {
            std::fill(classes.begin(), classes.end(), SysvClass::memory);
            return true;
        }
        merge_class(classes, base, 8, SysvClass::sse);
        if (*width == 16)
            merge_class(classes, base + 8, 8, SysvClass::sse_up);
        return true;
    }
    if (value.kind() == types::Kind::integer || value.kind() == types::Kind::boolean ||
        value.kind() == types::Kind::enumeration || value.kind() == types::Kind::pointer) {
        if (!size) { reason = "aggregate contains an incomplete scalar"; return false; }
        merge_class(classes, base, size, SysvClass::integer);
        return true;
    }
    reason = "aggregate contains an unsupported member type";
    return false;
}

SysvAggregate classify_sysv_aggregate(const types::Type &type) {
    SysvAggregate out;
    auto object_layout = types::layout(type, types::Abi::x86_64);
    if (!object_layout) { out.reason = object_layout.error().message; return out; }
    out.size = object_layout.value().size;
    if (!out.size) { out.reason = "empty aggregates are not classified"; return out; }
    if (out.size > 16) { out.reason = "aggregate exceeds the two-eightbyte register limit"; out.classes = {SysvClass::memory}; out.supported = true; return out; }
    out.classes.resize(static_cast<std::size_t>((out.size + 7) / 8), SysvClass::none);
    if (!classify_sysv_part(type, 0, out.classes, out.reason)) return out;
    if (std::find(out.classes.begin(), out.classes.end(), SysvClass::memory) != out.classes.end()) {
        out.classes = {SysvClass::memory}; out.supported = true; return out;
    }
    for (auto &value : out.classes) if (value == SysvClass::none) value = SysvClass::integer;
    for (std::size_t i = 0; i < out.classes.size(); ++i)
        if (out.classes[i] == SysvClass::sse_up &&
            (i == 0 || (out.classes[i - 1] != SysvClass::sse && out.classes[i - 1] != SysvClass::sse_up)))
            out.classes[i] = SysvClass::sse;
    out.supported = true;
    return out;
}

AbiValueLocation classify_result(CallingConvention convention, const types::Type &type,
                                 std::uint64_t pointer_size, AbiValueLocation &hidden_result_pointer) {
    if (type.kind() == types::Kind::void_type) return {};
    if (!is_x86_32(convention) && unqualified(type).kind() == types::Kind::array)
        return unsupported("array result types are not valid function results");
    if (convention == CallingConvention::sysv_x86_64) {
        if (const auto width = sysv_x64_vector_width(type))
            return {true, {}, {reg_location("XMM0", *width, 0, 16)}};
        if (unqualified(type).kind() == types::Kind::vector)
            return unsupported("SysV AMD64 vector result requires a 8- or 16-byte baseline SSE vector shape; wider vectors need target feature metadata");
    }
    if (convention == CallingConvention::windows_x64 && windows_x64_vector_argument(type))
        return {true, {}, {reg_location("XMM0", 16, 0, 16)}};
    if (is_aggregate(type)) {
        if (convention == CallingConvention::sysv_x86_64) {
            const auto aggregate = classify_sysv_aggregate(type);
            if (!aggregate.supported) return unsupported(aggregate.reason);
            if (aggregate.classes.size() == 1 && aggregate.classes[0] == SysvClass::memory) {
                hidden_result_pointer = {true, {}, {
                    reg_location("RDI", 8, 0, 8, AbiLocationRole::hidden_result_argument)}};
                hidden_result_pointer.indirect = true;
                AbiValueLocation result{true, {}, {
                    reg_location("RAX", 8, 0, 8, AbiLocationRole::returned_buffer_address)}};
                result.indirect = true;
                return result;
            }
            AbiValueLocation result;
            std::size_t integer_return = 0, sse_return = 0;
            for (std::size_t i = 0; i < aggregate.classes.size(); ++i) {
                if (aggregate.classes[i] == SysvClass::sse_up)
                    continue;
                const auto offset = static_cast<std::uint64_t>(i) * 8;
                if (aggregate.classes[i] == SysvClass::sse) {
                    std::size_t end = i + 1;
                    while (end < aggregate.classes.size() && aggregate.classes[end] == SysvClass::sse_up) ++end;
                    const auto size = std::min<std::uint64_t>((end - i) * 8, aggregate.size - offset);
                    result.locations.push_back(reg_location("XMM" + std::to_string(sse_return++), size, offset,
                                                             end - i > 1 ? 16 : 0));
                } else {
                    const auto size = std::min<std::uint64_t>(8, aggregate.size - offset);
                    result.locations.push_back(reg_location(integer_return++ == 0 ? "RAX" : "RDX", size, offset));
                }
            }
            return result;
        }
        if (convention == CallingConvention::windows_x64) {
            auto object_layout = types::layout(type, types::Abi::x86_64);
            if (!object_layout) return unsupported(object_layout.error().message);
            const auto size = object_layout.value().size;
            if (size == 1 || size == 2 || size == 4 || size == 8)
                return {{true}, {}, {reg_location(size == 1 ? "AL" : size == 2 ? "AX" : size == 4 ? "EAX" : "RAX", size)}};
            hidden_result_pointer = {true, {}, {
                reg_location("RCX", 8, 0, 8, AbiLocationRole::hidden_result_argument)}};
            hidden_result_pointer.indirect = true;
            AbiValueLocation result{true, {}, {
                reg_location("RAX", 8, 0, 8, AbiLocationRole::returned_buffer_address)}};
            result.indirect = true;
            return result;
        }
        if (convention == CallingConvention::x86_32_fastcall ||
            convention == CallingConvention::x86_32_thiscall)
            return unsupported("aggregate result hidden-pointer placement is not modeled for this x86-32 convention");
        hidden_result_pointer = {true, {}, {stack_location(4, 4, 4, 0, 4,
                                                            AbiLocationRole::hidden_result_argument)}};
        hidden_result_pointer.indirect = true;
        AbiValueLocation result{true, {}, {}};
        result.indirect = true;
        return result;
    }
    const auto scalar = scalar_type(type, pointer_size);
    if (!scalar.supported) return unsupported(scalar.reason);
    if (is_x86_32(convention)) {
        if (scalar.floating) return {{true}, {}, {reg_location("ST0", scalar.size)}};
        if (scalar.size <= 4) return {{true}, {}, {reg_location(scalar.size == 1 ? "AL" : scalar.size == 2 ? "AX" : "EAX", scalar.size)}};
        return {{true}, {}, {reg_location("EAX", 4), reg_location("EDX", 4, 4)}};
    }
    if (scalar.floating)
        return {{true}, {}, {reg_location("XMM0", scalar.size)}};
    if (scalar.size > 8) return unsupported("integer return wider than 64 bits is unsupported");
    const auto name = scalar.size == 1 ? "AL" : scalar.size == 2 ? "AX" : scalar.size == 4 ? "EAX" : "RAX";
    return {{true}, {}, {reg_location(name, scalar.size)}};
}

const char *x86_integer_alias(std::size_t index, std::uint64_t size) {
    static constexpr const char *full[] = {"EAX", "EDX"};
    static constexpr const char *word[] = {"AX", "DX"};
    static constexpr const char *byte[] = {"AL", "DL"};
    if (index >= 2) return "";
    return size == 1 ? byte[index] : size == 2 ? word[index] : full[index];
}

std::string vectorcall_vector_register(std::size_t index, std::uint64_t size) {
    return std::string(size == 32 ? "YMM" : "XMM") + std::to_string(index);
}

std::uint64_t vectorcall_register_width(std::uint64_t value_size) {
    return value_size == 32 ? 32 : 16;
}

struct VectorCallArgument {
    enum class Kind { unsupported, vector, hva, integer, stack_value, aggregate, indirect_aggregate } kind = Kind::unsupported;
    VectorCallVector vector;
    std::optional<VectorCallHva> hva;
    Scalar scalar;
    std::uint64_t size = 0;
    std::uint64_t alignment = 1;
    std::string reason;
    bool by_reference = false;
    std::vector<AbiLocation> locations;
};

AbiValueLocation vectorcall_result(CallingConvention convention, const types::Type &source,
                                   std::uint64_t pointer_size, AbiValueLocation &hidden_result_pointer) {
    const auto &type = unqualified(source);
    if (type.kind() == types::Kind::void_type) return {};
    if (type.kind() == types::Kind::array)
        return unsupported("array types cannot be returned by value from a C/C++ function");
    if (type.kind() == types::Kind::union_type && contains_vectorcall_component(type))
        return unsupported("unions containing vector elements are not modeled as vectorcall HVAs");
    const auto abi = convention == CallingConvention::x86_32_vectorcall ? types::Abi::x86_32
                                                                        : types::Abi::x86_64;
    if (const auto vector = vectorcall_vector(type))
        return {true, {}, {reg_location(vectorcall_vector_register(0, vector->size),
                                         vector->size, 0, vectorcall_register_width(vector->size))}};
    if (const auto hva = vectorcall_hva(type, abi)) {
        AbiValueLocation result;
        for (std::size_t i = 0; i < hva->offsets.size(); ++i)
            result.locations.push_back(reg_location(vectorcall_vector_register(i, hva->vector.size),
                                                    hva->vector.size, hva->offsets[i],
                                                    vectorcall_register_width(hva->vector.size)));
        return result;
    }
    const auto scalar = scalar_type(type, pointer_size);
    if (scalar.supported) {
        if (scalar.floating)
            return {true, {}, {reg_location("XMM0", scalar.size, 0, 16)}};
        if (scalar.size <= pointer_size) {
            const auto name = convention == CallingConvention::x86_32_vectorcall
                ? (scalar.size == 1 ? "AL" : scalar.size == 2 ? "AX" : "EAX")
                : (scalar.size == 1 ? "AL" : scalar.size == 2 ? "AX" :
                   scalar.size == 4 ? "EAX" : "RAX");
            return {true, {}, {reg_location(name, scalar.size, 0, pointer_size)}};
        }
        if (convention == CallingConvention::x86_32_vectorcall && scalar.size == 8)
            return {true, {}, {reg_location("EAX", 4, 0, 4), reg_location("EDX", 4, 4, 4)}};
        return unsupported("integer return exceeds the vectorcall native register width");
    }
    if (type.kind() == types::Kind::structure || type.kind() == types::Kind::union_type) {
        auto layout = types::layout(type, abi);
        if (!layout) return unsupported(layout.error().message);
        if ((convention == CallingConvention::x86_32_vectorcall && layout.value().size <= 8) ||
            (convention == CallingConvention::windows_x64_vectorcall && layout.value().size <= pointer_size)) {
            if (convention == CallingConvention::x86_32_vectorcall && layout.value().size > 4)
                return {true, {}, {reg_location("EAX", 4, 0, 4),
                                   reg_location("EDX", layout.value().size - 4, 4, 4)}};
            if (convention == CallingConvention::x86_32_vectorcall)
                return {true, {}, {reg_location(layout.value().size == 1 ? "AL" :
                                                 layout.value().size == 2 ? "AX" : "EAX",
                                                 layout.value().size, 0, 4)}};
            return {true, {}, {reg_location("RAX", layout.value().size, 0, 8)}};
        }
        if (convention == CallingConvention::x86_32_vectorcall)
            return unsupported("indirect x86 vectorcall result location is not modeled");
        hidden_result_pointer = {true, {}, {
            reg_location("RCX", 8, 0, 8, AbiLocationRole::hidden_result_argument)}};
        hidden_result_pointer.indirect = true;
        AbiValueLocation result{true, {}, {
            reg_location("RAX", 8, 0, 8, AbiLocationRole::returned_buffer_address)}};
        result.indirect = true;
        return result;
    }
    return unsupported(scalar.reason.empty() ? "result type is not supported by vectorcall" : scalar.reason);
}

AbiSignatureClassification classify_vectorcall(CallingConvention convention,
                                                const types::Type &function_type) {
    const bool x86 = convention == CallingConvention::x86_32_vectorcall;
    const auto abi = x86 ? types::Abi::x86_32 : types::Abi::x86_64;
    const std::uint64_t pointer_size = x86 ? 4 : 8;
    AbiSignatureClassification out;
    out.convention = convention;
    out.pointer_size = static_cast<std::uint8_t>(pointer_size);
    out.stack_alignment = static_cast<std::uint8_t>(x86 ? 4 : 16);
    out.stack_slot_size = static_cast<std::uint8_t>(x86 ? 4 : 8);
    out.stack_cleanup = x86 ? AbiStackCleanup::callee : AbiStackCleanup::caller;
    if (!x86) out.shadow_space = 32;
    if (function_type.kind() != types::Kind::function || !function_type.result_type()) {
        out.complete = false;
        out.result = unsupported("input type is not a function signature");
        return out;
    }
    const auto &parameters = function_type.parameters();
    out.arguments.resize(parameters.size());
    if (function_type.variadic()) {
        out.result = unsupported("Microsoft vectorcall does not support variadic signatures");
        out.complete = false;
        for (auto &argument : out.arguments)
            argument = unsupported("Microsoft vectorcall does not support variadic signatures");
        return out;
    }
    out.result = vectorcall_result(convention, *function_type.result_type(), pointer_size,
                                   out.hidden_result_pointer);
    if (!out.result.supported) out.complete = false;
    if (!out.result.supported) {
        for (auto &argument : out.arguments)
            argument = unsupported("unsupported vectorcall result leaves hidden-result argument placement indeterminate");
        return out;
    }
    if (out.result.indirect && x86) {
        out.complete = false;
        for (auto &argument : out.arguments)
            argument = unsupported("indirect x86 vectorcall result makes argument placement indeterminate");
        return out;
    }
    const std::size_t hidden_integer_position = out.result.indirect ? 1 : 0;
    std::uint64_t stack_cursor = x86 ? 4 : 40;
    std::size_t x86_integer_index = 0;
    std::size_t x86_vector_index = 0;
    std::array<bool, 6> vector_register_used{};
    std::vector<VectorCallArgument> parsed;
    parsed.reserve(parameters.size());
    bool vector_bank_known = true;
    std::optional<std::size_t> first_unknown_parameter;
    for (std::size_t parameter_index = 0; parameter_index < parameters.size(); ++parameter_index) {
        const auto &parameter = parameters[parameter_index];
        VectorCallArgument argument;
        if (!parameter.type) {
            argument.reason = "parameter has no type";
            out.complete = false;
            vector_bank_known = false;
            if (!first_unknown_parameter) first_unknown_parameter = parameter_index;
            parsed.push_back(std::move(argument));
            continue;
        }
        const auto &type = unqualified(*parameter.type);
        if (type.kind() == types::Kind::array) {
            argument.reason = "array parameters require C/C++ array-to-pointer adjustment";
            out.complete = false;
            vector_bank_known = false;
        } else if (type.kind() == types::Kind::union_type && contains_vectorcall_component(type)) {
            argument.reason = "unions containing vector elements are not modeled as vectorcall HVAs";
            out.complete = false;
            vector_bank_known = false;
        } else if (const auto vector = vectorcall_vector(type)) {
            argument.kind = VectorCallArgument::Kind::vector;
            argument.vector = *vector;
        } else if (const auto hva = vectorcall_hva(type, abi)) {
            argument.kind = VectorCallArgument::Kind::hva;
            argument.hva = *hva;
        } else if (type.kind() == types::Kind::structure || type.kind() == types::Kind::union_type ||
                   type.kind() == types::Kind::array) {
            auto layout = types::layout(type, abi);
            if (!layout) {
                argument.reason = layout.error().message;
                out.complete = false;
                vector_bank_known = false;
            } else {
                argument.size = layout.value().size;
                argument.alignment = layout.value().alignment;
                argument.kind = VectorCallArgument::Kind::aggregate;
                if (argument.size > pointer_size && !x86) {
                    argument.kind = VectorCallArgument::Kind::indirect_aggregate;
                    argument.by_reference = true;
                }
            }
        } else {
            argument.scalar = scalar_type(type, pointer_size);
            if (argument.scalar.supported && argument.scalar.floating) {
                argument.kind = VectorCallArgument::Kind::vector;
                argument.vector = {argument.scalar.size, 16};
            } else if (argument.scalar.supported && !argument.scalar.floating &&
                       (argument.scalar.size <= pointer_size || x86)) {
                argument.kind = argument.scalar.size <= pointer_size
                    ? VectorCallArgument::Kind::integer : VectorCallArgument::Kind::stack_value;
                argument.size = argument.scalar.size;
                argument.alignment = std::min<std::uint64_t>(argument.size, pointer_size);
            } else {
                argument.reason = argument.scalar.reason.empty()
                    ? "parameter type is not supported by vectorcall" : argument.scalar.reason;
                out.complete = false;
                vector_bank_known = false;
            }
        }
        if (argument.kind == VectorCallArgument::Kind::unsupported && !first_unknown_parameter)
            first_unknown_parameter = parameter_index;
        parsed.push_back(std::move(argument));
    }

    // Microsoft allocates ordinary vector parameters before allocating HVA
    // members, leaving register holes for the HVA pass to use.
    for (std::size_t i = 0; i < parsed.size(); ++i) {
        auto &argument = parsed[i];
        if (argument.kind != VectorCallArgument::Kind::vector) continue;
        if (x86 && first_unknown_parameter && i > *first_unknown_parameter) {
            argument.kind = VectorCallArgument::Kind::unsupported;
            argument.reason = "an earlier unclassified x86 parameter makes vector-register allocation indeterminate";
            out.complete = false;
            continue;
        }
        std::optional<std::size_t> slot;
        if (x86) {
            if (x86_vector_index < vector_register_used.size()) slot = x86_vector_index++;
        } else {
            const auto position = i + hidden_integer_position;
            if (position < vector_register_used.size()) slot = position;
        }
        if (slot) {
            argument.locations.push_back(reg_location(vectorcall_vector_register(*slot, argument.vector.size),
                                                       argument.vector.size, 0,
                                                       vectorcall_register_width(argument.vector.size)));
            vector_register_used[*slot] = true;
        } else {
            argument.by_reference = true;
        }
    }
    for (auto &argument : parsed) {
        if (argument.kind != VectorCallArgument::Kind::hva) continue;
        if (!vector_bank_known) {
            argument.reason = "earlier unsupported aggregate makes HVA register allocation indeterminate";
            argument.kind = VectorCallArgument::Kind::unsupported;
            out.complete = false;
            continue;
        }
        std::vector<std::size_t> slots;
        for (std::size_t i = 0; i < vector_register_used.size(); ++i)
            if (!vector_register_used[i]) slots.push_back(i);
        if (slots.size() >= argument.hva->offsets.size()) {
            for (std::size_t i = 0; i < argument.hva->offsets.size(); ++i) {
                const auto slot = slots[i];
                argument.locations.push_back(reg_location(
                    vectorcall_vector_register(slot, argument.hva->vector.size),
                    argument.hva->vector.size, argument.hva->offsets[i],
                    vectorcall_register_width(argument.hva->vector.size)));
                vector_register_used[slot] = true;
            }
        } else {
            argument.by_reference = true;
        }
    }

    std::size_t vector_shadow_slots = 0;
    if (!x86) {
        for (std::size_t i = 0; i < parsed.size(); ++i) {
            const auto position = i + hidden_integer_position;
            if (position >= 4 && position < 6 &&
                parsed[i].kind == VectorCallArgument::Kind::vector &&
                !parsed[i].locations.empty())
                ++vector_shadow_slots;
            if (position >= 4 && parsed[i].kind == VectorCallArgument::Kind::hva &&
                !parsed[i].locations.empty())
                ++vector_shadow_slots;
        }
        if (vector_shadow_slots > (std::numeric_limits<std::uint16_t>::max() - 32) / 8) {
            out.complete = false;
            for (auto &argument : out.arguments)
                argument = unsupported("vectorcall shadow-space size overflows");
            return out;
        }
        out.shadow_space = static_cast<std::uint16_t>(32 + vector_shadow_slots * 8);
        stack_cursor = 8 + out.shadow_space;
    }

    for (std::size_t i = 0; i < parsed.size(); ++i) {
        auto &argument = parsed[i];
        if (argument.kind == VectorCallArgument::Kind::unsupported) {
            out.arguments[i] = unsupported(argument.reason.empty() ? "unsupported vectorcall parameter" : argument.reason);
            continue;
        }
        if (x86 && first_unknown_parameter && i > *first_unknown_parameter) {
            out.arguments[i] = unsupported(
                "an earlier unclassified x86 parameter makes register and stack placement indeterminate");
            out.complete = false;
            continue;
        }
        if (!argument.locations.empty()) {
            out.arguments[i] = {true, {}, std::move(argument.locations)};
            continue;
        }
        if (argument.kind == VectorCallArgument::Kind::integer ||
            (argument.kind == VectorCallArgument::Kind::aggregate && argument.size <= pointer_size)) {
            const auto value_size = argument.size;
            if (x86) {
                if (x86_integer_index < 2) {
                    const auto name = x86_integer_alias(x86_integer_index++, value_size);
                    out.arguments[i] = {true, {}, {reg_location(name, value_size, 0, 4)}};
                } else {
                    if (value_size > std::numeric_limits<std::uint64_t>::max() - 3) {
                        out.arguments[i] = unsupported("vectorcall stack integer size overflows");
                        out.complete = false;
                        continue;
                    }
                    const auto slot = (value_size + 3) & ~std::uint64_t(3);
                    if (slot > std::numeric_limits<std::uint64_t>::max() - stack_cursor) {
                        out.arguments[i] = unsupported("vectorcall stack argument offset overflows");
                        out.complete = false;
                    } else {
                        out.arguments[i] = {true, {}, {stack_location(stack_cursor, value_size, 4)}};
                        stack_cursor += slot;
                    }
                }
            } else {
                const auto position = i + hidden_integer_position;
                if (position < 4) {
                    const auto register_size = argument.kind == VectorCallArgument::Kind::aggregate ? 8 : value_size;
                    const auto name = argument.kind == VectorCallArgument::Kind::aggregate
                        ? integer_register(CallingConvention::windows_x64, position, 8)
                        : integer_register(CallingConvention::windows_x64, position, value_size);
                    out.arguments[i] = {true, {}, {reg_location(name, value_size, 0, register_size)}};
                } else {
                    if (8 > std::numeric_limits<std::uint64_t>::max() - stack_cursor) {
                        out.arguments[i] = unsupported("vectorcall stack argument offset overflows");
                        out.complete = false;
                    } else {
                        out.arguments[i] = {true, {}, {stack_location(stack_cursor, value_size, 8, 0, 8)}};
                        stack_cursor += 8;
                    }
                }
            }
            continue;
        }
        const bool by_reference = argument.by_reference ||
            argument.kind == VectorCallArgument::Kind::indirect_aggregate;
        if (x86) {
            if (argument.kind == VectorCallArgument::Kind::aggregate ||
                argument.kind == VectorCallArgument::Kind::stack_value) {
                if (argument.size > std::numeric_limits<std::uint64_t>::max() - 3) {
                    out.arguments[i] = unsupported("vectorcall aggregate stack size overflows");
                    out.complete = false;
                    continue;
                }
                const auto slot = (argument.size + 3) & ~std::uint64_t(3);
                if (slot > std::numeric_limits<std::uint64_t>::max() - stack_cursor) {
                    out.arguments[i] = unsupported("vectorcall aggregate stack offset overflows");
                    out.complete = false;
                } else {
                    out.arguments[i] = {true, {}, {stack_location(stack_cursor, argument.size,
                                                                  std::min<std::uint64_t>(4, argument.alignment))}};
                    stack_cursor += slot;
                }
            } else {
                if (pointer_size > std::numeric_limits<std::uint64_t>::max() - stack_cursor) {
                    out.arguments[i] = unsupported("vectorcall reference argument offset overflows");
                    out.complete = false;
                } else {
                    AbiValueLocation value{true, {}, {stack_location(stack_cursor, pointer_size, 4, 0, 4)}};
                    value.indirect = by_reference;
                    out.arguments[i] = std::move(value);
                    stack_cursor += pointer_size;
                }
            }
        } else if (by_reference && i + hidden_integer_position < 4 &&
                   argument.kind == VectorCallArgument::Kind::hva) {
            const auto position = i + hidden_integer_position;
            AbiValueLocation value{true, {}, {reg_location(integer_register(
                CallingConvention::windows_x64, position, 8), 8, 0, 8)}};
            value.indirect = true;
            out.arguments[i] = std::move(value);
        } else {
            const auto position = i + hidden_integer_position;
            if (!x86 && position < 4 && by_reference) {
                AbiValueLocation value{true, {}, {reg_location(integer_register(
                    CallingConvention::windows_x64, position, 8), 8, 0, 8)}};
                value.indirect = true;
                out.arguments[i] = std::move(value);
            } else {
                const auto stored_size = by_reference ? pointer_size : argument.size;
                const auto stored_alignment = by_reference ? pointer_size :
                    std::min<std::uint64_t>(16, std::max<std::uint64_t>(8, argument.alignment));
                const auto slot = std::max<std::uint64_t>(stored_size, 8);
                if (slot > std::numeric_limits<std::uint64_t>::max() - stack_cursor) {
                    out.arguments[i] = unsupported("vectorcall stack argument offset overflows");
                    out.complete = false;
                } else {
                    AbiValueLocation value{true, {}, {stack_location(stack_cursor, stored_size,
                                                                      stored_alignment, 0,
                                                                      by_reference ? pointer_size : 0)}};
                    value.indirect = by_reference;
                    out.arguments[i] = std::move(value);
                    stack_cursor += slot;
                }
            }
        }
    }
    out.stack_argument_bytes = stack_cursor - (x86 ? 4 : 8 + out.shadow_space);
    if (x86) out.callee_pop_bytes = out.stack_argument_bytes;
    return out;
}

struct AapcsHfa {
    std::uint64_t element_size = 0;
    std::vector<std::uint64_t> offsets;
};

bool gather_aapcs_hfa(const types::Type &type, std::uint64_t base,
                      const types::TypeLayout &layout, AapcsHfa &out) {
    if (type.kind() == types::Kind::floating) {
        const auto size = type.size().value_or(0);
        if (size != 2 && size != 4 && size != 8 && size != 16) return false;
        if (out.element_size && out.element_size != size) return false;
        out.element_size = size;
        // AAPCS64 counts uniquely addressable members. Union alternatives
        // share an address and represent one HFA element, not one element per
        // alternative.
        if (std::find(out.offsets.begin(), out.offsets.end(), base) == out.offsets.end()) {
            if (out.offsets.size() == 4) return false;
            out.offsets.push_back(base);
        }
        return true;
    }
    if (type.kind() == types::Kind::array) {
        if (!type.element() || !type.count()) return false;
        auto element_layout = types::layout(*type.element(), types::Abi::aarch64);
        if (!element_layout) return false;
        for (std::uint64_t i = 0; i < type.count(); ++i) {
            if (element_layout.value().size && i > (std::numeric_limits<std::uint64_t>::max() - base) / element_layout.value().size)
                return false;
            if (!gather_aapcs_hfa(*type.element(), base + i * element_layout.value().size,
                                  element_layout.value(), out)) return false;
        }
        return true;
    }
    if ((type.kind() != types::Kind::structure && type.kind() != types::Kind::union_type) || type.members().empty()) return false;
    for (std::size_t i = 0; i < type.members().size(); ++i) {
        const auto &member = type.members()[i];
        if (!member.type || member.bit_width || i >= layout.members.size()) return false;
        auto child_layout = types::layout(*member.type, types::Abi::aarch64);
        if (!child_layout || !gather_aapcs_hfa(*member.type, base + layout.members[i].offset,
                                               child_layout.value(), out)) return false;
    }
    return true;
}

std::optional<AapcsHfa> aapcs_hfa(const types::Type &type) {
    auto object_layout = types::layout(type, types::Abi::aarch64);
    if (!object_layout) return std::nullopt;
    AapcsHfa result;
    if (!gather_aapcs_hfa(type, 0, object_layout.value(), result) || result.offsets.empty() ||
        result.offsets.size() > 4) return std::nullopt;
    return result;
}

std::string aapcs_fp_register(std::size_t index, std::uint64_t size) {
    const char *prefix = size == 2 ? "H" : size == 4 ? "S" : size == 8 ? "D" : "Q";
    return std::string(prefix) + std::to_string(index);
}

Scalar aapcs_scalar(const types::Type &type) {
    if (type.kind() == types::Kind::floating) {
        const auto size = type.size().value_or(0);
        if (size == 2 || size == 4 || size == 8 || size == 16) return {true, true, size, {}};
        return {false, true, size, "floating scalar format is unsupported by AAPCS64 classification"};
    }
    if (type.kind() == types::Kind::integer || type.kind() == types::Kind::boolean ||
        type.kind() == types::Kind::enumeration) {
        const auto size = type.size().value_or(0);
        if (size == 1 || size == 2 || size == 4 || size == 8 || size == 16)
            return {true, false, size, {}};
        return {false, false, size, "integer width is unsupported by AAPCS64 classification"};
    }
    if (type.kind() == types::Kind::pointer) {
        if (type.size().value_or(0) == 8) return {true, false, 8, {}};
        return {false, false, type.size().value_or(0), "pointer width does not match AAPCS64"};
    }
    if (type.kind() == types::Kind::void_type)
        return {false, false, 0, "void is only valid as a function result"};
    return {false, false, type.size().value_or(0), "aggregate, vector, function, or unresolved type is unsupported"};
}

std::uint64_t align_stack(std::uint64_t value, std::uint64_t alignment) {
    const auto remainder = value & (alignment - 1);
    if (!remainder) return value;
    const auto padding = alignment - remainder;
    return padding > std::numeric_limits<std::uint64_t>::max() - value
        ? std::numeric_limits<std::uint64_t>::max() : value + padding;
}

AbiSignatureClassification classify_aapcs64(const types::Type &function_type) {
    AbiSignatureClassification out;
    // AAPCS64 keeps integer and SIMD allocation as independent register banks.
    out.convention = CallingConvention::aapcs64;
    out.pointer_size = 8;
    out.stack_alignment = 16;
    out.stack_slot_size = 8;
    if (function_type.kind() != types::Kind::function || !function_type.result_type()) {
        out.complete = false;
        out.result = unsupported("input type is not a function signature");
        return out;
    }

    const auto &parameters = function_type.parameters();
    out.arguments.reserve(parameters.size());
    if (function_type.variadic()) {
        out.result = unsupported("AAPCS64 variadic signatures are unsupported");
        out.complete = false;
        for (std::size_t i = 0; i < parameters.size(); ++i)
            out.arguments.push_back(unsupported("AAPCS64 variadic argument placement is unsupported"));
        return out;
    }

    const auto &return_type = *function_type.result_type();
    if (return_type.kind() == types::Kind::void_type) {
        out.result = {};
    } else if (is_aggregate(return_type)) {
        auto layout = types::layout(return_type, types::Abi::aarch64);
        if (!layout) out.result = unsupported(layout.error().message);
        else if (auto hfa = aapcs_hfa(return_type)) {
            for (std::size_t i = 0; i < hfa->offsets.size(); ++i)
                out.result.locations.push_back(reg_location(aapcs_fp_register(i, hfa->element_size),
                                                              hfa->element_size, hfa->offsets[i]));
        } else if (layout.value().size > 16) {
            out.hidden_result_pointer = {true, {}, {
                reg_location("X8", 8, 0, 8, AbiLocationRole::hidden_result_argument)}};
            out.hidden_result_pointer.indirect = true;
            out.result = {true, {}, {}};
            out.result.indirect = true;
        } else {
            for (std::uint64_t offset = 0; offset < layout.value().size; offset += 8)
                out.result.locations.push_back(reg_location(offset ? "X1" : "X0",
                    std::min<std::uint64_t>(8, layout.value().size - offset), offset));
        }
    } else if (const auto width = aapcs64_vector_width(return_type)) {
        out.result = {true, {}, {reg_location(aapcs_fp_register(0, *width), *width,
                                               0, *width)}};
    } else if (unqualified(return_type).kind() == types::Kind::vector) {
        out.result = unsupported("AAPCS64 vector return requires a naturally aligned 8- or 16-byte vector of 32- or 64-bit lanes");
    } else {
        const auto scalar = aapcs_scalar(return_type);
        if (!scalar.supported) out.result = unsupported(scalar.reason);
        else if (scalar.floating) out.result = {true, {}, {reg_location(aapcs_fp_register(0, scalar.size), scalar.size)}};
        else if (scalar.size == 16)
            out.result = {true, {}, {reg_location("X0", 8, 0), reg_location("X1", 8, 8)}};
        else out.result = {true, {}, {reg_location("X0", scalar.size)}};
    }
    if (!out.result.supported) out.complete = false;

    std::size_t gpr = 0, simd = 0;
    std::uint64_t stack = 0;
    bool placement_known = out.result.supported;
    auto stack_value = [&](std::uint64_t size, std::uint64_t alignment) {
        alignment = std::clamp<std::uint64_t>(alignment, 8, 16);
        const auto offset = align_stack(stack, alignment);
        if (offset == std::numeric_limits<std::uint64_t>::max() || size > std::numeric_limits<std::uint64_t>::max() - offset)
            return stack_location(offset, size, alignment);
        stack = offset + ((size + 7) & ~std::uint64_t(7));
        return stack_location(offset, size, alignment);
    };

    for (const auto &parameter : parameters) {
        if (!parameter.type) {
            out.arguments.push_back(unsupported("parameter has no type"));
            out.complete = placement_known = false;
            continue;
        }
        if (!placement_known) {
            out.arguments.push_back(unsupported("preceding unsupported value makes placement indeterminate"));
            continue;
        }
        const auto &type = *parameter.type;
        if (const auto width = aapcs64_vector_width(type)) {
            if (simd < 8)
                out.arguments.push_back({true, {}, {reg_location(aapcs_fp_register(simd++, *width),
                                                                  *width, 0, *width)}});
            else out.arguments.push_back({true, {}, {stack_value(*width, *width)}});
            continue;
        }
        if (unqualified(type).kind() == types::Kind::vector) {
            out.arguments.push_back(unsupported("AAPCS64 vector argument requires a naturally aligned 8- or 16-byte vector of 32- or 64-bit lanes"));
            out.complete = placement_known = false;
            continue;
        }
        if (is_aggregate(type)) {
            auto layout = types::layout(type, types::Abi::aarch64);
            if (!layout) {
                out.arguments.push_back(unsupported(layout.error().message));
                out.complete = placement_known = false;
                continue;
            }
            if (auto hfa = aapcs_hfa(type)) {
                if (simd + hfa->offsets.size() <= 8) {
                    AbiValueLocation value;
                    for (std::size_t i = 0; i < hfa->offsets.size(); ++i)
                        value.locations.push_back(reg_location(aapcs_fp_register(simd++, hfa->element_size),
                                                              hfa->element_size, hfa->offsets[i]));
                    out.arguments.push_back(std::move(value));
                } else {
                    simd = 8;
                    out.arguments.push_back({true, {}, {stack_value(layout.value().size, layout.value().alignment)}});
                }
                continue;
            }
            const bool indirect = layout.value().size > 16;
            const auto value_size = indirect ? std::uint64_t(8) : layout.value().size;
            std::size_t slots = static_cast<std::size_t>((value_size + 7) / 8);
            if (!indirect && layout.value().alignment >= 16 && (gpr & 1)) ++gpr;
            if (gpr + slots <= 8) {
                AbiValueLocation value;
                value.indirect = indirect;
                for (std::size_t i = 0; i < slots; ++i) {
                    const auto offset = static_cast<std::uint64_t>(i) * 8;
                    value.locations.push_back(reg_location("X" + std::to_string(gpr++),
                        indirect ? 8 : std::min<std::uint64_t>(8, value_size - offset), indirect ? 0 : offset));
                }
                out.arguments.push_back(std::move(value));
            } else {
                gpr = 8;
                out.arguments.push_back({true, {}, {stack_value(value_size, indirect ? 8 : layout.value().alignment)}});
                out.arguments.back().indirect = indirect;
            }
            continue;
        }
        const auto scalar = aapcs_scalar(type);
        if (!scalar.supported) {
            out.arguments.push_back(unsupported(scalar.reason));
            out.complete = placement_known = false;
            continue;
        }
        if (scalar.floating) {
            if (simd < 8) out.arguments.push_back({true, {}, {reg_location(aapcs_fp_register(simd++, scalar.size), scalar.size)}});
            else out.arguments.push_back({true, {}, {stack_value(scalar.size, 8)}});
        } else {
            if (scalar.size == 16) {
                if (type.alignment() >= 16 && (gpr & 1)) ++gpr;
                if (gpr < 7) {
                    AbiValueLocation value;
                    value.locations.push_back(reg_location("X" + std::to_string(gpr++), 8, 0));
                    value.locations.push_back(reg_location("X" + std::to_string(gpr++), 8, 8));
                    out.arguments.push_back(std::move(value));
                } else {
                    gpr = 8;
                    out.arguments.push_back({true, {}, {stack_value(16, std::max<std::uint64_t>(8, type.alignment()))}});
                }
            } else if (gpr < 8) {
                const auto name = "X" + std::to_string(gpr++);
                out.arguments.push_back({true, {}, {reg_location(name, scalar.size)}});
            }
            else out.arguments.push_back({true, {}, {stack_value(scalar.size, 8)}});
        }
    }
    out.stack_argument_bytes = stack;
    return out;
}

AbiSignatureClassification classify_aapcs32(const types::Type &function_type) {
    AbiSignatureClassification out;
    out.convention = CallingConvention::aapcs32;
    out.pointer_size = 4;
    out.stack_alignment = 8;
    out.stack_slot_size = 4;
    if (function_type.kind() != types::Kind::function || !function_type.result_type()) {
        out.complete = false;
        out.result = unsupported("input type is not a function signature");
        return out;
    }

    const auto &parameters = function_type.parameters();
    out.arguments.reserve(parameters.size());
    const auto &return_type = unqualified(*function_type.result_type());
    if (return_type.kind() == types::Kind::void_type) {
        out.result = {};
    } else if (return_type.kind() == types::Kind::structure ||
               return_type.kind() == types::Kind::union_type ||
               return_type.kind() == types::Kind::array) {
        auto object = types::layout(return_type, types::Abi::aarch32);
        if (!object) {
            out.result = unsupported(object.error().message);
        } else if (return_type.kind() == types::Kind::array) {
            out.result = unsupported("array result types are not valid function results");
        } else if (object.value().size <= 4) {
            out.result = {true, {}, {reg_location("R0", object.value().size, 0, 4)}};
        } else {
            out.hidden_result_pointer = {true, {}, {
                reg_location("R0", 4, 0, 4, AbiLocationRole::hidden_result_argument)}};
            out.hidden_result_pointer.indirect = true;
            out.result = {true, {}, {}};
            out.result.indirect = true;
        }
    } else {
        const auto scalar = scalar_type(return_type, 4);
        if (!scalar.supported) {
            out.result = unsupported(scalar.reason);
        } else if (scalar.size <= 4) {
            out.result = {true, {}, {reg_location("R0", scalar.size, 0, 4)}};
        } else if (scalar.size == 8) {
            out.result = {true, {}, {reg_location("R0", 4, 0, 4),
                                      reg_location("R1", 4, 4, 4)}};
        } else {
            out.result = unsupported("AAPCS32 base PCS scalar result exceeds two core registers");
        }
    }
    if (!out.result.supported) out.complete = false;

    std::size_t ncrn = out.result.indirect ? 1 : 0;
    std::uint64_t nsaa = 0;
    bool placement_known = out.result.supported;
    const auto append_word_locations = [&](AbiValueLocation &value, std::uint64_t value_size,
                                           std::uint64_t slot_size, std::uint64_t first_offset,
                                           std::size_t register_first, std::size_t register_count,
                                           std::uint64_t stack_first) {
        for (std::size_t word = 0; word < register_count; ++word) {
            const auto value_offset = first_offset + static_cast<std::uint64_t>(word) * 4;
            const auto part_size = value_offset < value_size
                ? std::min<std::uint64_t>(4, value_size - value_offset) : std::uint64_t{0};
            value.locations.push_back(reg_location("R" + std::to_string(register_first + word),
                                                    part_size, value_offset, 4));
        }
        const auto stack_words = static_cast<std::size_t>(
            (slot_size - first_offset - static_cast<std::uint64_t>(register_count) * 4) / 4);
        for (std::size_t word = 0; word < stack_words; ++word) {
            const auto value_offset = first_offset +
                (static_cast<std::uint64_t>(register_count) + word) * 4;
            const auto part_size = value_offset < value_size
                ? std::min<std::uint64_t>(4, value_size - value_offset) : std::uint64_t{0};
            value.locations.push_back(stack_location(stack_first + static_cast<std::uint64_t>(word) * 4,
                                                       part_size, 4, value_offset, 4));
        }
    };

    for (const auto &parameter : parameters) {
        if (!parameter.type) {
            out.arguments.push_back(unsupported("parameter has no type"));
            out.complete = placement_known = false;
            continue;
        }
        if (!placement_known) {
            out.arguments.push_back(unsupported("preceding unsupported value makes placement indeterminate"));
            continue;
        }

        const auto &type = unqualified(*parameter.type);
        if (type.kind() == types::Kind::array) {
            out.arguments.push_back(unsupported("array parameters require C/C++ array-to-pointer adjustment"));
            out.complete = placement_known = false;
            continue;
        }
        const bool aggregate = type.kind() == types::Kind::structure || type.kind() == types::Kind::union_type;
        std::uint64_t value_size = 0;
        std::uint64_t alignment = 4;
        if (aggregate) {
            auto object = types::layout(type, types::Abi::aarch32);
            if (!object || !object.value().size) {
                out.arguments.push_back(unsupported(object ? "zero-sized aggregate argument is unsupported"
                                                           : object.error().message));
                out.complete = placement_known = false;
                continue;
            }
            value_size = object.value().size;
            alignment = object.value().alignment;
        } else {
            const auto scalar = scalar_type(type, 4);
            if (!scalar.supported) {
                out.arguments.push_back(unsupported(scalar.reason));
                out.complete = placement_known = false;
                continue;
            }
            value_size = scalar.size;
            alignment = std::max<std::uint64_t>(4, type.alignment());
        }

        const auto slot_size = aggregate ? ((value_size + 3) & ~std::uint64_t(3))
                                         : std::max<std::uint64_t>(4, value_size);
        if (slot_size < value_size || slot_size > std::numeric_limits<std::uint64_t>::max() - 3) {
            out.arguments.push_back(unsupported("AAPCS32 argument size overflows"));
            out.complete = placement_known = false;
            continue;
        }
        const auto words64 = slot_size / 4;
        if (!words64 || words64 > std::numeric_limits<std::size_t>::max()) {
            out.arguments.push_back(unsupported("AAPCS32 argument word count is invalid"));
            out.complete = placement_known = false;
            continue;
        }
        const auto words = static_cast<std::size_t>(words64);
        const bool doubleword_aligned = alignment >= 8;
        if (doubleword_aligned && (ncrn & 1)) ++ncrn;
        const auto available = ncrn < 4 ? 4 - ncrn : 0;
        if (words <= available) {
            AbiValueLocation value{true, {}, {}};
            append_word_locations(value, value_size, slot_size, 0, ncrn, words, 0);
            ncrn += words;
            out.arguments.push_back(std::move(value));
            continue;
        }

        // AAPCS32 C.5 permits at most one composite argument to straddle the
        // final core registers and the stack, and only while no earlier value
        // has consumed stack argument space.
        if (aggregate && available && nsaa == 0) {
            AbiValueLocation value{true, {}, {}};
            append_word_locations(value, value_size, slot_size, 0, ncrn, available, 0);
            const auto register_bytes = static_cast<std::uint64_t>(available) * 4;
            const auto stack_bytes = slot_size - register_bytes;
            if (stack_bytes > std::numeric_limits<std::uint64_t>::max() - nsaa) {
                out.arguments.push_back(unsupported("AAPCS32 split aggregate stack extent overflows"));
                out.complete = placement_known = false;
                continue;
            }
            nsaa += stack_bytes;
            ncrn = 4;
            out.arguments.push_back(std::move(value));
            continue;
        }

        ncrn = 4;
        const auto stack_alignment = doubleword_aligned ? std::uint64_t{8} : std::uint64_t{4};
        const auto stack_at = align_stack(nsaa, stack_alignment);
        if (stack_at == std::numeric_limits<std::uint64_t>::max() ||
            slot_size > std::numeric_limits<std::uint64_t>::max() - stack_at) {
            out.arguments.push_back(unsupported("AAPCS32 stack argument placement overflows"));
            out.complete = placement_known = false;
            continue;
        }
        AbiValueLocation value{true, {}, {}};
        append_word_locations(value, value_size, slot_size, 0, 4, 0, stack_at);
        // append_word_locations with no register words emits all payload words
        // at successive 4-byte offsets from the aligned stack argument base.
        nsaa = stack_at + slot_size;
        out.arguments.push_back(std::move(value));
    }
    out.stack_argument_bytes = nsaa;
    return out;
}

AbiSignatureClassification classify_riscv_integer(CallingConvention convention,
                                                    const types::Type &function_type) {
    AbiSignatureClassification out;
    out.convention = convention;
    const bool rv32 = convention == CallingConvention::riscv32;
    const std::uint64_t xlen_bytes = rv32 ? 4 : 8;
    out.pointer_size = static_cast<std::uint8_t>(xlen_bytes);
    out.stack_alignment = 16;
    out.stack_slot_size = static_cast<std::uint8_t>(xlen_bytes);
    if (function_type.kind() != types::Kind::function || !function_type.result_type()) {
        out.complete = false;
        out.result = unsupported("input type is not a function signature");
        return out;
    }

    const auto &parameters = function_type.parameters();
    out.arguments.reserve(parameters.size());
    if (function_type.variadic()) {
        out.complete = false;
        out.result = unsupported("variadic RISC-V signatures are outside the base integer ABI model");
        for (std::size_t i = 0; i < parameters.size(); ++i)
            out.arguments.push_back(unsupported("variadic RISC-V parameter placement is unsupported"));
        return out;
    }

    struct ValueShape {
        bool supported = false;
        bool indirect = false;
        std::uint64_t size = 0;
        std::uint64_t alignment = 1;
        std::string reason;
    };
    const auto value_shape = [&](const types::Type &type, bool is_result) -> ValueShape {
        const types::Type *value_type = &type;
        while (value_type->kind() == types::Kind::qualified && value_type->element())
            value_type = value_type->element().get();
        if (value_type->kind() == types::Kind::void_type && is_result)
            return {true, false, 0, 1, {}};
        if (value_type->kind() == types::Kind::pointer) {
            const auto scalar = scalar_type(*value_type, xlen_bytes);
            if (!scalar.supported) return {false, false, scalar.size, value_type->alignment(), scalar.reason};
            return {true, false, scalar.size, value_type->alignment(), {}};
        }
        const auto size = value_type->size().value_or(0);
        if (!size)
            return {false, false, size, value_type->alignment(), "incomplete or empty value is unsupported"};
        switch (value_type->kind()) {
        case types::Kind::boolean:
        case types::Kind::integer:
        case types::Kind::enumeration:
            return {true, size > 2 * xlen_bytes, size, value_type->alignment(), {}};
        case types::Kind::floating:
        case types::Kind::array:
        case types::Kind::structure:
        case types::Kind::union_type:
            return {true, size > 2 * xlen_bytes, size, value_type->alignment(), {}};
        case types::Kind::vector:
            return {false, false, size, value_type->alignment(),
                    "vector values require an explicit vector calling convention"};
        case types::Kind::void_type:
            return {false, false, size, value_type->alignment(), "void is only valid as a function result"};
        default:
            return {false, false, size, value_type->alignment(),
                    "function or unresolved named type is unsupported"};
        }
    };
    const auto &return_type = *function_type.result_type();
    if (return_type.kind() == types::Kind::void_type) {
        out.result = {};
    } else {
        const auto shape = value_shape(return_type, true);
        if (!shape.supported) {
            out.result = unsupported(shape.reason);
            out.complete = false;
        } else {
            const auto first_size = std::min(xlen_bytes, shape.size);
            if (shape.indirect) {
                out.hidden_result_pointer = {true, {}, {
                    reg_location("A0", xlen_bytes, 0, xlen_bytes, AbiLocationRole::hidden_result_argument)}};
                out.hidden_result_pointer.indirect = true;
                out.result = {true, {}, {}};
                out.result.indirect = true;
            } else {
                out.result.locations.push_back(reg_location("A0", first_size, 0, xlen_bytes));
                if (shape.size > xlen_bytes)
                    out.result.locations.push_back(reg_location("A1", shape.size - xlen_bytes,
                                                                  xlen_bytes, xlen_bytes));
            }
        }
    }

    std::size_t argument_register = out.result.indirect ? 1 : 0;
    std::uint64_t stack_cursor = 0;
    bool placement_known = out.result.supported;
    const auto stack_location_for = [&](std::uint64_t size, std::uint64_t alignment,
                                        std::uint64_t value_offset = 0,
                                        std::uint64_t placement_size = 0) -> std::optional<AbiLocation> {
        const auto bounded_alignment = std::min<std::uint64_t>(
            std::max<std::uint64_t>(xlen_bytes, alignment), out.stack_alignment);
        const auto offset = align_stack(stack_cursor, bounded_alignment);
        const auto physical_size = placement_size ? placement_size : size;
        if (offset == std::numeric_limits<std::uint64_t>::max() ||
            physical_size > std::numeric_limits<std::uint64_t>::max() - (xlen_bytes - 1))
            return {};
        const auto allocated_size = align_stack(physical_size, xlen_bytes);
        if (allocated_size == std::numeric_limits<std::uint64_t>::max() ||
            allocated_size > std::numeric_limits<std::uint64_t>::max() - offset)
            return {};
        stack_cursor = offset + allocated_size;
        return stack_location(offset, size, bounded_alignment, value_offset, allocated_size);
    };

    for (const auto &parameter : parameters) {
        if (!parameter.type) {
            out.arguments.push_back(unsupported("parameter has no type"));
            out.complete = placement_known = false;
            continue;
        }
        const auto shape = value_shape(*parameter.type, false);
        if (!shape.supported) {
            out.arguments.push_back(unsupported(shape.reason));
            out.complete = placement_known = false;
            continue;
        }
        if (!placement_known) {
            out.arguments.push_back(unsupported(
                "preceding unsupported value may affect argument placement"));
            continue;
        }

        AbiValueLocation argument;
        const auto passed_size = shape.indirect ? xlen_bytes : shape.size;
        const auto alignment = shape.indirect ? xlen_bytes : shape.alignment;
        if (passed_size <= xlen_bytes) {
            if (argument_register < 8) {
                argument.locations.push_back(reg_location(
                    "A" + std::to_string(argument_register++),
                    passed_size, 0, xlen_bytes));
            } else {
                auto location = stack_location_for(passed_size, alignment, 0, xlen_bytes);
                if (!location) {
                    out.arguments.push_back(unsupported("RISC-V stack argument offset overflows"));
                    out.complete = placement_known = false;
                    continue;
                }
                argument.locations.push_back(*location);
            }
        } else if (passed_size <= 2 * xlen_bytes && argument_register < 8) {
            const auto first_size = std::min(xlen_bytes, passed_size);
            argument.locations.push_back(reg_location(
                "A" + std::to_string(argument_register++), first_size, 0, xlen_bytes));
            const auto remaining = passed_size - first_size;
            if (remaining) {
                if (argument_register < 8) {
                    argument.locations.push_back(reg_location(
                        "A" + std::to_string(argument_register++), remaining, first_size, xlen_bytes));
                } else {
                    auto high_part = stack_location_for(remaining, alignment, first_size, xlen_bytes);
                    if (!high_part) {
                        out.arguments.push_back(unsupported("RISC-V split stack argument offset overflows"));
                        out.complete = placement_known = false;
                        continue;
                    }
                    argument.locations.push_back(*high_part);
                }
            }
        } else {
            auto location = stack_location_for(passed_size, alignment, 0, passed_size);
            if (!location) {
                out.arguments.push_back(unsupported("RISC-V stack argument offset overflows"));
                out.complete = placement_known = false;
                continue;
            }
            argument.locations.push_back(*location);
        }
        argument.indirect = shape.indirect;
        out.arguments.push_back(std::move(argument));
    }
    out.stack_argument_bytes = stack_cursor;
    return out;
}

} // namespace

namespace {
AbiSignatureClassification classify_ppc64le_elfv2(const types::Type &function_type) {
    AbiSignatureClassification out;
    out.convention = CallingConvention::ppc64le_elfv2;
    out.pointer_size = 8;
    out.stack_alignment = 16;
    out.stack_slot_size = 8;
    out.stack_cleanup = AbiStackCleanup::caller;

    const auto fail_signature = [&](std::string reason) {
        out.complete = false;
        out.result = unsupported(reason);
        if (function_type.kind() == types::Kind::function)
            for (std::size_t i = 0; i < function_type.parameters().size(); ++i)
                out.arguments.push_back(unsupported(reason));
        return out;
    };
    if (function_type.kind() != types::Kind::function || !function_type.result_type())
        return fail_signature("input type is not a function signature");
    if (function_type.variadic())
        return fail_signature("PowerPC64 ELFv2 variadic placement is unsupported");
    if (function_type.function_convention() != types::FunctionConvention::platform_default &&
        function_type.function_convention() != types::FunctionConvention::c_decl)
        return fail_signature("function declaration requests a different calling convention");

    struct Shape {
        enum class Class { invalid, integer, floating, aggregate, void_result } cls = Class::invalid;
        std::uint64_t size = 0;
        std::string reason;
    };
    const auto shape = [&](const types::Type &source, bool result) {
        const auto &type = unqualified(source);
        Shape s;
        s.size = type.size().value_or(0);
        if (type.kind() == types::Kind::void_type && result) {
            s.cls = Shape::Class::void_result;
            return s;
        }
        if (!s.size || !power_of_two(type.alignment()) || type.alignment() > 8) {
            s.reason = "PowerPC64 ELFv2 value has incomplete size or unsupported alignment";
            return s;
        }
        switch (type.kind()) {
        case types::Kind::boolean:
        case types::Kind::integer:
        case types::Kind::enumeration:
            if (s.size == 1 || s.size == 2 || s.size == 4 || s.size == 8)
                s.cls = Shape::Class::integer;
            else s.reason = "PowerPC64 ELFv2 integer width is unsupported";
            break;
        case types::Kind::pointer:
            if (s.size == 8) s.cls = Shape::Class::integer;
            else s.reason = "pointer width does not match PowerPC64 ELFv2";
            break;
        case types::Kind::floating:
            // The type graph has no decimal/binary or long-double format tag.
            // Only these C spellings identify the two binary scalar formats.
            if ((s.size == 4 && type.name() == "float") ||
                (s.size == 8 && type.name() == "double"))
                s.cls = Shape::Class::floating;
            else s.reason = "only binary float and double are modeled for PowerPC64 ELFv2";
            break;
        case types::Kind::structure: {
            // Whole doubleword memory images avoid endian-dependent partial
            // aggregate slots; padding may still exist inside the image.
            // Reject classes with methods and all field classes needing special
            // float, vector, union, or bitfield treatment. The caller must
            // supply only C-compatible types; triviality is not modeled.
            if ((s.size != 8 && s.size != 16 && s.size != 24 && s.size != 32) ||
                type.members().empty() || !type.methods().empty()) {
                s.reason = "PowerPC64 ELFv2 aggregate is outside the bounded C-like layout subset";
                break;
            }
            bool valid = true;
            std::uint64_t end = 0;
            for (const auto &member : type.members()) {
                if (!member.type || member.bit_width || member.bit_offset ||
                    member.virtual_base || member.offset < end) { valid = false; break; }
                const auto &field = unqualified(*member.type);
                const auto field_size = field.size().value_or(0);
                if ((field.kind() != types::Kind::boolean &&
                     field.kind() != types::Kind::integer &&
                     field.kind() != types::Kind::enumeration &&
                     field.kind() != types::Kind::pointer) ||
                    (field_size != 1 && field_size != 2 && field_size != 4 && field_size != 8) ||
                    (field.kind() == types::Kind::pointer && field_size != 8) ||
                    !power_of_two(field.alignment()) || field.alignment() > 8 ||
                    member.offset > s.size || field_size > s.size - member.offset) {
                    valid = false;
                    break;
                }
                end = member.offset + field_size;
            }
            if (valid) s.cls = Shape::Class::aggregate;
            else s.reason = "PowerPC64 ELFv2 aggregate fields require unsupported layout rules";
            break;
        }
        default:
            s.reason = "PowerPC64 ELFv2 vector, complex, array, union, or unresolved value is unsupported";
            break;
        }
        return s;
    };

    const auto result = shape(*function_type.result_type(), true);
    if (result.cls == Shape::Class::invalid)
        return fail_signature(result.reason);
    if (result.cls == Shape::Class::integer)
        out.result.locations.push_back(reg_location("R3", result.size, 0, 8));
    else if (result.cls == Shape::Class::floating)
        out.result.locations.push_back(reg_location("F1", result.size, 0, 8));
    else if (result.cls == Shape::Class::aggregate) {
        if (result.size <= 16) {
            for (std::uint64_t part = 0; part < result.size / 8; ++part)
                out.result.locations.push_back(reg_location("R" + std::to_string(3 + part), 8, part * 8, 8));
        } else {
            out.result.indirect = true;
            out.hidden_result_pointer = {true, {}, {
                reg_location("R3", 8, 0, 8, AbiLocationRole::hidden_result_argument)}};
            out.hidden_result_pointer.indirect = true;
        }
    }

    // Each value occupies its parameter-save-area home, even when it uses FPRs.
    // The home doubleword index selects R3-R10 and then SP+32 onward.
    std::uint64_t slot = out.result.indirect ? 1 : 0;
    std::uint64_t next_fpr = 1;
    bool spilled = false;
    bool placement_known = true;
    for (const auto &parameter : function_type.parameters()) {
        if (!placement_known) {
            out.arguments.push_back(unsupported("preceding value makes PowerPC64 ELFv2 placement indeterminate"));
            continue;
        }
        if (!parameter.type) {
            out.arguments.push_back(unsupported("parameter has no type"));
            out.complete = placement_known = false;
            continue;
        }
        const auto value = shape(*parameter.type, false);
        if (value.cls == Shape::Class::invalid || value.cls == Shape::Class::void_result) {
            out.arguments.push_back(unsupported(value.reason.empty() ?
                "void is only valid as a function result" : value.reason));
            out.complete = placement_known = false;
            continue;
        }
        const auto words = value.cls == Shape::Class::aggregate ? value.size / 8 : 1;
        if (slot > (std::numeric_limits<std::uint64_t>::max() - 32) / 8 - words) {
            out.arguments.push_back(unsupported("PowerPC64 ELFv2 parameter area overflows"));
            out.complete = placement_known = false;
            continue;
        }
        AbiValueLocation argument;
        if (value.cls == Shape::Class::floating && next_fpr <= 13) {
            argument.locations.push_back(reg_location("F" + std::to_string(next_fpr++),
                                                     value.size, 0, 8));
        } else if (value.cls != Shape::Class::floating && slot < 8 && words == 1) {
            argument.locations.push_back(reg_location("R" + std::to_string(3 + slot),
                                                     value.size, 0, 8));
        } else {
            for (std::uint64_t part = 0; part < words; ++part) {
                const auto home = slot + part;
                const auto part_size = value.cls == Shape::Class::aggregate ? 8 : value.size;
                if (value.cls != Shape::Class::floating && home < 8)
                    argument.locations.push_back(reg_location("R" + std::to_string(3 + home),
                                                             part_size, part * 8, 8));
                else {
                    argument.locations.push_back(stack_location(32 + home * 8, part_size, 8,
                                                                part * 8, 8));
                    spilled = true;
                }
            }
        }
        slot += words;
        out.arguments.push_back(std::move(argument));
    }
    // Once a stack home is used, the caller reserves the whole parameter save
    // area, including its first eight doublewords.
    if (spilled) out.stack_argument_bytes = std::max<std::uint64_t>(64, slot * 8);
    return out;
}

AbiSignatureClassification classify_mips_n64(const types::Type &function_type) {
    AbiSignatureClassification out; out.convention = CallingConvention::mips_n64;
    out.pointer_size = 8; out.stack_alignment = 16; out.stack_slot_size = 8;
    if (function_type.kind() != types::Kind::function || !function_type.result_type()) {
        out.complete = false; out.result = unsupported("input type is not a function signature"); return out;
    }
    if (function_type.variadic()) {
        out.complete = false; out.result = unsupported("variadic Linux MIPS N64 classification is unsupported");
        for (std::size_t i = 0; i < function_type.parameters().size(); ++i)
            out.arguments.push_back(unsupported("variadic MIPS N64 parameter placement is unsupported"));
        return out;
    }
    struct Shape { bool ok=false, fp=false, aggregate=false, array=false; std::uint64_t size=0, alignment=1; std::string why; };
    const auto aggregate_has_unmodeled_class = [](const types::Type &root) {
        std::set<const types::Type *> active;
        std::function<bool(const types::Type &, unsigned)> visit = [&](const types::Type &source, unsigned depth) {
            if (depth > 32) return true;
            const auto &type = unqualified(source);
            if (type.kind() == types::Kind::floating || type.kind() == types::Kind::vector ||
                type.kind() == types::Kind::named_reference || type.kind() == types::Kind::function)
                return true;
            if (type.kind() == types::Kind::pointer || type.kind() == types::Kind::integer ||
                type.kind() == types::Kind::boolean || type.kind() == types::Kind::enumeration)
                return false;
            if (type.kind() == types::Kind::array) {
                if (!type.element() || !active.insert(&type).second) return true;
                const bool bad = visit(*type.element(), depth + 1); active.erase(&type); return bad;
            }
            if (type.kind() == types::Kind::structure || type.kind() == types::Kind::union_type) {
                if (!active.insert(&type).second) return true;
                for (const auto &member : type.members())
                    if (!member.type || visit(*member.type, depth + 1)) { active.erase(&type); return true; }
                active.erase(&type); return false;
            }
            return true;
        };
        return visit(root, 0);
    };
    const auto shape = [&](const types::Type &source) {
        const auto &type = unqualified(source); Shape s;
        s.size = type.size().value_or(0); s.alignment = type.alignment();
        if (!s.size || !power_of_two(s.alignment) || s.alignment > 16) {
            s.why = "incomplete value or unsupported alignment"; return s;
        }
        switch (type.kind()) {
        case types::Kind::boolean: case types::Kind::integer: case types::Kind::enumeration:
            s.ok = s.size == 1 || s.size == 2 || s.size == 4 || s.size == 8;
            s.why = "unsupported MIPS N64 integer scalar width"; return s;
        case types::Kind::pointer:
            s.ok = s.size == 8; s.why = "pointer size does not match N64"; return s;
        case types::Kind::floating:
            s.fp = true; s.ok = s.size == 4 || s.size == 8;
            s.why = "N64 floating scalar must be 32 or 64 bits"; return s;
        case types::Kind::structure: case types::Kind::union_type:
            s.aggregate = true; s.ok = s.size <= 32 && !aggregate_has_unmodeled_class(type);
            s.why = s.size > 32 ? "MIPS N64 aggregate exceeds supported 32-byte limit" :
                    "aggregate with floating, vector, recursive, or unresolved fields is unsupported";
            return s;
        case types::Kind::array:
            s.array = true; s.ok = type.element() != nullptr;
            s.why = "MIPS N64 array parameter requires a complete element type"; return s;
        default: s.why = "MIPS N64 function, vector, or unresolved value is unsupported"; return s;
        }
    };
    const auto &return_type = unqualified(*function_type.result_type());
    if (return_type.kind() == types::Kind::void_type) out.result = {};
    else {
        const auto r = shape(return_type);
        if (!r.ok) { out.result = unsupported(r.why); out.complete = false; }
        else if (r.fp) out.result.locations.push_back(reg_location("F0", r.size, 0, 8));
        else if (r.array) { out.result = unsupported("array function results are unsupported"); out.complete = false; }
        else if (!r.aggregate || r.size <= 16) {
            out.result.locations.push_back(reg_location("V0", std::min<std::uint64_t>(8, r.size), 0, 8));
            if (r.size > 8) out.result.locations.push_back(reg_location("V1", r.size - 8, 8, 8));
        } else {
            out.result.indirect = true;
            out.hidden_result_pointer = {true, {}, {reg_location("A0", 8, 0, 8, AbiLocationRole::hidden_result_argument)}};
            out.hidden_result_pointer.indirect = true;
        }
    }
    // N64 assigns one 64-bit argument word per scalar and one or two words to
    // small aggregates. The ordinal slot selects A0-A7; hard-float scalars use
    // the corresponding F12-F19 lane. Slots after the eighth are on the stack.
    std::uint64_t slot = out.hidden_result_pointer.indirect ? 1 : 0, stack = 0;
    bool placement_known = out.result.supported;
    for (const auto &parameter : function_type.parameters()) {
        if (!placement_known) { out.arguments.push_back(unsupported("preceding value makes MIPS N64 placement indeterminate")); continue; }
        if (!parameter.type) { out.arguments.push_back(unsupported("parameter has no type")); out.complete = placement_known = false; continue; }
        const auto s = shape(*parameter.type);
        if (!s.ok) { out.arguments.push_back(unsupported(s.why)); out.complete = placement_known = false; continue; }
        const bool indirect = s.array;
        const std::uint64_t passed_size = indirect ? 8 : s.size;
        const std::uint64_t words = indirect || !s.aggregate ? 1 : (s.size + 7) / 8;
        AbiValueLocation arg; arg.indirect = indirect;
        if (s.aggregate && slot < 8) {
            const auto register_words = std::min<std::uint64_t>(words, 8 - slot);
            for (std::uint64_t n = 0; n < register_words; ++n)
                arg.locations.push_back(reg_location("A" + std::to_string(slot + n),
                    std::min<std::uint64_t>(8, s.size - n * 8), n * 8, 8));
            for (std::uint64_t n = register_words; n < words; ++n) {
                const auto at = align_stack(stack, 8);
                if (at == UINT64_MAX || at > UINT64_MAX - 8) { arg.locations.clear(); break; }
                arg.locations.push_back(stack_location(at, std::min<std::uint64_t>(8, s.size - n * 8), 8, n * 8, 8));
                stack = at + 8;
            }
            if (arg.locations.empty()) { out.arguments.push_back(unsupported("MIPS N64 aggregate stack extent overflows")); out.complete = placement_known = false; continue; }
        } else if (slot < 8 && words == 1) {
            if (s.fp) arg.locations.push_back(reg_location("F" + std::to_string(12 + slot), s.size, 0, 8));
            else arg.locations.push_back(reg_location("A" + std::to_string(slot), passed_size, 0, 8));
        } else {
            const auto alignment = std::min<std::uint64_t>(16, std::max<std::uint64_t>(8, s.alignment));
            const auto at = align_stack(stack, alignment), occupied = align_stack(passed_size, 8);
            if (at == UINT64_MAX || occupied == UINT64_MAX || occupied > UINT64_MAX - at) {
                out.arguments.push_back(unsupported("MIPS N64 stack argument extent overflows")); out.complete = placement_known = false; continue;
            }
            arg.locations.push_back(stack_location(at, passed_size, alignment, 0, occupied));
            stack = at + occupied;
        }
        slot += words;
        out.arguments.push_back(std::move(arg));
    }
    out.stack_argument_bytes = stack;
    return out;
}

AbiSignatureClassification classify_mips_n32(const types::Type &function_type) {
    AbiSignatureClassification out; out.convention = CallingConvention::mips_n32;
    out.pointer_size = 4; out.stack_alignment = 16; out.stack_slot_size = 8;
    if (function_type.kind() != types::Kind::function || !function_type.result_type()) {
        out.complete = false; out.result = unsupported("input type is not a function signature"); return out;
    }
    if (function_type.variadic()) {
        out.complete = false; out.result = unsupported("variadic Linux MIPS N32 classification is unsupported");
        for (std::size_t i = 0; i < function_type.parameters().size(); ++i)
            out.arguments.push_back(unsupported("variadic MIPS N32 parameter placement is unsupported"));
        return out;
    }
    struct Shape { bool ok=false, fp=false; std::uint64_t size=0; std::string why; };
    const auto shape = [](const types::Type &source) {
        const auto &type = unqualified(source); Shape s; s.size = type.size().value_or(0);
        switch (type.kind()) {
        case types::Kind::boolean: case types::Kind::integer: case types::Kind::enumeration:
            s.ok = s.size == 1 || s.size == 2 || s.size == 4 || s.size == 8;
            s.why = "unsupported MIPS N32 integer scalar width"; break;
        case types::Kind::pointer:
            s.ok = s.size == 4; s.why = "pointer size does not match N32"; break;
        case types::Kind::floating:
            s.fp = true; s.ok = s.size == 4 || s.size == 8;
            s.why = "N32 floating scalar must be 32 or 64 bits"; break;
        default:
            s.why = "MIPS N32 aggregate, array, vector, or unresolved values are unsupported"; break;
        }
        if (!s.ok && !s.size) s.why = "incomplete MIPS N32 scalar";
        return s;
    };
    const auto &result = unqualified(*function_type.result_type());
    if (result.kind() == types::Kind::void_type) out.result = {};
    else {
        const auto s = shape(result);
        if (!s.ok) { out.result = unsupported(s.why); out.complete = false; }
        else out.result.locations.push_back(reg_location(s.fp ? "F0" : "V0", s.size, 0, 8));
    }
    std::uint64_t slot = 0, stack = 0;
    bool placement_known = out.result.supported;
    for (const auto &parameter : function_type.parameters()) {
        if (!placement_known) { out.arguments.push_back(unsupported("preceding value makes MIPS N32 placement indeterminate")); continue; }
        if (!parameter.type) { out.arguments.push_back(unsupported("parameter has no type")); out.complete = placement_known = false; continue; }
        const auto s = shape(*parameter.type);
        if (!s.ok) { out.arguments.push_back(unsupported(s.why)); out.complete = placement_known = false; continue; }
        AbiValueLocation arg;
        if (slot < 8) {
            arg.locations.push_back(reg_location((s.fp ? "F" + std::to_string(12 + slot)
                                                        : "A" + std::to_string(slot)), s.size, 0, 8));
        } else {
            if (stack > UINT64_MAX - 8) { out.arguments.push_back(unsupported("MIPS N32 stack argument extent overflows")); out.complete = placement_known = false; continue; }
            arg.locations.push_back(stack_location(stack, s.size, 8, 0, 8)); stack += 8;
        }
        ++slot;
        out.arguments.push_back(std::move(arg));
    }
    out.stack_argument_bytes = stack;
    return out;
}
} // namespace

AbiSignatureClassification classify_abi_signature(CallingConvention convention,
                                                     const types::Type &function_type) {
    if (convention == CallingConvention::ppc64le_elfv2)
        return classify_ppc64le_elfv2(function_type);
    if (convention == CallingConvention::mips_n64)
        return classify_mips_n64(function_type);
    if (convention == CallingConvention::mips_n32)
        return classify_mips_n32(function_type);
    if (convention == CallingConvention::mips_o32) {
        AbiSignatureClassification out; out.convention = convention; out.complete = false;
        out.result = unsupported("Linux MIPS O32 ABI classification is not implemented");
        if (function_type.kind() == types::Kind::function)
            for (std::size_t i = 0; i < function_type.parameters().size(); ++i)
                out.arguments.push_back(unsupported("MIPS O32 parameter placement is unsupported"));
        return out;
    }
    if (is_vectorcall(convention))
        return classify_vectorcall(convention, function_type);
    if (convention == CallingConvention::aapcs32)
        return classify_aapcs32(function_type);
    if (convention == CallingConvention::aapcs64)
        return classify_aapcs64(function_type);
    if (is_riscv(convention))
        return classify_riscv_integer(convention, function_type);
    if (convention == CallingConvention::x86_32_thiscall &&
        function_type.kind() == types::Kind::function && function_type.variadic()) {
        AbiSignatureClassification unsupported_call;
        unsupported_call.convention = convention;
        unsupported_call.pointer_size = 4;
        unsupported_call.stack_alignment = 4;
        unsupported_call.stack_slot_size = 4;
        unsupported_call.stack_cleanup = AbiStackCleanup::caller;
        unsupported_call.complete = false;
        unsupported_call.result = unsupported(
            "variadic thiscall requires a stack-passed implicit this pointer, which is not modeled");
        unsupported_call.arguments.reserve(function_type.parameters().size());
        for (std::size_t i = 0; i < function_type.parameters().size(); ++i)
            unsupported_call.arguments.push_back(unsupported(
                "variadic thiscall parameter placement is indeterminate"));
        return unsupported_call;
    }
    // Microsoft x86 variadic functions use caller cleanup and pass arguments
    // on the stack, even when a non-variadic declaration uses another x86 ABI.
    if (is_x86_32(convention) && function_type.kind() == types::Kind::function &&
        function_type.variadic())
        convention = CallingConvention::x86_32_cdecl;
    AbiSignatureClassification out;
    out.convention = convention;
    if (is_x86_32(convention)) {
        out.pointer_size = 4; out.stack_alignment = 4; out.stack_slot_size = 4;
        out.stack_cleanup = convention == CallingConvention::x86_32_cdecl
            ? AbiStackCleanup::caller : AbiStackCleanup::callee;
    } else {
        out.pointer_size = 8; out.stack_alignment = 16; out.stack_slot_size = 8;
        if (convention == CallingConvention::windows_x64) out.shadow_space = 32;
    }
    if (function_type.kind() != types::Kind::function || !function_type.result_type()) {
        out.complete = false;
        out.result = unsupported("input type is not a function signature");
        return out;
    }

    if (function_type.variadic() &&
        (convention == CallingConvention::sysv_x86_64 || convention == CallingConvention::windows_x64)) {
        out.complete = false;
        out.result = unsupported("variadic 64-bit x86 classification requires call-site promotion and register metadata");
        out.arguments.reserve(function_type.parameters().size());
        for (std::size_t i = 0; i < function_type.parameters().size(); ++i)
            out.arguments.push_back(unsupported("variadic 64-bit x86 argument placement is not modeled"));
        return out;
    }

    const auto &parameters = function_type.parameters();
    out.arguments.reserve(parameters.size());
    out.result = classify_result(convention, *function_type.result_type(), out.pointer_size,
                                 out.hidden_result_pointer);
    if (!out.result.supported) out.complete = false;
    std::size_t integer_index = convention == CallingConvention::sysv_x86_64 && out.result.indirect ? 1 : 0;
    std::size_t float_index = 0;
    std::size_t win_position = convention == CallingConvention::windows_x64 && out.result.indirect ? 1 : 0;
    std::uint64_t stack_cursor = is_x86_32(convention) ? (out.result.indirect ? 8 : 4) :
                                 convention == CallingConvention::windows_x64 ? 40 : 8;
    std::size_t fastcall_register = 0;
    if (convention == CallingConvention::x86_32_thiscall) {
        out.implicit_this = {true, {}, {reg_location("ECX", 4)}};
    }
    bool allocation_known = out.result.supported;
    for (std::size_t i = 0; i < parameters.size(); ++i) {
        const auto &parameter = parameters[i];
        if (!parameter.type) {
            out.arguments.push_back(unsupported("parameter has no type"));
            out.complete = allocation_known = false;
            continue;
        }
        if (!is_x86_32(convention) && unqualified(*parameter.type).kind() == types::Kind::array) {
            out.arguments.push_back(unsupported("array parameters require C/C++ array-to-pointer adjustment"));
            out.complete = allocation_known = false;
            continue;
        }
        if (is_aggregate(*parameter.type)) {
            if (!allocation_known) {
                out.arguments.push_back(unsupported("preceding unsupported value makes placement indeterminate"));
                continue;
            }
            const auto layout_abi = is_x86_32(convention) ? types::Abi::x86_32 : types::Abi::x86_64;
            auto object_layout = types::layout(*parameter.type, layout_abi);
            if (!object_layout) {
                out.arguments.push_back(unsupported(object_layout.error().message));
                out.complete = allocation_known = false;
                continue;
            }
            const auto size = object_layout.value().size;
            if (is_x86_32(convention)) {
                out.arguments.push_back({true, {}, {stack_location(stack_cursor, size, 4)}});
                stack_cursor += (size + 3) & ~std::uint64_t(3);
                continue;
            }
            if (convention == CallingConvention::windows_x64) {
                const bool direct = size == 1 || size == 2 || size == 4 || size == 8;
                const auto arg_size = direct ? size : 8;
                AbiValueLocation value;
                if (win_position < 4)
                    value.locations.push_back(reg_location(integer_register(convention, win_position++, arg_size), arg_size));
                else {
                    ++win_position;
                    auto location = reserve_stack(stack_cursor, arg_size, 8, 8);
                    if (!location) {
                        out.arguments.push_back(unsupported("Windows x64 stack placement overflows"));
                        out.complete = allocation_known = false;
                        continue;
                    }
                    value.locations.push_back(std::move(*location));
                }
                value.indirect = !direct;
                out.arguments.push_back(std::move(value));
                continue;
            }
            const auto aggregate = classify_sysv_aggregate(*parameter.type);
            if (!aggregate.supported) {
                out.arguments.push_back(unsupported(aggregate.reason));
                out.complete = allocation_known = false;
                continue;
            }
            const bool memory = aggregate.classes.size() == 1 && aggregate.classes[0] == SysvClass::memory;
            std::size_t need_gpr = 0, need_xmm = 0;
            if (!memory) for (const auto cls : aggregate.classes)
                cls == SysvClass::sse ? ++need_xmm : cls == SysvClass::sse_up ? 0 : ++need_gpr;
            if (!memory && integer_index + need_gpr <= 6 && float_index + need_xmm <= 8) {
                AbiValueLocation value;
                for (std::size_t j = 0; j < aggregate.classes.size(); ++j) {
                    if (aggregate.classes[j] == SysvClass::sse_up)
                        continue;
                    const auto offset = static_cast<std::uint64_t>(j) * 8;
                    if (aggregate.classes[j] == SysvClass::sse) {
                        std::size_t end = j + 1;
                        while (end < aggregate.classes.size() && aggregate.classes[end] == SysvClass::sse_up) ++end;
                        const auto piece_size = std::min<std::uint64_t>((end - j) * 8, size - offset);
                        value.locations.push_back(reg_location("XMM" + std::to_string(float_index++), piece_size,
                                                                offset, end - j > 1 ? 16 : 0));
                    } else {
                        const auto piece_size = std::min<std::uint64_t>(8, size - offset);
                        value.locations.push_back(reg_location(integer_register(convention, integer_index++, 8), piece_size, offset));
                    }
                }
                out.arguments.push_back(std::move(value));
            } else {
                const auto alignment = std::max<std::uint64_t>(8, object_layout.value().alignment);
                if (alignment > 16 || !power_of_two(alignment)) {
                    out.arguments.push_back(unsupported("SysV stack aggregate alignment above 16 bytes is unsupported"));
                    out.complete = allocation_known = false;
                    continue;
                }
                auto location = reserve_stack(stack_cursor, size, alignment, 8);
                if (!location) {
                    out.arguments.push_back(unsupported("SysV stack aggregate placement overflows"));
                    out.complete = allocation_known = false;
                } else {
                    out.arguments.push_back({true, {}, {std::move(*location)}});
                }
            }
            continue;
        }
        if (convention == CallingConvention::sysv_x86_64) {
            if (const auto width = sysv_x64_vector_width(*parameter.type)) {
                if (!allocation_known) {
                    out.arguments.push_back(unsupported("preceding unsupported value makes vector register placement indeterminate"));
                    continue;
                }
                if (float_index < 8) {
                    out.arguments.push_back({true, {}, {reg_location("XMM" + std::to_string(float_index++), *width, 0, 16)}});
                } else {
                    auto location = reserve_stack(stack_cursor, *width, *width, 8);
                    if (!location) {
                        out.arguments.push_back(unsupported("SysV vector stack placement overflows"));
                        out.complete = allocation_known = false;
                    } else out.arguments.push_back({true, {}, {std::move(*location)}});
                }
                continue;
            }
            if (unqualified(*parameter.type).kind() == types::Kind::vector) {
                out.arguments.push_back(unsupported("SysV AMD64 vector argument requires a 8- or 16-byte baseline SSE vector shape; wider vectors need target feature metadata"));
                out.complete = allocation_known = false;
                continue;
            }
        }
        if (convention == CallingConvention::windows_x64 && windows_x64_vector_argument(*parameter.type)) {
            if (!allocation_known) {
                out.arguments.push_back(unsupported("preceding unsupported value makes vector placement indeterminate"));
                continue;
            }
            const auto position = win_position++;
            AbiValueLocation value;
            value.indirect = true;
            if (position < 4)
                value.locations.push_back(reg_location(integer_register(convention, position, 8), 8, 0, 8));
            else {
                auto location = reserve_stack(stack_cursor, 8, 8, 8);
                if (!location) {
                    out.arguments.push_back(unsupported("Windows x64 vector reference stack placement overflows"));
                    out.complete = allocation_known = false;
                    continue;
                }
                value.locations.push_back(std::move(*location));
            }
            out.arguments.push_back(std::move(value));
            continue;
        }
        const auto scalar = scalar_type(*parameter.type, out.pointer_size);
        if (!scalar.supported) {
            out.arguments.push_back(unsupported(scalar.reason));
            out.complete = allocation_known = false;
            continue;
        }
        if (!allocation_known) {
            out.arguments.push_back(unsupported(out.result.supported
                ? "preceding unsupported argument makes placement indeterminate"
                : "unsupported result may require a hidden return location, so argument placement is indeterminate"));
            continue;
        }

        if (is_x86_32(convention)) {
            const auto slot = ((scalar.size + 3) / 4) * 4;
            const bool fastcall_register_eligible = convention == CallingConvention::x86_32_fastcall &&
                !scalar.floating && scalar.size <= 4 && fastcall_register < 2;
            if (fastcall_register_eligible) {
                const char *name = fastcall_register++ == 0 ? "ECX" : "EDX";
                const char *alias = name;
                if (scalar.size == 2) alias = name[1] == 'C' ? "CX" : "DX";
                else if (scalar.size == 1) alias = name[1] == 'C' ? "CL" : "DL";
                out.arguments.push_back({true, {}, {reg_location(alias, scalar.size)}});
            } else {
                out.arguments.push_back({true, {}, {stack_location(stack_cursor, scalar.size, 4)}});
                stack_cursor += slot;
            }
            continue;
        }
        if (convention == CallingConvention::windows_x64) {
            const auto position = win_position++;
            if (position < 4) {
                if (scalar.floating)
                    out.arguments.push_back({true, {}, {reg_location("XMM" + std::to_string(position), scalar.size)}});
                else
                    out.arguments.push_back({true, {}, {reg_location(integer_register(convention, position, scalar.size), scalar.size)}});
            } else {
                auto location = reserve_stack(stack_cursor, scalar.size, 8, 8);
                if (!location) {
                    out.arguments.push_back(unsupported("Windows x64 stack placement overflows"));
                    out.complete = allocation_known = false;
                } else {
                    out.arguments.push_back({true, {}, {std::move(*location)}});
                }
            }
            continue;
        }
        if (scalar.floating) {
            if (float_index < 8) {
                out.arguments.push_back({true, {}, {reg_location("XMM" + std::to_string(float_index++), scalar.size)}});
            } else {
                out.arguments.push_back({true, {}, {stack_location(stack_cursor, scalar.size, 8)}});
                stack_cursor += 8;
            }
        } else if (integer_index < 6) {
            out.arguments.push_back({true, {}, {reg_location(integer_register(convention, integer_index++, scalar.size), scalar.size)}});
        } else {
            auto location = reserve_stack(stack_cursor, scalar.size, 8, 8);
            if (!location) {
                out.arguments.push_back(unsupported("SysV stack scalar placement overflows"));
                out.complete = allocation_known = false;
            } else {
                out.arguments.push_back({true, {}, {std::move(*location)}});
            }
        }
    }
    const auto stack_base = is_x86_32(convention) ? 4 + (out.result.indirect ? 4 : 0) :
        convention == CallingConvention::windows_x64 ? 40 : 8;
    out.stack_argument_bytes = stack_cursor - stack_base;
    if (out.stack_cleanup == AbiStackCleanup::callee)
        out.callee_pop_bytes = out.stack_argument_bytes + (out.result.indirect ? 4 : 0);
    return out;
}

AbiSignatureClassification classify_abi_signature(const types::Type &function_type,
                                                     CallingConvention platform_default) {
    using types::FunctionConvention;
    auto selected = platform_default;
    auto unsupported_declared = [&](std::string reason) {
        auto out = classify_abi_signature(platform_default, function_type);
        out.complete = false;
        out.result = unsupported(reason);
        for (auto &argument : out.arguments) argument = unsupported(reason);
        return out;
    };
    switch (function_type.function_convention()) {
    case FunctionConvention::platform_default:
        break;
    case FunctionConvention::c_decl:
        // The cdecl spelling is explicit on 32-bit x86; on 64-bit targets it
        // denotes the platform's single default C ABI.
        if (platform_default == CallingConvention::x86_32_cdecl)
            selected = CallingConvention::x86_32_cdecl;
        break;
    case FunctionConvention::sysv_abi:
        if (platform_default != CallingConvention::sysv_x86_64 &&
            platform_default != CallingConvention::windows_x64)
            return unsupported_declared("sysv_abi is only modeled for 64-bit x86 targets");
        selected = CallingConvention::sysv_x86_64;
        break;
    case FunctionConvention::ms_abi:
        if (platform_default != CallingConvention::sysv_x86_64 &&
            platform_default != CallingConvention::windows_x64)
            return unsupported_declared("ms_abi is only modeled for 64-bit x86 targets");
        selected = CallingConvention::windows_x64;
        break;
    case FunctionConvention::aapcs64:
        if (platform_default != CallingConvention::aapcs64)
            return unsupported_declared("aapcs64 is only modeled for AArch64 targets");
        selected = CallingConvention::aapcs64;
        break;
    case FunctionConvention::aapcs32:
        if (platform_default != CallingConvention::aapcs32)
            return unsupported_declared("aapcs32 is only modeled for AArch32 targets");
        selected = CallingConvention::aapcs32;
        break;
    case FunctionConvention::mips_n64:
        if (platform_default != CallingConvention::mips_n64)
            return unsupported_declared("mips_n64 is only modeled for Linux MIPS64 N64 targets");
        selected = CallingConvention::mips_n64;
        break;
    case FunctionConvention::stdcall:
        if (platform_default != CallingConvention::x86_32_cdecl)
            return unsupported_declared("stdcall is only modeled for 32-bit x86 targets");
        selected = CallingConvention::x86_32_stdcall;
        break;
    case FunctionConvention::fastcall:
        if (platform_default != CallingConvention::x86_32_cdecl)
            return unsupported_declared("fastcall is only modeled for 32-bit x86 targets");
        selected = CallingConvention::x86_32_fastcall;
        break;
    case FunctionConvention::thiscall:
        if (platform_default != CallingConvention::x86_32_cdecl)
            return unsupported_declared("thiscall is only modeled for 32-bit x86 targets");
        selected = CallingConvention::x86_32_thiscall;
        break;
    case FunctionConvention::vectorcall: {
        if (platform_default == CallingConvention::x86_32_cdecl)
            selected = CallingConvention::x86_32_vectorcall;
        else if (platform_default == CallingConvention::windows_x64)
            selected = CallingConvention::windows_x64_vectorcall;
        else if (platform_default == CallingConvention::x86_32_vectorcall ||
                 platform_default == CallingConvention::windows_x64_vectorcall)
            selected = platform_default;
        else
            return unsupported_declared("vectorcall is only modeled for native x86 and Microsoft x64 targets");
        break;
    }
    }
    return classify_abi_signature(selected, function_type);
}

AbiSignatureClassification classify_abi_method(CallingConvention convention,
                                                const types::Method &method) {
    auto reject = [&](std::string reason) {
        AbiSignatureClassification out;
        out.convention = convention;
        out.pointer_size = convention == CallingConvention::windows_x64 ? 8 : 0;
        out.stack_alignment = convention == CallingConvention::windows_x64 ? 16 : 0;
        out.stack_slot_size = convention == CallingConvention::windows_x64 ? 8 : 0;
        out.shadow_space = convention == CallingConvention::windows_x64 ? 32 : 0;
        out.complete = false;
        out.result = unsupported(std::move(reason));
        return out;
    };
    if (convention != CallingConvention::windows_x64)
        return reject("method-aware classification currently supports Microsoft x64 only");
    if (!method.signature || method.signature->kind() != types::Kind::function ||
        !method.signature->result_type())
        return reject("method has no valid function signature");
    if (method.is_static)
        return classify_abi_signature(convention, *method.signature);

    auto pointer = types::Type::pointer(method.this_type ? method.this_type : types::Type::void_type(), 8, 8);
    if (!pointer) return reject("method receiver pointer type could not be represented");
    std::vector<types::Parameter> parameters;
    parameters.reserve(method.signature->parameters().size() + 1);
    parameters.push_back({"this", pointer.value()});
    parameters.insert(parameters.end(), method.signature->parameters().begin(),
                      method.signature->parameters().end());
    auto signature = types::Type::function(method.signature->result_type(), std::move(parameters),
                                           method.signature->variadic(),
                                           method.signature->function_convention());
    if (!signature) return reject("method receiver could not be incorporated into its function signature");
    auto out = classify_abi_signature(convention, *signature.value());
    if (!out.arguments.empty()) {
        out.implicit_this = std::move(out.arguments.front());
        out.arguments.erase(out.arguments.begin());
    }
    out.this_adjustment = method.this_adjustment;
    return out;
}

AbiSignatureClassification classify_abi_call(
    CallingConvention convention, const types::Type &function_type,
    std::span<const types::TypePtr> actual_argument_types) {
    const auto failure = [&](std::string reason) {
        AbiSignatureClassification out;
        out.convention = convention;
        out.pointer_size = 8;
        out.stack_alignment = 16;
        out.stack_slot_size = 8;
        if (convention == CallingConvention::windows_x64) out.shadow_space = 32;
        out.complete = false;
        out.result = unsupported(reason);
        out.arguments.reserve(std::min<std::size_t>(actual_argument_types.size(), 4096));
        for (std::size_t i = 0; i < actual_argument_types.size() && i < 4096; ++i)
            out.arguments.push_back(unsupported(reason));
        return out;
    };
    if (function_type.kind() != types::Kind::function || !function_type.result_type())
        return failure("call-site ABI input is not a complete function type");
    if (!function_type.variadic())
        return failure("call-site ABI classification requires a variadic function type");
    if (convention != CallingConvention::sysv_x86_64 && convention != CallingConvention::windows_x64)
        return failure("call-site variadic classification supports only SysV AMD64 and Microsoft x64");
    constexpr std::size_t max_call_arguments = 4096;
    if (actual_argument_types.size() > max_call_arguments)
        return failure("variadic call-site argument count exceeds 4096");
    const auto &fixed_parameters = function_type.parameters();
    if (actual_argument_types.size() < fixed_parameters.size())
        return failure("variadic call site has fewer arguments than its fixed parameters");

    std::vector<types::Parameter> call_parameters;
    call_parameters.reserve(actual_argument_types.size());
    for (std::size_t index = 0; index < actual_argument_types.size(); ++index) {
        types::TypePtr argument_type;
        if (index < fixed_parameters.size()) {
            // Named arguments have already undergone their declared parameter
            // conversions; the prototype is authoritative for their ABI class.
            argument_type = fixed_parameters[index].type;
            if (!argument_type)
                return failure("fixed function parameter has no type");
        } else {
            argument_type = actual_argument_types[index];
            if (!argument_type)
                return failure("variadic call-site argument has no type");
            const auto &actual = unqualified(*argument_type);
            if (actual.kind() == types::Kind::vector)
                return failure("variadic vector arguments require target-specific promotion and register-save metadata");
            if (actual.kind() == types::Kind::array) {
                if (!actual.element()) return failure("variadic array argument has no element type");
                auto pointer = types::Type::pointer(actual.element(), 8, 8);
                if (!pointer) return failure(pointer.error().message);
                argument_type = std::move(pointer.value());
            } else if (actual.kind() == types::Kind::function) {
                auto pointer = types::Type::pointer(argument_type, 8, 8);
                if (!pointer) return failure(pointer.error().message);
                argument_type = std::move(pointer.value());
            } else if (actual.kind() == types::Kind::boolean ||
                       ((actual.kind() == types::Kind::integer || actual.kind() == types::Kind::enumeration) &&
                        actual.size().value_or(8) < 4)) {
                auto promoted = types::Type::integer("int", 4, 4, true);
                if (!promoted) return failure(promoted.error().message);
                argument_type = std::move(promoted.value());
            } else if (actual.kind() == types::Kind::floating && actual.size() == 4) {
                auto promoted = types::Type::floating("double", 8, 8);
                if (!promoted) return failure(promoted.error().message);
                argument_type = std::move(promoted.value());
            }
        }
        call_parameters.push_back({index < fixed_parameters.size()
                                       ? fixed_parameters[index].name : std::string{},
                                   std::move(argument_type)});
    }

    auto concrete_type = types::Type::function(function_type.result_type(), std::move(call_parameters),
                                                false, function_type.function_convention());
    if (!concrete_type) return failure(concrete_type.error().message);
    auto out = classify_abi_signature(convention, *concrete_type.value());
    if (out.arguments.size() != actual_argument_types.size())
        return failure("ABI classifier returned an inconsistent call-site argument count");

    if (convention == CallingConvention::windows_x64) {
        static constexpr const char *gpr_names[] = {"RCX", "RDX", "R8", "R9"};
        const auto positional_bias = out.result.indirect ? std::size_t{1} : std::size_t{0};
        for (std::size_t index = 0; index < actual_argument_types.size(); ++index) {
            const auto position = index + positional_bias;
            if (position >= 4 || !out.arguments[index].supported) continue;
            const auto &classified_type = *concrete_type.value()->parameters()[index].type;
            const auto &scalar = unqualified(classified_type);
            if (scalar.kind() != types::Kind::floating) continue;
            auto &locations = out.arguments[index].locations;
            const auto floating = std::find_if(locations.begin(), locations.end(), [&](const auto &location) {
                return location.kind == AbiLocationKind::register_ &&
                       location.register_name == "XMM" + std::to_string(position);
            });
            if (floating == locations.end()) continue;
            auto duplicate = reg_location(gpr_names[position], floating->size, 0, 8);
            duplicate.duplicate = true;
            locations.push_back(std::move(duplicate));
        }
    } else if (out.complete) {
        std::array<bool, 8> used_xmm{};
        for (const auto &argument : out.arguments) {
            for (const auto &location : argument.locations) {
                if (location.kind != AbiLocationKind::register_ ||
                    !location.register_name.starts_with("XMM")) continue;
                const auto suffix = std::string_view(location.register_name).substr(3);
                if (suffix.empty()) continue;
                unsigned index = 0;
                bool valid = true;
                for (const char ch : suffix) {
                    if (ch < '0' || ch > '9') { valid = false; break; }
                    index = index * 10 + static_cast<unsigned>(ch - '0');
                }
                if (valid && index < used_xmm.size()) used_xmm[index] = true;
            }
        }
        out.sysv_vector_register_count = static_cast<std::uint8_t>(
            std::count(used_xmm.begin(), used_xmm.end(), true));
    }
    return out;
}

} // namespace hexlab
