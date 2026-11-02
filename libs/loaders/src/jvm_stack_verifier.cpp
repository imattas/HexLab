#include "jvm_stack_verifier.hpp"
#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/jvm_semantics.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <utility>

namespace hexlab::jvm_detail {
namespace {
enum class Kind : std::uint8_t {
    top, integer, long_value, long_tail, float_value, double_value, double_tail, reference
};
struct Value {
    Kind kind = Kind::top;
    // Zero is an initialized value; allocation offsets are stored plus one.
    // The maximum uint32 value denotes uninitializedThis.
    std::uint32_t uninitialized = 0;
    // A descriptor such as Lpkg/Type; or [I. Empty means the loader has no
    // identity evidence for this reference. Null is kept separately.
    std::string reference_type;
    bool null_reference = false;
    constexpr Value() = default;
    Value(Kind value_kind, std::uint32_t identity = 0, std::string type = {}, bool is_null = false)
        : kind(value_kind), uninitialized(identity), reference_type(std::move(type)), null_reference(is_null) {}
    bool operator==(const Value &) const = default;
    friend constexpr bool operator==(Value value, Kind kind) { return value.kind == kind; }
};
using Stack = std::vector<Value>;
using Locals = std::vector<Value>;
struct FrameState { Stack stack; Locals locals; bool constructor_initialized = true; };
constexpr auto top = Kind::top, integer = Kind::integer, long_value = Kind::long_value,
    long_tail = Kind::long_tail, float_value = Kind::float_value,
    double_value = Kind::double_value, double_tail = Kind::double_tail,
    reference = Kind::reference;
constexpr std::array scalar{integer, long_value, float_value, double_value};
constexpr std::array local{integer, long_value, float_value, double_value, reference};
constexpr std::array array_element{integer, long_value, float_value, double_value, reference, integer, integer, integer};
std::uint8_t width(Kind value) { return value == long_value || value == double_value ? 2 : 1; }
std::uint8_t width(Value value) { return width(value.kind); }
constexpr std::uint32_t uninitialized_this = std::numeric_limits<std::uint32_t>::max();
bool is_uninitialized(Value value) { return value.kind == reference && value.uninitialized != 0; }
std::size_t slots(const Stack &stack) {
    std::size_t result = 0;
    for (const auto value : stack) result += width(value);
    return result;
}
// Descriptors have already passed classfile syntax validation. Keep this reader
// defensive, and never search for ')' through class names inside a descriptor.
bool read_type(std::string_view text, std::size_t &position, std::optional<Kind> &result, bool allow_void,
               std::string *reference_descriptor = nullptr) {
    if (position >= text.size()) return false;
    const auto start = position;
    if (text[position] == '[') {
        while (position < text.size() && text[position] == '[') ++position;
        std::optional<Kind> element;
        if (!read_type(text, position, element, false)) return false;
        result = reference;
        if (reference_descriptor) *reference_descriptor = std::string(text.substr(start, position - start));
        return true;
    }
    switch (text[position++]) {
    case 'B': case 'C': case 'I': case 'S': case 'Z': result = integer; return true;
    case 'J': result = long_value; return true;
    case 'F': result = float_value; return true;
    case 'D': result = double_value; return true;
    case 'L': {
        const auto end = text.find(';', position);
        if (end == std::string_view::npos || end == position) return false;
        position = end + 1; result = reference;
        if (reference_descriptor) *reference_descriptor = std::string(text.substr(start, position - start));
        return true;
    }
    case 'V': result.reset(); return allow_void;
    default: return false;
    }
}
std::optional<std::string_view> descriptor(const JvmMetadata &metadata, std::uint64_t index) {
    const auto &pool = metadata.constant_pool;
    if (!index || index >= pool.size()) return {};
    const auto &entry = pool[static_cast<std::size_t>(index)];
    if (entry.second >= pool.size()) return {};
    const auto &name_and_type = pool[static_cast<std::size_t>(entry.second)];
    if (name_and_type.tag != 12 || name_and_type.second >= pool.size()) return {};
    const auto &text = pool[static_cast<std::size_t>(name_and_type.second)];
    if (text.tag != 1) return {};
    return text.text;
}
std::optional<std::uint16_t> member_owner_index(const JvmMetadata &metadata, std::uint64_t index) {
    const auto &pool = metadata.constant_pool;
    if (!index || index >= pool.size()) return {};
    const auto &member = pool[static_cast<std::size_t>(index)];
    if ((member.tag != 9 && member.tag != 10 && member.tag != 11) ||
        !member.first || member.first >= pool.size() || pool[static_cast<std::size_t>(member.first)].tag != 7)
        return {};
    return static_cast<std::uint16_t>(member.first);
}
std::optional<std::string_view> class_name(const JvmMetadata &metadata, std::uint64_t index) {
    const auto &pool = metadata.constant_pool;
    if (!index || index >= pool.size()) return {};
    const auto &class_entry = pool[static_cast<std::size_t>(index)];
    if (class_entry.tag != 7 || !class_entry.first || class_entry.first >= pool.size()) return {};
    const auto &name = pool[static_cast<std::size_t>(class_entry.first)];
    if (name.tag != 1) return {};
    return name.text;
}
bool same_class(const JvmMetadata &metadata, std::uint64_t left, std::uint64_t right) {
    const auto left_name = class_name(metadata, left);
    const auto right_name = class_name(metadata, right);
    return left_name && right_name && *left_name == *right_name;
}
std::optional<std::string> class_descriptor(const JvmMetadata &metadata, std::uint64_t index) {
    const auto name = class_name(metadata, index);
    if (!name || name->empty()) return {};
    if (name->front() == '[') return std::string(*name);
    return "L" + std::string(*name) + ";";
}
using HierarchyKey = std::pair<std::string, std::string>;
struct ReferenceResolver {
    const JvmMetadata &metadata;
    std::map<HierarchyKey, JvmHierarchyClass> nodes;
    bool graph_valid = true;
    std::size_t work = 0;
    static constexpr std::size_t max_nodes = 16'384, max_edges = 65'536, max_work = 262'144;

    explicit ReferenceResolver(const JvmMetadata &value) : metadata(value) {
        if (metadata.class_name.empty() || metadata.known_hierarchy.size() > max_nodes ||
            metadata.interfaces.size() > max_edges) {
            graph_valid = false;
            return;
        }
        JvmHierarchyClass self;
        self.identity = {metadata.class_name, metadata.defining_loader};
        self.complete = true;
        if (!metadata.super_name.empty()) self.superclass = JvmTypeIdentity{metadata.super_name, metadata.defining_loader};
        for (const auto &name : metadata.interfaces) self.interfaces.push_back({name, metadata.defining_loader});
        nodes.emplace(HierarchyKey{self.identity.defining_loader, self.identity.class_name}, std::move(self));
        std::size_t edges = 0;
        for (const auto &node : metadata.known_hierarchy) {
            if (node.identity.class_name.empty() || node.identity.defining_loader.empty() ||
                node.interfaces.size() > max_edges - std::min(edges, max_edges)) {
                graph_valid = false;
                return;
            }
            edges += node.interfaces.size() + (node.superclass ? 1u : 0u);
            if (edges > max_edges) { graph_valid = false; return; }
            const auto valid_id = [](const JvmTypeIdentity &id) {
                return !id.class_name.empty() && !id.defining_loader.empty();
            };
            if ((node.superclass && !valid_id(*node.superclass)) ||
                !std::all_of(node.interfaces.begin(), node.interfaces.end(), valid_id)) {
                graph_valid = false;
                return;
            }
            const HierarchyKey key{node.identity.defining_loader, node.identity.class_name};
            if (nodes.contains(key)) {
                // The current class may be repeated only with precisely the
                // complete direct edges already read from its class file.
                const auto &existing = nodes.at(key);
                if (key != HierarchyKey{metadata.defining_loader, metadata.class_name} || !node.complete ||
                    node.superclass != existing.superclass || node.interfaces != existing.interfaces) {
                    graph_valid = false;
                    return;
                }
                continue;
            }
            nodes.emplace(key, node);
        }
    }

    std::optional<bool> assignable(std::string_view actual, std::string_view expected,
                                   bool actual_is_null = false, unsigned depth = 0) {
        if (actual_is_null) return true;
        if (expected == "Ljava/lang/Object;") return true;
        if (actual.empty() || expected.empty()) return {};
        if (actual == expected) return true;
        if (depth > 255) return {};
        const bool actual_array = actual.front() == '[';
        const bool expected_array = expected.front() == '[';
        if (actual_array && expected_array) {
            const auto from = actual.substr(1), to = expected.substr(1);
            const auto primitive = [](std::string_view item) {
                return item.size() == 1 && std::string_view("BCDFIJSZ").find(item.front()) != std::string_view::npos;
            };
            if (primitive(from) || primitive(to)) return from == to;
            return assignable(from, to, false, depth + 1);
        }
        if (expected_array) return false;
        if (actual_array) {
            if (expected == "Ljava/lang/Cloneable;" || expected == "Ljava/io/Serializable;") return true;
            return false;
        }
        if (actual.size() < 3 || actual.front() != 'L' || actual.back() != ';' ||
            expected.size() < 3 || expected.front() != 'L' || expected.back() != ';') return {};
        const std::string actual_name(actual.substr(1, actual.size() - 2));
        const std::string expected_name(expected.substr(1, expected.size() - 2));
        if (actual_name == metadata.class_name &&
            (expected_name == metadata.super_name ||
             std::find(metadata.interfaces.begin(), metadata.interfaces.end(), expected_name) != metadata.interfaces.end()))
            return true;
        if (metadata.defining_loader.empty() || !graph_valid) return {};
        const HierarchyKey start{metadata.defining_loader, actual_name};
        const HierarchyKey target{metadata.defining_loader, expected_name};
        std::vector<HierarchyKey> pending{start};
        std::set<HierarchyKey> visited;
        bool unresolved = false;
        while (!pending.empty()) {
            if (++work > max_work || visited.size() >= max_nodes) return {};
            auto current = std::move(pending.back());
            pending.pop_back();
            if (!visited.insert(current).second) continue;
            if (current == target) return true;
            const auto found = nodes.find(current);
            if (found == nodes.end() || !found->second.complete) { unresolved = true; continue; }
            const auto visit_edge = [&](const JvmTypeIdentity &edge) {
                if (++work > max_work) return false;
                if (HierarchyKey{edge.defining_loader, edge.class_name} == target) return true;
                pending.emplace_back(edge.defining_loader, edge.class_name);
                return false;
            };
            if (found->second.superclass && visit_edge(*found->second.superclass)) return true;
            for (const auto &interface : found->second.interfaces)
                if (visit_edge(interface)) return true;
            if (work > max_work) return {};
        }
        return unresolved ? std::optional<bool>{} : std::optional<bool>{false};
    }

    std::optional<std::string> common_type(const Value &left, const Value &right) {
        if (left.null_reference) return right.reference_type.empty()
            ? std::optional<std::string>{"Ljava/lang/Object;"} : right.reference_type;
        if (right.null_reference) return left.reference_type.empty()
            ? std::optional<std::string>{"Ljava/lang/Object;"} : left.reference_type;
        if (left.reference_type.empty() || right.reference_type.empty()) return "Ljava/lang/Object;";
        if (left.reference_type == right.reference_type) return left.reference_type;
        if (assignable(left.reference_type, right.reference_type).value_or(false)) return right.reference_type;
        if (assignable(right.reference_type, left.reference_type).value_or(false)) return left.reference_type;
        // All references, including arrays, have the proven common type Object.
        return std::string("Ljava/lang/Object;");
    }
};
std::optional<std::string_view> member_name(const JvmMetadata &metadata, std::uint64_t index) {
    const auto &pool = metadata.constant_pool;
    if (!index || index >= pool.size()) return {};
    const auto &member = pool[static_cast<std::size_t>(index)];
    if ((member.tag != 9 && member.tag != 10 && member.tag != 11) || member.second >= pool.size()) return {};
    const auto &name_and_type = pool[static_cast<std::size_t>(member.second)];
    if (name_and_type.tag != 12 || !name_and_type.first || name_and_type.first >= pool.size()) return {};
    const auto &name = pool[static_cast<std::size_t>(name_and_type.first)];
    if (name.tag != 1) return {};
    return name.text;
}
std::optional<Kind> frame_kind(JvmVerificationKind kind) {
    switch (kind) {
    case JvmVerificationKind::integer: return integer;
    case JvmVerificationKind::float_value: return float_value;
    case JvmVerificationKind::long_value: return long_value;
    case JvmVerificationKind::double_value: return double_value;
    case JvmVerificationKind::object: case JvmVerificationKind::null_value:
    case JvmVerificationKind::uninitialized_this: case JvmVerificationKind::uninitialized: return reference;
    default: return {};
    }
}
Value frame_value(const JvmVerificationType &value, const JvmMetadata &metadata,
                  std::string_view implicit_descriptor) {
    const auto kind = frame_kind(value.kind);
    const auto identity = value.kind == JvmVerificationKind::uninitialized
        ? static_cast<std::uint32_t>(value.uninitialized_offset) + 1u
        : value.kind == JvmVerificationKind::uninitialized_this ? uninitialized_this : 0u;
    std::string type;
    if (value.kind == JvmVerificationKind::object) {
        if (auto resolved = class_descriptor(metadata, value.class_index)) type = std::move(*resolved);
        else if (value.descriptor_length && value.descriptor_offset <= implicit_descriptor.size() &&
                 value.descriptor_length <= implicit_descriptor.size() - value.descriptor_offset)
            type = std::string(implicit_descriptor.substr(value.descriptor_offset, value.descriptor_length));
    } else if (value.kind == JvmVerificationKind::uninitialized_this) {
        if (auto resolved = class_descriptor(metadata, metadata.this_class)) type = std::move(*resolved);
    }
    return Value{kind.value_or(top), identity, std::move(type), value.kind == JvmVerificationKind::null_value};
}
void normalize_category2(Locals &locals) {
    for (std::size_t i = 0; i < locals.size(); ++i) {
        if (locals[i] == long_value) {
            if (i + 1 < locals.size() && locals[i + 1] == long_tail) { ++i; continue; }
            locals[i] = top;
        } else if (locals[i] == double_value) {
            if (i + 1 < locals.size() && locals[i + 1] == double_tail) { ++i; continue; }
            locals[i] = top;
        } else if (locals[i] == long_tail || locals[i] == double_tail) {
            if (i && ((locals[i] == long_tail && locals[i - 1] == long_value) ||
                      (locals[i] == double_tail && locals[i - 1] == double_value))) continue;
            locals[i] = top;
        }
    }
}
bool descriptor_locals(const JvmMember &method, std::size_t max_locals, Locals &locals,
                       bool constructor_this_initialized, const JvmMetadata &metadata) {
    locals.assign(max_locals, top);
    std::size_t position = 0, slot = 0;
    const std::string_view text = method.descriptor;
    if (text.empty() || text[position++] != '(') return false;
    if ((method.access_flags & 0x0008u) == 0) {
        if (slot >= max_locals) return false;
        locals[slot++] = Value{reference, method.name == "<init>" && !constructor_this_initialized
            ? uninitialized_this : 0u, method.name == "<init>" && !constructor_this_initialized
            ? "L" + metadata.class_name + ";" : std::string{}};
    }
    while (position < text.size() && text[position] != ')') {
        std::optional<Kind> kind;
        std::string reference_type;
        if (!read_type(text, position, kind, false, &reference_type) || !kind || slot >= max_locals) return false;
        locals[slot++] = Value{*kind, 0, std::move(reference_type)};
        if (width(*kind) == 2) {
            if (slot >= max_locals) return false;
            locals[slot++] = *kind == long_value ? long_tail : double_tail;
        }
    }
    if (position >= text.size() || text[position++] != ')') return false;
    std::optional<Kind> result;
    if (!read_type(text, position, result, true) || position != text.size()) return false;
    return true;
}
bool descriptor_return_kind(std::string_view text, std::optional<Kind> &result,
                           std::string *reference_type = nullptr) {
    if (text.empty() || text.front() != '(') return false;
    std::size_t position = 1;
    while (position < text.size() && text[position] != ')') {
        std::optional<Kind> argument;
        if (!read_type(text, position, argument, false) || !argument) return false;
    }
    if (position >= text.size() || text[position++] != ')') return false;
    return read_type(text, position, result, true, reference_type) && position == text.size();
}
bool stack_map_locals(const std::vector<JvmVerificationType> &values, std::size_t max_locals,
                      Locals &locals, const JvmMetadata &metadata, std::string_view implicit_descriptor) {
    locals.assign(max_locals, top);
    std::size_t slot = 0;
    for (const auto &value : values) {
        if (slot >= max_locals) return false;
        const auto kind = frame_kind(value.kind);
        locals[slot++] = frame_value(value, metadata, implicit_descriptor);
        if (kind && width(*kind) == 2) {
            if (slot >= max_locals) return false;
            locals[slot++] = Value{*kind == long_value ? long_tail : double_tail};
        }
    }
    normalize_category2(locals);
    return true;
}
bool intersect_locals(Locals &current, const Locals &incoming, ReferenceResolver &references) {
    if (current.size() != incoming.size()) return false;
    bool changed = false;
    for (std::size_t i = 0; i < current.size(); ++i) {
        if (current[i].kind == top || incoming[i].kind == top) {
            if (current[i].kind != top) { current[i] = top; changed = true; }
        } else if (current[i] != incoming[i] && (is_uninitialized(current[i]) || is_uninitialized(incoming[i]))) {
            current[i] = top;
            changed = true;
        } else if (current[i] != incoming[i] && current[i].kind == reference && incoming[i].kind == reference) {
            const auto joined = references.common_type(current[i], incoming[i]);
            current[i] = Value{reference, 0, joined.value_or("Ljava/lang/Object;")};
            changed = true;
        } else if (current[i] != incoming[i] && current[i] != top) {
            current[i] = top;
            changed = true;
        }
    }
    normalize_category2(current);
    return changed;
}
}

Result<bool> verify_operand_stack(std::span<const std::byte> bytes, const std::vector<bool> &starts,
                                 const JvmCode &code, const JvmMember &method, const JvmMetadata &metadata,
                                 std::stop_token stop, std::size_t &class_work) {
    constexpr std::size_t max_class_work = 8'000'000, max_retained_entries = 1'048'576;
    bool partial = false, unresolved_frames = false;
    ReferenceResolver references(metadata);
    const auto tick = [&](std::size_t amount) {
        if (amount > max_class_work - class_work) { partial = true; return false; }
        class_work += amount; return true;
    };
    // Subroutine return addresses need context-sensitive jsr/ret analysis. Do
    // not infer normal successors, or report violations from a partial model.
    for (std::size_t offset = 0; offset < bytes.size(); ++offset) {
        if ((offset & 255u) == 0 && stop.stop_requested())
            return Error{ErrorCode::canceled, "JVM operand-stack verification canceled"};
        if (!tick(1)) return false;
        if (!starts[offset]) continue;
        const auto op = std::to_integer<std::uint8_t>(bytes[offset]);
        if (op == 0xa8 || op == 0xa9 || op == 0xc9 ||
            (op == 0xc4 && offset + 1 < bytes.size() && bytes[offset + 1] == std::byte{0xa9})) return false;
    }
    std::vector<std::optional<FrameState>> states(bytes.size());
    std::vector<const JvmStackMapFrame *> frames(bytes.size(), nullptr);
    if (code.stack_map_table)
        for (const auto &frame : code.stack_map_table->frames) frames[frame.bytecode_offset] = &frame;
    const bool constructor_method = method.name == "<init>";
    const bool requires_constructor_call = constructor_method && metadata.super_class != 0;
    const auto current_class_name = class_name(metadata, metadata.this_class);
    const bool root_object_constructor = constructor_method && !code.stack_map_table &&
        current_class_name && *current_class_name == "java/lang/Object";
    std::optional<Kind> declared_return;
    std::string declared_return_type;
    if (!descriptor_return_kind(method.descriptor, declared_return, &declared_return_type)) return false;
    Locals initial;
    if (code.stack_map_table) {
        if (!stack_map_locals(code.stack_map_table->initial_locals, code.max_locals, initial, metadata,
                              method.descriptor)) return false;
    } else if (!descriptor_locals(method, code.max_locals, initial, root_object_constructor, metadata)) return false;
    std::vector<std::size_t> pending;
    std::map<std::uint32_t, std::uint16_t> uninitialized_allocations;
    std::size_t retained_entries = initial.size();
    std::optional<Error> failure;
    const auto fail = [&](std::size_t offset, const char *reason) {
        failure = Error{ErrorCode::malformed, "JVM operand stack at bytecode offset " + std::to_string(offset) + ": " + reason};
    };
    const auto merge = [&](std::size_t offset, const Stack &incoming_stack, const Locals &incoming_locals,
                           bool constructor_initialized) {
        if (failure || partial || !tick(incoming_stack.size() + incoming_locals.size() + 1)) return;
        if (offset >= bytes.size() || !starts[offset]) { fail(offset, "control flow falls outside its Code array"); return; }
        if (slots(incoming_stack) > code.max_stack) { fail(offset, "depth exceeds Code.max_stack"); return; }
        if (incoming_locals.size() != code.max_locals) return;
        Stack effective_stack = incoming_stack;
        Locals effective_locals = incoming_locals;
        if (const auto *frame = frames[offset]) {
            if (!tick(frame->stack.size() + frame->locals.size())) return;
            if (!constructor_method && (std::any_of(frame->stack.begin(), frame->stack.end(), [](const auto &value) {
                    return value.kind == JvmVerificationKind::uninitialized_this;
                }) || std::any_of(frame->locals.begin(), frame->locals.end(), [](const auto &value) {
                    return value.kind == JvmVerificationKind::uninitialized_this;
                }))) {
                fail(offset, "uninitializedThis is declared outside a constructor");
                return;
            }
            // Top is unusable rather than a specific primitive/reference kind;
            // its detailed assignability is outside this coarse stack model.
            if (std::none_of(frame->stack.begin(), frame->stack.end(), [](const auto &value) {
                    return value.kind == JvmVerificationKind::top;
                })) {
                if (frame->stack.size() != incoming_stack.size()) { fail(offset, "height disagrees with the declared stack-map frame"); return; }
                for (std::size_t n = 0; n < incoming_stack.size(); ++n) {
                    const auto expected = frame_value(frame->stack[n], metadata, method.descriptor);
                    const auto actual = incoming_stack[n];
                    if (expected.kind == top) continue;
                    if (expected.kind == reference && actual.kind == reference &&
                        (is_uninitialized(expected) || is_uninitialized(actual))) {
                        if (!is_uninitialized(expected) || !is_uninitialized(actual) ||
                            expected.uninitialized != actual.uninitialized) {
                            fail(offset, "uninitialized identity disagrees with the declared stack-map frame"); return;
                        }
                        effective_stack[n] = actual;
                        continue;
                    }
                    if (expected.kind == reference && actual.kind == reference &&
                        !is_uninitialized(expected) && !is_uninitialized(actual)) {
                        if (frame->stack[n].kind == JvmVerificationKind::null_value) {
                            if (!actual.null_reference) { fail(offset, "reference stack type disagrees with the declared null stack-map frame"); return; }
                        } else {
                            const auto assignable = references.assignable(actual.reference_type,
                                expected.reference_type, actual.null_reference);
                            if (assignable == false) { fail(offset, "reference stack type is not assignable to the declared stack-map frame"); return; }
                            if (!assignable) unresolved_frames = true;
                        }
                        effective_stack[n] = expected;
                    } else if (expected != actual) {
                        fail(offset, "type or uninitialized identity disagrees with the declared stack-map frame"); return;
                    }
                }
            } else unresolved_frames = true;
            Locals frame_locals;
            if (!stack_map_locals(frame->locals, code.max_locals, frame_locals, metadata,
                                  method.descriptor)) return;
            for (std::size_t n = 0; n < effective_locals.size(); ++n) {
                const auto expected = frame_locals[n];
                const auto actual = effective_locals[n];
                if (expected == top) { effective_locals[n] = top; continue; }
                if (expected.kind == reference && actual.kind == reference &&
                    (is_uninitialized(expected) || is_uninitialized(actual))) {
                    if (!is_uninitialized(expected) || !is_uninitialized(actual) ||
                        expected.uninitialized != actual.uninitialized) {
                        fail(offset, "local uninitialized identity disagrees with the declared stack-map type"); return;
                    }
                    effective_locals[n] = actual;
                    continue;
                }
                if (expected.kind == reference && actual.kind == reference &&
                    !is_uninitialized(expected) && !is_uninitialized(actual)) {
                    if (expected.null_reference) {
                        if (!actual.null_reference) { fail(offset, "local reference disagrees with the declared null stack-map type"); return; }
                    } else {
                        const auto assignable = references.assignable(actual.reference_type,
                            expected.reference_type, actual.null_reference);
                        if (assignable == false) { fail(offset, "local reference is not assignable to the declared stack-map type"); return; }
                        if (!assignable) unresolved_frames = true;
                    }
                    effective_locals[n] = expected;
                    continue;
                }
                if (expected != actual) {
                    fail(offset, "local type disagrees with the declared stack-map frame");
                    return;
                }
            }
            normalize_category2(effective_locals);
        }
        auto &state = states[offset];
        if (state) {
            if (state->stack.size() != effective_stack.size()) {
                fail(offset, "inconsistent height, category layout or primitive types at control-flow merge");
                return;
            }
            bool stack_changed = false;
            for (std::size_t n = 0; n < effective_stack.size(); ++n) {
                if (state->stack[n] == effective_stack[n]) continue;
                if (state->stack[n].kind == reference && effective_stack[n].kind == reference &&
                    !is_uninitialized(state->stack[n]) && !is_uninitialized(effective_stack[n])) {
                    const auto joined = references.common_type(state->stack[n], effective_stack[n]);
                    const Value value{reference, 0, joined.value_or("Ljava/lang/Object;")};
                    if (state->stack[n] != value) { state->stack[n] = value; stack_changed = true; }
                } else {
                    fail(offset, "inconsistent height, category layout or primitive types at control-flow merge");
                    return;
                }
            }
            if (state->constructor_initialized != constructor_initialized) {
                fail(offset, "constructor initialization state disagrees at control-flow merge");
                return;
            }
            const bool locals_changed = intersect_locals(state->locals, effective_locals, references);
            if (locals_changed || stack_changed) pending.push_back(offset);
            return;
        }
        if (effective_locals.size() + incoming_stack.size() > max_retained_entries - retained_entries) { partial = true; return; }
        retained_entries += effective_locals.size() + incoming_stack.size();
        state = FrameState{std::move(effective_stack), std::move(effective_locals), constructor_initialized};
        pending.push_back(offset);
    };
    merge(0, {}, initial, !requires_constructor_call);
    for (std::size_t next = 0; next < pending.size() && !partial && !failure; ++next) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM operand-stack verification canceled"};
        const auto offset = pending[next];
        Stack stack = states[offset]->stack;
        Locals locals = states[offset]->locals;
        bool constructor_initialized = states[offset]->constructor_initialized;
        Locals exceptional_locals = locals;
        bool exceptional_constructor_initialized = constructor_initialized;
        if (!tick(stack.size() + 1)) break;
        auto decoded = decode_jvm(bytes.subspan(offset), {code.begin.space, offset});
        if (!decoded.instruction) return false; // The earlier static scan owns encoding errors.
        const auto &instruction = *decoded.instruction;
        const auto raw_op = std::to_integer<std::uint8_t>(bytes[offset]);
        const bool wide = raw_op == 0xc4;
        auto op = wide ? std::to_integer<std::uint8_t>(bytes[offset + 1]) : raw_op;
        const auto pool_index = [&]() -> std::uint64_t {
            const auto *value = instruction.operands.empty() ? nullptr : std::get_if<ImmediateOperand>(&instruction.operands[0]);
            return value ? value->value : 0;
        };
        const auto pop = [&](Kind expected, bool allow_uninitialized = false) -> Value {
            if (failure) return {};
            if (stack.empty()) { fail(offset, "operand underflow"); return {}; }
            if (stack.back().kind != expected) { fail(offset, "instruction consumes an incompatible primitive/reference category"); return {}; }
            const auto value = stack.back();
            if (expected == reference && is_uninitialized(value) && !allow_uninitialized) {
                fail(offset, "instruction uses an uninitialized object outside local/stack movement or constructor initialization");
                return {};
            }
            stack.pop_back();
            return value;
        };
        const auto push = [&](Value value) { stack.push_back(value); };
        const auto replace = [&](Kind from, Kind to) { pop(from); push(to); };
        const auto require_assignable = [&](const Value &actual, std::string_view expected, const char *reason) {
            if (failure) return;
            if (actual.kind != reference || is_uninitialized(actual)) {
                fail(offset, reason);
                return;
            }
            const auto result = references.assignable(actual.reference_type, expected, actual.null_reference);
            if (result == false) fail(offset, reason);
            else if (!result) unresolved_frames = true;
        };
        const std::uint8_t local_op = op;
        const auto local_index_for = [&]() -> std::optional<std::size_t> {
            if ((local_op >= 0x15 && local_op <= 0x19) || (local_op >= 0x36 && local_op <= 0x3a) || local_op == 0x84) {
                const auto operand_index = wide ? 1u : 0u;
                if (operand_index >= instruction.operands.size()) return {};
                const auto *value = std::get_if<ImmediateOperand>(&instruction.operands[operand_index]);
                if (!value) return {};
                return static_cast<std::size_t>(value->value);
            }
            if (local_op >= 0x1a && local_op <= 0x2d) {
                const auto group = static_cast<std::size_t>(local_op - 0x1a);
                return group % 4;
            }
            if (local_op >= 0x3b && local_op <= 0x4e) {
                const auto group = static_cast<std::size_t>(local_op - 0x3b);
                return group % 4;
            }
            return {};
        };
        const auto clear_local_slot = [&](std::size_t index) {
            if (index >= locals.size()) return;
            if ((locals[index] == long_value || locals[index] == double_value) && index + 1 < locals.size())
                locals[index + 1] = top;
            if (locals[index] == long_tail || locals[index] == double_tail) {
                if (index) locals[index - 1] = top;
            }
            locals[index] = top;
        };
        bool local_handled = false;
        if ((local_op >= 0x15 && local_op <= 0x19) || (local_op >= 0x1a && local_op <= 0x2d)) {
            const auto index = local_index_for();
            const std::size_t group = local_op >= 0x1a ? static_cast<std::size_t>((local_op - 0x1a) / 4)
                                                       : static_cast<std::size_t>(local_op - 0x15);
            if (!index || group >= local.size()) return false;
            const auto kind = local[group];
            const auto count = width(kind);
            if (*index + count > locals.size()) { fail(offset, "local load exceeds Code.max_locals"); }
            else if (locals[*index] != kind ||
                     (count == 2 && locals[*index + 1] != (kind == long_value ? long_tail : double_tail)))
                fail(offset, "local load reads an uninitialized or incompatible local category");
            else push(locals[*index]);
            local_handled = true;
        } else if ((local_op >= 0x36 && local_op <= 0x3a) || (local_op >= 0x3b && local_op <= 0x4e)) {
            const auto index = local_index_for();
            const std::size_t group = local_op >= 0x3b ? static_cast<std::size_t>((local_op - 0x3b) / 4)
                                                       : static_cast<std::size_t>(local_op - 0x36);
            if (!index || group >= local.size()) return false;
            const auto kind = local[group];
            const auto count = width(kind);
            const auto stored = pop(kind, kind == reference);
            if (!failure) {
                if (*index + count > locals.size()) fail(offset, "local store exceeds Code.max_locals");
                else {
                    clear_local_slot(*index);
                    if (count == 2) clear_local_slot(*index + 1);
                    locals[*index] = stored;
                    if (count == 2) locals[*index + 1] = kind == long_value ? long_tail : double_tail;
                }
            }
            local_handled = true;
        } else if (local_op == 0x84) {
            const auto index = local_index_for();
            if (!index) return false;
            if (*index >= locals.size()) fail(offset, "iinc local exceeds Code.max_locals");
            else if (locals[*index] != integer) fail(offset, "iinc reads an uninitialized or non-integer local");
            local_handled = true;
        }
        if (failure) break;
        if (local_handled) {}
        else if (op == 0x00 || op == 0xa7 || op == 0xc8) {}
        else if (op == 0xb1) {
            if (declared_return) fail(offset, "void return does not match the method descriptor");
        }
        else if (op == 0x01) push(Value{reference, 0, {}, true});
        else if ((op >= 0x02 && op <= 0x08) || op == 0x10 || op == 0x11) push(integer);
        else if (op <= 0x0a) push(long_value);
        else if (op <= 0x0d) push(float_value);
        else if (op <= 0x0f) push(double_value);
        else if (op >= 0x12 && op <= 0x14) {
            const auto index = pool_index();
            if (!index || index >= metadata.constant_pool.size()) return false;
            const auto tag = metadata.constant_pool[static_cast<std::size_t>(index)].tag;
            if (tag == 3) push(integer);
            else if (tag == 4) push(float_value);
            else if (tag == 5) push(long_value);
            else if (tag == 6) push(double_value);
            else if (tag == 17) {
                const auto text = descriptor(metadata, index);
                std::size_t position = 0; std::optional<Kind> kind; std::string reference_type;
                if (text && !tick(text->size())) return false;
                if (!text || !read_type(*text, position, kind, false, &reference_type) || !kind) return false;
                push(Value{*kind, 0, std::move(reference_type)});
            } else if (tag == 7) push(Value{reference, 0, "Ljava/lang/Class;"});
            else if (tag == 8) push(Value{reference, 0, "Ljava/lang/String;"});
            else if (tag == 15) push(Value{reference, 0, "Ljava/lang/invoke/MethodHandle;"});
            else if (tag == 16) push(Value{reference, 0, "Ljava/lang/invoke/MethodType;"});
            else return false;
        } else if (op >= 0x2e && op <= 0x35) {
            pop(integer);
            const auto array = pop(reference);
            const auto kind = array_element[op - 0x2e];
            if (kind == reference && op == 0x32 && !failure) {
                if (!array.reference_type.empty() && array.reference_type.front() == '[')
                    push(Value{reference, 0, array.reference_type.substr(1)});
                    else if (array.null_reference) push(Value{reference, 0, "Ljava/lang/Object;"});
                    else if (!array.reference_type.empty()) fail(offset, "aaload requires a reference-array operand");
                    else { push(reference); unresolved_frames = true; }
            } else push(kind);
        }
        else if (op >= 0x4f && op <= 0x56) {
            const auto kind = array_element[op - 0x4f];
            const auto value = pop(kind);
            pop(integer);
            const auto array = pop(reference);
            if (kind == reference && op == 0x53 && !failure) {
                if (!array.reference_type.empty() && array.reference_type.front() == '[')
                    require_assignable(value, std::string_view(array.reference_type).substr(1),
                        "aastore value is not assignable to the array component type");
                else unresolved_frames = true;
            }
        }
        else if (op >= 0x57 && op <= 0x5f) {
            bool matched = false;
            for (std::size_t count = 1; count <= std::min<std::size_t>(4, stack.size()); ++count) {
                std::array<std::uint8_t, 4> widths{};
                const auto begin = stack.size() - count;
                for (std::size_t n = 0; n < count; ++n) widths[n] = width(stack[begin + n]);
                auto form = evaluate_jvm_stack_manipulation_instruction(instruction, std::span(widths).first(count));
                if (!form) continue;
                Stack suffix(stack.begin() + begin, stack.end());
                stack.resize(begin);
                for (const auto index : form->source_indices) push(suffix[index]);
                matched = true; break;
            }
            if (!matched) fail(offset, "stack manipulation underflows or splits a category-2 value");
        } else if (op >= 0x60 && op <= 0x73) {
            const auto kind = scalar[(op - 0x60) % 4]; pop(kind); pop(kind); push(kind);
        } else if (op >= 0x74 && op <= 0x77) { const auto kind = scalar[op - 0x74]; replace(kind, kind); }
        else if (op >= 0x78 && op <= 0x7d) { const auto kind = (op & 1) ? long_value : integer; pop(integer); pop(kind); push(kind); }
        else if (op >= 0x7e && op <= 0x83) { const auto kind = (op & 1) ? long_value : integer; pop(kind); pop(kind); push(kind); }
        else if (op >= 0x85 && op <= 0x93) {
            constexpr std::array from{integer, integer, integer, long_value, long_value, long_value,
                float_value, float_value, float_value, double_value, double_value, double_value, integer, integer, integer};
            constexpr std::array to{long_value, float_value, double_value, integer, float_value, double_value,
                integer, long_value, double_value, integer, long_value, float_value, integer, integer, integer};
            replace(from[op - 0x85], to[op - 0x85]);
        } else if (op >= 0x94 && op <= 0x98) {
            const auto kind = op == 0x94 ? long_value : op <= 0x96 ? float_value : double_value;
            pop(kind); pop(kind); push(integer);
        } else if (op >= 0x99 && op <= 0x9e) pop(integer);
        else if (op >= 0x9f && op <= 0xa4) { pop(integer); pop(integer); }
        else if (op == 0xa5 || op == 0xa6) { pop(reference); pop(reference); }
        else if (op == 0xaa || op == 0xab) pop(integer);
        else if (op >= 0xac && op <= 0xb0) {
            const auto returned_kind = local[op - 0xac];
            if (!declared_return || *declared_return != returned_kind) {
                fail(offset, "return opcode does not match the method descriptor");
            } else {
                const auto returned = pop(returned_kind);
                if (returned_kind == reference && !failure)
                    require_assignable(returned, declared_return_type,
                        "reference return is not assignable to the method descriptor");
            }
        }
        else if (op >= 0xb2 && op <= 0xba) {
            const auto cp_index = pool_index();
            const auto text = descriptor(metadata, cp_index);
            if (!text) return false;
            if (!tick(text->size())) return false;
            std::size_t position = 0; std::optional<Kind> kind;
            if (op <= 0xb5) {
                std::string field_type;
                if (!read_type(*text, position, kind, false, &field_type) || !kind) return false;
                if (op == 0xb3 || op == 0xb5) {
                    const auto value = pop(*kind);
                    if (*kind == reference && !failure)
                        require_assignable(value, field_type, "reference field value is not assignable to the field descriptor");
                }
                if (op == 0xb4 || op == 0xb5) {
                    const auto receiver = pop(reference, op == 0xb5);
                    const auto owner = (op == 0xb4 || op == 0xb5)
                        ? member_owner_index(metadata, cp_index) : std::optional<std::uint16_t>{};
                    if (!failure && is_uninitialized(receiver) &&
                        (receiver.uninitialized != uninitialized_this || !constructor_method || constructor_initialized ||
                         !owner || !same_class(metadata, *owner, metadata.this_class)))
                        fail(offset, "putfield uses uninitializedThis outside a constructor field write to the current class");
                    else if (!failure && !is_uninitialized(receiver) && owner) {
                        const auto expected_owner = class_descriptor(metadata, *owner);
                        if (expected_owner) require_assignable(receiver, *expected_owner,
                            "field receiver is not assignable to the field owner");
                        else unresolved_frames = true;
                    } else if (!failure && !owner) unresolved_frames = true;
                }
                if (op == 0xb2 || op == 0xb4) push(Value{*kind, 0, std::move(field_type)});
            } else {
                if (text->empty() || (*text)[position++] != '(') return false;
                struct Parameter { Kind kind; std::string reference_type; };
                std::vector<Parameter> parameters;
                while (position < text->size() && (*text)[position] != ')') {
                    std::string reference_type;
                    if (!read_type(*text, position, kind, false, &reference_type) || !kind) return false;
                    parameters.push_back({*kind, std::move(reference_type)});
                }
                if (position >= text->size() || (*text)[position++] != ')') return false;
                for (auto argument = parameters.rbegin(); argument != parameters.rend(); ++argument) {
                    const auto value = pop(argument->kind);
                    if (argument->kind == reference && !failure)
                        require_assignable(value, argument->reference_type,
                            "reference argument is not assignable to the invoked descriptor");
                }
                std::string return_reference_type;
                if (!read_type(*text, position, kind, true, &return_reference_type)) return false;
                if (position != text->size()) return false;
                const auto name = op == 0xba ? std::optional<std::string_view>{} : member_name(metadata, cp_index);
                const bool initializes = op == 0xb7 && name && *name == "<init>";
                if (name && *name == "<init>" && op != 0xb7) {
                    fail(offset, "constructor must be invoked with invokespecial");
                } else if (initializes) {
                    if (kind) fail(offset, "constructor descriptor must return void");
                    const auto receiver = pop(reference, true);
                    const auto owner = member_owner_index(metadata, cp_index);
                    if (!failure && (!owner || !is_uninitialized(receiver))) {
                        fail(offset, "invokespecial <init> requires an uninitialized receiver and valid owner");
                    } else if (!failure && receiver.uninitialized == uninitialized_this) {
                        if (!constructor_method || constructor_initialized ||
                            (!same_class(metadata, *owner, metadata.this_class) &&
                             !same_class(metadata, *owner, metadata.super_class))) {
                            fail(offset, "uninitializedThis constructor call must target this class or its direct superclass");
                        } else {
                            for (auto &alias : exceptional_locals)
                                if (alias.uninitialized == uninitialized_this) alias = top;
                            exceptional_constructor_initialized = false;
                            const auto initialized = Value{reference, 0, "L" + metadata.class_name + ";"};
                            for (auto &alias : stack) if (alias.uninitialized == uninitialized_this) alias = initialized;
                            for (auto &alias : locals) if (alias.uninitialized == uninitialized_this) alias = initialized;
                            constructor_initialized = true;
                        }
                    } else if (!failure) {
                        const auto allocation = uninitialized_allocations.find(receiver.uninitialized);
                        if (allocation == uninitialized_allocations.end() ||
                            !same_class(metadata, allocation->second, *owner)) {
                            fail(offset, "constructor owner does not match the receiver's NEW instruction");
                        } else {
                            const auto identity = receiver.uninitialized;
                            for (auto &alias : exceptional_locals)
                                if (alias.uninitialized == identity) alias = top;
                            const auto initialized = Value{reference, 0,
                                class_descriptor(metadata, allocation->second).value_or(std::string{})};
                            for (auto &alias : stack) if (alias.uninitialized == identity) alias = initialized;
                            for (auto &alias : locals) if (alias.uninitialized == identity) alias = initialized;
                        }
                    }
                } else if (op != 0xb8 && op != 0xba) {
                    const auto receiver = pop(reference);
                    if (!failure) {
                        const auto owner = member_owner_index(metadata, cp_index);
                        const auto expected_owner = owner ? class_descriptor(metadata, *owner) : std::optional<std::string>{};
                        if (expected_owner) require_assignable(receiver, *expected_owner,
                            "invocation receiver is not assignable to the method owner");
                        else unresolved_frames = true;
                    }
                }
                if (kind) push(Value{*kind, 0, std::move(return_reference_type)});
            }
        } else if (op == 0xbb) {
            const auto class_index = pool_index();
            if (!class_index || class_index >= metadata.constant_pool.size() ||
                metadata.constant_pool[static_cast<std::size_t>(class_index)].tag != 7 ||
                class_index > std::numeric_limits<std::uint16_t>::max()) return false;
            const auto identity = static_cast<std::uint32_t>(offset) + 1u;
            if (std::any_of(stack.begin(), stack.end(), [&](const auto &value) {
                    return value.uninitialized == identity;
                })) {
                fail(offset, "new instruction reuses an uninitialized identity still on the operand stack");
            }
            for (auto &alias : locals) if (alias.uninitialized == identity) alias = top;
            uninitialized_allocations[identity] = static_cast<std::uint16_t>(class_index);
            push(Value{reference, identity, class_descriptor(metadata, class_index).value_or(std::string{})});
        }
        else if (op == 0xbc) {
            const auto *atype = instruction.operands.empty() ? nullptr : std::get_if<ImmediateOperand>(&instruction.operands[0]);
            pop(integer);
            if (!atype || atype->value < 4 || atype->value > 11) return false;
            constexpr std::array<std::string_view, 12> primitive_arrays{
                "", "", "", "", "[Z", "[C", "[F", "[D", "[B", "[S", "[I", "[J"};
            push(Value{reference, 0, std::string(primitive_arrays[atype->value])});
        }
        else if (op == 0xbd) {
            const auto component = pool_index();
            const auto type = class_descriptor(metadata, component);
            if (!type) return false;
            pop(integer);
            push(Value{reference, 0, "[" + *type});
        }
        else if (op == 0xbe) {
            const auto array = pop(reference);
            if (!failure && !array.null_reference) {
                if (array.reference_type.empty()) unresolved_frames = true;
                else if (array.reference_type.front() != '[') fail(offset, "arraylength requires an array operand");
            }
            push(integer);
        }
        else if (op == 0xc1) { pop(reference); push(integer); }
        else if (op == 0xbf) {
            const auto thrown = pop(reference);
            if (!failure) require_assignable(thrown, "Ljava/lang/Throwable;",
                "athrow operand is not assignable to java/lang/Throwable");
        }
        else if (op == 0xc2 || op == 0xc3 || op == 0xc6 || op == 0xc7) pop(reference);
        else if (op == 0xc0) {
            pop(reference);
            const auto type = class_descriptor(metadata, pool_index());
            if (!type) return false;
            push(Value{reference, 0, *type});
        }
        else if (op == 0xc5) {
            const auto *dimensions = instruction.operands.size() > 1 ? std::get_if<ImmediateOperand>(&instruction.operands[1]) : nullptr;
            if (!dimensions) return false;
            for (std::uint64_t n = 0; n < dimensions->value; ++n) pop(integer);
            const auto type = class_descriptor(metadata, pool_index());
            if (!type) return false;
            push(Value{reference, 0, *type});
        } else return false;
        if (!failure && op == 0xb1 && requires_constructor_call && !constructor_initialized)
            fail(offset, "constructor returns before initializing this");
        if (failure) break;
        if (slots(stack) > code.max_stack) { fail(offset, "depth exceeds Code.max_stack"); break; }
        // Every reachable protected instruction contributes its pre-execution
        // locals to its handler. The operand stack is replaced by one reference.
        for (std::size_t n = 0; n < code.exception_table.size(); ++n) {
            if (!tick(1)) break;
            const auto &handler = code.exception_table[n];
            if (offset >= handler.start_pc && offset < handler.end_pc) {
                const auto catch_type = handler.catch_type
                    ? class_descriptor(metadata, handler.catch_type)
                    : std::optional<std::string>{"Ljava/lang/Throwable;"};
                if (!catch_type) unresolved_frames = true;
                merge(handler.handler_pc, {Value{reference, 0, catch_type.value_or(std::string{})}},
                      exceptional_locals, exceptional_constructor_initialized);
            }
        }
        if (op == 0xaa || op == 0xab) {
            if (!instruction.jvm_switch) return false;
            merge(instruction.jvm_switch->default_target.offset, stack, locals, constructor_initialized);
            for (const auto &entry : instruction.jvm_switch->cases) {
                merge(entry.target.offset, stack, locals, constructor_initialized);
                if (partial || failure) break;
            }
        } else if (op == 0xa7 || op == 0xc8) {
            if (!instruction.direct_target) return false;
            merge(instruction.direct_target->offset, stack, locals, constructor_initialized);
        } else if (!((op >= 0xac && op <= 0xb1) || op == 0xbf)) {
            if (instruction.direct_target) merge(instruction.direct_target->offset, stack, locals, constructor_initialized);
            merge(offset + instruction.length, stack, locals, constructor_initialized);
        }
    }
    if (failure) return *failure;
    return !partial && !unresolved_frames;
}
}
