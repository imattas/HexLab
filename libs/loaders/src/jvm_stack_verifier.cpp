#include "jvm_stack_verifier.hpp"
#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/jvm_semantics.hpp"
#include <algorithm>
#include <array>
#include <optional>

namespace hexlab::jvm_detail {
namespace {
enum class Kind : std::uint8_t {
    top, integer, long_value, long_tail, float_value, double_value, double_tail, reference
};
using Stack = std::vector<Kind>;
using Locals = std::vector<Kind>;
struct FrameState { Stack stack; Locals locals; };
constexpr auto top = Kind::top, integer = Kind::integer, long_value = Kind::long_value,
    long_tail = Kind::long_tail, float_value = Kind::float_value,
    double_value = Kind::double_value, double_tail = Kind::double_tail,
    reference = Kind::reference;
constexpr std::array scalar{integer, long_value, float_value, double_value};
constexpr std::array local{integer, long_value, float_value, double_value, reference};
constexpr std::array array_element{integer, long_value, float_value, double_value, reference, integer, integer, integer};
std::uint8_t width(Kind value) { return value == long_value || value == double_value ? 2 : 1; }
std::size_t slots(const Stack &stack) {
    std::size_t result = 0;
    for (const auto value : stack) result += width(value);
    return result;
}
// Descriptors have already passed classfile syntax validation. Keep this reader
// defensive, and never search for ')' through class names inside a descriptor.
bool read_type(std::string_view text, std::size_t &position, std::optional<Kind> &result, bool allow_void) {
    if (position >= text.size()) return false;
    if (text[position] == '[') {
        while (position < text.size() && text[position] == '[') ++position;
        std::optional<Kind> element;
        if (!read_type(text, position, element, false)) return false;
        result = reference;
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
        position = end + 1; result = reference; return true;
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
bool descriptor_locals(const JvmMember &method, std::size_t max_locals, Locals &locals, bool &unresolved) {
    locals.assign(max_locals, top);
    std::size_t position = 0, slot = 0;
    const std::string_view text = method.descriptor;
    if (text.empty() || text[position++] != '(') return false;
    if ((method.access_flags & 0x0008u) == 0) {
        if (slot >= max_locals) return false;
        locals[slot++] = reference;
        if (method.name == "<init>") unresolved = true;
    }
    while (position < text.size() && text[position] != ')') {
        std::optional<Kind> kind;
        if (!read_type(text, position, kind, false) || !kind || slot >= max_locals) return false;
        locals[slot++] = *kind;
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
bool stack_map_locals(const std::vector<JvmVerificationType> &values, std::size_t max_locals,
                      Locals &locals, bool &unresolved) {
    locals.assign(max_locals, top);
    std::size_t slot = 0;
    for (const auto &value : values) {
        if (value.kind == JvmVerificationKind::uninitialized ||
            value.kind == JvmVerificationKind::uninitialized_this) unresolved = true;
        if (slot >= max_locals) return false;
        const auto kind = frame_kind(value.kind);
        // An uninitialized verification type is retained as a reference
        // category. Constructor initialization/alias identity is unresolved.
        locals[slot++] = kind.value_or(top);
        if (kind && width(*kind) == 2) {
            if (slot >= max_locals) return false;
            locals[slot++] = *kind == long_value ? long_tail : double_tail;
        }
    }
    normalize_category2(locals);
    return true;
}
bool intersect_locals(Locals &current, const Locals &incoming) {
    if (current.size() != incoming.size()) return false;
    bool changed = false;
    for (std::size_t i = 0; i < current.size(); ++i) {
        if (current[i] != incoming[i] && current[i] != top) {
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
    Locals initial;
    if (code.stack_map_table) {
        if (!stack_map_locals(code.stack_map_table->initial_locals, code.max_locals, initial, unresolved_frames)) return false;
    } else if (!descriptor_locals(method, code.max_locals, initial, unresolved_frames)) return false;
    std::vector<std::size_t> pending;
    std::size_t retained_entries = initial.size();
    std::optional<Error> failure;
    const auto fail = [&](std::size_t offset, const char *reason) {
        failure = Error{ErrorCode::malformed, "JVM operand stack at bytecode offset " + std::to_string(offset) + ": " + reason};
    };
    const auto merge = [&](std::size_t offset, const Stack &incoming_stack, const Locals &incoming_locals) {
        if (failure || partial || !tick(incoming_stack.size() + incoming_locals.size() + 1)) return;
        if (offset >= bytes.size() || !starts[offset]) { fail(offset, "control flow falls outside its Code array"); return; }
        if (slots(incoming_stack) > code.max_stack) { fail(offset, "depth exceeds Code.max_stack"); return; }
        if (incoming_locals.size() != code.max_locals) return;
        Locals effective_locals = incoming_locals;
        if (const auto *frame = frames[offset]) {
            if (!tick(frame->stack.size() + frame->locals.size())) return;
            if (std::any_of(frame->stack.begin(), frame->stack.end(), [](const auto &value) {
                    return value.kind == JvmVerificationKind::uninitialized ||
                           value.kind == JvmVerificationKind::uninitialized_this;
                })) unresolved_frames = true;
            // Top is unusable rather than a specific primitive/reference kind;
            // its detailed assignability is outside this coarse stack model.
            if (std::none_of(frame->stack.begin(), frame->stack.end(), [](const auto &value) {
                    return value.kind == JvmVerificationKind::top;
                })) {
                if (frame->stack.size() != incoming_stack.size()) { fail(offset, "height disagrees with the declared stack-map frame"); return; }
                for (std::size_t n = 0; n < incoming_stack.size(); ++n) {
                    const auto kind = frame_kind(frame->stack[n].kind);
                    if (kind && *kind != incoming_stack[n]) { fail(offset, "type disagrees with the declared stack-map frame"); return; }
                }
            } else unresolved_frames = true;
            Locals frame_locals;
            if (!stack_map_locals(frame->locals, code.max_locals, frame_locals, unresolved_frames)) return;
            for (std::size_t n = 0; n < effective_locals.size(); ++n) {
                const auto expected = frame_locals[n];
                const auto actual = effective_locals[n];
                if (expected == top) { effective_locals[n] = top; continue; }
                if (expected != actual) {
                    fail(offset, "local type disagrees with the declared stack-map frame");
                    return;
                }
            }
            normalize_category2(effective_locals);
        }
        auto &state = states[offset];
        if (state) {
            if (state->stack != incoming_stack) {
                fail(offset, "inconsistent height, category layout or primitive types at control-flow merge");
                return;
            }
            if (intersect_locals(state->locals, effective_locals)) pending.push_back(offset);
            return;
        }
        if (effective_locals.size() + incoming_stack.size() > max_retained_entries - retained_entries) { partial = true; return; }
        retained_entries += effective_locals.size() + incoming_stack.size();
        state = FrameState{incoming_stack, std::move(effective_locals)};
        pending.push_back(offset);
    };
    merge(0, {}, initial);
    for (std::size_t next = 0; next < pending.size() && !partial && !failure; ++next) {
        if (stop.stop_requested()) return Error{ErrorCode::canceled, "JVM operand-stack verification canceled"};
        const auto offset = pending[next];
        Stack stack = states[offset]->stack;
        Locals locals = states[offset]->locals;
        const Locals exceptional_locals = locals;
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
        const auto pop = [&](Kind expected) {
            if (failure) return;
            if (stack.empty()) { fail(offset, "operand underflow"); return; }
            if (stack.back() != expected) { fail(offset, "instruction consumes an incompatible primitive/reference category"); return; }
            stack.pop_back();
        };
        const auto push = [&](Kind value) { stack.push_back(value); };
        const auto replace = [&](Kind from, Kind to) { pop(from); push(to); };
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
            else push(kind);
            local_handled = true;
        } else if ((local_op >= 0x36 && local_op <= 0x3a) || (local_op >= 0x3b && local_op <= 0x4e)) {
            const auto index = local_index_for();
            const std::size_t group = local_op >= 0x3b ? static_cast<std::size_t>((local_op - 0x3b) / 4)
                                                       : static_cast<std::size_t>(local_op - 0x36);
            if (!index || group >= local.size()) return false;
            const auto kind = local[group];
            const auto count = width(kind);
            pop(kind);
            if (!failure) {
                if (*index + count > locals.size()) fail(offset, "local store exceeds Code.max_locals");
                else {
                    clear_local_slot(*index);
                    if (count == 2) clear_local_slot(*index + 1);
                    locals[*index] = kind;
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
        else if (op == 0x00 || op == 0xa7 || op == 0xc8 || op == 0xb1) {}
        else if (op == 0x01) push(reference);
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
                std::size_t position = 0; std::optional<Kind> kind;
                if (text && !tick(text->size())) return false;
                if (!text || !read_type(*text, position, kind, false) || !kind) return false;
                push(*kind);
            } else push(reference);
        } else if (op >= 0x2e && op <= 0x35) { pop(integer); pop(reference); push(array_element[op - 0x2e]); }
        else if (op >= 0x4f && op <= 0x56) { pop(array_element[op - 0x4f]); pop(integer); pop(reference); }
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
        else if (op >= 0xac && op <= 0xb0) pop(local[op - 0xac]);
        else if (op >= 0xb2 && op <= 0xba) {
            const auto text = descriptor(metadata, pool_index());
            if (!text) return false;
            if (!tick(text->size())) return false;
            std::size_t position = 0; std::optional<Kind> kind;
            if (op <= 0xb5) {
                if (!read_type(*text, position, kind, false) || !kind) return false;
                if (op == 0xb3 || op == 0xb5) pop(*kind);
                if (op == 0xb4 || op == 0xb5) pop(reference);
                if (op == 0xb2 || op == 0xb4) push(*kind);
            } else {
                if (text->empty() || (*text)[position++] != '(') return false;
                Stack parameters;
                while (position < text->size() && (*text)[position] != ')') {
                    if (!read_type(*text, position, kind, false) || !kind) return false;
                    parameters.push_back(*kind);
                }
                if (position >= text->size() || (*text)[position++] != ')') return false;
                for (auto argument = parameters.rbegin(); argument != parameters.rend(); ++argument) pop(*argument);
                if (op != 0xb8 && op != 0xba) pop(reference);
                if (!read_type(*text, position, kind, true)) return false;
                if (kind) push(*kind);
            }
        } else if (op == 0xbb) { unresolved_frames = true; push(reference); }
        else if (op == 0xbc || op == 0xbd) replace(integer, reference);
        else if (op == 0xbe || op == 0xc1) replace(reference, integer);
        else if (op == 0xbf || op == 0xc2 || op == 0xc3 || op == 0xc6 || op == 0xc7) pop(reference);
        else if (op == 0xc0) replace(reference, reference);
        else if (op == 0xc5) {
            const auto *dimensions = instruction.operands.size() > 1 ? std::get_if<ImmediateOperand>(&instruction.operands[1]) : nullptr;
            if (!dimensions) return false;
            for (std::uint64_t n = 0; n < dimensions->value; ++n) pop(integer);
            push(reference);
        } else return false;
        if (failure) break;
        if (slots(stack) > code.max_stack) { fail(offset, "depth exceeds Code.max_stack"); break; }
        // Every reachable protected instruction contributes its pre-execution
        // locals to its handler. The operand stack is replaced by one reference.
        for (std::size_t n = 0; n < code.exception_table.size(); ++n) {
            if (!tick(1)) break;
            const auto &handler = code.exception_table[n];
            if (offset >= handler.start_pc && offset < handler.end_pc)
                merge(handler.handler_pc, {reference}, exceptional_locals);
        }
        if (op == 0xaa || op == 0xab) {
            if (!instruction.jvm_switch) return false;
            merge(instruction.jvm_switch->default_target.offset, stack, locals);
            for (const auto &entry : instruction.jvm_switch->cases) {
                merge(entry.target.offset, stack, locals);
                if (partial || failure) break;
            }
        } else if (op == 0xa7 || op == 0xc8) {
            if (!instruction.direct_target) return false;
            merge(instruction.direct_target->offset, stack, locals);
        } else if (!((op >= 0xac && op <= 0xb1) || op == 0xbf)) {
            if (instruction.direct_target) merge(instruction.direct_target->offset, stack, locals);
            merge(offset + instruction.length, stack, locals);
        }
    }
    if (failure) return *failure;
    return !partial && !unresolved_frames;
}
}
