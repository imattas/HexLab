#include "functions_internal.hpp"
#include <algorithm>
#include <bit>

namespace hexlab::function_detail {
namespace {
constexpr std::uint16_t all_flags = 0xffff;
using FlagTransfer = std::array<std::uint16_t, 16>;
struct Constants {
    std::array<std::uint64_t, 31> values{};
    std::uint32_t known = 0;
};
bool a64(const Node &node) {
    return node.fact && node.fact->instruction.context.architecture == Architecture::arm64 &&
           node.fact->instruction.context.mode == ExecutionMode::a64;
}
std::uint64_t width_mask(unsigned width) {
    return width == 32 ? UINT64_C(0xffffffff) : UINT64_MAX;
}
const RegisterOperand *reg(const Instruction &i, std::size_t n) {
    if (n >= i.operands.size()) return nullptr;
    const auto *r = std::get_if<RegisterOperand>(&i.operands[n]);
    if (!r || (r->width != 32 && r->width != 64)) return nullptr;
    if (r->bank == RegisterBank::arm64_gpr) return r->index < 31 ? r : nullptr;
    return (r->bank == RegisterBank::arm64_zero || r->bank == RegisterBank::arm64_sp) && r->index == 31 ? r : nullptr;
}
std::optional<std::uint64_t> immediate(const Instruction &i, std::size_t n) {
    if (n >= i.operands.size()) return {};
    const auto *value = std::get_if<ImmediateOperand>(&i.operands[n]);
    return value ? std::optional{value->value} : std::nullopt;
}
std::optional<std::uint64_t> read(const Constants &state, const RegisterOperand *r) {
    if (!r) return {};
    if (r->bank == RegisterBank::arm64_zero) return 0;
    if (r->bank != RegisterBank::arm64_gpr || r->index >= 31 || !(state.known & (1u << r->index)))
        return {};
    return state.values[r->index] & width_mask(r->width);
}
void write(Constants &state, const RegisterOperand *r, std::optional<std::uint64_t> value) {
    if (!r || r->bank != RegisterBank::arm64_gpr || r->index >= 31 || !value) return;
    state.known |= 1u << r->index;
    // A W write establishes the complete zero-extended X value.
    state.values[r->index] = *value & width_mask(r->width);
}
bool condition(std::uint8_t code, std::uint8_t f) {
    const bool n = f & 8, z = f & 4, c = f & 2, v = f & 1;
    switch (code) {
    case 0: return z; case 1: return !z; case 2: return c; case 3: return !c;
    case 4: return n; case 5: return !n; case 6: return v; case 7: return !v;
    case 8: return c && !z; case 9: return !c || z;
    case 10: return n == v; case 11: return n != v;
    case 12: return !z && n == v; case 13: return z || n != v;
    default: return true;
    }
}
std::uint8_t flags(std::uint64_t lhs, std::uint64_t rhs, unsigned width, bool subtract) {
    const auto mask = width_mask(width), sign = UINT64_C(1) << (width - 1);
    lhs &= mask; rhs &= mask;
    const auto result = (subtract ? lhs - rhs : lhs + rhs) & mask;
    const bool carry = subtract ? lhs >= rhs : lhs > mask - rhs;
    const bool overflow = ((subtract ? (lhs ^ rhs) : ~(lhs ^ rhs)) & (lhs ^ result) & sign) != 0;
    return static_cast<std::uint8_t>((result & sign ? 8 : 0) | (!result ? 4 : 0) |
                                     (carry ? 2 : 0) | (overflow ? 1 : 0));
}
struct Binary {
    unsigned width = 0;
    std::optional<std::uint64_t> lhs, rhs;
    bool same_unshifted_register = false;
};
Binary binary(const Instruction &i, const Constants &state, std::size_t first = 1, std::size_t second = 2) {
    Binary result;
    const auto *lhs = reg(i, first);
    if (!lhs) return result;
    result.width = lhs->width;
    result.lhs = read(state, lhs);
    if (const auto value = immediate(i, second)) {
        result.rhs = *value & width_mask(result.width);
        return result;
    }
    const auto *rhs = reg(i, second);
    if (!rhs || rhs->width != result.width) return {};
    result.rhs = read(state, rhs);
    unsigned shift = 0, amount = 0;
    if (first == 1 && i.operands.size() == 4) {
        const auto encoded_amount = immediate(i, 3);
        if (!encoded_amount || *encoded_amount >= result.width || i.byte_length() != 4) return {};
        std::uint32_t word = 0;
        for (unsigned b = 0; b < 4; ++b) word |= std::to_integer<std::uint32_t>(i.bytes[b]) << (8 * b);
        shift = (word >> 22) & 3u;
        amount = static_cast<unsigned>(*encoded_amount);
    }
    result.same_unshifted_register = !shift && !amount && *lhs == *rhs;
    if (result.rhs && (shift || amount)) {
        const auto value = *result.rhs;
        if (shift == 0) result.rhs = (value << amount) & width_mask(result.width);
        else if (shift == 1) result.rhs = value >> amount;
        else if (shift == 2) {
            if (result.width == 32)
                result.rhs = static_cast<std::uint32_t>(std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(value)) >> amount);
            else result.rhs = static_cast<std::uint64_t>(std::bit_cast<std::int64_t>(value) >> amount);
        } else if (i.opcode == Opcode::a64_and || i.opcode == Opcode::a64_ands ||
                   i.opcode == Opcode::a64_orr || i.opcode == Opcode::a64_eor) {
            result.rhs = result.width == 32 ? std::rotr(static_cast<std::uint32_t>(value), amount)
                                             : std::rotr(value, amount);
        } else return {};
    }
    return result;
}
bool binary_opcode(Opcode op) {
    return op == Opcode::a64_add || op == Opcode::a64_adds || op == Opcode::a64_sub || op == Opcode::a64_subs ||
           op == Opcode::a64_and || op == Opcode::a64_ands || op == Opcode::a64_orr || op == Opcode::a64_eor;
}
std::optional<std::uint64_t> binary_result(Opcode op, const Binary &b) {
    if (!b.width) return {};
    if (b.same_unshifted_register && (op == Opcode::a64_sub || op == Opcode::a64_subs || op == Opcode::a64_eor))
        return 0;
    if ((op == Opcode::a64_and || op == Opcode::a64_ands) &&
        ((b.lhs && !*b.lhs) || (b.rhs && !*b.rhs))) return 0;
    if (!b.lhs || !b.rhs) return {};
    switch (op) {
    case Opcode::a64_add: case Opcode::a64_adds: return (*b.lhs + *b.rhs) & width_mask(b.width);
    case Opcode::a64_sub: case Opcode::a64_subs: return (*b.lhs - *b.rhs) & width_mask(b.width);
    case Opcode::a64_and: case Opcode::a64_ands: return *b.lhs & *b.rhs;
    case Opcode::a64_orr: return *b.lhs | *b.rhs;
    case Opcode::a64_eor: return *b.lhs ^ *b.rhs;
    default: return {};
    }
}
std::optional<FlagTransfer> flag_transfer(const Instruction &i, const Constants &state) {
    std::optional<std::uint8_t> known;
    if (i.opcode == Opcode::a64_adds || i.opcode == Opcode::a64_subs || i.opcode == Opcode::a64_ands) {
        const auto b = binary(i, state);
        const auto value = binary_result(i.opcode, b);
        if (i.opcode == Opcode::a64_subs && b.same_unshifted_register) known = std::uint8_t{6};
        else if (i.opcode == Opcode::a64_ands && value)
            known = static_cast<std::uint8_t>((*value & (UINT64_C(1) << (b.width - 1)) ? 8 : 0) | (!*value ? 4 : 0));
        else if (b.lhs && b.rhs) known = flags(*b.lhs, *b.rhs, b.width, i.opcode == Opcode::a64_subs);
        if (known) { FlagTransfer transfer; transfer.fill(static_cast<std::uint16_t>(1u << *known)); return transfer; }
    } else if ((i.opcode == Opcode::a64_ccmp || i.opcode == Opcode::a64_ccmn) && i.operands.size() == 3) {
        const auto b = binary(i, state, 0, 1);
        const auto fallback = immediate(i, 2);
        if (!b.width || !fallback || *fallback > 15) return {};
        if (i.opcode == Opcode::a64_ccmp && b.same_unshifted_register) known = std::uint8_t{6};
        else if (b.lhs && b.rhs) known = flags(*b.lhs, *b.rhs, b.width, i.opcode == Opcode::a64_ccmp);
        FlagTransfer transfer;
        for (std::uint8_t input = 0; input < 16; ++input)
            transfer[input] = condition(i.condition, input)
                ? (known ? static_cast<std::uint16_t>(1u << *known) : all_flags)
                : static_cast<std::uint16_t>(1u << *fallback);
        return transfer;
    }
    return {};
}
Constants transfer(const Instruction &i, const Constants &input, bool relocated) {
    Constants output = input;
    for (const auto &r : i.register_writes)
        if (r.bank == RegisterBank::arm64_gpr && r.index < 31) output.known &= ~(1u << r.index);
    if (i.flow == FlowKind::call || i.opcode == Opcode::opaque) return {};
    if (relocated) return output;
    const auto *destination = reg(i, 0);
    if (binary_opcode(i.opcode) && (i.operands.size() == 3 || i.operands.size() == 4)) {
        const auto b = binary(i, input);
        if (destination && destination->width == b.width) write(output, destination, binary_result(i.opcode, b));
    } else if ((i.opcode == Opcode::a64_movz || i.opcode == Opcode::a64_movn || i.opcode == Opcode::a64_movk) &&
               destination && (i.operands.size() == 2 || i.operands.size() == 3)) {
        const auto value = immediate(i, 1);
        const auto shift = i.operands.size() == 3 ? immediate(i, 2) : std::optional<std::uint64_t>{0};
        if (value && *value <= 0xffff && shift && *shift < destination->width && *shift % 16 == 0) {
            const auto part = *value << *shift, mask = width_mask(destination->width);
            if (i.opcode == Opcode::a64_movz) write(output, destination, part);
            else if (i.opcode == Opcode::a64_movn) write(output, destination, ~part & mask);
            else if (const auto prior = read(input, destination))
                write(output, destination, (*prior & ~(UINT64_C(0xffff) << *shift)) | part);
        }
    } else if ((i.opcode == Opcode::a64_csel || i.opcode == Opcode::a64_csinc ||
                i.opcode == Opcode::a64_csinv || i.opcode == Opcode::a64_csneg) &&
               destination && i.operands.size() == 3) {
        const auto *left = reg(i, 1), *right = reg(i, 2);
        if (left && right && destination->width == left->width && left->width == right->width) {
            const auto yes = read(input, left);
            auto no = read(input, right);
            if (no) {
                if (i.opcode == Opcode::a64_csinc) no = (*no + 1) & width_mask(destination->width);
                else if (i.opcode == Opcode::a64_csinv) no = ~*no & width_mask(destination->width);
                else if (i.opcode == Opcode::a64_csneg) no = (UINT64_C(0) - *no) & width_mask(destination->width);
            }
            if (i.condition >= 14 || (yes && no && *yes == *no)) write(output, destination, yes);
        }
    }
    return output;
}
void meet(Constants &state, const Constants &other) {
    state.known &= other.known;
    for (unsigned r = 0; r < 31; ++r)
        if ((state.known & (1u << r)) && state.values[r] != other.values[r]) state.known &= ~(1u << r);
}
} // namespace

std::uint16_t Recovery::edge_flags(const Node &node, const NodeEdge &edge, std::uint16_t incoming) const {
    incoming = static_cast<std::uint16_t>(incoming & edge.flags_guard);
    if (!incoming || !edge.flags_unknown_after) return incoming;
    const auto transfer = a64_flag_transfers.find(node.at);
    if (transfer == a64_flag_transfers.end()) return all_flags;
    std::uint16_t outgoing_flags = 0;
    for (unsigned input = 0; input < 16; ++input)
        if (incoming & (1u << input)) outgoing_flags = static_cast<std::uint16_t>(outgoing_flags | transfer->second[input]);
    return outgoing_flags;
}

void Recovery::refine_a64_flow() {
    // Keep memory and work bounded independently of the user's decode budget.
    constexpr std::size_t node_limit = 100000;
    constexpr std::size_t edge_limit = 500000;
    AddressSet eligible, entries;
    for (const auto &[at, node] : nodes) {
        canceled();
        if (a64(node)) eligible.insert(at);
        if (eligible.size() > node_limit) return;
    }
    for (const auto &[entry, seeds] : all_seeds) { (void)seeds; entries.insert(entry); }
    entries.insert(root_entries.begin(), root_entries.end());
    for (const auto &[entry, definition] : definitions) {
        (void)entry;
        for (const auto &chunk : definition->chunks) entries.insert(chunk.begin);
    }
    AddressMap<AddressSet> predecessors, successors;
    std::size_t edges = 0;
    for (const auto at : eligible) {
        canceled();
        for (const auto &edge : nodes.at(at).edges) {
            if (++edges > edge_limit) return;
            if (!edge.target || !eligible.contains(*edge.target)) continue;
            const auto &source = nodes.at(at).fact->instruction;
            const auto &target = nodes.at(*edge.target).fact->instruction;
            if (at.space != edge.target->space || source.context != target.context) {
                entries.insert(*edge.target);
                continue;
            }
            predecessors[*edge.target].insert(at);
            successors[at].insert(*edge.target);
        }
    }
    AddressMap<std::size_t> remaining;
    std::deque<Address> ready;
    for (const auto at : eligible) {
        const auto count = entries.contains(at) ? 0 : predecessors[at].size();
        remaining.emplace(at, count);
        if (!count) ready.push_back(at);
    }
    AddressMap<Constants> outputs;
    const auto evaluate = [&](Address at, const Constants &input) {
        canceled();
        auto &node = nodes.at(at);
        const auto &i = node.fact->instruction;
        bool relocated = false;
        for (std::uint32_t n = 0; n < i.operands.size(); ++n)
            if (take(relocations.operand(i, n, stop)).relocated()) { relocated = true; break; }
        if (!relocated) {
            if (const auto evaluated = flag_transfer(i, input)) a64_flag_transfers[at] = *evaluated;
            if (i.opcode == Opcode::a64_cbz || i.opcode == Opcode::a64_cbnz ||
                i.opcode == Opcode::a64_tbz || i.opcode == Opcode::a64_tbnz) {
                const auto value = read(input, reg(i, 0));
                std::optional<bool> taken;
                if (value && (i.opcode == Opcode::a64_cbz || i.opcode == Opcode::a64_cbnz))
                    taken = i.opcode == Opcode::a64_cbz ? *value == 0 : *value != 0;
                else if (value) {
                    const auto bit = immediate(i, 1);
                    const auto *source = reg(i, 0);
                    if (bit && source && *bit < source->width)
                        taken = i.opcode == Opcode::a64_tbz ? ((*value >> *bit) & 1) == 0 : ((*value >> *bit) & 1) != 0;
                }
                if (taken) {
                    for (auto &edge : node.edges)
                        if ((edge.kind == BlockEdgeKind::conditional_false && *taken) ||
                            ((edge.kind == BlockEdgeKind::conditional_true || edge.kind == BlockEdgeKind::unresolved) && !*taken))
                            edge.flags_guard = 0;
                    if (!*taken) node.stop_guard = 0;
                }
            }
        }
        return transfer(i, input, relocated);
    };
    while (!ready.empty()) {
        const auto at = ready.front(); ready.pop_front();
        Constants incoming;
        bool first = true;
        if (!entries.contains(at)) for (const auto source : predecessors[at]) {
            const auto found = outputs.find(source);
            if (found == outputs.end()) { incoming = {}; first = false; break; }
            if (first) { incoming = found->second; first = false; }
            else meet(incoming, found->second);
        }
        outputs.emplace(at, evaluate(at, incoming));
        for (const auto target : successors[at]) {
            auto &count = remaining.at(target);
            if (count && --count == 0) ready.push_back(target);
        }
    }
    // Back edges do not establish speculative entry constants. Local identities
    // and zero-register operands still prove flags inside an unresolved cycle.
    for (const auto at : eligible) if (!outputs.contains(at)) (void)evaluate(at, {});
}
} // namespace hexlab::function_detail
