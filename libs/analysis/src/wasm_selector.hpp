#pragma once

#include "hexlab/analysis/functions.hpp"
#include <algorithm>
#include <bit>
#include <cstdint>
#include <optional>
#include <vector>

namespace hexlab::analysis_detail {

// Evaluate a small postfix i32 expression immediately preceding call_indirect.
// This is deliberately bounded and only consumes a contiguous straight-line
// expression made from constants and MVP integer arithmetic.
inline std::optional<std::uint32_t> wasm_constant_selector(
    std::vector<const Instruction *> instructions, Address call) {
    std::sort(instructions.begin(), instructions.end(), [](const auto *a, const auto *b) {
        return a->address.offset < b->address.offset;
    });
    auto end = std::find_if(instructions.begin(), instructions.end(), [&](const auto *instruction) {
        return instruction->address.offset + instruction->length == call.offset;
    });
    if (end == instructions.end()) return {};
    auto begin = end;
    std::size_t budget = 1;
    while (begin != instructions.begin() && budget < 64) {
        const auto *previous = *(begin - 1);
        const auto *next = *begin;
        if (previous->address.space != call.space ||
            previous->address.offset + previous->length != next->address.offset) break;
        --begin;
        ++budget;
    }
    instructions = std::vector<const Instruction *>(begin, end + 1);
    const auto count = instructions.size();
    struct Value { std::uint32_t bits; std::size_t begin; };
    const auto evaluate = [&](auto &&self, std::size_t exclusive, unsigned depth) -> std::optional<Value> {
        if (!exclusive || depth > 32) return {};
        const auto *instruction = instructions[exclusive - 1];
        if (instruction->address.space != call.space ||
            instruction->address.offset + instruction->length !=
                (exclusive == count ? call.offset : instructions[exclusive]->address.offset)) return {};
        const auto &mnemonic = instruction->mnemonic_override;
        if (mnemonic == "i32.const" && instruction->operands.size() == 1) {
            const auto *immediate = std::get_if<ImmediateOperand>(&instruction->operands[0]);
            if (!immediate || !immediate->is_signed || immediate->effective_width != 32) return {};
            return Value{static_cast<std::uint32_t>(immediate->value), exclusive - 1};
        }
        const auto unary = mnemonic == "i32.eqz" || mnemonic == "i32.clz" ||
                           mnemonic == "i32.ctz" || mnemonic == "i32.popcnt";
        const auto binary = mnemonic == "i32.add" || mnemonic == "i32.sub" ||
            mnemonic == "i32.mul" || mnemonic == "i32.and" || mnemonic == "i32.or" ||
            mnemonic == "i32.xor" || mnemonic == "i32.shl" || mnemonic == "i32.shr_s" ||
            mnemonic == "i32.shr_u" || mnemonic == "i32.rotl" || mnemonic == "i32.rotr";
        if ((!unary && !binary) || !instruction->operands.empty()) return {};
        auto right = self(self, exclusive - 1, depth + 1);
        if (!right) return {};
        std::uint32_t result = 0;
        if (unary) {
            if (mnemonic == "i32.eqz") result = right->bits == 0;
            else if (mnemonic == "i32.clz") result = std::countl_zero(right->bits);
            else if (mnemonic == "i32.ctz") result = std::countr_zero(right->bits);
            else result = std::popcount(right->bits);
            return Value{result, right->begin};
        }
        auto left = self(self, right->begin, depth + 1);
        if (!left) return {};
        const unsigned shift = right->bits & 31u;
        if (mnemonic == "i32.add") result = left->bits + right->bits;
        else if (mnemonic == "i32.sub") result = left->bits - right->bits;
        else if (mnemonic == "i32.mul") result = left->bits * right->bits;
        else if (mnemonic == "i32.and") result = left->bits & right->bits;
        else if (mnemonic == "i32.or") result = left->bits | right->bits;
        else if (mnemonic == "i32.xor") result = left->bits ^ right->bits;
        else if (mnemonic == "i32.shl") result = left->bits << shift;
        else if (mnemonic == "i32.shr_u") result = left->bits >> shift;
        else if (mnemonic == "i32.shr_s") result = static_cast<std::uint32_t>(static_cast<std::int32_t>(left->bits) >> shift);
        else if (mnemonic == "i32.rotl") result = std::rotl(left->bits, static_cast<int>(shift));
        else result = std::rotr(left->bits, static_cast<int>(shift));
        return Value{result, left->begin};
    };
    // The full prefix may contain unrelated earlier code, so only the
    // recursively consumed suffix matters; cap the scan at 64 instructions.
    const auto value = evaluate(evaluate, count, 0);
    if (!value) return {};
    for (std::size_t i = value->begin; i < count; ++i) {
        if (instructions[i]->address.space != call.space) return {};
        const auto next = i + 1 == count ? call.offset : instructions[i + 1]->address.offset;
        if (instructions[i]->address.offset + instructions[i]->length != next) return {};
    }
    return value->bits;
}

} // namespace hexlab::analysis_detail
