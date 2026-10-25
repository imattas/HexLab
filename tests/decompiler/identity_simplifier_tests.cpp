#include "hexlab/decompiler/decompiler.hpp"

#include <cstdlib>
#include <iostream>

using namespace hexlab;
using namespace hexlab::decompiler;

namespace {
void require(bool condition, const char *message) {
    if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}

ExpressionPtr reg(unsigned index, std::uint16_t bits = 8) {
    return std::make_shared<Expression>(Expression{{TypeKind::integer, bits, false},
        RegisterValue{RegisterOperand{RegisterBank::gpr, static_cast<std::uint8_t>(index), bits, false},
                      std::uint32_t{1}}});
}
ExpressionPtr constant(std::uint64_t value, std::uint16_t bits = 8) {
    auto type = ValueType{TypeKind::integer, bits, false};
    return std::make_shared<Expression>(Expression{type, ConstantValue{value, type}});
}
ExpressionPtr binary(const char *op, ExpressionPtr left, ExpressionPtr right, std::uint16_t bits = 8) {
    return std::make_shared<Expression>(Expression{{TypeKind::integer, bits, false},
        BinaryValue{op, std::move(left), std::move(right)}});
}
}

int main() {
    const Address at{{0}, 0x1000};
    const RegisterOperand dst{RegisterBank::gpr, 2, 8, false};
    auto original = binary("and", reg(0), constant(0));
    LiftedFunction input{FunctionId{1}, at, {{BlockId{1}, at,
        {{{at, 1}, Assign{dst, original}}}, {}, {}}}, {}};
    auto simplified = simplify_identities(input);
    require(simplified.has_value(), "identity pass accepts a valid function");
    const auto &out = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    const auto *zero = std::get_if<ConstantValue>(&out->value);
    require(zero && zero->value == 0 && zero->type.bits == 8,
            "x & zero folds to a zero value at the expression width");
    require(std::holds_alternative<BinaryValue>(original->value), "input IR remains unchanged");

    auto all_ones = constant(0xff);
    auto x_and_ones = binary("and", reg(0), all_ones);
    input.blocks[0].instructions[0].statement = Assign{dst, x_and_ones};
    simplified = simplify_identities(input);
    const auto &copy = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::get_if<RegisterValue>(&copy->value) != nullptr,
            "x & width-mask simplifies to x");

    auto mismatched = binary("and", reg(0, 8), constant(0, 16), 8);
    input.blocks[0].instructions[0].statement = Assign{dst, mismatched};
    simplified = simplify_identities(input);
    const auto &preserved = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(preserved->value),
            "ill-typed operands remain explicit instead of being rewritten");

    auto duplicate = binary("xor", reg(0), reg(0));
    input.blocks[0].instructions[0].statement = Assign{dst, duplicate};
    simplified = simplify_identities(input);
    const auto &same = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    const auto *zero_again = std::get_if<ConstantValue>(&same->value);
    require(zero_again && zero_again->value == 0, "x xor x simplifies to a width-correct zero");

    auto memory = std::make_shared<Expression>(Expression{{TypeKind::integer, 8, false},
        MemoryValue{{TypeKind::integer, 8, false}}});
    input.blocks[0].instructions[0].statement = Assign{dst, binary("and", memory, constant(0))};
    simplified = simplify_identities(input);
    const auto &memory_result = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(memory_result->value),
            "annihilator identities retain memory reads that may fault or be volatile");

    input.blocks[0].instructions[0].statement = Assign{dst, binary("and", reg(3), reg(3))};
    simplified = simplify_identities(input);
    const auto &and_idempotent = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<RegisterValue>(and_idempotent->value),
            "x & x simplifies to x when both operands have matching pure bit-vector types");

    // A left/right logical shift pair preserves only the low bits that survive
    // the left shift. Keep the test narrow enough to exercise width masking.
    input.blocks[0].instructions[0].statement = Assign{dst,
        binary("shr", binary("shl", reg(5), constant(2)), constant(2))};
    simplified = simplify_identities(input);
    const auto &shift_mask = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    const auto *masked = std::get_if<BinaryValue>(&shift_mask->value);
    const auto *mask_constant = masked ? std::get_if<ConstantValue>(&masked->right->value) : nullptr;
    require(masked && masked->operation == "and" && std::holds_alternative<RegisterValue>(masked->left->value) &&
                mask_constant && mask_constant->value == 0x3f,
            "logical shift pair becomes the equivalent width-correct bit mask");

    const Address shift_at{{0}, 0x2000};
    const RegisterOperand shift_reg{RegisterBank::gpr, 6, 8, false};
    auto shift_definition = binary("shl", reg(6), constant(2));
    auto shifted_value = std::make_shared<Expression>(Expression{{TypeKind::integer, 8, false},
        RegisterValue{shift_reg, std::uint32_t{2}}});
    LiftedBlock sequence_block;
    sequence_block.id = BlockId{2};
    sequence_block.begin = shift_at;
    sequence_block.instructions.push_back(
        {InstructionOrigin{shift_at, 1}, Assign{shift_reg, shift_definition, 2}});
    sequence_block.instructions.push_back(
        {InstructionOrigin{Address{{0}, 0x2001}, 2},
         Assign{shift_reg, binary("shr", shifted_value, constant(2)), 3}});
    LiftedFunction sequence{FunctionId{2}, shift_at, {sequence_block}, {}};
    simplified = simplify_identities(sequence);
    const auto &sequence_value = std::get<Assign>(simplified.value().blocks[0].instructions[1].statement).value;
    const auto *sequence_mask = std::get_if<BinaryValue>(&sequence_value->value);
    const auto *sequence_constant = sequence_mask ? std::get_if<ConstantValue>(&sequence_mask->right->value) : nullptr;
    require(sequence_mask && sequence_mask->operation == "and" &&
                std::get<RegisterValue>(sequence_mask->left->value).version == std::uint32_t{1} &&
                sequence_constant && sequence_constant->value == 0x3f,
            "same-block SSA assignments expose multi-instruction shift-pair masks");

    sequence_block.instructions.clear();
    sequence_block.instructions.push_back(
        {InstructionOrigin{shift_at, 1}, Assign{shift_reg, shift_definition, 2}});
    sequence_block.instructions.push_back(
        {InstructionOrigin{Address{{0}, 0x2001}, 2}, Call{Address{{0}, 0x4000}, {}}});
    sequence_block.instructions.push_back(
        {InstructionOrigin{Address{{0}, 0x2002}, 3},
         Assign{shift_reg, binary("shr", shifted_value, constant(2)), 3}});
    sequence.blocks[0] = sequence_block;
    simplified = simplify_identities(sequence);
    const auto &after_call = std::get<Assign>(simplified.value().blocks[0].instructions[2].statement).value;
    require(std::holds_alternative<BinaryValue>(after_call->value) &&
                std::get<BinaryValue>(after_call->value).operation == "shr",
            "opaque calls stop same-block SSA expression substitution");

    LiftedBlock predecessor;
    predecessor.id = BlockId{10};
    predecessor.begin = shift_at;
    predecessor.instructions.push_back(
        {InstructionOrigin{shift_at, 10}, Assign{shift_reg, shift_definition, 2}});
    predecessor.successors.push_back(
        {shift_at, Address{{0}, 0x2010}, BlockId{11}, BlockEdgeKind::fallthrough});
    LiftedBlock successor;
    successor.id = BlockId{11};
    successor.begin = Address{{0}, 0x2010};
    successor.instructions.push_back(
        {InstructionOrigin{successor.begin, 11},
         Assign{shift_reg, binary("shr", shifted_value, constant(2)), 3}});
    sequence.blocks = {successor, predecessor}; // Deliberately not in CFG order.
    simplified = simplify_identities(sequence);
    const auto &cross_block = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    const auto *cross_block_mask = std::get_if<BinaryValue>(&cross_block->value);
    const auto *cross_block_constant = cross_block_mask
        ? std::get_if<ConstantValue>(&cross_block_mask->right->value) : nullptr;
    require(cross_block_mask && cross_block_mask->operation == "and" &&
                cross_block_constant && cross_block_constant->value == 0x3f,
            "pure SSA expressions propagate over acyclic single-predecessor edges independent of block order");

    predecessor.successors[0].kind = BlockEdgeKind::delay_slot;
    sequence.blocks = {successor, predecessor};
    simplified = simplify_identities(sequence);
    const auto &after_delay_slot = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(after_delay_slot->value) &&
                std::get<BinaryValue>(after_delay_slot->value).operation == "shr",
            "delay-slot edges do not propagate pure expression facts");

    LiftedBlock loop_header = successor;
    loop_header.successors.push_back(
        {loop_header.begin, loop_header.begin, loop_header.id, BlockEdgeKind::jump});
    predecessor.successors = {
        {predecessor.begin, loop_header.begin, loop_header.id, BlockEdgeKind::fallthrough}};
    sequence.blocks = {loop_header, predecessor};
    simplified = simplify_identities(sequence);
    const auto &inside_loop = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(inside_loop->value) &&
                std::get<BinaryValue>(inside_loop->value).operation == "shr",
            "cyclic blocks do not inherit path-local expression facts");

    LiftedBlock split_branch = predecessor;
    split_branch.id = BlockId{20};
    split_branch.successors.clear();
    LiftedBlock left_path;
    left_path.id = BlockId{21};
    left_path.begin = Address{{0}, 0x2021};
    LiftedBlock right_path;
    right_path.id = BlockId{22};
    right_path.begin = Address{{0}, 0x2022};
    LiftedBlock join;
    join.id = BlockId{23};
    join.begin = Address{{0}, 0x2023};
    split_branch.successors = {
        {shift_at, left_path.begin, left_path.id, BlockEdgeKind::conditional_true},
        {shift_at, right_path.begin, right_path.id, BlockEdgeKind::conditional_false}};
    left_path.successors.push_back(
        {left_path.begin, join.begin, join.id, BlockEdgeKind::jump});
    right_path.successors.push_back(
        {right_path.begin, join.begin, join.id, BlockEdgeKind::jump});
    join.instructions.push_back(
        {InstructionOrigin{join.begin, 23}, Assign{shift_reg, binary("shr", shifted_value, constant(2)), 3}});
    sequence.blocks = {join, right_path, split_branch, left_path};
    simplified = simplify_identities(sequence);
    const auto &at_join = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(at_join->value) &&
                std::get<BinaryValue>(at_join->value).operation == "shr",
            "joins do not inherit a path-local expression fact");

    input.blocks[0].instructions[0].statement = Assign{dst,
        binary("shr", binary("shl", reg(5), constant(2)), constant(3))};
    simplified = simplify_identities(input);
    const auto &unequal_shift_pair = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(unequal_shift_pair->value),
            "different shift counts do not trigger shift-pair recovery");

    input.blocks[0].instructions[0].statement = Assign{dst,
        binary("shr", binary("shl", reg(5), constant(8)), constant(8))};
    simplified = simplify_identities(input);
    const auto &oversized_shift_pair = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(oversized_shift_pair->value),
            "out-of-range shift counts remain explicit");

    input.blocks[0].instructions[0].statement = Assign{dst,
        binary("shr", binary("shl", memory, constant(2)), constant(2))};
    simplified = simplify_identities(input);
    const auto &effectful_shift_pair = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(effectful_shift_pair->value),
            "shift-pair rewrite retains potentially faulting or volatile memory reads");

    input.blocks[0].instructions[0].statement = Assign{dst, binary("or", reg(3), reg(3))};
    simplified = simplify_identities(input);
    const auto &or_idempotent = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<RegisterValue>(or_idempotent->value),
            "x | x simplifies to x when both operands have matching pure bit-vector types");

    input.blocks[0].instructions[0].statement = Assign{dst,
        binary("sub", binary("add", reg(4), constant(0x123)), constant(0x123))};
    simplified = simplify_identities(input);
    const auto &cancelled = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<RegisterValue>(cancelled->value),
            "(x + c) - c cancels under fixed-width wraparound when types and constants match");

    input.blocks[0].instructions[0].statement = Assign{dst,
        binary("sub", binary("add", reg(4), constant(0x12, 16)), constant(0x12, 16))};
    simplified = simplify_identities(input);
    const auto &mismatched_cancel = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(mismatched_cancel->value),
            "cancellation is not applied when the inner operands have a different width");

    input.blocks[0].instructions[0].statement = Assign{dst,
        binary("sub", binary("add", memory, constant(1)), constant(1))};
    simplified = simplify_identities(input);
    const auto &memory_cancel = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(memory_cancel->value),
            "cancellation retains memory reads that may fault or be volatile");

    auto unknown = std::make_shared<Expression>(Expression{{TypeKind::integer, 8, false},
        UnknownValue{"unmodeled effect"}});
    input.blocks[0].instructions[0].statement = Assign{dst,
        binary("sub", binary("add", unknown, constant(1)), constant(1))};
    simplified = simplify_identities(input);
    const auto &unknown_cancel = std::get<Assign>(simplified.value().blocks[0].instructions[0].statement).value;
    require(std::holds_alternative<BinaryValue>(unknown_cancel->value),
            "cancellation retains unknown computations that may have effects");
    return 0;
}
