#include "hexlab/symbols/dwarf.hpp"

#include <cassert>
#include <unordered_map>

using namespace hexlab::symbols;

static LocationOperation operation(LocationOperationKind kind, std::uint64_t u = 0, std::int64_t s = 0) {
    LocationOperation result; result.kind = kind; result.unsigned_operand = u; result.signed_operand = s; return result;
}

int main() {
    std::unordered_map<std::uint64_t, std::uint64_t> regs{{3, 0x1000}, {7, 0x2000}};
    LocationEvaluationContext context;
    context.address_size = 8;
    context.frame_base = 0x3000;
    context.call_frame_cfa = 0x4000;
    context.read_register = [&](std::uint64_t n) -> std::optional<std::uint64_t> {
        auto it = regs.find(n); return it == regs.end() ? std::nullopt : std::optional(it->second);
    };
    context.read_memory = [](std::uint64_t address, std::uint8_t width) -> hexlab::Result<std::uint64_t> {
        if (address != 0x4000 || width != 8) return hexlab::Error{hexlab::ErrorCode::out_of_bounds, "unexpected test read"};
        return UINT64_C(0x12345678);
    };

    auto arithmetic = evaluate_location_expression(std::vector{operation(LocationOperationKind::address, 0x100),
        operation(LocationOperationKind::plus_unsigned, 0x20)}, context);
    assert((arithmetic && arithmetic.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 0x120}));
    auto regloc = evaluate_location_expression(std::vector{operation(LocationOperationKind::register_location, 3)}, context);
    assert((regloc && regloc.value() == EvaluatedLocation{EvaluatedLocationKind::register_location, 3}));
    auto breg = evaluate_location_expression(std::vector{operation(LocationOperationKind::base_register_plus_offset, 3, -8)}, context);
    assert((breg && breg.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 0xff8}));
    auto fbreg = evaluate_location_expression(std::vector{operation(LocationOperationKind::frame_base_relative, 0, -16)}, context);
    assert((fbreg && fbreg.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 0x2ff0}));
    ImportedVariable frame_variable;
    frame_variable.location_operations = {operation(LocationOperationKind::frame_base_relative, 0, -16)};
    auto variable_fbreg = evaluate_imported_variable_location(frame_variable, 0x1234, context);
    assert((variable_fbreg && variable_fbreg.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 0x2ff0}));
    auto deref = evaluate_location_expression(std::vector{operation(LocationOperationKind::call_frame_cfa),
        operation(LocationOperationKind::dereference)}, context);
    assert((deref && deref.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 0x12345678}));
    auto value = evaluate_location_expression(std::vector{operation(LocationOperationKind::unsigned_constant, 42),
        operation(LocationOperationKind::stack_value)}, context);
    assert((value && value.value() == EvaluatedLocation{EvaluatedLocationKind::value, 42}));

    LocationEvaluationContext narrow; narrow.address_size = 4;
    auto wrapped = evaluate_location_expression(std::vector{operation(LocationOperationKind::address, 0xfffffff0),
        operation(LocationOperationKind::plus_unsigned, 0x30)}, narrow);
    assert((wrapped && wrapped.value() == EvaluatedLocation{EvaluatedLocationKind::memory, 0x20}));
    auto underflow = evaluate_location_expression(std::vector{operation(LocationOperationKind::plus)}, context);
    assert(!underflow && underflow.error().code == hexlab::ErrorCode::malformed);
    auto missing_register = evaluate_location_expression(std::vector{operation(LocationOperationKind::register_location, 99)}, context);
    assert(missing_register && missing_register.value().kind == EvaluatedLocationKind::register_location);
    auto missing_base = evaluate_location_expression(std::vector{operation(LocationOperationKind::base_register_plus_offset, 99)}, context);
    assert(!missing_base && missing_base.error().code == hexlab::ErrorCode::unsupported);
    auto pieces = evaluate_location_expression(std::vector{operation(LocationOperationKind::literal, 1),
        operation(LocationOperationKind::piece, 4)}, context);
    assert(!pieces && pieces.error().code == hexlab::ErrorCode::unsupported);
}
