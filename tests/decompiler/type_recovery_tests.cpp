#include "hexlab/decompiler/type_recovery.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#if defined(__APPLE__)
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#endif
#if defined(_MSC_VER)
#include <crtdbg.h>
#endif

using namespace hexlab;
using namespace hexlab::decompiler;

#if defined(__APPLE__)
namespace {
volatile sig_atomic_t current_test_stage = '0';

void print_segv_backtrace(int signal_number) {
    void *frames[64];
    const int frame_count = ::backtrace(frames, static_cast<int>(sizeof(frames) / sizeof(frames[0])));
    constexpr char message[] = "decompiler_type_recovery: SIGSEGV at test stage ";
    (void)::write(STDERR_FILENO, message, sizeof(message) - 1);
    const char stage = static_cast<char>(current_test_stage);
    (void)::write(STDERR_FILENO, &stage, 1);
    constexpr char newline[] = "\n";
    (void)::write(STDERR_FILENO, newline, sizeof(newline) - 1);
    constexpr char backtrace_message[] = "decompiler_type_recovery: backtrace follows\n";
    (void)::write(STDERR_FILENO, backtrace_message, sizeof(backtrace_message) - 1);
    if (frame_count > 0) ::backtrace_symbols_fd(frames, frame_count, STDERR_FILENO);
    ::_exit(128 + signal_number);
}
void mark_test_stage(char stage) { current_test_stage = stage; }
}
#endif

int main() {
#if defined(__APPLE__)
    struct sigaction action{};
    action.sa_handler = print_segv_backtrace;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    (void)sigaction(SIGSEGV, &action, nullptr);
    mark_test_stage('1');
#endif
#if defined(_MSC_VER)
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
#endif
    const RegisterOperand arg{RegisterBank::gpr, 1, 64, false};
    const RegisterOperand copied{RegisterBank::gpr, 2, 64, false};
    const RegisterOperand result_reg{RegisterBank::gpr, 0, 64, false};
    const RegisterOperand base{RegisterBank::gpr, 3, 64, false};
    const RegisterOperand copied_base{RegisterBank::gpr, 4, 64, false};
    auto reg = [](RegisterOperand r, std::optional<std::uint32_t> v={}) {
        return std::make_shared<Expression>(Expression{{TypeKind::integer,r.width,false},RegisterValue{r,v}});
    };
    auto fn=std::make_shared<LiftedFunction>();
    fn->entry={{0},0x1000};
    LiftedBlock block; block.id={1}; block.begin=fn->entry;
    block.instructions.push_back({{{0},0x0ffe},Assign{copied_base,reg(base,0),1}});
    block.instructions.push_back({{fn->entry,1},Assign{copied,reg(arg,0),1}});
    MemoryValue mem; mem.base=base; mem.type={TypeKind::integer,32,false}; mem.base_version=0;
    auto load=std::make_shared<Expression>(Expression{mem.type,mem});
    block.instructions.push_back({{{0},0x1004},Assign{result_reg,load,1}});
    RegisterOperand extra_field{RegisterBank::gpr, 5, 32, false};
    mem.displacement = 8;
    auto second_load = std::make_shared<Expression>(Expression{mem.type, mem});
    block.instructions.push_back({{{0},0x1006},Assign{extra_field,second_load,1}});
    block.instructions.push_back({{{0},0x1008},Return{reg(result_reg,1)}});
    fn->blocks.push_back(block);

    AbiDescription abi; abi.name="test-x64"; abi.pointer_bits=64;
    abi.integer_argument_registers={arg,base}; abi.integer_return_register=result_reg;
    auto recovered=recover_types(*fn,abi);
    assert(recovered);
    bool saw_arg=false,saw_copy=false,saw_base=false,saw_result=false;
    for(const auto &v:recovered.value().variables) {
        if(v.reg==arg && v.version==0) { saw_arg=true; assert(v.name == "arg0" && v.parameter_index == 0); }
        if(v.reg==copied && v.version==1) saw_copy=true;
        if(v.reg==base && v.version==0) { saw_base=true; assert(v.type && v.type->kind()==types::Kind::pointer); }
        if(v.reg==result_reg && v.version==1) { saw_result=true; assert(v.type && v.type->size()==8); }
    }
    assert(saw_arg&&saw_copy&&saw_base&&saw_result);
    assert(std::any_of(recovered.value().variables.begin(), recovered.value().variables.end(),
        [&](const auto &value) { return value.reg == copied && value.version == 1 && !value.name.empty(); }));
    assert(recovered.value().return_type && recovered.value().return_type->size()==8);
    assert(recovered.value().inferred_prototype);
    assert(recovered.value().inferred_prototype->kind()==types::Kind::function);
    assert(recovered.value().inferred_prototype->parameters().size()==2);
    assert(recovered.value().inferred_prototype->parameters()[0].type->size()==8);
    assert(recovered.value().inferred_prototype->parameters()[1].type->kind()==types::Kind::pointer);
    assert(recovered.value().inferred_prototype->result_type()->size()==8);
    const auto recovered_base = std::find_if(recovered.value().variables.begin(), recovered.value().variables.end(),
        [&](const auto &variable) { return variable.reg == base && variable.version == 0; });
    assert(recovered_base != recovered.value().variables.end());
    assert(recovered_base->type->element()->kind() == types::Kind::structure);
    assert(recovered_base->type->element()->members().size() == 2);
    assert(recovered_base->type->element()->members().front().offset == 0);
    assert(recovered_base->type->element()->members().front().type->size() == 4);
    assert(recovered_base->type->element()->members().back().offset == 8);
    assert(recovered_base->type->element()->size() == 12);

    // Three observed adjacent words are a sufficiently strong shape signal
    // to recover an array member; a later gap must start a separate field.
#if defined(__APPLE__)
    mark_test_stage('2');
#endif
    LiftedFunction array_fn;
    array_fn.entry = {{0}, 0x1100};
    LiftedBlock array_block{BlockId{11}, array_fn.entry};
    for (std::uint64_t offset : {0, 4, 8, 16}) {
        MemoryValue element;
        element.base = base;
        element.base_version = 0;
        element.displacement = static_cast<std::int64_t>(offset);
        element.type = {TypeKind::integer, 32, false};
        auto value = std::make_shared<Expression>(Expression{element.type, element});
        array_block.instructions.push_back({{{0}, 0x1100 + offset}, Assign{extra_field, value, static_cast<std::uint32_t>(offset + 1)}});
    }
    array_fn.blocks.push_back(std::move(array_block));
    auto array_types = recover_types(array_fn, abi);
    assert(array_types);
    const auto array_base = std::find_if(array_types.value().variables.begin(), array_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == base && variable.version == 0; });
    assert(array_base != array_types.value().variables.end());
    const auto &array_members = array_base->type->element()->members();
    assert(array_members.size() == 2);
    assert(array_members.front().offset == 0 && array_members.front().type->kind() == types::Kind::array);
    assert(array_members.front().type->count() == 3 && array_members.front().type->element()->size() == 4);
    assert(array_members.back().offset == 16 && array_members.back().type->kind() == types::Kind::integer);

    auto two_field_fn = array_fn;
    two_field_fn.blocks.front().instructions.resize(2);
    auto two_field_types = recover_types(two_field_fn, abi);
    assert(two_field_types);
    const auto two_field_base = std::find_if(two_field_types.value().variables.begin(), two_field_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == base && variable.version == 0; });
    assert(two_field_base != two_field_types.value().variables.end());
    const auto &two_fields = two_field_base->type->element()->members();
    assert(two_fields.size() == 2 && two_fields[0].type->kind() == types::Kind::integer &&
           two_fields[1].type->kind() == types::Kind::integer);

    auto sparse_fn = array_fn;
    for (std::size_t index = 0; index < sparse_fn.blocks.front().instructions.size(); ++index) {
        const auto displacement = index * 4;
        auto &assignment = std::get<Assign>(sparse_fn.blocks.front().instructions[index].statement);
        auto memory = std::get<MemoryValue>(assignment.value->value);
        memory.displacement = static_cast<std::int64_t>(displacement * 2);
        assignment.value = std::make_shared<Expression>(Expression{memory.type, memory});
    }
    auto sparse_types = recover_types(sparse_fn, abi);
    assert(sparse_types);
    const auto sparse_base = std::find_if(sparse_types.value().variables.begin(), sparse_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == base && variable.version == 0; });
    assert(sparse_base != sparse_types.value().variables.end());
    const auto &sparse_fields = sparse_base->type->element()->members();
    assert(sparse_fields.size() == 4 && std::all_of(sparse_fields.begin(), sparse_fields.end(),
        [](const auto &member) { return member.type->kind() == types::Kind::integer; }));

    // A scaled indexed load is definitive evidence for the pointer's element
    // width, and should be rendered as ordinary source array indexing.
    const RegisterOperand array_index{RegisterBank::gpr, 10, 64, false};
    const RegisterOperand indexed_result{RegisterBank::gpr, 11, 32, false};
    LiftedFunction indexed_fn;
    indexed_fn.entry = {{0}, 0x1200};
    LiftedBlock indexed_block{BlockId{12}, indexed_fn.entry};
    MemoryValue indexed_memory;
    indexed_memory.base = base;
    indexed_memory.base_version = 0;
    indexed_memory.index = array_index;
    indexed_memory.index_version = 0;
    indexed_memory.scale = 4;
    indexed_memory.type = {TypeKind::integer, 32, false};
    auto indexed_load = std::make_shared<Expression>(Expression{indexed_memory.type, indexed_memory});
    indexed_block.instructions.push_back({{indexed_fn.entry, 1}, Assign{indexed_result, indexed_load, 1}});
    indexed_fn.blocks.push_back(std::move(indexed_block));
    const auto indexed_types = recover_types(indexed_fn, abi);
    assert(indexed_types);
    const auto indexed_base = std::find_if(indexed_types.value().variables.begin(), indexed_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == base && variable.version == 0; });
    assert(indexed_base != indexed_types.value().variables.end());
    assert(indexed_base->type && indexed_base->type->kind() == types::Kind::pointer);
    assert(indexed_base->type->element() && indexed_base->type->element()->kind() == types::Kind::integer);
    assert(indexed_base->type->element()->size() == 4);
    const auto indexed_pseudocode = format_pseudocode(indexed_fn);
    assert(indexed_pseudocode.find("r3_0[r10_0]") != std::string::npos);

    const RegisterOperand frame{RegisterBank::gpr, 5, 64, false};
    MemoryValue local_memory;
#if defined(__APPLE__)
    mark_test_stage('3');
#endif
    local_memory.base = frame;
    local_memory.base_version = 0;
    local_memory.displacement = -8;
    local_memory.type = {TypeKind::integer, 32, false};
    auto local_expression = std::make_shared<Expression>(Expression{local_memory.type, local_memory});
    LiftedFunction local_function;
    local_function.entry = {{0}, 0x1800};
    LiftedBlock local_block{BlockId{8}, local_function.entry};
    local_block.instructions.push_back({{local_function.entry, 1}, Store{local_expression,
        std::make_shared<Expression>(Expression{{TypeKind::integer, 32, false},
            ConstantValue{7, {TypeKind::integer, 32, false}}})}});
    local_block.instructions.push_back({{{{0}, 0x1804}, 2}, Assign{result_reg, local_expression, 1}});
    local_block.instructions.push_back({{{{0}, 0x1808}, 3}, Return{reg(result_reg, 1)}});
    local_function.blocks.push_back(std::move(local_block));
    auto local_types = recover_types(local_function, abi);
    assert(local_types && local_types.value().stack_variables.size() == 1);
    assert(local_types.value().stack_variables.front().name == "local_8");
    assert(local_types.value().stack_variables.front().offset == -8);
    assert(local_types.value().stack_variables.front().type->size() == 4);
    assert(types::format(*local_types.value().stack_variables.front().type) == "u32");
    auto typed_pseudocode = format_pseudocode_with_types(local_function, abi);
    assert(typed_pseudocode);
    assert(typed_pseudocode.value().find("u32 local_8;") != std::string::npos);
    assert(typed_pseudocode.value().find("local_8 =") != std::string::npos);

    // Conflicting widths make one byte range ambiguous, but should not erase
    // independent, non-overlapping locals in the same frame.
    LiftedFunction partial_local_fn;
    partial_local_fn.entry = {{0}, 0x1810};
    LiftedBlock partial_local_block{BlockId{18}, partial_local_fn.entry};
    const auto add_local_access = [&](std::int64_t displacement, std::uint16_t bits,
                                     std::uint64_t address) {
        MemoryValue local;
        local.base = frame;
        local.base_version = 0;
        local.displacement = displacement;
        local.type = {TypeKind::integer, bits, false};
        auto access = std::make_shared<Expression>(Expression{local.type, local});
        partial_local_block.instructions.push_back({{{0}, address}, Assign{result_reg, access,
            static_cast<std::uint32_t>(address)}});
    };
    add_local_access(-8, 32, 0x1810);
    add_local_access(-8, 64, 0x1814);
    add_local_access(-24, 16, 0x1818);
    partial_local_fn.blocks.push_back(std::move(partial_local_block));
    auto partial_named = recover_stack_variables(partial_local_fn);
    assert(partial_named);
    std::vector<std::string> recovered_local_names;
    for (const auto &instruction : partial_named.value().blocks.front().instructions) {
        const auto *assignment = std::get_if<Assign>(&instruction.statement);
        const auto *memory = assignment && assignment->value
            ? std::get_if<MemoryValue>(&assignment->value->value) : nullptr;
        if (memory && memory->stack_variable) recovered_local_names.push_back(*memory->stack_variable);
    }
    assert(recovered_local_names.size() == 1 && recovered_local_names.front() == "local_24");
    auto partial_local_types = recover_types(partial_local_fn, abi);
    assert(partial_local_types && partial_local_types.value().stack_variables.size() == 1);
    assert(partial_local_types.value().stack_variables.front().name == "local_24");
    assert(partial_local_types.value().stack_variables.front().type->size() == 2);
    const auto recovered_copy = std::find_if(recovered.value().variables.begin(), recovered.value().variables.end(),
        [&](const auto &variable) { return variable.reg == copied_base && variable.version == 1; });
    assert(recovered_copy != recovered.value().variables.end());
    assert(recovered_copy->type->kind() == types::Kind::pointer);
    assert(recovered_copy->type->element()->kind() == types::Kind::structure);

    // Accesses through an interior pointer should contribute to the enclosing
    // object's field layout while retaining offsets relative to the interior
    // pointer's own view.
#if defined(__APPLE__)
    mark_test_stage('4');
#endif
    const RegisterOperand interior{RegisterBank::gpr, 6, 64, false};
    const RegisterOperand interior_load{RegisterBank::gpr, 7, 32, false};
    LiftedFunction interior_fn;
    interior_fn.entry = {{0}, 0x2000};
    LiftedBlock interior_block;
    interior_block.id = {2};
    interior_block.begin = interior_fn.entry;
    auto offset = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
        ConstantValue{8, {TypeKind::integer, 64, false}}});
    auto interior_address = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
        BinaryValue{"add", reg(base, 0), offset}});
    interior_block.instructions.push_back({{interior_fn.entry, 1}, Assign{interior, interior_address, 1}});
    MemoryValue interior_mem;
    interior_mem.base = interior;
    interior_mem.base_version = 1;
    interior_mem.displacement = 4;
    interior_mem.type = {TypeKind::integer, 32, false};
    auto interior_load_expr = std::make_shared<Expression>(Expression{interior_mem.type, interior_mem});
    interior_block.instructions.push_back({{{0}, 0x2004}, Assign{interior_load, interior_load_expr, 1}});
    interior_fn.blocks.push_back(interior_block);
    auto interior_types = recover_types(interior_fn, abi);
    assert(interior_types);
    const auto enclosing = std::find_if(interior_types.value().variables.begin(), interior_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == base && variable.version == 0; });
    const auto interior_pointer = std::find_if(interior_types.value().variables.begin(), interior_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == interior && variable.version == 1; });
    assert(enclosing != interior_types.value().variables.end());
    assert(interior_pointer != interior_types.value().variables.end());
    assert(enclosing->type && enclosing->type->kind() == types::Kind::pointer);
    assert(enclosing->type->element()->kind() == types::Kind::structure);
    assert(enclosing->type->element()->members().size() == 1);
    assert(enclosing->type->element()->members().front().offset == 12);
    assert(interior_pointer->type && interior_pointer->type->element()->kind() == types::Kind::structure);
    assert(interior_pointer->type->element()->members().front().offset == 4);

    // A malformed non-SSA alias cycle with a non-zero displacement must not
    // grow a field layout forever or publish a partial structure.
    LiftedFunction cyclic_alias_fn;
    cyclic_alias_fn.entry = {{0}, 0x3000};
    LiftedBlock cyclic_alias_block;
    cyclic_alias_block.id = {3};
    cyclic_alias_block.begin = cyclic_alias_fn.entry;
    auto plus_eight = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
        ConstantValue{8, {TypeKind::integer, 64, false}}});
    cyclic_alias_block.instructions.push_back({{cyclic_alias_fn.entry, 1}, Assign{interior,
        std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false}, BinaryValue{"add", reg(base), plus_eight}}), {}}});
    cyclic_alias_block.instructions.push_back({{{0}, 0x3004}, Assign{base,
        std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false}, BinaryValue{"add", reg(interior), plus_eight}}), {}}});
    MemoryValue cyclic_mem;
    cyclic_mem.base = interior;
    cyclic_mem.type = {TypeKind::integer, 32, false};
    cyclic_alias_block.instructions.push_back({{{0}, 0x3008}, Assign{interior_load,
        std::make_shared<Expression>(Expression{cyclic_mem.type, cyclic_mem}), {}}});
    cyclic_alias_fn.blocks.push_back(cyclic_alias_block);
    auto cyclic_types = recover_types(cyclic_alias_fn, abi);
    if (!cyclic_types || cyclic_types.value().diagnostics.empty()) {
        std::cerr << "nonconvergent pointer-alias cycle was not conservatively rejected\n";
        return 2;
    }
    const auto cyclic_pointer = std::find_if(cyclic_types.value().variables.begin(), cyclic_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == base && !variable.version; });
    if (cyclic_pointer == cyclic_types.value().variables.end() || !cyclic_pointer->type ||
        cyclic_pointer->type->kind() != types::Kind::pointer ||
        cyclic_pointer->type->element()->kind() != types::Kind::integer) {
        std::cerr << "nonconvergent pointer-alias cycle published an aggregate or lost pointer classification\n";
        return 3;
    }

    auto overlap_fn = std::make_shared<LiftedFunction>(*fn);
    MemoryValue overlapping = mem;
    overlapping.displacement = 2;
    auto overlap_load = std::make_shared<Expression>(Expression{overlapping.type, overlapping});
    overlap_fn->blocks.front().instructions.insert(overlap_fn->blocks.front().instructions.begin(),
        {{{0},0x0ffc},Assign{extra_field,overlap_load,2}});
    auto overlap_recovered = recover_types(*overlap_fn, abi);
    assert(overlap_recovered);
    const auto overlap_base = std::find_if(overlap_recovered.value().variables.begin(), overlap_recovered.value().variables.end(),
        [&](const auto &variable) { return variable.reg == base && variable.version == 0; });
    assert(overlap_base != overlap_recovered.value().variables.end());
    assert(overlap_base->type->kind() == types::Kind::pointer);
    assert(overlap_base->type->element()->kind() == types::Kind::integer);

    auto i32=types::Type::integer("int",4,4,true); assert(i32);
#if defined(__APPLE__)
    mark_test_stage('5');
#endif
    auto proto=types::Type::function(i32.value(),{{"x",i32.value()}},false); assert(proto);
    auto constrained=recover_types(*fn,abi,proto.value()); assert(constrained);
    bool constrained_arg=false;
    for(const auto &v:constrained.value().variables) if(v.reg==arg && v.version==0) {
        constrained_arg=true; assert(v.prototype_constrained); assert(v.type->is_signed()); assert(v.type->size()==4);
    }
    assert(constrained_arg && constrained.value().return_type->is_signed());

    LiftedFunction bare_return = *fn;
    bare_return.blocks.front().instructions.back().statement = Return{};
    auto inferred_bare_return = recover_types(bare_return, abi);
    assert(inferred_bare_return && inferred_bare_return.value().return_type);
    assert(inferred_bare_return.value().return_type->kind() == types::Kind::void_type);
    assert(inferred_bare_return.value().inferred_prototype);
    assert(inferred_bare_return.value().inferred_prototype->result_type()->kind() == types::Kind::void_type);

#if defined(__APPLE__)
    mark_test_stage('A'); // Windows ABI construction and slot checks
#endif
    auto win=x86_64_windows_abi();
    assert(win.integer_argument_registers.size()==4 && win.stack_argument_base &&
           !win.stack_argument_offsets.empty() && win.stack_argument_offsets.front()==40);
#if defined(__APPLE__)
    mark_test_stage('B'); // System V ABI construction and slot checks
#endif
    auto sysv=x86_64_system_v_abi();
    assert(sysv.integer_argument_registers.size()==6 && !sysv.stack_argument_offsets.empty() &&
           sysv.stack_argument_offsets.front()==8);
#if defined(__APPLE__)
    mark_test_stage('C'); // AArch64 ABI construction and slot checks
#endif
    auto arm=aarch64_abi();
    assert(arm.integer_argument_registers.size()==8 && arm.stack_argument_base &&
           arm.stack_argument_base->bank==RegisterBank::arm64_sp);

#if defined(__APPLE__)
    mark_test_stage('D'); // Windows ABI stack argument recovery
#endif
    auto stack_fn=std::make_shared<LiftedFunction>(*fn);
    MemoryValue stack_mem; stack_mem.base=win.stack_argument_base; stack_mem.displacement=40;
    stack_mem.type={TypeKind::integer,32,false};
    auto stack_expr=std::make_shared<Expression>(Expression{stack_mem.type,stack_mem});
    stack_fn->blocks.front().instructions.insert(stack_fn->blocks.front().instructions.begin(),
        {{{0},0x0ffc},Assign{copied,stack_expr,2}});
    auto stack_recovered=recover_types(*stack_fn,win); assert(stack_recovered);
    // The explicit Windows ABI order has four register slots before stack
    // arguments. This fixture observes only the first register slot, so the
    // stack read must not be promoted past the missing register slots.
#if defined(__APPLE__)
    mark_test_stage('E'); // Windows inferred prototype validation
#endif
    assert(stack_recovered.value().inferred_prototype);
    assert(stack_recovered.value().inferred_prototype->parameters().size()==1);
    assert(stack_recovered.value().diagnostics.empty());

    // Normalize a stack argument access through a stack pointer adjusted by
    // the prologue: current_sp = entry_sp - 40, load [current_sp + 80] is the
    // ABI slot at entry_sp + 40.
#if defined(__APPLE__)
    mark_test_stage('F'); // Prologue-adjusted stack argument recovery
#endif
    const RegisterOperand adjusted_sp{RegisterBank::gpr, 4, 64, false};
    auto forty = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
        ConstantValue{40, {TypeKind::integer, 64, false}}});
    auto subtract_forty = std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
        BinaryValue{"sub", reg(adjusted_sp, 0), forty}});
    LiftedFunction adjusted_stack_fn;
    adjusted_stack_fn.entry = {{0}, 0x6000};
    LiftedBlock adjusted_stack_block;
    adjusted_stack_block.id = {9};
    adjusted_stack_block.begin = adjusted_stack_fn.entry;
    adjusted_stack_block.instructions.push_back({{adjusted_stack_fn.entry, 1},
        Assign{adjusted_sp, subtract_forty, 3}});
    adjusted_stack_block.instructions.push_back({{{0}, 0x6002},
        Assign{adjusted_sp, reg(adjusted_sp, 3), 4}});
    MemoryValue adjusted_stack_mem;
    adjusted_stack_mem.base = adjusted_sp;
    adjusted_stack_mem.base_version = 4;
    adjusted_stack_mem.displacement = 80;
    adjusted_stack_mem.type = {TypeKind::integer, 32, false};
    auto adjusted_stack_load = std::make_shared<Expression>(Expression{adjusted_stack_mem.type, adjusted_stack_mem});
    const RegisterOperand stack_loaded{RegisterBank::gpr, 11, 32, false};
    adjusted_stack_block.instructions.push_back({{{0}, 0x6004}, Assign{stack_loaded, adjusted_stack_load, 4}});
    adjusted_stack_block.instructions.push_back({{{0}, 0x6008}, Return{}});
    adjusted_stack_fn.blocks.push_back(adjusted_stack_block);
    AbiDescription stack_only_abi;
    stack_only_abi.name = "stack-only test ABI";
    stack_only_abi.pointer_bits = 64;
    stack_only_abi.stack_argument_base = adjusted_sp;
    stack_only_abi.stack_argument_offsets = {40};
    stack_only_abi.arguments = {{AbiValueClass::integer, {}, 40}};
    auto adjusted_stack_recovery = recover_types(adjusted_stack_fn, stack_only_abi);
    assert(adjusted_stack_recovery);
    assert(adjusted_stack_recovery.value().inferred_prototype);
    assert(adjusted_stack_recovery.value().inferred_prototype->parameters().size() == 1);
    assert(adjusted_stack_recovery.value().inferred_prototype->parameters().front().type->size() == 4);

    auto f64=types::Type::floating("double",8,8); assert(f64);
#if defined(__APPLE__)
    mark_test_stage('G'); // Floating and mixed ABI recovery
#endif
    auto floating_proto=types::Type::function(f64.value(),{{"x",f64.value()}},false); assert(floating_proto);
    AbiDescription floating_abi; floating_abi.name="test floating"; floating_abi.pointer_bits=64;
    floating_abi.floating_argument_registers={arg}; floating_abi.floating_return_register=result_reg;
    auto floating_constrained=recover_types(*fn,floating_abi,floating_proto.value()); assert(floating_constrained);
    assert(floating_constrained.value().return_type);
    assert(floating_constrained.value().return_type->kind()==types::Kind::floating);
    bool saw_float=false;
    for(const auto &v:floating_constrained.value().variables) if(v.reg==arg && v.version==0) saw_float=v.type->kind()==types::Kind::floating && v.prototype_constrained;
    assert(saw_float);
    floating_abi.vector_argument_registers={arg};
    auto vector_unknown=recover_types(*fn,floating_abi); assert(vector_unknown);
    assert(!vector_unknown.value().diagnostics.empty());

    // An explicit ordered ABI slot map preserves mixed integer/floating
    // argument positions in the inferred candidate signature. The observed
    // register width supplies size; the ABI slot supplies the value class.
    const RegisterOperand floating_arg{RegisterBank::gpr, 15, 64, false};
    LiftedFunction mixed_abi_fn;
    mixed_abi_fn.entry = {{0}, 0x4800};
    LiftedBlock mixed_abi_block;
    mixed_abi_block.id = {8};
    mixed_abi_block.begin = mixed_abi_fn.entry;
    mixed_abi_block.instructions.push_back({{mixed_abi_fn.entry, 1}, Return{reg(arg, 0)}});
    // Mention the floating incoming value without constraining it with a
    // prototype. A self-copy is enough to make its incoming version visible.
    mixed_abi_block.instructions.insert(mixed_abi_block.instructions.begin(),
        {{{0}, 0x47fc}, Assign{floating_arg, reg(floating_arg, 0), 1}});
    mixed_abi_fn.blocks.push_back(mixed_abi_block);
    AbiDescription mixed_abi;
    mixed_abi.name = "mixed register classes";
    mixed_abi.pointer_bits = 64;
    mixed_abi.integer_argument_registers = {arg};
    mixed_abi.floating_argument_registers = {floating_arg};
    mixed_abi.arguments = {
        {AbiValueClass::integer, arg, {}},
        {AbiValueClass::floating, floating_arg, {}}
    };
    auto mixed_abi_recovered = recover_types(mixed_abi_fn, mixed_abi);
    assert(mixed_abi_recovered && mixed_abi_recovered.value().inferred_prototype);
    const auto &mixed_parameters = mixed_abi_recovered.value().inferred_prototype->parameters();
    assert(mixed_parameters.size() == 2);
    assert(mixed_parameters[0].type->kind() == types::Kind::integer);
    assert(mixed_parameters[1].type->kind() == types::Kind::floating);
    assert(mixed_parameters[1].type->size() == 8);

    // A later observed ABI slot does not justify skipping an unobserved
    // earlier slot: the resulting parameter list remains a contiguous prefix.
    auto mixed_abi_gap_fn = mixed_abi_fn;
    mixed_abi_gap_fn.blocks.front().instructions.erase(
        mixed_abi_gap_fn.blocks.front().instructions.begin() + 1);
    mixed_abi_gap_fn.blocks.front().instructions.front().statement =
        Return{reg(floating_arg, 0)};
    mixed_abi.integer_argument_registers.clear();
    mixed_abi.arguments = {
        {AbiValueClass::integer, copied, {}},
        {AbiValueClass::floating, floating_arg, {}}
    };
    auto mixed_abi_gap = recover_types(mixed_abi_gap_fn, mixed_abi);
    assert(mixed_abi_gap && mixed_abi_gap.value().inferred_prototype);
    assert(mixed_abi_gap.value().inferred_prototype->parameters().empty());

    // A phi is pointer-valued only when every incoming value carries pointer
    // evidence. One pointer arm must not turn an integer/pointer join into a
    // pointer type.
#if defined(__APPLE__)
    mark_test_stage('8');
#endif
    const RegisterOperand joined{RegisterBank::gpr, 10, 64, false};
    const RegisterOperand observed{RegisterBank::gpr, 12, 32, false};
    LiftedFunction mixed_phi;
    mixed_phi.entry = {{0}, 0x5000};
    LiftedBlock phi_block;
    phi_block.id = {1};
    phi_block.begin = mixed_phi.entry;
    phi_block.phis.push_back({joined, 3, {{BlockId{2}, 1}, {BlockId{3}, 2}}});
    MemoryValue pointed_memory;
    pointed_memory.base = joined;
    pointed_memory.base_version = 1;
    pointed_memory.type = {TypeKind::integer, 32, false};
    auto pointed_load = std::make_shared<Expression>(Expression{pointed_memory.type, pointed_memory});
    phi_block.instructions.push_back({{mixed_phi.entry, 1}, Assign{observed, pointed_load, 1}});
    phi_block.instructions.push_back({{{0}, 0x5004}, Assign{joined,
        std::make_shared<Expression>(Expression{{TypeKind::integer, 64, false},
            ConstantValue{7, {TypeKind::integer, 64, false}}}), 2}});
    mixed_phi.blocks.push_back(phi_block);
    auto mixed_phi_types = recover_types(mixed_phi, abi);
    assert(mixed_phi_types);
    const auto mixed_join = std::find_if(mixed_phi_types.value().variables.begin(), mixed_phi_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == joined && variable.version == std::uint32_t{3}; });
    assert(mixed_join != mixed_phi_types.value().variables.end());
    assert(mixed_join->type && mixed_join->type->kind() == types::Kind::integer);

    auto uniform_phi = mixed_phi;
    uniform_phi.blocks.front().phis.front().inputs.back().version = 4;
    uniform_phi.blocks.front().instructions.insert(uniform_phi.blocks.front().instructions.begin(),
        {{{0}, 0x4ffc}, Assign{joined, reg(joined, 1), 4}});
    auto uniform_phi_types = recover_types(uniform_phi, abi);
    assert(uniform_phi_types);
    const auto uniform_join = std::find_if(uniform_phi_types.value().variables.begin(), uniform_phi_types.value().variables.end(),
        [&](const auto &variable) { return variable.reg == joined && variable.version == std::uint32_t{3}; });
    assert(uniform_join != uniform_phi_types.value().variables.end());
    assert(uniform_join->type && uniform_join->type->kind() == types::Kind::pointer);

    // Typed vector lane metadata in the IR should survive register recovery,
    // the explicit vector ABI slot, return inference, and prototype building.
#if defined(__APPLE__)
    mark_test_stage('9');
#endif
    const RegisterOperand vector_arg{RegisterBank::xmm, 0, 128, false};
    const ValueType vector_value{TypeKind::vector, 128, false, TypeKind::integer, 32, 4};
    auto vector_expression = std::make_shared<Expression>(Expression{
        vector_value, RegisterValue{vector_arg, 0}});
    LiftedFunction vector_function;
    vector_function.entry = {{0}, 0x6000};
    LiftedBlock vector_block{BlockId{60}, vector_function.entry};
    vector_block.instructions.push_back({{vector_function.entry, 1}, Return{vector_expression}});
    vector_function.blocks.push_back(std::move(vector_block));
    AbiDescription vector_abi;
    vector_abi.name = "test-vector";
    vector_abi.pointer_bits = 64;
    vector_abi.vector_argument_registers = {vector_arg};
    vector_abi.vector_return_register = vector_arg;
    vector_abi.arguments = {{AbiValueClass::vector, vector_arg, {}}};
    const auto vector_recovery = recover_types(vector_function, vector_abi);
    assert(vector_recovery && vector_recovery.value().return_type &&
           vector_recovery.value().return_type->kind() == types::Kind::vector);
    const auto recovered_vector = std::find_if(vector_recovery.value().variables.begin(),
        vector_recovery.value().variables.end(), [&](const auto &value) {
            return value.reg == vector_arg && value.version == std::uint32_t{0};
        });
    assert(recovered_vector != vector_recovery.value().variables.end());
    assert(recovered_vector->type && recovered_vector->type->kind() == types::Kind::vector &&
           recovered_vector->type->size() == 16 && recovered_vector->type->count() == 4 &&
           recovered_vector->type->element()->kind() == types::Kind::integer);
    assert(vector_recovery.value().inferred_prototype &&
           vector_recovery.value().inferred_prototype->parameters().size() == 1 &&
           vector_recovery.value().inferred_prototype->parameters().front().type->kind() == types::Kind::vector);

    auto opaque_vector_function = vector_function;
    auto opaque_value = vector_value;
    opaque_value.element_kind = TypeKind::unknown;
    opaque_value.element_bits = 0;
    opaque_value.lanes = 0;
    auto opaque_expression = std::make_shared<Expression>(Expression{
        opaque_value, RegisterValue{vector_arg, 0}});
    opaque_vector_function.blocks.front().instructions.front().statement = Return{opaque_expression};
    const auto opaque_vector_recovery = recover_types(opaque_vector_function, vector_abi);
    assert(opaque_vector_recovery && opaque_vector_recovery.value().inferred_prototype &&
           opaque_vector_recovery.value().inferred_prototype->parameters().empty());
    const auto opaque_recovered = std::find_if(opaque_vector_recovery.value().variables.begin(),
        opaque_vector_recovery.value().variables.end(), [&](const auto &value) {
            return value.reg == vector_arg && value.version == std::uint32_t{0};
        });
    assert(opaque_recovered != opaque_vector_recovery.value().variables.end() && !opaque_recovered->type);
}
