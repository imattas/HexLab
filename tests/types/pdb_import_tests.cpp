#include "hexlab/types/pdb_import.hpp"

#include <cassert>

using namespace hexlab::types;

int main() {
    PdbTypeGraph graph;
    graph.nodes.push_back({CodeViewTypeRecord{.index=0x1000, .leaf=0x1504,
        .kind=CodeViewTypeKind::structure, .field_list=0x1001, .size=8, .name="Pair"}, 0x1000,
        {{.leaf=0x150d, .type=0x74, .offset=0, .name="first"},
         {.leaf=0x150d, .type=0x75, .offset=4, .name="second"}}});
    auto imported = import_pdb_type_graph(graph);
    assert(imported);
    const auto pair = imported.value().definitions.at("Pair");
    assert(pair->kind() == Kind::structure && pair->size() == 8);
    assert(pair->members().size() == 2 && pair->members()[0].name == "first");
    assert(pair->members()[0].type->is_signed() && !pair->members()[1].type->is_signed());

    PdbTypeGraph bitfield_graph;
    bitfield_graph.nodes = {
        {CodeViewTypeRecord{.index=0x1000, .leaf=0x1205, .kind=CodeViewTypeKind::bitfield,
            .referenced_type=0x22, .bitfield_width=3, .bitfield_position=0}, 0x1000, {}},
        {CodeViewTypeRecord{.index=0x1001, .leaf=0x1205, .kind=CodeViewTypeKind::bitfield,
            .referenced_type=0x22, .bitfield_width=5, .bitfield_position=3}, 0x1001, {}},
        {CodeViewTypeRecord{.index=0x1002, .leaf=0x1505, .kind=CodeViewTypeKind::structure,
            .size=4, .name="Bits"}, 0x1002,
            {{.leaf=0x150d,.type=0x1000,.offset=0,.name="low"},
             {.leaf=0x150d,.type=0x1001,.offset=0,.name="next"}}},
        {CodeViewTypeRecord{.index=0x1003, .leaf=0x1205, .kind=CodeViewTypeKind::bitfield,
            .referenced_type=0x22, .bitfield_width=5, .bitfield_position=30}, 0x1003, {}},
        {CodeViewTypeRecord{.index=0x1004, .leaf=0x1505, .kind=CodeViewTypeKind::structure,
            .size=4, .name="BadBits"}, 0x1004,
            {{.leaf=0x150d,.type=0x1003,.offset=0,.name="bad"}}}
    };
    auto bitfield_import = import_pdb_type_graph(bitfield_graph);
    assert(bitfield_import && bitfield_import.value().definitions.contains("Bits") &&
           !bitfield_import.value().definitions.contains("BadBits") &&
           bitfield_import.value().skipped_unsupported == 1 && bitfield_import.value().skipped_unnamed == 3);
    const auto imported_bits = bitfield_import.value().definitions.at("Bits");
    assert(imported_bits->members().size() == 2 && imported_bits->members()[0].type->size() == 4 &&
           !imported_bits->members()[0].type->is_signed() &&
           imported_bits->members()[0].bit_width == 3 && imported_bits->members()[0].bit_offset == 0 &&
           imported_bits->members()[1].bit_width == 5 && imported_bits->members()[1].bit_offset == 3);

    PdbTypeGraph array_graph;
    array_graph.nodes.push_back({CodeViewTypeRecord{.index=0x1000, .kind=CodeViewTypeKind::array,
        .referenced_type=0x74, .size=12, .name="Values"}, 0x1000, {}});
    auto array_import = import_pdb_type_graph(array_graph);
    assert(array_import && array_import.value().definitions.at("Values")->kind() == Kind::array);
    assert(array_import.value().definitions.at("Values")->count() == 3);

    PdbTypeGraph recursive;
    recursive.nodes.push_back({CodeViewTypeRecord{.index=0x1000, .kind=CodeViewTypeKind::structure,
        .name="Loop"}, 0x1000, {{.leaf=0x150d, .type=0x1000, .name="next"}}});
    auto recursive_import = import_pdb_type_graph(recursive);
    assert(recursive_import && recursive_import.value().definitions.empty());
    assert(recursive_import.value().skipped_unsupported == 1);

    // Pointer-recursive records are representable without constructing a C++
    // shared_ptr cycle: the pointee is a named graph edge resolved by name.
    PdbTypeGraph recursive_pointer;
    recursive_pointer.nodes.push_back({CodeViewTypeRecord{.index=0x1000, .kind=CodeViewTypeKind::structure,
        .size=8, .name="Node"}, 0x1000, {{.leaf=0x150d, .type=0x1001, .offset=0, .name="next"}}});
    recursive_pointer.nodes.push_back({CodeViewTypeRecord{.index=0x1001, .kind=CodeViewTypeKind::pointer,
        .referenced_type=0x1000, .size=8, .pointer_kind=0x0c}, 0x1001, {}});
    auto recursive_pointer_import = import_pdb_type_graph(recursive_pointer);
    assert(recursive_pointer_import && recursive_pointer_import.value().definitions.contains("Node"));
    const auto recursive_node = recursive_pointer_import.value().definitions.at("Node");
    assert(recursive_node->members().size() == 1 && recursive_node->members()[0].type->kind() == Kind::pointer);
    const auto recursive_target = recursive_node->members()[0].type->element();
    assert(recursive_target->kind() == Kind::named_reference && recursive_target->name() == "Node" && !recursive_target->size());
    auto encoded_recursive = encode(*recursive_node);
    assert(encoded_recursive);
    auto decoded_recursive = decode(encoded_recursive.value());
    assert(decoded_recursive && decoded_recursive.value()->members()[0].type->element()->kind() == Kind::named_reference &&
           decoded_recursive.value()->members()[0].type->element()->name() == "Node");
    assert(format(*recursive_node).find("Node*") != std::string::npos);

    PdbTypeGraph mutual_recursive;
    CodeViewTypeRecord a_forward{.index=0x1000, .kind=CodeViewTypeKind::structure,
        .name="A", .forward_declaration=true};
    CodeViewTypeRecord b_definition{.index=0x1001, .kind=CodeViewTypeKind::structure,
        .size=8, .name="B"};
    CodeViewTypeRecord b_to_a{.index=0x1002, .kind=CodeViewTypeKind::pointer,
        .referenced_type=0x1000, .size=8, .pointer_kind=0x0c};
    CodeViewTypeRecord a_definition{.index=0x1003, .kind=CodeViewTypeKind::structure,
        .size=8, .name="A"};
    CodeViewTypeRecord a_to_b{.index=0x1004, .kind=CodeViewTypeKind::pointer,
        .referenced_type=0x1001, .size=8, .pointer_kind=0x0c};
    mutual_recursive.nodes = {
        {a_forward, 0x1003, {}},
        {b_definition, 0x1001, {{.leaf=0x150d, .type=0x1002, .offset=0, .name="a"}}},
        {b_to_a, 0x1002, {}},
        {a_definition, 0x1003, {{.leaf=0x150d, .type=0x1004, .offset=0, .name="b"}}},
        {a_to_b, 0x1004, {}}
    };
    auto mutual_import = import_pdb_type_graph(mutual_recursive);
    assert(mutual_import && mutual_import.value().definitions.contains("A") &&
           mutual_import.value().definitions.contains("B"));
    const auto mutual_a = mutual_import.value().definitions.at("A");
    assert(mutual_a->members()[0].type->element()->kind() == Kind::named_reference &&
           mutual_a->members()[0].type->element()->name() == "B");

    PdbTypeGraph duplicate_indices;
    duplicate_indices.nodes = {
        {CodeViewTypeRecord{.index=0x1000, .kind=CodeViewTypeKind::array, .referenced_type=0x74, .size=4, .name="A"}, 0x1000, {}},
        {CodeViewTypeRecord{.index=0x1000, .kind=CodeViewTypeKind::array, .referenced_type=0x74, .size=8, .name="B"}, 0x1000, {}}
    };
    auto duplicate_import = import_pdb_type_graph(duplicate_indices);
    assert(!duplicate_import && duplicate_import.error().code == hexlab::ErrorCode::malformed);

    PdbTypeGraph enumeration;
    enumeration.nodes.push_back({CodeViewTypeRecord{.index=0x1000, .kind=CodeViewTypeKind::enumeration,
        .name="State"}, 0x1000, {}});
    auto enum_import = import_pdb_type_graph(enumeration);
    assert(enum_import && enum_import.value().definitions.empty());
    assert(enum_import.value().skipped_unsupported == 1);
    enumeration.nodes[0].record.underlying_type = 0x74;
    enumeration.nodes[0].expanded_fields = {{.leaf=0x1502, .name="Ready", .value=1},
                                             {.leaf=0x1502, .name="Done", .value=0xffff'ffff'ffff'fffeULL}};
    auto enum_values_import = import_pdb_type_graph(enumeration);
    assert(enum_values_import && enum_values_import.value().definitions.contains("State"));
    const auto state = enum_values_import.value().definitions.at("State");
    assert(state->kind() == Kind::enumeration && state->enumerators().size() == 2);
    assert(state->enumerators()[0] == "Ready" && state->enumerator_values()[0].value == 1);
    assert(state->enumerators()[1] == "Done" && state->enumerator_values()[1].value == 0xffff'ffff'ffff'fffeULL);
    auto encoded_enum = encode(*state);
    assert(encoded_enum);
    auto decoded_enum = decode(encoded_enum.value());
    assert(decoded_enum && decoded_enum.value()->enumerator_values() == state->enumerator_values());

    PdbTypeGraph mixed_arrays;
    mixed_arrays.nodes.push_back({CodeViewTypeRecord{.index=0x1000, .kind=CodeViewTypeKind::array,
        .referenced_type=0x74, .size=12, .name="Values"}, 0x1000, {}});
    mixed_arrays.nodes.push_back({CodeViewTypeRecord{.index=0x1001, .kind=CodeViewTypeKind::array,
        .referenced_type=0x74, .size=0, .name="Flexible"}, 0x1001, {}});
    auto mixed_import = import_pdb_type_graph(mixed_arrays);
    assert(mixed_import && mixed_import.value().definitions.contains("Values") &&
           !mixed_import.value().definitions.contains("Flexible") &&
           mixed_import.value().skipped_unsupported == 1);

    PdbTypeGraph ambiguous;
    ambiguous.nodes.push_back({CodeViewTypeRecord{.index=0x1000, .kind=CodeViewTypeKind::array,
        .referenced_type=0x74, .size=4, .name="Shared"}, 0x1000, {}});
    ambiguous.nodes.push_back({CodeViewTypeRecord{.index=0x1001, .kind=CodeViewTypeKind::array,
        .referenced_type=0x74, .size=8, .name="Shared"}, 0x1001, {}});
    auto ambiguous_import = import_pdb_type_graph(ambiguous);
    assert(ambiguous_import && !ambiguous_import.value().definitions.contains("Shared") &&
           ambiguous_import.value().skipped_ambiguous == 1);

    PdbTypeGraph pointers;
    CodeViewTypeRecord int_pointer{.index=0x1000, .kind=CodeViewTypeKind::pointer,
        .referenced_type=0x74, .size=8, .pointer_kind=0x0c, .pointer_mode=0};
    CodeViewTypeRecord pointer_alias{.index=0x1001, .kind=CodeViewTypeKind::typedef_type,
        .referenced_type=0x1000, .name="IntPointer"};
    CodeViewTypeRecord reference{.index=0x1002, .kind=CodeViewTypeKind::pointer,
        .referenced_type=0x74, .size=8, .pointer_kind=0x0c, .pointer_mode=1, .name="Reference"};
    CodeViewTypeRecord qualified_pointer{.index=0x1003, .kind=CodeViewTypeKind::pointer,
        .referenced_type=0x74, .size=8, .pointer_kind=0x0c, .pointer_options=0x400, .name="ConstPointer"};
    pointers.nodes={{int_pointer,0x1000,{}},{pointer_alias,0x1001,{}},{reference,0x1002,{}},
                    {qualified_pointer,0x1003,{}}};
    auto pointer_import=import_pdb_type_graph(pointers);
    assert(pointer_import && pointer_import.value().definitions.contains("IntPointer") &&
           pointer_import.value().definitions.at("IntPointer")->kind()==Kind::pointer &&
           pointer_import.value().definitions.at("IntPointer")->size()==8 &&
           pointer_import.value().definitions.at("IntPointer")->element()->size()==4 &&
           !pointer_import.value().definitions.contains("Reference") &&
           !pointer_import.value().definitions.contains("ConstPointer") &&
           pointer_import.value().skipped_unsupported==2);

    PdbTypeGraph forward_pointer;
    CodeViewTypeRecord target_forward{.index=0x1002, .kind=CodeViewTypeKind::structure,
        .name="Target", .forward_declaration=true};
    CodeViewTypeRecord target_definition{.index=0x1003, .kind=CodeViewTypeKind::structure,
        .size=4, .name="Target"};
    CodeViewTypeRecord target_pointer{.index=0x1000, .kind=CodeViewTypeKind::pointer,
        .referenced_type=0x1002, .size=8, .pointer_kind=0x0c};
    CodeViewTypeRecord target_alias{.index=0x1001, .kind=CodeViewTypeKind::typedef_type,
        .referenced_type=0x1000, .name="TargetPointer"};
    forward_pointer.nodes={{target_pointer,0x1000,{}},{target_alias,0x1001,{}},
        {target_forward,0x1003,{}}, {target_definition,0x1003,{{.leaf=0x150d,.type=0x74,.offset=0,.name="value"}}}};
    forward_pointer.nodes[2].canonical_index=0x1003;
    auto forward_import=import_pdb_type_graph(forward_pointer);
    assert(forward_import && forward_import.value().definitions.contains("TargetPointer") &&
           forward_import.value().definitions.at("TargetPointer")->element()->kind()==Kind::structure &&
           forward_import.value().definitions.at("TargetPointer")->element()->name()=="Target");
}
