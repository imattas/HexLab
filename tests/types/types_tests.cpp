#include "hexlab/types/types.hpp"
#include "hexlab/types/layout.hpp"
#include <iostream>
int main() {
    using namespace hexlab::types;
    auto i32 = Type::integer("i32", 4, 4, true);
    if (!i32 || i32.value()->size() != 4)
        return 1;
    auto array = Type::array(i32.value(), 3);
    if (!array || array.value()->size() != 12)
        return 2;
    auto record = Type::structure("Pair", {{"a", i32.value(), 0}, {"b", i32.value(), 4}}, 8, 4);
    if (!record || format(*record.value()) != "struct Pair { a@0: i32; b@4: i32; }")
        return 3;
    if (Type::structure("Bad", {{"a", i32.value(), 0}, {"b", i32.value(), 2}}, 8, 4))
        return 4;
    auto u8 = Type::integer("u8", 1, 1, false);
    if (!u8)
        return 24;
    auto packed_member = Type::structure("PackedMember", {{"lead", u8.value(), 0}, {"value", i32.value(), 1}}, 5, 1);
    if (!packed_member || Type::structure("MisalignedNatural", {{"value", i32.value(), 1}}, 5, 4))
        return 24;
    auto ptr = Type::pointer(i32.value(), 8, 8);
    if (!ptr || ptr.value()->size() != 8)
        return 5;
    auto fn = Type::function(i32.value(), {{"x", i32.value()}}, false);
    if (!fn || fn.value()->size().has_value())
        return 6;
    if (fn.value()->id() == i32.value()->id())
        return 7;
    auto delimiter_name = Type::integer("i32:4:4", 4, 4, true);
    auto ordinary_name = Type::integer("i32", 4, 4, true);
    if (!delimiter_name || delimiter_name.value()->id() == ordinary_name.value()->id())
        return 8;
    auto duplicate_members = Type::structure("BadNames", {{"same", i32.value(), 0}, {"same", i32.value(), 4}}, 8, 4);
    if (duplicate_members)
        return 9;
    auto flags = Type::integer("u32", 4, 4, false);
    auto bitfields = Type::structure("Flags", {
        {"low", flags.value(), 0, 3, 0}, {"next", flags.value(), 0, 5, 3},
        {"high", flags.value(), 0, 8, 8}}, 4, 4);
    if (!bitfields || bitfields.value()->members()[1].bit_width != 5 ||
        bitfields.value()->members()[1].bit_offset != 3)
        return 29;
    if (Type::structure("BadWidth", {{"bad", flags.value(), 0, 0, 0}}, 4, 4) ||
        Type::structure("BadExtent", {{"bad", flags.value(), 0, 33, 0}}, 4, 4) ||
        Type::structure("BadOverlap", {{"a", flags.value(), 0, 5, 0}, {"b", flags.value(), 0, 4, 4}}, 4, 4) ||
        Type::structure("BadMixedOverlap", {{"bits", flags.value(), 0, 1, 0}, {"whole", flags.value(), 0}}, 4, 4))
        return 30;
    auto boundary_bits = Type::structure("BoundaryBits", {{"all", flags.value(), 0, 24, 8}}, 4, 4);
    if (!boundary_bits || format(*boundary_bits.value()).find("all@0: u32 : 24@8") == std::string::npos)
        return 34;
    auto packed_bits = layout(*bitfields.value(), Abi::x86_64, LayoutOptions{1});
    if (!packed_bits || packed_bits.value().size != 4 || packed_bits.value().members.size() != 3 ||
        packed_bits.value().members[0].offset != 0 || packed_bits.value().members[1].offset != 0 ||
        packed_bits.value().members[2].offset != 0 || packed_bits.value().members[2].bit_width != 8 ||
        packed_bits.value().members[2].bit_offset != 8)
        return 31;
    auto flag_tag = Type::integer("flag_tag", 1, 1, false);
    auto packed_flag_record = Type::structure("PackedFlagRecord", {
        {"tag", flag_tag.value(), 0}, {"low", flags.value(), 1, 3, 0},
        {"next", flags.value(), 1, 5, 3}}, 5, 1);
    auto packed_flag_layout = packed_flag_record
        ? layout(*packed_flag_record.value(), Abi::x86_64, LayoutOptions{1})
        : hexlab::Result<TypeLayout>(packed_flag_record.error());
    if (!packed_flag_layout || packed_flag_layout.value().members[1].offset != 1 ||
        packed_flag_layout.value().members[2].offset != 1 || packed_flag_layout.value().size != 5)
        return 33;
    auto encoded_bits = encode(*bitfields.value());
    auto decoded_bits = encoded_bits ? decode(encoded_bits.value()) : hexlab::Result<TypePtr>(encoded_bits.error());
    if (!decoded_bits || decoded_bits.value()->members()[2].bit_width != 8 ||
        decoded_bits.value()->members()[2].bit_offset != 8)
        return 32;
    auto duplicate_enum = Type::enumeration("BadEnum", i32.value(), {"same", "same"});
    if (duplicate_enum)
        return 10;
    auto duplicate_parameters = Type::function(i32.value(), {{"same", i32.value()}, {"same", i32.value()}}, false);
    if (duplicate_parameters)
        return 11;

    auto byte = Type::integer("u8", 1, 1, false);
    auto wide = Type::integer("u64", 8, 8, false);
    auto pointer = Type::pointer(byte.value(), 4, 4);
    auto padding_record = Type::structure("Padding", {{"tag", byte.value(), 0}, {"value", wide.value(), 8}}, 16, 8);
    if (!byte || !wide || !pointer || !padding_record)
        return 12;
    auto x86 = layout(*padding_record.value(), Abi::x86_64);
    if (!x86 || x86.value().size != 16 || x86.value().alignment != 8 || x86.value().members.size() != 2 ||
        x86.value().members[1].offset != 8 || x86.value().padding.size() != 1 ||
        x86.value().padding[0].offset != 1 || x86.value().padding[0].size != 7)
        return 13;
    LayoutOptions packed_one;
    packed_one.maximum_member_alignment = 1;
    auto packed_record = layout(*padding_record.value(), Abi::x86_64, packed_one);
    if (!packed_record || packed_record.value().members[1].offset != 1 || packed_record.value().size != 9 ||
        packed_record.value().alignment != 1 || packed_record.value().padding.size() != 0)
        return 22;
    auto packed_four = layout(*padding_record.value(), Abi::x86_64, LayoutOptions{4});
    if (!packed_four || packed_four.value().members[1].offset != 4 || packed_four.value().size != 12 ||
        packed_four.value().alignment != 4 || packed_four.value().padding.size() != 1 ||
        packed_four.value().padding[0].size != 3)
        return 23;

    auto invalid_pack = layout(*padding_record.value(), Abi::x86_64, LayoutOptions{3});
    if (invalid_pack || invalid_pack.error().code != hexlab::ErrorCode::invalid_argument)
        return 25;
    auto ptr32 = layout(*pointer.value(), Abi::x86_32);
    auto ptr64 = layout(*pointer.value(), Abi::aarch64);
    if (!ptr32 || !ptr64 || ptr32.value().size != 4 || ptr64.value().size != 8 || pointer_size(Abi::x86_64) != 8)
        return 14;
    auto array_layout = layout(*array.value(), Abi::x86_32);
    if (!array_layout || array_layout.value().size != 12 || array_layout.value().alignment != 4)
        return 15;
    auto vector_lane = Type::integer("i32", 4, 4, true);
    auto vector_type = vector_lane ? Type::vector(vector_lane.value(), 4, 16) :
        hexlab::Result<TypePtr>(hexlab::Error{hexlab::ErrorCode::invalid_argument, "vector lane creation failed"});
    if (!vector_type || vector_type.value()->kind() != Kind::vector || vector_type.value()->count() != 4 ||
        vector_type.value()->size() != 16 || vector_type.value()->element() != vector_lane.value() ||
        format(*vector_type.value()) != "vector<i32, 4>")
        return 29;
    const auto vector_layout = layout(*vector_type.value(), Abi::x86_64);
    if (!vector_layout || vector_layout.value().size != 16 || vector_layout.value().alignment != 16)
        return 30;
    const auto vector_encoded = encode(*vector_type.value());
    const auto vector_decoded = vector_encoded ? decode(vector_encoded.value()) :
        hexlab::Result<TypePtr>(vector_encoded.error());
    if (!vector_decoded || vector_encoded.value().front() != std::byte{5} ||
        vector_decoded.value()->id() != vector_type.value()->id() ||
        vector_decoded.value()->element()->kind() != Kind::integer)
        return 31;
    auto legacy_v4 = encode(*vector_lane.value());
    if (legacy_v4) legacy_v4.value().front() = std::byte{4};
    const auto legacy_v4_decoded = legacy_v4 ? decode(legacy_v4.value()) :
        hexlab::Result<TypePtr>(legacy_v4.error());
    if (!legacy_v4_decoded || legacy_v4_decoded.value()->kind() != Kind::integer)
        return 32;
    if (Type::vector(vector_lane.value(), 0, 16) || Type::vector(vector_lane.value(), 4, 3) ||
        Type::vector(array.value(), 4, 16))
        return 33;
    auto huge_lane = Type::integer("huge", UINT64_MAX, 1, false);
    if (!huge_lane || Type::vector(huge_lane.value(), 2, 1))
        return 34;
    auto union_type = Type::union_type("Scalar", {{"b", byte.value(), 0}, {"w", wide.value(), 0}}, 8, 8);
    auto union_layout = layout(*union_type.value(), Abi::aarch64);
    if (!union_layout || union_layout.value().size != 8 || union_layout.value().alignment != 8 ||
        union_layout.value().members.size() != 2 || union_layout.value().members[1].offset != 0)
        return 16;
    auto nested = Type::structure("Nested", {{"inner", padding_record.value(), 0}, {"tail", wide.value(), 16}}, 24, 8);
    if (!nested)
        return 26;
    auto packed_nested = layout(*nested.value(), Abi::x86_64, packed_one);
    if (!packed_nested || packed_nested.value().members[1].offset != 9 || packed_nested.value().size != 17 ||
        packed_nested.value().members[0].size != 9)
        return 27;
    auto packed_scalar = layout(*wide.value(), Abi::x86_64, packed_one);
    if (!packed_scalar || packed_scalar.value().alignment != 8)
        return 28;
    auto packed_union = layout(*union_type.value(), Abi::x86_64, packed_one);
    if (!packed_union || packed_union.value().size != 8 || packed_union.value().alignment != 1 ||
        packed_union.value().members[1].alignment != 1)
        return 24;
    auto record32 = layout(*padding_record.value(), Abi::x86_32);
    if (!record32 || record32.value().members[1].offset != 4 || record32.value().alignment != 4 ||
        record32.value().size != 12 || record32.value().padding.size() != 1 ||
        record32.value().padding[0].size != 3)
        return 17;
    auto enumeration = Type::enumeration("State", wide.value(), {"ready", "done"});
    if (!enumeration || enumeration.value()->enumerator_values()[0].value != 0 ||
        enumeration.value()->enumerator_values()[1].value != 1)
        return 20;
    std::vector<std::byte> legacy_enum;
    const auto legacy_number = [&](std::uint64_t value, std::size_t width) {
        for (std::size_t i = 0; i < width; ++i)
            legacy_enum.push_back(static_cast<std::byte>(value >> (8 * (width - i - 1))));
    };
    const auto legacy_text = [&](std::string_view value) {
        legacy_number(value.size(), 4);
        for (const auto c : value) legacy_enum.push_back(static_cast<std::byte>(c));
    };
    legacy_number(1, 1); // Previous persisted type record version.
    legacy_number(static_cast<unsigned>(Kind::enumeration), 1); legacy_text("LegacyState");
    legacy_number(8, 8); legacy_number(8, 8); legacy_number(0, 1); legacy_number(0, 8);
    legacy_number(static_cast<unsigned>(Kind::integer), 1); legacy_text("u64");
    legacy_number(8, 8); legacy_number(8, 8); legacy_number(0, 1); legacy_number(0, 8);
    legacy_number(2, 4); legacy_text("old_a"); legacy_text("old_b");
    const auto legacy_decoded = decode(legacy_enum);
    if (!legacy_decoded || legacy_decoded.value()->enumerators().size() != 2 ||
        legacy_decoded.value()->enumerator_values()[0].value != 0 ||
        legacy_decoded.value()->enumerator_values()[1].value != 1)
        return 21;
    auto enum_layout = layout(*enumeration.value(), Abi::x86_32);
    if (!enum_layout || enum_layout.value().size != 8 || enum_layout.value().alignment != 4)
        return 18;
    auto void_layout = layout(*Type::void_type(), Abi::x86_64);
    if (void_layout || void_layout.error().code != hexlab::ErrorCode::unsupported)
        return 19;
    auto named_ref = Type::named_reference("Node");
    if (!named_ref || named_ref.value()->kind() != Kind::named_reference || named_ref.value()->size() ||
        format(*named_ref.value()) != "Node")
        return 22;
    auto unresolved_layout = layout(*named_ref.value(), Abi::x86_64);
    if (unresolved_layout || unresolved_layout.error().code != hexlab::ErrorCode::unsupported)
        return 23;
    if (Type::named_reference(""))
        return 24;
    std::cout << "types tests passed\n";
}
