#pragma once
#include "hexlab/core/result.hpp"
#include "hexlab/types/types_export.hpp"
#include <cstdint>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace hexlab::types {
enum class Kind { void_type, boolean, integer, floating, pointer, array, structure, union_type, enumeration, function, named_reference, vector, qualified };
enum class Qualifier : std::uint8_t { const_ = 1, volatile_ = 2, restrict_ = 4 };
enum class FunctionConvention : std::uint8_t { platform_default, c_decl, stdcall, fastcall, thiscall, vectorcall, sysv_abi, ms_abi, aapcs64, aapcs32, mips_n64, mips_n32 };
using TypePtr = std::shared_ptr<const class Type>;
class Type;
enum class MemberAccess : std::uint8_t { unknown, private_, protected_, public_ };
HEXLAB_TYPES_EXPORT std::string format(const Type &type);
HEXLAB_TYPES_EXPORT hexlab::Result<std::vector<std::byte>> encode(const Type &type);
HEXLAB_TYPES_EXPORT hexlab::Result<TypePtr> decode(std::span<const std::byte> bytes);
struct Member {
    std::string name;
    TypePtr type;
    std::uint64_t offset = 0;
      // Present together only for CodeView/C-style bitfields. A zero width is
      // reserved for an unnamed allocation-unit barrier; bit_offset is zero.
      // Otherwise offset is the byte offset of the storage unit and bit_offset
      // is LSB-relative within it.
    std::optional<std::uint32_t> bit_width;
    std::optional<std::uint32_t> bit_offset;
    // Compiler-derived effective alignment for this member (for example from
    // #pragma pack or an explicit aligned attribute). When present this exact
    // value is used by layout; empty inherits natural ABI/aggregate packing.
    std::optional<std::uint64_t> effective_alignment;
    struct VirtualBaseLocation {
        TypePtr vbptr_type;
        std::uint64_t vbptr_offset = 0;
        // Entry index into signed 32-bit displacements, not a byte offset.
        // The runtime displacement is relative to object + vbptr_offset.
        std::uint64_t vbtable_index = 0;
        bool indirect = false;
    };
    // Present for CodeView virtual bases. `offset` is only a zero placeholder
    // in that case; runtime vbtable lookup determines the base subobject offset.
    std::optional<VirtualBaseLocation> virtual_base;
    // Source access control is declaration metadata and does not affect layout.
    MemberAccess access = MemberAccess::unknown;
    bool has_fixed_offset() const noexcept { return !virtual_base.has_value(); }
};
struct Parameter {
    std::string name;
    TypePtr type;
};
// A PDB CodeView LF_VFTABLE name list identifies a method by vftable slot.
// This metadata locates the slot but does not prove which runtime object owns
// the table; that proof remains the analysis caller's responsibility.
struct VTableSlot {
    std::uint32_t vfptr_offset = 0; // Byte offset of this table pointer in the object.
    std::uint32_t slot_index = 0;   // Zero-based function-pointer entry in the table.
    std::string table_name;
    std::string method_name;        // Raw CodeView slot name, retained verbatim.
    std::uint8_t source_namespace = 0;
    std::uint32_t source_type_index = 0;
    std::uint32_t source_record_offset = 0; // Byte offset in the source PDB TPI stream.
};
enum class MemberDispatch : std::uint8_t {
    non_virtual, virtual_method, introducing_virtual, pure_virtual,
    pure_introducing_virtual, unknown
};
// Function declarations are aggregate metadata, not data members: they do not
// participate in size, alignment, offsets, or ABI layout.
struct Method {
    std::string name;
    TypePtr signature;
    MemberAccess access = MemberAccess::unknown;
    MemberDispatch dispatch = MemberDispatch::unknown;
    std::uint16_t source_attributes = 0;
    bool is_static = false;
    std::optional<std::uint32_t> introducing_vtable_offset;
    TypePtr this_type;
    std::int32_t this_adjustment = 0;
    std::uint8_t function_options = 0;
    std::uint32_t declaration_ordinal = 0;
    std::vector<VTableSlot> vtable_slots;
};
// Static data belongs to an aggregate's declaration, but not to its instance
// layout. It is retained separately from Member so offsets and sizeof remain
// faithful to the object representation.
struct StaticDataMember {
    std::string name;
    TypePtr type;
    MemberAccess access = MemberAccess::unknown;
    std::uint16_t source_attributes = 0;
    std::uint32_t declaration_ordinal = 0;
};
struct Enumerator { std::string name; std::uint64_t value = 0; friend bool operator==(const Enumerator&, const Enumerator&) = default; };

class HEXLAB_TYPES_EXPORT Type final {
  public:
    Kind kind() const noexcept { return kind_; }
    const std::string &name() const noexcept { return name_; }
    std::uint64_t id() const noexcept { return id_; }
    std::optional<std::uint64_t> size() const noexcept { return size_; }
    std::uint64_t alignment() const noexcept { return alignment_; }
    bool is_signed() const noexcept { return signed_; }
    std::uint64_t count() const noexcept { return count_; }
    const TypePtr &element() const noexcept { return element_; }
    const std::vector<Member> &members() const noexcept { return members_; }
    std::optional<std::uint64_t> packing_alignment() const noexcept { return packing_alignment_; }
    const std::vector<std::string> &enumerators() const noexcept { return enumerators_; }
    const std::vector<Enumerator> &enumerator_values() const noexcept { return enumerator_values_; }
    const std::vector<Parameter> &parameters() const noexcept { return parameters_; }
    const std::vector<Method> &methods() const noexcept { return methods_; }
    const std::vector<StaticDataMember> &static_data_members() const noexcept { return static_data_members_; }
    const TypePtr &result_type() const noexcept { return result_; }
    bool variadic() const noexcept { return variadic_; }
    FunctionConvention function_convention() const noexcept { return function_convention_; }
    std::uint8_t qualifiers() const noexcept { return qualifiers_; }

    static TypePtr void_type();
    // A non-owning symbolic edge to a separately stored named definition.
    // This breaks recursive graphs without introducing shared_ptr cycles.
    static hexlab::Result<TypePtr> named_reference(std::string name);
    // C/C++ cv/restrict qualification; nested qualification is flattened.
    static hexlab::Result<TypePtr> qualified(TypePtr base, std::uint8_t qualifiers);
    // Returns a shallow copy with stronger ABI alignment, preserving size and
    // all nested type/member metadata. Alignment may only be increased.
    static hexlab::Result<TypePtr> with_alignment(TypePtr base, std::uint64_t alignment);
    // Rebuilds an aggregate with source function declarations while preserving
    // its data layout. The owning aggregate supplies each method's identity.
    static hexlab::Result<TypePtr> with_methods(TypePtr aggregate, std::vector<Method> methods);
    static hexlab::Result<TypePtr> with_static_data_members(TypePtr aggregate, std::vector<StaticDataMember> members);
    static hexlab::Result<TypePtr> boolean(std::uint64_t size, std::uint64_t alignment);
    static hexlab::Result<TypePtr> integer(std::string name, std::uint64_t size, std::uint64_t alignment,
                                           bool is_signed);
    static hexlab::Result<TypePtr> floating(std::string name, std::uint64_t size, std::uint64_t alignment);
    // Homogeneous integer/floating vector with a fixed lane count and ABI alignment.
    static hexlab::Result<TypePtr> vector(TypePtr element, std::uint64_t lanes, std::uint64_t alignment);
    static hexlab::Result<TypePtr> pointer(TypePtr pointee, std::uint64_t size, std::uint64_t alignment);
    // count == 0 represents an incomplete array; aggregates allow it only as
    // the final member of a structure (after at least one preceding member).
    static hexlab::Result<TypePtr> array(TypePtr element, std::uint64_t count);
    // An incomplete tagged aggregate declaration. It has no object size and
    // cannot be laid out until a complete definition is available.
    static hexlab::Result<TypePtr> incomplete_aggregate(Kind kind, std::string name);
    static hexlab::Result<TypePtr> structure(std::string name, std::vector<Member> members, std::uint64_t size,
                                             std::uint64_t alignment,
                                             std::optional<std::uint64_t> packing_alignment = std::nullopt);
    static hexlab::Result<TypePtr> union_type(std::string name, std::vector<Member> members, std::uint64_t size,
                                              std::uint64_t alignment,
                                              std::optional<std::uint64_t> packing_alignment = std::nullopt);
    static hexlab::Result<TypePtr> enumeration(std::string name, TypePtr underlying,
                                               std::vector<std::string> enumerators);
    static hexlab::Result<TypePtr> enumeration_with_values(std::string name, TypePtr underlying,
                                                          std::vector<Enumerator> enumerators);
    static hexlab::Result<TypePtr> function(TypePtr result, std::vector<Parameter> parameters, bool variadic,
                                             FunctionConvention convention = FunctionConvention::platform_default);

  private:
    explicit Type(Kind kind) : kind_(kind) {}
    static hexlab::Result<TypePtr> aggregate(Kind, std::string, std::vector<Member>, std::uint64_t, std::uint64_t,
                                             std::optional<std::uint64_t>);
    Kind kind_;
    std::string name_;
    std::uint64_t id_ = 0;
    std::optional<std::uint64_t> size_;
    std::uint64_t alignment_ = 1;
    bool signed_ = false;
    bool variadic_ = false;
    std::uint8_t qualifiers_ = 0;
    FunctionConvention function_convention_ = FunctionConvention::platform_default;
    std::uint64_t count_ = 0;
    TypePtr element_, result_;
    std::vector<Member> members_;
    std::optional<std::uint64_t> packing_alignment_;
    std::vector<std::string> enumerators_;
    std::vector<Enumerator> enumerator_values_;
    std::vector<Parameter> parameters_;
    std::vector<Method> methods_;
    std::vector<StaticDataMember> static_data_members_;
    friend void assign_id(Type &);
};
} // namespace hexlab::types
