#include "hexlab/types/header_import.hpp"
#include "hexlab/types/layout.hpp"

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <string>
#ifdef _WIN32
#include <crtdbg.h>
#endif

using namespace hexlab::types;

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT,_CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT,_CRTDBG_FILE_STDERR);
    _set_abort_behavior(0,_WRITE_ABORT_MSG|_CALL_REPORTFAULT);
#endif
    auto type_size_expressions=import_c_header(R"(
        struct HeaderRecord { char tag; int value; };
        static_assert(sizeof(int) == 4, "int ABI width");
        static_assert(sizeof(struct HeaderRecord) == 8, "aggregate extent");
        static_assert(alignof(struct HeaderRecord) == 4, "aggregate alignment");
        static_assert(sizeof(int *) == 8, "pointer width");
        static_assert(sizeof(unsigned char[3]) == 3, "array extent");
        enum HeaderSizes { header_record_bytes = sizeof(struct HeaderRecord) };
    )");
    if (!type_size_expressions ||
        type_size_expressions.value().enum_constants.at("header_record_bytes") != 8) {
        std::cerr << "RED: sizeof(type-id) and alignof(type-id) were not evaluated in header constants";
        if (!type_size_expressions) std::cerr << ": " << type_size_expressions.error().message;
        std::cerr << '\n';
        return 1;
    }
    const std::string header=R"(
        typedef unsigned long UWORD;
        struct Packet {
            unsigned char kind;
            UWORD length;
            const char *data;
            int samples[3];
        };
        union Payload { int number; double real; };
        enum State { Idle = 0, Ready = 3, Done, Failed = -1 };
        typedef struct Packet Packet;
        int process(Packet *packet, unsigned long flags);
        void reset(void);
    )";
    auto parsed=import_c_header(header);assert(parsed);
    const auto &r=parsed.value();
    assert(r.symbols.at("UWORD").kind==HeaderSymbolKind::typedef_name);
    auto packet=r.symbols.at("struct Packet").type;
    assert(packet->kind()==Kind::structure && packet->size()==40 && packet->alignment()==8);
    assert(packet->members().size()==4);
    assert(packet->members()[0].offset==0 && packet->members()[1].offset==8);
    assert(packet->members()[2].offset==16 && packet->members()[3].offset==24);
    assert(packet->members()[2].type->kind()==Kind::pointer);
    assert(packet->members()[3].type->kind()==Kind::array && packet->members()[3].type->count()==3);
    auto payload=r.symbols.at("union Payload").type;
    assert(payload->kind()==Kind::union_type && payload->size()==8);
    assert(r.enum_constants.at("Idle")==0 && r.enum_constants.at("Ready")==3 && r.enum_constants.at("Done")==4 && r.enum_constants.at("Failed")==-1);
    auto process=r.symbols.at("process").type;
    assert(process->kind()==Kind::function && process->parameters().size()==2);
    assert(process->parameters()[0].type->kind()==Kind::pointer && process->parameters()[0].name=="packet");
    assert(r.symbols.at("reset").type->parameters().empty());

    auto unsupported=import_c_header("#include <stdint.h>\nint f(void);");
    assert(!unsupported && unsupported.error().code==hexlab::ErrorCode::unsupported);
    auto bitfield=import_c_header("struct Bits { unsigned int x:3; };");
    assert(!bitfield && bitfield.error().code==hexlab::ErrorCode::unsupported);
    auto recursive=import_c_header("struct Loop { struct Loop *next; };");
    if(!recursive) { std::cerr << "RED: pointer-recursive aggregate rejected: " << recursive.error().message << '\n'; return 1; }
    const auto recursive_type=recursive.value().symbols.at("struct Loop").type;
    if(!(recursive_type->members().size()==1 &&
         recursive_type->members()[0].type->kind()==Kind::pointer &&
         recursive_type->members()[0].type->element()->kind()==Kind::named_reference &&
         recursive_type->members()[0].type->element()->name()=="struct Loop")) {
        std::cerr << "RED: recursive pointer did not retain a symbolic type edge\n"; return 1;
    }
    auto recursive_roundtrip=decode(encode(*recursive_type).value());
    if(!(recursive_roundtrip && recursive_roundtrip.value()->members()[0].type->element()->name()=="struct Loop")) {
        std::cerr << "RED: recursive type edge did not survive type serialization\n"; return 1;
    }
    auto mutually_recursive=import_c_header(
        "struct Left { struct Right *right; }; struct Right { struct Left *left; };");
    if(!(mutually_recursive &&
         mutually_recursive.value().symbols.at("struct Left").type->members()[0].type->kind()==Kind::pointer &&
         mutually_recursive.value().symbols.at("struct Left").type->members()[0].type->element()->kind()==Kind::named_reference &&
         mutually_recursive.value().symbols.at("struct Left").type->members()[0].type->element()->name()=="struct Right" &&
         mutually_recursive.value().symbols.at("struct Right").type->members()[0].type->kind()==Kind::pointer &&
         mutually_recursive.value().symbols.at("struct Right").type->members()[0].type->element()->kind()==Kind::named_reference &&
         mutually_recursive.value().symbols.at("struct Right").type->members()[0].type->element()->name()=="struct Left")) {
        std::cerr << "RED: mutually recursive pointer graph was not imported";
        if(!mutually_recursive) std::cerr << ": " << mutually_recursive.error().message;
        else std::cerr << ": Left edge=" << mutually_recursive.value().symbols.at("struct Left").type->members()[0].type->element()->name()
                       << ", Right edge=" << mutually_recursive.value().symbols.at("struct Right").type->members()[0].type->element()->name();
        std::cerr << '\n'; return 1;
    }
    auto recursive_by_value=import_c_header("struct InvalidLoop { struct InvalidLoop next; };");
    if(recursive_by_value || recursive_by_value.error().code!=hexlab::ErrorCode::unsupported) {
        std::cerr << "recursive by-value aggregate should be rejected without creating an owning cycle\n"; return 1;
    }
    auto duplicate=import_c_header("typedef int T; typedef long T;");
    assert(!duplicate && duplicate.error().code==hexlab::ErrorCode::conflict);
    auto function_pointer=import_c_header("int (*callback)(int value);");
    if (!function_pointer) { std::cerr << "RED: function-pointer declaration rejected: " << function_pointer.error().message << '\n'; return 1; }
    auto callback=function_pointer.value().symbols.at("callback").type;
    if (!(callback->kind()==Kind::pointer && callback->element()->kind()==Kind::function &&
           callback->element()->result_type()->kind()==Kind::integer &&
           callback->element()->parameters().size()==1 &&
           callback->element()->parameters()[0].name=="value" &&
           callback->element()->parameters()[0].type->kind()==Kind::integer)) {
        std::cerr << "RED: function-pointer declarator has the wrong type graph\n"; return 1;
    }
    auto serialized_callback=encode(*callback);
    auto restored_callback=serialized_callback ? decode(serialized_callback.value()) : hexlab::Result<TypePtr>(serialized_callback.error());
    if (!(restored_callback && restored_callback.value()->kind()==Kind::pointer &&
           restored_callback.value()->element()->kind()==Kind::function &&
           restored_callback.value()->element()->parameters()[0].name=="value")) {
        std::cerr << "RED: function-pointer type graph does not survive encode/decode\n"; return 1;
    }
    auto callback_typedef=import_c_header("typedef int (*Callback)(const char *text, ...); Callback callback;");
    if (!callback_typedef) { std::cerr << "RED: function-pointer typedef rejected: " << callback_typedef.error().message << '\n'; return 1; }
    auto callback_alias=callback_typedef.value().symbols.at("Callback").type;
    auto callback_object=callback_typedef.value().symbols.at("callback").type;
    if (!(callback_alias->kind()==Kind::pointer && callback_alias->element()->kind()==Kind::function &&
           callback_alias->element()->variadic() && callback_alias->element()->parameters().size()==1 &&
           callback_alias->element()->parameters()[0].type->kind()==Kind::pointer &&
           callback_object->kind()==Kind::pointer && callback_object->element()->kind()==Kind::function)) {
        std::cerr << "RED: function-pointer typedef lost variadic/signature information\n"; return 1;
    }
    auto nested=import_c_header(R"(
        int (*callbacks[3])(const char *text);
        int (*(*factory(void))[4])(long code);
    )");
    if (!nested) { std::cerr << "RED: nested function-pointer arrays rejected: " << nested.error().message << '\n'; return 1; }
    auto callback_array=nested.value().symbols.at("callbacks").type;
    if (!(callback_array->kind()==Kind::array && callback_array->count()==3 &&
          callback_array->element()->kind()==Kind::pointer &&
          callback_array->element()->element()->kind()==Kind::function &&
          callback_array->element()->element()->parameters()[0].type->kind()==Kind::pointer)) {
        std::cerr << "RED: array-of-function-pointers precedence is wrong\n"; return 1;
    }
    auto factory=nested.value().symbols.at("factory").type;
    auto factory_result=factory->result_type();
    if (!(factory->kind()==Kind::function && factory->parameters().empty() &&
          factory_result->kind()==Kind::pointer && factory_result->element()->kind()==Kind::array &&
          factory_result->element()->count()==4 && factory_result->element()->element()->kind()==Kind::pointer &&
          factory_result->element()->element()->element()->kind()==Kind::function &&
          factory_result->element()->element()->element()->parameters()[0].type->kind()==Kind::integer)) {
        std::cerr << "RED: nested function-return declarator precedence is wrong\n"; return 1;
    }
    auto precedence=import_c_header("int *table[2]; int (*row)[2]; int *produce(void);");
    assert(precedence);
    auto table=precedence.value().symbols.at("table").type;
    auto row=precedence.value().symbols.at("row").type;
    auto produce=precedence.value().symbols.at("produce").type;
    assert(table->kind()==Kind::array && table->element()->kind()==Kind::pointer);
    assert(row->kind()==Kind::pointer && row->element()->kind()==Kind::array);
    assert(produce->kind()==Kind::function && produce->result_type()->kind()==Kind::pointer);
    auto body=import_c_header("int compute(int value) { return value; }");
    assert(!body && body.error().code==hexlab::ErrorCode::unsupported);
    HeaderImportOptions limited;limited.max_tokens=3;
    auto over_limit=import_c_header("typedef int TooManyTokens;",limited);
    assert(!over_limit && over_limit.error().code==hexlab::ErrorCode::resource_limit);
    auto continued_macro=import_c_header("#define API_WORD \\\n    unsigned long\ntypedef API_WORD api_word;\napi_word exported;");
    if (!continued_macro || continued_macro.value().symbols.at("api_word").type->size()!=8 ||
        continued_macro.value().symbols.at("exported").type->size()!=8) {
        std::cerr << "RED: continued object-like macro was not spliced before preprocessing\n"; return 1;
    }
    HeaderImportOptions continued_condition_options;
    continued_condition_options.predefined_macros.emplace("HEX_FEATURE", "1");
    auto continued_condition=import_c_header("#if \\\n    1\nint enabled;\n#else\nint disabled;\n#endif\n",continued_condition_options);
    if (!continued_condition || !continued_condition.value().symbols.contains("enabled") ||
        continued_condition.value().symbols.contains("disabled")) {
        std::cerr << "RED: continued conditional directive was not evaluated as one line\n"; return 1;
    }
    auto aliases=import_c_header("int32_t id; uint64_t mask;");assert(aliases);
    assert(aliases.value().symbols.at("id").type->size()==4 && aliases.value().symbols.at("id").type->is_signed());
    assert(aliases.value().symbols.at("mask").type->size()==8 && !aliases.value().symbols.at("mask").type->is_signed());

    auto packed=import_c_header(R"(
        struct __attribute__((packed)) WireRecord {
            unsigned char kind;
            unsigned int length;
            short status;
        };
    )");
    if (!packed) { std::cerr << "packed aggregate rejected: " << packed.error().message << '\n'; return 1; }
    auto wire=packed.value().symbols.at("struct WireRecord").type;
    assert(wire->kind()==Kind::structure && wire->size()==7 && wire->alignment()==1);
    assert(wire->members().size()==3);
    assert(wire->members()[0].offset==0 && wire->members()[1].offset==1 && wire->members()[2].offset==5);
    auto packed_bytes=encode(*wire);
    auto restored_packed=packed_bytes ? decode(packed_bytes.value()) : hexlab::Result<TypePtr>(packed_bytes.error());
    assert(restored_packed && restored_packed.value()->alignment()==1 &&
           restored_packed.value()->members()[1].offset==1 && restored_packed.value()->members()[2].offset==5);

    auto packed_alias=import_c_header("union __attribute__((__packed__)) PackedUnion { unsigned char byte; unsigned int word; };");
    assert(packed_alias && packed_alias.value().symbols.at("union PackedUnion").type->size()==4 &&
           packed_alias.value().symbols.at("union PackedUnion").type->alignment()==1);

    auto packed_member=import_c_header(R"(
        struct MixedPacking {
            char tag;
            unsigned int __attribute__((__packed__)) wire_value;
            unsigned short trailer __attribute__((packed));
            unsigned int native_value;
        };
    )");
    if (!packed_member) { std::cerr << "RED: packed field attribute rejected: " << packed_member.error().message << '\n'; return 1; }
    const auto member_type=packed_member.value().symbols.at("struct MixedPacking").type;
    if (!(member_type->size()==12 && member_type->alignment()==4 &&
          member_type->members()[1].offset==1 && member_type->members()[1].effective_alignment==1 &&
          member_type->members()[2].offset==5 && member_type->members()[2].effective_alignment==1 &&
          member_type->members()[3].offset==8)) {
        std::cerr << "RED: packed field attribute did not affect only its member alignment\n"; return 1;
    }
    auto packed_member_roundtrip=decode(encode(*member_type).value());
    if (!(packed_member_roundtrip && packed_member_roundtrip.value()->members()[1].effective_alignment==1)) {
        std::cerr << "RED: packed field alignment was lost in type serialization\n"; return 1;
    }

    auto malformed_attribute=import_c_header("struct __attribute__((packed WireRecord { int value; };");
    assert(!malformed_attribute && malformed_attribute.error().code==hexlab::ErrorCode::malformed);
    auto unsupported_attribute=import_c_header("struct __attribute__((aligned(16))) AlignedRecord { int value; };");
    if (!unsupported_attribute || unsupported_attribute.value().symbols.at("struct AlignedRecord").type->alignment()!=16) {
        std::cerr << "RED: supported aligned aggregate attribute was not applied";
        if (!unsupported_attribute) std::cerr << ": " << unsupported_attribute.error().message;
        std::cerr << '\n'; return 1;
    }
    auto attributed_calling_convention=import_c_header("int __attribute__((stdcall)) callback(int value);");
    assert(attributed_calling_convention && attributed_calling_convention.value().symbols.at("callback").type->function_convention()==FunctionConvention::stdcall);
    auto keyword_calling_convention=import_c_header("int __stdcall callback(int value);");
    assert(keyword_calling_convention && keyword_calling_convention.value().symbols.at("callback").type->function_convention()==FunctionConvention::stdcall);
    auto declspec_aligned=import_c_header("struct __declspec(align(16)) AlignedRecord { int value; };");
    assert(declspec_aligned && declspec_aligned.value().symbols.at("struct AlignedRecord").type->alignment()==16);

    auto pragma_packed=import_c_header(R"(
#pragma pack(push, 2)
struct PackedByPragma { char tag; int value; short code; };
#pragma pack(pop)
struct NaturalAgain { char tag; int value; };
#pragma pack(1)
struct PackedBySet { char tag; int value; };
#pragma pack()
struct ResetAgain { char tag; int value; };
#pragma pack(1)
#pragma pack(0)
struct ResetByZero { char tag; int value; };
#pragma pack(push, wire_layout, 2)
struct NamedPush { char tag; int value; };
#pragma pack(push, nested_layout, 1)
struct NamedNested { char tag; int value; };
#pragma pack(pop, wire_layout)
struct NamedRestore { char tag; int value; };
#pragma pack(1)
#pragma pack(push, keep_current)
#pragma pack(4)
#pragma pack(pop, keep_current)
struct NamedCurrent { char tag; int value; };
#pragma pack()
    )");
    if (!pragma_packed) { std::cerr << "RED: pragma pack rejected: " << pragma_packed.error().message << '\n'; return 1; }
    auto pragma_type=pragma_packed.value().symbols.at("struct PackedByPragma").type;
    auto natural_again=pragma_packed.value().symbols.at("struct NaturalAgain").type;
    auto packed_set=pragma_packed.value().symbols.at("struct PackedBySet").type;
    auto reset_again=pragma_packed.value().symbols.at("struct ResetAgain").type;
    auto reset_zero=pragma_packed.value().symbols.at("struct ResetByZero").type;
    auto named_push=pragma_packed.value().symbols.at("struct NamedPush").type;
    auto named_nested=pragma_packed.value().symbols.at("struct NamedNested").type;
    auto named_restore=pragma_packed.value().symbols.at("struct NamedRestore").type;
    auto named_current=pragma_packed.value().symbols.at("struct NamedCurrent").type;
    if (!(pragma_type->size()==8 && pragma_type->alignment()==2 &&
          pragma_type->members()[1].offset==2 && pragma_type->members()[2].offset==6 &&
          natural_again->size()==8 && natural_again->members()[1].offset==4 &&
          packed_set->size()==5 && packed_set->alignment()==1 && packed_set->members()[1].offset==1 &&
          reset_again->size()==8 && reset_again->members()[1].offset==4 &&
          reset_zero->size()==8 && reset_zero->members()[1].offset==4 &&
          named_push->size()==6 && named_push->members()[1].offset==2 &&
          named_nested->size()==5 && named_nested->members()[1].offset==1 &&
          named_restore->size()==8 && named_restore->members()[1].offset==4 &&
          named_current->size()==5 && named_current->members()[1].offset==1)) {
        std::cerr << "RED: pragma pack push/pop/set/reset did not preserve aggregate layout semantics\n"; return 1;
    }
    auto restored_pragma=decode(encode(*pragma_type).value());
    if (!(restored_pragma && restored_pragma.value()->size()==pragma_type->size() &&
          restored_pragma.value()->alignment()==pragma_type->alignment() &&
          restored_pragma.value()->members()[1].offset==2 && restored_pragma.value()->members()[1].effective_alignment==2 &&
          restored_pragma.value()->members()[2].offset==6)) {
        std::cerr << "RED: pragma layout semantics were lost in type serialization\n"; return 1;
    }
    auto computed_pragma_layout=layout(*pragma_type,Abi::x86_64);
    if (!(computed_pragma_layout&&computed_pragma_layout.value().size==8&&
          computed_pragma_layout.value().alignment==2&&computed_pragma_layout.value().members[1].offset==2&&
          computed_pragma_layout.value().members[2].offset==6)) {
        std::cerr << "RED: compiler-derived member alignment is not retained by the reusable layout model\n"; return 1;
    }
    auto restored_pragma_layout=restored_pragma?layout(*restored_pragma.value(),Abi::x86_64):hexlab::Result<TypeLayout>(hexlab::Error{hexlab::ErrorCode::malformed,"decode failed"});
    if (!(restored_pragma_layout&&restored_pragma_layout.value().size==8&&
          restored_pragma_layout.value().alignment==2&&restored_pragma_layout.value().members[1].offset==2)) {
        std::cerr << "RED: v4 type record lost compiler-derived layout behavior\n"; return 1;
    }
    HeaderImportOptions preprocessing;
    preprocessing.predefined_macros.emplace("HEX_FEATURE", "1");
    preprocessing.include_resolver = [](std::string_view name, std::string_view including, bool angled)
        -> std::optional<HeaderInclude> {
        if (name == "public.h" && including == "<input>" && !angled)
            return HeaderInclude{"public.h", R"(
#ifndef PUBLIC_H
#define PUBLIC_H
#define API_WORD unsigned int
#if defined(HEX_FEATURE)
typedef API_WORD api_word;
#else
typedef long api_word;
#endif
struct PublicRecord { api_word size; };
#endif
)"};
        return std::nullopt;
    };
    auto included = import_c_header(R"(
#include "public.h"
#include "public.h"
api_word exported;
)", preprocessing);
    if (!included) { std::cerr << "RED: bounded include/macro preprocessing failed: " << included.error().message << '\n'; return 1; }
    assert(included.value().symbols.at("api_word").type->size() == 4);
    assert(included.value().symbols.at("exported").type->size() == 4);
    assert(included.value().symbols.at("struct PublicRecord").type->members()[0].type->size() == 4);
    HeaderImportOptions recursive_guard = preprocessing;
    recursive_guard.include_resolver = [](std::string_view, std::string_view, bool)
        -> std::optional<HeaderInclude> {
        return HeaderInclude{"self.h", "#ifndef SELF_H\n#define SELF_H\n#include \"self.h\"\ntypedef int self_t;\n#endif\n"};
    };
    auto guarded_self_include = import_c_header("#include \"self.h\"\nself_t value;", recursive_guard);
    assert(guarded_self_include && guarded_self_include.value().symbols.contains("value"));
    auto unresolved_include = import_c_header("#include <missing.h>\nint value;", preprocessing);
    assert(!unresolved_include && unresolved_include.error().code == hexlab::ErrorCode::unsupported &&
           unresolved_include.error().message.find("unable to resolve include") != std::string::npos);
    auto function_macro = import_c_header("#define DECLARE(x) int x\nint value;", preprocessing);
    assert(function_macro && function_macro.value().symbols.contains("value"));
    auto conditional = import_c_header("#if 0\nint hidden;\n#elif defined(HEX_FEATURE)\nint selected;\n#else\nint other;\n#endif\n", preprocessing);
    if (!conditional) { std::cerr << "conditional preprocessing failed: " << conditional.error().message << '\n'; return 1; }
    if (conditional.value().symbols.contains("hidden") || !conditional.value().symbols.contains("selected") || conditional.value().symbols.contains("other")) {
        std::cerr << "conditional preprocessing selected symbols:";
        for (const auto &[name, symbol] : conditional.value().symbols) { (void)symbol; std::cerr << ' ' << name; }
        std::cerr << '\n'; return 1;
    }
    assert(conditional && !conditional.value().symbols.contains("hidden") &&
           conditional.value().symbols.contains("selected") && !conditional.value().symbols.contains("other"));
    auto defined_prefix = import_c_header("#define definedness 1\n#if definedness\nint selected;\n#else\nint other;\n#endif\n");
    if (!defined_prefix || !defined_prefix.value().symbols.contains("selected") || defined_prefix.value().symbols.contains("other")) {
        std::cerr << "RED: identifier beginning with defined was parsed as the defined operator\n"; return 1;
    }
    auto commented_macro = import_c_header("#define FEATURE 1 /* enabled */\n#if FEATURE\nint selected;\n#else\nint other;\n#endif\n");
    if (!commented_macro || !commented_macro.value().symbols.contains("selected") || commented_macro.value().symbols.contains("other")) {
        std::cerr << "RED: comment in object-like macro value broke conditional evaluation\n"; return 1;
    }
    HeaderImportOptions macro_limited = preprocessing;
    macro_limited.max_macros = 1;
    auto macro_overflow = import_c_header("#define A 1\n#define B 2\nint value;", macro_limited);
    assert(!macro_overflow && macro_overflow.error().code == hexlab::ErrorCode::resource_limit);
    HeaderImportOptions include_limited = preprocessing;
    include_limited.max_include_depth = 1;
    include_limited.include_resolver = [](std::string_view name, std::string_view, bool)
        -> std::optional<HeaderInclude> {
        if (name == "child") return HeaderInclude{"child", "#include \"grandchild\"\n"};
        if (name == "grandchild") return HeaderInclude{"grandchild", "typedef int nested_t;\n"};
        return std::nullopt;
    };
    auto include_overflow = import_c_header("#include \"child\"\n", include_limited);
    assert(!include_overflow && include_overflow.error().code == hexlab::ErrorCode::resource_limit &&
           include_overflow.error().message.find("include depth") != std::string::npos);
    include_limited.include_resolver = [](std::string_view, std::string_view, bool)
        -> std::optional<HeaderInclude> { return HeaderInclude{"cycle.h", "#include \"cycle.h\"\n"}; };
    auto recursive_include_overflow = import_c_header("#include \"cycle.h\"\n", include_limited);
    assert(!recursive_include_overflow && recursive_include_overflow.error().code == hexlab::ErrorCode::resource_limit &&
           recursive_include_overflow.error().message.find("unguarded recursive include") != std::string::npos);
    HeaderImportOptions byte_limited = preprocessing;
    byte_limited.max_expanded_bytes = 8;
    auto expansion_overflow = import_c_header("#define LONG_NAME 123456789\nint value;", byte_limited);
    assert(!expansion_overflow && expansion_overflow.error().code == hexlab::ErrorCode::resource_limit);
    auto unmatched_pop=import_c_header("#pragma pack(pop)\nint value;");
    if (unmatched_pop || unmatched_pop.error().code!=hexlab::ErrorCode::malformed) {
        std::cerr << "RED: unmatched pragma pack pop was silently accepted\n"; return 1;
    }
    auto unmatched_named_pop=import_c_header("#pragma pack(pop, missing)\nint value;");
    if (unmatched_named_pop || unmatched_named_pop.error().code!=hexlab::ErrorCode::malformed) {
        std::cerr << "RED: unmatched named pragma pack pop was silently accepted\n"; return 1;
    }
}
