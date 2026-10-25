#include "hexlab/loaders/ar.hpp"
#include "hexlab/loaders/recipe.hpp"
#include "support/checks.hpp"
#include "support/fixture_files.hpp"
#include <cstddef>
#include <array>
#include <string>
#include <string_view>
#include <stop_token>
using namespace hexlab;
using namespace hexlab_test;

namespace {
void append(std::vector<std::byte>& out, std::string_view s) {
    for (const char c : s) out.push_back(static_cast<std::byte>(c));
}
void field(std::vector<std::byte>& out, std::string s, std::size_t width) {
    s.resize(width, ' '); append(out, s);
}
void member(std::vector<std::byte>& out, std::string name, std::string data) {
    field(out, std::move(name), 16); field(out, "0", 12); field(out, "0", 6); field(out, "0", 6);
    field(out, "100644", 8); field(out, std::to_string(data.size()), 10); append(out, "`\n"); append(out, data);
    if (data.size() & 1) out.push_back(std::byte{'\n'});
}
std::vector<std::byte> fixture() {
    std::vector<std::byte> out; append(out, "!<arch>\n");
    member(out, "//", "lib/a_very_long_object_name.o/\n");
    const auto symbol_data = out.size() + 60;
    member(out, "/", std::string("\0\0\0\1", 4) + std::string(4, '\0') + std::string("exported_symbol\0", 16));
    const auto target_header = out.size();
    for (int i = 0; i < 4; ++i) out[symbol_data + 4 + static_cast<std::size_t>(i)] = static_cast<std::byte>((target_header >> (24 - i * 8)) & 0xff);
    member(out, "/0", "abc");
    member(out, "#1/12", "bsd_object.oxyz");
    return out;
}
std::vector<std::byte> sym64_fixture() {
    std::vector<std::byte> out; append(out, "!<arch>\n");
    // GNU /SYM64/ payload: 64-bit big-endian symbol count, member header
    // offsets, then the NUL-terminated symbol-name table.
    const std::size_t target_header = 8 + 60 + 8 + 8 + 12;
    std::string index(16, '\0');
    index[7] = 1;
    for (int i = 0; i < 8; ++i) index[8 + i] = static_cast<char>((target_header >> (56 - 8 * i)) & 0xff);
    index += "wide_symbol"; index.push_back('\0');
    member(out, "/SYM64/", index);
    member(out, "wide.o/", "obj");
    return out;
}
void le32(std::string &out, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) out.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
}
void le64(std::string &out, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<char>((value >> (8 * i)) & 0xff));
}
std::vector<std::byte> coff_object_fixture() {
    std::string object(20, '\0');
    object[0] = static_cast<char>(0x64); object[1] = static_cast<char>(0x86); // AMD64
    object[2] = 1; // one section
    object[8] = 60; // symbol table follows the 20-byte header and 40-byte section
    object[12] = 3; // foo, bar, and one auxiliary record
    object.resize(60, '\0');
    object.replace(20, 5, ".text");
    auto symbol = [&](std::string name, std::uint16_t section, std::uint8_t storage, std::uint8_t aux) {
        std::string row(18, '\0');
        row.replace(0, name.size(), name);
        row[12] = static_cast<char>(section & 0xff); row[13] = static_cast<char>(section >> 8);
        row[16] = static_cast<char>(storage); row[17] = static_cast<char>(aux);
        object += row;
    };
    symbol("foo", 1, 2, 1); // external definition with one auxiliary row
    object.append(18, '\0'); // auxiliary record must not be interpreted as a symbol
    symbol("bar", 0, 2, 0); // external undefined reference
    object.append(4, '\0'); // empty string table
    object[114] = 4;
    object[8] = static_cast<char>(60 & 0xff); object[9] = static_cast<char>(60 >> 8);
    object[10] = object[11] = 0;
    std::vector<std::byte> result;
    result.reserve(object.size());
    for (unsigned char c : object) result.push_back(static_cast<std::byte>(c));
    return result;
}
std::vector<std::byte> bsd_symdef_fixture() {
    std::vector<std::byte> out; append(out, "!<arch>\n");
    std::string ranlib;
    le32(ranlib, 8); // one 32-bit ranlib descriptor
    le32(ranlib, 0); // symbol string offset
    const std::uint32_t member_header = static_cast<std::uint32_t>(8 + 60 + 28 + 60 + 4);
    le32(ranlib, member_header);
    le32(ranlib, 11);
    ranlib += "bsd_symbol";
    ranlib.push_back('\0');
    member(out, "__.SYMDEF", ranlib);
    member(out, "first.o/", "one");
    member(out, "second.o/", "two");
    return out;
}
std::vector<std::byte> bsd_symdef64_fixture() {
    std::vector<std::byte> out; append(out, "!<arch>\n");
    std::string ranlib;
    le64(ranlib, 16);
    le64(ranlib, 0);
    const std::uint64_t member_header = 8 + 60 + 48;
    le64(ranlib, member_header);
    le64(ranlib, 16);
    ranlib += "wide_bsd_symbol";
    ranlib.push_back('\0');
    member(out, "__.SYMDEF_64", ranlib);
    member(out, "wide.o/", "obj");
    return out;
}
void put(std::vector<std::byte> &out, std::size_t at, std::uint64_t value, std::size_t width, bool little) {
    for (std::size_t i = 0; i < width; ++i) {
        const auto index = little ? i : width - i - 1;
        out[at + index] = static_cast<std::byte>((value >> (i * 8)) & 0xff);
    }
}
std::vector<std::byte> elf_rel_symbols(bool wide, bool little) {
    const std::size_t ehsize = wide ? 64 : 52, shentsize = wide ? 64 : 40, symentsize = wide ? 24 : 16;
    const std::string strings("\0defined\0missing\0weak_missing\0defined\0", 39);
    const std::size_t text_at = ehsize, strings_at = text_at + 4, symbols_at = strings_at + strings.size();
    const std::size_t sections_at = (symbols_at + symentsize * 5 + 7) & ~std::size_t(7);
    std::vector<std::byte> out(sections_at + shentsize * 4);
    out[0]=std::byte{0x7f}; out[1]=std::byte{'E'}; out[2]=std::byte{'L'}; out[3]=std::byte{'F'};
    out[4]=wide ? std::byte{2} : std::byte{1}; out[5]=little ? std::byte{1} : std::byte{2}; out[6]=std::byte{1};
    put(out,16,1,2,little); put(out,18,wide ? 62 : 3,2,little); put(out,20,1,4,little);
    put(out,wide ? 40 : 32,sections_at,wide ? 8 : 4,little);
    put(out,wide ? 52 : 40,wide ? 64 : 52,2,little);
    put(out,wide ? 54 : 42,0,2,little); put(out,wide ? 56 : 44,0,2,little);
    put(out,wide ? 58 : 46,shentsize,2,little); put(out,wide ? 60 : 48,4,2,little);
    put(out,wide ? 62 : 50,0,2,little);
    out[text_at]=std::byte{0x90};
    std::copy(strings.begin(), strings.end(), reinterpret_cast<char *>(out.data()+strings_at));
    const auto set_section = [&](std::size_t i, std::uint32_t type, std::uint64_t offset, std::uint64_t size,
                                 std::uint32_t link, std::uint32_t info, std::uint64_t stride) {
        const auto at=sections_at+i*shentsize;
        put(out,at+4,type,4,little); put(out,at+(wide?24:16),offset,wide?8:4,little);
        put(out,at+(wide?32:20),size,wide?8:4,little); put(out,at+(wide?40:24),link,4,little);
        put(out,at+(wide?44:28),info,4,little); put(out,at+(wide?56:36),stride,wide?8:4,little);
    };
    set_section(1,1,text_at,4,0,0,0); set_section(2,3,strings_at,strings.size(),0,0,0);
    set_section(3,2,symbols_at,symentsize*5,2,1,symentsize);
    const auto sym = [&](std::size_t i, std::uint32_t name, std::uint8_t binding, std::uint16_t section) {
        const auto at=symbols_at+i*symentsize;
        put(out,at,name,4,little);
        if (wide) { out[at+4]=static_cast<std::byte>(binding<<4); put(out,at+6,section,2,little); }
        else { out[at+12]=static_cast<std::byte>(binding<<4); put(out,at+14,section,2,little); }
    };
    sym(1,1,1,1); sym(2,9,1,0); sym(3,17,2,0); sym(4,30,1,0);
    return out;
}
}

int main() { return run([] {
    FixtureFile file(fixture());
    const auto storage = FileStorage::open(file.path).value();
    const auto detected = detect_format(*storage);
    check(detected && detected.value() == DetectedFormat::ar_candidate, "ar signature detected automatically");
    if (!detected) return;
    const auto resolved = resolve_load_recipe(*storage, {Format::automatic, {}, {}}, {});
    check(resolved && resolved.value().format == Format::ar, "automatic opening resolves to durable ar recipe");
    if (!resolved) return;
    const auto recipe = resolved.value();
    const auto encoded = encode_recipe(recipe);
    check(encoded && encoded.value() == bytes({1,0,6}), "ar load recipe encodes canonically");
    const auto decoded = decode_recipe(bytes({1,0,6}));
    check(decoded && decoded.value().format == Format::ar, "ar load recipe decodes durably");
    if (!encoded || !decoded) return;
    const auto loaded = load_archive(storage, recipe, {});
    check(bool(loaded), loaded ? "durable archive load succeeds" : loaded.error().message.c_str());
    if (!loaded) return;
    const auto &loaded_archive = loaded.value();
    check(loaded_archive.storage == storage && loaded_archive.archive.members.size() == 4,
          "durable archive open retains source storage and member listing");
    check(load_image(storage, recipe, {}).error().code == ErrorCode::unsupported,
          "image-only project loading clearly rejects archive containers");
    const auto archive = read_ar_archive(*storage).value();
    check(archive.members.size() == 4, "archive includes explicit special members");
    check(archive.members[2].name == "lib/a_very_long_object_name.o" && archive.members[2].size == 3,
          "GNU long-name table resolves member references");
    check(archive.members[3].name == "bsd_object.o" && archive.members[3].size == 3,
          "BSD inline name is removed from extracted payload extent");
    check(archive.has_symbol_index && archive.symbol_index_complete && archive.symbols.size() == 1 &&
          archive.symbols[0].name == "exported_symbol" && archive.members[archive.symbols[0].member_index].name == "lib/a_very_long_object_name.o",
          "GNU symbol index resolves member header offsets");
    const std::array<std::string_view, 3> requested_symbols{"exported_symbol", "not_in_archive", "exported_symbol"};
    const auto selection = select_ar_members(archive, requested_symbols);
    check(selection && selection.value().member_indices == std::vector<std::size_t>{2} &&
          selection.value().unresolved_symbols == std::vector<std::string>{"not_in_archive"} &&
          selection.value().archive_index_complete,
          "archive symbol selection deduplicates requests and reports unresolved names");
    ArArchive link_archive;
    link_archive.members = {{"entry.o", {}, {}, 1, ArMemberKind::regular},
                            {"helper.o", {}, {}, 1, ArMemberKind::regular},
                            {"duplicate.o", {}, {}, 1, ArMemberKind::regular},
                            {"unused.o", {}, {}, 1, ArMemberKind::regular}};
    const std::array<ArMemberSymbols, 4> summaries{{
        {0, {"entry"}, {"helper", "external"}},
        {1, {"helper"}, {"leaf"}},
        {2, {"external"}, {}},
        {3, {"unused"}, {}}}};
    const std::array<std::string_view, 1> link_roots{"entry"};
    const auto linked = select_ar_members_fixed_point(link_archive, summaries, link_roots);
    check(linked && linked.value().members.size() == 3 &&
          linked.value().members[0].member_index == 0 &&
          linked.value().members[0].selected_for == std::vector<std::string>{"entry"} &&
          linked.value().members[1].member_index == 1 &&
          linked.value().members[1].selected_for == std::vector<std::string>{"helper"} &&
          linked.value().members[2].member_index == 2 &&
          linked.value().members[2].selected_for == std::vector<std::string>{"external"} &&
          linked.value().unresolved_symbols == std::vector<std::string>{"leaf"},
          "fixed-point archive selection follows transitive undefined symbols and records selection provenance");
    for (const auto [wide, little] : {std::pair{false, true}, std::pair{false, false},
                                      std::pair{true, true}, std::pair{true, false}}) {
        FixtureFile object_file(elf_rel_symbols(wide, little));
        const auto object_storage = FileStorage::open(object_file.path).value();
        const auto summary = summarize_elf_ar_member(*object_storage, 7);
        check(summary && summary.value().member_index == 7 &&
              summary.value().definitions == std::vector<std::string>{"defined"} &&
              summary.value().undefined == std::vector<std::string>{"missing"},
              wide ? (little ? "ELF64 little-endian ET_REL symbol summary" : "ELF64 big-endian ET_REL symbol summary")
                   : (little ? "ELF32 little-endian ET_REL symbol summary" : "ELF32 big-endian ET_REL symbol summary"));
        ArObjectLimits tight; tight.max_symbols = 2;
        check(summarize_elf_ar_member(*object_storage, 0, {}, tight).error().code == ErrorCode::resource_limit,
              "ELF archive symbol summary enforces symbol count limit");
    }
    FixtureFile coff_file(coff_object_fixture());
    const auto coff_storage = FileStorage::open(coff_file.path).value();
    const auto coff_summary = summarize_coff_ar_member(*coff_storage, 11);
    check(coff_summary && coff_summary.value().member_index == 11 &&
          coff_summary.value().definitions == std::vector<std::string>{"foo"} &&
          coff_summary.value().undefined == std::vector<std::string>{"bar"},
          "COFF archive symbol summary skips auxiliary records and separates external definitions from references");
    ArArchive coff_archive;
    for (std::size_t i = 0; i < 12; ++i)
        coff_archive.members.push_back({"member" + std::to_string(i) + ".obj", {}, {}, 1, ArMemberKind::regular});
    const std::array<ArMemberSymbols, 1> coff_summaries{coff_summary.value()};
    const std::array<std::string_view, 1> coff_roots{"foo"};
    const auto coff_selection = select_ar_members_fixed_point(coff_archive, coff_summaries, coff_roots);
    check(coff_selection && coff_selection.value().members.size() == 1 &&
          coff_selection.value().members.front().member_index == 11 &&
          coff_selection.value().members.front().selected_for == std::vector<std::string>{"foo"} &&
          coff_selection.value().unresolved_symbols == std::vector<std::string>{"bar"},
          "COFF summary participates in fixed-point archive selection and propagates unresolved references");
    ArObjectLimits coff_tight; coff_tight.max_symbols = 2;
    check(summarize_coff_ar_member(*coff_storage, 0, {}, coff_tight).error().code == ErrorCode::resource_limit,
          "COFF archive symbol summary enforces symbol count limit");
    auto bad_aux_bytes = coff_object_fixture();
    bad_aux_bytes[77] = static_cast<std::byte>(0xff);
    FixtureFile bad_aux_file(std::move(bad_aux_bytes));
    const auto bad_aux_storage = FileStorage::open(bad_aux_file.path).value();
    check(summarize_coff_ar_member(*bad_aux_storage, 0).error().code == ErrorCode::malformed,
          "COFF archive symbol summary rejects auxiliary records extending beyond symbol table");
    std::stop_source coff_stop; coff_stop.request_stop();
    check(summarize_coff_ar_member(*coff_storage, 0, coff_stop.get_token()).error().code == ErrorCode::canceled,
          "COFF archive symbol summary honors cancellation");
    ArLinkLimits tiny_link; tiny_link.max_selected_members = 1;
    check(select_ar_members_fixed_point(link_archive, summaries, link_roots, {}, {}, tiny_link).error().code == ErrorCode::resource_limit,
          "fixed-point archive selection enforces selected member limit");
    std::stop_source link_stop; link_stop.request_stop();
    check(select_ar_members_fixed_point(link_archive, summaries, link_roots, {}, link_stop.get_token()).error().code == ErrorCode::canceled,
          "fixed-point archive selection honors cancellation");
    auto invalid_symbol_archive = archive;
    invalid_symbol_archive.symbols.push_back({"bad_reference", invalid_symbol_archive.members.size()});
    const std::array<std::string_view, 1> bad_reference{"exported_symbol"};
    check(!select_ar_members(invalid_symbol_archive, bad_reference),
          "archive symbol selection rejects invalid indexed member references");
    FixtureFile sym64_file(sym64_fixture());
    const auto sym64 = read_ar_archive(*FileStorage::open(sym64_file.path).value());
    check(sym64 && sym64.value().has_symbol_index && sym64.value().symbol_index_complete &&
          sym64.value().symbols.size() == 1 && sym64.value().symbols[0].name == "wide_symbol" &&
          sym64.value().members[sym64.value().symbols[0].member_index].name == "wide.o",
          "GNU 64-bit symbol index resolves symbols to archive members");
    FixtureFile bsd_file(bsd_symdef_fixture());
    const auto bsd = read_ar_archive(*FileStorage::open(bsd_file.path).value());
    check(bsd && bsd.value().has_symbol_index && bsd.value().symbol_index_complete &&
          bsd.value().symbols.size() == 1 && bsd.value().symbols[0].name == "bsd_symbol" &&
          bsd.value().members[bsd.value().symbols[0].member_index].name == "second.o",
          "BSD ranlib index resolves symbols to archive members");
    FixtureFile bsd64_file(bsd_symdef64_fixture());
    const auto bsd64 = read_ar_archive(*FileStorage::open(bsd64_file.path).value());
    check(bsd64 && bsd64.value().has_symbol_index && bsd64.value().symbol_index_complete &&
          bsd64.value().symbols.size() == 1 && bsd64.value().symbols[0].name == "wide_bsd_symbol" &&
          bsd64.value().members[bsd64.value().symbols[0].member_index].name == "wide.o",
          "BSD 64-bit ranlib index resolves symbols to archive members");
    check(extract_ar_member(*storage, archive.members[2]).value() == bytes({'a','b','c'}), "regular member extraction");
    check(extract_ar_member(*storage, archive.members[3]).value() == bytes({'x','y','z'}), "BSD member extraction excludes inline name");
    const auto member_storage = open_ar_member(storage, archive.members[2]);
    check(bool(member_storage), "regular archive member opens as bounded ByteStorage");
    if (member_storage) {
        const auto member_read = member_storage.value()->read_at({1}, 2);
        check(member_storage.value()->size() == 3 && member_read && member_read.value().bytes.size() == 2 &&
              member_read.value().bytes[0] == std::byte{'b'} && member_read.value().bytes[1] == std::byte{'c'},
              "member storage view reads only the selected payload");
        check(!member_storage.value()->read_at({2}, 2), "member storage view rejects reads past member boundary");
        const RawOptions raw{Architecture::x86_64, ExecutionMode::x86_64, {{0}, 0x5000}, true, false, false, {}};
        const auto image = load_raw(member_storage.value(), raw, {});
        check(image && image.value()->read({{0}, 0x5000}, 3).value() == bytes({'a','b','c'}),
              "existing image loader consumes member ByteStorage directly");
    }

    std::stop_source stop; stop.request_stop();
    check(read_ar_archive(*storage, stop.get_token()).error().code == ErrorCode::canceled, "archive scan cancellation");
    check(read_ar_archive(*FileStorage::open(bsd_file.path).value(), stop.get_token()).error().code == ErrorCode::canceled,
          "BSD ranlib scan cancellation");
    check(extract_ar_member(*storage, archive.members[2], stop.get_token()).error().code == ErrorCode::canceled,
          "member extraction cancellation");
    ArLimits small; small.max_members = 1;
    check(read_ar_archive(*storage, {}, small).error().code == ErrorCode::resource_limit, "member count limit");
    small = {}; small.max_extracted_bytes = 2;
    check(extract_ar_member(*storage, archive.members[2], {}, small).error().code == ErrorCode::resource_limit,
          "extraction size limit");

    auto corrupt = fixture(); corrupt.resize(corrupt.size() - 1);
    FixtureFile truncated(corrupt);
    check(read_ar_archive(*FileStorage::open(truncated.path).value()).error().code == ErrorCode::malformed,
          "truncated archive member rejected");
    corrupt = fixture(); corrupt[8 + 58] = std::byte{'x'};
    FixtureFile bad_trailer(corrupt);
    check(read_ar_archive(*FileStorage::open(bad_trailer.path).value()).error().code == ErrorCode::malformed,
          "invalid member trailer rejected");
    corrupt = fixture();
    for (std::size_t i = 0; i < 10; ++i) corrupt[8 + 48 + i] = std::byte{'9'};
    FixtureFile oversized_member(corrupt);
    check(!read_ar_archive(*FileStorage::open(oversized_member.path).value()), "oversized decimal member extent rejected without wraparound");
    corrupt.clear(); append(corrupt, "!<arch>\n");
    member(corrupt, "//", "long_filename.o/\n");
    member(corrupt, "/1", "x");
    FixtureFile interior_gnu_name(corrupt);
    check(read_ar_archive(*FileStorage::open(interior_gnu_name.path).value()).error().code == ErrorCode::malformed,
          "GNU long-name references must point to the start of a table entry");
    corrupt = std::vector<std::byte>{}; append(corrupt, "!<thin>\n");
    FixtureFile thin(corrupt);
    check(read_ar_archive(*FileStorage::open(thin.path).value()).error().code == ErrorCode::unsupported,
          "thin archive is explicitly unsupported");
    auto forged = archive.members[2]; forged.data_offset.value = UINT64_MAX; forged.size = 2;
    check(!extract_ar_member(*storage, forged), "forged extraction offset cannot wrap");
}); }
