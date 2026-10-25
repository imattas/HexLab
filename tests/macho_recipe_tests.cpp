#include "hexlab/loaders/recipe.hpp"
#include "support/macho_fixture.hpp"
#include "support/analysis_fixture.hpp"
#include "support/fixture_files.hpp"
#include "support/checks.hpp"
using namespace hexlab;
using namespace hexlab_test;
int main() {
    return run([] {
        const auto encoded = encode_recipe({Format::macho, {}, {}});
        check(encoded && encoded.value() == bytes({1, 0, 5, 0}),
              "Mach-O thin durable tag is appended without changing old bytes");
        auto decoded = decode_recipe(bytes({1, 0, 5, 1, 0, 0, 0, 1}));
        check(decoded && decoded.value().format == Format::macho && decoded.value().macho &&
                  decoded.value().macho->slice_index == 1,
              "explicit universal selection has canonical durable index");
        MemoryStorage source(macho_fixture::mapped_fat());
        auto selected = resolve_load_recipe(source, {Format::macho, {}, {}}, {});
        check(selected && selected.value().macho && selected.value().macho->slice_index == 1,
              "default supported fat choice is made concrete before persistent import");
        check(!decode_recipe(bytes({1, 0, 5, 2})) && !decode_recipe(bytes({1, 0, 5, 1, 0, 0})),
              "Mach-O recipe flags/extent checked");
        check(encode_recipe({Format::pe, {}, {}}).value() == bytes({1, 0, 2}) &&
                  encode_recipe({Format::elf, {}, {}}).value() == bytes({1, 0, 4}),
              "old PE/ELF tags remain byte-identical");
    });
}
