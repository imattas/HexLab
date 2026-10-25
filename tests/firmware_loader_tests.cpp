#include "hexlab/loaders/firmware.hpp"
#include <cstdlib>
#include <iostream>

int main() {
    const std::string input = ":0400100001020304E2\n:021000000506E3\n:0400000500000010E7\n:00000001FF\n";
    auto loaded = hexlab::load_firmware(input, {});
    if (!loaded) { std::cerr << loaded.error().message << '\n'; return 1; }
    const auto &image = *loaded.value().image;
    const auto &metadata = *loaded.value().metadata.firmware;
    if (image.layout().segments.size() != 2 || image.layout().entries.size() != 1 ||
        image.layout().entries[0].offset != 0x10 || metadata.records.size() != 2 ||
        metadata.records[0].source_line != 1 || metadata.records[0].record_index != 1 ||
        metadata.records[1].source_line != 2 || metadata.records[1].packed_file_offset.value != 4 ||
        loaded.value().metadata.image_size != 6) return 2;
    auto bytes = image.read({{0}, 0x10}, 4);
    if (!bytes || bytes.value() != std::vector<std::byte>{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}}) return 3;
    if (image.segment_at({{0}, 0x1000}) == nullptr || image.segment_at({{0}, 0x100}) != nullptr) return 4;
    auto missing_start = hexlab::load_firmware(":0100000001FE\n:0400000500000010E7\n:00000001FF\n", {});
    if (!missing_start || missing_start.value().metadata.firmware->start_address != 0x10 ||
        !missing_start.value().image->layout().entries.empty() || missing_start.value().diagnostics.empty()) return 5;
    auto srec = hexlab::load_firmware("S1040000AA51\nS9030000FC\n",
        {hexlab::firmware::Format::motorola_s_record});
    if (!srec || srec.value().metadata.firmware->intel_hex || srec.value().metadata.image_size != 1 ||
        srec.value().metadata.firmware->records[0].source_line != 1 ||
        srec.value().image->read({{0}, 0}, 1).value()[0] != std::byte{0xaa}) return 6;
    std::cout << "firmware loader adapter passed\n";
}
