#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include <iostream>
using namespace hexlab;
int main() {
    std::uint64_t address, word;
    unsigned count = 0;
    while (std::cin >> std::hex >> address >> word) {
        if (++count > 100000 || word > UINT32_MAX)
            return 2;
        const std::array bytes{std::byte(word), std::byte(word >> 8), std::byte(word >> 16), std::byte(word >> 24)};
        const auto result = decode_a32(bytes, {{0}, address});
        if (!result.instruction || result.status != DecodeStatus::decoded) {
            std::cerr << result.reason << '\n';
            return 1;
        }
        std::cout << std::hex << address << '\t' << word << '\t' << format_instruction(*result.instruction) << '\n';
    }
    return std::cin.eof() && count ? 0 : 2;
}
