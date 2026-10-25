#include "hexlab/processors/decoder.hpp"
#include "hexlab/processors/format.hpp"
#include <iostream>
using namespace hexlab;
int main() {
    std::uint64_t at, word, size, expected = 0;
    unsigned count = 0;
    ThumbITState state{true, 0};
    while (std::cin >> std::hex >> at >> word >> size) {
        if (++count > 100000 || word > UINT32_MAX || (size != 2 && size != 4) || (size == 2 && word > UINT16_MAX) ||
            (count > 1 && at != expected))
            return 2;
        const std::array raw{std::byte(word), std::byte(word >> 8), std::byte(word >> 16), std::byte(word >> 24)};
        const auto result = decode_thumb(std::span(raw).first(static_cast<std::size_t>(size)), {{0}, at}, state);
        if (result.status != DecodeStatus::decoded || !result.instruction || result.instruction->length != size) {
            std::cerr << std::hex << at << ": " << result.reason << '\n';
            return 1;
        }
        state = result.instruction->arm->it_after;
        expected = at + size;
        std::cout << std::hex << at << '\t' << word << '\t' << format_instruction(*result.instruction) << '\n';
    }
    return std::cin.eof() && count && state == ThumbITState{true, 0} ? 0 : 2;
}
