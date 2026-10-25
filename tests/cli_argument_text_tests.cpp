#include "argument_text.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>

int main() {
    const std::string original = "program-\xF0\x9F\x94\xAC-\xE9\x9B\xAA";
    const auto wide = hexlab::cli::utf8_to_wide(original);
    if (hexlab::cli::wide_to_utf8(wide) != original) {
        std::cerr << "UTF-8 CLI arguments must round-trip non-BMP and multibyte characters\n";
        return EXIT_FAILURE;
    }
    const auto path = hexlab::cli::path_from_wide(wide);
#ifdef _WIN32
    if (path.native() != wide) {
#else
    if (path.native() != original) {
#endif
        std::cerr << "CLI Unicode paths must use the host filesystem representation\n";
        return EXIT_FAILURE;
    }
    bool rejected = false;
    try { (void)hexlab::cli::utf8_to_wide("bad-\xC0\xAF"); }
    catch (const std::invalid_argument &) { rejected = true; }
    if (!rejected) {
        std::cerr << "Malformed UTF-8 must be rejected\n";
        return EXIT_FAILURE;
    }
}
