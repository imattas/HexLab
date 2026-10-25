#include "support/checks.hpp"
#include <charconv>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
using hexlab_test::check;
int main(int argc, char **argv) {
    return hexlab_test::run([&] {
        if (argc != 2 && !(argc == 3 && std::string(argv[2]) == "qemu-safe"))
            throw std::runtime_error("Expected authored16 measurement path and optional qemu-safe subset");
        const std::filesystem::path path = argv[1];
        if (std::filesystem::file_size(path) > 65536)
            throw std::runtime_error("Authored16 record file exceeds64KiB");
        std::ifstream stream(path);
        if (!stream)
            throw std::runtime_error("Cannot read authored16 record file");
        std::string line;
        std::getline(stream, line);
        check(line == "HX16_ORACLE_V1", "independent oracle version");
        std::map<std::string, std::uint32_t> expected{{"real_operand16", 0x11221235},
                                                      {"real_operand32", 0x11221236},
                                                      {"real_ds_bx", 0x1111},
                                                      {"real_ss_bp", 0x2222},
                                                      {"real_alias", 0x5a},
                                                      {"real_a20_disabled", 0x11},
                                                      {"real_a20_enabled", 0x22},
                                                      {"real_far_stack", 0x6ffc},
                                                      {"pm_operand16", 0x33445679},
                                                      {"pm_operand32", 0x3344567a},
                                                      {"pm_stack_value16", 0x6ffe},
                                                      {"pm_stack_value32", 0x6ffc},
                                                      {"pm_stack_address16", 0x1fffe},
                                                      {"pm_stack_address32", 0xfffe},
                                                      {"pm_high_sequential", 0x10006},
                                                      {"pm_high_untaken", 0x10007},
                                                      {"pm_high_call16_return", 0x23},
                                                      {"pm_high_taken", 0x80},
                                                      {"pm_far16_stack", 0x6ffc},
                                                      {"pm_far32_stack", 0x6ff8},
                                                      {"pm_limit_faults", 1},
                                                      {"real_limit_faults", 1},
                                                      {"pm_code_limit_eip", 0x10000},
                                                      {"pm_code_limit_faults", 2}};
        if (argc == 3) {
            for (auto name : {"pm_high_sequential", "pm_high_untaken", "pm_high_call16_return", "pm_high_taken",
                              "pm_far16_stack", "pm_far32_stack", "pm_limit_faults", "real_limit_faults",
                              "pm_code_limit_eip", "pm_code_limit_faults"})
                expected.erase(name);
        }
        std::map<std::string, std::uint32_t> seen;
        bool done = false;
        while (std::getline(stream, line)) {
            if (line == "DONE") {
                done = true;
                break;
            }
            auto separator = line.find('=');
            if (separator == std::string::npos || line.size() - separator - 1 != 8)
                throw std::runtime_error("Malformed authored16 measurement");
            auto name = line.substr(0, separator);
            std::uint32_t value = 0;
            const auto *begin = line.data() + separator + 1;
            auto parsed = std::from_chars(begin, line.data() + line.size(), value, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != line.data() + line.size() ||
                !seen.emplace(name, value).second)
                throw std::runtime_error("Invalid or repeated authored16 measurement");
            auto want = expected.find(name);
            check(want != expected.end() && want->second == value, name.c_str());
        }
        check(done, "authored16 completed every probe");
        check(seen.size() == expected.size(), "authored16 exact record count");
        for (const auto &[name, value] : expected)
            check(seen.contains(name), name.c_str());
        check(!std::getline(stream, line), "no trailing authored16 records");
    });
}
