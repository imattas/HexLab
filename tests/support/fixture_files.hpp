#pragma once
#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <vector>

namespace hexlab_test {
inline void write_file(const std::filesystem::path& path, std::span<const std::byte> bytes) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!bytes.empty()) stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) throw std::runtime_error("Cannot write test fixture");
}
class FixtureFile {
public:
    explicit FixtureFile(std::span<const std::byte> bytes) {
        static std::atomic<unsigned> serial{0};
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        path = std::filesystem::current_path() / "fixture-data" /
            (std::to_string(stamp) + "_" + std::to_string(serial++) + ".bin");
        write_file(path, bytes);
    }
    ~FixtureFile() { std::error_code ignored; std::filesystem::remove(path, ignored); }
    FixtureFile(const FixtureFile&) = delete;
    FixtureFile& operator=(const FixtureFile&) = delete;
    std::filesystem::path path;
};
inline std::vector<std::byte> bytes(std::initializer_list<unsigned> values) {
    std::vector<std::byte> result;
    for (auto value : values) result.push_back(static_cast<std::byte>(value));
    return result;
}
}
