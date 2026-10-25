#pragma once

#include <filesystem>
#include <string>
#include <string_view>

// Keep test tools usable on POSIX while preserving native UTF-16 argv handling
// on Windows. POSIX argv is UTF-8 by contract for these test paths.
#ifdef _WIN32
#define HEXLAB_TEST_MAIN wmain
using hexlab_test_arg_char = wchar_t;
inline std::filesystem::path hexlab_test_path(const wchar_t *value) {
    return std::filesystem::path(value);
}
inline bool hexlab_test_arg_equals(const wchar_t *value, std::string_view expected) {
    return std::wstring_view(value) == std::wstring(expected.begin(), expected.end());
}
#else
#define HEXLAB_TEST_MAIN main
using hexlab_test_arg_char = char;
inline std::filesystem::path hexlab_test_path(const char *value) {
    return std::filesystem::u8path(value);
}
inline bool hexlab_test_arg_equals(const char *value, std::string_view expected) {
    return std::string_view(value) == expected;
}
#endif
