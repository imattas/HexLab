#pragma once
#include <filesystem>
#include <string>
#include <string_view>

namespace hexlab::cli {
std::wstring utf8_to_wide(std::string_view text);
std::string wide_to_utf8(std::wstring_view text);
std::filesystem::path path_from_wide(std::wstring_view path);
}
