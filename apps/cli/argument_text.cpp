#include "argument_text.hpp"
#include <cstdint>
#include <stdexcept>
#ifdef _WIN32
#include <Windows.h>
#endif

namespace hexlab::cli {
namespace {
void append_utf8(std::string &out, std::uint32_t cp) {
    if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        if (cp >= 0xd800 && cp <= 0xdfff) throw std::invalid_argument("Invalid Unicode scalar value");
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0x10ffff) {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else throw std::invalid_argument("Invalid Unicode scalar value");
}
}

std::wstring utf8_to_wide(std::string_view text) {
    if (text.size() > 1024 * 1024) throw std::invalid_argument("Argument exceeds text limit");
#ifdef _WIN32
    if (text.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!length) throw std::invalid_argument("Invalid UTF-8 argument");
    std::wstring out(static_cast<std::size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), length) != length)
        throw std::invalid_argument("Cannot decode UTF-8 argument");
    return out;
#else
    std::wstring out;
    for (std::size_t i = 0; i < text.size();) {
        const auto first = static_cast<unsigned char>(text[i++]);
        std::uint32_t cp = 0;
        unsigned continuation = 0;
        if (first <= 0x7f) cp = first;
        else if (first >= 0xc2 && first <= 0xdf) cp = first & 0x1f, continuation = 1;
        else if (first >= 0xe0 && first <= 0xef) cp = first & 0x0f, continuation = 2;
        else if (first >= 0xf0 && first <= 0xf4) cp = first & 0x07, continuation = 3;
        else throw std::invalid_argument("Invalid UTF-8 argument");
        if (continuation > text.size() - i) throw std::invalid_argument("Truncated UTF-8 argument");
        for (unsigned n = 0; n < continuation; ++n) {
            const auto byte = static_cast<unsigned char>(text[i++]);
            if ((byte & 0xc0) != 0x80) throw std::invalid_argument("Invalid UTF-8 continuation byte");
            cp = (cp << 6) | (byte & 0x3f);
        }
        if ((continuation == 1 && cp < 0x80) || (continuation == 2 && cp < 0x800) ||
            (continuation == 3 && cp < 0x10000) || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
            throw std::invalid_argument("Invalid UTF-8 scalar value");
        out.push_back(static_cast<wchar_t>(cp));
    }
    return out;
#endif
}

std::string wide_to_utf8(std::wstring_view text) {
    if (text.size() > 1024 * 1024) throw std::invalid_argument("Argument exceeds text limit");
#ifdef _WIN32
    if (text.empty()) return {};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!length) throw std::invalid_argument("Invalid UTF-16 argument");
    std::string out(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), length, nullptr, nullptr) != length)
        throw std::invalid_argument("Cannot encode argument");
    return out;
#else
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        std::uint32_t cp = static_cast<std::uint32_t>(text[i]);
        if constexpr (sizeof(wchar_t) == 2) {
            if (cp >= 0xd800 && cp <= 0xdbff) {
                if (++i >= text.size()) throw std::invalid_argument("Unpaired UTF-16 surrogate");
                const auto low = static_cast<std::uint32_t>(text[i]);
                if (low < 0xdc00 || low > 0xdfff) throw std::invalid_argument("Unpaired UTF-16 surrogate");
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
            }
        }
        append_utf8(out, cp);
    }
    return out;
#endif
}

std::filesystem::path path_from_wide(std::wstring_view path) {
#ifdef _WIN32
    return std::filesystem::path(path);
#else
    return std::filesystem::path(wide_to_utf8(path));
#endif
}
}
