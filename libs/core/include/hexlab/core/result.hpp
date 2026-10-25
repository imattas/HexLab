#pragma once
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace hexlab {
enum class ErrorCode { overflow, out_of_bounds, invalid_argument, io, unsupported, malformed, canceled, resource_limit,
    conflict, read_only, busy, integrity };
struct Error { ErrorCode code; std::string message; };

template<class T> class [[nodiscard]] Result {
public:
    Result(T value) : data_(std::move(value)) {}
    Result(Error error) : data_(std::move(error)) {}
    bool has_value() const noexcept { return std::holds_alternative<T>(data_); }
    explicit operator bool() const noexcept { return has_value(); }
    const T& value() const {
        if (!has_value()) throw std::logic_error("Result has no value");
        return std::get<T>(data_);
    }
    T& value() {
        if (!has_value()) throw std::logic_error("Result has no value");
        return std::get<T>(data_);
    }
    const Error& error() const {
        if (has_value()) throw std::logic_error("Result has no error");
        return std::get<Error>(data_);
    }
private:
    std::variant<T, Error> data_;
};
}
