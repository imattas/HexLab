#pragma once
#include <span>
#include <string_view>
#include <iosfwd>
namespace hexlab::cli {
int run_project_cli(std::span<const std::wstring_view>,std::ostream&,std::ostream&);
void project_usage(std::ostream&);
}
