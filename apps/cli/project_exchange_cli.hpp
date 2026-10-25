#pragma once
#include "project_arguments.hpp"
#include "hexlab/types/type_library.hpp"
namespace hexlab::cli::project_detail {
Result<std::vector<std::byte>> read_exchange_file(const std::filesystem::path &);
Result<bool> write_exchange_file(const ProjectSnapshot &, const std::filesystem::path &, bool replace);
Result<bool> write_type_library_file(const ProjectSnapshot &, const std::filesystem::path &, bool replace);
Result<types::LibraryBundle> read_type_library_file(const std::filesystem::path &);
}
