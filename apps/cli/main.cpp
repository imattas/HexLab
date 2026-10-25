#include "commands.hpp"
#include "argument_text.hpp"
#include <iostream>
#include <vector>

#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
    try {
        std::vector<std::wstring_view> arguments;
        for(int n=1;n<argc;++n)arguments.emplace_back(argv[n]);
        return hexlab::cli::run_cli(arguments,std::cout,std::cerr);
    } catch(const std::exception& error){std::cerr<<"HexLab: "<<error.what()<<'\n';return 1;}
}
#else
int main(int argc, char **argv) {
    try {
        std::vector<std::wstring> storage;
        std::vector<std::wstring_view> arguments;
        storage.reserve(static_cast<std::size_t>(argc > 1 ? argc - 1 : 0));
        arguments.reserve(storage.capacity());
        for (int n = 1; n < argc; ++n) storage.push_back(hexlab::cli::utf8_to_wide(argv[n]));
        for (const auto &argument : storage) arguments.emplace_back(argument);
        return hexlab::cli::run_cli(arguments, std::cout, std::cerr);
    } catch (const std::exception &error) {
        std::cerr << "HexLab: " << error.what() << '\n';
        return 1;
    }
}
#endif
