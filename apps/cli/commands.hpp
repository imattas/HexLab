#pragma once
#include <ostream>
#include <span>
#include <string_view>
namespace hexlab::cli {
// arguments excludes the executable name; paths stay native Unicode.
int run_cli(std::span<const std::wstring_view> arguments,std::ostream& out,std::ostream& err);
int run_compare_cli(std::span<const std::wstring_view> arguments,std::ostream& out,std::ostream& err);
int run_uefi_firmware_cli(std::span<const std::wstring_view> arguments,std::ostream& out,std::ostream& err);
int run_uefi_capsule_cli(std::span<const std::wstring_view> arguments,std::ostream& out,std::ostream& err);
int run_intel_fit_cli(std::span<const std::wstring_view> arguments,std::ostream& out,std::ostream& err);
int run_intel_microcode_cli(std::span<const std::wstring_view> arguments,std::ostream& out,std::ostream& err);
}
