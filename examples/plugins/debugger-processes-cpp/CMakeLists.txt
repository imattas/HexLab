cmake_minimum_required(VERSION 3.24)
project(HexLabDebuggerProcessesCppPlugin VERSION 1.0.0 LANGUAGES CXX)

find_package(HexLabPluginSdk CONFIG REQUIRED)
include("${HexLabPluginSdk_PLUGIN_PACKAGE_HELPER}")

add_library(hexlab_debugger_processes MODULE debugger_processes.cpp)
target_link_libraries(hexlab_debugger_processes PRIVATE hexlab::plugin_sdk)
target_compile_features(hexlab_debugger_processes PRIVATE cxx_std_17)
set_target_properties(hexlab_debugger_processes PROPERTIES PREFIX "")

hexlab_package_plugin(hexlab_debugger_processes
  "org.hexlab.example.debugger-processes-cpp"
  "Debugger Process Inventory C++ Example" "${PROJECT_VERSION}")
