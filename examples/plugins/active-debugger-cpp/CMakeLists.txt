cmake_minimum_required(VERSION 3.24)
project(HexLabActiveDebuggerCppPlugin VERSION 1.0.0 LANGUAGES CXX)

find_package(HexLabPluginSdk CONFIG REQUIRED)
include("${HexLabPluginSdk_PLUGIN_PACKAGE_HELPER}")

add_library(hexlab_active_debugger MODULE active_debugger.cpp)
target_link_libraries(hexlab_active_debugger PRIVATE hexlab::plugin_sdk)
target_compile_features(hexlab_active_debugger PRIVATE cxx_std_17)
set_target_properties(hexlab_active_debugger PROPERTIES PREFIX "")

hexlab_package_plugin(hexlab_active_debugger
  "org.hexlab.example.active-debugger-cpp"
  "Active Debugger C++ Example" "${PROJECT_VERSION}")
