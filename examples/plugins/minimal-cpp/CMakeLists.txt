cmake_minimum_required(VERSION 3.24)
project(HexLabMinimalCppPlugin VERSION 1.0.0 LANGUAGES CXX)

find_package(HexLabPluginSdk CONFIG REQUIRED)
include("${HexLabPluginSdk_PLUGIN_PACKAGE_HELPER}")

add_library(hexlab_hello MODULE minimal_plugin.cpp)
target_link_libraries(hexlab_hello PRIVATE hexlab::plugin_sdk)
target_compile_features(hexlab_hello PRIVATE cxx_std_17)
set_target_properties(hexlab_hello PROPERTIES PREFIX "")

hexlab_package_plugin(hexlab_hello
  "org.hexlab.example.hello-cpp" "Hello C++ Plugin" "${PROJECT_VERSION}")
