cmake_minimum_required(VERSION 3.24)
project(HexLabActiveDocumentCppPlugin VERSION 1.0.0 LANGUAGES CXX)

find_package(HexLabPluginSdk CONFIG REQUIRED)
include("${HexLabPluginSdk_PLUGIN_PACKAGE_HELPER}")

add_library(hexlab_active_document MODULE active_document.cpp)
target_link_libraries(hexlab_active_document PRIVATE hexlab::plugin_sdk)
target_compile_features(hexlab_active_document PRIVATE cxx_std_17)
set_target_properties(hexlab_active_document PROPERTIES PREFIX "")

hexlab_package_plugin(hexlab_active_document
  "org.hexlab.example.active-document-cpp"
  "Active Document C++ Example" "${PROJECT_VERSION}")
