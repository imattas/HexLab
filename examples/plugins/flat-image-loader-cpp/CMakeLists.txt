cmake_minimum_required(VERSION 3.24)
project(HexLabFlatImageLoaderCppPlugin VERSION 1.0.0 LANGUAGES CXX)

find_package(HexLabPluginSdk CONFIG REQUIRED)
include("${HexLabPluginSdk_PLUGIN_PACKAGE_HELPER}")

add_library(hexlab_flat_image_loader MODULE flat_image_loader.cpp)
target_link_libraries(hexlab_flat_image_loader PRIVATE hexlab::plugin_sdk)
target_compile_features(hexlab_flat_image_loader PRIVATE cxx_std_17)
set_target_properties(hexlab_flat_image_loader PROPERTIES PREFIX "")

hexlab_package_plugin(hexlab_flat_image_loader
  "org.hexlab.example.flat-image-loader-cpp"
  "Flat Image Loader C++ Example" "${PROJECT_VERSION}")
