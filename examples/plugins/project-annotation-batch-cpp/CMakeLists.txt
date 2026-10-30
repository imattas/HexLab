cmake_minimum_required(VERSION 3.24)
project(HexLabProjectAnnotationBatchCppPlugin VERSION 1.0.0 LANGUAGES CXX)

find_package(HexLabPluginSdk CONFIG REQUIRED)
include("${HexLabPluginSdk_PLUGIN_PACKAGE_HELPER}")

add_library(hexlab_project_annotation_batch MODULE project_annotation_batch.cpp)
target_link_libraries(hexlab_project_annotation_batch PRIVATE hexlab::plugin_sdk)
target_compile_features(hexlab_project_annotation_batch PRIVATE cxx_std_17)
set_target_properties(hexlab_project_annotation_batch PROPERTIES PREFIX "")

hexlab_package_plugin(hexlab_project_annotation_batch
  "org.hexlab.example.project-annotation-batch-cpp"
  "Project Annotation Batch C++ Example" "${PROJECT_VERSION}")
