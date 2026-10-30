cmake_minimum_required(VERSION 3.24)
project(HexLabFunctionCfgReportCppPlugin VERSION 1.0.0 LANGUAGES CXX)

find_package(HexLabPluginSdk CONFIG REQUIRED)
include("${HexLabPluginSdk_PLUGIN_PACKAGE_HELPER}")

add_library(hexlab_function_cfg_report MODULE function_cfg_report.cpp)
target_link_libraries(hexlab_function_cfg_report PRIVATE hexlab::plugin_sdk)
target_compile_features(hexlab_function_cfg_report PRIVATE cxx_std_17)
set_target_properties(hexlab_function_cfg_report PROPERTIES PREFIX "")

hexlab_package_plugin(hexlab_function_cfg_report
  "org.hexlab.example.function-cfg-report-cpp"
  "Function CFG Report C++ Example" "${PROJECT_VERSION}")
