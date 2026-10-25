cmake_minimum_required(VERSION 3.24)
project(HexLabProjectReportPlugin LANGUAGES C)
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/HexLabPluginPackage.cmake")

add_library(hexlab_project_report MODULE project_report.c)
target_include_directories(hexlab_project_report PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../../libs/plugins/include")
set_target_properties(hexlab_project_report PROPERTIES PREFIX "")
hexlab_package_plugin(hexlab_project_report
    "org.hexlab.example.project-report" "Project Report Example" "1.0.0")
