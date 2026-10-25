cmake_minimum_required(VERSION 3.24)
project(HexLabTypeWorkflowPlugin LANGUAGES C)
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/HexLabPluginPackage.cmake")

add_library(hexlab_type_workflow MODULE type_workflow.c)
target_include_directories(hexlab_type_workflow PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../../libs/plugins/include")
set_target_properties(hexlab_type_workflow PROPERTIES PREFIX "")
hexlab_package_plugin(hexlab_type_workflow
    "org.hexlab.example.type-workflow" "C Type Workflow Example" "1.0.0")
