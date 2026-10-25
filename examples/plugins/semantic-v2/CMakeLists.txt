cmake_minimum_required(VERSION 3.24)
project(HexLabSemanticV2Plugin LANGUAGES C)
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/HexLabPluginPackage.cmake")

add_library(hexlab_semantic_v2 MODULE semantic_v2.c)
target_include_directories(hexlab_semantic_v2 PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../../libs/plugins/include")
set_target_properties(hexlab_semantic_v2 PROPERTIES PREFIX "")
hexlab_package_plugin(hexlab_semantic_v2
    "example.semantic-v2" "Semantic V2 example" "1.0")
