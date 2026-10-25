if(NOT TARGET hexlab::plugins)
  set(HEXLAB_PLUGINS_STANDALONE TRUE)
  cmake_minimum_required(VERSION 3.24)
  project(HexLabPluginsTests VERSION 0.1.0 LANGUAGES C CXX)
  include(CTest)
  include(GNUInstallDirs)
  include(GenerateExportHeader)
  include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/HexLabLibrary.cmake")
  add_library(hexlab_options INTERFACE)
  target_compile_features(hexlab_options INTERFACE cxx_std_20)
  target_compile_options(hexlab_options INTERFACE
    $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/W4;/permissive-;/utf-8>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>)
  add_library(hexlab_sqlite3 SHARED "${CMAKE_CURRENT_LIST_DIR}/../../third_party/sqlite/sqlite3.c")
  target_include_directories(hexlab_sqlite3 PUBLIC "${CMAKE_CURRENT_LIST_DIR}/../../third_party/sqlite")
  target_compile_definitions(hexlab_sqlite3 PRIVATE SQLITE_THREADSAFE=1 SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_DQS=0 SQLITE_DEFAULT_FOREIGN_KEYS=1 SQLITE_TRUSTED_SCHEMA=0 "SQLITE_API=__declspec(dllexport)")
  foreach(component core image loaders database processors types analysis workspace automation)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../libs/${component}"
      "${CMAKE_CURRENT_BINARY_DIR}/hexlab-${component}")
  endforeach()
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../libs/plugins" "${CMAKE_CURRENT_BINARY_DIR}/hexlab-plugins")
endif()
add_executable(hexlab_plugins_tests plugins_tests.cpp)
target_link_libraries(hexlab_plugins_tests PRIVATE hexlab::plugins)
target_include_directories(hexlab_plugins_tests PRIVATE "${CMAKE_CURRENT_LIST_DIR}/..")
add_library(hexlab_cli_analysis_test_plugin MODULE cli_analysis_test_plugin.c)
target_include_directories(hexlab_cli_analysis_test_plugin PRIVATE "${PROJECT_SOURCE_DIR}/libs/plugins/include")
set_target_properties(hexlab_cli_analysis_test_plugin PROPERTIES PREFIX "")
if(HEXLAB_PLUGINS_STANDALONE)
  add_custom_command(TARGET hexlab_plugins_tests POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_core>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_image>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_loaders>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_database>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_sqlite3>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_processors>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_types>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_analysis>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_workspace>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_automation>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_plugins>" "$<TARGET_FILE_DIR:hexlab_plugins_tests>")
  add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../plugins_sdk" "${CMAKE_CURRENT_BINARY_DIR}/plugins_sdk")
endif()
add_test(NAME plugins COMMAND hexlab_plugins_tests)
