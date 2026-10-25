cmake_minimum_required(VERSION 3.24)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(HexLabFirmware VERSION 0.1.0 LANGUAGES CXX)
  include(GNUInstallDirs)
  include(GenerateExportHeader)
  include(CTest)
  add_library(hexlab_options INTERFACE)
  target_compile_features(hexlab_options INTERFACE cxx_std_20)
  target_compile_options(hexlab_options INTERFACE
    $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/W4;/permissive-;/utf-8>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wall;-Wextra;-Wpedantic>)
  add_library(hexlab_core INTERFACE)
  add_library(hexlab::core ALIAS hexlab_core)
  target_include_directories(hexlab_core INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/../core/include")
  include(../../cmake/HexLabLibrary.cmake)
endif()

hexlab_add_library(firmware SOURCES src/firmware.cpp src/uefi_volume.cpp DEPENDS hexlab::core)
if(BUILD_TESTING)
  add_executable(hexlab_firmware_tests ../../tests/firmware_tests.cpp)
  target_include_directories(hexlab_firmware_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../tests")
  target_link_libraries(hexlab_firmware_tests PRIVATE hexlab::firmware)
  add_test(NAME firmware_formats COMMAND hexlab_firmware_tests)
endif()
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/firmware-formats.md"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/docs")
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../../docs/uefi-firmware-volume.md"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/hexlab/docs")
