if(WIN32)
  set(HEXLAB_PLUGIN_NATIVE src/module_provider_win.cpp)
else()
  set(HEXLAB_PLUGIN_NATIVE src/module_provider_posix.cpp)
endif()
hexlab_add_library(plugins SOURCES src/plugins.cpp src/runtime.cpp src/scalar_ir.cpp ${HEXLAB_PLUGIN_NATIVE}
  DEPENDS hexlab::core hexlab::automation hexlab::loaders hexlab::processors hexlab::debugger hexlab::decompiler)
if(UNIX AND NOT APPLE)
  target_link_libraries(hexlab_plugins PRIVATE ${CMAKE_DL_LIBS})
endif()

add_library(hexlab_plugin_sdk INTERFACE)
add_library(hexlab::plugin_sdk ALIAS hexlab_plugin_sdk)
set_target_properties(hexlab_plugin_sdk PROPERTIES EXPORT_NAME plugin_sdk)
target_include_directories(hexlab_plugin_sdk INTERFACE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
install(TARGETS hexlab_plugin_sdk EXPORT HexLabPluginSdkTargets COMPONENT PluginSDK)
install(FILES include/hexlab/plugins/plugin_abi.h include/hexlab/plugins/sdk.h
              include/hexlab/plugins/sdk.hpp
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/hexlab/plugins" COMPONENT PluginSDK)
include(CMakePackageConfigHelpers)
set(_hexlab_plugin_sdk_cmake_dir "${CMAKE_INSTALL_LIBDIR}/cmake/HexLabPluginSdk")
configure_package_config_file(
  "${PROJECT_SOURCE_DIR}/cmake/HexLabPluginSdkConfig.cmake.in"
  "${PROJECT_BINARY_DIR}/HexLabPluginSdkConfig.cmake"
  INSTALL_DESTINATION "${_hexlab_plugin_sdk_cmake_dir}")
write_basic_package_version_file(
  "${PROJECT_BINARY_DIR}/HexLabPluginSdkConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)
install(EXPORT HexLabPluginSdkTargets NAMESPACE hexlab::
  FILE HexLabPluginSdkTargets.cmake
  DESTINATION "${_hexlab_plugin_sdk_cmake_dir}" COMPONENT PluginSDK)
install(FILES
  "${PROJECT_BINARY_DIR}/HexLabPluginSdkConfig.cmake"
  "${PROJECT_BINARY_DIR}/HexLabPluginSdkConfigVersion.cmake"
  "${PROJECT_SOURCE_DIR}/examples/plugins/cmake/HexLabPluginPackage.cmake"
  DESTINATION "${_hexlab_plugin_sdk_cmake_dir}" COMPONENT PluginSDK)
