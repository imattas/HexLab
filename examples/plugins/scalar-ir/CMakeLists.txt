cmake_minimum_required(VERSION 3.24)
project(HexLabScalarIRPlugin VERSION 1.0 LANGUAGES C)
find_package(HexLabPluginSdk CONFIG REQUIRED)
include(GNUInstallDirs)
add_library(hexlab_scalar_ir MODULE scalar_ir.c)
target_link_libraries(hexlab_scalar_ir PRIVATE hexlab::plugin_sdk)
target_compile_features(hexlab_scalar_ir PRIVATE c_std_11)
set_target_properties(hexlab_scalar_ir PROPERTIES PREFIX "")
# The sidecar exactly matches the binary's versioned capability declarations.
set(_manifest "$<TARGET_FILE:hexlab_scalar_ir>.hexlab-plugin")
file(GENERATE OUTPUT "${_manifest}" CONTENT
"format=hexlab-plugin-v1
id=example.scalar-ir
name=Scalar IR example
version=1.0
capability=processor.ir.scalar,1,22,0
requires=processor.ir.scalar,1,22
")
set(_package_dir "${CMAKE_INSTALL_LIBDIR}/hexlab/plugins")
install(TARGETS hexlab_scalar_ir RUNTIME DESTINATION "${_package_dir}" LIBRARY DESTINATION "${_package_dir}")
install(FILES "${_manifest}" DESTINATION "${_package_dir}")
