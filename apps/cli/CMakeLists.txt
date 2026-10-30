add_executable(hexlab_cli main.cpp argument_text.cpp commands.cpp compare_command.cpp firmware_uefi.cpp firmware_fit.cpp firmware_microcode.cpp project_commands.cpp project_arguments.cpp project_output.cpp project_exchange_cli.cpp project_history_cli.cpp signature_catalog_command.cpp)
target_link_libraries(hexlab_cli PRIVATE hexlab::workspace hexlab::plugins hexlab::decompiler hexlab::compare hexlab::analysis hexlab::firmware)
if(MSVC)
  # The CLI command dispatcher has grown enough to exceed the standard COFF
  # section-index limit under MSVC. Largeobj extends that limit for its object.
  target_compile_options(hexlab_cli PRIVATE /bigobj)
endif()
if(APPLE)
  set_target_properties(hexlab_cli PROPERTIES INSTALL_RPATH "@loader_path/../${CMAKE_INSTALL_LIBDIR}")
elseif(UNIX)
  set_target_properties(hexlab_cli PROPERTIES INSTALL_RPATH "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
endif()
if(WIN32)
  install(TARGETS hexlab_cli
    RUNTIME_DEPENDENCY_SET hexlab_windows_runtime_dependencies
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
else()
  install(TARGETS hexlab_cli RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()
