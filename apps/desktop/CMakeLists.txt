add_library(hexlab_desktop_components STATIC main_frame.cpp document_controller.cpp session_controller.cpp session_search.cpp session_listing.cpp session_graph.cpp graph_canvas.cpp graph_view.cpp reference_view.cpp document_tabs.cpp project_actions.cpp reference_dialog.cpp close_coordinator.cpp project_view.cpp edit_dialogs.cpp search_view.cpp data_views.cpp open_dialogs.cpp type_symbols_view.cpp type_editor.cpp debugger_view.cpp debugger_locals.cpp plugins_view.cpp)
target_include_directories(hexlab_desktop_components PRIVATE "${PROJECT_SOURCE_DIR}/libs/workspace/src")
target_sources(hexlab_desktop_components PRIVATE string_view.cpp analysis_issues_view.cpp)
target_sources(hexlab_desktop_components PRIVATE minidump_view.cpp)
target_sources(hexlab_desktop_components PRIVATE macho_view.cpp pseudocode_view.cpp source_view.cpp pe_view.cpp compare_view.cpp compare_adapter.cpp archive_view.cpp history_view.cpp)
if(BUILD_TESTING)
  target_compile_definitions(hexlab_desktop_components PRIVATE HEXLAB_WORKSPACE_TESTING)
endif()
target_link_libraries(hexlab_desktop_components PUBLIC hexlab::workspace hexlab::decompiler hexlab::debugger hexlab::plugins hexlab::compare hexlab_wx)
if(HEXLAB_ENABLE_PYTHON_AUTOMATION)
  find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter Development.Embed)
  target_sources(hexlab_desktop_components PRIVATE
    python_console.cpp
    "${PROJECT_SOURCE_DIR}/libs/automation/src/python_module.cpp")
  target_include_directories(hexlab_desktop_components PRIVATE
    "${PROJECT_SOURCE_DIR}/libs/automation/src"
    "${PROJECT_BINARY_DIR}/libs/automation")
  target_compile_definitions(hexlab_desktop_components PRIVATE HEXLAB_DESKTOP_PYTHON_CONSOLE)
  target_link_libraries(hexlab_desktop_components PUBLIC hexlab::automation Python3::Python)
endif()
add_executable(hexlab WIN32 app.cpp)
target_link_libraries(hexlab PRIVATE hexlab_desktop_components)
if(APPLE)
  set(_hexlab_install_rpath "@loader_path/../${CMAKE_INSTALL_LIBDIR}")
  set(_hexlab_wx_install_rpath "@loader_path")
else()
  set(_hexlab_install_rpath "$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")
  set(_hexlab_wx_install_rpath "$ORIGIN")
endif()
set_target_properties(hexlab PROPERTIES INSTALL_RPATH "${_hexlab_install_rpath}")
if(WIN32)
  add_custom_command(TARGET hexlab POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      $<TARGET_RUNTIME_DLLS:hexlab> $<TARGET_FILE_DIR:hexlab>
    COMMAND_EXPAND_LISTS)
  if(HEXLAB_ENABLE_PYTHON_AUTOMATION)
    get_filename_component(HEXLAB_DESKTOP_PYTHON_DIR "${Python3_EXECUTABLE}" DIRECTORY)
    set(HEXLAB_DESKTOP_PYTHON_DLL
      "${HEXLAB_DESKTOP_PYTHON_DIR}/python${Python3_VERSION_MAJOR}${Python3_VERSION_MINOR}.dll")
    if(NOT EXISTS "${HEXLAB_DESKTOP_PYTHON_DLL}")
      message(FATAL_ERROR "Embedded Python runtime DLL not found: ${HEXLAB_DESKTOP_PYTHON_DLL}")
    endif()
    add_custom_command(TARGET hexlab POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${HEXLAB_DESKTOP_PYTHON_DLL}" "$<TARGET_FILE_DIR:hexlab>")
    install(FILES "${HEXLAB_DESKTOP_PYTHON_DLL}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
  endif()
endif()
# wxBUILD_INSTALL is disabled because this monorepo installs only the runtime
# products it ships. Keep the shared wx libraries beside the engine libraries
# on Unix and in bin with the other DLLs on Windows.
foreach(_target IN ITEMS wxbase wxcore wxaui)
  if(UNIX)
    set_target_properties(${_target} PROPERTIES INSTALL_RPATH "${_hexlab_wx_install_rpath}")
  endif()
endforeach()
install(TARGETS wxbase wxcore wxaui
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(TARGETS hexlab RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # Desktop environments discover the application from the standard XDG
  # locations. Keep this metadata optional with the GUI target.
  install(FILES "${PROJECT_SOURCE_DIR}/packaging/linux/hexlab.desktop"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/applications")
  install(FILES "${PROJECT_SOURCE_DIR}/packaging/linux/hexlab.svg"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps")
endif()
