include(GNUInstallDirs)

# Give a standalone SDK example the same data-only package metadata consumed by
# PluginManager::scan_directory, then install both files side by side.
function(hexlab_package_plugin target plugin_id plugin_name plugin_version)
  if(NOT TARGET "${target}")
    message(FATAL_ERROR "hexlab_package_plugin: unknown target '${target}'")
  endif()
  if(NOT plugin_id MATCHES "^[A-Za-z0-9._-]+$")
    message(FATAL_ERROR "hexlab_package_plugin: invalid plugin ID '${plugin_id}'")
  endif()

  set(_package_dir "${CMAKE_INSTALL_LIBDIR}/hexlab/plugins")
  set(_manifest "$<TARGET_FILE:${target}>.hexlab-plugin")
  file(GENERATE OUTPUT "${_manifest}" CONTENT
"format=hexlab-plugin-v1
id=${plugin_id}
name=${plugin_name}
version=${plugin_version}
")

  install(TARGETS "${target}"
    RUNTIME DESTINATION "${_package_dir}"
    LIBRARY DESTINATION "${_package_dir}"
    BUNDLE DESTINATION "${_package_dir}")
  install(FILES "${_manifest}" DESTINATION "${_package_dir}")
endfunction()
