add_library(hexlab_sdk_example MODULE example_plugin.c)
target_link_libraries(hexlab_sdk_example PRIVATE hexlab::plugin_sdk)
set_target_properties(hexlab_sdk_example PROPERTIES PREFIX "")
add_library(hexlab_sdk_legacy_example MODULE legacy_plugin.c)
target_link_libraries(hexlab_sdk_legacy_example PRIVATE hexlab::plugin_sdk)
set_target_properties(hexlab_sdk_legacy_example PROPERTIES PREFIX "")
foreach(stage IN ITEMS 1 2 3)
  add_library(hexlab_sdk_throw_stage${stage} MODULE throwing_plugin.cpp)
  target_link_libraries(hexlab_sdk_throw_stage${stage} PRIVATE hexlab::plugin_sdk)
  target_compile_definitions(hexlab_sdk_throw_stage${stage} PRIVATE HEXLAB_THROW_STAGE=${stage})
  set_target_properties(hexlab_sdk_throw_stage${stage} PROPERTIES PREFIX "")
endforeach()
add_executable(hexlab_sdk_tests sdk_tests.cpp)
target_link_libraries(hexlab_sdk_tests PRIVATE hexlab::plugins hexlab::automation)
add_dependencies(hexlab_sdk_tests hexlab_sdk_example hexlab_sdk_legacy_example
  hexlab_sdk_throw_stage1 hexlab_sdk_throw_stage2 hexlab_sdk_throw_stage3)
add_test(NAME plugin_sdk COMMAND hexlab_sdk_tests "$<TARGET_FILE:hexlab_sdk_example>"
  "$<TARGET_FILE:hexlab_sdk_legacy_example>" "$<TARGET_FILE:hexlab_sdk_throw_stage1>"
  "$<TARGET_FILE:hexlab_sdk_throw_stage2>" "$<TARGET_FILE:hexlab_sdk_throw_stage3>")
if(HEXLAB_PLUGINS_STANDALONE)
  add_custom_command(TARGET hexlab_sdk_tests POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_core>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_image>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_loaders>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_database>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_sqlite3>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_processors>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_types>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_analysis>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_workspace>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_automation>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:hexlab_plugins>" "$<TARGET_FILE_DIR:hexlab_sdk_tests>")
endif()
