execute_process(COMMAND "${POWERSHELL}" -NoProfile -File "${CMAKE_CURRENT_LIST_DIR}/project_save_crash_tests.ps1"
  -Helper "${HELPER}" -FixtureDirectory "${FIXTURES}" RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 110)
if(NOT "${result}" STREQUAL "0")
  message(FATAL_ERROR "Project publication/lease recovery failed: ${result}\n${output}\n${error}")
endif()
