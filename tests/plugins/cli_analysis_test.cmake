execute_process(
  COMMAND "${CLI}" disassemble "${FIXTURE}" --format raw --arch x86-64 --base 0 --plugin "${PLUGIN}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "plugin CLI analysis failed (${result}): ${error}\n${output}")
endif()
if(NOT output MATCHES "plugin_nop")
  message(FATAL_ERROR "loaded processor plugin did not affect image analysis output:\n${output}")
endif()
