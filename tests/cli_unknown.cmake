execute_process(COMMAND "${RL_BIN}" unknown-command
    RESULT_VARIABLE exit_code OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT exit_code STREQUAL "64")
    message(FATAL_ERROR "Expected usage exit 64, got '${exit_code}': ${err}")
endif()
execute_process(COMMAND "${RL_BIN}" run -r /tmp/nonexistent -- /bin/sh
    RESULT_VARIABLE exit_code OUTPUT_VARIABLE out ERROR_VARIABLE err)
if(NOT exit_code STREQUAL "69")
    message(FATAL_ERROR "Expected unavailable exit 69, got '${exit_code}': ${err}")
endif()
