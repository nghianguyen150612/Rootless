cmake_minimum_required(VERSION 3.18)
project(rootless VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(rootless_probe STATIC src/probe/probe.c)
target_include_directories(rootless_probe PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

add_executable(rl src/cli/main.c)
target_link_libraries(rl PRIVATE rootless_probe)
foreach(target IN ITEMS rootless_probe rl)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endforeach()
install(TARGETS rl RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_TESTING)
    add_executable(probe_tests tests/probe_test.c)
    target_link_libraries(probe_tests PRIVATE rootless_probe)
    add_test(NAME probe_contract COMMAND probe_tests)
    add_test(NAME cli_help COMMAND rl --help)
    add_test(NAME cli_version COMMAND rl --version)
    add_test(NAME cli_probe COMMAND rl probe)
    add_test(NAME cli_unknown_exit
        COMMAND ${CMAKE_COMMAND} -DRL_BIN=$<TARGET_FILE:rl>
            -P ${PROJECT_SOURCE_DIR}/tests/cli_unknown.cmake)
endif()
