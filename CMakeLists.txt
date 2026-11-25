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

add_library(rootless_native STATIC
    src/native/execute.c src/native/feasibility.c src/native/namespace.c
    src/native/rootfs.c)
target_include_directories(rootless_native PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(rootless_native PUBLIC rootless_probe)

add_library(rootless_experimental STATIC
    src/experimental/intercept.c src/experimental/vfs.c)
target_include_directories(rootless_experimental PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(rootless_experimental PUBLIC rootless_native)

add_executable(rl src/cli/main.c)
target_link_libraries(rl PRIVATE rootless_native rootless_experimental)
foreach(target IN ITEMS rootless_probe rootless_native rootless_experimental rl)
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

if(BUILD_TESTING)
    add_executable(native_tests tests/native_test.c)
    target_link_libraries(native_tests PRIVATE rootless_native)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(native_tests PRIVATE -Wall -Wextra -Wpedantic -UNDEBUG)
    endif()
    add_test(NAME native_capabilities COMMAND native_tests)
    add_test(NAME cli_native_probe COMMAND rl native-probe)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-static -no-pie")
    check_c_source_compiles("int main(void) { return 0; }" RL_STATIC_LINK_AVAILABLE)
    unset(CMAKE_REQUIRED_FLAGS)
    find_package(Python3 COMPONENTS Interpreter)
    if(RL_STATIC_LINK_AVAILABLE AND Python3_Interpreter_FOUND)
        add_executable(native_fixture tests/native_fixture.c)
        target_compile_options(native_fixture PRIVATE -fno-pie)
        target_link_options(native_fixture PRIVATE -static -no-pie)
        add_executable(dynamic_fixture tests/native_fixture.c)
        target_compile_options(dynamic_fixture PRIVATE -fno-pie)
        target_link_options(dynamic_fixture PRIVATE -no-pie)
        add_test(NAME native_execution COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/tests/native_test.py $<TARGET_FILE:rl>
            $<TARGET_FILE:native_fixture> $<TARGET_FILE:dynamic_fixture>)
        add_executable(intercept_fixture tests/intercept_fixture.c)
        target_compile_options(intercept_fixture PRIVATE -fno-pie)
        target_link_options(intercept_fixture PRIVATE -static -no-pie)
        add_test(NAME seccomp_user_notif_intercept COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/tests/intercept_test.py $<TARGET_FILE:rl>
            $<TARGET_FILE:intercept_fixture>)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            add_executable(vfs_fixture tests/vfs_fixture.c)
            target_compile_options(vfs_fixture PRIVATE -fno-pie -Wall -Wextra -Wpedantic)
            target_link_options(vfs_fixture PRIVATE -static -no-pie)
            add_test(NAME experimental_vfs COMMAND ${Python3_EXECUTABLE}
                ${PROJECT_SOURCE_DIR}/tests/vfs_smoke.py $<TARGET_FILE:rl>
                $<TARGET_FILE:vfs_fixture> --allow-unavailable)
            set_tests_properties(experimental_vfs PROPERTIES SKIP_RETURN_CODE 77)
        endif()
    else()
        message(WARNING "Static native execution and interception tests NOT_RUN: static libc or Python3 unavailable")
    endif()
endif()
