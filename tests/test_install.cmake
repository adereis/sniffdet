# Test that cmake --install --prefix works correctly
#
# This test verifies that:
# 1. All expected files are installed
# 2. The pkg-config file uses the correct (overridden) prefix
#
# Run with: ctest -R install_prefix

cmake_minimum_required(VERSION 3.20)

# Get paths from environment (set by CTest)
set(BUILD_DIR "$ENV{BUILD_DIR}")
set(SOURCE_DIR "$ENV{SOURCE_DIR}")

if(NOT BUILD_DIR OR NOT SOURCE_DIR)
    message(FATAL_ERROR "BUILD_DIR and SOURCE_DIR must be set")
endif()

# Create a temporary install directory
set(INSTALL_PREFIX "${BUILD_DIR}/test_install_prefix")
file(REMOVE_RECURSE "${INSTALL_PREFIX}")
file(MAKE_DIRECTORY "${INSTALL_PREFIX}")

# Run cmake --install with custom prefix
execute_process(
    COMMAND ${CMAKE_COMMAND} --install "${BUILD_DIR}" --prefix "${INSTALL_PREFIX}"
    RESULT_VARIABLE install_result
    OUTPUT_VARIABLE install_output
    ERROR_VARIABLE install_error
)

if(NOT install_result EQUAL 0)
    message(FATAL_ERROR "Install failed:\n${install_output}\n${install_error}")
endif()

# Verify expected files exist
set(EXPECTED_FILES
    "sbin/sniffdet"
    "lib64/libsniffdet.so"
    "lib64/pkgconfig/libsniffdet.pc"
    "include/libsniffdet.h"
    "etc/sniffdet.conf"
    "share/man/man1/sniffdet.1"
)

foreach(file ${EXPECTED_FILES})
    if(NOT EXISTS "${INSTALL_PREFIX}/${file}")
        message(FATAL_ERROR "Expected file not installed: ${file}")
    endif()
endforeach()

message(STATUS "All expected files installed successfully")

# Verify pkg-config file has correct prefix
file(READ "${INSTALL_PREFIX}/lib64/pkgconfig/libsniffdet.pc" pc_content)

# Check that the prefix line contains our custom install path
string(FIND "${pc_content}" "prefix=${INSTALL_PREFIX}" prefix_found)
if(prefix_found EQUAL -1)
    message(FATAL_ERROR
        "pkg-config file does not contain correct prefix.\n"
        "Expected: prefix=${INSTALL_PREFIX}\n"
        "Content:\n${pc_content}"
    )
endif()

# Check that libdir contains our custom install path
string(FIND "${pc_content}" "libdir=${INSTALL_PREFIX}" libdir_found)
if(libdir_found EQUAL -1)
    message(FATAL_ERROR
        "pkg-config file does not contain correct libdir.\n"
        "Expected libdir to start with: ${INSTALL_PREFIX}\n"
        "Content:\n${pc_content}"
    )
endif()

message(STATUS "pkg-config file has correct prefix")

# Cleanup
file(REMOVE_RECURSE "${INSTALL_PREFIX}")

message(STATUS "Install prefix test PASSED")
