# Test infrastructure for sniffdet
#
# Uses CMocka for unit testing.
# Hybrid approach: use system package if available, otherwise download via FetchContent.

include(FetchContent)

# Try to find system CMocka first
find_package(cmocka 1.1.5 QUIET)

if(cmocka_FOUND)
    message(STATUS "Found system CMocka: ${cmocka_VERSION}")
else()
    message(STATUS "CMocka not found on system, downloading...")
    FetchContent_Declare(
        cmocka
        GIT_REPOSITORY https://gitlab.com/cmocka/cmocka.git
        GIT_TAG        cmocka-1.1.7
        GIT_SHALLOW    TRUE
    )
    # CMocka build options - we only need the library, not examples/docs
    set(WITH_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "" FORCE)
    set(UNIT_TESTING OFF CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(cmocka)
endif()

# Helper function to add a unit test
# Usage: sniffdet_add_test(test_name source1.c source2.c ...)
function(sniffdet_add_test TEST_NAME)
    add_executable(${TEST_NAME} ${ARGN})
    target_link_libraries(${TEST_NAME}
        PRIVATE
            cmocka::cmocka
            sniffdet_lib
            libnet  # Need libnet for compile definitions (endianness, etc.)
    )
    target_include_directories(${TEST_NAME}
        PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/lib
    )
    # Register with CTest
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})

    # Set test properties for better output
    set_tests_properties(${TEST_NAME} PROPERTIES
        TIMEOUT 30
        ENVIRONMENT "CMOCKA_MESSAGE_OUTPUT=STDOUT"
    )
endfunction()

# Add unit tests subdirectory
add_subdirectory(unit)
