# Unit tests for sniffdet

# Test for helper functions (sndet_random, sndet_sleep, etc.)
sniffdet_add_test(test_helpers test_helpers.c)

# Test for utility functions (parse_targets_file, etc.)
# These need CLI sources since util.c is part of CLI, not library
add_executable(test_util test_util.c
    ${CMAKE_SOURCE_DIR}/src/util.c
)
target_link_libraries(test_util
    PRIVATE
        cmocka::cmocka
)
target_include_directories(test_util
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME test_util COMMAND test_util)
set_tests_properties(test_util PROPERTIES
    TIMEOUT 30
    ENVIRONMENT "CMOCKA_MESSAGE_OUTPUT=STDOUT"
)
