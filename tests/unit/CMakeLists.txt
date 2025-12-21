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

# Test for config file parser
# Needs config_file.c and its dependencies (libnet for TCP flags, etc.)
add_executable(test_config test_config.c
    ${CMAKE_SOURCE_DIR}/src/config_file.c
)
target_link_libraries(test_config
    PRIVATE
        cmocka::cmocka
        sniffdet_lib
        libnet
)
target_include_directories(test_config
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/lib
)
add_test(NAME test_config COMMAND test_config)
set_tests_properties(test_config PROPERTIES
    TIMEOUT 30
    ENVIRONMENT "CMOCKA_MESSAGE_OUTPUT=STDOUT"
)

# Test for logging module
add_executable(test_log test_log.c
    ${CMAKE_SOURCE_DIR}/src/log.c
)
target_link_libraries(test_log
    PRIVATE
        cmocka::cmocka
)
target_include_directories(test_log
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME test_log COMMAND test_log)
set_tests_properties(test_log PROPERTIES
    TIMEOUT 30
    ENVIRONMENT "CMOCKA_MESSAGE_OUTPUT=STDOUT"
)
