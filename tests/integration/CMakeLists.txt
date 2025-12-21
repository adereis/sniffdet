# Integration tests for sniffdet
#
# These tests require:
# - Root privileges (CAP_NET_ADMIN + CAP_NET_RAW)
# - Python 3.6+
# - Network namespace support
#
# Run with: sudo ctest -R integration --output-on-failure
# Or directly: sudo python3 tests/integration/run_tests.py

find_package(Python3 COMPONENTS Interpreter REQUIRED)

# Add integration test (marked as requiring root)
add_test(
    NAME integration_tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py
            --build-dir ${CMAKE_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# These tests require root/sudo, so they're labeled separately
set_tests_properties(integration_tests PROPERTIES
    LABELS "integration;requires_root"
    TIMEOUT 120  # Allow up to 2 minutes for all integration tests
    # Skip if not running as root (test will fail with clear message)
    SKIP_RETURN_CODE 77
)

# Individual test targets for convenience
add_test(
    NAME integration_icmp
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py
            --build-dir ${CMAKE_BINARY_DIR} --tests icmp
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(integration_icmp PROPERTIES
    LABELS "integration;requires_root"
    TIMEOUT 60
)

add_test(
    NAME integration_arp
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py
            --build-dir ${CMAKE_BINARY_DIR} --tests arp
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(integration_arp PROPERTIES
    LABELS "integration;requires_root"
    TIMEOUT 60
)

add_test(
    NAME integration_dns
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py
            --build-dir ${CMAKE_BINARY_DIR} --tests dns
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(integration_dns PROPERTIES
    LABELS "integration;requires_root"
    TIMEOUT 60
)
