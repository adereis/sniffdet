cmake_minimum_required(VERSION 3.31)

# Prevent in-source builds - they pollute the source tree and are hard to clean
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds are not allowed.\n"
        "Use: cmake -B build\n"
        "Remove CMakeCache.txt and CMakeFiles/ if they exist in the source directory.")
endif()

project(sniffdet
    VERSION 0.10.0
    DESCRIPTION "Remote Sniffer Detection Tool/Library"
    LANGUAGES C
)

# Use C11 as the default standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # Enable GNU extensions (legacy code needs them)

# Generate compile_commands.json for IDE/tooling support (clangd, clang-tidy, etc.)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# Build options
option(SNIFFDET_BUILD_CLI "Build the sniffdet command-line tool" ON)
option(SNIFFDET_BUILD_TESTS "Build the test suite" ON)
option(SNIFFDET_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

# Compiler warnings - strict but tolerant of legacy patterns
add_compile_options(
    -Wall
    -Wextra
    -Wno-unused-parameter      # Legacy code has many unused params in callbacks
    -Wno-missing-field-initializers
)

# Sanitizers (for development/debugging)
if(SNIFFDET_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Find required system dependencies
find_package(Threads REQUIRED)
find_library(PCAP_LIBRARY pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap.h REQUIRED)

# Check for dlopen (in libc on modern glibc, in libdl on older systems)
include(CheckLibraryExists)
check_library_exists(dl dlopen "" HAVE_LIBDL)
if(HAVE_LIBDL)
    set(DL_LIBRARY dl)
else()
    set(DL_LIBRARY "")
endif()

# We need GNUInstallDirs for standard install paths
include(GNUInstallDirs)

# Configuration options (like the old --with-uid, --with-gid, etc.)
set(SNDET_DEFAULT_UID 65534 CACHE STRING "Default UID for dropping privileges (default: nobody)")
set(SNDET_DEFAULT_GID 65534 CACHE STRING "Default GID for dropping privileges (default: nogroup)")

# Path defaults: Debug builds use source/build directories for convenience,
# Release builds use standard install paths.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Development mode: run directly from build directory
    set(SNDET_PLUGINSDIR "${CMAKE_BINARY_DIR}/src/plugins"
        CACHE PATH "Directory for sniffdet plugins")
    set(SNDET_CONFIG "${CMAKE_SOURCE_DIR}/sniffdet.conf-debug"
        CACHE PATH "Default configuration file path")
else()
    # Install mode: standard FHS paths
    set(SNDET_PLUGINSDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/sniffdet/plugins"
        CACHE PATH "Directory for sniffdet plugins")
    set(SNDET_CONFIG "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/sniffdet.conf"
        CACHE PATH "Default configuration file path")
endif()

# Generate config.h from template
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
    @ONLY
)

# Generate pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/libsniffdet.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/libsniffdet.pc
    @ONLY
)

# Generate default config file (for installation)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sniffdet.conf.in
    ${CMAKE_CURRENT_BINARY_DIR}/sniffdet.conf
    @ONLY
)

# Make generated config.h available to all targets
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Build vendored libnet 1.0
add_subdirectory(third_party/libnet)

# Build libsniffdet
add_subdirectory(src/lib)

# Build sniffdet CLI
if(SNIFFDET_BUILD_CLI)
    add_subdirectory(src)
endif()

# Build tests
if(SNIFFDET_BUILD_TESTS)
    enable_testing()  # Must be in root CMakeLists.txt for CTest to find tests
    add_subdirectory(tests)
endif()

# Installation rules
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsniffdet.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sniffdet.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
    RENAME sniffdet.conf)

# Man pages
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/man/sniffdet.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/man/libsniffdet.3
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/man/sniffdet.conf.5
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)

# Configuration summary (like the old configure script output)
message(STATUS "")
message(STATUS "sniffdet ${PROJECT_VERSION} configuration:")
message(STATUS "  Build type:      ${CMAKE_BUILD_TYPE}")
message(STATUS "  C compiler:      ${CMAKE_C_COMPILER}")
message(STATUS "  C standard:      C${CMAKE_C_STANDARD}")
message(STATUS "  Sanitizers:      ${SNIFFDET_ENABLE_SANITIZERS}")
message(STATUS "  Build CLI:       ${SNIFFDET_BUILD_CLI}")
message(STATUS "  Build tests:     ${SNIFFDET_BUILD_TESTS}")
message(STATUS "")
