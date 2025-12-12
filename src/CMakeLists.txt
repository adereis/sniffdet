# sniffdet - Remote sniffer detection CLI tool

set(SNIFFDET_SOURCES
    sniffdet.c
    sniffdet.h
    log.c
    log.h
    config_file.c
    util.c
    util.h
)

add_executable(sniffdet ${SNIFFDET_SOURCES})

# Link to libsniffdet and libnet (need libnet's public defines for headers)
target_link_libraries(sniffdet
    PRIVATE
        sniffdet_lib
        libnet
)

# Need libnet headers for some type definitions used in the CLI
target_include_directories(sniffdet
    PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/libnet/include
        ${CMAKE_SOURCE_DIR}/third_party/libnet/include/libnet
        lib  # For libsniffdet.h
)

# Install the binary
include(GNUInstallDirs)

install(TARGETS sniffdet
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# Build output plugins
add_subdirectory(plugins)
