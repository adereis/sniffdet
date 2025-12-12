# libsniffdet - Remote sniffer detection library

set(LIBSNIFFDET_SOURCES
    arptest.c
    dnstest.c
    icmptest.c
    latencytest.c
    helpers.c
    ping.c
    init.c
)

set(LIBSNIFFDET_HEADERS
    libsniffdet.h
)

# Build as shared library (like the original libtool .la)
add_library(sniffdet_lib SHARED
    ${LIBSNIFFDET_SOURCES}
    ${LIBSNIFFDET_HEADERS}
)

# Output name: libsniffdet.so (not libsniffdet_lib.so)
set_target_properties(sniffdet_lib PROPERTIES
    OUTPUT_NAME sniffdet
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Include directories
target_include_directories(sniffdet_lib
    PUBLIC
        # Consumers need the public header
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        # Internal: pcap headers
        ${PCAP_INCLUDE_DIR}
)

# Link dependencies
target_link_libraries(sniffdet_lib
    PUBLIC
        # Consumers linking to libsniffdet also need pthreads
        Threads::Threads
    PRIVATE
        # Internal implementation details
        libnet
        ${PCAP_LIBRARY}
        ${DL_LIBRARY}
)

# Install the library and header
include(GNUInstallDirs)

install(TARGETS sniffdet_lib
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${LIBSNIFFDET_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
