# libnet 1.0.2a - Vendored build via CMake
#
# This replaces the original autotools build for this ancient library.
# libnet 1.0 is incompatible with libnet 1.1+ and no longer available
# in modern distributions, so we vendor it.

# Detect endianness
include(TestBigEndian)
test_big_endian(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
    set(LIBNET_BIG_ENDIAN 1)
else()
    set(LIBNET_LIL_ENDIAN 1)
endif()

# Detect available headers
include(CheckIncludeFile)
check_include_file(net/ethernet.h HAVE_NET_ETHERNET_H)
check_include_file(sys/bufmod.h HAVE_SYS_BUFMOD_H)
check_include_file(sys/dlpi_ext.h HAVE_SYS_DLPI_EXT_H)
check_include_file(sys/sockio.h HAVE_SYS_SOCKIO_H)

# Detect available functions
include(CheckFunctionExists)
check_function_exists(strerror HAVE_STRERROR)

# Platform-specific configuration
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Linux uses PF_PACKET sockets (since kernel 2.2)
    set(HAVE_PF_PACKET 1)
    set(LINK_LAYER_SOURCE src/libnet_link_sockpacket.c)
    # Modern glibc needs these for BSD-style struct definitions
    set(__FAVOR_BSD 1)

elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD|OpenBSD|NetBSD|DragonFly")
    # BSDs use BPF (Berkeley Packet Filter)
    set(LIBNET_BSDISH_OS 1)
    set(LIBNET_BSD_BYTE_SWAP 1)
    set(HAVE_SOCKADDR_SA_LEN 1)
    set(LINK_LAYER_SOURCE src/libnet_link_bpf.c)

elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # macOS also uses BPF
    set(LIBNET_BSDISH_OS 1)
    set(HAVE_SOCKADDR_SA_LEN 1)
    set(LINK_LAYER_SOURCE src/libnet_link_bpf.c)

elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    # Solaris uses DLPI
    set(HAVE_SOLARIS 1)
    set(HAVE_DLPI 1)
    set(STUPID_SOLARIS_CHECKSUM_BUG 1)
    set(LINK_LAYER_SOURCE src/libnet_link_dlpi.c)

else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

# We have libpcap (required by parent project)
set(HAVE_LIB_PCAP 1)

# Generate version.h (the original Makefile did this from VERSION file)
# Put it in source tree since source files include "../version.h"
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/VERSION LIBNET_VERSION)
string(STRIP "${LIBNET_VERSION}" LIBNET_VERSION)
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/version.h
    "#define VERSION \"${LIBNET_VERSION}\"\n"
)

# Source files (matches original Makefile.in OBJECTS list)
set(LIBNET_SOURCES
    src/libnet_resolve.c
    src/libnet_socket.c
    src/libnet_checksum.c
    src/libnet_prand.c
    src/libnet_version.c
    src/libnet_write_ip.c
    src/libnet_insert_ipo.c
    src/libnet_insert_tcpo.c
    src/libnet_error.c
    src/libnet_packet_mem.c
    src/libnet_build_ip.c
    src/libnet_build_tcp.c
    src/libnet_build_udp.c
    src/libnet_build_arp.c
    src/libnet_build_ethernet.c
    src/libnet_build_icmp.c
    src/libnet_build_igmp.c
    src/libnet_build_dns.c
    src/libnet_build_snmp.c
    src/libnet_build_rip.c
    src/libnet_build_ospf.c
    src/libnet_build_vrrp.c
    src/libnet_asn1.c
    src/libnet_hex_dump.c
    src/libnet_if_addr.c
    src/libnet_port_list.c
    # Platform-specific link layer implementation
    ${LINK_LAYER_SOURCE}
)

# Build as a static library (internal use only, not installed)
add_library(libnet STATIC ${LIBNET_SOURCES})

# Enable Position Independent Code - required for linking into shared libraries on x86_64
set_target_properties(libnet PROPERTIES POSITION_INDEPENDENT_CODE ON)

# The library is named "libnet" but CMake would produce "liblibnet.a"
# Set OUTPUT_NAME to get "libnet.a"
set_target_properties(libnet PROPERTIES OUTPUT_NAME net)

# Include directories:
# - Generated config.h is in binary dir
# - Original headers are in source include/
target_include_directories(libnet
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/libnet
    PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}
)

# Pass configuration as compiler definitions (like the original -D flags)
# PUBLIC: endianness and header detection needed by anyone including libnet.h
# PRIVATE: internal implementation details
target_compile_definitions(libnet
    PUBLIC
        $<$<BOOL:${LIBNET_BIG_ENDIAN}>:LIBNET_BIG_ENDIAN=1>
        $<$<BOOL:${LIBNET_LIL_ENDIAN}>:LIBNET_LIL_ENDIAN=1>
        $<$<BOOL:${HAVE_NET_ETHERNET_H}>:HAVE_NET_ETHERNET_H=1>
        $<$<BOOL:${HAVE_SYS_SOCKIO_H}>:HAVE_SYS_SOCKIO_H=1>
        $<$<BOOL:${__FAVOR_BSD}>:__FAVOR_BSD=1>
        $<$<BOOL:${LIBNET_BSDISH_OS}>:LIBNET_BSDISH_OS=1>
        $<$<BOOL:${HAVE_SOCKADDR_SA_LEN}>:HAVE_SOCKADDR_SA_LEN=1>
    PRIVATE
        $<$<BOOL:${HAVE_PF_PACKET}>:HAVE_PF_PACKET=1>
        $<$<BOOL:${HAVE_SOLARIS}>:HAVE_SOLARIS=1>
        $<$<BOOL:${HAVE_STRERROR}>:HAVE_STRERROR=1>
)

# Suppress warnings in this legacy code - it's vendored and we won't fix it
target_compile_options(libnet PRIVATE
    -Wno-all
    -Wno-extra
    -Wno-pointer-sign
    -Wno-address-of-packed-member
    -Wno-stringop-truncation
)

# This is legacy C code, allow older standards
set_target_properties(libnet PROPERTIES
    C_STANDARD 90
    C_STANDARD_REQUIRED OFF
)
