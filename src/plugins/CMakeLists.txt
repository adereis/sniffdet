# sniffdet output plugins
#
# Plugins are shared libraries loaded at runtime via dlopen().
# They implement test_output() to format/output test results.

# Common include paths for all plugins
set(PLUGIN_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/lib
    ${CMAKE_SOURCE_DIR}/third_party/libnet/include
    ${CMAKE_SOURCE_DIR}/third_party/libnet/include/libnet
)

# Helper function to create a plugin
function(sniffdet_add_plugin PLUGIN_NAME)
    add_library(${PLUGIN_NAME} MODULE ${ARGN})

    # Plugins need access to sniffdet headers
    target_include_directories(${PLUGIN_NAME} PRIVATE ${PLUGIN_INCLUDE_DIRS})

    # Link to libnet for type definitions
    target_link_libraries(${PLUGIN_NAME} PRIVATE libnet)

    # Remove 'lib' prefix - plugins should be named foo.so, not libfoo.so
    set_target_properties(${PLUGIN_NAME} PROPERTIES PREFIX "")

    # Output to plugins directory in build tree
    set_target_properties(${PLUGIN_NAME} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/src/plugins
    )
endfunction()

# Build plugins
sniffdet_add_plugin(null null.c)
sniffdet_add_plugin(stdout stdout.c)
sniffdet_add_plugin(xml xml.c)

# Install plugins
include(GNUInstallDirs)
install(TARGETS null stdout xml
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/sniffdet/plugins
)
