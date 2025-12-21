/*
 * Unit tests for src/config_file.c
 *
 * Tests the configuration file parser.
 *
 * Note: The config parser uses global state (static variables and extern
 * config struct), so tests must be careful about isolation. Each test
 * creates its own temporary config file and resets the config struct.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sniffdet.h"
#include "log.h"

/* The config parser writes to this global struct */
struct config_options config;

/*
 * Helper: Create a temporary file with given content and return its path.
 * Caller must free the returned path and delete the file when done.
 */
static char *create_temp_config(const char *content)
{
    char *path = strdup("/tmp/sniffdet_test_XXXXXX");
    if (!path)
        return NULL;

    int fd = mkstemp(path);
    if (fd < 0) {
        free(path);
        return NULL;
    }

    if (content) {
        size_t len = strlen(content);
        if (write(fd, content, len) != (ssize_t)len) {
            close(fd);
            unlink(path);
            free(path);
            return NULL;
        }
    }

    close(fd);
    return path;
}

/*
 * Helper: Reset config struct to known state
 */
static void reset_config(void)
{
    memset(&config, 0, sizeof(config));
}

/*
 * Setup/teardown for each test
 */
static int test_setup(void **state)
{
    (void)state;
    reset_config();
    return 0;
}

/*
 * Test: read_config() returns error for nonexistent file
 */
static void test_config_nonexistent_file(void **state)
{
    (void)state;

    int result = read_config("/nonexistent/path/sniffdet.conf");
    /* read_config returns 0 (false) when fopen fails */
    assert_int_equal(result, 0);
}

/*
 * Test: Parse minimal global section with verbose setting
 */
static void test_config_parse_global_verbose(void **state)
{
    (void)state;

    const char *content =
        "global {\n"
        "    verbose = 1;\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_int_equal(config.global.verbose, 1);
}

/*
 * Test: Parse global section with string values
 */
static void test_config_parse_global_strings(void **state)
{
    (void)state;

    const char *content =
        "global {\n"
        "    iface = \"eth1\";\n"
        "    logfilename = \"test.log\";\n"
        "    plugin = \"myplugin.so\";\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_string_equal(config.global.iface, "eth1");
    assert_string_equal(config.global.logfilename, "test.log");
    assert_string_equal(config.global.plugin, "myplugin.so");
}

/*
 * Test: Parse UID and GID values
 */
static void test_config_parse_uid_gid(void **state)
{
    (void)state;

    const char *content =
        "global {\n"
        "    UID = 1000;\n"
        "    GID = 1000;\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_int_equal(config.global.UID, 1000);
    assert_int_equal(config.global.GID, 1000);
}

/*
 * Test: Parse MAC address
 */
static void test_config_parse_mac_address(void **state)
{
    (void)state;

    const char *content =
        "global {\n"
        "    fake_hwaddr = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_int_equal(config.global.fake_hwaddr[0], 0xDE);
    assert_int_equal(config.global.fake_hwaddr[1], 0xAD);
    assert_int_equal(config.global.fake_hwaddr[2], 0xBE);
    assert_int_equal(config.global.fake_hwaddr[3], 0xEF);
    assert_int_equal(config.global.fake_hwaddr[4], 0xCA);
    assert_int_equal(config.global.fake_hwaddr[5], 0xFE);
}

/*
 * Test: Parse logtype with multiple flags
 */
static void test_config_parse_logtype_multiple(void **state)
{
    (void)state;

    const char *content =
        "global {\n"
        "    logtype = FILE,STDERR;\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    /* Both FILE and STDERR flags should be set */
    assert_true(config.global.logtype & LOG_USE_FILE);
    assert_true(config.global.logtype & LOG_USE_STDERR);
    /* STDOUT and SYSLOG should NOT be set */
    assert_false(config.global.logtype & LOG_USE_STDOUT);
    assert_false(config.global.logtype & LOG_USE_SYSLOG);
}

/*
 * Test: Parse icmptest section
 */
static void test_config_parse_icmptest(void **state)
{
    (void)state;

    const char *content =
        "icmptest {\n"
        "    timeout = 10;\n"
        "    tries = 5;\n"
        "    interval = 500;\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_int_equal(config.icmptest.timeout, 10);
    assert_int_equal(config.icmptest.tries, 5);
    assert_int_equal(config.icmptest.interval, 500);
}

/*
 * Test: Parse dnstest section with ports
 */
static void test_config_parse_dnstest_ports(void **state)
{
    (void)state;

    const char *content =
        "dnstest {\n"
        "    sport = 12345;\n"
        "    dport = 53;\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_int_equal(config.dnstest.sport, 12345);
    assert_int_equal(config.dnstest.dport, 53);
}

/*
 * Test: Parse latencytest section with tcpflags
 */
static void test_config_parse_tcpflags(void **state)
{
    (void)state;

    const char *content =
        "latencytest {\n"
        "    tcpflags = SYN,ACK;\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_true(config.latencytest.tcpflags & TCP_FLAG__SYN);
    assert_true(config.latencytest.tcpflags & TCP_FLAG__ACK);
    assert_false(config.latencytest.tcpflags & TCP_FLAG__FIN);
}

/*
 * Test: Parse plugins section
 */
static void test_config_parse_plugins(void **state)
{
    (void)state;

    const char *content =
        "plugins {\n"
        "    xmlplugin_filename = \"output.xml\";\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_string_equal(config.plugins.xml.filename, "output.xml");
}

/*
 * Test: Invalid section name causes error
 */
static void test_config_invalid_section(void **state)
{
    (void)state;

    const char *content =
        "nosuchsection {\n"
        "    foo = 1;\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    /* Should return non-zero for syntax error */
    assert_int_not_equal(result, 0);
}

/*
 * Test: Comments are properly ignored
 */
static void test_config_comments_ignored(void **state)
{
    (void)state;

    const char *content =
        "# This is a comment\n"
        "global {\n"
        "    # Another comment\n"
        "    verbose = 42;\n"
        "    # trailing comment\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_int_equal(config.global.verbose, 42);
}

/*
 * Test: Multiple sections in one file
 */
static void test_config_multiple_sections(void **state)
{
    (void)state;

    const char *content =
        "global {\n"
        "    verbose = 1;\n"
        "    iface = \"lo\";\n"
        "}\n"
        "icmptest {\n"
        "    timeout = 30;\n"
        "}\n"
        "arptest {\n"
        "    tries = 20;\n"
        "}\n";

    char *path = create_temp_config(content);
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    assert_int_equal(result, 0);
    assert_int_equal(config.global.verbose, 1);
    assert_string_equal(config.global.iface, "lo");
    assert_int_equal(config.icmptest.timeout, 30);
    assert_int_equal(config.arptest.tries, 20);
}

/*
 * Test: Empty file parses without error
 */
static void test_config_empty_file(void **state)
{
    (void)state;

    char *path = create_temp_config("");
    assert_non_null(path);

    int result = read_config(path);
    unlink(path);
    free(path);

    /* Empty file should parse successfully (no sections is valid) */
    assert_int_equal(result, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_config_nonexistent_file, test_setup),
        cmocka_unit_test_setup(test_config_parse_global_verbose, test_setup),
        cmocka_unit_test_setup(test_config_parse_global_strings, test_setup),
        cmocka_unit_test_setup(test_config_parse_uid_gid, test_setup),
        cmocka_unit_test_setup(test_config_parse_mac_address, test_setup),
        cmocka_unit_test_setup(test_config_parse_logtype_multiple, test_setup),
        cmocka_unit_test_setup(test_config_parse_icmptest, test_setup),
        cmocka_unit_test_setup(test_config_parse_dnstest_ports, test_setup),
        cmocka_unit_test_setup(test_config_parse_tcpflags, test_setup),
        cmocka_unit_test_setup(test_config_parse_plugins, test_setup),
        cmocka_unit_test_setup(test_config_invalid_section, test_setup),
        cmocka_unit_test_setup(test_config_comments_ignored, test_setup),
        cmocka_unit_test_setup(test_config_multiple_sections, test_setup),
        cmocka_unit_test_setup(test_config_empty_file, test_setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
