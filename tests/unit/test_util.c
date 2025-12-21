/*
 * Unit tests for src/util.c
 *
 * Tests utility functions from the sniffdet CLI.
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

#include "util.h"

/*
 * Helper: Create a temporary file with given content
 */
static FILE *create_temp_file(const char *content)
{
    FILE *f = tmpfile();
    if (f && content) {
        fputs(content, f);
        rewind(f);
    }
    return f;
}

/*
 * Test: parse_targets_file() with simple hostnames
 */
static void test_parse_targets_simple(void **state)
{
    (void)state;

    FILE *f = create_temp_file("host1\nhost2\nhost3\n");
    assert_non_null(f);

    char **result = parse_targets_file(f);
    fclose(f);

    assert_non_null(result);
    assert_string_equal(result[0], "host1");
    assert_string_equal(result[1], "host2");
    assert_string_equal(result[2], "host3");
    assert_null(result[3]);

    free_stringlist(result);
}

/*
 * Test: parse_targets_file() skips comments
 */
static void test_parse_targets_comments(void **state)
{
    (void)state;

    FILE *f = create_temp_file("# This is a comment\nhost1\n# Another comment\nhost2\n");
    assert_non_null(f);

    char **result = parse_targets_file(f);
    fclose(f);

    assert_non_null(result);
    assert_string_equal(result[0], "host1");
    assert_string_equal(result[1], "host2");
    assert_null(result[2]);

    free_stringlist(result);
}

/*
 * Test: parse_targets_file() skips empty lines
 */
static void test_parse_targets_empty_lines(void **state)
{
    (void)state;

    FILE *f = create_temp_file("host1\n\nhost2\n\n\nhost3\n");
    assert_non_null(f);

    char **result = parse_targets_file(f);
    fclose(f);

    assert_non_null(result);
    assert_string_equal(result[0], "host1");
    assert_string_equal(result[1], "host2");
    assert_string_equal(result[2], "host3");
    assert_null(result[3]);

    free_stringlist(result);
}

/*
 * Test: parse_targets_file() with empty file
 */
static void test_parse_targets_empty_file(void **state)
{
    (void)state;

    FILE *f = create_temp_file("");
    assert_non_null(f);

    char **result = parse_targets_file(f);
    fclose(f);

    assert_non_null(result);
    assert_null(result[0]);  /* Empty list, NULL terminated */

    free_stringlist(result);
}

/*
 * Test: parse_targets_file() with IP addresses
 */
static void test_parse_targets_ip_addresses(void **state)
{
    (void)state;

    FILE *f = create_temp_file("192.168.1.1\n10.0.0.1\n172.16.0.1\n");
    assert_non_null(f);

    char **result = parse_targets_file(f);
    fclose(f);

    assert_non_null(result);
    assert_string_equal(result[0], "192.168.1.1");
    assert_string_equal(result[1], "10.0.0.1");
    assert_string_equal(result[2], "172.16.0.1");
    assert_null(result[3]);

    free_stringlist(result);
}

/*
 * Test: free_stringlist() with empty list
 */
static void test_free_stringlist_empty(void **state)
{
    (void)state;

    char **list = malloc(sizeof(char *));
    assert_non_null(list);
    list[0] = NULL;

    /* Should not crash */
    int result = free_stringlist(list);
    assert_int_equal(result, 0);
}

/*
 * Test: free_stringlist() with single element
 */
static void test_free_stringlist_single(void **state)
{
    (void)state;

    char **list = malloc(sizeof(char *) * 2);
    assert_non_null(list);
    list[0] = strdup("test");
    list[1] = NULL;

    int result = free_stringlist(list);
    assert_int_equal(result, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_targets_simple),
        cmocka_unit_test(test_parse_targets_comments),
        cmocka_unit_test(test_parse_targets_empty_lines),
        cmocka_unit_test(test_parse_targets_empty_file),
        cmocka_unit_test(test_parse_targets_ip_addresses),
        cmocka_unit_test(test_free_stringlist_empty),
        cmocka_unit_test(test_free_stringlist_single),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
