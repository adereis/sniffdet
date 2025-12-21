/*
 * Unit tests for src/log.c
 *
 * Tests the mylog() logging function which can output to multiple
 * destinations: file, stdout, stderr, and syslog.
 *
 * Testing approach:
 * - FILE output: write to temp file, verify contents
 * - STDOUT/STDERR: redirect to temp file using dup2(), capture and verify
 * - SYSLOG: not tested (would require mocking or parsing system logs)
 *
 * The dup2() technique for capturing stdout/stderr is a classic Unix
 * testing pattern that works without modifying the code under test.
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
#include <fcntl.h>

#include "log.h"

/*
 * Helper: Create a temporary file and return its fd and path.
 * Caller must close fd and unlink path when done.
 */
static int create_temp_file(char *path_out, size_t path_size)
{
    snprintf(path_out, path_size, "/tmp/sniffdet_log_test_XXXXXX");
    int fd = mkstemp(path_out);
    return fd;
}

/*
 * Helper: Read entire file contents into a buffer.
 * Returns allocated buffer (caller must free) or NULL on error.
 */
static char *read_file_contents(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read_size = fread(buf, 1, size, f);
    buf[read_size] = '\0';
    fclose(f);

    return buf;
}

/*
 * Test: LOG_USE_FILE writes message with timestamp to file
 */
static void test_log_to_file(void **state)
{
    (void)state;

    char path[256];
    int fd = create_temp_file(path, sizeof(path));
    assert_true(fd >= 0);

    int result = mylog(LOG_USE_FILE, fd, "Test message %d", 42);
    assert_int_equal(result, 0);

    /* Ensure data is flushed */
    fsync(fd);
    close(fd);

    char *contents = read_file_contents(path);
    unlink(path);

    assert_non_null(contents);
    /* File output includes timestamp like "[Mon Dec 20 14:30:42]: Test message 42\n" */
    assert_non_null(strstr(contents, "Test message 42"));
    assert_non_null(strstr(contents, "]:"));  /* Part of timestamp format */

    free(contents);
}

/*
 * Test: LOG_USE_FILE with fd=-1 returns error
 */
static void test_log_to_file_invalid_fd(void **state)
{
    (void)state;

    int result = mylog(LOG_USE_FILE, -1, "This should fail");
    assert_int_equal(result, -1);
}

/*
 * Test: LOG_USE_STDOUT writes message to stdout (no timestamp)
 */
static void test_log_to_stdout(void **state)
{
    (void)state;

    char path[256];
    int temp_fd = create_temp_file(path, sizeof(path));
    assert_true(temp_fd >= 0);

    /* Save original stdout */
    int saved_stdout = dup(STDOUT_FILENO);
    assert_true(saved_stdout >= 0);

    /* Redirect stdout to temp file */
    int dup_result = dup2(temp_fd, STDOUT_FILENO);
    assert_true(dup_result >= 0);

    /* Call mylog - this writes to our temp file now */
    int result = mylog(LOG_USE_STDOUT, -1, "Stdout test %s", "hello");
    assert_int_equal(result, 0);

    /* Restore stdout */
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);

    /* Read captured output */
    fsync(temp_fd);
    close(temp_fd);

    char *contents = read_file_contents(path);
    unlink(path);

    assert_non_null(contents);
    assert_non_null(strstr(contents, "Stdout test hello"));
    /* stdout output should NOT have timestamp */
    assert_null(strstr(contents, "]:"));

    free(contents);
}

/*
 * Test: LOG_USE_STDERR writes message to stderr (no timestamp)
 */
static void test_log_to_stderr(void **state)
{
    (void)state;

    char path[256];
    int temp_fd = create_temp_file(path, sizeof(path));
    assert_true(temp_fd >= 0);

    /* Save original stderr */
    int saved_stderr = dup(STDERR_FILENO);
    assert_true(saved_stderr >= 0);

    /* Redirect stderr to temp file */
    int dup_result = dup2(temp_fd, STDERR_FILENO);
    assert_true(dup_result >= 0);

    /* Call mylog */
    int result = mylog(LOG_USE_STDERR, -1, "Stderr test %d", 123);
    assert_int_equal(result, 0);

    /* Restore stderr */
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);

    /* Read captured output */
    fsync(temp_fd);
    close(temp_fd);

    char *contents = read_file_contents(path);
    unlink(path);

    assert_non_null(contents);
    assert_non_null(strstr(contents, "Stderr test 123"));
    /* stderr output should NOT have timestamp */
    assert_null(strstr(contents, "]:"));

    free(contents);
}

/*
 * Test: Multiple flags - LOG_USE_FILE | LOG_USE_STDERR writes to both
 *
 * This verifies that the OR'd flags work independently and the message
 * appears in both destinations.
 */
static void test_log_to_multiple_destinations(void **state)
{
    (void)state;

    /* Create temp file for LOG_USE_FILE */
    char file_path[256];
    int file_fd = create_temp_file(file_path, sizeof(file_path));
    assert_true(file_fd >= 0);

    /* Create temp file to capture stderr */
    char stderr_path[256];
    int stderr_temp_fd = create_temp_file(stderr_path, sizeof(stderr_path));
    assert_true(stderr_temp_fd >= 0);

    /* Save and redirect stderr */
    int saved_stderr = dup(STDERR_FILENO);
    assert_true(saved_stderr >= 0);
    dup2(stderr_temp_fd, STDERR_FILENO);

    /* Call mylog with both flags */
    int result = mylog(LOG_USE_FILE | LOG_USE_STDERR, file_fd, "Multi dest test");
    assert_int_equal(result, 0);

    /* Restore stderr */
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);

    /* Read and verify file output */
    fsync(file_fd);
    close(file_fd);
    char *file_contents = read_file_contents(file_path);
    unlink(file_path);

    assert_non_null(file_contents);
    assert_non_null(strstr(file_contents, "Multi dest test"));
    assert_non_null(strstr(file_contents, "]:"));  /* Has timestamp */

    /* Read and verify stderr output */
    fsync(stderr_temp_fd);
    close(stderr_temp_fd);
    char *stderr_contents = read_file_contents(stderr_path);
    unlink(stderr_path);

    assert_non_null(stderr_contents);
    assert_non_null(strstr(stderr_contents, "Multi dest test"));
    assert_null(strstr(stderr_contents, "]:"));  /* No timestamp */

    free(file_contents);
    free(stderr_contents);
}

/*
 * Test: LOG_NOLOG does nothing
 */
static void test_log_nolog(void **state)
{
    (void)state;

    /* With NOLOG, nothing should be written anywhere */
    int result = mylog(LOG_NOLOG, -1, "This goes nowhere");
    assert_int_equal(result, 0);
}

/*
 * Test: Format string with multiple arguments
 */
static void test_log_format_string(void **state)
{
    (void)state;

    char path[256];
    int fd = create_temp_file(path, sizeof(path));
    assert_true(fd >= 0);

    int result = mylog(LOG_USE_FILE, fd, "Values: %d, %s, %.2f", 42, "hello", 3.14);
    assert_int_equal(result, 0);

    fsync(fd);
    close(fd);

    char *contents = read_file_contents(path);
    unlink(path);

    assert_non_null(contents);
    assert_non_null(strstr(contents, "Values: 42, hello, 3.14"));

    free(contents);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_log_to_file),
        cmocka_unit_test(test_log_to_file_invalid_fd),
        cmocka_unit_test(test_log_to_stdout),
        cmocka_unit_test(test_log_to_stderr),
        cmocka_unit_test(test_log_to_multiple_destinations),
        cmocka_unit_test(test_log_nolog),
        cmocka_unit_test(test_log_format_string),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
