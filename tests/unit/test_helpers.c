/*
 * Unit tests for src/lib/helpers.c
 *
 * Tests helper functions from libsniffdet.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <limits.h>
#include <cmocka.h>

#include <time.h>
#include <sys/time.h>

#include "libsniffdet.h"

/*
 * Test: sndet_random() produces different values on successive calls
 *
 * This test will FAIL with the current implementation because
 * sndet_random() re-seeds with time(NULL) on every call.
 * Two calls in the same second produce the same "random" value.
 */
static void test_sndet_random_produces_different_values(void **state)
{
    (void)state;

    int val1 = sndet_random();
    int val2 = sndet_random();
    int val3 = sndet_random();

    /* At minimum, consecutive calls should produce different values */
    assert_true(val1 != val2 || val2 != val3);
}

/*
 * Test: sndet_random() returns values in expected range
 */
static void test_sndet_random_range(void **state)
{
    (void)state;

    for (int i = 0; i < 100; i++) {
        int val = sndet_random();
        assert_true(val >= 0);
        assert_true(val < INT_MAX);
    }
}

/*
 * Test: sndet_sleep() sleeps for approximately the requested time
 */
static void test_sndet_sleep_timing(void **state)
{
    (void)state;

    struct timeval start, end;
    long elapsed_usec;

    /* Sleep for 50ms */
    gettimeofday(&start, NULL);
    sndet_sleep(0, 50000);
    gettimeofday(&end, NULL);

    elapsed_usec = (end.tv_sec - start.tv_sec) * 1000000 +
                   (end.tv_usec - start.tv_usec);

    /* Should be at least 50ms (50000 usec) */
    assert_true(elapsed_usec >= 50000);

    /* Should be less than 100ms (allow for scheduling delays) */
    assert_true(elapsed_usec < 100000);
}

/*
 * Test: sndet_sleep() with zero time returns immediately
 */
static void test_sndet_sleep_zero(void **state)
{
    (void)state;

    struct timeval start, end;
    long elapsed_usec;

    gettimeofday(&start, NULL);
    sndet_sleep(0, 0);
    gettimeofday(&end, NULL);

    elapsed_usec = (end.tv_sec - start.tv_sec) * 1000000 +
                   (end.tv_usec - start.tv_usec);

    /* Should return almost immediately (< 10ms) */
    assert_true(elapsed_usec < 10000);
}

/*
 * Test: sndet_resolve() with invalid hostname returns 0
 */
static void test_sndet_resolve_invalid(void **state)
{
    (void)state;

    /* This should fail to resolve and return 0 */
    u_long result = sndet_resolve("this.hostname.definitely.does.not.exist.invalid");

    assert_int_equal(result, 0);
}

/*
 * Test: sndet_resolve() with localhost
 */
static void test_sndet_resolve_localhost(void **state)
{
    (void)state;

    u_long result = sndet_resolve("127.0.0.1");

    /* 127.0.0.1 in network byte order */
    assert_int_not_equal(result, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sndet_random_produces_different_values),
        cmocka_unit_test(test_sndet_random_range),
        cmocka_unit_test(test_sndet_sleep_timing),
        cmocka_unit_test(test_sndet_sleep_zero),
        cmocka_unit_test(test_sndet_resolve_invalid),
        cmocka_unit_test(test_sndet_resolve_localhost),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
