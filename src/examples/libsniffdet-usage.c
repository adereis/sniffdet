// SPDX-License-Identifier: GPL-2.0-only
//
// libsniffdet usage example
//
// Demonstrates how to use libsniffdet to run all four detection tests.
//
// Build with:
//   gcc libsniffdet-usage.c -o example \
//       $(pkg-config --cflags --libs libsniffdet) -lpthread
//
// Run with:
//   sudo ./example <interface> <target>
//
// Example:
//   sudo ./example eth0 192.168.1.100

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <libsniffdet.h>

static volatile int cancel_test_flag;

static int tests_msg_callback(struct test_status *status,
		const int msg_type, char *msg);
static void sighandler(int sig);
static int print_test_result(char *target, struct test_info *info);
static char *timeString(time_t t);

int main(int argc, char **argv)
{
	char *iface;
	char *target;
	struct test_info t_info;
	struct sndet_device *device;
	char errbuf[LIBSNIFFDET_ERR_BUF_LEN];
	int status;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <interface> <host>\n", argv[0]);
		fprintf(stderr, "Example: %s eth0 192.168.1.100\n", argv[0]);
		exit(1);
	}
	iface = argv[1];
	target = argv[2];

	if ((device = sndet_init_device(iface, 1, errbuf)) == NULL) {
		fprintf(stderr, "Error initializing interface %s: %s\n", iface, errbuf);
		exit(1);
	}

	if (!sndet_resolve(target)) {
		fprintf(stderr, "Cannot resolve target hostname \"%s\"\n", target);
		exit(1);
	}

	// Allow SIGINT to cancel running tests
	signal(SIGINT, sighandler);

	// Run all four detection tests in sequence

	// ICMP TEST
	printf("\n=== Running ICMP Test ===\n");
	status = sndet_icmptest(target,
			device,
			20,   // timeout (secs)
			0,    // tries (0 = default)
			0,    // interval in ms (0 = default)
			tests_msg_callback,
			&t_info,
			NULL); // fake MAC (NULL = default)

	if (status == 0)
		print_test_result(target, &t_info);
	else
		fprintf(stderr, "Error running ICMP test\n");

	cancel_test_flag = 0;

	// ARP TEST
	printf("\n=== Running ARP Test ===\n");
	status = sndet_arptest(target,
			device,
			20,   // timeout (secs)
			0,    // tries
			0,    // interval in ms
			tests_msg_callback,
			&t_info,
			NULL); // fake MAC

	if (status == 0)
		print_test_result(target, &t_info);
	else
		fprintf(stderr, "Error running ARP test\n");

	cancel_test_flag = 0;

	// DNS TEST
	printf("\n=== Running DNS Test ===\n");
	status = sndet_dnstest(target,
			device,
			20,   // timeout (secs)
			0,    // tries
			0,    // interval in ms
			tests_msg_callback,
			&t_info,
			NULL, // fake IP
			NULL, // fake MAC
			0,    // destination port
			0,    // source port
			NULL, // payload
			0);   // payload length

	if (status == 0)
		print_test_result(target, &t_info);
	else
		fprintf(stderr, "Error running DNS test\n");

	cancel_test_flag = 0;

	// LATENCY TEST
	printf("\n=== Running Latency Test ===\n");
	status = sndet_latencytest_pktflood(target,
			device,
			60,   // timeout (secs) - latency test needs more time
			0,    // probe interval in ms
			tests_msg_callback,
			&t_info,
			NULL); // bogus packet info

	if (status == 0)
		print_test_result(target, &t_info);
	else
		fprintf(stderr, "Error running Latency test\n");

	if (sndet_finish_device(device, errbuf))
		fprintf(stderr, "Error closing device: %s\n", errbuf);

	return 0;
}

// Callback invoked by tests to report progress and messages
static int tests_msg_callback(struct test_status *status,
		const int msg_type, char *msg)
{
	switch (msg_type) {
		case RUNNING:
			break;
		case NOTIFICATION:
			if (msg != NULL)
				printf("  [INFO] %s\n", msg);
			break;
		case ERROR:
			if (msg != NULL)
				fprintf(stderr, "  [ERROR] %s\n", msg);
			break;
		case WARNING:
			if (msg != NULL)
				fprintf(stderr, "  [WARN] %s\n", msg);
			break;
		case DETECTION:
			printf("  [DETECTION] Promiscuous mode detected!\n");
			break;
		case ENDING:
			break;
	}

	// Progress indicator
	printf("  Progress: %d%% | Sent: %d bytes | Recv: %d bytes\r",
			status->percent, status->bytes_sent, status->bytes_recvd);
	fflush(stdout);

	// Return non-zero to cancel the test
	return cancel_test_flag ? 1 : 0;
}

// Signal handler to allow canceling tests with Ctrl+C
static void sighandler(int sig)
{
	(void)sig;
	cancel_test_flag = 1;
	printf("\nCanceling test...\n");
}

// Print test results
static int print_test_result(char *target, struct test_info *info)
{
	printf("\n");
	printf("------------------------------------------------------------\n");
	printf("Test: %s\n", info->test_name);
	printf("      %s\n", info->test_short_desc);
	printf("------------------------------------------------------------\n");
	printf("Target: %s\n", target);
	printf("Valid: %s\n", info->valid ? "Yes" : "No");
	printf("Started: %s\n", timeString(info->time_start));
	printf("Finished: %s\n", timeString(info->time_fini));
	printf("Bytes: %d sent, %d received\n", info->b_sent, info->b_recvd);
	printf("Packets: %d sent, %d received\n", info->pkts_sent, info->pkts_recvd);
	printf("------------------------------------------------------------\n");

	switch (info->code) {
		case ICMPTEST:
			printf("RESULT: %s\n",
					info->test.icmp.positive ? "POSITIVE (sniffer detected)" : "NEGATIVE");
			return info->test.icmp.positive;

		case ARPTEST:
			printf("RESULT: %s\n",
					info->test.arp.positive ? "POSITIVE (sniffer detected)" : "NEGATIVE");
			return info->test.arp.positive;

		case DNSTEST:
			printf("RESULT: %s\n",
					info->test.dns.positive ? "POSITIVE (sniffer detected)" : "NEGATIVE");
			return info->test.dns.positive;

		case LATENCYTEST:
			printf("Normal RTT: %u.%u ms\n",
					info->test.latency.normal_time / 10,
					info->test.latency.normal_time % 10);
			printf("Flood RTT (min/avg/max): %u.%u / %u.%u / %u.%u ms\n",
					info->test.latency.min_time / 10,
					info->test.latency.min_time % 10,
					info->test.latency.mean_time / 10,
					info->test.latency.mean_time % 10,
					info->test.latency.max_time / 10,
					info->test.latency.max_time % 10);
			return 0;

		default:
			printf("Unknown test type\n");
			return -1;
	}
}

// Convert time_t to human-readable string
static char *timeString(time_t t)
{
	static char buffer[64];
	struct tm *local = localtime(&t);
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", local);
	return buffer;
}
