// SPDX-License-Identifier: GPL-2.0-only

#ifndef SNIFFDET_H
#define SNIFFDET_H

#include <stdint.h>
#include <limits.h>

#ifndef __LIBNET_H
#include <libnet.h>
#endif

/* comand line arguments
 * Notice that some comand line arguments are part of
 * global_options structure. The ones here are not
 * configuration options.
 */
struct arguments {
	const char *prgname;
	const char *configfile;
	const char *targetsfile;
	const char *target;
};

/* struct with general options
 * They're read from config file or came from comand line
 * arguments
 */
#define MAX_CFG_VAR_SIZE 128        // Short strings (interface names, IPs)
#define MAX_PATH_SIZE PATH_MAX      // Filesystem paths

/* if you change some type here, remember
 * to also change the handler for the config file..
 * *really* weird things can happen if you forget that because of the
 * variable's size
 *
 * You have been warned :-)
 */
struct config_options {
	// global options
	struct {
		int verbose;
		int silent;
		unsigned int logtype;
		char logfile_path[MAX_PATH_SIZE];
		char plugins_dir[MAX_PATH_SIZE];
		char plugin[MAX_CFG_VAR_SIZE];      // just filename, not full path
		int UID;
		int GID;
		char iface[MAX_CFG_VAR_SIZE];
		uint8_t fake_hwaddr[6];
		char fake_ipaddr[MAX_CFG_VAR_SIZE]; // string form for inet_addr()
	} global;

	// icmptest options
	struct {
		char iface[MAX_CFG_VAR_SIZE];
		int timeout;
		int tries;
		int interval;
		uint8_t fake_hwaddr[6];
	} icmptest;

	// arptest options
	struct {
		char iface[MAX_CFG_VAR_SIZE];
		int timeout;
		int tries;
		int interval;
		uint8_t fake_hwaddr[6];
	} arptest;

	// dnstest options
	struct {
		char iface[MAX_CFG_VAR_SIZE];
		int timeout;
		int tries;
		int interval;
		uint16_t dport;
		uint16_t sport;
		uint8_t fake_hwaddr[6];
		char fake_ipaddr[MAX_CFG_VAR_SIZE]; // string form for inet_addr()
		uint8_t *payload;
		uint16_t payload_len;
	} dnstest;

	// latencytest options
	struct {
		char iface[MAX_CFG_VAR_SIZE];
		int timeout;
		int probe_interval;
		unsigned int tcpflags;
	} latencytest;

	// plugins options
	struct {
		struct {
			char output_path[MAX_PATH_SIZE];
		} xml;
	} plugins;
};

/* TCP Flags that we use
 * We wrapp the libnet definitions here
 */
#define TCP_FLAG__SYN    TH_SYN
#define TCP_FLAG__FIN    TH_FIN
#define TCP_FLAG__RST    TH_RST
#define TCP_FLAG__PUSH   TH_PUSH
#define TCP_FLAG__ACK    TH_ACK
#define TCP_FLAG__URG    TH_URG

// tests to run
// 1 --> run
// 0 --> don't run :)
struct snd_tests {
	short int dnstest;
	short int icmptest;
	short int arptest;
	short int latencytest;
};

int read_config(const char *filename);

#endif // SNIFFDET_H
