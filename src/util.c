// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "util.h"

/* drop root privileges, if they found a way to exploit us, we don't
 * want the exploit to run as root.
 *
 * IMPORTANT: setgid() must be called before setuid(). Once UID is dropped,
 * we no longer have permission to change GID.
 */
int drop_root(int uid, int gid)
{
	if (setgid(gid)) {
		return 1;
	}

	if (setuid(uid)) {
		return 2;
	}

	return 0;
}

/* returns a NULL terminated vector of strings
 * with one hostname/ip in each one
 */
char **parse_targets_file(FILE *f_hosts)
{
#define MAX_HOSTS 1024
	char **hostnames;
	char buffer[1024]; // just a magic number
	int i = 0;

	// + 1 is for NULL termination
	hostnames = malloc(sizeof (char *) * (MAX_HOSTS + 1));
	if (hostnames == NULL) {
		return NULL;
	}

	while (fgets(buffer, sizeof buffer, f_hosts) != NULL) {
		char *p = buffer;

		if (i >= MAX_HOSTS) {
			fprintf(stderr,
					"Warning: Stopped reading hostnames from file after %d entries\n",
					MAX_HOSTS);
			break;
		}

		// Skip leading whitespace
		while (*p == ' ' || *p == '\t')
			p++;

		// Skip empty lines and comments
		if (*p == '\0' || *p == '\n' || *p == '#')
			continue;
		hostnames[i] = malloc(strlen(buffer) + 1);
		if (hostnames[i] == NULL) {
			// Clean up already-allocated entries
			hostnames[i] = NULL;
			free_stringlist(hostnames);
			return NULL;
		}
		strncpy(hostnames[i], buffer, strlen(buffer) + 1);

		// Remove trailing newline if present
		size_t len = strlen(hostnames[i]);
		if (len > 0 && hostnames[i][len - 1] == '\n') {
			hostnames[i][len - 1] = '\0';
		}
		i++;
	}

	// NULL termination
	hostnames[i] = NULL;

	return hostnames;
}

/*	free_stringlist()
 *		Free a vector of strings, NULL terminated
 */
int free_stringlist(char **list)
{
	char **temp;

	if (list == NULL) {
		return 0;
	}

	temp = list;
	while (*list) {
		free(*list);
		list++;
	}
	free(temp);

	return 0; // OK
}
