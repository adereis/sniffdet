// SPDX-License-Identifier: GPL-2.0-only

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>

#define HASH_SYMBOL '*'

#ifdef IFACE_MODULE_TEST
int main(void)
{
#define MAX 10
	int i;

	for (i = 0; i < MAX; i++) {
		print_hash(i, MAX);
		usleep(500000);
	}
	print_hash(1, 1);
}
#endif


/*
 * This code is derived from the RPM printHash() function
 * http://www.rpm.org
 */
void print_hash(const unsigned long amount, const unsigned long total)
{
	int hashesNeeded;
	int hashesTotal = 50;

	int hashesPrinted = 0;
	int progressCurrent = 0;
	int progressTotal = 0;

	// limit to 80 chars wide
	if (isatty (STDOUT_FILENO))
		hashesTotal = 73;

	if (hashesPrinted != hashesTotal) {
		hashesNeeded = hashesTotal * (total ? (((float) amount) / total) : 1);
		while (hashesNeeded > hashesPrinted) {
			if (isatty (STDOUT_FILENO)) {
				int i;
				for (i = 0; i < hashesPrinted; i++)
					(void) putchar (HASH_SYMBOL);
				for (; i < hashesTotal; i++)
					(void) putchar (' ');
				fprintf(stdout, "(%3d%%)",
					(int)(100 * (total ? (((float) amount) / total) : 1)));
				for (i = 0; i < (hashesTotal + 6); i++)
					(void) putchar ('\b');
			} else
				(void) putchar (HASH_SYMBOL);

			hashesPrinted++;
		}
		(void) fflush(stdout);
		hashesPrinted = hashesNeeded;

		if (hashesPrinted == hashesTotal) {
			int i;
			progressCurrent++;
			if (isatty(STDOUT_FILENO)) {
				for (i = 1; i < hashesPrinted; i++)
					(void) putchar (HASH_SYMBOL);
				fprintf(stdout, " [%3d%%]", (int) (100 * (progressTotal ?
					(((float) progressCurrent) / progressTotal) : 1)));
			}
			fprintf(stdout, "\n");
		}
		(void) fflush(stdout);
	}
}
