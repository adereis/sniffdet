// SPDX-License-Identifier: GPL-2.0-only

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#include "log.h"

static char *timeString(time_t t);

/*
 *	mylog()
 *		Simple log system.
 *		Chooses betwen System log daemon, a file, etc.
 *
 *	log_type ltype
 *		ORed value with log destination(s)
 *	const char *msg
 *		Msg to log
 *	int log_fd
 *		Open filedescriptor to write.
 *		Ignored when using something different than USE_FILE
 *		Ignored if its value is -1;
 */
int mylog(unsigned int ltype, int log_fd, const char *format, ...)
{
	va_list ap;
	char bufmsg[MAX_LOG_MSG_LEN];
	char log_text[MAX_LOG_OUTPUT_LEN];
	char *s_time;
	time_t curr_time;

	curr_time = time(NULL);
	s_time = timeString(curr_time);

	va_start(ap, format);
	vsnprintf(bufmsg, MAX_LOG_MSG_LEN, format, ap);

	// syslog
	if (ltype & LOG_USE_SYSLOG) {
			syslog(LOG_INFO, bufmsg);
	}

	// file (includes timestring)
	if (ltype & LOG_USE_FILE) {
		if (log_fd != -1) {
			snprintf(log_text, MAX_LOG_OUTPUT_LEN, "[%s:%02d]: %s\n", s_time,
					(int) curr_time % 60, bufmsg);
			write(log_fd, log_text, strlen(log_text));
		} else {
#ifdef DEBUG
			fprintf(stderr, "Aborting at line %d in source file %s\n",
					__LINE__, __FILE__);
			abort();
#endif
			return -1;
		}
	}

	// stdout (no timestring)
	if (ltype & LOG_USE_STDOUT) {
		snprintf(log_text, MAX_LOG_OUTPUT_LEN, "%s\n", bufmsg);
		write(STDOUT_FILENO, log_text, strlen(log_text));
	}

	// stderr (no timestring)
	if (ltype & LOG_USE_STDERR) {
		snprintf(log_text, MAX_LOG_OUTPUT_LEN, "%s\n", bufmsg);
		write(STDERR_FILENO, log_text, strlen(log_text));
	}

	va_end(ap);
	return 0;
}

/*
 * timeString()
 * converts a time to a particular representation:
 * "The preferred date and time representation for the current locale"
 */
static char *timeString(time_t t)
{
	static char buffer[64];
	static char timestr[64];
	struct tm *local;

	local = localtime(&t);
	strftime(buffer, 64, "%b %e %H:%M", local);

	strncpy(timestr, buffer, 64);

	return timestr;
}
