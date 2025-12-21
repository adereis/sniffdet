// SPDX-License-Identifier: GPL-2.0-only
//
// log.h - Simple log system definitions


#ifndef SNIFFDET_LOG_H
#define SNIFFDET_LOG_H

/*
 * Multiple outputs can be used
 * by ORing these values
 */
#define LOG_NOLOG        0x00
#define LOG_USE_SYSLOG   0x01 << 0
#define LOG_USE_FILE     0x01 << 1
#define LOG_USE_STDOUT   0x01 << 2
#define LOG_USE_STDERR   0x01 << 3

#define MAX_LOG_MSG_LEN 512
int mylog(unsigned int ltype, int fd, const char *format, ...);

#endif // SNIFFDET_LOG_H
