// SPDX-License-Identifier: GPL-2.0-only
//
// util.h - General use functions

#ifndef SNIFFDET_UTIL_H
#define SNIFFDET_UTIL_H

int drop_root(int uid, int gid);
char **parse_targets_file(FILE *f_hosts);
char **network_ips(const char *netmask, const char *network);
int free_stringlist(char **list);

#endif // SNIFFDET_UTIL_H
