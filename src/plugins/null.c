// SPDX-License-Identifier: GPL-2.0-only

#include <lib/libsniffdet.h>
#include "sniffdet.h"
#include "plugins.h"

/*
 * Plugin Metadata
 */
const char *plugin_name(void)
{
	return "Null Output";
}

const char *plugin_version(void)
{
	return "1.0.0";
}

int plugin_api_version(void)
{
	return SNIFFDET_PLUGIN_API_VERSION;
}

int test_output(__attribute__((unused)) const char *target,
		__attribute__((unused)) struct test_info info[],
		__attribute__((unused)) struct config_options config,
		__attribute__((unused)) char *errbuf)
{
	return 0;
}
