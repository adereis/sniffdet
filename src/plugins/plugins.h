// SPDX-License-Identifier: GPL-2.0-only

#ifndef SNIFFDET_PLUGINS_H
#define SNIFFDET_PLUGINS_H

/*
 * Plugin API Version
 *
 * Increment this when the plugin interface changes in incompatible ways
 * (e.g., struct layout changes, function signature changes). The loader
 * checks this before calling plugin functions to prevent ABI mismatches.
 *
 * History:
 *   1 - Initial versioned API (2025). Added plugin_name(), plugin_version(),
 *       plugin_api_version() metadata functions.
 */
#define SNIFFDET_PLUGIN_API_VERSION 1

/*
 * Plugin Metadata Functions
 *
 * All plugins must export these functions for version checking and
 * identification. The loader queries these before calling test_output().
 */

/* Human-readable plugin name (e.g., "Standard Output", "XML Output") */
const char *plugin_name(void);

/* Plugin version string (e.g., "1.0.0") */
const char *plugin_version(void);

/* Returns SNIFFDET_PLUGIN_API_VERSION that plugin was built against */
int plugin_api_version(void);

/*
 * Main Plugin Function
 *
 * Called after all tests complete to output results.
 *
 * Parameters:
 *   target - hostname/IP that was tested
 *   info   - array of test results, terminated by info[i].code == MAX_TESTS
 *   config - configuration options (includes plugin-specific settings)
 *   errbuf - buffer for error message if returning non-zero
 *
 * Returns: 0 on success, non-zero on error (message in errbuf)
 */
int test_output(const char *target, struct test_info info[],
		struct config_options config, char *errbuf);

#endif // SNIFFDET_PLUGINS_H
