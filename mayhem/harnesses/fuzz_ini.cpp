// Fuzzes MiSTer.ini parsing: upstream's cfg_parse() (sections, video-mode sections, includes,
// numeric/string/array variable parsing) over the fuzzer's bytes served as the ini file.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../../cfg.h"
#include "../stubs/mister_env.h"

// cfg.cpp's `debug=` line reassigns the global stdout and never restores it. stdout is pinned to one
// persistent /dev/null stream before and after every input, so no input inherits another's stdout.
static FILE *g_null;

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
	g_null = fopen("/dev/null", "w");
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (g_null) stdout = g_null;
	mayhem_set_ini(data, size);
	cfg_parse();
	char msg[1024];
	cfg_check_errors(msg, sizeof(msg));
	yc_mode yc[16];
	yc_parse(yc, 16);
	if (g_null) stdout = g_null;
	return 0;
}
