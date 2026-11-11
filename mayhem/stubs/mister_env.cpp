// Host-side stand-ins for the MiSTer hardware/filesystem layer that cfg.cpp and
// support/chd/mister_chd.cpp call into. Only the environment is mocked (file reads, core name,
// root dir); the INI and CHD parsing code under test is upstream's own, linked unmodified.
#include <stdio.h>
#include <string.h>
#include "../../file_io.h"
#include "../../user_io.h"
#include "../../video.h"
#include "../../support/arcade/mra_loader.h"
#include "mister_env.h"

static const uint8_t *g_ini = nullptr;
static size_t g_ini_size = 0;

void mayhem_set_ini(const uint8_t *data, size_t size)
{
	g_ini = data;
	g_ini_size = size;
}

extern "C" FILE *mayhem_fopen(const char *path, const char *mode)
{
	return fopen(strcmp(path, "/tmp/debug.txt") ? path : "/dev/null", mode);
}

fileTYPE::fileTYPE() { memset(this, 0, sizeof(*this)); }
fileTYPE::~fileTYPE() {}
int fileTYPE::opened() { return g_ini != nullptr; }

int FileOpen(fileTYPE *file, const char *, char)
{
	if (!g_ini) return 0;
	memset(file, 0, sizeof(*file));
	file->size = (__off64_t)g_ini_size;
	return 1;
}

int FileClose(fileTYPE *file)
{
	file->size = 0;
	return 1;
}

int FileReadSec(fileTYPE *file, void *pBuffer)
{
	size_t left = ((size_t)file->offset < g_ini_size) ? g_ini_size - (size_t)file->offset : 0;
	size_t n = left < 512 ? left : 512;
	memset(pBuffer, 0, 512);
	if (n) memcpy(pBuffer, g_ini + file->offset, n);
	file->offset += 512;
	return (int)n;
}

const char *getRootDir() { return "/nonexistent-mister-root"; }
const char *getFullPath(const char *name) { return name; }

uint16_t altcfg(int) { return 0; }
char is_arcade() { return 0; }
bool arcade_is_vertical() { return false; }

char *user_io_get_core_name(int orig)
{
	static char names[2][16] = { "NES", "Nintendo" };
	return names[orig ? 1 : 0];
}

char *video_get_core_mode_name(int)
{
	static char mode[] = "1280x720@60";
	return mode;
}
