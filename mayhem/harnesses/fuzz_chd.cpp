// Fuzzes the CD-image loader behind MiSTer's CHD support: upstream's mister_load_chd() (CHD header
// and map parse through the bundled libchdr, track-metadata parse into the TOC) followed by
// mister_chd_read_sector() on the first hunks of every track. The libFuzzer bytes are written to a
// scratch file because libchdr opens a path.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>

#include "../../support/chd/mister_chd.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *tmpdir = getenv("TMPDIR");
	std::string path = std::string(tmpdir && *tmpdir ? tmpdir : "/tmp") + "/fuzz_chd_XXXXXX";
	int fd = mkstemp(&path[0]);
	if (fd < 0) return 0;
	size_t off = 0;
	while (off < size)
	{
		ssize_t n = write(fd, data + off, size - off);
		if (n <= 0) break;
		off += (size_t)n;
	}
	close(fd);

	toc_t *toc = (toc_t *)calloc(1, sizeof(toc_t));
	if (mister_load_chd(path.c_str(), toc) == CHDERR_NONE && toc->chd_f)
	{
		const chd_header *hdr = chd_get_header(toc->chd_f);
		// mister_chd_read_sector() indexes a hunk in CD_FRAME_SIZE units, so it is only defined for CD CHDs
		if (hdr && hdr->unitbytes == CD_FRAME_SIZE && hdr->hunkbytes >= hdr->unitbytes && hdr->hunkbytes % hdr->unitbytes == 0)
		{
			uint8_t *hunk = (uint8_t *)calloc(1, hdr->hunkbytes);
			uint8_t sector[CD_MAX_SECTOR_DATA];
			int hunknum = -1;
			for (int lba = 0; lba < 16; lba++)
				mister_chd_read_sector(toc->chd_f, lba, 0, 0, sizeof(sector), sector, hunk, &hunknum);
			free(hunk);
		}
	}
	if (toc->chd_f) chd_close(toc->chd_f);
	free(toc);
	unlink(path.c_str());
	return 0;
}
