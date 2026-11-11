// Fuzzes MiSTer's Apple II / IIgs / Apple III floppy+hard-disk image codecs (support/a2, support/a3):
// format sniffing, 2MG / DiskCopy 4.2 / WOZ parsing, DOS<->ProDOS sector order, 6-and-2 GCR
// nibblize/denibblize, 5.25" and 3.5" WOZ decode, and per-track write-back decode.
// The first input byte picks the operation, the rest is the image; fixed-geometry buffers are
// zero-padded to the size each function documents.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <vector>

#include "../../support/a2/iigs_fmt.h"
#include "../../support/a2/a2_nib_codec.h"
#include "../../support/a3/a3_woz.h"

static const char *const kExt[] = { "", "po", "do", "dsk", "nib", "woz", "2mg", "hdv", "dc42", "img" };

static std::vector<uint8_t> padded(const uint8_t *p, size_t n, size_t want)
{
	std::vector<uint8_t> v(want, 0);
	memcpy(v.data(), p, n < want ? n : want);
	return v;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2) return -1;
	const unsigned op = data[0] % 14;
	const unsigned arg = data[1];
	const uint8_t *buf = data + 2;
	const size_t len = size - 2;
	volatile uint32_t sink = 0;

	const size_t kWozCap = 2u << 20;

	switch (op)
	{
	case 0:
		sink += iigs_classify(buf, len, len, kExt[arg % (sizeof(kExt) / sizeof(kExt[0]))]);
		sink += iigs_classify(buf, len, (size_t)arg << 16, NULL);
		break;
	case 1:
	{
		TwoMG h;
		if (twomg_parse(buf, len, &h))
		{
			sink += h.blocks + h.data_len;
			std::vector<uint8_t> out(64 + 4096);
			sink += (uint32_t)twomg_build(out.data(), out.size(), buf, len < 4096 ? (uint32_t)len : 4096u, h.format);
		}
		break;
	}
	case 2:
	{
		DC42 d;
		sink += dc42_probe(buf, len);
		sink += dc42_parse(buf, len, &d);
		sink += dc42_checksum(buf, len);
		break;
	}
	case 3:
		sink += woz_disk_type(buf, len);
		sink += woz_crc32(buf, len);
		break;
	case 4:
		sink += a2_detect_525_order(buf, len);
		sink += a2_resolve_525_order(buf, len, kExt[arg % (sizeof(kExt) / sizeof(kExt[0]))]);
		break;
	case 5:
	{
		auto src = padded(buf, len, A2_525_IMAGE_SIZE);
		std::vector<uint8_t> dst(A2_525_IMAGE_SIZE);
		a2_dos_to_prodos(dst.data(), src.data());
		a2_prodos_to_dos(dst.data(), src.data());
		a2_dos_track_to_prodos(dst.data(), src.data());
		sink += dst[arg];
		break;
	}
	case 6:
	{
		// a2_nib_to_dsk() is 35 calls of the per-track decoder that op 7 already fuzzes, and it is
		// quadratic on a sector-less track (known-findings/nib_track_scan_quadratic), so a
		// zero-padded image costs ~14 s under ASan: only the encode direction runs here.
		auto dsk2 = padded(buf, len, A2_525_IMAGE_SIZE);
		std::vector<uint8_t> nib2(A2_NIB_IMAGE_SIZE);
		a2_dsk_to_nib(nib2.data(), dsk2.data());
		sink += nib2[arg];
		break;
	}
	case 7:
	{
		auto nibtrack = padded(buf, len, A2_NIB_TRACK_SIZE);
		std::vector<uint8_t> dsktrack(A2_TRACK_SIZE);
		sink += a2_nib_track_to_dsk(nibtrack.data(), dsktrack.data());
		auto dsk = padded(buf, len, A2_TRACK_SIZE);
		std::vector<uint8_t> nib(A2_NIB_TRACK_SIZE);
		a2_dsk_track_to_nib(nib.data(), dsk.data(), (int)(arg % A2_TRACKS_525));
		sink += nib[0];
		break;
	}
	case 8:
	{
		std::vector<uint8_t> dsk(A2_525_IMAGE_SIZE);
		sink += a2_woz525_to_dsk(dsk.data(), buf, len);
		sink += a2_woz525_decode_track(buf, len, (int)(arg % A2_TRACKS_525), dsk.data());
		sink += a2_woz_track_for_lba(buf, len, (uint32_t)arg * 977u);
		break;
	}
	case 9:
	{
		std::vector<uint8_t> po(A2_35_IMAGE_SIZE);
		sink += a2_woz35_to_po(po.data(), buf, len);
		int base = 0, count = 0;
		sink += a2_woz35_decode_track(buf, len, (int)(arg % 160), po.data(), &base, &count);
		sink += base + count;
		break;
	}
	case 10:
	{
		std::vector<uint8_t> trk(A2_TRACK_SIZE);
		uint8_t volumes[16];
		sink += a3_decode_track(buf, len, (int)(arg % A2_TRACKS_525), trk.data(), volumes);
		sink += volumes[arg & 15];
		break;
	}
	case 11:
	{
		auto dsk = padded(buf, len, A2_525_IMAGE_SIZE);
		std::vector<uint8_t> woz(kWozCap);
		sink += (uint32_t)a3_dsk_to_woz(woz.data(), woz.size(), dsk.data(), a3_sos_interp_encrypted(dsk.data()), a3_dos33_volume(dsk.data()));
		auto nib = padded(buf, len, A2_NIB_IMAGE_SIZE);
		sink += (uint32_t)a3_nib_to_woz(woz.data(), woz.size(), nib.data());
		break;
	}
	case 12:
	{
		auto trk = padded(buf, len, A2NIB_DSK_TRACK_SIZE);
		std::vector<uint8_t> nib(A2NIB_TRACK_SIZE);
		a2_nibblize_track(trk.data(), (int)(arg % A2NIB_TRACKS), (int)(arg ^ 0x55), (int)(arg & 1), nib.data());
		std::vector<uint8_t> back(A2NIB_DSK_TRACK_SIZE);
		sink += a2_denibblize_track(nib.data(), (int)(arg % A2NIB_TRACKS), (int)(arg & 1), back.data());
		break;
	}
	default:
	{
		auto nib = padded(buf, len, A2NIB_TRACK_SIZE);
		std::vector<uint8_t> out(A2NIB_DSK_TRACK_SIZE);
		sink += a2_denibblize_track(nib.data(), (int)(arg % A2NIB_TRACKS), (int)(arg & 1), out.data());
		sink += a2_file_sector((int)(arg & 15), (int)(arg >> 7));
		break;
	}
	}
	return 0;
}
