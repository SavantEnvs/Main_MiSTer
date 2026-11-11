// Known-answer tests for the code the fuzz targets cover, built with the project's normal flags
// (no sanitizers, no fuzzer runtime) and run by mayhem/test.sh. Each check prints
// "KAT <name> PASS|FAIL" and test.sh counts those lines against the expected total, so a binary
// that does nothing (or exits early) cannot pass.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <string>

#include "../cfg.h"
#include "../sxmlc.h"
#include "../support/a2/iigs_fmt.h"
#include "../support/a2/a2_nib_codec.h"
#include "../support/a3/a3_woz.h"
#include "../support/chd/mister_chd.h"
#include "stubs/mister_env.h"

static int g_fail;

static void check(const char *name, bool ok)
{
	dprintf(1, "KAT %s %s\n", name, ok ? "PASS" : "FAIL"); // fd 1: cfg_parse() repoints stdout at /dev/null
	if (!ok) g_fail++;
}

static void kat_ini()
{
	static const char ini[] =
		"; comment\n"
		"[MiSTer]\n"
		"vsync_adjust=2\n"
		"bootscreen=0\n"
		"video_mode=1280,720,60\n"
		"mouse_throttle=7\n"
		"keyrah_mode=0x23\n"
		"hdmi_cec_clock=3.5\n"
		"bootcore_timeout=10\n"
		"font=fonts/my.pf\n"
		"[NES]\n"
		"vsync_adjust=1\n"
		"[SNES]\n"
		"vsync_adjust=0\n"
		"bootscreen=1\n";
	mayhem_set_ini((const uint8_t *)ini, sizeof(ini) - 1);
	cfg_parse();
	check("ini_core_section_overrides_main", cfg.vsync_adjust == 1);
	check("ini_other_core_section_ignored", cfg.bootscreen == 0);
	check("ini_string_value", !strcmp(cfg.video_conf, "1280,720,60") && !strcmp(cfg.font, "fonts/my.pf"));
	check("ini_numeric_values", cfg.mouse_throttle == 7 && cfg.keyrah_mode == 0x23 && cfg.bootcore_timeout == 10);
	check("ini_float_value", cfg.hdmi_cec_clock > 3.49f && cfg.hdmi_cec_clock < 3.51f);
	check("ini_defaults_kept", cfg.csync == 1 && cfg.logo == 1 && !strcmp(cfg.main, "MiSTer"));
	char msg[256];
	check("ini_clean_file_no_errors", !cfg_check_errors(msg, sizeof(msg)));

	static const char bad[] =
		"[MiSTer]\n"
		"mouse_throttle=500\n"
		"vsync_adjust=banana\n"
		"bootscreen=0\n";
	mayhem_set_ini((const uint8_t *)bad, sizeof(bad) - 1);
	cfg_parse();
	check("ini_out_of_range_clamped", cfg.mouse_throttle == 100);
	check("ini_bad_lines_reported", cfg_check_errors(msg, sizeof(msg)) && strstr(msg, "2 INI Errors") && strstr(msg, "out of range") && strstr(msg, "not a number"));
	check("ini_parse_continues_after_error", cfg.bootscreen == 0);

	static const char vm[] =
		"[MiSTer]\n"
		"video_mode=1\n"
		"[video=1280x720@60]\n"
		"video_mode=3\n";
	mayhem_set_ini((const uint8_t *)vm, sizeof(vm) - 1);
	cfg_parse();
	check("ini_video_section_matches_mode", cfg_has_video_sections() && !strcmp(cfg.video_conf, "3"));
}

static int g_sax_start, g_sax_end, g_sax_attr;
static std::string g_sax_text;

static int sax_cb(XMLEvent evt, const XMLNode *node, SXML_CHAR *text, const int, SAX_Data *)
{
	if (evt == XML_EVENT_START_NODE) { g_sax_start++; g_sax_attr += node->n_attributes; }
	else if (evt == XML_EVENT_END_NODE) g_sax_end++;
	else if (evt == XML_EVENT_TEXT) g_sax_text += text;
	return true;
}

static void kat_xml()
{
	static const char xml[] =
		"<misterromdescription>"
		"<name>Test Game</name>"
		"<rom index=\"0\" zip=\"a.zip\" md5=\"none\"><part name=\"x.bin\" crc=\"DEADBEEF\"/></rom>"
		"<!-- note -->"
		"</misterromdescription>";

	SAX_Callbacks sax;
	SAX_Callbacks_init(&sax);
	sax.all_event = sax_cb;
	check("xml_sax_parses", XMLDoc_parse_buffer_SAX(xml, "kat", &sax, NULL));
	check("xml_sax_node_counts", g_sax_start == 5 && g_sax_end == 5 && g_sax_attr == 5);
	check("xml_sax_text", g_sax_text.find("Test Game") != std::string::npos);

	XMLDoc doc;
	XMLDoc_init(&doc);
	bool ok = XMLDoc_parse_buffer_DOM(xml, "kat", &doc) != 0;
	check("xml_dom_parses", ok && doc.i_root >= 0);
	if (ok && doc.i_root >= 0)
	{
		XMLNode *root = XMLDoc_root(&doc);
		check("xml_dom_root_tag", !strcmp(root->tag, "misterromdescription") && root->n_children == 3);
		XMLNode *rom = root->children[1];
		const char *v = NULL;
		XMLNode_get_attribute(rom, "zip", &v);
		check("xml_dom_attribute", v && !strcmp(v, "a.zip") && !strcmp(rom->tag, "rom"));
		XMLNode_get_attribute(rom->children[0], "crc", &v);
		check("xml_dom_nested_attribute", v && !strcmp(v, "DEADBEEF"));
	}
	else for (int i = 0; i < 3; i++) check("xml_dom_skipped", false);
	XMLDoc_free(&doc);

	XMLDoc tn;
	XMLDoc_init(&tn);
	bool tok = XMLDoc_parse_buffer_DOM_text_as_nodes("<a>hi<b/>there</a>", "kat", &tn, 1) != 0;
	check("xml_text_as_nodes", tok && XMLDoc_root(&tn)->n_children == 3);
	XMLDoc_free(&tn);
}

static std::vector<uint8_t> pattern(size_t n, uint32_t seed)
{
	std::vector<uint8_t> v(n);
	uint32_t x = seed;
	for (size_t i = 0; i < n; i++) { x = x * 1664525u + 1013904223u; v[i] = (uint8_t)(x >> 24); }
	return v;
}

static void kat_a2()
{
	const char *digits = "123456789";
	check("woz_crc32_check_value", woz_crc32((const uint8_t *)digits, 9) == 0xCBF43926u);

	auto payload = pattern(512, 1);
	std::vector<uint8_t> img(64 + 512);
	size_t n = twomg_build(img.data(), img.size(), payload.data(), 512, 1);
	TwoMG h;
	check("twomg_roundtrip", n == 64 + 512 && twomg_parse(img.data(), n, &h) && h.blocks == 1 && h.data_offset == 64 && h.data_len == 512 && h.format == 1);
	check("twomg_rejects_garbage", !twomg_parse(payload.data(), payload.size(), &h));

	std::vector<uint8_t> dc(84 + 512 + 64);
	n = dc42_build(dc.data(), dc.size(), payload.data(), 512, 0x22, "KAT");
	DC42 d;
	check("dc42_build_parse", n > 0 && dc42_probe(dc.data(), n) && dc42_parse(dc.data(), n, &d) && d.data_size == 512 && d.data_checksum == dc42_checksum(payload.data(), 512));
	check("dc42_rejects_garbage", !dc42_probe(payload.data(), payload.size()));

	auto dos = pattern(A2_525_IMAGE_SIZE, 2);
	for (int s = 0; s < 16; s++) memset(&dos[s * 256], s, 256);
	std::vector<uint8_t> po(A2_525_IMAGE_SIZE), back(A2_525_IMAGE_SIZE);
	a2_dos_to_prodos(po.data(), dos.data());
	check("a2_dos_to_prodos_sector_map", po[0] == 0 && po[256] == 14 && po[512] == 13 && po[256 * 15] == 15);
	a2_prodos_to_dos(back.data(), po.data());
	check("a2_order_roundtrip", back == dos);

	auto dsk = pattern(A2_525_IMAGE_SIZE, 3);
	std::vector<uint8_t> nib(A2_NIB_IMAGE_SIZE);
	a2_dsk_to_nib(nib.data(), dsk.data());
	int addr = 0, dat = 0;
	for (int i = 0; i + 2 < A2_NIB_TRACK_SIZE; i++)
	{
		if (nib[i] == 0xD5 && nib[i + 1] == 0xAA && nib[i + 2] == 0x96) addr++;
		if (nib[i] == 0xD5 && nib[i + 1] == 0xAA && nib[i + 2] == 0xAD) dat++;
	}
	check("a2_nib_track_has_16_sectors", addr == 16 && dat == 16);
	std::vector<uint8_t> dsk2(A2_525_IMAGE_SIZE);
	check("a2_nib_roundtrip", a2_nib_to_dsk(dsk2.data(), nib.data()) == 1 && dsk2 == dsk);

	uint8_t track[A2NIB_TRACK_SIZE], dtrack[A2NIB_DSK_TRACK_SIZE];
	a2_nibblize_track(dsk.data(), 5, 254, A2NIB_ORDER_DOS, track);
	uint32_t mask = a2_denibblize_track(track, 5, A2NIB_ORDER_DOS, dtrack);
	check("a2_track_codec_roundtrip", mask == 0xFFFFu && !memcmp(dtrack, dsk.data(), A2NIB_DSK_TRACK_SIZE));

	std::vector<uint8_t> woz(2u << 20);
	size_t wn = a2_dsk_to_woz525(woz.data(), woz.size(), dsk.data());
	std::vector<uint8_t> dsk3(A2_525_IMAGE_SIZE);
	check("woz525_roundtrip", wn > 0 && woz_disk_type(woz.data(), wn) == 1 && a2_woz525_to_dsk(dsk3.data(), woz.data(), wn) && dsk3 == dsk);

	auto po35 = pattern(A2_35_IMAGE_SIZE, 4);
	size_t w35 = a2_po_to_woz35(woz.data(), woz.size(), po35.data());
	std::vector<uint8_t> po35b(A2_35_IMAGE_SIZE);
	check("woz35_roundtrip", w35 > 0 && woz_disk_type(woz.data(), w35) == 2 && a2_woz35_to_po(po35b.data(), woz.data(), w35) && po35b == po35);

	size_t a3 = a3_dsk_to_woz(woz.data(), woz.size(), dsk.data(), 0, 254);
	uint8_t trk[A2_TRACK_SIZE], vols[16];
	int found = a3_decode_track(woz.data(), a3, 7, trk, vols);
	check("a3_woz_track_decode", a3 > 0 && found == 16 && vols[3] == 254);

	check("classify_140k", iigs_classify(dos.data(), 512, A2_525_IMAGE_SIZE, "po") == DC_FLOPPY_525);
	check("classify_800k", iigs_classify(po35.data(), 512, A2_35_IMAGE_SIZE, "po") == DC_FLOPPY_35);
}

static void kat_chd()
{
	toc_t *toc = (toc_t *)calloc(1, sizeof(toc_t));
	chd_error err = mister_load_chd("mayhem/fuzz_chd/testsuite/two_track_uncompressed.chd", toc);
	check("chd_load_ok", err == CHDERR_NONE && toc->chd_f);
	if (err == CHDERR_NONE && toc->chd_f)
	{
		check("chd_toc_tracks", toc->last == 2 && toc->tracks[0].type == TT_MODE1 && toc->tracks[0].sector_size == 2352 && toc->tracks[1].type == TT_CDDA);
		check("chd_toc_ranges", toc->tracks[0].start == 0 && toc->tracks[0].end == 4 && toc->tracks[1].start == 4 && toc->tracks[1].end == 8 && toc->end == 8);
		uint8_t hunk[4896], out[2352];
		int hunknum = -1;
		bool ok = true;
		for (int lba = 0; lba < 8; lba++)
		{
			ok &= mister_chd_read_sector(toc->chd_f, lba, 0, 0, 2352, out, hunk, &hunknum) == CHDERR_NONE;
			for (int i = 0; i < 2352; i++) ok &= out[i] == (uint8_t)((lba * 7 + i) & 0xff);
		}
		check("chd_sector_data", ok);
		chd_close(toc->chd_f);
	}
	else { check("chd_toc_tracks", false); check("chd_toc_ranges", false); check("chd_sector_data", false); }
	free(toc);

	toc = (toc_t *)calloc(1, sizeof(toc_t));
	check("chd_missing_file_rejected", mister_load_chd("mayhem/does-not-exist.chd", toc) != CHDERR_NONE);
	free(toc);
	toc = (toc_t *)calloc(1, sizeof(toc_t));
	check("chd_non_chd_rejected", mister_load_chd("mayhem/kat.cpp", toc) != CHDERR_NONE);
	free(toc);
}

int main()
{
	kat_ini();
	kat_xml();
	kat_a2();
	kat_chd();
	dprintf(1, "KAT-SUMMARY failures=%d\n", g_fail);
	return g_fail ? 1 : 0;
}
