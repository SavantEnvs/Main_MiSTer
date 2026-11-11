// Fuzzes sxmlc, the XML parser MiSTer uses for MRA / MGL / neogeo romsets: SAX with the same
// all_event callback shape the loaders use, plus DOM (with and without text nodes) and a re-print.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "../../sxmlc.h"
}

static int all_event(XMLEvent evt, const XMLNode *node, SXML_CHAR *text, const int n, SAX_Data *sd)
{
	// per-input counter in unsigned arithmetic, so a long run can't overflow it
	unsigned *touch = (unsigned *)sd->user;
	switch (evt)
	{
	case XML_EVENT_START_NODE:
	case XML_EVENT_END_NODE:
		*touch += (unsigned)strlen(node->tag);
		for (int i = 0; i < node->n_attributes; i++)
			*touch += (unsigned)strlen(node->attributes[i].name) + (unsigned)strlen(node->attributes[i].value) + (unsigned)strcasecmp(node->attributes[i].name, "name");
		if (node->text) *touch += (unsigned)strlen(node->text);
		break;
	case XML_EVENT_TEXT:
		*touch += (unsigned)strlen(text);
		break;
	default:
		*touch += (unsigned)n;
		break;
	}
	return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf = (char *)malloc(size + 1);
	memcpy(buf, data, size);
	buf[size] = 0;

	SAX_Callbacks sax;
	SAX_Callbacks_init(&sax);
	sax.all_event = all_event;
	unsigned touch = 0;
	XMLDoc_parse_buffer_SAX(buf, "fuzz", &sax, &touch);

	for (int text_as_nodes = 0; text_as_nodes < 2; text_as_nodes++)
	{
		XMLDoc doc;
		XMLDoc_init(&doc);
		if (XMLDoc_parse_buffer_DOM_text_as_nodes(buf, "fuzz", &doc, text_as_nodes))
		{
			char *out = NULL;
			size_t out_len = 0;
			FILE *f = open_memstream(&out, &out_len);
			if (f)
			{
				XMLDoc_print(&doc, f, "\n", "  ", 0, 0, 4);
				fclose(f);
			}
			free(out);
		}
		XMLDoc_free(&doc);
	}

	free(buf);
	return 0;
}
