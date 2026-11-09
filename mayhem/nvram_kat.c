// Known-answer driver for mayhem/test.sh: runs the real libnvram code (nvram.c, crc.c) over a fixed
// fixture and prints what it parsed, so test.sh can diff the output against a golden file.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nvram.h"

extern size_t nvram_part_size;

static int cmp(const void *a, const void *b)
{
	return strcmp((*(nvram_tuple_t **)a)->name, (*(nvram_tuple_t **)b)->name);
}

static int crc_ok(nvram_header_t *hdr)
{
	nvram_header_t tmp;
	uint8_t crc;

	memset(&tmp, 0, sizeof(tmp));
	tmp.crc_ver_init = hdr->crc_ver_init;
	tmp.config_refresh = hdr->config_refresh;
	tmp.config_ncdl = hdr->config_ncdl;
	crc = hndcrc8((uint8_t *)&tmp + NVRAM_CRC_START_POSITION, sizeof(tmp) - NVRAM_CRC_START_POSITION, 0xff);
	crc = hndcrc8((uint8_t *)hdr + sizeof(*hdr), hdr->len - sizeof(*hdr), crc);
	return crc == (hdr->crc_ver_init & 0xff);
}

static void dump(nvram_handle_t *h, const char *label)
{
	nvram_tuple_t *all = nvram_getall(h), *t, *list[64];
	size_t n = 0, i;
	nvram_header_t *hdr = nvram_header(h);

	for (t = all; t && n < 64; t = t->next)
		list[n++] = t;
	qsort(list, n, sizeof(list[0]), cmp);
	printf("[%s] vars=%zu len=%u crc=0x%02x crc_ok=%d\n", label, n, hdr->len, hdr->crc_ver_init & 0xff,
	       crc_ok(hdr));
	for (i = 0; i < n; i++)
		printf("%s=%s\n", list[i]->name, list[i]->value);
	while (all) {
		t = all;
		all = all->next;
		free(t);
	}
}

int main(int argc, char **argv)
{
	nvram_handle_t *h;
	FILE *in, *out;
	char buf[0x10000];
	size_t n;
	char copy[] = "nvram_kat.XXXXXX";
	int fd;

	if (argc != 2)
		return 2;
	nvram_part_size = 0x10000;

	h = nvram_open(argv[1], NVRAM_RO);
	if (!h) {
		puts("open failed");
		return 1;
	}
	dump(h, "parsed");
	printf("get lan_ipaddr=%s\n", nvram_safe_get(h, "lan_ipaddr"));
	printf("get missing=%s\n", nvram_safe_get(h, "missing"));
	nvram_close(h);

	in = fopen(argv[1], "rb");
	fd = mkstemp(copy);
	if (!in || fd < 0)
		return 2;
	out = fdopen(fd, "wb");
	n = fread(buf, 1, sizeof(buf), in);
	fwrite(buf, 1, n, out);
	fflush(out);
	/* The file is mapped as nvram_part_size bytes; back all of them (older libnvram SIGBUSes otherwise). */
	if (ftruncate(fd, nvram_part_size) != 0)
		return 2;
	fclose(out);
	fclose(in);

	h = nvram_open(copy, NVRAM_RW);
	if (!h) {
		puts("rw open failed");
		unlink(copy);
		return 1;
	}
	nvram_set(h, "lan_ipaddr", "10.0.0.1");
	nvram_set(h, "new_var", "new_value");
	nvram_unset(h, "wan_proto");
	nvram_commit(h);
	nvram_close(h);

	h = nvram_open(copy, NVRAM_RO);
	if (!h) {
		puts("reopen failed");
		unlink(copy);
		return 1;
	}
	dump(h, "committed");
	nvram_close(h);
	unlink(copy);
	return 0;
}
