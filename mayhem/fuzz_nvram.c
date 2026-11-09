// libFuzzer harness for OpenWrt's libnvram parser (package/utils/nvram/src): the Broadcom
// "FLSH" header plus "name=value\0...\0\0" blob that nvram_open() maps and nvram_rehash() parses.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nvram.h"

extern size_t nvram_part_size;

static int scratch_fd = -1;
static char scratch_path[PATH_MAX];
static char open_path[64];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *dir = getenv("TMPDIR");

	(void)argc;
	(void)argv;
	snprintf(scratch_path, sizeof(scratch_path), "%s/fuzz_nvram.XXXXXX",
		 dir && *dir ? dir : "/tmp");
	scratch_fd = mkstemp(scratch_path);
	if (scratch_fd < 0)
		return 1;
	unlink(scratch_path);
	snprintf(open_path, sizeof(open_path), "/proc/self/fd/%d", scratch_fd);
	nvram_part_size = 0x10000;
	return 0;
}

static int stage(const uint8_t *data, size_t size)
{
	if (ftruncate(scratch_fd, 0) != 0)
		return -1;
	if (size && pwrite(scratch_fd, data, size, 0) != (ssize_t)size)
		return -1;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	nvram_handle_t *h;
	nvram_tuple_t *all, *t;

	if (size > nvram_part_size || stage(data, size))
		return -1;

	h = nvram_open(open_path, NVRAM_RO);
	if (h) {
		all = nvram_getall(h);
		while (all) {
			t = all;
			all = all->next;
			volatile char c = t->value[0];
			(void)c;
			(void)nvram_get(h, t->name);
			free(t);
		}
		(void)nvram_get(h, "sdram_init");
		nvram_close(h);
	}

	h = nvram_open(open_path, NVRAM_RW);
	if (h) {
		nvram_set(h, "fuzz_var", "fuzz_value");
		nvram_unset(h, "fuzz_var");
		/* nvram_commit() without all four sdram_* vars shifts SDRAM_REFRESH (0x8040) << 16 in an
		 * int, which UBSan halts on for every input; setting them takes the other branch. */
		nvram_set(h, "sdram_init", "0x0419");
		nvram_set(h, "sdram_config", "0x0152");
		nvram_set(h, "sdram_refresh", "0x0008");
		nvram_set(h, "sdram_ncdl", "0x5");
		nvram_commit(h);
		nvram_close(h);
	}
	return 0;
}
