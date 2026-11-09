# fuzz_nvram known findings

`nvram_commit()` (`package/utils/nvram/src/nvram.c`, line 300) computes `SDRAM_REFRESH << 16` where
`SDRAM_REFRESH` is the int `0x8040`, which overflows a signed int (UBSan: "left shift of 32832 by 16
places cannot be represented in type 'int'"). It happens on every commit where the four `sdram_*`
variables are not all present, so it halts the harness on every input. `fuzz_nvram.c` therefore sets
all four `sdram_*` variables before committing, which takes the other branch (same `<< 16` pattern, but
the values are fixed and small). To reproduce, remove those four `nvram_set` calls and run any seed
(e.g. `fuzz_nvram/testsuite/empty.nvram`) through the harness.
