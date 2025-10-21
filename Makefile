# CC := $(CROSS_COMPILE)gcc
CC := aarch64-linux-gnu-gcc
CFLAGS :=

dc_pp: physmap.h walk.h env.h pp_dcache_probe.c dc_probe_aarch64.S physmap.c walk.c
	$(CC) $(CFLAGS) -static -O3 -g -DDBG_TIMER_HW $< -o $@

ic_pp: physmap.h walk.h env.h pp_icache_probe.c ic_probe_aarch64.S physmap.c walk.c
	$(CC) $(CFLAGS) -static -O3 -g -DDBG_TIMER_HW $< -o $@