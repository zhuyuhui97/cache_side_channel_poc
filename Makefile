# CC := $(CROSS_COMPILE)gcc
CC := aarch64-linux-gnu-gcc
CFLAGS :=

all: pp_dc pp_ic

pp_dc: physmap.h walk.h env.h pp_dc.c pp_dc_aarch64.S physmap.c walk.c env.c
	$(CC) $(CFLAGS) -static -O3 -g -DDBG_TIMER_HW $^ -o $@

pp_ic: physmap.h walk.h env.h pp_ic.c pp_ic_aarch64.S physmap.c walk.c env.c
	$(CC) $(CFLAGS) -static -O3 -g -DDBG_TIMER_HW $^ -o $@