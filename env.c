#include <argp.h>
#include <stdlib.h>
#include <sys/types.h>
#include "env.h"


static struct argp_option options[] = {
    {"tramp", 't', "TRAMPOLINE_BASE", 0, "Base address of trampoline."},
    {"ways", 'w', "CACHE_WAYS", 0, "Number of ways."},
    {"bits", 'b', "CACHE_IDX_BITS", 0, "Number of index bits."},
    {"offset", 'o', "CACHE_OFFSET_BITS", 0, "Size of cache line, default 64b."},
    {"size", 's', "TRAMPOLINE_BITS", 0,
     "Bits of address span of the RET trampoline, size=(1<<TRAMPOLINE_BITS)."},
    {"probe", 'p', "OFFSET", 0, "DEBUG: test offset of P+P probe"},
    {"evict", 'e', NULL, 0, "DEBUG: do eviction"},
    {"pmu-ev", 'm', "PMU_EVENT_ID", 0,
     "DEBUG: PMU event to monitor (ARM only)."},
    {"ns", 'n', "NANOSEC", 0, "Threshold in nanoseconds."},
    {"verbose", 'v', NULL, 0, "Print debug information."},
    {"repeat", 'r', "NR_REPEAT", 0, "Repeat P+P on single VA for NR_REPEAT times."},
    {"peek-phys-map", 1000, NULL, 0, "Use page map to generate prime set, root required."},
    {"prime-sweep", 1001, "NR_PR_SWEEP", 0, "Priming the cache set by N/2 sweeping between the first and the last prime entry (i.e. forward then backward)."},
    {"prime-repeats", 1002, "NR_PR_REPEAT", 0, "Repeat NR_PR_SWEEP for NR_PR_REPEAT times"},
    {"evict-repeats", 1003, "NR_EV_REPEAT", 0, "Repeat eviction for NR_EV_REPEAT times"},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    switch (key) {
    case 't':
        args.tramp_base = (void *)strtoull(arg, NULL, 0);
        break;
    case 'w':
        args.cache_ways = strtoull(arg, NULL, 0);
        break;
    case 'b':
        args.cache_idx_bits = strtoull(arg, NULL, 0);
        if (args.cache_idx_bits < 6) {
            fprintf(stderr, "error: cache_idx_bits must be >= 6\n");
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case 'o':
        args.cache_offset_bits = strtoull(arg, NULL, 0);
        break;
    case 's':
        args.tramp_bits = strtoull(arg, NULL, 0);
        args.tramp_size = 1 << args.tramp_bits;
        break;
    case 'p':
        args.offset_dbg_probe = strtoull(arg, NULL, 0);
        break;
    case 'e':
        args.do_eviction = true;
        break;
    case 'm':
        args.pmu_event_id = strtoull(arg, NULL, 0);
        break;
    case 'n':
        args.threshold_ns = strtoull(arg, NULL, 0);
        break;
    case 'v':
        args.verbose = true;
        break;
    case 'r':
        args.nr_repeat = strtoull(arg, NULL, 0);
        break;
    case 1000:
        args.peek_phys_map = true;
        break;
    case 1001:
        args.prime_sweep = strtoull(arg, NULL, 0);
        break;
    case 1002:
        args.prime_repeat = strtoull(arg, NULL, 0);
        break;
    case 1003:
        args.evict_repeat = strtoull(arg, NULL, 0);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, NULL, NULL, NULL};
pid_t pid = -1;

error_t init_args(int argc, char **argv) {
    return argp_parse(&argp, argc, argv, 0, 0, NULL);
}


