// #include <stdint.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

MODULE_DESCRIPTION("Enable PMU in user space");
MODULE_AUTHOR("ZHU Yuhui");
MODULE_LICENSE("GPL");

#define PMUSERENR_ENABLE (1 << 0)
#define PMCR_E (1 << 0) /* Enable all counters */
#define PMCR_P (1 << 1) /* Reset all counters */
#define PMCR_C (1 << 2) /* Cycle counter reset */
#define PMCR_D (1 << 3) /* Cycle counts every 64th cpu cycle */
#define PMCR_X (1 << 4) /* Export to ETM */

#define FOREACH_PMUREG(D)                                                      \
    D(PMUSERENR_EL0)                                                           \
    D(PMCNTENSET_EL0)                                                          \
    D(PMCR_EL0)
#define DEFINE_SYSREG_VARS(name) u64 val_##name = 0, bak_##name = 0;
FOREACH_PMUREG(DEFINE_SYSREG_VARS);
#undef DEFINE_SYSREG_VARS
#undef DEFINE_SYSREG_VARS

static void get_regs(void) {
#define GET_ALL_SYSREGS(name)                                                  \
    asm volatile("MRS %0, " #name : "=r"(bak_##name));                         \
    val_##name = bak_##name;

    FOREACH_PMUREG(GET_ALL_SYSREGS);
#undef GET_ALL_SYSREGS
}

static void commit_regs(void) {
#define COMMIT_ALL_SYSREGS(name)                                               \
    asm volatile("MSR " #name ", %0" ::"r"(val_##name));
    FOREACH_PMUREG(COMMIT_ALL_SYSREGS);
#undef COMMIT_ALL_SYSREGS
}

static void restore_regs(void) {
#define RESTORE_ALL_SYSREGS(name) val_##name = bak_##name;
    FOREACH_PMUREG(RESTORE_ALL_SYSREGS);
#undef RESTORE_ALL_SYSREGS
    commit_regs();
}

// Enable EL0 read/write access to PMU registers
static void enable_el0_access(void) { val_PMUSERENR_EL0 |= PMUSERENR_ENABLE; }

//
static void enable_evcntrs(void) {
    val_PMCR_EL0 |= PMCR_E;
    val_PMCR_EL0 |= PMCR_P;
    val_PMCR_EL0 |= PMCR_C;
    val_PMCR_EL0 &= ~PMCR_D;
    val_PMCR_EL0 |= ~PMCR_X;
}

// Enable the cycle counter register.
static void enable_ccntr(void) { val_PMCNTENSET_EL0 |= (1 << 31); }

static void enable(void) {
    get_regs();
    enable_el0_access();
    enable_evcntrs();
    enable_ccntr();
    commit_regs();
}

static int __init mod_start(void) {
    on_each_cpu((smp_call_func_t)&enable, NULL, 0);
    return 0;
}

static void __exit mod_end(void) {
    on_each_cpu((smp_call_func_t)&restore_regs, NULL, 0);
}

module_init(mod_start);
module_exit(mod_end);
