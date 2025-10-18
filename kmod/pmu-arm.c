// #include <stdint.h>
#include <linux/init.h>
#include <linux/cpu.h>
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
    D(PMCR_EL0)                                                                \
    D(S3_1_c15_c2_0) /* CPUACTLR_EL1 */                                        \
    D(S3_1_c15_c2_1) /* CPUECTLR_EL1 */                                        \
    D(S3_1_c15_c0_0) /* L2ACTLR_EL1 */

typedef struct {
#define DEFINE_SYSREG_VARS(name) u64 val_##name; u64 bak_##name;
FOREACH_PMUREG(DEFINE_SYSREG_VARS)
#undef DEFINE_SYSREG_VARS
} sys_reg_per_cpu;

static sys_reg_per_cpu cpu_reg[128];

static void get_regs(int cpu) {
#define GET_ALL_SYSREGS(name)                                                  \
    asm volatile("MRS %0, " #name : "=r"(cpu_reg[cpu].bak_##name));                         \
    cpu_reg[cpu].val_##name = cpu_reg[cpu].bak_##name;

    FOREACH_PMUREG(GET_ALL_SYSREGS);
#undef GET_ALL_SYSREGS
}

static void commit_regs(int cpu) {
#define COMMIT_ALL_SYSREGS(name)                                               \
    asm volatile("MSR " #name ", %0" ::"r"(cpu_reg[cpu].val_##name));
    FOREACH_PMUREG(COMMIT_ALL_SYSREGS);
#undef COMMIT_ALL_SYSREGS
}

static void restore_regs(int cpu) {
#define RESTORE_ALL_SYSREGS(name) cpu_reg[cpu].val_##name = cpu_reg[cpu].bak_##name;
    FOREACH_PMUREG(RESTORE_ALL_SYSREGS);
#undef RESTORE_ALL_SYSREGS
    commit_regs(cpu);
}

// Enable EL0 read/write access to PMU registers
static void enable_el0_access(int cpu) { cpu_reg[cpu].val_PMUSERENR_EL0 |= PMUSERENR_ENABLE; }

//
static void enable_evcntrs(int cpu) {
    cpu_reg[cpu].val_PMCR_EL0 |= PMCR_E;
    cpu_reg[cpu].val_PMCR_EL0 |= PMCR_P;
    cpu_reg[cpu].val_PMCR_EL0 |= PMCR_C;
    cpu_reg[cpu].val_PMCR_EL0 &= ~PMCR_D;
    cpu_reg[cpu].val_PMCR_EL0 |= ~PMCR_X;
}

// Enable the cycle counter register.
static void enable_ccntr(int cpu) { cpu_reg[cpu].val_PMCNTENSET_EL0 |= (1 << 31); }

static void set_classic_lru(int cpu) {
    cpu_reg[cpu].val_S3_1_c15_c0_0 &= ~(3ULL << 30);
    cpu_reg[cpu].val_S3_1_c15_c0_0 |= (1ULL << 30);
}

static void disable_prefetch(int cpu) {
    cpu_reg[cpu].val_S3_1_c15_c2_0 |= (1ULL << 56);
    cpu_reg[cpu].val_S3_1_c15_c2_0 |= (1ULL << 43);
    cpu_reg[cpu].val_S3_1_c15_c2_0 |= (1ULL << 42);
    cpu_reg[cpu].val_S3_1_c15_c2_0 |= (1ULL << 32);
    cpu_reg[cpu].val_S3_1_c15_c2_1 &= ~(3ULL << 35); // CPUECTLR_EL1[36:35] = 0b11
}

static void enable(void) {
    int cpu = smp_processor_id();
    printk(KERN_INFO "PMU-ARM: enabling PMU on CPU %d\n", cpu);
    get_regs(cpu);
    enable_el0_access(cpu);
    enable_evcntrs(cpu);
    enable_ccntr(cpu);
    // disable_prefetch(cpu);
    commit_regs(cpu);
    printk(KERN_INFO "PMU-ARM: finished on CPU %d\n", cpu);
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
