#ifndef V7_PMU_H
#define V7_PMU_H

#include <linux/module.h>

#define CYCLE_COUNTER_IDX (31)
#define IS_CYCLE_COUNTER_IDX(IDX)((IDX) == CYCLE_COUNTER_IDX)
#define CYCLE_COUNTER_1_DIVIDER 1
#define CYCLE_COUNTER_64_DIVIDER 64
#define IS_CYCLE_COUNTER_VALID_DIVIDER(divider) (divider == CYCLE_COUNTER_1_DIVIDER || divider == CYCLE_COUNTER_64_DIVIDER)
#define PMCR_TO_DIVIDER(PMCR) ((PMCR) & PMCR_D_MASK ? CYCLE_COUNTER_64_DIVIDER : CYCLE_COUNTER_1_DIVIDER)

#define PMCR_E_MASK  (1 << 0)   /* Enable all counters */
#define PMCR_P_MASK  (1 << 1)   /* Reset all counters */
#define PMCR_C_MASK	 (1 << 2)   /* Cycle counter reset */
#define PMCR_D_MASK  (1 << 3)   /* CCNT counts every 64th cpu cycle */
#define	PMCR_MASK	    0x3f    /* Mask for writable bits */

#define PMUSERENR_EN_MASK 1     /* Enable user mode access */

#define IDX_TO_REG_MASK(IDX)(1 << (IDX))

#define	PMOVSR_OVERFLOWED_MASK	0xffffffff
#define COUNTER_HAS_OVERFLOWED(IDX, PMOVSR)(IDX_TO_REG_MASK(IDX) & (PMOVSR))

#define NUM_EVENT_COUNTERS 6

#define PMU_IRQ 126

#define	HW_COUNTER_MASK 0xFFFFFFFF

#define for_each_event_counter(idx)               \
    for((idx)=0; (idx)<NUM_EVENT_COUNTERS; (idx)++)

#define stop_pmu() \
    pmcr_write(pmcr_read() & ~PMCR_E_MASK)

#define start_pmu() \
    pmcr_write(pmcr_read() | PMCR_E_MASK)

#define select_event_counter(IDX) \
    pmselr_write(IDX)

#define init_event_counter(VAL) \
    pmxevcntr_write(VAL)

static inline u32 pmcr_read(void)
{
	u32 val;

	asm volatile("mrc p15, 0, %0, c9, c12, 0" : "=r"(val));

	return val;
}

static inline void pmcr_write(u32 val)
{
	val &= PMCR_MASK;

	asm volatile("mcr p15, 0, %0, c9, c12, 0" : : "r"(val));
}

/**
 * Get cycle counter value.
 */
static inline u32 pmccntr_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(val));

    return val;
}

/**
 * Set cycle counter value.
 */
static inline void pmccntr_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c13, 0" : : "r"(val));
}

/**
 * Disables, one by one, the cycle counter register (PMCCNTR) and all
 * events counters.
 */
static inline void pmcntenclr_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c12, 2" : : "r" (val));
}

/**
 * Returns which counters are enabled.
 */
static inline u32 pmcntenclr_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c12, 2" : "=r"(val));

    return val;
}

/**
 * Returns which counters are enabled.
 */
static inline u32 pmcntenset_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c12, 1" : "=r"(val));

    return val;
}

/**
 * Enables, one by one, the cycle counter register (PMCCNTR) and all
 * events counters.
 */
static inline void pmcntenset_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c12, 1" : : "r" (val));
}

/**
 * Get the event counter selected.
 */
static inline u32 pmselr_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c12, 5" : "=r" (val));

    return val;
}

/**
 * Select an event counter.
 */
static inline void pmselr_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c12, 5" : : "r" (val));
}

/**
 * Clear counters overflow bits.
 */
static inline void pmovsr_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c12, 3" : : "r" (val));
}

/**
 * Read counters overflow bits.
 */
static inline u32 pmovsr_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c12, 3" : "=r" (val));

    return val;
}

/**
 * Get the value of the the event counter selected by PMSELR.
 */
static inline u32 pmxevcntr_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c13, 2" : "=r" (val));

    return val;
}

/**
 * Set the value of the the event counter selected by PMSELR.
 */
static inline void pmxevcntr_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c13, 2" : : "r" (val));
}

/**
 * Get the event used to increment the event counter selected by PMSELR.
 */
static inline u32 pmxevtyper_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c13, 1" : "=r" (val));

    return val;
}

/**
 * Set the event used to increment the event counter selected by PMSELR.
 */
static inline void pmxevtyper_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c13, 1" : : "r" (val));
}

/**
 * Disables the generation of interrupt requests on counters overflows.
 */
static inline void pmintenclr_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c14, 2" : : "r" (val));
}

/**
 * Returns which overflow interrupt requests are enabled.
 */
static inline u32 pmintenset_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c14, 1" : "=r" (val));

    return val;
}

/**
 * Enables, one by one, the genration of interrupt requests on counters
 * overflows.
 */
static inline void pmintenset_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c14, 1" : : "r" (val));
}

/**
 * Get user mode access to the performance Monitors registers.
 */
static inline u32 pmuserenr_read(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c14, 0" : "=r" (val));

    return val;
}

/**
 * Enables/Disables user mode access to the performance Monitors registers.
 */
static inline void pmuserenr_write(u32 val)
{
    asm volatile("mcr p15, 0, %0, c9, c14, 0" : : "r" (val));
}

static inline void reset_counters(void)
{
    u32 pmcr;

    pmcr = pmcr_read();

    pmcr |= PMCR_C_MASK; // Reset cycle counter
    pmcr |= PMCR_P_MASK; // Reset event counters

    pmcr_write(pmcr);
}

#endif
