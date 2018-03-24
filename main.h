#ifndef H_MAIN
#define H_MAIN

#include "v7_pmu.h"

struct counter_conf {
    int idx;

    union {
        struct {
            u32 val;
            int is_dirty;
        } event;
        struct {
            u32 val;
            int is_dirty;
        } divider;
    } specific;

    struct {
        bool val;
        int is_dirty;
    } is_enabled;

    struct {
        u32 val;
        int is_dirty;
    } init_value;

    struct {
        bool val;
        int is_dirty;
    } has_interrupt;

    struct {
        u32 val;
        int is_dirty;
    } value;

    bool has_overflowed;
};

struct sample {
    u32 cycles;
    u32 event[NUM_EVENT_COUNTERS];
    u32 pmovsr;
    u32 ip;
    pid_t pid;
};

struct samples {
    struct {
        struct sample * pages;
        unsigned int order;
        unsigned int iter;
        int has_overflowed;
    } buffer;
    u64 num_irqs;

    // Configuration used for start sampling
    struct {
        // Cycles counter configuration
        struct counter_conf cycles_cc;
        // event counter configuration
        struct counter_conf event_ccs[NUM_EVENT_COUNTERS];
        // Cpu used for sampling
        u32 cpu;
    } conf;
};

struct core_conf {
    int cpu;
    struct {
        int is_dirty;
        bool val;
    } is_uaccess_enabled;
};

#define NUM_PAGES(ORDER) (1 << (ORDER))

#define NUM_SAMPLES(NUM_PAGES) (PAGE_SIZE * (NUM_PAGES) / sizeof(struct sample))

static inline void counter_conf_init(struct counter_conf * cc, int idx)
{
    memset(cc, 0, sizeof(struct counter_conf));
    cc->idx = idx;
}

static inline void core_conf_init(struct core_conf * cc, int cpu)
{
    memset(cc, 0, sizeof(struct core_conf));
    cc->cpu = cpu;
}

int pmu_init_core(struct core_conf * cc);

int pmu_get_core(struct core_conf * cc);

int pmu_init_counter(struct counter_conf * cc);

int pmu_get_counter(struct counter_conf * cc);

int pmu_start(void);

int pmu_stop(void);

int pmu_is_started(void);

int pmu_get_cpu(void);

int pmu_set_cpu(int cpu);

u64 pmu_get_samples_order(void);

int pmu_set_samples_order(u64 order);

struct samples const * pmu_get_samples(void);

#endif
