#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/irq_work.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <asm-generic/irq_regs.h>

#include "main.h"
#include "interface.h"
#include "v7_debug.h"

#include <linux/delay.h>

static struct {
    int is_started;
    int cpu;
    struct samples samples;
    int irq_num;
} global;

static DEFINE_PER_CPU(u32, cycles_counter_init_value);

static DEFINE_PER_CPU(u32[NUM_EVENT_COUNTERS], event_counters_init_values);

/*  You should set SUNIDEN and SUIDEN bit on Secure Debug Enable
    Register. (Cf "C12.4.1 Interaction with Security Extensions",
    "C12.1.7 Effects of non-invasive debug authentication on the
    Performance Monitors, "B4.1.131 SDER Secure Debug Enable Register,
    Security Extensions" of "ARM Architecture Reference Manual
    ARMv7-A and ARMv7-R").*/
static void enable_invasive_non_invasive_debug(void)
{
    u32 val = 0b11; // SUNIDEN, SUIDEN bits

    asm volatile("mcr p15, 0, %0, c1, c1, 1" : : "r" (val));
}

static void set_core_config(void * data)
{
    struct core_conf * cc = data;

    if(cc->is_uaccess_enabled.is_dirty)
    {
        if(cc->is_uaccess_enabled.val)
            pmuserenr_write(PMUSERENR_EN_MASK);
        else
            pmuserenr_write(~PMUSERENR_EN_MASK);
    }
}

static void get_core_config(void * data)
{
    ((struct core_conf *)data)->is_uaccess_enabled.val =
        pmuserenr_read() & PMUSERENR_EN_MASK;
}

static void set_event_config(void * data)
{
    struct counter_conf * cc = data;

    if(cc->is_enabled.is_dirty)
    {
        u32 mask = IDX_TO_REG_MASK(cc->idx);

        if(cc->is_enabled.val)
            // Enable counter
            pmcntenset_write(mask);
        else
            // Disable counter
            pmcntenclr_write(mask);
    }

    if(cc->has_interrupt.is_dirty)
    {
        u32 mask = IDX_TO_REG_MASK(cc->idx);

        if(cc->has_interrupt.val)
            // Enable interrupts
            pmintenset_write(mask);
        else
            // Disable interrupts
            pmintenclr_write(mask);
    }

    if(cc->init_value.is_dirty)
    {
        if(IS_CYCLE_COUNTER_IDX(cc->idx))
        {
            get_cpu_var(cycles_counter_init_value) = cc->init_value.val;
            put_cpu_var(cycles_counter_init_value);
        }
        else
        {
            get_cpu_var(event_counters_init_values)[cc->idx] = cc->init_value.val;
            put_cpu_var(event_counters_init_values);
        }
    }

    if(IS_CYCLE_COUNTER_IDX(cc->idx))
    {
        if(cc->value.is_dirty)
            // init cycle counter
            pmccntr_write(cc->value.val);

        if(cc->specific.divider.is_dirty)
        {
            // Set cycle counter divider to 1
            if(cc->specific.divider.val == CYCLE_COUNTER_1_DIVIDER)
                pmcr_write(pmcr_read() & ~PMCR_D_MASK);
            // Set cycle counter divider to 64
            else if(cc->specific.divider.val == CYCLE_COUNTER_64_DIVIDER)
                pmcr_write(pmcr_read() | PMCR_D_MASK);
            else
                pr_err("pmu: Wrong cycle counter divider\n");
        }
    }
    else
    {
        // Select counter
        select_event_counter(cc->idx);

        if(cc->value.is_dirty)
            init_event_counter(cc->value.val);

        if(cc->specific.event.is_dirty)
            // Write event type
            pmxevtyper_write(cc->specific.event.val);
    }
}

static void get_event_config(void * data)
{
    struct counter_conf * cc = data;

    if(IS_CYCLE_COUNTER_IDX(cc->idx))
    {
        cc->init_value.val = get_cpu_var(cycles_counter_init_value);
        put_cpu_var(cycles_counter_init_value);

        cc->value.val = pmccntr_read();

        cc->specific.divider.val = PMCR_TO_DIVIDER(pmcr_read());
    }
    else
    {
        // Select counter
        select_event_counter(cc->idx);

        // Read event type
        cc->specific.event.val = pmxevtyper_read();

        // Read counter value
        cc->value.val = pmxevcntr_read();

        cc->init_value.val = get_cpu_var(event_counters_init_values)[cc->idx];
        put_cpu_var(cc->init_value.val);
    }

    cc->is_enabled.val = pmcntenset_read() & IDX_TO_REG_MASK(cc->idx);
    cc->has_interrupt.val = pmintenset_read() & IDX_TO_REG_MASK(cc->idx);
    cc->has_overflowed = pmovsr_read() & IDX_TO_REG_MASK(cc->idx);
}

static void sampling_free(void)
{
    if(global.samples.buffer.pages)
        free_pages((unsigned long)global.samples.buffer.pages, global.samples.buffer.order);
}

static int sampling_realloc(u64 order)
{
    void * tmp;

    tmp = (void*)__get_free_pages(GFP_KERNEL, order);
    if(tmp == NULL)
        goto err_nomem;

    sampling_free();

    global.samples.buffer.pages = tmp;
    global.samples.buffer.order = order;

    return 0;

    err_nomem:

    return -ENOMEM;
}

static int sampling_alloc(void)
{
    global.samples.buffer.pages = (void*)__get_free_pages(GFP_KERNEL, global.samples.buffer.order);
    if(global.samples.buffer.pages == NULL)
        goto err_nomem;

    return 0;

    err_nomem:

    return -ENOMEM;
}

static void sampling_init(void)
{
    int idx;
    struct counter_conf * cc;

    global.samples.buffer.iter = 0;
    global.samples.buffer.has_overflowed = 0;
    global.samples.num_irqs = 0;

    // Read cycle configuration
    cc = &global.samples.conf.cycles_cc;
    counter_conf_init(cc, CYCLE_COUNTER_IDX);
    get_event_config(cc);

    for(cc=global.samples.conf.event_ccs, idx=0; idx<NUM_EVENT_COUNTERS; cc=&global.samples.conf.event_ccs[++idx])
    {
        // Read event counter configuration
        counter_conf_init(cc, idx);
        get_event_config(cc);
    }

    global.samples.conf.cpu = global.cpu;
}

static inline void sampling_add(u32 pmovsr, u32 ip, pid_t pid)
{
    int idx;
    unsigned int next;
    struct sample * s = &global.samples.buffer.pages[global.samples.buffer.iter];
    u32 num_pages = NUM_PAGES(global.samples.buffer.order);
    u32 num_samples = NUM_SAMPLES(num_pages);

    s->pmovsr = pmovsr;
    s->cycles = pmccntr_read();
    s->ip = ip;
    s->pid = pid;

    for_each_event_counter(idx)
    {
        // Select counter
        select_event_counter(idx);

        s->event[idx] = pmxevcntr_read();
    }

    next = global.samples.buffer.iter + 1;
    global.samples.buffer.iter = next % num_samples;
    global.samples.buffer.has_overflowed = global.samples.buffer.has_overflowed | (next / num_samples);
}

static inline void sampling_configure_counters(void)
{
    int idx;
    u32 pmovsr_mask = 0;

    if(global.samples.conf.cycles_cc.is_enabled.val)
    {
        // Initialize cycle counter needed
        pmccntr_write(global.samples.conf.cycles_cc.init_value.val);

        pmovsr_mask |= IDX_TO_REG_MASK(CYCLE_COUNTER_IDX);
    }

    for_each_event_counter(idx)
    {
        if(global.samples.conf.event_ccs[idx].is_enabled.val)
        {
            pmovsr_mask |= IDX_TO_REG_MASK(idx);

            // Select counter
            select_event_counter(idx);

            // Initialize counter
            init_event_counter(global.samples.conf.event_ccs[idx].init_value.val);
        }
    }

    // Reset counters overflow
    pmovsr_write(pmovsr_mask);

}

static int sampling_print(void)
{
    int i, idx;

    if(global.samples.buffer.has_overflowed)
        goto not_enough_mem;

    for(i=0; i<global.samples.buffer.iter; i++)
    {
        struct sample * s = &global.samples.buffer.pages[i];

        pr_info("%u\t", s->cycles);
        for_each_event_counter(idx)
            pr_info("%u\t", s->event[idx]);
    }

    return 0;

    not_enough_mem:

    pr_err("Not enough memory to save all samples");

    return -1;
}

static void start(void * osef)
{
    enable_invasive_non_invasive_debug();

    // Get sampling configuration
    sampling_init();

    // Configure sampling using sampling configuration
    sampling_configure_counters();

    // Start the whole PMU
    start_pmu();
}

static void stop(void * osef)
{
    // Disable the whole PMU
    stop_pmu();

    // Add last sample
    sampling_add(pmovsr_read(), 0, current->pid);
}

// TODO check perfs + inlining
static irqreturn_t pmu_irq_handler(int irq, void *dev)
{
    u32 pmovsr;
    struct pt_regs *regs;

    stop_pmu();

    global.samples.num_irqs++;

    // Read counters overflows
    pmovsr = pmovsr_read();

    // No overflow
    if(!(pmovsr & PMOVSR_OVERFLOWED_MASK))
        goto wrong_irq;

    regs = get_irq_regs();
    sampling_add(pmovsr, instruction_pointer(regs), current->pid);

     // Re-set counters initialization value
     sampling_configure_counters();

	/*
	 * Handle the pending perf events.
	 *
	 * Note: this call *must* be run with interrupts disabled. For
	 * platforms that can have the PMU interrupts raised as an NMI, this
	 * will not work.
	 */
	irq_work_run();

    start_pmu();

    return IRQ_HANDLED;

    wrong_irq:

    pr_err("NOT armv7_pmnc_has_overflowed\n");

    start_pmu();

    return IRQ_NONE;
}

static int init_counter(struct counter_conf * cc, int cpu)
{
    return smp_call_function_single(cpu, &set_event_config, cc, 1);
}

static int get_counter(struct counter_conf * cc, int cpu)
{
    return smp_call_function_single(cpu, &get_event_config, cc, 1);
}

int pmu_start(void)
{
    int err = -EINVAL;;

    if(global.is_started)
        goto state_err;

    if(!try_module_get(THIS_MODULE))
        goto modd_err;

    err = smp_call_function_single(global.cpu, &start, NULL, 1);
    if(err != 0)
        goto error;

    global.is_started = 1;

    return 0;

    error:
    module_put(THIS_MODULE);

    state_err:
    modd_err:

    return err;
}

int pmu_stop(void)
{
    int err = -EINVAL;;

    if(!global.is_started)
        goto error;

    err = smp_call_function_single(global.cpu, &stop, NULL, 1);
    if(err != 0)
        goto error;

    global.is_started = 0;

    module_put(THIS_MODULE);

    return 0;

    error:

    return err;
}

int pmu_get_cpu(void)
{
    return global.cpu;
}

int pmu_set_cpu(int cpu)
{
    int ret;

    if(global.is_started || cpu < 0 || cpu >= num_possible_cpus())
        return -EINVAL;

    ret = irq_set_affinity_hint(global.irq_num, cpumask_of(cpu));
    if(ret != 0)
        return ret;

    global.cpu = cpu;

    return 0;
}

int pmu_is_started(void)
{
    return global.is_started;
}

int pmu_init_counter(struct counter_conf * cc)
{
    if(global.is_started)
        return -EINVAL;

    return init_counter(cc, global.cpu);
}

int pmu_get_counter(struct counter_conf * cc)
{
    return get_counter(cc, global.cpu);
}

struct samples const * pmu_get_samples(void)
{
    return &global.samples;
}

u64 pmu_get_samples_order(void)
{
    return global.samples.buffer.order;
}

int pmu_set_samples_order(u64 order)
{
    if(global.is_started)
        return -EINVAL;

    return sampling_realloc(order);
}

int pmu_init_core(struct core_conf * cc)
{
    if(global.is_started)
        return -EINVAL;

    return smp_call_function_single(cc->cpu, &set_core_config, cc, 1);
}

int pmu_get_core(struct core_conf * cc)
{
    return smp_call_function_single(cc->cpu, &get_core_config, cc, 1);
}

static int irq_alloc(void)
{
    char const * devtree_pmu_dev_name = "soc:pmu";
    const unsigned long irq_flags = IRQF_NOBALANCING | IRQF_NO_THREAD;
    struct device * pmu_dev;
    struct platform_device * plat_pmu_dev;
    int err;

    // https://www.kernel.org/doc/Documentation/IRQ-domain.txt

    // Get the platform_device struct instanciated from device
    // tree configuration and used by the PMU implementation in the
    // kernel (arch/arm/kernel/pperf_event_cpu.c)
    pmu_dev = bus_find_device_by_name(&platform_bus_type, NULL, devtree_pmu_dev_name);
    if(!pmu_dev)
    {
        err = -ENODEV;
        goto error;
    }

    plat_pmu_dev = to_platform_device(pmu_dev);
    global.irq_num = platform_get_irq(plat_pmu_dev, 0);

    if((err = request_irq(global.irq_num, pmu_irq_handler, irq_flags, "local-a9pmu", NULL)) != 0)
        goto error;

    return 0;

    error:

    return -1;
}

static int irq_free(void)
{
    int ret;

    if(global.irq_num != 0)
    {
        // Reset affinity to NULL avoiding free_irq errors
        if((ret = irq_set_affinity_hint(global.irq_num, NULL)) != 0)
            goto error;

        free_irq(global.irq_num, NULL);
    }

    return 0;

    error:

    return ret;
}

static int __init profiler_init(void)
{
    struct counter_conf counter_c = {0};
    int cpu, ret;

    counter_c.is_enabled.is_dirty = 1;
    counter_c.init_value.is_dirty = 1;
    counter_c.has_interrupt.is_dirty = 1;
    counter_c.value.is_dirty = 1;

    if((ret = sampling_alloc()) != 0)
        goto error;

    if((ret = irq_alloc()) != 0)
        goto error;

    pmu_set_cpu(0);

    // Reset counters to zero
    for_each_possible_cpu(cpu)
    {
        struct core_conf core_c;

        core_conf_init(&core_c, cpu);
        if((ret = pmu_init_core(&core_c)) != 0)
            goto error;

        counter_c.idx = CYCLE_COUNTER_IDX;
        counter_c.specific.divider.is_dirty = 1;
        counter_c.specific.divider.val = 1;
        if((ret = init_counter(&counter_c, cpu)) != 0)
            goto error;

        counter_c.specific.event.is_dirty = 1;
        counter_c.specific.event.val = 0;
        for_each_event_counter(counter_c.idx)
            if((ret = init_counter(&counter_c, cpu)) != 0)
                goto error;
    }

    if((ret = iface_init()) != 0)
        goto error;

    return 0;

    error:

    irq_free();

    sampling_free();

    iface_cleanup();

    return ret;
}

static void __exit profiler_exit(void)
{
    iface_cleanup();

    irq_free();

    sampling_free();
}

MODULE_AUTHOR("Antoine B");
MODULE_LICENSE("GPL");

module_init(profiler_init);
module_exit(profiler_exit);
