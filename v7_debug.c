#include "v7_debug.h"
#include "v7_pmu.h"

static void id_dfr0_print(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c0, c1, 2" : "=r" (val));

    pr_info("    Support de la PMU\n");
    pr_info("        ID_DFR0 = 0x%08x\n", val);

    if((val >> 24 & 0b1111) == 0b0000)
        pr_info("        PMUv2 not supported\n");
    else if((val >> 24 & 0b1111) == 0b0001)
        pr_info("        PMUv1 supported\n");
    else if((val >> 24 & 0b1111) == 0b0010)
        pr_info("        PMUv2 supported\n");
    else if((val >> 24 & 0b1111) == 0b111)
        pr_info("        PMUv2 supported\n");
    else
        pr_info("        PMU wrong value\n");

    pr_info("\n");
}

static void pmceid_print(void)
{
    u32 val;

    pr_info("    Liste des evenements implementes\n");

    asm volatile("mrc p15, 0, %0, c9, c12, 6" : "=r" (val));
    pr_info("        PMCEID0 = 0x%08x\n", val);

    asm volatile("mrc p15, 0, %0, c9, c12, 7" : "=r" (val));
    pr_info("        PMCEID1 = 0x%08x\n", val);

    pr_info("\n");
}

static void pmccntr_print(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r" (val));

    pr_info("    Valeur du compteur de cycles\n");
    pr_info("        PMCCNTR = 0x%08x\n", val);

    pr_info("\n");
}

static void pmcntenclr_print(void)
{
    u32 val;
    int idx;

    pr_info("    Si bit a 1 compteur active, sinon desactive\n");

    asm volatile("mrc p15, 0, %0, c9, c12, 2" : "=r" (val));
    pr_info("        PMCNTENCLR = 0x%08x\n", val);

    if(val & (1<<31))
        pr_info("        Cycle counter enabled\n");
    else
        pr_info("        Cycle counter disabled\n");

    for_each_event_counter(idx)
        if(val & (1<<idx))
            pr_info("        counter %d is enabled\n", idx);
        else
            pr_info("        counter %d is disabled\n", idx);

    pr_info("\n");
}

static void pmcntenset_print(void)
{
    u32 val;
    int idx;

    pr_info("    Si bit a 1 compteur active, sinon desactive\n");

    asm volatile("mrc p15, 0, %0, c9, c12, 1" : "=r" (val));
    pr_info("        PMCNTENSET = 0x%08x\n", val);

    if(val & (1<<31))
        pr_info("        Cycle counter enabled\n");
    else
        pr_info("        Cycle counter disabled\n");

    for_each_event_counter(idx)
        if(val & (1<<idx))
            pr_info("        counter %d is enabled\n", idx);
        else
            pr_info("        counter %d is disabled\n", idx);

    pr_info("\n");
}

static void pmcr_print(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c12, 0" : "=r" (val));

    pr_info("    Fournit des details sur l'implementation de la PMU\n");
    pr_info("        PMCR = 0x%08x\n", val);

    if(val & 1)
        pr_info("        All counters are enabled\n");
    else
        pr_info("        All counters are disabled\n");

    if(val & (1 << 3))
        pr_info("        Cycle counter divider 64\n");
    else
        pr_info("        Cycle counter divider 1\n");

    if(val & (1 << 4))
        pr_info("        Export events enabled\n");
    else
        pr_info("        Export events disabled\n");

    if(val & (1 << 5))
        pr_info("        Cycle counter is disabled if non-invasive debug is not permited\n");
    else
        pr_info("        Cycle counter is enabled even if non-invasive debug is not permited\n");


    pr_info("        Num of events counter %d\n", (val >> 11) & 0b11111);

    pr_info("\n");
}

static void pmintenclr_print(void)
{
    u32 val;
    int idx;

    asm volatile("mrc p15, 0, %0, c9, c14, 2" : "=r" (val));

    pr_info("    Si bit a 1 interruption compteur activee, sinon desactivee\n");
    pr_info("        PMINTENCLR = 0x%08x\n", val);

    if(val & (1<<31))
        pr_info("        Cycle counter interrupt enabled\n");
    else
        pr_info("        Cycle counter interrupt disabled\n");

    for_each_event_counter(idx)
        if(val & (1<<idx))
            pr_info("        counter %d interrupt enabled\n", idx);
        else
            pr_info("        counter %d interrupt disabled\n", idx);

    pr_info("\n");
}

static void pmintenset_print(void)
{
    u32 val;
    int idx;

    asm volatile("mrc p15, 0, %0, c9, c14, 1" : "=r" (val));

    pr_info("    Si bit a 1 interruption compteur activee, sinon desactivee\n");
    pr_info("        PMINTENSET = 0x%08x\n", val);

    if(val & (1<<31))
        pr_info("        Cycle counter interrupt enabled\n");
    else
        pr_info("        Cycle counter interrupt disabled\n");

    for_each_event_counter(idx)
        if(val & (1<<idx))
            pr_info("        counter %d interrupt enabled\n", idx);
        else
            pr_info("        counter %d interrupt disabled\n", idx);

    pr_info("\n");
}

static void pmovsr_print(void)
{
    u32 val;
    int idx;

    asm volatile("mrc p15, 0, %0, c9, c12, 3" : "=r" (val));

    pr_info("    Si bit a 1 overflow compteur\n");
    pr_info("        PMOVSR (FLAGS) = 0x%08x\n", val);

    if(val & (1<<31))
        pr_info("        Cycle counter has overflowed\n");
    else
        pr_info("        Cycle counter has not overflowed\n");

    for_each_event_counter(idx)
        if(val & (1<<idx))
            pr_info("        counter %d interrupt has overflowed\n", idx);
        else
            pr_info("        counter %d interrupt has not overflowed\n", idx);

    pr_info("\n");
}

/*static void pmovsset_print(void)
{
    u32 val;
    int idx;

    asm volatile("mrc p15, 0, %0, c9, c14, 3" : "=r" (val));

    pr_info("    Si bit a 1 overflow compteur\n");
    pr_info("        PMOVSSET = 0x%08x\n", val);

    if(val & (1<<31))
        pr_info("        Cycle counter has overflowed\n");
    else
        pr_info("        Cycle counter has not overflowed\n");

    for_each_event_counter(idx)
        if(val & (1<<idx))
            pr_info("        counter %d interrupt has overflowed\n", idx);
        else
            pr_info("        counter %d interrupt has not overflowed\n", idx);

    pr_info("\n");
}*/

static void pmuserenr_print(void)
{
    u32 val;

    asm volatile("mrc p15, 0, %0, c9, c14, 0" : "=r" (val));

    pr_info("    Acces aux compteurs en mode utilisateur\n");

    if(val & 1)
        pr_info("        Acces aux compteurs autorise en mode utilisateur\n");
    else
        pr_info("        Acces aux compteurs interdit en mode utilisateur\n");

    pr_info("\n");
}

static void pmxevcntr_print(void)
{
    u32 val;
    int idx;

    pr_info("    Lecture de la valeur des compteurs\n");

    for_each_event_counter(idx)
    {
        // Select counter
        asm volatile("mcr p15, 0, %0, c9, c12, 5" : : "r" (idx));

        asm volatile("mrc p15, 0, %0, c9, c13, 2" : "=r" (val));

        pr_info("        %d) %u\n", idx, val);
    }

    pr_info("\n");
}

static void pmxevtyper_print(void)
{
    u32 val;
    int idx;

    pr_info("    Lecture de l'evenement des compteurs\n");
    for_each_event_counter(idx)
    {
        // Select counter
        asm volatile("mcr p15, 0, %0, c9, c12, 5" : : "r" (idx));

        asm volatile("mrc p15, 0, %0, c9, c13, 1" : "=r" (val));

        pr_info("        %d) %3u %#3x\n", idx, val, val);
    }

    pr_info("\n");
}

static void print_dbgauthstatus(void)
{
    u32 val;

    pr_info("    Lecture de l'Authentication Status register\n");

    asm volatile("mrc p14, 0, %0, c7, c14, 6" : "=r" (val));

    pr_info("        DBGAUTHSTATUS: 0x%08x\n", val);

    if(val & 1)
        pr_info("        Non-secure invasive debug enabled\n");
    else
        pr_info("        Non-secure invasive debug disabled\n");

    if(val & (1 << 1))
        pr_info("        Non-secure invasive debug implemented\n");
    else
        pr_info("        Non-secure invasive debug not implemented\n");

    if(val & (1 << 2))
        pr_info("        Non-secure non-invasive debug enabled\n");
    else
        pr_info("        Non-secure non-invasive debug disabled\n");

    if(val & (1 << 3))
        pr_info("        Non-secure non-invasive debug implemented\n");
    else
        pr_info("        Non-secure non-invasive debug not implemented\n");

    if(val & (1 << 4))
        pr_info("        Secure invasive debug enabled\n");
    else
        pr_info("        Secure invasive debug disabled\n");

    if(val & (1 << 5))
        pr_info("        Secure invasive debug implemented.\n");
    else
        pr_info("        Secure invasive debug not implemented.\n");

    if(val & (1 << 6))
        pr_info("        Secure non-invasive debug enabled\n");
    else
        pr_info("        Secure non-invasive debug disabled\n");

    if(val & (1 << 7))
        pr_info("        Secure non-invasive debug implemented\n");
    else
        pr_info("        Secure non-invasive debug not implemented\n");

    pr_info("\n");
}

void v7_pmu_dump(void)
{
    u32 val;

    pr_info("====================================================\n");

    id_dfr0_print();

    pmceid_print();

    pmccntr_print();

    pmcntenset_print();

    pmcntenclr_print();

    pmcr_print();

    pmintenclr_print();

    pmintenset_print();

    pmovsr_print();

    // pmovsset_print();

    pmuserenr_print();

    pmxevcntr_print();

    pmxevtyper_print();

    asm volatile("mrc p15, 0, %0, c1, c1, 1" : "=r" (val));
    pr_info("    Lecture de SDER %u\n", val);

    print_dbgauthstatus();

    pr_info("====================================================\n");
    pr_info("\n");
}

