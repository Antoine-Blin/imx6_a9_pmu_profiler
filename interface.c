#include "interface.h"
#include "main.h"
#include "v7_debug.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <asm/uaccess.h>

#define PROCFS_DIRNAME "a9pmu"

static struct {
    struct dentry * root;
} interface;

#define SP_TO_IV(PERIOD)    (HW_COUNTER_MASK - (PERIOD))
#define IV_TO_SP(VAL)       (HW_COUNTER_MASK - (VAL))

#define bool_to_str(VAL) ((VAL) ? "Y" :  "N")

/* Comes from newest version of linux kernel */
/**
 * kstrtobool - convert common user inputs into boolean values
 * @s: input string
 * @res: result
 *
 * This routine returns 0 iff the first character is one of 'Yy1Nn0', or
 * [oO][NnFf] for "on" and "off". Otherwise it will return -EINVAL.  Value
 * pointed to by res is updated upon finding a match.
 */
static int kstrtobool(const char *s, bool *res)
{
    if (!s)
        return -EINVAL;

    switch (s[0]) {
    case 'y':
    case 'Y':
    case '1':
        *res = true;
        return 0;
    case 'n':
    case 'N':
    case '0':
        *res = false;
        return 0;
    case 'o':
    case 'O':
        switch (s[1]) {
        case 'n':
        case 'N':
            *res = true;
            return 0;
        case 'f':
        case 'F':
            *res = false;
            return 0;
        default:
            break;
        }
    default:
        break;
    }

    return -EINVAL;
}

/* Comes from newest version of linux kernel */
static int __must_check kstrtobool_from_user(const char __user *ubuf, size_t count, bool *res)
{
    /* Longest string needed to differentiate, newline, terminator */
    char buf[4];

    count = min(count, sizeof(buf) - 1);
    if(copy_from_user(buf, ubuf, count))
        return -EFAULT;
    buf[count] = '\0';

    return kstrtobool(buf, res);
}

static ssize_t kbooltostr_to_user(char __user *ubuf, size_t count, loff_t *ppos, bool val)
{
    char buf[3];

    buf[0] = bool_to_str(val)[0];
    buf[1] = '\n';
    buf[2] = '\0';

    return simple_read_from_buffer(ubuf, count, ppos, buf, 2);
}

static void none_seq_stop(struct seq_file *s, void *v) {}

static int event_set(void *idx, u64 val)
{
    struct counter_conf cc;

    counter_conf_init(&cc, (int)idx);
    cc.specific.event.is_dirty = 1;
    cc.specific.event.val = (u32)val;

    return pmu_init_counter(&cc);
}

static int event_get(void *idx, u64 *val)
{
    int ret;
    struct counter_conf cc;

    counter_conf_init(&cc, (int)idx);
    ret = pmu_get_counter(&cc);
    *val = (u64)cc.specific.event.val;

    return ret;
}

DEFINE_SIMPLE_ATTRIBUTE(event_fops, event_get, event_set, "%#llx\n");

static int sampling_period_set(void *idx, u64 sampling_period)
{
    struct counter_conf cc;

    counter_conf_init(&cc, (int)idx);
    cc.init_value.is_dirty = 1;
    cc.init_value.val = SP_TO_IV(sampling_period);

    return pmu_init_counter(&cc);
}

static int sampling_period_get(void *idx, u64 *sampling_period)
{
    int ret;

    struct counter_conf cc;

    counter_conf_init(&cc, (int)idx);
    ret = pmu_get_counter(&cc);
    if(ret == 0)
        *sampling_period = IV_TO_SP(cc.init_value.val);

    return ret;
}

DEFINE_SIMPLE_ATTRIBUTE(sampling_period_fops, sampling_period_get, sampling_period_set, "%llu\n");

static ssize_t enable_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    int idx = (int)file->f_inode->i_private;
    struct counter_conf cc;

    counter_conf_init(&cc, idx);
    ret = pmu_get_counter(&cc);
    if(ret == 0)
        return kbooltostr_to_user(buf, count, ppos, cc.is_enabled.val);

    return ret;
}

static ssize_t enable_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    bool bv;
    int idx = (int)file->f_inode->i_private;

    ret = kstrtobool_from_user(buf, count, &bv);

    if(ret == 0)
    {
        struct counter_conf cc;

        counter_conf_init(&cc, idx);
        cc.is_enabled.is_dirty = 1;
        cc.is_enabled.val = bv;

        if((ret = pmu_init_counter(&cc)) == 0)
            return count;
    }

    return ret;
}

static const struct file_operations enable_fops = {
    .owner  =   THIS_MODULE,
    .read   =   enable_read,
    .write  =   enable_write
};

static ssize_t enable_interrupt_read(struct file const *file, char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    int idx = (int)file->f_inode->i_private;
    struct counter_conf cc;

    counter_conf_init(&cc, idx);
    ret = pmu_get_counter(&cc);
    if(ret == 0)
        return kbooltostr_to_user(buf, count, ppos, cc.has_interrupt.val);

    return ret;
}

static ssize_t enable_interrupt_write(struct file const *file, const char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    bool bv;
    int idx = (int)file->f_inode->i_private;

    ret = kstrtobool_from_user(buf, count, &bv);
    if(ret == 0)
    {
        struct counter_conf cc;

        counter_conf_init(&cc, idx);
        cc.has_interrupt.is_dirty = 1;
        cc.has_interrupt.val = bv;

        if((ret = pmu_init_counter(&cc)) == 0)
            return count;
    }

    return ret;
}

static const struct file_operations enable_interrupt_fops = {
    .owner  =   THIS_MODULE,
    .read   =   enable_interrupt_read,
    .write  =   enable_interrupt_write
};

static int read_counter_get(void *idx, u64 *value)
{
    int ret;
    struct counter_conf cc;

    counter_conf_init(&cc, (int)idx);
    ret = pmu_get_counter(&cc);
    if(ret == 0)
        *value = cc.value.val;

    return ret;
}

DEFINE_SIMPLE_ATTRIBUTE(read_counter_fops, read_counter_get, NULL, "%llu\n");

static ssize_t has_overflowed_read(struct file const *file, char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    int idx = (int)file->f_inode->i_private;
    struct counter_conf cc;

    counter_conf_init(&cc, idx);
    ret = pmu_get_counter(&cc);
    if(ret == 0)
        return kbooltostr_to_user(buf, count, ppos, cc.has_overflowed);

    return ret;
}

static const struct file_operations has_overflowed_fops = {
    .owner  =   THIS_MODULE,
    .read   =   has_overflowed_read,
};

static int cc_divider_set(void *idx, u64 val)
{
    struct counter_conf cc;

    if(IS_CYCLE_COUNTER_VALID_DIVIDER((u32)val))
    {
        counter_conf_init(&cc, (int)idx);
        cc.specific.divider.is_dirty = 1;
        cc.specific.divider.val = (u32)val;

        return pmu_init_counter(&cc);
    }
    else
        return -EINVAL;
}

static int cc_divider_get(void *idx, u64 *val)
{
    int ret;
    struct counter_conf cc;

    counter_conf_init(&cc, (int)idx);
    ret = pmu_get_counter(&cc);
    *val = (u64)cc.specific.divider.val;

    return ret;
}

DEFINE_SIMPLE_ATTRIBUTE(cc_divider_fops, cc_divider_get, cc_divider_set, "%llu\n");

static int create_counter_fs(struct dentry * root, int idx, char const * name)
{
    umode_t r_mode = S_IFREG | S_IRUSR;
    umode_t rw_mode = r_mode | S_IWUSR;

    struct dentry * curr, * folder;

    folder = curr = debugfs_create_dir(name, root);
    if(!folder)
        goto fail;

    if(!IS_CYCLE_COUNTER_IDX(idx))
    {
        curr = debugfs_create_file("event", rw_mode, folder, (void*)idx, &event_fops);
        if(!curr)
            goto fail;
    }
    else
    {
        curr = debugfs_create_file("divider", rw_mode, folder, (void*)idx, &cc_divider_fops);
        if(!curr)
            goto fail;
    }

    curr = debugfs_create_file("sampling_period", rw_mode, folder, (void*)idx, &sampling_period_fops);
    if(!curr)
        goto fail;

    curr = debugfs_create_file("enable", rw_mode, folder, (void*)idx, &enable_fops);
    if(!curr)
        goto fail;

    curr = debugfs_create_file("enable_interrupt", rw_mode, folder, (void*)idx, &enable_interrupt_fops);
    if(!curr)
        goto fail;

    curr = debugfs_create_file("value", r_mode, folder, (void*)idx, &read_counter_fops);
    if(!curr)
        goto fail;

    curr = debugfs_create_file("has_overflowed", r_mode, folder, (void*)idx, &has_overflowed_fops);
    if(!curr)
        goto fail;

    return 0;

    fail:

    if(folder)
        debugfs_remove_recursive(folder);

    return PTR_ERR(curr);
}

static ssize_t control_write(struct file *filp, const char __user *from, size_t count, loff_t *ppos)
{
    char buff[64];
    ssize_t ret, len;

    ret = len = simple_write_to_buffer(buff, sizeof(buff), ppos, from, count);
    if(len <= 0)
        goto err;

    if(strncmp(buff, "start", strlen("start")) == 0)
    {
        if((ret = pmu_start()) != 0)
            goto err;
    }
    else if(strncmp(buff, "stop", strlen("stop")) == 0)
    {
        if((ret = pmu_stop()) != 0)
            goto err;
    }
    else
    {
        ret = -EINVAL;
        goto err;
    }

    return len;

err:
    return ret;
}

static ssize_t control_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    char const * state = pmu_is_started() ? "started\n" : "stopped\n";

    return simple_read_from_buffer(buf, count, ppos, state, strlen(state));
}

static const struct file_operations control_fops = {
    .owner  =   THIS_MODULE,
    .read   =   control_read,
    .write  =   control_write,
};

static int cpu_set(void *data, u64 val)
{
    return pmu_set_cpu((u32)val);
}

static int cpu_get(void *data, u64 *val)
{
    *val = pmu_get_cpu();
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(cpu_fops, cpu_get, cpu_set, "%llu\n");

static void v7_pmu_dump_on_cpu(void * data)
{
    v7_pmu_dump();
}

static ssize_t dbg_set(void *data, u64 cpu)
{
    return smp_call_function_single(cpu, &v7_pmu_dump_on_cpu, NULL, 1);
}

DEFINE_SIMPLE_ATTRIBUTE(dbg_fops, NULL, dbg_set, "%llu\n");

static struct sample * get_sample(struct samples const * sams, loff_t pos)
{
    pos -= 1;
    if(pos < 0)
    {
        pr_err("Negative index should not happen\n");
        return NULL;
    }

    if(sams->buffer.has_overflowed)
        return NULL;

    return pos < sams->buffer.iter ? &sams->buffer.pages[pos] : NULL;
}

static void *samples_seq_start(struct seq_file *s, loff_t *pos)
{
    void * ret = NULL;

    if (*pos == 0)
        return SEQ_START_TOKEN;
    else
        return get_sample(s->private, *pos);

    return ret;
}

static void *samples_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    void * ret = NULL;

    ret = get_sample(s->private, *pos + 1);
    if(ret)
        ++*pos;

    return ret;
}

#define SEP "    "

static int samples_seq_show(struct seq_file *s, void *v)
{
    int idx;
    struct samples const * sams = s->private;

    if(sams->buffer.has_overflowed)
    {
        seq_printf(s, "Not enough memory to record all samples\n");
        return 0;
    }

    if(v == SEQ_START_TOKEN)
    {
        if(sams->conf.cycles_cc.is_enabled.val)
            seq_printf(s, "%10s"SEP"%10s"SEP, "cycles", "cycles_ovf");

        for_each_event_counter(idx)
        {
            if(sams->conf.event_ccs[idx].is_enabled.val)
            {
                char overflow_name[64];
                snprintf(overflow_name, sizeof(overflow_name), "%#x_ovf",
                        sams->conf.event_ccs[idx].specific.event.val);
                seq_printf(s, "%#10x"SEP"%10s"SEP, sams->conf.event_ccs[idx].specific.event.val, overflow_name);
            }
        }

        seq_printf(s, "%10s"SEP, "instr_ptr");
        seq_printf(s, "%10s"SEP, "pid");
        seq_printf(s, "\n");
    }
    else
    {
        struct sample const * sam = v;

        if(sams->conf.cycles_cc.is_enabled.val)
        {
            seq_printf(s, "%10u"SEP, sam->cycles);
            seq_printf(s, "%10u"SEP, COUNTER_HAS_OVERFLOWED(CYCLE_COUNTER_IDX, sam->pmovsr) ? 1 : 0);
        }

        for_each_event_counter(idx)
        {
            if(sams->conf.event_ccs[idx].is_enabled.val)
            {
                seq_printf(s, "%10u"SEP, sam->event[idx]);
                seq_printf(s, "%10u"SEP, COUNTER_HAS_OVERFLOWED(idx, sam->pmovsr) ? 1 : 0);
            }
        }

        seq_printf(s, "%10p"SEP, (void *)sam->ip);
        seq_printf(s, "%10u"SEP, sam->pid);
        seq_printf(s, "\n");
    }

    return 0;
}

static const struct seq_operations samples_seq_ops = {
    .start = &samples_seq_start,
    .next  = &samples_seq_next,
    .stop  = &none_seq_stop,
    .show  = &samples_seq_show
};

static int samples_open(struct inode *inode, struct file *file)
{
    int ret = seq_open(file, &samples_seq_ops);
    if(ret == 0)
    {
        struct seq_file *seq = file->private_data;
        seq->private = inode->i_private;
    }

    return ret;
}

const struct file_operations samples_fops = {
    .owner   = THIS_MODULE,
    .open    = samples_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release
};

int samples_config_show(struct seq_file *s, void *p)
{
    int idx;
    struct samples const * sams = pmu_get_samples();

    if(sams->buffer.iter > 0)
    {
        seq_printf(s, "%15s"SEP, "event");

        if(sams->conf.cycles_cc.is_enabled.val)
            seq_printf(s, SEP"%10s", "cycles");

        for_each_event_counter(idx)
            if(sams->conf.event_ccs[idx].is_enabled.val)
                seq_printf(s, SEP"%#10x", sams->conf.event_ccs[idx].specific.event.val);

        seq_printf(s, "\n");
        seq_printf(s, "%15s"SEP, "sampling_period");

        if(sams->conf.cycles_cc.is_enabled.val)
            seq_printf(s, SEP"%10u", IV_TO_SP(sams->conf.cycles_cc.init_value.val));

        for_each_event_counter(idx)
            if(sams->conf.event_ccs[idx].is_enabled.val)
                seq_printf(s, SEP"%10u", IV_TO_SP(sams->conf.event_ccs[idx].init_value.val));

        seq_printf(s, "\n");
        seq_printf(s, "%15s"SEP, "has_interrupt");

        if(sams->conf.cycles_cc.is_enabled.val)
            seq_printf(s, SEP"%10s", bool_to_str(sams->conf.cycles_cc.has_interrupt.val));

        for_each_event_counter(idx)
            if(sams->conf.event_ccs[idx].is_enabled.val)
                seq_printf(s, SEP"%10s", bool_to_str(sams->conf.event_ccs[idx].has_interrupt.val));

        seq_printf(s, "\n");
        seq_printf(s, "%15s"SEP, "cpu");

        if(sams->conf.cycles_cc.is_enabled.val)
            seq_printf(s, SEP"%10d", sams->conf.cpu);

        for_each_event_counter(idx)
            if(sams->conf.event_ccs[idx].is_enabled.val)
                seq_printf(s, SEP"%10d", sams->conf.cpu);
    }
    else
        seq_printf(s, "No sampling has been done");

    seq_printf(s, "\n");

    return 0;
}

static int samples_config_open(struct inode *inode, struct file *file)
{
    return single_open(file, &samples_config_show, NULL);
}

const struct file_operations samples_config_fops = {
    .owner   = THIS_MODULE,
    .open    = samples_config_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release
};

static int samples_num_irqs_get(void *null, u64 *value)
{
    *value = pmu_get_samples()->num_irqs;
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(samples_num_irqs_fops, samples_num_irqs_get, NULL, "%llu\n");

static ssize_t sample_has_overflowed_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    return kbooltostr_to_user(buf, count, ppos, pmu_get_samples()->buffer.has_overflowed);
}

static const struct file_operations samples_has_overflowed_fops = {
    .owner  =   THIS_MODULE,
    .read   =   sample_has_overflowed_read,
};

static int sample_length_get(void *null, u64 *value)
{
    *value = NUM_SAMPLES(NUM_PAGES(pmu_get_samples()->buffer.order));
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(sample_length_fops, sample_length_get, NULL, "%llu\n");

static int samples_order_set(void *data, u64 val)
{
    return pmu_set_samples_order(val);
}

static int samples_order_get(void *data, u64 *val)
{
    *val = pmu_get_samples_order();
    return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(samples_order_fops, samples_order_get, samples_order_set, "%llu\n");

static ssize_t enable_user_access_read(struct file const *file, char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    struct core_conf cc;

    core_conf_init(&cc, pmu_get_cpu());
    ret = pmu_get_core(&cc);
    if(ret == 0)
        return kbooltostr_to_user(buf, count, ppos, cc.is_uaccess_enabled.val);

    return ret;
}

static ssize_t enable_user_access_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    bool bv;

    ret = kstrtobool_from_user(buf, count, &bv);
    if(ret == 0)
    {
        struct core_conf cc;

        core_conf_init(&cc, pmu_get_cpu());
        cc.is_uaccess_enabled.is_dirty = 1;
        cc.is_uaccess_enabled.val = bv;

        if((ret = pmu_init_core(&cc)) == 0)
            return count;
    }

    return ret;
}

static const struct file_operations enable_user_access_fops = {
    .owner  =   THIS_MODULE,
    .read   =   enable_user_access_read,
    .write  =   enable_user_access_write
};

int iface_init(void)
{
    int idx;
    int ret;
    struct dentry * curr, * samples;
    umode_t r_mode = S_IFREG | S_IRUSR;
    umode_t w_mode = S_IFREG | S_IWUSR;
    umode_t rw_mode = r_mode | w_mode;

    interface.root = curr = debugfs_create_dir(PROCFS_DIRNAME, NULL);
    if(!interface.root)
        goto dentry_fail;

    curr = debugfs_create_file("control", rw_mode, interface.root, NULL, &control_fops);
    if (!curr)
        goto dentry_fail;

    curr = debugfs_create_file("cpu", rw_mode, interface.root, NULL, &cpu_fops);
    if (!curr)
        goto dentry_fail;

    curr = debugfs_create_file("debug", w_mode, interface.root, NULL, &dbg_fops);
    if (!curr)
        goto dentry_fail;

    curr = debugfs_create_file("enable_user_access", r_mode, interface.root, NULL, &enable_user_access_fops);
    if(!curr)
        goto dentry_fail;

    samples = curr = debugfs_create_dir("samples", interface.root);
    if(!curr)
        goto dentry_fail;

    curr = debugfs_create_file("order", rw_mode, samples, NULL, &samples_order_fops);
    if(!curr)
        goto dentry_fail;

    curr = debugfs_create_file("length", r_mode, samples, NULL, &sample_length_fops);
    if(!curr)
        goto dentry_fail;

    curr = debugfs_create_file("has_overflowed", r_mode, samples, NULL, &samples_has_overflowed_fops);
    if(!curr)
        goto dentry_fail;

    curr = debugfs_create_file("raw", r_mode, samples, (void*)pmu_get_samples(), &samples_fops);
    if(!curr)
        goto dentry_fail;

    curr = debugfs_create_file("config", r_mode, samples, NULL, &samples_config_fops);
    if(!curr)
        goto dentry_fail;

    curr = debugfs_create_file("num_irqs", r_mode, samples, NULL, &samples_num_irqs_fops);
    if(!curr)
        goto dentry_fail;

    for_each_event_counter(idx)
    {
        char name[10];

        snprintf(name, sizeof(name), "counter_%d", idx);

        ret = create_counter_fs(interface.root, idx, name);
        if(ret != 0)
            goto fail;
    }

    ret = create_counter_fs(interface.root, CYCLE_COUNTER_IDX, "cycles_counter");
    if(ret != 0)
        goto fail;

    return 0;

fail:

    debugfs_remove_recursive(interface.root);
    return ret;

dentry_fail:

    debugfs_remove_recursive(interface.root);

    return PTR_ERR(curr);
}

void iface_cleanup(void)
{
    debugfs_remove_recursive(interface.root);
}
