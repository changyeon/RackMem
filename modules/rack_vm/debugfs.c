#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#include "debugfs.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

struct dentry *dbgfs_root = NULL;

struct rack_vm_region_dbgfs {
    struct rack_vm_region *region;
    spinlock_t lock;
};

static int rack_vm_stat_print(struct seq_file *f, void *v)
{
    int i, j, cpu;
    struct rack_vm_region *region;
    u64 sum[__NR_RACK_VM_EVENTS + __NR_RACK_DVS_EVENTS];

    region = (struct rack_vm_region *) f->private;

    memset(sum, 0, sizeof(sum));
    for_each_online_cpu(cpu) {
        for (i = 0; i < __NR_RACK_VM_EVENTS; i++)
            sum[i]   += per_cpu(region->stat->count[i], cpu);
        for (j = 0; j < __NR_RACK_DVS_EVENTS; j++)
            sum[i+j] += per_cpu(region->dvsr->stat->count[j], cpu);
    }

    for (i = 0; i < __NR_RACK_VM_EVENTS; i++)
        seq_printf(f, "%s: %llu\n", rack_vm_events[i], sum[i]);
    for (j = 0; j < __NR_RACK_DVS_EVENTS; j++)
        seq_printf(f, "%s: %llu\n", rack_dvs_events[j], sum[i+j]);

    seq_printf(f, "region_size: %llu\n", region->size);
    seq_printf(f, "region_page_size: %llu\n", region->page_size);
    seq_printf(f, "page_count: %lld\n", atomic64_read(&region->page_count));
    seq_printf(f, "page_count_limit: %lld\n",
            atomic64_read(&region->page_count_limit));
    seq_printf(f, "full: %d\n", region->full);
    seq_printf(f, "active_list_size: %d\n",
            rack_vm_page_list_size(&region->active_list));
    seq_printf(f, "inactive_list_size: %d\n",
            rack_vm_page_list_size(&region->inactive_list));

    return 0;
}

static int rack_vm_stat_open(struct inode *inode, struct file *file)
{
    int ret;
    struct dentry *dentry_root;
    struct rack_vm_region_dbgfs *region_dbgfs;

    dentry_root = file->f_path.dentry->d_parent;
    region_dbgfs = dentry_root->d_inode->i_private;

    spin_lock(&region_dbgfs->lock);
    ret = single_open(file, rack_vm_stat_print, (void *) region_dbgfs->region);
    spin_unlock(&region_dbgfs->lock);

    return ret;
}

static const struct file_operations fops_stat = {
    .open = rack_vm_stat_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release
};


static ssize_t debugfs_mem_limit_read(
        struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
    ssize_t ret = 0;
    struct dentry *dentry_root;
    struct rack_vm_region_dbgfs *region_dbgfs;
    struct rack_vm_region *region;
    char mem_limit_str[64] = {0};

    dentry_root = file->f_path.dentry->d_parent;
    region_dbgfs = dentry_root->d_inode->i_private;
    region = region_dbgfs->region;

    snprintf(mem_limit_str, 64, "%lld\n",
             region->page_size * atomic64_read(&region->page_count_limit));

    ret = simple_read_from_buffer(buf, len, ppos, mem_limit_str, 64);

    return ret;
}

static ssize_t debugfs_mem_limit_write(
        struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    ssize_t ret = 0;
    struct dentry *dentry_root;
    struct rack_vm_region_dbgfs *region_dbgfs;
    struct rack_vm_region *region;
    char mem_limit_str[64] = {0};
    u64 mem_limit_bytes, mem_limit_pages;
    void *page_buf;

    dentry_root = file->f_path.dentry->d_parent;
    region_dbgfs = dentry_root->d_inode->i_private;
    region = region_dbgfs->region;

    ret = simple_write_to_buffer(mem_limit_str, len, ppos, buf, 64);

    sscanf(mem_limit_str, "%llu\n", &mem_limit_bytes);

    mem_limit_pages = mem_limit_bytes / region->page_size;
    if (mem_limit_pages > region->max_pages)
        mem_limit_pages = region->max_pages;

    spin_lock(&region_dbgfs->lock);

    /* Step 1: update the region page_count_limit */
    pr_info("update memory_limit_pages: %p (%lld -> %llu)\n",
            region, atomic64_read(&region->page_count_limit), mem_limit_pages);
    atomic64_set(&region->page_count_limit, mem_limit_pages);

    while (atomic64_read(&region->page_count) > mem_limit_pages) {
        /* try to reclaim a page from inactive_list */
        page_buf = rack_vm_reclaim_inactive(region);
        if (page_buf) {
            vfree(page_buf);
            atomic64_dec(&region->page_count);
            count_event(region, RACK_VM_EVENT_FREE_LOCAL_PAGE);
            continue;
        }

        /* reclaim a page from active_list */
        page_buf = rack_vm_reclaim_active(region);
        if (page_buf) {
            vfree(page_buf);
            atomic64_dec(&region->page_count);
            count_event(region, RACK_VM_EVENT_FREE_LOCAL_PAGE);
        }
    }

    spin_unlock(&region_dbgfs->lock);

    return ret;
}

static const struct file_operations fops_mem_limit = {
    .read  = debugfs_mem_limit_read,
    .write = debugfs_mem_limit_write,
};

int rack_vm_debugfs_add_region(struct rack_vm_region *region)
{
    int ret;
    char pid_str[32];
    struct rack_vm_region_dbgfs *region_dbgfs;

    sprintf(pid_str, "%llu", region->pid);

    region->dbgfs_root = debugfs_create_dir(pid_str, dbgfs_root);
    if (region->dbgfs_root == NULL) {
        pr_err("failed to create region debugfs: %s\n", pid_str);
        ret = -EINVAL;
        goto out;
    }

    region_dbgfs = kzalloc(sizeof(*region_dbgfs), GFP_KERNEL);
    if (region_dbgfs == NULL) {
        pr_err("failed to allocate memory for region_dbgfs\n");
        ret = -ENOMEM;
        goto out_destroy_dbgfs;
    }

    region_dbgfs->region = region;
    spin_lock_init(&region_dbgfs->lock);
    region->dbgfs_root->d_inode->i_private = (void *) region_dbgfs;

    region->dbgfs_stat = debugfs_create_file(
            "stat", 0440, region->dbgfs_root, NULL, &fops_stat);
    if (region->dbgfs_stat == NULL) {
        pr_err("failed to create region debugfs: stat\n");
        ret = -EINVAL;
        goto out_destroy_dbgfs;
    }

    region->dbgfs_mem_limit = debugfs_create_file(
            "memory_limit_bytes", 0660, region->dbgfs_root, NULL,
            &fops_mem_limit);
    if (region->dbgfs_mem_limit == NULL) {
        pr_err("failed to create region_debugfs: mem_limit\n");
        ret = -EINVAL;
        goto out_destroy_dbgfs;
    }

    return 0;

out_destroy_dbgfs:
    debugfs_remove_recursive(region->dbgfs_root);
out:
    return ret;
}

void rack_vm_debugfs_del_region(struct rack_vm_region *region)
{
    struct rack_vm_region_dbgfs *region_dbgfs;
    if (region->dbgfs_root) {
        region_dbgfs = region->dbgfs_root->d_inode->i_private;
        debugfs_remove_recursive(region->dbgfs_root);
        kfree(region_dbgfs);
    }
}

int rack_vm_debugfs_setup(void)
{
    int ret;

    dbgfs_root = debugfs_create_dir(RACK_VM_DEBUGFS_ROOT, NULL);
    if (dbgfs_root == NULL) {
        pr_err("error on debugfs_create_dir\n");
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    return ret;
}

void rack_vm_debugfs_cleanup(void)
{
    if (dbgfs_root)
        debugfs_remove_recursive(dbgfs_root);
}

