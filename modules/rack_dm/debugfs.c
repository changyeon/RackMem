#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "debugfs.h"

struct dentry *dbgfs_root = NULL;

struct rack_dm_region_dbgfs {
    struct rack_dm_region *region;
    spinlock_t lock;
};

static int rack_dm_stat_print(struct seq_file *f, void *v)
{
    int i, cpu;
    struct rack_dm_region *region;
    u64 sum[__NR_RACK_DM_EVENTS];

    region = (struct rack_dm_region *) f->private;

    memset(sum, 0, sizeof(sum));
    for_each_online_cpu(cpu)
        for (i = 0; i < __NR_RACK_DM_EVENTS; i++)
            sum[i] += per_cpu(region->stat->count[i], cpu);

    for (i = 0; i < __NR_RACK_DM_EVENTS; i++)
        seq_printf(f, "%s: %llu\n", rack_dm_events[i], sum[i]);

    return 0;
}

static int rack_dm_stat_open(struct inode *inode, struct file *file)
{
    int ret;
    struct dentry *dentry_root;
    struct rack_dm_region_dbgfs *region_dbgfs;

    dentry_root = file->f_path.dentry->d_parent;
    region_dbgfs = dentry_root->d_inode->i_private;

    spin_lock(&region_dbgfs->lock);
    ret = single_open(file, rack_dm_stat_print, (void *) region_dbgfs->region);
    spin_unlock(&region_dbgfs->lock);

    return ret;
}

static const struct file_operations fops_stat = {
    .open = rack_dm_stat_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release
};

int rack_dm_debugfs_add_region(struct rack_dm_region *region)
{
    int ret;
    char pid_str[32];
    struct rack_dm_region_dbgfs *region_dbgfs;

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

    return 0;

out_destroy_dbgfs:
    debugfs_remove_recursive(region->dbgfs_root);
out:
    return ret;
}

void rack_dm_debugfs_del_region(struct rack_dm_region *region)
{
    struct rack_dm_region_dbgfs *region_dbgfs;
    if (region->dbgfs_root) {
        region_dbgfs = region->dbgfs_root->d_inode->i_private;
        debugfs_remove_recursive(region->dbgfs_root);
        kfree(region_dbgfs);
    }
}

int rack_dm_debugfs_setup(void)
{
    int ret;

    dbgfs_root = debugfs_create_dir(RACK_DM_DEBUGFS_ROOT, NULL);
    if (dbgfs_root == NULL) {
        pr_err("error on debugfs_create_dir\n");
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    return ret;
}

void rack_dm_debugfs_cleanup(void)
{
    if (dbgfs_root)
        debugfs_remove_recursive(dbgfs_root);
}
