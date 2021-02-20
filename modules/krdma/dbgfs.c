#include <linux/printk.h>
#include <linux/debugfs.h>

static struct krdma_debugfs_data {
    struct dentry *dentry_root;
} krdma_debugfs_data;

int krdma_debugfs_setup(void)
{
    struct dentry *dentry;

    dentry = debugfs_create_dir("krdma", NULL);
    if (dentry == NULL) {
        pr_err("krdma: failed to create debugfs (dentry root)\n");
        krdma_debugfs_data.dentry_root = NULL;
        goto err;
    }
    krdma_debugfs_data.dentry_root = dentry;
err:
    return 1;
}

void krdma_debugfs_cleanup(void)
{
    struct dentry *dentry;

    dentry = krdma_debugfs_data.dentry_root;
    if (dentry) {
        debugfs_remove_recursive(dentry);
    }
}
