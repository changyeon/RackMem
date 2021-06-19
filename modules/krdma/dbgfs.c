#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/debugfs.h>

#include "dbgfs.h"
#include "cm.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

static struct dentry *dbgfs_root;
static struct dentry *dbgfs_connect = NULL;
static struct dentry *dbgfs_disconnect = NULL;

static ssize_t debugfs_connect(
        struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    ssize_t ret = 0;
    char cmd[64] = "";
    char addr[16] = "0.0.0.0";
    int port = 0;

    ret = simple_write_to_buffer(cmd, len, ppos, buf, 64);

    sscanf(cmd, "%s %d\n", addr, &port);

    pr_info("connect addr: %s, port: %d\n", addr, port);

    if (krdma_connect(addr, port))
        pr_err("failed to connect the krdma node (%s, %d)\n", addr, port);

    return ret;
}

static ssize_t debugfs_disconnect(
        struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    ssize_t ret = 0;
    char nodename[64] = "";

    ret = simple_write_to_buffer(nodename, len, ppos, buf, 64);

    /* remove the trailing newline character */
    nodename[strcspn(nodename, "\n")] = 0;

    pr_info("disconnect nodename: %s\n", nodename);

    return ret;
}

static const struct file_operations fops_connect = {
    .write = debugfs_connect,
};

static const struct file_operations fops_disconnect = {
    .write = debugfs_disconnect,
};

int krdma_debugfs_setup(void)
{
    int ret;

    dbgfs_root = debugfs_create_dir("krdma", NULL);
    if (IS_ERR(dbgfs_root)) {
        pr_err("failed to create debugfs: root\n");
        ret = PTR_ERR(dbgfs_root);
        goto out;
    }

    dbgfs_connect = debugfs_create_file(
            "connect", 0660, dbgfs_root, NULL, &fops_connect);
    if (IS_ERR(dbgfs_connect)) {
        pr_err("failed to create krdma debugfs: connect\n");
        ret = PTR_ERR(dbgfs_connect);
        goto out_destroy_dbgfs;
    }

    dbgfs_disconnect = debugfs_create_file(
            "disconnect", 0660, dbgfs_root, NULL, &fops_disconnect);
    if (IS_ERR(dbgfs_disconnect)) {
        pr_err("failed to create krdma debugfs: disconnect\n");
        ret = PTR_ERR(dbgfs_disconnect);
        goto out_destroy_dbgfs;
    }

    return 0;

out_destroy_dbgfs:
    debugfs_remove_recursive(dbgfs_root);
    dbgfs_disconnect = NULL;
    dbgfs_connect = NULL;
    dbgfs_root = NULL;
out:
    return ret;
}

void krdma_debugfs_cleanup(void)
{
    DEBUG_LOG("krdma_debugfs_cleanup, dbgfs_root: %p\n", dbgfs_root);

    debugfs_remove_recursive(dbgfs_root);
    dbgfs_disconnect = NULL;
    dbgfs_connect = NULL;
    dbgfs_root = NULL;
}
