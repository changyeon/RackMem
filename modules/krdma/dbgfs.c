#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/printk.h>
#include <linux/debugfs.h>
#include <linux/string.h>

#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

static struct dentry *dbgfs_root = NULL;
static struct dentry *dbgfs_connect = NULL;
static struct dentry *dbgfs_disconnect = NULL;

static ssize_t debugfs_connect(
        struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    ssize_t ret = 0;
    char cmd[64] = {0};
    char addr[16] = "0.0.0.0";
    int port = 0;

    ret = simple_write_to_buffer(cmd, len, ppos, buf, 64);

    sscanf(cmd, "%s %d\n", addr, &port);

    pr_info("connect addr: %s, port: %d\n", addr, port);

    if (krdma_cm_connect(addr, port))
        pr_err("error on krdma_cm_connect\n");

    return ret;
}

static ssize_t debugfs_disconnect(
        struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
    ssize_t ret = 0;
    char nodename[64] = {0};
    struct krdma_conn *conn;

    ret = simple_write_to_buffer(nodename, len, ppos, buf, 64);

    /* remove the trailing newline character */
    nodename[strcspn(nodename, "\n")] = 0;

    pr_info("disconnect nodename: %s\n", nodename);
    conn = krdma_get_node_by_name(nodename);

    if (conn == NULL) {
        pr_err("error on krdma_get_node_by_name: %s\n", nodename);
        goto out;
    }

    rdma_disconnect(conn->cm_id);

out:
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
    int ret = 0;

    dbgfs_root = debugfs_create_dir("krdma", NULL);
    if (dbgfs_root == NULL) {
        pr_err("krdma: failed to create debugfs (dentry root)\n");
        ret = -EINVAL;
        goto err;
    }


    dbgfs_connect = debugfs_create_file(
            "connect", 0660, dbgfs_root, NULL, &fops_connect);
    if (dbgfs_connect == NULL) {
        pr_err("failed to create dbgfs: connect\n");
        ret = -EINVAL;
        goto out_destroy_dbgfs;
    }

    dbgfs_disconnect = debugfs_create_file(
            "disconnect", 0660, dbgfs_root, NULL, &fops_disconnect);
    if (dbgfs_disconnect == NULL) {
        pr_err("failed to create dbgfs: connect\n");
        ret = -EINVAL;
        goto out_destroy_dbgfs;
    }

    return 0;

out_destroy_dbgfs:
    debugfs_remove_recursive(dbgfs_root);
    dbgfs_disconnect= NULL;
    dbgfs_connect= NULL;
    dbgfs_root = NULL;
err:
    return ret;
}

void krdma_debugfs_cleanup(void)
{
    if (dbgfs_root)
        debugfs_remove_recursive(dbgfs_root);
}
