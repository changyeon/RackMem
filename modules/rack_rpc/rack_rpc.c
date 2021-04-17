#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/debugfs.h>

#include <krdma.h>
#include <rack_rpc.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem RPC benchmark");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

char g_target[__NEW_UTS_LEN + 1] = "";
module_param_string(target, g_target, sizeof(g_target), 0);
MODULE_PARM_DESC(target, "target node name for the benchmark");

#define DEBUG_LOG if (g_debug) pr_info

struct krdma_conn *conn = NULL;

struct rack_rpc_ctx {
    struct dentry *root;
    struct dentry *ctrl;
    struct dentry *stat;
} rack_rpc_ctx;

static int rack_rpc_dummy_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    u64 val;

    val = *((u64 *) input);
    *((u64 *) output) = val + 1;

    ret += sizeof(u64);

    return ret;
}

int rack_rpc_dummy(u64 val)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = KRDMA_RPC_DUMMY;

    fmt->payload = val;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        ret = -EINVAL;
        goto out_free_msg;
    }

    DEBUG_LOG("val: %llu, result: %llu\n", val, fmt->payload);

    val = fmt->payload;

    krdma_free_msg(conn, send_msg);

    return val;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int register_benchmark_rpc(void)
{
    int ret;
    u32 rpc_id;

    rpc_id = RACK_RPC_DUMMY;
    ret = krdma_register_rpc(rpc_id, rack_rpc_dummy_handler, NULL);
    if (ret) {
        pr_err("failed to register rack_rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    return ret;
}

static void unregister_benchmark_rpc(void)
{
    krdma_unregister_rpc(RACK_RPC_DUMMY);
}

static int rpc_stat_show(struct seq_file *f, void *v)
{

    pr_info("rpc_stat_show\n");

    seq_printf(f, "a\n");
    seq_printf(f, "b\n");
    seq_printf(f, "c\n");
    seq_printf(f, "d\n");
    seq_printf(f, "e\n");

    return 0;
}

/**
 * ctrl_wr - read from the user buffer
 */
static ssize_t ctrl_wr(struct file *file, const char __user *buf, size_t len,
                       loff_t *ppos)
{
    ssize_t ret;
    char msg[128] = "";
    int cmd;

    ret = simple_write_to_buffer(msg, sizeof(msg), ppos, buf, len);
    sscanf(msg, "%d\n", &cmd);

    pr_info("ctrl_wr: %d\n", cmd);

    pr_info("rack_rpc_dummy: %d\n", rack_rpc_dummy(1234));

    return ret;
}

static const struct file_operations fops_ctrl = {
    .write = ctrl_wr,
};

static int rpc_stat_open(struct inode *inode, struct file *file)
{
    int ret;

    ret = single_open(file, rpc_stat_show, NULL);

    return ret;
}

static const struct file_operations fops_stat = {
    .open = rpc_stat_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release
};

static int rack_rpc_create_dbgfs(void)
{
    int ret;

    rack_rpc_ctx.root = debugfs_create_dir("rack_rpc", NULL);
    if (rack_rpc_ctx.root == NULL) {
        pr_err("failed to create dbgfs: root\n");
        ret = -EINVAL;
        goto out;
    }

    rack_rpc_ctx.ctrl = debugfs_create_file(
            "ctrl", 0220, rack_rpc_ctx.root, NULL, &fops_ctrl);
    if (rack_rpc_ctx.ctrl == NULL) {
        pr_err("failed to create dbgfs: ctrl\n");
        ret = -EINVAL;
        goto out_destroy;
    }

    rack_rpc_ctx.stat = debugfs_create_file(
            "stat", 0440, rack_rpc_ctx.root, NULL, &fops_stat);
    if (rack_rpc_ctx.stat == NULL) {
        pr_err("failed to create dbgfs: stat\n");
        ret = -EINVAL;
        goto out_destroy;
    }

    return 0;

out_destroy:
    debugfs_remove_recursive(rack_rpc_ctx.root);
out:
    return ret;
}

static void rack_rpc_destroy_dbgfs(void)
{
    if (rack_rpc_ctx.root)
        debugfs_remove_recursive(rack_rpc_ctx.root);
}

static int __init rack_rpc_init(void)
{
    int ret;

    if (strcmp(g_target, "") == 0) {
        pr_err("target node is not given\n");
        ret = -EINVAL;
        goto out;
    }

    conn = krdma_get_node_by_name(g_target);
    if (conn == NULL) {
        pr_err("target node is not connected: %s\n", g_target);
        ret = -EINVAL;
        goto out;
    }

    ret = register_benchmark_rpc();
    if (ret) {
        pr_err("error on register_benchmark_rpc\n");
        goto out;
    }

    ret = rack_rpc_create_dbgfs();
    if (ret) {
        pr_err("error on rack_rpc_create_dbgfs\n");
        goto out_unregister_rpc;
    }

    pr_info("module loaded\n");

    return 0;

out_unregister_rpc:
    unregister_benchmark_rpc();
out:
    return ret;
}

static void __exit rack_rpc_exit(void)
{
    rack_rpc_destroy_dbgfs();
    unregister_benchmark_rpc();
    pr_info("module unloaded\n");
}

module_init(rack_rpc_init);
module_exit(rack_rpc_exit);
