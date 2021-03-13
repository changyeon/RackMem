#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/uaccess.h>

#include <krdma.h>
#include "ioctl.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

static long krdma_ioctl_connect(unsigned long arg)
{
    long ret;
    struct krdma_ioctl_address addr_info;

    ret = copy_from_user(&addr_info, (void __user *) arg, sizeof(addr_info));
    if (ret) {
        pr_err("error on copy_from_user: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("ioctl_connect addr: %s, port: %d\n", addr_info.addr,
              addr_info.port);

    ret = krdma_cm_connect(addr_info.addr, addr_info.port);
    if (ret) {
        pr_err("error on krdma_cm_connect\n");
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    return ret;
}

static long krdma_ioctl_rpc_stress_test(unsigned long arg)
{
    long ret = 0;
    struct krdma_conn *conn;

    conn = krdma_get_node(NULL);
    if (conn == NULL) {
        pr_err("error on krdma_get_node\n");
        ret = -EINVAL;
        goto out;
    }

    ret = krdma_test_rpc_performance(conn, 10);
    if (ret) {
        pr_err("error on krdma_test_rpc_performance\n");
        goto out;
    }

    return 0;

out:
    return ret;
}

long krdma_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
    long ret = 0;

    switch (cmd) {
    case KRDMA_IOCTL_CONNECT:
        ret = krdma_ioctl_connect(arg);
        break;
    case KRDMA_IOCTL_DISCONNECT:
        break;
    case KRDMA_IOCTL_RPC_STRESS_TEST:
        ret = krdma_ioctl_rpc_stress_test(arg);
        break;
    default:
        pr_err("unexpected ioctl cmd: %u\n", cmd);
        ret = -EINVAL;
        break;
    }

    return ret;
}
