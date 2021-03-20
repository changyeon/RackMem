#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/uaccess.h>

#include <krdma.h>
#include <rack_dm.h>
#include "ioctl.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

struct mmap_msg {
    u64 region_id;
    u64 remote_region_id;
    char remote_node[64];
};

struct close_msg {
    uint64_t region_id;
};

static long rack_dm_ioctl_close(unsigned long arg)
{
    long ret;
    struct close_msg msg;

    ret = copy_from_user(&msg, (void __user *) arg, sizeof(msg));
    if (ret) {
        pr_err("error on copy_from_user: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("rack_dm_ioctl_close region_id: %llu\n", msg.region_id);

    return 0;

out:
    return ret;
}

static long rack_dm_ioctl_mmap(unsigned long arg)
{
    long ret;
    struct mmap_msg msg;
    struct krdma_conn *conn;

    ret = copy_from_user(&msg, (void __user *) arg, sizeof(msg));
    if (ret) {
        pr_err("error on copy_from_user: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("rack_dm_ioctl_mmap region_id: %llu, remote_region_id: %llu, "
              "remote_node: %s\n", msg.region_id, msg.remote_region_id,
              msg.remote_node);

    conn = krdma_get_node(msg.remote_node);

    ret = get_region_metadata(conn, msg.remote_region_id);
    if (ret) {
        pr_err("error on get_region_metadata\n");
        goto out;
    }

    return 0;

out:
    return ret;
}

long rack_dm_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
    long ret = 0;

    DEBUG_LOG("rack_dm_ioctl cmd: %u\n", cmd);

    switch (cmd) {
    case RACK_DM_IOCTL_OPEN:
        break;
    case RACK_DM_IOCTL_CLOSE:
        ret = rack_dm_ioctl_close(arg);
        break;
    case RACK_DM_IOCTL_MMAP:
        ret = rack_dm_ioctl_mmap(arg);
        break;
    default:
        pr_err("unexpected ioctl cmd: %u\n", cmd);
        ret = -EINVAL;
        break;
    }

    return ret;
}
