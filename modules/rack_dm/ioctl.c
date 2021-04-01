#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/uaccess.h>

#include <krdma.h>
#include <rack_dm.h>
#include "ioctl.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

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

struct mmap_msg {
    u64 region_id;
    u64 remote_region_id;
    char remote_node[64];
};

static long rack_dm_ioctl_mmap(unsigned long arg)
{
    long ret;
    struct mmap_msg msg;
    struct krdma_conn *conn;
    struct rack_dm_region *region;

    ret = copy_from_user(&msg, (void __user *) arg, sizeof(msg));
    if (ret) {
        pr_err("error on copy_from_user: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("rack_dm_ioctl_mmap region_id: %llu, remote_region_id: %llu, "
              "remote_node: %s\n",
              msg.region_id, msg.remote_region_id, msg.remote_node);

    conn = krdma_get_node_by_name(msg.remote_node);
    region = (struct rack_dm_region *) msg.region_id;
    ret = get_region_metadata(conn, region, msg.remote_region_id);
    if (ret) {
        pr_err("error on get_region_metadata\n");
        goto out;
    }

    return 0;

out:
    return ret;
}

struct page_init_msg {
    u64 region_id;
    u64 pg_index;;
};

static long rack_dm_ioctl_page_init(unsigned long arg)
{
    long ret;
    struct page_init_msg msg;
    struct rack_dm_region *region;
    struct rack_dm_page *rpage;

    ret = copy_from_user(&msg, (void __user *) arg, sizeof(msg));
    if (ret) {
        pr_err("error on copy_from_user: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("rack_dm_ioctl_page_init region_id: %llu, pg_index: %llu\n",
              msg.region_id, msg.pg_index);

    region = (struct rack_dm_region *) msg.region_id;
    rpage = &region->pages[msg.pg_index];

    list_del_init(&rpage->head);
    rack_dm_unmap(region, rpage);
    if (rpage->buf) {
        vfree(rpage->buf);
        rpage->buf = NULL;
        count_event(region, RACK_DM_EVENT_FREE_LOCAL_PAGE);
    }

    if (rpage->remote_page) {
        ret = free_remote_user_page(
                rpage->remote_page->conn, region->page_size,
                rpage->remote_page->remote_vaddr,
                rpage->remote_page->remote_paddr);
        if (ret) {
            pr_err("error on free_remote_page %ld\n", ret);
            goto out;
        }
        kfree(rpage->remote_page);
        rpage->remote_page = NULL;
        count_event(region, RACK_DM_EVENT_FREE_REMOTE_PAGE);
    }
    rpage->flags = RACK_DM_PAGE_IDLE;

    return 0;

out:
    return ret;
}

struct set_persistent_msg {
    u64 region_id;
    u64 val;
};

static long rack_dm_ioctl_set_persistent(unsigned long arg)
{
    long ret;
    struct set_persistent_msg msg;
    struct rack_dm_region *region;

    ret = copy_from_user(&msg, (void __user *) arg, sizeof(msg));
    if (ret) {
        pr_err("error on copy_from_user: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("rack_dm_ioctl_set_persistent region_id: %llu, val: %llu\n",
              msg.region_id, msg.val);

    region = (struct rack_dm_region *) msg.region_id;
    if (msg.val)
        region->persistent = true;
    else
        region->persistent = false;

    return 0;

out:
    return ret;
}

struct migrate_clean_up_msg {
    u64 remote_region_id;
    char remote_node[64];
};

static long rack_dm_ioctl_migrate_clean_up(unsigned long arg)
{
    long ret;
    struct migrate_clean_up_msg msg;
    struct krdma_conn *conn;

    ret = copy_from_user(&msg, (void __user *) arg, sizeof(msg));
    if (ret) {
        pr_err("error on copy_from_user: %ld\n", ret);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("rack_dm_ioctl_migrate_clean_up remote_region_id: %llu, "
              "remote_node: %s\n",
              msg.remote_region_id, msg.remote_node);

    conn = krdma_get_node_by_name(msg.remote_node);
    ret = migrate_clean_up(conn, msg.remote_region_id);
    if (ret) {
        pr_err("error on migrate_clean_up\n");
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
    case RACK_DM_IOCTL_PAGE_INIT:
        ret = rack_dm_ioctl_page_init(arg);
        break;
    case RACK_DM_IOCTL_SET_PERSISTENT:
        ret = rack_dm_ioctl_set_persistent(arg);
        break;
    case RACK_DM_IOCTL_MIGRATE_CLEAN_UP:
        ret = rack_dm_ioctl_migrate_clean_up(arg);
        break;
    default:
        pr_err("unexpected ioctl cmd: %u\n", cmd);
        ret = -EINVAL;
        break;
    }

    return ret;
}
