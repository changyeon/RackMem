#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <krdma.h>
#include <rack_dm.h>
#include "ioctl.h"
#include "debugfs.h"

#define DEVICE_NAME "rack_vm"
#define CLASS_NAME "rack_vm"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem Distributed Memory");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

int g_local_pages = 65536;
module_param_named(local_pages, g_local_pages, int, 0);
MODULE_PARM_DESC(local_pages, "the number of local pages for caching");

LIST_HEAD(to_free_remote_page_list);

static struct rack_dm_device_data {
    int major_number;
    struct class *class;
    struct device *device;
} rack_dm_device_data;


static struct file_operations rack_fops = {
    .mmap = rack_dm_mmap,
    .unlocked_ioctl = rack_dm_ioctl
};

static int __init rack_dm_init(void)
{
    int ret = 0;
    int major_number;
    struct class* rack_dm_class = NULL;
    struct device* rack_dm_device = NULL;

    /* create a character device */
    major_number = register_chrdev(0, DEVICE_NAME, &rack_fops);
    if (major_number < 0) {
        pr_err("failed to register character device\n");
        ret = major_number;
        goto out;
    }

    rack_dm_device_data.major_number = major_number;
    rack_dm_class = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(rack_dm_class)) {
        pr_err("failed to register device class\n");
        ret = PTR_ERR(rack_dm_class);
        goto out_unregister_chrdev;
    }
    rack_dm_device_data.class = rack_dm_class;
    rack_dm_device = device_create(rack_dm_class, NULL, MKDEV(major_number, 0),
                                   NULL, DEVICE_NAME);
    if (IS_ERR(rack_dm_device)) {
        pr_err("failed to create device\n");
        ret = PTR_ERR(rack_dm_device);
        goto out_class_destroy;
    }
    rack_dm_device_data.device = rack_dm_device;

    ret = rack_dm_setup_rpc();
    if (ret) {
        pr_err("failed to register rack_dm rpc calls\n");
        goto out_device_destroy;
    }

    ret = rack_dm_debugfs_setup();
    if (ret) {
        pr_err("failed to setup debugfs\n");
        goto out_cleanup_rpc;
    }

    pr_info("module loaded\n");

    return 0;

out_cleanup_rpc:
    rack_dm_cleanup_rpc();
out_device_destroy:
    device_destroy(rack_dm_device_data.class,
                   MKDEV(rack_dm_device_data.major_number, 0));
out_class_destroy:
    class_destroy(rack_dm_class);
out_unregister_chrdev:
    unregister_chrdev(major_number, DEVICE_NAME);
out:
    return ret;
}

static void free_remote_page_list_lazy(void)
{
    u64 count = 0;
    struct remote_page *node, *next;

    list_for_each_entry_safe(node, next, &to_free_remote_page_list, head) {
        free_remote_user_page(
                node->conn, 4096UL, node->remote_vaddr, node->remote_paddr);
        list_del_init(&node->head);
        kfree(node);
        count++;
    }
    pr_info("lazy free of remote pages: %llu\n", count);
}

static void __exit rack_dm_exit(void)
{
    free_remote_page_list_lazy();
    rack_dm_debugfs_cleanup();
    rack_dm_cleanup_rpc();
    device_destroy(rack_dm_device_data.class,
                   MKDEV(rack_dm_device_data.major_number, 0));
    class_destroy(rack_dm_device_data.class);
    unregister_chrdev(rack_dm_device_data.major_number, DEVICE_NAME);

    pr_info("module unloaded\n");
}

module_init(rack_dm_init);
module_exit(rack_dm_exit);
