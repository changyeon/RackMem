#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <krdma.h>
#include <rack_dvs.h>
#include <rack_vm.h>
#include "debugfs.h"

#define DEVICE_NAME "rack_vm"
#define CLASS_NAME "rack_vm"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem virtual memory");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

int g_bg_reclaim = 0;
module_param_named(bg_reclaim, g_bg_reclaim, int, 0);
MODULE_PARM_DESC(bg_reclaim, "enable background page reclamation");

int g_page_size = PAGE_SIZE;
module_param_named(page_size, g_page_size, int, 0);
MODULE_PARM_DESC(page_size, "RackVM page size");

int g_local_pages = 65536;
module_param_named(local_pages, g_local_pages, int, 0);
MODULE_PARM_DESC(local_pages, "the number of local pages for caching");

unsigned long g_slab_size_bytes = 67108864UL;
module_param_named(slab_size_bytes, g_slab_size_bytes, ulong, 0);
MODULE_PARM_DESC(glab_size_bytes, "the slab size in bytes");

static struct rack_vm_device_data {
    int major_number;
    struct class *class;
    struct device *device;
} rack_vm_device_data;


static struct file_operations rack_fops = {
    .mmap = rack_vm_mmap
};

static int __init rack_vm_init(void)
{
    int ret = 0;
    int major_number;
    struct class* rack_vm_class = NULL;
    struct device* rack_vm_device = NULL;

    /* create a character device */
    major_number = register_chrdev(0, DEVICE_NAME, &rack_fops);
    if (major_number < 0) {
        pr_err("failed to register character device\n");
        ret = major_number;
        goto out;
    }

    rack_vm_device_data.major_number = major_number;
    rack_vm_class = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(rack_vm_class)) {
        pr_err("failed to register device class\n");
        ret = PTR_ERR(rack_vm_class);
        goto out_unregister_chrdev;
    }
    rack_vm_device_data.class = rack_vm_class;
    rack_vm_device = device_create(rack_vm_class, NULL, MKDEV(major_number, 0),
                                   NULL, DEVICE_NAME);
    if (IS_ERR(rack_vm_device)) {
        pr_err("failed to create device\n");
        ret = PTR_ERR(rack_vm_device);
        goto out_class_destroy;
    }
    rack_vm_device_data.device = rack_vm_device;

    ret = rack_vm_debugfs_setup();
    if (ret) {
        pr_err("failed to setup debugfs\n");
        goto out_device_destroy;
    }

    pr_info("module loaded: (%d, %d, %d, %lu)\n", g_debug, g_page_size,
            g_local_pages, g_slab_size_bytes);

    return 0;

out_device_destroy:
    device_destroy(rack_vm_device_data.class,
                   MKDEV(rack_vm_device_data.major_number, 0));
out_class_destroy:
    class_destroy(rack_vm_class);
out_unregister_chrdev:
    unregister_chrdev(major_number, DEVICE_NAME);
out:
    return ret;
}

static void __exit rack_vm_exit(void)
{
    rack_vm_debugfs_cleanup();
    device_destroy(rack_vm_device_data.class,
                   MKDEV(rack_vm_device_data.major_number, 0));
    class_destroy(rack_vm_device_data.class);
    unregister_chrdev(rack_vm_device_data.major_number, DEVICE_NAME);

    pr_info("module unloaded\n");
}

module_init(rack_vm_init);
module_exit(rack_vm_exit);
