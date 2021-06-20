#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/utsname.h>

#include "cm.h"
#include "dbgfs.h"

#define DEVICE_NAME "krdma"
#define CLASS_NAME "krdma"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A kernel space RPC implementation on RDMA");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "debug flag");

char g_nodename[__NEW_UTS_LEN + 1] = "";
module_param_string(nodename, g_nodename, sizeof(g_nodename), 0);
MODULE_PARM_DESC(nodename, "node name");

static char g_server[12] = "0.0.0.0";
module_param_string(server, g_server, sizeof(g_server), 0);
MODULE_PARM_DESC(server, "server ip address");

static int g_port = 7472;
module_param_named(port, g_port, int, 0);
MODULE_PARM_DESC(port, "server port number");

static struct krdma_data {
    int major_number;
    struct class *class;
    struct device *device;
} krdma_data;

static struct file_operations krdma_fops = {};

static int __init krdma_init(void)
{
    int ret = -EINVAL;
    int major_number;
    struct class* krdma_class = NULL;
    struct device* krdma_device = NULL;

    /* register a character device */
    major_number = register_chrdev(0, DEVICE_NAME, &krdma_fops);
    if (major_number < 0) {
        pr_err("failed to register KRDMA character device\n");
        ret = major_number;
        goto out;
    }

    krdma_data.major_number = major_number;
    krdma_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(krdma_class)) {
        pr_err("failed to register KRDMA device class\n");
        ret = PTR_ERR(krdma_class);
        goto out_unregister_chrdev;
    }
    krdma_data.class = krdma_class;

    krdma_device = device_create(krdma_class, NULL, MKDEV(major_number, 0),
                                 NULL, DEVICE_NAME);
    if (IS_ERR(krdma_device)) {
        pr_err("failed to create device\n");
        ret = PTR_ERR(krdma_device);
        goto out_class_destroy;
    }
    krdma_data.device = krdma_device;

    /* assign a name to this node. */
    if (strcmp(g_nodename, "") == 0) {
        pr_info("a node name is not given, use the hostname: %s\n",
                utsname()->nodename);
        strcpy(g_nodename, utsname()->nodename);
    }

    /* make KRDMA ready for accepting connections */
    ret = krdma_setup(g_server, g_port);
    if (ret) {
        pr_err("error on krdma_setup\n");
        goto out_device_destroy;
    }

    ret = krdma_debugfs_setup();
    if (ret) {
        pr_err("failed to register KRDMA debugfs\n");
        goto out_krdma_cleanup;
    }

    pr_info("module loaded: %s (%s, %d)\n", g_nodename, g_server, g_port);

    return 0;

out_krdma_cleanup:
    krdma_cleanup();
out_device_destroy:
    device_destroy(krdma_data.class, MKDEV(krdma_data.major_number, 0));
out_class_destroy:
    class_destroy(krdma_class);
out_unregister_chrdev:
    unregister_chrdev(major_number, DEVICE_NAME);
out:
    return ret;
}

static void __exit krdma_exit(void)
{
    krdma_debugfs_cleanup();
    krdma_cleanup();
    device_destroy(krdma_data.class, MKDEV(krdma_data.major_number, 0));
    class_destroy(krdma_data.class);
    unregister_chrdev(krdma_data.major_number, DEVICE_NAME);

    pr_info("module unloaded\n");
}

module_init(krdma_init);
module_exit(krdma_exit);
