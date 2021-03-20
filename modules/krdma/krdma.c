#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/string.h>
#include <linux/utsname.h>

#include <krdma.h>
#include "ioctl.h"

#define DEVICE_NAME "krdma"
#define CLASS_NAME "krdma"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A kernel space RDMA library");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

static char g_server[12] = "0.0.0.0";
module_param_string(server, g_server, sizeof(g_server), 0);
MODULE_PARM_DESC(server, "server address");

static int g_port = 7472;
module_param_named(port, g_port, int, 0);
MODULE_PARM_DESC(port, "port number");

char g_nodename[__NEW_UTS_LEN + 1] = "";
module_param_string(nodename, g_nodename, sizeof(g_nodename), 0);
MODULE_PARM_DESC(nodename, "node name of this server");

static struct krdma_device_data {
    int major_number;
    struct class *class;
    struct device *device;
} krdma_device_data;

static struct file_operations fops = {
    .unlocked_ioctl = krdma_ioctl
};

void krdma_node_name(char *dst)
{
    strcpy(dst, g_nodename);
}
EXPORT_SYMBOL(krdma_node_name);

static int __init krdma_init(void)
{
    int ret = 0;
    int major_number;
    struct class* krdma_class = NULL;
    struct device* krdma_device = NULL;

    /* create a character device */
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("failed to register character device\n");
        ret = major_number;
        goto out;
    }

    krdma_device_data.major_number = major_number;
    krdma_class = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(krdma_class)) {
        pr_err("failed to register device class\n");
        ret = PTR_ERR(krdma_class);
        goto out_unregister_chrdev;
    }
    krdma_device_data.class = krdma_class;
    krdma_device = device_create(krdma_class, NULL, MKDEV(major_number, 0),
                                 NULL, DEVICE_NAME);
    if (IS_ERR(krdma_device)) {
        pr_err("failed to create device\n");
        ret = PTR_ERR(krdma_device);
        goto out_class_destroy;
    }
    krdma_device_data.device = krdma_device;

    if (strcmp(g_nodename, "") == 0) {
        pr_info("A nodename is not given. Use the hostname.\n");
        strcpy(g_nodename, utsname()->nodename);
    }

    ret = krdma_cm_setup(g_server, g_port, NULL);
    if (ret) {
        pr_err("error on krdma_listen\n");
        ret = -EINVAL;
        goto out_device_destroy;
    }

    pr_info("module loaded: %s (%s, %d)\n", g_nodename, g_server, g_port);

    return 0;

out_device_destroy:
    device_destroy(krdma_device_data.class,
                   MKDEV(krdma_device_data.major_number, 0));
out_class_destroy:
    class_destroy(krdma_class);
out_unregister_chrdev:
    unregister_chrdev(major_number, DEVICE_NAME);
out:
    return ret;
}

static void __exit krdma_exit(void)
{
    krdma_cm_cleanup();
    krdma_free_rpc_table();

    /* destroy the character device */
    device_destroy(krdma_device_data.class,
                   MKDEV(krdma_device_data.major_number, 0));
    class_destroy(krdma_device_data.class);
    unregister_chrdev(krdma_device_data.major_number, DEVICE_NAME);

    pr_info("module unloaded\n");
}

module_init(krdma_init);
module_exit(krdma_exit);
