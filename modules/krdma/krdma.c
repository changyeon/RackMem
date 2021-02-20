#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/string.h>

#include <krdma.h>
#include "dbgfs.h"
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

static struct krdma_device_data {
    int major_number;
    struct class *class;
    struct device *device;
} krdma_device_data;

struct krdma_context {
    int test;
} krdma_context;

static long krdma_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);

static struct file_operations fops = {
    .unlocked_ioctl = krdma_ioctl
};

static long krdma_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
    long ret = 0;
    struct krdma_message_ioctl msg;
    struct krdma_cb *cb = NULL;

    switch (cmd) {
    case KRDMA_IOCTL_ACCEPT:
        pr_info("krdma: ioctl ACCEPT, addr: %s, port: %d\n", g_server, g_port);
        cb = krdma_accept(g_server, g_port);
        if (cb == NULL) {
            pr_err("krdma: error krdma_accept\n");
            ret = -EINVAL;
            break;
        }
        krdma_disconnect(cb);
        break;
    case KRDMA_IOCTL_CONNECT:
        copy_from_user(&msg, (void __user *) arg, sizeof(msg));
        pr_info("krdma: ioctl CONNECT, addr: %s, port: %d\n",
                msg.addr, msg.port);
        cb = krdma_connect(msg.addr, msg.port);
        if (cb == NULL) {
            pr_err("krdma: error on krdma_connect\n");
            ret = -EINVAL;
        }
        krdma_disconnect(cb);
        break;
    case KRDMA_IOCTL_DISCONNECT:
        pr_info("krdma: ioctl DISCONNECT\n");
        break;
    default:
        return -ENOTTY;
    }

    pr_info("krdma: ioctl succesful\n");

    return ret;
}

static int __init krdma_init(void)
{
    int ret = 0;
    int major_number;
    struct class* krdma_class = NULL;
    struct device* krdma_device = NULL;

    /* create a character device */
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("krdma: failed to register character device\n");
        ret = major_number;
        goto err;
    }

    krdma_device_data.major_number = major_number;
    krdma_class = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(krdma_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        pr_err("krdma: failed to register device class\n");
        ret = PTR_ERR(krdma_class);
        goto err;
    }
    krdma_device_data.class = krdma_class;
    krdma_device = device_create(krdma_class, NULL, MKDEV(major_number, 0),
                                 NULL, DEVICE_NAME);
    if (IS_ERR(krdma_device)) {
        class_destroy(krdma_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        pr_err("krdma: failed to create device\n");
        ret = PTR_ERR(krdma_device);
        goto err;
    }
    krdma_device_data.device = krdma_device;

    /* create a debugfs */
    krdma_debugfs_setup();

    /* initialize global krdma context */
    krdma_context.test = 0;

    pr_info("krdma: module loaded (%s, %d)\n", g_server, g_port);
err:
    return ret;
}

static void __exit krdma_exit(void)
{
    /* cleanup the debugfs */
    krdma_debugfs_cleanup();

    /* destroy the character device */
    device_destroy(krdma_device_data.class,
                   MKDEV(krdma_device_data.major_number, 0));
    class_unregister(krdma_device_data.class);
    class_destroy(krdma_device_data.class);
    unregister_chrdev(krdma_device_data.major_number, DEVICE_NAME);

    /* clean up the global krdma context */

    pr_info("krdma: module unloaded\n");
}

module_init(krdma_init);
module_exit(krdma_exit);
