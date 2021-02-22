#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/uaccess.h>

#include <krdma.h>
#include "ioctl.h"

long krdma_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
    long ret = 0;
    struct krdma_message_ioctl msg;

    switch (cmd) {
    case KRDMA_IOCTL_CONNECT:
        copy_from_user(&msg, (void __user *) arg, sizeof(msg));
        DEBUG_LOG("ioctl cmd: connect, args: (%s, %d)\n", msg.addr, msg.port);
        ret = krdma_cm_connect(msg.addr, msg.port);
        if (ret) {
            pr_err("error on krdma_cm_connect\n");
            return -EINVAL;
        }
        break;
    case KRDMA_IOCTL_DISCONNECT:
    default:
        pr_err("unexpected ioctl cmd: %u\n", cmd);
        return -EINVAL;
    }

    return 0;
}
