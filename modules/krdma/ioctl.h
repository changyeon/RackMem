#ifndef _KRDMA_IOCTL_H_
#define _KRDMA_IOCTL_H_

#include <linux/ioctl.h>
#include <linux/fs.h>

#define KRDMA_IOCTL_CONNECT     _IOW(0xF7, 1, struct krdma_message_ioctl)
#define KRDMA_IOCTL_DISCONNECT  _IO(0xF7, 2)

struct krdma_message_ioctl {
    int port;
    char addr[12];
};

long krdma_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);

#endif /* _KRDMA_IOCTL_H_ */

