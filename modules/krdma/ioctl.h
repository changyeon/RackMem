#ifndef _KRDMA_IOCTL_H_
#define _KRDMA_IOCTL_H_

#include <linux/ioctl.h>
#include <linux/fs.h>

struct krdma_ioctl_address {
    int port;
    char addr[12];
};

struct krdma_ioctl_msg {
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
};

#define KRDMA_IOCTL_CONNECT             _IOW(0xF7, 1, struct krdma_ioctl_address)
#define KRDMA_IOCTL_DISCONNECT           _IO(0xF7, 2)
#define KRDMA_IOCTL_RPC_STRESS_TEST     _IOR(0xF7, 3, struct krdma_ioctl_msg)

long krdma_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);

#endif /* _KRDMA_IOCTL_H_ */

