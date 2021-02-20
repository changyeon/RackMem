#ifndef _KRDMA_IOCTL_H_
#define _KRDMA_IOCTL_H_

#include <linux/ioctl.h>

#define KRDMA_IOCTL_ACCEPT      _IO(0xF7, 1)
#define KRDMA_IOCTL_CONNECT     _IOW(0xF7, 2, struct krdma_message_ioctl)
#define KRDMA_IOCTL_DISCONNECT  _IO(0xF7, 3)

struct krdma_message_ioctl {
    int port;
    char addr[12];
};

#endif /* _KRDMA_IOCTL_H_ */

