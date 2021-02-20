#ifndef _LIBKRDMA_KRDMA_H_
#define _LIBKRDMA_KRDMA_H_

#include <string>
#include <sys/ioctl.h>

#define KRDMA_IOCTL_ACCEPT          _IO(0xF7, 1)
#define KRDMA_IOCTL_CONNECT         _IOW(0xF7, 2, libkrdma::krdma_message_ioctl)
#define KRDMA_IOCTL_DISCONNECT      _IO(0xF7, 3)

#define KRDMA_CMD_JOIN_CLUSTER      1
#define KRDMA_CMD_LEAVE_CLUSTER     2
#define KRDMA_CMD_NODE_INFO         3
#define KRDMA_CMD_EOF               4

namespace libkrdma
{
    struct krdma_message {
        int cmd;
        int port;
        char addr[12];
    };

    struct krdma_message_ioctl {
        int port;
        char addr[12];
    };

    int libkrdma_accept(std::string &server, int port);
    int libkrdma_connect(std::string &server, int port);
    void libkrdma_test(void);
}

#endif /* _LIBKRDMA_KRDMA_H */
