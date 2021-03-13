#ifndef _LIBKRDMA_KRDMA_H_
#define _LIBKRDMA_KRDMA_H_

#include <string>
#include <stdint.h>
#include <sys/ioctl.h>

#define KRDMA_IOCTL_CONNECT             _IOW(0xF7, 1, struct krdma_ioctl_address)
#define KRDMA_IOCTL_DISCONNECT           _IO(0xF7, 2)
#define KRDMA_IOCTL_RPC_STRESS_TEST     _IOR(0xF7, 3, struct krdma_ioctl_msg)

#define KRDMA_CMD_JOIN_CLUSTER      1
#define KRDMA_CMD_LEAVE_CLUSTER     2
#define KRDMA_CMD_NODE_INFO         3
#define KRDMA_CMD_EOF               4

namespace libkrdma
{

    /* for krdma_cm client and server */
    struct krdma_message {
        int cmd;
        int port;
        char addr[12];
    };

    struct krdma_ioctl_address {
        int port;
        char addr[12];
    };

    struct krdma_ioctl_msg {
        uint64_t arg0;
        uint64_t arg1;
        uint64_t arg2;
        uint64_t arg3;
        uint64_t arg4;
        uint64_t arg5;
    };

    int libkrdma_accept(std::string &server, int port);
    int libkrdma_connect(std::string &server, int port);
    int libkrdma_test(void);
}

#endif /* _LIBKRDMA_KRDMA_H */
