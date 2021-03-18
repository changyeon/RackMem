#include <cstdio>
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>

#include <libkrdma/krdma.hpp>

static int libkrdma_ioctl(unsigned long cmd, void *buf)
{
    int fd, ret = 0;

    fd = open("/dev/krdma", O_RDWR);
    if (fd < 0) {
        perror("failed to open krdma device");
        ret = -errno;
        goto out;
    }

    if (ioctl(fd, cmd, buf) < 0) {
        perror("ioctl failed on krdma device");
        ret = -errno;
        goto out_close_fd;
    }

out_close_fd:
    close(fd);
out:
    return ret;
}

int libkrdma::libkrdma_connect(std::string &server, int port)
{
    int ret = 0;
    libkrdma::krdma_ioctl_address addr_info;

    memset(&addr_info, 0, sizeof(addr_info));
    server.copy(addr_info.addr, server.size(), 0);
    addr_info.port = port;

    ret = libkrdma_ioctl(KRDMA_IOCTL_CONNECT, &addr_info);

    return ret;
}

int libkrdma::libkrdma_test(void)
{
    int ret = 0;
    libkrdma::krdma_ioctl_address addr_info;

    memset(&addr_info, 0, sizeof(addr_info));

    ret = libkrdma_ioctl(KRDMA_IOCTL_RPC_STRESS_TEST, &addr_info);

    return ret;
}
