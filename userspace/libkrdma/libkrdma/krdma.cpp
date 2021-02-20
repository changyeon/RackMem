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
        perror("failed to call an ioctl on krdma device");
        ret = -errno;
        goto out_close_fd;
    }

out_close_fd:
    close(fd);
out:
    return ret;
}

int libkrdma::libkrdma_accept(std::string &server, int port)
{
    int ret = 0;
    libkrdma::krdma_message_ioctl msg;

    memset(&msg, 0, sizeof(msg));
    server.copy(msg.addr, server.size(), 0);
    msg.port = port;

    ret = libkrdma_ioctl(KRDMA_IOCTL_ACCEPT, &msg);

    return ret;
}

int libkrdma::libkrdma_connect(std::string &server, int port)
{
    int ret = 0;
    libkrdma::krdma_message_ioctl msg;

    memset(&msg, 0, sizeof(msg));
    server.copy(msg.addr, server.size(), 0);
    msg.port = port;

    ret = libkrdma_ioctl(KRDMA_IOCTL_CONNECT, &msg);

    return ret;
}

void libkrdma::libkrdma_test(void)
{
    printf("libkrdma_test\n");
}
