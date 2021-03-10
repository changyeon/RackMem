#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define PAGE_SIZE   4096UL

#define KB          (1UL << 10)
#define MB          (1UL << 20)
#define GB          (1UL << 30)

using namespace std;

int main(void)
{
    int ret, fd, prot, flags;
    uint64_t i, n, offset;
    size_t length = 1024UL * MB;
    void *buf;

    fd = open("/dev/rack_vm", O_RDWR);
    if (fd < 0) {
        perror("failed to open the device\n");
        ret = -errno;
        goto out;
    }

    printf("fd: %d\n", fd);

    prot = PROT_READ | PROT_WRITE;
    flags = MAP_SHARED;
    buf = mmap(NULL, length, prot, flags, fd, 0);
    if (buf == MAP_FAILED) {
        perror("mmap failed\n");
        ret = -errno;
        goto out_close_fd;
    }

    n = length / PAGE_SIZE;
    for (i = 0; i < n; i++) {
        offset = PAGE_SIZE * i;
        printf("offset: %lu\n", offset);
        *((uint64_t *) (((uint64_t) buf) + offset)) = 0xabcd1234;
    }

    munmap(buf, length);

    close(fd);

    return 0;

out_close_fd:
    close(fd);
out:
    return ret;
}
