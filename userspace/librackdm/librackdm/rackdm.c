#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include <librackdm/rackdm.h>

static int rack_dm_ioctl(unsigned long cmd, struct rack_dm_ioctl_msg *msg)
{
    int fd, ret = 0;

    fd = open(RACK_DM_DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("failed to open RackDM deivce");
        ret = -errno;
        goto out;
    }

    if (ioctl(fd, cmd, (char *) msg) < 0) {
        perror("ioctl failed on RackDM device");
        ret = -errno;
        goto out_close_fd;
    }

    return 0;

out_close_fd:
    close(fd);
out:
    return ret;
}

struct rack_dm_region *rack_dm_open(uint64_t size)
{
    struct rack_dm_region *region;
    int fd;
    void *buf;

    region = malloc(sizeof(*region));
    if (region == NULL) {
        perror("failed to allocation memory for struct rack_dm_region");
        goto out;
    }

    fd = open(RACK_DM_DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("failed to open RackDM device");
        goto out_free_region;
    }

    buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        perror("mmap error on RackDM device");
        goto out_close_fd;
    }

    region->id = *((uint64_t *) buf);
    strcpy(region->node, (char *) (((uint64_t) buf) + sizeof(uint64_t)));
    region->size = size;
    region->buf = buf;
    memset(buf, 0, 4096UL);

    close(fd);

    return region;

out_close_fd:
    close(fd);
out_free_region:
    free(region);
out:
    return NULL;
}

struct mmap_msg {
    uint64_t region_id;
    uint64_t remote_region_id;
    char remote_node[64];
};

struct rack_dm_region *rack_dm_mmap(const char *node, uint64_t remote_region_id,
                                    uint64_t size)
{
    int ret;
    struct mmap_msg msg;
    struct rack_dm_region *region;

    region = rack_dm_open(size);
    if (region == NULL) {
        perror("error on rack_dm_open");
        goto out;
    }

    ret = rack_dm_page_init(region, 0);
    if (ret) {
        perror("error on rack_dm_page_init");
        goto out;
    }

    msg.region_id = region->id;
    msg.remote_region_id = remote_region_id;
    strcpy(msg.remote_node, node);

    ret = rack_dm_ioctl(RACK_DM_IOCTL_MMAP, (struct rack_dm_ioctl_msg *) &msg);
    if (ret) {
        perror("error on mmap ioctl");
        goto out;
    }

    return region;

out:
    return NULL;
}

struct close_msg {
    uint64_t region_id;
};

int rack_dm_close(struct rack_dm_region *region)
{
    int ret;
    struct mmap_msg msg;

    ret = munmap(region->buf, region->size);
    if (ret) {
        perror("error on munmap");
        ret = -errno;
        goto out;
    }

    memset(&msg, 0, sizeof(msg));
    msg.region_id = region->id;

    ret = rack_dm_ioctl(RACK_DM_IOCTL_CLOSE, (struct rack_dm_ioctl_msg *) &msg);
    if (ret) {
        perror("error on mmap ioctl");
        goto out;
    }

    return 0;

out:
    return ret;
}

struct page_init_msg {
    uint64_t region_id;
    uint64_t pg_index;
};

int rack_dm_page_init(struct rack_dm_region *region, uint64_t pg_index)
{
    int ret;
    struct page_init_msg msg;

    memset(&msg, 0, sizeof(msg));
    msg.region_id = region->id;
    msg.pg_index = pg_index;

    ret = rack_dm_ioctl(
            RACK_DM_IOCTL_PAGE_INIT, (struct rack_dm_ioctl_msg *) &msg);
    if (ret) {
        perror("error on mmap ioctl");
        goto out;
    }

    return 0;

out:
    return ret;
}

struct set_persistent_msg {
    uint64_t region_id;
    uint64_t val;
};

int rack_dm_set_persistent(struct rack_dm_region *region, uint64_t val)
{
    int ret;
    struct set_persistent_msg msg;

    memset(&msg, 0, sizeof(msg));
    msg.region_id = region->id;
    msg.val = val;

    ret = rack_dm_ioctl(
            RACK_DM_IOCTL_SET_PERSISTENT, (struct rack_dm_ioctl_msg *) &msg);
    if (ret) {
        perror("error on mmap ioctl");
        goto out;
    }

    return 0;

out:
    return ret;
}

struct migrate_clean_up_msg {
    uint64_t remote_region_id;
    char remote_node[64];
};

int rack_dm_migrate_clean_up(const char *node, uint64_t remote_region_id)
{
    int ret;
    struct migrate_clean_up_msg msg;

    memset(&msg, 0, sizeof(msg));

    msg.remote_region_id = remote_region_id;
    strcpy(msg.remote_node, node);

    ret = rack_dm_ioctl(
            RACK_DM_IOCTL_MIGRATE_CLEAN_UP, (struct rack_dm_ioctl_msg *) &msg);
    if (ret) {
        perror("error on mmap ioctl");
        goto out;
    }

    return 0;

out:
    return ret;
}
