#include "migrate.h"

static int start_server(int port)
{
    int ret, fd, new_fd, len;
    int opt = 1, backlog = 128;
    uint64_t i, n, cnt, region_size = REGION_SIZE, page_size = 4096UL;
    uint64_t *ptr;
    struct sockaddr_in addr;
    struct migrate_msg msg;
    struct rack_dm_region *region;
    struct timespec t0, t1;

    memset(&msg, 0, sizeof(msg));

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == 0) {
        perror("failed to create a socket");
        ret = -errno;
        goto out;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("failed to set socket options");
        ret = -errno;
        goto out_close_fd;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("failed to bind the socket");
        ret = -errno;
        goto out_close_fd;
    }

    if (listen(fd, backlog) < 0) {
        perror("failed to call listen on the socket");
        ret = -errno;
        goto out_close_fd;
    }

    len = sizeof(addr);
    new_fd = accept(fd, (struct sockaddr *) &addr, (socklen_t *) &len);
    if (new_fd < 0) {
        ret = -errno;
        perror("failed to accept the request");
        goto out_close_fd;
    }

    ret = read(new_fd, &msg, sizeof(msg));
    if (ret < 0) {
        perror("failed to read the migration request message");
        goto out_close_new_fd;
    }

    printf("node: %s, region_id: %lu, region_size: %lu\n",
           msg.node, msg.region_id, msg.region_size);

    memset(&t0, 0, sizeof(t0));
    memset(&t1, 0, sizeof(t1));


    region = rack_dm_open(msg.region_size);
    if (region == NULL) {
        ret = -EINVAL;
        goto out;
    }
    printf("start migration\n");
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ret = rack_dm_mmap(region, msg.node, msg.region_id);
    if (ret) {
        perror("error on rack_dm_mmap");
        goto out_close_new_fd;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("migration finished\n");

    printf("migration_time size: %lu, usecs: %lu\n", REGION_SIZE,
           (uint64_t) (((10e9 * t1.tv_sec + t1.tv_nsec) - (10e9 * t0.tv_sec + t0.tv_nsec)) / 1000));

    ret = rack_dm_migrate_clean_up(msg.node, msg.region_id);
    if (ret) {
        perror("error on rack_dm_migrate_clean_up");
        goto out_close_new_fd;
    }

    cnt = 0;
    n = region_size / page_size;
    for (i = 0; i < n; i++) {
        ptr = (uint64_t *) (((uint64_t) region->buf) + i * page_size);
        if (*ptr == i)
            cnt++;
    }

    printf("migration: %s!\n", (cnt == n) ? "SUCCESS" : "FAIL");

    rack_dm_close(region);

    ret = write(new_fd, &msg, sizeof(msg));
    if (ret < 0) {
        perror("failed to write the migration completion message");
        goto out_close_new_fd;
    }

    close(new_fd);
    close(fd);

    return 0;

out_close_new_fd:
    close(new_fd);
out_close_fd:
    close(fd);
out:
    return ret;
}

int migrate_dst(int port)
{
    int ret, fd;

    fd = start_server(port);
    if (fd < 0) {
        perror("error on accept_client");
        ret = -EINVAL;
        goto out;
    }

    close(fd);

    return 0;
out:
    return ret;
}

static void print_usage(char *argv[])
{
    fprintf(stderr, "Usage: %s -s <ip> -p <port>\n", argv[0]);
}

int main(int argc, char *argv[])
{
    int opt, port = 7471;
    char server[16] = "0.0.0.0";

    while ((opt = getopt(argc, argv, "sp")) != -1) {
        switch (opt) {
        case 's':
            strcpy(server, argv[optind]);
            break;
        case 'p':
            port = strtoimax(argv[optind], NULL, 10);
            break;
        default:
            print_usage(argv);
            exit(EXIT_FAILURE);
            break;
        }
    }

    printf("ip: %s, port: %d\n", server, port);

    if (migrate_dst(port)) {
        perror("migration test failed");
        exit(EXIT_FAILURE);
    }

    return 0;
}
