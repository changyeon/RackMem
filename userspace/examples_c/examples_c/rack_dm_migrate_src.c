#include "migrate.h"

static int connect_server(char *server, int port)
{
    int ret = 0, fd = 0;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == 0) {
        perror("failed to create a socket");
        ret = -errno;
        goto out;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server, &addr.sin_addr) <= 0) {
        perror("failed to conver the ip address");
        ret = -errno;
        goto out_close_fd;
    }

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("failed to connect the server");
        ret = -errno;
        goto out_close_fd;
    }

    return fd;

out_close_fd:
    close(fd);
out:
    return ret;
}

static int migrate_src(char *server, int port)
{
    int ret, fd;
    uint64_t i, n, region_size = REGION_SIZE, page_size = 4096UL;
    uint64_t *ptr;
    struct migrate_msg msg;
    struct rack_dm_region *region;

    memset(&msg, 0, sizeof(msg));

    region = rack_dm_open(region_size);
    if (region == NULL) {
        ret = -EINVAL;
        goto out;
    }

    n = region_size / page_size;
    for (i = 0; i < n; i++) {
        ptr = (uint64_t *) (((uint64_t) region->buf) + i * page_size);
        *ptr = i;
    }

    for (i = 0; i < (n / 2); i++) {
        ptr = (uint64_t *) (((uint64_t) region->buf) + i * page_size);
        *ptr = i;
    }

    fd = connect_server(server, port);
    if (fd < 0) {
        perror("error on connect_server");
        ret = -EINVAL;
        goto out_close_region;
    }

    strcpy(msg.node, region->node);
    msg.region_id = region->id;
    msg.region_size = region->size;

    ret = write(fd, &msg, sizeof(msg));
    if (ret < 0) {
        perror("failed to write the migration request message");
        goto out_close_region;
    }
    ret = read(fd, &msg, sizeof(msg));
    if (ret < 0) {
        perror("failed to read the migration completion message");
        goto out_close_region;
    }

    ret = rack_dm_set_persistent(region, 1);
    if (ret) {
        perror("error on rack_dm_set_persistent");
        goto out_close_region;
    }

    close(fd);

    return 0;

out_close_region:
    rack_dm_close(region);
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
    char server[16] = "";

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

    if (strcmp("", server) == 0) {
        fprintf(stderr, "Destination ip address is required\n");
        print_usage(argv);
        exit(EXIT_FAILURE);
    }

    printf("ip: %s, port: %d\n", server, port);

    if (migrate_src(server, port)) {
        perror("migration test failed");
        exit(EXIT_FAILURE);
    }

    return 0;
}
