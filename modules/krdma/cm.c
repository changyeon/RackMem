#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <rdma/ib_verbs.h>
#include <linux/inet.h>
#include <linux/socket.h>

#include "cm.h"
#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

static struct rdma_cm_id *server_cm_id;

static int fill_sockaddr(struct sockaddr_storage *sin, uint8_t addr_type,
                         char *server, int port)
{
    int ret;
    u8 addr[16];

    memset(addr, 0, 16);
    memset(sin, 0, sizeof(*sin));

    if (addr_type == AF_INET) {
        struct sockaddr_in *sin4 = (struct sockaddr_in *) sin;
        sin4->sin_family = AF_INET;
        sin4->sin_port = htons(port);
        if (!in4_pton(server, -1, addr, -1, NULL)) {
            pr_err("error on in4_pton\n");
            ret = -EINVAL;
            goto out;
        }
        memcpy((void *) &sin4->sin_addr.s_addr, addr, 4);
    } else if (addr_type == AF_INET6) {
        /* TODO */
        ret = -EINVAL;
        goto out;
    } else {
        /* wrong address type! */
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    return ret;
}

int krdma_listen(char *server, int port)
{
    int ret;
    int backlog = 128;
    struct sockaddr_storage sin;

    /* NOTE: returning non-zero value from the handler will destroy cm_id. */
    server_cm_id = rdma_create_id(&init_net, NULL, NULL, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(server_cm_id)) {
        ret = PTR_ERR(server_cm_id);
        pr_err("error on rdma_create_id: %d\n", ret);
        goto out;
    }

    DEBUG_LOG("rdma_create_id: %p\n", server_cm_id);

    ret = fill_sockaddr(&sin, AF_INET, server, port);
    if (ret) {
        pr_err("error on fill_sockaddr\n");
        goto out_destroy_cm_id;
    }

    ret = rdma_bind_addr(server_cm_id, (struct sockaddr *) &sin);
    if (ret) {
        pr_err("error on rdma_bind_addr: %d\n", ret);
        goto out_destroy_cm_id;
    }

    ret = rdma_listen(server_cm_id, backlog);
    if (ret) {
        pr_err("error on rdma_listen: %d\n", ret);
        goto out_destroy_cm_id;
    }

    return 0;

out_destroy_cm_id:
    rdma_destroy_id(server_cm_id);
out:
    return ret;
}

void krdma_close(void)
{
    rdma_destroy_id(server_cm_id);
}
