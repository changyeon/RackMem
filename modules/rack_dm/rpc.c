#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <rack_dm.h>
#include <krdma.h>
#include "rpc.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

struct rack_dm_node {
    struct list_head head;
    struct krdma_conn *conn;
};

static LIST_HEAD(node_list);
static DEFINE_SPINLOCK(node_list_lock);

int rack_dm_update_node_list(void)
{
    int i, n, ret = 0;
    struct krdma_conn *nodes[32];
    struct rack_dm_node *node, *next;

    n = krdma_get_all_nodes(nodes, 32);
    if (n == 0) {
        pr_err("no available nodes\n");
        ret = -EINVAL;
        goto out;
    }

    pr_info("available nodes: %d\n", n);
    for (i = 0; i < n; i++)
        pr_info("node: %s (%p)\n", nodes[i]->nodename, nodes[i]);

    spin_lock(&node_list_lock);

    for (i = 0; i < n; i++) {
        node = kzalloc(sizeof(*node), GFP_KERNEL);
        if (node == NULL) {
            pr_err("failed to allocate memory for rdma_node\n");
            ret = -ENOMEM;
            goto out_free_nodes;
        }
        INIT_LIST_HEAD(&node->head);
        node->conn = nodes[i];
        list_add_tail(&node->head, &node_list);
    }

    spin_unlock(&node_list_lock);

    return 0;

out_free_nodes:
    list_for_each_entry_safe(node, next, &node_list, head) {
        list_del_init(&node->head);
        kfree(node);
    }

    spin_unlock(&node_list_lock);

out:
    return ret;
}

void rack_dm_destroy_node_list(void)
{
    struct rack_dm_node *node, *next;

    spin_lock(&node_list_lock);
    list_for_each_entry_safe(node, next, &node_list, head) {
        list_del_init(&node->head);
        kfree(node);
    }
    spin_unlock(&node_list_lock);
}

static struct rack_dm_node *get_node_round_robin(void)
{
    struct rack_dm_node *node = NULL;

    spin_lock(&node_list_lock);
    if (list_empty(&node_list)) {
        pr_err("failed to get a rdma node from the list\n");
        spin_unlock(&node_list_lock);
        goto out;
    }
    node = list_first_entry(&node_list, struct rack_dm_node, head);
    list_rotate_left(&node_list);
    spin_unlock(&node_list_lock);

    return node;

out:
    return NULL;
}

static int get_region_metadata_rpc_handler(void *input, void *output)
{
    u64 *ptr;

    ptr = (u64 *) input;
    pr_info("metadata_rpc_handler: region_id: %llu\n", *ptr);
    ptr = (u64 *) output;
    *ptr = 22419;

    return 0;
}

int get_region_metadata(struct krdma_conn *conn, u64 region_id)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->rpc_id = (u64) RACK_DM_RPC_GET_REGION_METADATA;

    fmt->size = sizeof(u64);
    fmt->payload = (u64) region_id;

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        ret = -EINVAL;
        goto out_free_msg;
    }

    pr_info("get_region_metadata received msg: %llu\n", fmt->payload);

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

int rack_dm_register_rpc(void)
{
    int ret;
    u32 rpc_id;

    rpc_id = RACK_DM_RPC_GET_REGION_METADATA;
    ret = krdma_register_rpc(rpc_id, get_region_metadata_rpc_handler);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    return ret;
}

void rack_dm_unregister_rpc(void)
{
    krdma_unregister_rpc(RACK_DM_RPC_GET_REGION_METADATA);
}
