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

static int rack_dm_update_node_list(void)
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

static void rack_dm_destroy_node_list(void)
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

static int alloc_remote_page_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    void *buf;
    u64 size, vaddr, paddr;
    struct ib_device *ib_dev = (struct ib_device *) ctx;

    size = *((u64 *) input);

    buf = dma_alloc_coherent(ib_dev->dma_device, size, &paddr, GFP_KERNEL);
    if (buf == NULL) {
        pr_err("failed to allocate memory for remote_page buf\n");
        ret = -ENOMEM;
        goto out;
    }

    vaddr = (u64) buf;

    DEBUG_LOG("alloc_remote_page_rpc_handler vaddr: %llu, paddr: %llu "
              "paddr: %llu, (%p)\n",
              vaddr, paddr, (u64) page_to_phys(vmalloc_to_page(buf)), ib_dev);

    *((u64 *) ((u64) output + 0UL * sizeof(u64))) = (u64) vaddr;
    *((u64 *) ((u64) output + 1UL * sizeof(u64))) = (u64) paddr;

    ret = 2UL * sizeof(u64);

out:
    return ret;
}

int alloc_remote_page(struct rack_dm_page *rpage, u64 page_size)
{
    int ret;
    struct remote_page *remote_page;
    struct rack_dm_node *node;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    u64 ptr;

    remote_page = kzalloc(sizeof(*remote_page), GFP_KERNEL);
    if (remote_page == NULL) {
        pr_err("failed to allocate memory for struct remote_page\n");
        ret = -ENOMEM;
        goto out;
    }

    node = get_node_round_robin();
    if (node == NULL) {
        pr_err("error on get_node_round_robin\n");
        ret = -EINVAL;
        goto out_free_remote_page;
    }

    send_msg = krdma_alloc_msg(node->conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out_free_remote_page;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_ALLOC_REMOTE_PAGE;

    fmt->payload = page_size;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(node->conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

   ptr = (u64) &fmt->payload;
   remote_page->conn = node->conn;
   remote_page->remote_vaddr = *((u64 *) (ptr + 0UL * sizeof(u64)));
   remote_page->remote_paddr = *((u64 *) (ptr + 1UL * sizeof(u64)));

   rpage->remote_page = remote_page;

   return 0;

out_free_msg:
    krdma_free_msg(node->conn, send_msg);
out_free_remote_page:
    kfree(remote_page);
out:
    return ret;
}

static int free_remote_page_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    u64 size, vaddr, paddr;
    struct ib_device *ib_dev = (struct ib_device *) ctx;

    size  = *((u64 *) ((u64) input + 0UL * sizeof(u64)));
    vaddr = *((u64 *) ((u64) input + 1UL * sizeof(u64)));
    paddr = *((u64 *) ((u64) input + 2UL * sizeof(u64)));

    DEBUG_LOG("free_remote_page_rpc_handler vaddr: %llu %p\n", vaddr, ib_dev);
    dma_free_coherent(ib_dev->dma_device, size, (void *) vaddr, paddr);

    return ret;
}

int free_remote_page(struct rack_dm_page *rpage)
{
    int ret;
    struct krdma_conn *conn = rpage->remote_page->conn;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    u64 ptr;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_FREE_REMOTE_PAGE;

    ptr = (u64) &fmt->payload;
    *((u64 *) ptr + 0UL * sizeof(u64)) = 4096UL;
    *((u64 *) ptr + 1UL * sizeof(u64)) = rpage->remote_page->remote_vaddr;
    *((u64 *) ptr + 2UL * sizeof(u64)) = rpage->remote_page->remote_paddr;
    fmt->size = 3UL * sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

    kfree(rpage->remote_page);
    rpage->remote_page = NULL;

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int get_region_metadata_rpc_handler(void *input, void *output, void *ctx)
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

int rack_dm_setup_rpc(void)
{
    int ret;
    struct rack_dm_node *node;
    struct ib_device *ib_dev;
    u32 rpc_id;

    DEBUG_LOG("rack_dm_setup_rpc\n");

    ret = rack_dm_update_node_list();
    if (ret) {
        pr_err("error on rack_dm_update_node_list\n");
        ret = -EINVAL;
        goto out;
    }

    node = get_node_round_robin();
    if (node == NULL) {
        pr_err("error on get_node_round_robin\n");
        ret = -EINVAL;
        goto out;
    }

    ib_dev = node->conn->cm_id->device;

    rpc_id = RACK_DM_RPC_GET_REGION_METADATA;
    ret = krdma_register_rpc(rpc_id, get_region_metadata_rpc_handler, ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out;
    }

    rpc_id = RACK_DM_RPC_ALLOC_REMOTE_PAGE;
    ret = krdma_register_rpc(rpc_id, alloc_remote_page_rpc_handler, ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_get_region_metadata;
    }

    rpc_id = RACK_DM_RPC_FREE_REMOTE_PAGE;
    ret = krdma_register_rpc(rpc_id, free_remote_page_rpc_handler, ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_alloc_remote_page;
    }

    return 0;

out_unregister_alloc_remote_page:
    krdma_unregister_rpc(RACK_DM_RPC_ALLOC_REMOTE_PAGE);
out_unregister_get_region_metadata:
    krdma_unregister_rpc(RACK_DM_RPC_GET_REGION_METADATA);
out:
    rack_dm_destroy_node_list();

    return ret;
}

void rack_dm_cleanup_rpc(void)
{
    DEBUG_LOG("rack_dm_cleanup_rpc\n");

    krdma_unregister_rpc(RACK_DM_RPC_FREE_REMOTE_PAGE);
    krdma_unregister_rpc(RACK_DM_RPC_ALLOC_REMOTE_PAGE);
    krdma_unregister_rpc(RACK_DM_RPC_GET_REGION_METADATA);
    rack_dm_destroy_node_list();
}
