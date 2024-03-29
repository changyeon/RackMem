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

static struct krdma_conn *get_node_round_robin(void)
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

    return node->conn;

out:
    return NULL;
}

static int alloc_remote_user_page_rpc_handler(void *input, void *output,
                                              void *ctx)
{
    int ret = 0;
    void *buf;
    u64 size, vaddr, paddr;
    struct ib_device *ib_dev = (struct ib_device *) ctx;
    struct payload_fmt *payload;

    payload = (struct payload_fmt *) input;
    size = payload->arg1;

    buf = vmalloc_user(size);
    if (buf == NULL) {
        pr_err("failed to allocate memory for remote_page buf\n");
        ret = -ENOMEM;
        goto out;
    }

    vaddr = (u64) buf;
    paddr = ib_dma_map_page(
            ib_dev, vmalloc_to_page(buf), 0, size, DMA_BIDIRECTIONAL);

    DEBUG_LOG("alloc_remote_user_page_rpc_handler vaddr: %llu, paddr: %llu "
              "(%p)\n", vaddr, paddr, ib_dev);

    payload = (struct payload_fmt *) output;
    payload->arg1 = vaddr;
    payload->arg2 = paddr;

    ret = 2UL * sizeof(u64);

out:
    return ret;
}

void refill_remote_page_list(struct work_struct *ws)
{
    struct rack_dm_work *work;
    struct rack_dm_region *region;
    struct rack_dm_page_list *remote_page_list;
    struct remote_page *remote_page;
    int i, ret;

    work = container_of(ws, struct rack_dm_work, ws);
    region = work->region;
    remote_page_list = &region->remote_page_list;

    for (i = 0; i < 1024; i++) {
        remote_page = kzalloc(sizeof(*remote_page), GFP_KERNEL);
        ret = alloc_remote_page(region, remote_page);
        if (ret) {
            pr_err("error on alloc_remote_user_page\n");
            break;
        }
        spin_lock(&remote_page_list->lock);
        list_add_tail(&remote_page->head, &remote_page_list->head);
        remote_page_list->size++;
        spin_unlock(&remote_page_list->lock);
    }

    count_event(region, RACK_DM_EVENT_REMOTE_PAGE_REFILL);
}

void refill_remote_page_list_bulk(struct work_struct *ws)
{
    struct rack_dm_work *work;
    struct rack_dm_region *region;
    struct rack_dm_page_list *remote_page_list;
    struct remote_page **remote_page_array;
    int i, j, ret;

    work = container_of(ws, struct rack_dm_work, ws);
    region = work->region;
    remote_page_list = &region->remote_page_list;

    remote_page_array = (struct remote_page **) vmalloc(
            250 * sizeof(struct remote_page *));
    if (remote_page_array == NULL) {
        pr_err("failed to allocate memory for remote_page_array\n");
        return;
    }

    for (i = 0; i < 64; i++) {
        memset(remote_page_array, 0x0, 250 * sizeof(struct remote_page *));
        for (j = 0; j < 250; j++) {
            remote_page_array[j] = kzalloc(
                    sizeof(struct remote_page), GFP_KERNEL);
            if (remote_page_array[j] == NULL) {
                pr_err("failed to allocate memory for struct remote_page\n");
                goto out;
            }
        }
        ret = alloc_remote_page_bulk(region, remote_page_array, 250);
        if (ret) {
            pr_err("error on alloc_remote_page_bulk\n");
            goto out;
        }
        spin_lock(&remote_page_list->lock);
        for (j = 0; j < 250; j++) {
            list_add_tail(&remote_page_array[j]->head, &remote_page_list->head);
            remote_page_list->size++;
        }
        spin_unlock(&remote_page_list->lock);
    }

out:
    vfree(remote_page_array);
    count_event(region, RACK_DM_EVENT_REMOTE_PAGE_REFILL_BULK);
}

int alloc_remote_page(struct rack_dm_region *region,
                      struct remote_page *remote_page)
{
    int ret;
    struct krdma_conn *conn;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;

    /* slow path */
    conn = get_node_round_robin();
    if (conn == NULL) {
        pr_err("error on get_node_round_robin\n");
        ret = -EINVAL;
        goto out_free_remote_page;
    }

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out_free_remote_page;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_ALLOC_REMOTE_USER_PAGE;

    fmt->payload = region->page_size;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

    payload = (struct payload_fmt *) &fmt->payload;
    remote_page->conn = conn;
    remote_page->remote_vaddr = payload->arg1;
    remote_page->remote_paddr = payload->arg2;
    INIT_LIST_HEAD(&remote_page->head);

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out_free_remote_page:
    kfree(remote_page);
    return ret;
}

int alloc_remote_user_page(struct rack_dm_region *region,
                           struct rack_dm_page *rpage, char *target_node)
{
    int ret;
    struct remote_page *remote_page = NULL;
    struct krdma_conn *conn;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;
    struct rack_dm_page_list *remote_page_list = &region->remote_page_list;

    /* fast path */
    spin_lock(&remote_page_list->lock);
    if (remote_page_list->size > 0) {
        remote_page = list_first_entry(
                &remote_page_list->head, struct remote_page, head);
        list_del_init(&remote_page->head);
        remote_page_list->size--;
    }
    if (remote_page_list->size < 1024) {
        /* launch a background task to add remote pages to the list */
        schedule_work(&region->remote_page_work.ws);
    }
    spin_unlock(&remote_page_list->lock);

    if (remote_page) {
        count_event(region, RACK_DM_EVENT_ALLOC_REMOTE_PAGE_FAST);
        goto success;
    }

    /* slow path */
    remote_page = kzalloc(sizeof(*remote_page), GFP_KERNEL);
    if (remote_page == NULL) {
        pr_err("failed to allocate memory for struct remote_page\n");
        ret = -ENOMEM;
        goto out;
    }

    if (target_node == NULL)
        conn = get_node_round_robin();
    else
        conn = krdma_get_node_by_name(target_node);

    if (conn == NULL) {
        pr_err("failed to get node %s\n", target_node);
        ret = -EINVAL;
        goto out_free_remote_page;
    }

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out_free_remote_page;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_ALLOC_REMOTE_USER_PAGE;

    fmt->payload = region->page_size;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

    payload = (struct payload_fmt *) &fmt->payload;
    remote_page->conn = conn;
    remote_page->remote_vaddr = payload->arg1;
    remote_page->remote_paddr = payload->arg2;
    INIT_LIST_HEAD(&remote_page->head);

    krdma_free_msg(conn, send_msg);
    count_event(region, RACK_DM_EVENT_ALLOC_REMOTE_PAGE_SLOW);

success:
    rpage->remote_page = remote_page;

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out_free_remote_page:
    kfree(remote_page);
out:
    return ret;
}

static int free_remote_user_page_rpc_handler(void *input, void *output,
                                             void *ctx)
{
    int ret = 0;
    u64 size, vaddr, paddr;
    struct ib_device *ib_dev = (struct ib_device *) ctx;
    struct payload_fmt *payload;

    payload = (struct payload_fmt *) input;
    size  = payload->arg1;
    vaddr = payload->arg2;
    paddr = payload->arg3;

    DEBUG_LOG("free_remote_user_page_rpc_handler size: %llu, vaddr: %llu, "
              "paddr: %llu (%p)\n", size, vaddr, paddr, (void *) ib_dev);

    ib_dma_unmap_page(ib_dev, paddr, size, DMA_BIDIRECTIONAL);
    vfree((void *) vaddr);

    return ret;
}

int free_remote_user_page(struct krdma_conn *conn, u64 size, u64 remote_vaddr,
                          u64 remote_paddr)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_FREE_REMOTE_USER_PAGE;

    payload = (struct payload_fmt *) &fmt->payload;
    payload->arg1 = size;
    payload->arg2 = remote_vaddr;
    payload->arg3 = remote_paddr;
    fmt->size = 3UL * sizeof(u64);

    DEBUG_LOG("free_remote_user_page size: %llu, vaddr: %llu, paddr: %llu\n",
              payload->arg1, payload->arg2, payload->arg3);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

struct remote_page_info {
    u64 vaddr;
    u64 paddr;
};

static int alloc_remote_page_bulk_rpc_handler(void *input, void *output,
                                              void *ctx)
{
    int ret = 0;
    u64 i, n;
    void *buf;
    struct ib_device *ib_dev = (struct ib_device *) ctx;
    struct payload_fmt *payload;
    struct remote_page_info *info;

    payload = (struct payload_fmt *) input;
    n = payload->arg1;

    info = (struct remote_page_info *) output;
    for (i = 0; i < n; i++) {
        buf = vmalloc_user(PAGE_SIZE);
        if (buf == NULL) {
            pr_err("failed to allocate memory for remote_page buf\n");
            ret = -ENOMEM;
            goto out;
        }
        info[i].vaddr = (u64) buf;
        info[i].paddr = ib_dma_map_page(
                ib_dev, vmalloc_to_page(buf), 0, PAGE_SIZE, DMA_BIDIRECTIONAL);

        DEBUG_LOG("alloc_remote_page_bulk_rpc_handler vaddr: %llu, paddr: %llu "
                  "(%p)\n", info[i].vaddr, info[i].paddr, ib_dev);
    }
    ret = n * 2UL * sizeof(u64);

out:
    return ret;
}

int alloc_remote_page_bulk(struct rack_dm_region *region,
                           struct remote_page **remote_page_array, int n)
{
    int i, ret = 0;
    struct remote_page *remote_page;
    struct krdma_conn *conn;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct remote_page_info *info;

    conn = get_node_round_robin();
    if (conn == NULL) {
        pr_err("error on get_node_round_robin\n");
        ret = -EINVAL;
        goto out;
    }

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_ALLOC_REMOTE_PAGE_BULK;

    fmt->payload = (u64) n;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

    info = (struct remote_page_info *) &fmt->payload;
    for (i = 0; i < n; i++) {
        remote_page = remote_page_array[i];
        remote_page->conn = conn;
        remote_page->remote_vaddr = info[i].vaddr;
        remote_page->remote_paddr = info[i].paddr;
        INIT_LIST_HEAD(&remote_page->head);
    }

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int free_remote_page_bulk_rpc_handler(void *input, void *output,
                                             void *ctx)
{
    return 0;
}

int free_remote_page_bulk(struct rack_dm_region *region,
                          struct rack_dm_page *rpage)
{
    return 0;
}

static int alloc_remote_memory_rpc_handler(void *input, void *output,
                                           void *ctx)
{
    int ret = 0;
    struct payload_fmt *payload;
    void *buf;
    u64 size, vaddr, paddr;
    struct ib_device *ib_dev = (struct ib_device *) ctx;

    payload = (struct payload_fmt *) input;
    size = payload->arg1;

    buf = dma_alloc_coherent(ib_dev->dma_device, size, &paddr, GFP_KERNEL);
    if (buf == NULL) {
        pr_err("failed to allocate RDMA buffer\n");
        ret = -ENOMEM;
        goto out;
    }

    vaddr = (u64) buf;

    DEBUG_LOG("alloc_remote_memory_rpc_handler size: %llu, vaddr: %llu, "
              "paddr: %llu (%p)\n", size, vaddr, paddr, ib_dev);

    payload = (struct payload_fmt *) output;
    payload->arg1 = vaddr;
    payload->arg2 = paddr;

    ret = 2UL * sizeof(u64);

out:
    return ret;
}

int alloc_remote_memory(struct krdma_conn *conn, u64 size, u64 *vaddr,
                        u64 *paddr)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_ALLOC_REMOTE_MEMORY;

    payload = (struct payload_fmt *) &fmt->payload;
    payload->arg1 = size;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

    *vaddr = payload->arg1;
    *paddr = payload->arg2;

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int free_remote_memory_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    u64 size, vaddr, paddr;
    struct ib_device *ib_dev = (struct ib_device *) ctx;
    struct payload_fmt *payload;

    payload = (struct payload_fmt *) input;
    size  = payload->arg1;
    vaddr = payload->arg2;
    paddr = payload->arg3;

    DEBUG_LOG("free_remote_memory_rpc_handler size: %llu, vaddr: %llu, "
              "paddr: %llu (%p)\n", size, vaddr, paddr, (void *) ib_dev);

    dma_free_coherent(ib_dev->dma_device, size, (void *) vaddr, paddr);

    return ret;
}

int free_remote_memory(struct krdma_conn *conn, u64 size, u64 remote_vaddr,
                       u64 remote_paddr)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_FREE_REMOTE_MEMORY;

    payload = (struct payload_fmt *) &fmt->payload;
    payload->arg1 = size;
    payload->arg2 = remote_vaddr;
    payload->arg3 = remote_paddr;
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

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

#define MB 1048576UL
#define GB 1073741824UL

struct page_metadata {
    u32 index;
    u32 hash;
    u64 paddr;
    u64 vaddr;
};

static int get_region_metadata_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    u32 local_node_hash;
    u64 i, cnt, size, vaddr, paddr, pg_node_hash, pg_vaddr, pg_paddr;
    void *rdma_buf;
    struct payload_fmt *payload;
    struct rack_dm_region *region;
    struct rack_dm_page *rpage;
    struct ib_device *ib_dev = (struct ib_device *) ctx;
    u64 remote_cnt = 0, inactive_cnt = 0, active_cnt = 0, precopy_cnt = 0;

    DEBUG_LOG("[!!!] get_region_metadata_rpc_handler\n");

    payload = (struct payload_fmt *) input;
    region = (struct rack_dm_region *) payload->arg1;

    size = (region->max_pages + 1) * sizeof(struct page_metadata);
    rdma_buf = dma_alloc_coherent(ib_dev->dma_device, size, &paddr, GFP_KERNEL);
    if (rdma_buf == NULL) {
        pr_err("failed to allocate memory for region metadata buffer\n");
        ret = -EINVAL;
        goto out;
    }

    local_node_hash = krdma_local_node_hash();
    cnt = 1;

    for (i = 0; i < region->max_pages; i++) {
        rpage = &region->pages[i];

        if ((rpage->buf != NULL) || (rpage->remote_page == NULL))
            continue;

        pg_node_hash = rpage->remote_page->conn->nodename_hash;
        pg_vaddr = rpage->remote_page->remote_vaddr;
        pg_paddr = rpage->remote_page->remote_paddr;

        ((struct page_metadata *) rdma_buf + cnt)->index = rpage->index;
        ((struct page_metadata *) rdma_buf + cnt)->hash  = pg_node_hash;
        ((struct page_metadata *) rdma_buf + cnt)->vaddr = pg_vaddr;
        ((struct page_metadata *) rdma_buf + cnt)->paddr = pg_paddr;
        cnt++;
        remote_cnt++;
    }

    list_for_each_entry(rpage, &region->inactive_list.head, head) {
        if (rpage->remote_page) {
            pg_node_hash = rpage->remote_page->conn->nodename_hash;
            pg_vaddr = rpage->remote_page->remote_vaddr;
            pg_paddr = rpage->remote_page->remote_paddr;
            kfree(rpage->remote_page);
            rpage->remote_page = NULL;
        } else {
            pr_err("it should not be printed!!!\n");
            pg_node_hash = local_node_hash;
            pg_vaddr = (u64) rpage->buf;
            pg_paddr = ib_dma_map_page(
                    ib_dev, vmalloc_to_page(rpage->buf), 0, 4096,
                    DMA_BIDIRECTIONAL);
        }
        ((struct page_metadata *) rdma_buf + cnt)->index = rpage->index;
        ((struct page_metadata *) rdma_buf + cnt)->hash  = pg_node_hash;
        ((struct page_metadata *) rdma_buf + cnt)->vaddr = pg_vaddr;
        ((struct page_metadata *) rdma_buf + cnt)->paddr = pg_paddr;
        inactive_cnt++;
        cnt++;
    }

    list_for_each_entry(rpage, &region->active_list.head, head) {
        /*if (rpage->remote_page) {*/
        if (false) {
            /* NOTE: PRECOPY_STOP OPTIMIZATION */
            rack_dm_writeback(region, rpage);
            pg_node_hash = rpage->remote_page->conn->nodename_hash;
            pg_vaddr = rpage->remote_page->remote_vaddr;
            pg_paddr = rpage->remote_page->remote_paddr;
            kfree(rpage->remote_page);
            rpage->remote_page = NULL;
            count_event(region, RACK_DM_EVENT_PRECOPY_PAGES);
        } else {
            pg_node_hash = local_node_hash;
            pg_vaddr = (u64) rpage->buf;
            pg_paddr = ib_dma_map_page(
                    ib_dev, vmalloc_to_page(rpage->buf), 0, 4096,
                    DMA_BIDIRECTIONAL);
        }
        ((struct page_metadata *) rdma_buf + cnt)->index = rpage->index;
        ((struct page_metadata *) rdma_buf + cnt)->hash  = pg_node_hash;
        ((struct page_metadata *) rdma_buf + cnt)->vaddr = pg_vaddr;
        ((struct page_metadata *) rdma_buf + cnt)->paddr = pg_paddr;
        active_cnt++;
        cnt++;
    }
    pr_info("migration remote: %llu, inactive: %llu, active: %llu, "
            "precopy: %llu\n", remote_cnt, inactive_cnt, active_cnt,
            precopy_cnt);

    ((u64 *) rdma_buf)[0] = remote_cnt;
    ((u64 *) rdma_buf)[1] = inactive_cnt;
    ((u64 *) rdma_buf)[2] = active_cnt;

    vaddr = (u64) rdma_buf;
    payload = (struct payload_fmt *) output;
    payload->arg1 = cnt * sizeof(struct page_metadata);
    payload->arg2 = vaddr;
    payload->arg3 = paddr;

    ret = 3UL * sizeof(u64);

    return ret;

out:
    return ret;
}

int get_region_metadata(struct krdma_conn *conn,
                        struct rack_dm_region *region, u64 remote_region_id)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;
    u64 size, remote_vaddr, remote_paddr;
    void *rdma_buf;
    u64 rdma_buf_dma_addr;
    u64 i, n, pg_index, pg_node_hash, pg_vaddr, pg_paddr;
    u32 local_node_hash;
    struct rack_dm_page *rpage;
    struct krdma_conn *pg_conn;
    struct remote_page *remote_page;
    u64 remote_cnt, inactive_cnt, active_cnt, prefetch_cnt;
    u64 *prefetch_pages;

    DEBUG_LOG("[!!!] get_region_metadata\n");

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_GET_REGION_METADATA;

    payload = (struct payload_fmt *) &fmt->payload;
    payload->arg1 = remote_region_id;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

    payload = (struct payload_fmt *) &fmt->payload;
    size = payload->arg1;
    remote_vaddr = payload->arg2;
    remote_paddr = payload->arg3;

    rdma_buf = dma_alloc_coherent(
            conn->cm_id->device->dma_device, size, &rdma_buf_dma_addr,
            GFP_KERNEL);
    if (rdma_buf == NULL) {
        pr_err("failed to allocate memory for local region metadata buffer\n");
        ret = -ENOMEM;
        goto out_free_remote_memory;
    }

    ret = rack_dm_rdma(conn, rdma_buf_dma_addr, remote_paddr, size, READ);
    if (ret) {
        pr_err("error on rack_dm_rdma\n");
        goto out_free_dma_buf;
    }

    remote_cnt   = ((u64 *) rdma_buf)[0];
    inactive_cnt = ((u64 *) rdma_buf)[1];
    active_cnt   = ((u64 *) rdma_buf)[2];

    pr_info("migration remote: %llu, inactive: %llu, active: %llu\n",
            remote_cnt, inactive_cnt, active_cnt);

    prefetch_pages = vzalloc(sizeof(u64) * active_cnt);
    if (prefetch_pages == NULL) {
        pr_err("failed to allocate memory for prefetch_pages\n");
        goto out_free_dma_buf;
    }
    prefetch_cnt = 0;

    local_node_hash = krdma_local_node_hash();
    n = (size / sizeof(struct page_metadata)) - 1;
    for (i = 0; i < n; i++) {
        pg_index     = ((struct page_metadata *) rdma_buf + (i + 1))->index;
        pg_node_hash = ((struct page_metadata *) rdma_buf + (i + 1))->hash;
        pg_vaddr     = ((struct page_metadata *) rdma_buf + (i + 1))->vaddr;
        pg_paddr     = ((struct page_metadata *) rdma_buf + (i + 1))->paddr;

        rpage = &region->pages[pg_index];
        if (pg_node_hash == local_node_hash) {
            rpage->buf = (void *) pg_vaddr;
            ib_dma_unmap_page(
                    conn->cm_id->device, pg_paddr, region->page_size,
                    DMA_BIDIRECTIONAL);

            ret = rack_dm_remap(
                    region, rpage,
                    region->vma->vm_start + pg_index * region->page_size,
                    region->page_size);
            if (ret) {
                pr_err("failed to remap the page\n");
                goto out_free_prefetch_pages;
            }

            atomic64_fetch_add(1, &region->page_count);
            count_event(region, RACK_DM_EVENT_ALLOC_LOCAL_PAGE);

            DEBUG_LOG("[***] (restore local page) index: %llu, vaddr: %llu, "
                      "paddr: %llu\n", pg_index, pg_vaddr, pg_paddr);
        } else {
            pg_conn = krdma_get_node_by_key(pg_node_hash);
            if (pg_conn == NULL) {
                pr_err("error on krdma_get_node_by_key\n");
                ret = -EINVAL;
                goto out_free_prefetch_pages;
            }
            remote_page = kzalloc(sizeof(*remote_page), GFP_KERNEL);
            if (remote_page == NULL) {
                pr_err("failed to allocate memory for struct remote_page\n");
                ret = -ENOMEM;
                goto out_free_prefetch_pages;
            }
            remote_page->conn = pg_conn;
            remote_page->remote_paddr = pg_paddr;
            remote_page->remote_vaddr = pg_vaddr;
            rpage->remote_page = remote_page;
            rpage->flags = RACK_DM_PAGE_NOT_PRESENT;
            DEBUG_LOG("[***] (restore remote page) node: %s, index: %llu, "
                      "vaddr: %llu, paddr: %llu\n",
                      pg_conn->nodename, pg_index, pg_vaddr, pg_paddr);

            /* pre-fetch active and remote pages */
            if (i >= (remote_cnt + inactive_cnt))
                prefetch_pages[prefetch_cnt++] = pg_index;
        }
    }

    /* NOTE: PREFETCH OPTIMIZATION */
    if (prefetch_cnt > 0) {
        region->prefetch_work.nr_pages = prefetch_cnt;
        region->prefetch_work.arr = prefetch_pages;
        schedule_work(&region->prefetch_work.ws);
    } else {
        /* there are no pages to fetch, release the array here */
        vfree(prefetch_pages);
    }

    dma_free_coherent(
            conn->cm_id->device->dma_device, size, rdma_buf, rdma_buf_dma_addr);

    ret = free_remote_memory(conn, size, remote_vaddr, remote_paddr);
    if (ret) {
        pr_err("error on free_remote_memory\n");
        goto out_free_msg;
    }

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_prefetch_pages:
    vfree(prefetch_pages);
out_free_dma_buf:
    dma_free_coherent(
            conn->cm_id->device->dma_device, size, rdma_buf, rdma_buf_dma_addr);
out_free_remote_memory:
    free_remote_memory(conn, size, remote_vaddr, remote_paddr);
out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int migrate_clean_up_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    struct payload_fmt *payload;
    u64 region_id;
    struct rack_dm_region *region;

    payload = (struct payload_fmt *) input;
    region_id = payload->arg1;

    DEBUG_LOG("migrate_clean_up_rpc_handler region_id: %llu\n", region_id);

    region = (struct rack_dm_region *) region_id;
    rack_dm_migrate_clean_up_region(region);

    return ret;
}

int migrate_clean_up(struct krdma_conn *conn, u64 remote_region_id)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;

    DEBUG_LOG("migrate_clean_up remote_node: %s, remote_region_id: %llu\n",
              conn->nodename, remote_region_id);

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -EINVAL;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = RACK_DM_RPC_MIGRATE_CLEAN_UP;

    payload = (struct payload_fmt *) &fmt->payload;
    payload->arg1 = remote_region_id;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

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
    struct krdma_conn *conn;
    struct ib_device *ib_dev;
    u32 rpc_id;

    DEBUG_LOG("rack_dm_setup_rpc\n");

    ret = rack_dm_update_node_list();
    if (ret) {
        pr_err("error on rack_dm_update_node_list\n");
        ret = -EINVAL;
        goto out;
    }

    conn = get_node_round_robin();
    if (conn == NULL) {
        pr_err("error on get_node_round_robin\n");
        ret = -EINVAL;
        goto out;
    }

    ib_dev = conn->cm_id->device;

    rpc_id = RACK_DM_RPC_ALLOC_REMOTE_USER_PAGE;
    ret = krdma_register_rpc(rpc_id, alloc_remote_user_page_rpc_handler,
                             ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out;
    }

    rpc_id = RACK_DM_RPC_FREE_REMOTE_USER_PAGE;
    ret = krdma_register_rpc(rpc_id, free_remote_user_page_rpc_handler, ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_alloc_remote_user_page;
    }

    rpc_id = RACK_DM_RPC_ALLOC_REMOTE_PAGE_BULK;
    ret = krdma_register_rpc(rpc_id, alloc_remote_page_bulk_rpc_handler,
                             ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_free_remote_user_page;
    }

    rpc_id = RACK_DM_RPC_FREE_REMOTE_PAGE_BULK;
    ret = krdma_register_rpc(rpc_id, free_remote_page_bulk_rpc_handler,
                             ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_alloc_remote_page_bulk;
    }

    rpc_id = RACK_DM_RPC_ALLOC_REMOTE_MEMORY;
    ret = krdma_register_rpc(rpc_id, alloc_remote_memory_rpc_handler, ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_free_remote_page_bulk;
    }

    rpc_id = RACK_DM_RPC_FREE_REMOTE_MEMORY;
    ret = krdma_register_rpc(rpc_id, free_remote_memory_rpc_handler, ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_alloc_remote_memory;
    }

    rpc_id = RACK_DM_RPC_GET_REGION_METADATA;
    ret = krdma_register_rpc(rpc_id, get_region_metadata_rpc_handler, ib_dev);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_free_remote_memory;
    }

    rpc_id = RACK_DM_RPC_MIGRATE_CLEAN_UP;
    ret = krdma_register_rpc(rpc_id, migrate_clean_up_rpc_handler, NULL);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_get_region_metadata;
    }

    return 0;

out_unregister_get_region_metadata:
    krdma_unregister_rpc(RACK_DM_RPC_GET_REGION_METADATA);
out_unregister_free_remote_memory:
    krdma_unregister_rpc(RACK_DM_RPC_FREE_REMOTE_MEMORY);
out_unregister_alloc_remote_memory:
    krdma_unregister_rpc(RACK_DM_RPC_ALLOC_REMOTE_MEMORY);
out_unregister_free_remote_page_bulk:
    krdma_unregister_rpc(RACK_DM_RPC_FREE_REMOTE_PAGE_BULK);
out_unregister_alloc_remote_page_bulk:
    krdma_unregister_rpc(RACK_DM_RPC_ALLOC_REMOTE_PAGE_BULK);
out_unregister_free_remote_user_page:
    krdma_unregister_rpc(RACK_DM_RPC_FREE_REMOTE_USER_PAGE);
out_unregister_alloc_remote_user_page:
    krdma_unregister_rpc(RACK_DM_RPC_ALLOC_REMOTE_USER_PAGE);
out:
    rack_dm_destroy_node_list();

    return ret;
}

void rack_dm_cleanup_rpc(void)
{
    DEBUG_LOG("rack_dm_cleanup_rpc\n");

    krdma_unregister_rpc(RACK_DM_RPC_MIGRATE_CLEAN_UP);
    krdma_unregister_rpc(RACK_DM_RPC_GET_REGION_METADATA);
    krdma_unregister_rpc(RACK_DM_RPC_FREE_REMOTE_MEMORY);
    krdma_unregister_rpc(RACK_DM_RPC_ALLOC_REMOTE_MEMORY);
    krdma_unregister_rpc(RACK_DM_RPC_FREE_REMOTE_USER_PAGE);
    krdma_unregister_rpc(RACK_DM_RPC_ALLOC_REMOTE_USER_PAGE);

    rack_dm_destroy_node_list();
}
