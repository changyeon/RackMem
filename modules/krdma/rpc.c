#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include "rpc.h"
#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

struct kmem_cache *rpc_work_cache;

/* conn hash table */
static DEFINE_SPINLOCK(rpc_ht_lock);
static DEFINE_HASHTABLE(rpc_ht, 10);


struct krdma_mr *krdma_alloc_remote_memory(struct krdma_conn *conn, u64 size)
{
    int ret;
    struct krdma_msg *send_msg, *recv_msg;
    struct krdma_rpc *send_rpc, *recv_rpc;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;

    volatile u32 *send_completion;
    volatile u32 *recv_completion;

    struct krdma_mr *kmr = NULL;
    u64 vaddr, paddr, rkey;

    DEBUG_LOG("krdma_alloc_remote_memory: %llu\n", size);

    /* Step 1: get a send message from the pool */
    send_msg = krdma_msg_pool_get(conn->send_msg_pool);

    /* Step 2: fill the message with the RPC request data */
    send_rpc = (struct krdma_rpc *) send_msg->buf;
    send_rpc->rpc_id = KRDMA_RPC_ID_ALLOC_REMOTE_MEMORY;
    send_rpc->type = KRDMA_RPC_REQUEST;
    send_rpc->send_completion = 0;
    send_rpc->recv_completion = 0;
    send_rpc->ret_code = 0;
    send_rpc->send_ptr = (u64) send_msg;
    send_rpc->recv_ptr = 0;

    ((u64 *) &send_rpc->payload)[0] = size;

    /* Step 3: post send */
    DEBUG_LOG("krdma_alloc_remote_memory: post_send\n");
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        kmr = NULL;
        goto out;
    }

    /* Step 4: poll send completion */
    DEBUG_LOG("krdma_alloc_remote_memory: poll send\n");
    send_completion = &send_rpc->send_completion;
    while ((*send_completion) == 0);

    /* Step 5: poll recv completion */
    DEBUG_LOG("krdma_alloc_remote_memory: poll recv\n");
    recv_completion = &send_rpc->recv_completion;
    while ((*recv_completion) == 0);

    /* Step 6: read the received message */
    recv_msg = (struct krdma_msg *) send_rpc->recv_ptr;
    recv_rpc = (struct krdma_rpc *) recv_msg->buf;

    if (recv_rpc->ret_code) {
        pr_err("failed RPC request\n");
        kmr = NULL;
        goto out_post_recv;
    }
    DEBUG_LOG("krdma_alloc_remote_memory: ret_code: %d\n", recv_rpc->ret_code);

    kmr = kzalloc(sizeof(*kmr), GFP_KERNEL);
    if (kmr == NULL) {
        pr_err("failed to allocate memory for krdma_mr\n");
        goto out_post_recv;
    }

    vaddr = ((u64 *) &recv_rpc->payload)[1];
    paddr = ((u64 *) &recv_rpc->payload)[2];
    rkey = ((u64 *) &recv_rpc->payload)[3];

    DEBUG_LOG("krdma_alloc_remote_memory: (%llu:%llu:%llu)\n", vaddr, paddr, rkey);

    kmr->conn = conn;
    kmr->size = size;
    kmr->vaddr = vaddr;
    kmr->paddr = paddr;
    kmr->rkey = (u32) rkey;

out_post_recv:
    /* Step 7: post the recv message */
    ret = ib_post_recv(conn->rpc_qp.qp, &recv_msg->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        /* TODO: free the remote memory */
        goto out;
    }

out:
    /* Step 8: put the send message */
    krdma_msg_pool_put(conn->send_msg_pool, send_msg);

    return kmr;
}
EXPORT_SYMBOL(krdma_alloc_remote_memory);

static void alloc_remote_memory_rpc_handler(struct krdma_rpc_work *rpc_work)
{
    int ret = 0;
    struct krdma_conn *conn;
    struct krdma_msg *send_msg, *recv_msg;
    struct krdma_rpc *send_rpc, *recv_rpc;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;
    volatile u32 *send_completion;

    struct ib_device *ib_dev;
    void *buf;
    size_t size;
    dma_addr_t dma_addr;

    DEBUG_LOG("alloc_remote_memory_rpc_handler\n");

    conn = rpc_work->conn;
    recv_msg = rpc_work->recv_msg;
    recv_rpc = (struct krdma_rpc *) recv_msg->buf;

    /* Step 1: process the RPC request */
    size = (size_t) ((u64 *) &recv_rpc->payload)[0];
    ib_dev = conn->cm_id->device;

    DEBUG_LOG("requested_size: %lu\n", size);

    buf = ib_dma_alloc_coherent(ib_dev, size, &dma_addr, GFP_KERNEL);

    DEBUG_LOG("please show me this message!!!!: %llu, %llu\n", (u64) buf, dma_addr);

    if (buf == NULL) {
        pr_err("failed to allocate memory for kmr buffer\n");
        ret = -ENOMEM;
    }

    DEBUG_LOG("[!!!] size: %llu, local buf: %llu, dma_addr: %llu\n", (u64) size, (u64) buf, dma_addr);

    /* Step 2: make result message */
    send_msg = krdma_msg_pool_get(conn->send_msg_pool);
    send_rpc = (struct krdma_rpc *) send_msg->buf;
    send_rpc->rpc_id = recv_rpc->rpc_id;
    send_rpc->type = KRDMA_RPC_RESPONSE;
    send_rpc->send_completion = 0;
    send_rpc->recv_completion = 0;
    send_rpc->ret_code = ret;
    send_rpc->send_ptr = recv_rpc->send_ptr;
    send_rpc->recv_ptr = 0;

    ((u64 *) &send_rpc->payload)[0] = size;
    ((u64 *) &send_rpc->payload)[1] = (u64) buf;
    ((u64 *) &send_rpc->payload)[2] = (u64) dma_addr;
    ((u64 *) &send_rpc->payload)[3] = (u64) conn->pd->unsafe_global_rkey;

    /* Step 3: post send */
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* Step 4: poll send completion */
    send_completion = &send_rpc->send_completion;
    while ((*send_completion) == 0);

out:
    /* Step 5: post the recv message */
    ret = ib_post_recv(conn->rpc_qp.qp, &recv_msg->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

    /* Step 6: put the send message */
    krdma_msg_pool_put(conn->send_msg_pool, send_msg);

    /* Step 7: put the rpc_work to the cache */
    kmem_cache_free(rpc_work_cache, rpc_work);

    return;
}

int krdma_free_remote_memory(struct krdma_conn *conn, struct krdma_mr *kmr)
{
    int ret = 0;
    struct krdma_msg *send_msg, *recv_msg;
    struct krdma_rpc *send_rpc, *recv_rpc;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;

    volatile u32 *send_completion;
    volatile u32 *recv_completion;

    DEBUG_LOG("krdma_alloc_remote_memory: %p\n", kmr);

    /* Step 1: get a send message from the pool */
    send_msg = krdma_msg_pool_get(conn->send_msg_pool);

    /* Step 2: fill the message with the RPC request data */
    send_rpc = (struct krdma_rpc *) send_msg->buf;
    send_rpc->rpc_id = KRDMA_RPC_ID_FREE_REMOTE_MEMORY;
    send_rpc->type = KRDMA_RPC_REQUEST;
    send_rpc->send_completion = 0;
    send_rpc->recv_completion = 0;
    send_rpc->ret_code = 0;
    send_rpc->send_ptr = (u64) send_msg;
    send_rpc->recv_ptr = 0;

    ((u64 *) &send_rpc->payload)[0] = kmr->size;
    ((u64 *) &send_rpc->payload)[1] = kmr->vaddr;
    ((u64 *) &send_rpc->payload)[2] = kmr->paddr;

    DEBUG_LOG("request free (%llu:%llu:%llu)\n", kmr->size, kmr->vaddr, kmr->paddr);

    /* Step 3: post send */
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    /* Step 4: poll send completion */
    send_completion = &send_rpc->send_completion;
    while ((*send_completion) == 0);

    /* Step 5: poll recv completion */
    recv_completion = &send_rpc->recv_completion;
    while ((*recv_completion) == 0);

    /* Step 6: read the received message */
    recv_msg = (struct krdma_msg *) send_rpc->recv_ptr;
    recv_rpc = (struct krdma_rpc *) recv_msg->buf;

    if (recv_rpc->ret_code) {
        pr_err("failed RPC request\n");
        ret = -EINVAL;
        goto out_post_recv;
    }

out_post_recv:
    /* Step 7: post the recv message */
    ret = ib_post_recv(conn->rpc_qp.qp, &recv_msg->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

out:
    /* Step 8: put the send message */
    krdma_msg_pool_put(conn->send_msg_pool, send_msg);

    return ret;
}
EXPORT_SYMBOL(krdma_free_remote_memory);

static void free_remote_memory_rpc_handler(struct krdma_rpc_work *rpc_work)
{
    int ret = 0;
    struct krdma_conn *conn;
    struct krdma_msg *send_msg, *recv_msg;
    struct krdma_rpc *send_rpc, *recv_rpc;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;
    volatile u32 *send_completion;

    struct ib_device *ib_dev;
    size_t size;
    void *buf;
    dma_addr_t paddr;

    DEBUG_LOG("free_remote_memory_rpc_handler\n");

    conn = rpc_work->conn;
    recv_msg = rpc_work->recv_msg;
    recv_rpc = (struct krdma_rpc *) recv_msg->buf;

    /* Step 1: process the RPC request */
    size = (size_t) (((u64 *) &recv_rpc->payload)[0]);
    buf = (void *) (((u64 *) &recv_rpc->payload)[1]);
    paddr = (dma_addr_t) (((u64 *) &recv_rpc->payload)[2]);

    DEBUG_LOG("[!!!] got free request (%llu:%llu:%llu)\n", (u64) size, (u64) buf, (u64) paddr);

    ib_dev = conn->cm_id->device;

    ib_dma_free_coherent(ib_dev, size, buf, paddr);

    /* Step 2: make result message */
    send_msg = krdma_msg_pool_get(conn->send_msg_pool);
    send_rpc = (struct krdma_rpc *) send_msg->buf;
    send_rpc->rpc_id = recv_rpc->rpc_id;
    send_rpc->type = KRDMA_RPC_RESPONSE;
    send_rpc->send_completion = 0;
    send_rpc->recv_completion = 0;
    send_rpc->ret_code = ret;
    send_rpc->send_ptr = recv_rpc->send_ptr;
    send_rpc->recv_ptr = 0;

    ((u64 *) &send_rpc->payload)[0] = size;

    /* Step 3: post send */
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* Step 4: poll send completion */
    send_completion = &send_rpc->send_completion;
    while ((*send_completion) == 0);

out:
    /* Step 5: post the recv message */
    ret = ib_post_recv(conn->rpc_qp.qp, &recv_msg->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

    /* Step 6: put the send message */
    krdma_msg_pool_put(conn->send_msg_pool, send_msg);

    /* Step 7: put the rpc_work to the cache */
    kmem_cache_free(rpc_work_cache, rpc_work);

    return;
}

void krdma_dummy_rpc(struct krdma_conn *conn)
{
    int ret;
    struct krdma_msg *send_msg, *recv_msg;
    struct krdma_rpc *send_rpc, *recv_rpc;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;

    volatile u32 *send_completion;
    volatile u32 *recv_completion;

    /* Step 1: get a send message from the pool */
    send_msg = krdma_msg_pool_get(conn->send_msg_pool);

    /* Step 2: fill the message with the RPC request data */
    send_rpc = (struct krdma_rpc *) send_msg->buf;
    send_rpc->rpc_id = KRDMA_RPC_ID_DUMMY;
    send_rpc->type = KRDMA_RPC_REQUEST;
    send_rpc->send_completion = 0;
    send_rpc->recv_completion = 0;
    send_rpc->ret_code = 0;
    send_rpc->send_ptr = (u64) send_msg;
    send_rpc->recv_ptr = 0;

    ((u64 *) &send_rpc->payload)[0] = 1;
    ((u64 *) &send_rpc->payload)[1] = 2;
    ((u64 *) &send_rpc->payload)[2] = 3;
    ((u64 *) &send_rpc->payload)[3] = 4;
    ((u64 *) &send_rpc->payload)[4] = 5;

    /* Step 3: post send */
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* Step 4: poll send completion */
    send_completion = &send_rpc->send_completion;
    while ((*send_completion) == 0);

    /* Step 5: poll recv completion */
    recv_completion = &send_rpc->recv_completion;
    while ((*recv_completion) == 0);

    /* Step 6: read the received message */
    recv_msg = (struct krdma_msg *) send_rpc->recv_ptr;
    recv_rpc = (struct krdma_rpc *) recv_msg->buf;

    DEBUG_LOG("received ret_code: %d\n", recv_rpc->ret_code);
    DEBUG_LOG("received rpc_id: %u\n", recv_rpc->rpc_id);
    DEBUG_LOG("received send_ptr: %llu\n", (u64) recv_rpc->send_ptr);
    DEBUG_LOG("received result[0]: %llu\n", ((u64 *) &recv_rpc->payload)[0]);
    DEBUG_LOG("received result[1]: %llu\n", ((u64 *) &recv_rpc->payload)[1]);
    DEBUG_LOG("received result[2]: %llu\n", ((u64 *) &recv_rpc->payload)[2]);
    DEBUG_LOG("received result[3]: %llu\n", ((u64 *) &recv_rpc->payload)[3]);
    DEBUG_LOG("received result[4]: %llu\n", ((u64 *) &recv_rpc->payload)[4]);

    /* Step 7: post the recv message */
    ret = ib_post_recv(conn->rpc_qp.qp, &recv_msg->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

out:
    /* Step 8: put the send message */
    krdma_msg_pool_put(conn->send_msg_pool, send_msg);
}


static void dummy_rpc_handler(struct krdma_rpc_work *rpc_work)
{
    int ret = 0;
    struct krdma_conn *conn;
    struct krdma_msg *send_msg, *recv_msg;
    struct krdma_rpc *send_rpc, *recv_rpc;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;
    volatile u32 *send_completion;

    DEBUG_LOG("dummy_rpc_handler\n");

    conn = rpc_work->conn;
    recv_msg = rpc_work->recv_msg;
    recv_rpc = (struct krdma_rpc *) recv_msg->buf;

    /* Step 1: process the RPC request */
    DEBUG_LOG("requested rpc_id: %u\n", recv_rpc->rpc_id);
    DEBUG_LOG("requested send_ptr: %llu\n", (u64) recv_rpc->send_ptr);
    DEBUG_LOG("requested result[0]: %llu\n", ((u64 *) &recv_rpc->payload)[0]);
    DEBUG_LOG("requested result[1]: %llu\n", ((u64 *) &recv_rpc->payload)[1]);
    DEBUG_LOG("requested result[2]: %llu\n", ((u64 *) &recv_rpc->payload)[2]);
    DEBUG_LOG("requested result[3]: %llu\n", ((u64 *) &recv_rpc->payload)[3]);
    DEBUG_LOG("requested result[4]: %llu\n", ((u64 *) &recv_rpc->payload)[4]);

    /* Step 2: make result message */
    send_msg = krdma_msg_pool_get(conn->send_msg_pool);
    send_rpc = (struct krdma_rpc *) send_msg->buf;
    send_rpc->rpc_id = recv_rpc->rpc_id;
    send_rpc->type = KRDMA_RPC_RESPONSE;
    send_rpc->send_completion = 0;
    send_rpc->recv_completion = 0;
    send_rpc->ret_code = ret;
    send_rpc->send_ptr = recv_rpc->send_ptr;
    send_rpc->recv_ptr = 0;

    ((u64 *) &send_rpc->payload)[0] = 5;
    ((u64 *) &send_rpc->payload)[1] = 4;
    ((u64 *) &send_rpc->payload)[2] = 3;
    ((u64 *) &send_rpc->payload)[3] = 2;
    ((u64 *) &send_rpc->payload)[4] = 1;

    /* Step 3: post send */
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* Step 4: poll send completion */
    send_completion = &send_rpc->send_completion;
    while ((*send_completion) == 0);

out:
    /* Step 5: post the recv message */
    ret = ib_post_recv(conn->rpc_qp.qp, &recv_msg->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

    /* Step 6: put the send message */
    krdma_msg_pool_put(conn->send_msg_pool, send_msg);

    /* Step 7: put the rpc_work to the cache */
    kmem_cache_free(rpc_work_cache, rpc_work);

    return;
}

int krdma_rpc_register(u32 rpc_id, void (*func)(struct krdma_rpc_work *))
{
    int ret;
    struct krdma_rpc_func *rpc_func;

    DEBUG_LOG("krdma_rpc_register rpc_id: %u, func: %p\n", rpc_id, func);

    rpc_func = kzalloc(sizeof(*rpc_func), GFP_KERNEL);
    if (rpc_func == NULL) {
        pr_err("failed to allocate memory for krdma_rpc_func\n");
        ret = -ENOMEM;
        goto out;
    }

    rpc_func->rpc_id = rpc_id;
    rpc_func->func = func;

    spin_lock(&rpc_ht_lock);
    hash_add(rpc_ht, &rpc_func->hn, rpc_func->rpc_id);
    spin_unlock(&rpc_ht_lock);

    return 0;

out:
    return ret;
}
EXPORT_SYMBOL(krdma_rpc_register);

void krdma_rpc_unregister(u32 rpc_id)
{
    struct krdma_rpc_func *curr;

    DEBUG_LOG("krdma_unregister_rpc rpc_id: %u\n", rpc_id);

    spin_lock(&rpc_ht_lock);
    hash_for_each_possible(rpc_ht, curr, hn, rpc_id) {
        if (curr->rpc_id == rpc_id) {
            hash_del(&curr->hn);
            kfree(curr);
            break;
        }
    }
    spin_unlock(&rpc_ht_lock);
}
EXPORT_SYMBOL(krdma_rpc_unregister);

static void krdma_free_rpc_table(void)
{
    int i = 0;
    struct hlist_node *tmp;
    struct krdma_rpc_func *curr;

    DEBUG_LOG("krdma_free_rpc_table\n");

    spin_lock(&rpc_ht_lock);
    hash_for_each_safe(rpc_ht, i, tmp, curr, hn) {
        hash_del(&curr->hn);
        kfree(curr);
    }
    spin_unlock(&rpc_ht_lock);
}

/* We process the RPC request in a separate task */
static void process_rpc_request(struct work_struct *ws)
{
    u32 rpc_id;
    struct krdma_rpc_func *curr;
    struct krdma_rpc_work *rpc_work;

    rpc_work = container_of(ws, struct krdma_rpc_work, ws);

    rpc_id = ((struct krdma_rpc *) rpc_work->recv_msg->buf)->rpc_id;

    spin_lock(&rpc_ht_lock);
    hash_for_each_possible(rpc_ht, curr, hn, rpc_id)
        if (curr->rpc_id == rpc_id)
            break;
    spin_unlock(&rpc_ht_lock);

    if (curr->rpc_id != rpc_id) {
        pr_err("failed to lookup the RPC id in the table: %u\n", rpc_id);
        goto out;
    }

    /* process the RPC request */
    DEBUG_LOG("process_rpc_request: %u\n", rpc_id);
    curr->func(rpc_work);

out:
    return;
}

static void rpc_work_constructor(void *data)
{
    struct krdma_rpc_work *rpc_work = (struct krdma_rpc_work *) data;
    rpc_work->conn = NULL;
    rpc_work->recv_msg = NULL;
    INIT_WORK(&rpc_work->ws, process_rpc_request);
}

/* We handle the RPC response in the context of the CQ completion handler */
static void process_rpc_response(struct krdma_msg *recv_msg)
{
    struct krdma_msg *send_msg;
    struct krdma_rpc *send_rpc, *recv_rpc;

    recv_rpc = (struct krdma_rpc *) recv_msg->buf;
    send_msg = (struct krdma_msg *) recv_rpc->send_ptr;
    send_rpc = (struct krdma_rpc *) send_msg->buf;

    send_rpc->recv_ptr = (u64) recv_msg;
    send_rpc->recv_completion = 1;

    DEBUG_LOG("rpc_response: set flag on the recv_compeltion: %p\n",
              &send_rpc->recv_completion);
}

static void process_completion(struct krdma_conn *conn, struct ib_wc *wc)
{
    struct krdma_rpc_work *rpc_work;
    struct krdma_msg *msg = (struct krdma_msg *) wc->wr_id;
    struct krdma_rpc *rpc = (struct krdma_rpc *) msg->buf;

    DEBUG_LOG("process_completion opcode: %s, status: %s (%p)\n",
              wc_opcodes[wc->opcode], ib_wc_status_msg(wc->status), msg);

    switch (wc->status) {
    case IB_WC_SUCCESS:
        break;
    default:
        pr_err("oof bad wc status %s (%s)\n", ib_wc_status_msg(wc->status),
                wc_opcodes[wc->opcode]);
        goto out;
    };

    switch (wc->opcode) {
    case IB_WC_SEND:
        rpc->send_completion = 1;
        DEBUG_LOG("send_completion: set flag on the send_compeltion: %p\n",
                  &rpc->send_completion);
        break;
    case IB_WC_RECV:
        if (rpc->type == KRDMA_RPC_REQUEST) {
            DEBUG_LOG("process_rpc_request\n");
            rpc_work = kmem_cache_alloc(rpc_work_cache, GFP_KERNEL);
            if (rpc_work == NULL) {
                pr_err("failed to get a rpc_work from the cache\n");
                goto out;
            }
            rpc_work->conn = conn;
            rpc_work->recv_msg = msg;
            schedule_work(&rpc_work->ws);
        } else if (rpc->type == KRDMA_RPC_RESPONSE) {
            DEBUG_LOG("process_rpc_response\n");
            process_rpc_response(msg);
        } else {
            pr_err("unexpected recv message type: %u\n", rpc->type);
        }
        break;
    case IB_WC_RDMA_WRITE:
    case IB_WC_RDMA_READ:
    case IB_WC_COMP_SWAP:
    case IB_WC_FETCH_ADD:
    case IB_WC_LSO:
    case IB_WC_LOCAL_INV:
    case IB_WC_REG_MR:
    case IB_WC_MASKED_COMP_SWAP:
    case IB_WC_MASKED_FETCH_ADD:
    case IB_WC_RECV_RDMA_WITH_IMM:
    default:
        pr_err("%s:%d Unexpected opcode %d\n", __func__, __LINE__, wc->opcode);
        goto out;
    }
out:
    return;
}

void krdma_cq_comp_handler(struct ib_cq *cq, void *ctx)
{
    int i, ret = 0;
    bool to_stop = false;
    struct krdma_conn *conn;
    struct ib_wc wc[KRDMA_NR_CQ_POLL_ENTRIES];

    DEBUG_LOG("[BEGIN] cq_comp_handler: (%p, %p)\n", cq, ctx);

    conn = (struct krdma_conn *) ctx;
    cq = conn->rpc_qp.cq;

    while (true) {
        ret = ib_poll_cq(conn->rpc_qp.cq, KRDMA_NR_CQ_POLL_ENTRIES, wc);
        if (ret < 0) {
            pr_err("error on ib_poll_cq: ret: %d (%s, %s)\n",
                   ret, ib_wc_status_msg(wc[0].status),
                   wc_opcodes[wc[0].opcode]);
            break;
        }

        if (ret == 0 && to_stop) {
            DEBUG_LOG("stop the CQ polling\n");
            break;
        }

        if (ret == 0) {
            DEBUG_LOG("request CQ notify\n");
            ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
            if (ret) {
                pr_err("error on ib_req_notify_cq: %d\n", ret);
                break;
            }
            to_stop = true;
            continue;
        }

        if (ret > 0) {
            DEBUG_LOG("process_completion: total: %d, start\n", ret);
            for (i = 0; i < ret; i++) {
                DEBUG_LOG("process_completion: %d\n", i);
                process_completion(conn, &wc[i]);
            }
            DEBUG_LOG("process_completion: total: %d, end\n", ret);
            to_stop = false;
            continue;
        }
    }
    DEBUG_LOG("[END] cq_comp_handler: (%p, %p)\n", cq, ctx);
}

void krdma_cq_event_handler(struct ib_event *event, void *ctx)
{
    pr_info("cq_event_handler: (%s, %p)\n", ib_event_msg(event->event), ctx);
}

struct krdma_msg *krdma_msg_alloc(struct krdma_conn *conn, unsigned long size)
{
    struct krdma_msg *msg;

    msg = kzalloc(sizeof(*msg), GFP_KERNEL);
    if (msg == NULL) {
        pr_err("failed to allocate memory for krdma_msg\n");
        goto out;
    }

    INIT_LIST_HEAD(&msg->lh);
    init_completion(&msg->done);
    msg->size = size;
    msg->ib_dev = conn->cm_id->device;

    msg->buf = ib_dma_alloc_coherent(msg->ib_dev, size, &msg->dma_addr,
                                     GFP_KERNEL);
    if (msg->buf == NULL) {
        pr_err("failed to allocate DMA buffer for krdma_msg\n");
        kfree(msg);
        goto out;
    }

    msg->sge.addr = msg->dma_addr;
    msg->sge.length = size;
    msg->sge.lkey = conn->pd->local_dma_lkey;

    msg->send_wr.wr_id = (u64) msg;
    msg->send_wr.opcode = IB_WR_SEND;
    msg->send_wr.send_flags = IB_SEND_SIGNALED;
    msg->send_wr.sg_list = &msg->sge;
    msg->send_wr.num_sge = 1;

    msg->recv_wr.wr_id = (u64) msg;
    msg->recv_wr.sg_list = &msg->sge;
    msg->recv_wr.num_sge = 1;

    return msg;

out:
    return NULL;
}

void krdma_msg_free(struct krdma_msg *msg)
{
    ib_dma_free_coherent(msg->ib_dev, msg->size, msg->buf, msg->dma_addr);
    kfree(msg);
}

struct krdma_msg_pool *krdma_msg_pool_create(
        struct krdma_conn *conn, unsigned long n, unsigned long size)
{
    unsigned long i;
    struct krdma_msg *msg;
    struct krdma_msg_pool *pool;

    pool = kzalloc(sizeof(*pool), GFP_KERNEL);
    if (pool == NULL) {
        pr_err("failed to allocate memory for krdma_msg_pool\n");
        goto out;
    }

    INIT_LIST_HEAD(&pool->lh);
    spin_lock_init(&pool->lock);
    pool->size = 0;

    for (i = 0; i < n; i++) {
        msg = krdma_msg_alloc(conn, size);
        if (msg == NULL) {
            pr_err("failed to allocate a krdma_msg\n");
            goto out;
        }
        /* add the message to the pool */
        krdma_msg_pool_put(pool, msg);
    }

    DEBUG_LOG("create msg pool (%p, %lu, %lu)\n", pool, n, size);

    return pool;

out:
    return NULL;
}

void krdma_msg_pool_destroy(struct krdma_msg_pool *pool)
{
    struct krdma_msg *msg;

    DEBUG_LOG("destroy msg pool %p\n", pool);

    while(!list_empty(&pool->lh)) {
        msg = krdma_msg_pool_get(pool);
        ib_dma_free_coherent(msg->ib_dev, msg->size, msg->buf, msg->dma_addr);
        kfree(msg);
    }

    kfree(pool);
}

struct krdma_msg *krdma_msg_pool_get(struct krdma_msg_pool *pool)
{
    struct krdma_msg *msg;

    spin_lock(&pool->lock);
    msg = list_first_entry(&pool->lh, struct krdma_msg, lh);
    list_del_init(&msg->lh);
    pool->size--;
    spin_unlock(&pool->lock);

    return msg;
}

void krdma_msg_pool_put(struct krdma_msg_pool *pool, struct krdma_msg *msg)
{
    spin_lock(&pool->lock);
    list_add_tail(&msg->lh, &pool->lh);
    pool->size++;
    spin_unlock(&pool->lock);
}

int krdma_rpc_setup(void)
{
    int ret, flags;
    u32 rpc_id;

    flags = 0;
    rpc_work_cache = kmem_cache_create(
            "rpc_work", sizeof(struct krdma_rpc_work),
            __alignof__(struct krdma_rpc_work), 0, rpc_work_constructor);
    if (rpc_work_cache == NULL) {
        pr_err("failed to create a kmem_cache for rpc_work\n");
        ret = -ENOMEM;
        goto out;
    }

    rpc_id = KRDMA_RPC_ID_DUMMY;
    ret = krdma_rpc_register(rpc_id, dummy_rpc_handler);
    if (ret) {
        pr_err("failed to register rpc_id: %x\n", rpc_id);
        goto out_destroy_rpc_work_cache;
    }

    rpc_id = KRDMA_RPC_ID_ALLOC_REMOTE_MEMORY;
    ret = krdma_rpc_register(rpc_id, alloc_remote_memory_rpc_handler);
    if (ret) {
        pr_err("failed to register rpc_id: %x\n", rpc_id);
        goto out_free_rpc_table;
    }

    rpc_id = KRDMA_RPC_ID_FREE_REMOTE_MEMORY;
    ret = krdma_rpc_register(rpc_id, free_remote_memory_rpc_handler);
    if (ret) {
        pr_err("failed to register rpc_id: %x\n", rpc_id);
        goto out_free_rpc_table;
    }

    return 0;

out_free_rpc_table:
    krdma_free_rpc_table();
out_destroy_rpc_work_cache:
    kmem_cache_destroy(rpc_work_cache);
out:
    kmem_cache_destroy(rpc_work_cache);
    return ret;
}

void krdma_rpc_cleanup(void)
{
    kmem_cache_destroy(rpc_work_cache);
    krdma_free_rpc_table();
}
