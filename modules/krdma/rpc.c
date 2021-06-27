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

static void process_rpc_request(struct krdma_conn *conn, struct krdma_msg *recv_msg)
{
    int ret;
    struct krdma_msg *send_msg;
    struct krdma_rpc *send_rpc, *recv_rpc;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;

    recv_rpc = (struct krdma_rpc *) recv_msg->buf;

    /* Step 1: process the RPC request */
    DEBUG_LOG("requested id: %u\n", recv_rpc->id);
    DEBUG_LOG("requested send_ptr: %llu\n", (u64) recv_rpc->send_ptr);
    DEBUG_LOG("requested result[0]: %lu\n", ((unsigned long *) &recv_rpc->payload)[0]);
    DEBUG_LOG("requested result[1]: %lu\n", ((unsigned long *) &recv_rpc->payload)[1]);
    DEBUG_LOG("requested result[2]: %lu\n", ((unsigned long *) &recv_rpc->payload)[2]);
    DEBUG_LOG("requested result[3]: %lu\n", ((unsigned long *) &recv_rpc->payload)[3]);
    DEBUG_LOG("requested result[4]: %lu\n", ((unsigned long *) &recv_rpc->payload)[4]);

    /* Step 2: make a result message */
    send_msg = krdma_msg_pool_get(conn->send_msg_pool);
    send_rpc = (struct krdma_rpc *) send_msg->buf;
    send_rpc->id = recv_rpc->id;
    send_rpc->type = KRDMA_RPC_RESPONSE;
    send_rpc->send_completion = 0;
    send_rpc->recv_completion = 0;
    send_rpc->send_ptr = recv_rpc->send_ptr;
    send_rpc->recv_ptr = 0;

    ((unsigned long *) &send_rpc->payload)[0] = 5;
    ((unsigned long *) &send_rpc->payload)[1] = 4;
    ((unsigned long *) &send_rpc->payload)[2] = 3;
    ((unsigned long *) &send_rpc->payload)[3] = 2;
    ((unsigned long *) &send_rpc->payload)[4] = 1;

    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* Step XXX: post receive */
    ret = ib_post_recv(conn->rpc_qp.qp, &recv_msg->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

    /* TODO: poll the send completion */

    /* TODO: add the send message to the pool */

out:
    return;
}

static void process_rpc_response(struct krdma_conn *conn,
                                 struct krdma_msg *recv_msg)
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
            process_rpc_request(conn, msg);
        } else if (rpc->type == KRDMA_RPC_RESPONSE) {
            DEBUG_LOG("process_rpc_response\n");
            process_rpc_response(conn, msg);
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
