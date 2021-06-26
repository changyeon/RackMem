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

void krdma_cq_comp_handler(struct ib_cq *cq, void *ctx)
{
    pr_info("cq_comp_handler: (%p, %p)\n", cq, ctx);
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
