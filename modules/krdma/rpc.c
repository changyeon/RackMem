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

struct rpc_queue {
    unsigned long size;
    struct list_head lh;
    spinlock_t lock;
};

struct cq_thread_data {
    char name[64];
    struct ib_cq *cq;
    struct task_struct *task;
};

struct rpc_thread_data {
    int id;
    char name[64];
    struct rpc_queue *queue;
    struct task_struct *task;
};

struct rpc_thread_pool {
    int n;
    struct rpc_thread_data *threads;
};

/* CQ processing thread */
struct cq_thread_data *cq_thread;

/* RPC processing thread pool */
struct rpc_thread_pool *rpc_thread_pool;

static int cq_thread_func(void *data)
{
    int timeout = 1000;
    struct cq_thread_data *context = (struct cq_thread_data *) data;

    DEBUG_LOG("start CQ processing thread: %p\n", context->cq);

    while (!kthread_should_stop()) {
        /* TODO: check the CQ and process the pending completions */
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(timeout));
    }

    return 0;
}

static int rpc_thread_func(void *data)
{
    int timeout = 1000;
    struct rpc_thread_data *context = (struct rpc_thread_data *) data;

    DEBUG_LOG("start RPC processing thread: %d\n", context->id);

    while (!kthread_should_stop()) {
        /* TODO: check the queue and process the pending requests */
        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(msecs_to_jiffies(timeout));
    }

    return 0;
}

static struct krdma_msg *alloc_msg(struct krdma_conn *conn, unsigned long size)
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
        msg = alloc_msg(conn, size);
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

int krdma_rpc_setup(struct ib_device *ib_dev, struct ib_pd *pd,
                    struct ib_cq *cq)
{
    int i, to_free, ret;
    unsigned int nr_cpus;

    /* Step 1: create a RPC processing thread pool */
    nr_cpus = num_online_cpus();
    DEBUG_LOG("num_online_cpus: %u\n", nr_cpus);

    /* allocate rpc_thread_pool */
    rpc_thread_pool = kzalloc(sizeof(*rpc_thread_pool), GFP_KERNEL);
    if (rpc_thread_pool == NULL) {
        pr_err("failed to allocate memory for rpc_thread_pool\n");
        ret = -ENOMEM;
        goto out;
    }

    /* initialize rpc_thread_pool */
    rpc_thread_pool->n = nr_cpus;
    rpc_thread_pool->threads = kzalloc(
            rpc_thread_pool->n * sizeof(struct rpc_thread_data), GFP_KERNEL);
    if (rpc_thread_pool->threads == NULL) {
        pr_err("failed to allocate memory for rpc_thread_data array\n");
        ret = -ENOMEM;
        goto out_kfree_rpc_thread_pool;
    }

    for (i = 0; i < rpc_thread_pool->n; i++) {
        /* allocate rpc waiting queue */
        rpc_thread_pool->threads[i].queue = kzalloc(
                sizeof(struct rpc_queue), GFP_KERNEL);
        if (rpc_thread_pool->threads[i].queue == NULL) {
            pr_err("failed to allocate memory for rpc_queue\n");
            ret = -ENOMEM;
            to_free = i;
            goto out_kfree_rpc_queue;
        }

        /* initialize rpc waiting queue */
        INIT_LIST_HEAD(&rpc_thread_pool->threads[i].queue->lh);
        rpc_thread_pool->threads[i].queue->size = 0;
        spin_lock_init(&rpc_thread_pool->threads[i].queue->lock);
    }

    for (i = 0; i < rpc_thread_pool->n; i++) {
        /* create rpc processing thread */
        rpc_thread_pool->threads[i].id = i;
        sprintf(rpc_thread_pool->threads[i].name, "krpc_worker/%d", i);
        rpc_thread_pool->threads[i].task = kthread_create(rpc_thread_func,
                &rpc_thread_pool->threads[i], rpc_thread_pool->threads[i].name);
        if (IS_ERR(rpc_thread_pool->threads[i].task)) {
            ret = PTR_ERR(rpc_thread_pool->threads[i].task);
            pr_err("failed to create krdma_rpc_worker thread\n");
            to_free = i;
            goto out_stop_rpc_thread_pool;
        }
    }

    /* allocate cq_thread */
    cq_thread = kzalloc(sizeof(*cq_thread), GFP_KERNEL);
    if (cq_thread == NULL) {
        pr_err("failed allocate memory for cq_thread\n");
        ret = -ENOMEM;
        to_free = rpc_thread_pool->n;
        goto out_stop_rpc_thread_pool;
    }

    /* create cq_thread */
    sprintf(cq_thread->name, "kcq_worker");
    cq_thread->cq = cq;
    cq_thread->task = kthread_create(
            cq_thread_func, cq_thread, cq_thread->name);
    if (IS_ERR(cq_thread->task)) {
        ret = PTR_ERR(cq_thread->task);
        pr_err("failed to create krdma_cq_worker thread\n");
        goto out_kfree_cq_thread;
    }

    for (i = 0; i < rpc_thread_pool->n; i++)
        wake_up_process(rpc_thread_pool->threads[i].task);
    wake_up_process(cq_thread->task);

    return 0;

out_kfree_cq_thread:
    kfree(cq_thread);
    to_free = rpc_thread_pool->n;
out_stop_rpc_thread_pool:
    for (i = 0; i < to_free; i++)
        kthread_stop(rpc_thread_pool->threads[i].task);
    to_free = rpc_thread_pool->n;
out_kfree_rpc_queue:
    for (i = 0; i < to_free; i++)
        kfree(rpc_thread_pool->threads[i].queue);
out_kfree_rpc_thread_pool:
    kfree(rpc_thread_pool);
    rpc_thread_pool = NULL;
out:
    return ret;
}

void krdma_rpc_cleanup(void)
{
    int i;

    /* stop the CQ processing thread */
    kthread_stop(cq_thread->task);
    kfree(cq_thread);

    /* stop the RPC processing threads*/
    for (i = 0; i < rpc_thread_pool->n; i++) {
        kthread_stop(rpc_thread_pool->threads[i].task);
        kfree(rpc_thread_pool->threads[i].queue);
    }
    kfree(rpc_thread_pool);

    cq_thread = NULL;
    rpc_thread_pool = NULL;
}
