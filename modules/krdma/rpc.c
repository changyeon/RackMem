#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>

#include "rpc.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

struct rpc_request {
    struct list_head lh;
};

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

int krdma_rpc_setup(struct ib_cq *cq)
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
