#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <krdma.h>
/*#include <linux/cpumask.h>*/

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

struct task_context {
    int id;
    char name[64];
    struct completion done;
    struct krdma_conn *conn;
    struct task_struct *task;
};

static int rpc_task(void *data)
{
    int i, n = 1000;
    struct task_context *task_context = (struct task_context *) data;
    struct krdma_conn *conn;

    conn = task_context->conn;

    for (i = 0; i < n; i++) {
        if ((i % 100) == 0)
            pr_info("rpc_task/%d count: %d\n", task_context->id, i);
        krdma_dummy_rpc(conn, i);
    }

    complete(&task_context->done);

    return 0;
}

int krdma_test_rpc_performance(struct krdma_conn *conn, int nr_threads)
{
    int i;
    struct task_context **tasks;

    tasks = kzalloc(nr_threads * sizeof(struct task_context *), GFP_KERNEL);
    for (i = 0; i < nr_threads; i++) {
        tasks[i] = kzalloc(sizeof(struct task_context), GFP_KERNEL);
        tasks[i]->id = i;
        sprintf(tasks[i]->name, "rpc_test/%d", i);
        init_completion(&tasks[i]->done);
        tasks[i]->conn = conn;
        tasks[i]->task = kthread_create(rpc_task, tasks[i], tasks[i]->name);
    }

    for (i = 0; i < nr_threads; i++)
        wake_up_process(tasks[i]->task);

    for (i = 0; i < nr_threads; i++)
        wait_for_completion(&tasks[i]->done);

    for (i = 0; i < nr_threads; i++)
        kfree(tasks[i]);
    kfree(tasks);

    return 0;
}
