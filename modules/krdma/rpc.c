#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/cpumask.h>

#include "rpc.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

int krdma_rpc_setup(struct ib_cq *cq)
{
    /* TODO: add implementation */
    return 0;
}

void krdma_rpc_cleanup(void)
{
    /* TODO: add implementation */
}
