#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info


int krdma_test_rpc_performance(void)
{
    pr_info("krdma_test_rpc_performance");

    return 0;
}
