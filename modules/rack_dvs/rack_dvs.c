#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/timekeeping.h>
#include <krdma.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem distributed virtual storage");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

#define DEBUG_LOG if (g_debug) pr_info

static int dvs_test(void)
{
    int i, n, ret = 0;
    struct krdma_conn *nodes[16];
    struct krdma_conn *conn;
    struct krdma_mr *kmr;
    dma_addr_t paddr;
    void *vaddr;
    ktime_t t1, t2;
    u64 tv, tv_sum = 0;

    n = krdma_get_all_nodes(nodes, 16);

    DEBUG_LOG("available nodes: %d\n", n);
    for (i = 0; i < n; i++)
        DEBUG_LOG("node: %s (%p)\n", nodes[i]->nodename, nodes[i]);

    if (n < 1) {
        ret = -EINVAL;
        goto out;
    }
    conn = nodes[0];

    kmr = krdma_alloc_remote_memory(conn, 1048576);
    if (kmr == NULL) {
        pr_err("error on krdma_alloc_remote_memory\n");
        ret = -ENOMEM;
        goto out;
    }

    DEBUG_LOG("kmr size: %u, vaddr: %llu, paddr: %llu\n",
              (u32) kmr->size, (u64) kmr->vaddr, (u64) kmr->paddr);

    vaddr = ib_dma_alloc_coherent(conn->pd->device, kmr->size, &paddr,
                                  GFP_KERNEL);
    if (vaddr == NULL) {
        pr_err("error on ib_dma_alloc_coherent\n");
        ret = -ENOMEM;
        goto out_free_remote_memory;
    }

    DEBUG_LOG("local buf vaddr: %p, paddr: %llx\n", vaddr, paddr);

    /* 4KB RDMA read latency */
    tv_sum = 0;
    for (i = 0; i < 100; i++) {
        t1 = ktime_get_ns();
        ret = krdma_read(conn, kmr, paddr, 0, 4096U);
        t2 = ktime_get_ns();
        tv = (u64) (t2 - t1);
        tv_sum += tv;
        if (ret) {
            pr_err("error on krdma_read\n");
            goto out_dma_free;
        }
    }
    pr_info("4KB RDMA read latency: %lluns\n", tv_sum / 100ULL);

    /* 4KB RDMA write latency */
    tv_sum = 0;
    for (i = 0; i < 100; i++) {
        t1 = ktime_get_ns();
        ret = krdma_write(conn, kmr, paddr, 0, 4096U);
        t2 = ktime_get_ns();
        tv = (u64) (t2 - t1);
        tv_sum += tv;
        if (ret) {
            pr_err("error on krdma_write\n");
            goto out_dma_free;
        }
    }
    pr_info("4KB RDMA write latency: %lluns\n", tv_sum / 100ULL);

    /* 1MB RDMA read throughput */
    tv_sum = 0;
    for (i = 0; i < 100; i++) {
        t1 = ktime_get_ns();
        ret = krdma_read(conn, kmr, paddr, 0, 1048576U);
        t2 = ktime_get_ns();
        tv = (u64) (t2 - t1);
        tv_sum += tv;
        if (ret) {
            pr_err("error on krdma_read\n");
            goto out_dma_free;
        }
    }
    pr_info("1MB RDMA read throughput: %lluMB/s\n",
            1000000000ULL / (tv_sum / 100ULL));

    /* 1MB RDMA write throughput */
    tv_sum = 0;
    for (i = 0; i < 100; i++) {
        t1 = ktime_get_ns();
        ret = krdma_write(conn, kmr, paddr, 0, 1048576U);
        t2 = ktime_get_ns();
        tv = (u64) (t2 - t1);
        tv_sum += tv;
        if (ret) {
            pr_err("error on krdma_read\n");
            goto out_dma_free;
        }
    }
    pr_info("1MB RDMA write throughput: %lluMB/s\n",
            1000000000ULL / (tv_sum / 100ULL));

    krdma_free_remote_memory(conn, kmr);

    return 0;

out_dma_free:
    ib_dma_free_coherent(conn->pd->device, kmr->size, vaddr, paddr);
out_free_remote_memory:
    krdma_free_remote_memory(conn, kmr);
out:
    return ret;
}

static int __init rack_dvs_init(void)
{
    int ret = 0;

    pr_info("rack_dvs: module loaded\n");
    if (dvs_test()) {
        pr_err("error on dvs_test\n");
    }

    return ret;
}

static void __exit rack_dvs_exit(void)
{
    pr_info("rack_dvs: module unloaded\n");
}

module_init(rack_dvs_init);
module_exit(rack_dvs_exit);
