#include <rack_dvs.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

int dvs_test(void)
{
    int i, n, ret = 0;
    struct krdma_conn *nodes[DVS_MAX_NODES];
    struct krdma_conn *conn;
    struct krdma_mr *kmr;
    dma_addr_t paddr;
    void *vaddr;
    ktime_t t1, t2;
    u64 tv, tv_sum = 0;

    n = krdma_get_all_nodes(nodes, DVS_MAX_NODES);

    DEBUG_LOG("available nodes: %d\n", n);
    for (i = 0; i < n; i++)
        DEBUG_LOG("node: %s (%p)\n", nodes[i]->nodename, nodes[i]);

    if (n < 1) {
        ret = -EINVAL;
        goto out;
    }
    conn = nodes[0];

    for (i = 0; i < 1000; i++) {
        kmr = krdma_alloc_remote_memory(conn, 1048576);
        if (kmr == NULL) {
            pr_err("error on krdma_alloc_remote_memory\n");
            ret = -ENOMEM;
            goto out;
        }
        krdma_free_remote_memory(conn, kmr);
    }

    kmr = krdma_alloc_remote_memory(conn, 1048576);
    if (kmr == NULL) {
        pr_err("error on krdma_alloc_remote_memory\n");
        ret = -ENOMEM;
        goto out;
    }

    DEBUG_LOG("kmr size: %u, vaddr: %llu, paddr: %llu\n",
              (u32) kmr->size, (u64) kmr->vaddr, (u64) kmr->paddr);

    vaddr = dma_alloc_coherent(conn->pd->device->dma_device, kmr->size, &paddr,
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
    dma_free_coherent(conn->pd->device->dma_device, kmr->size, vaddr, paddr);
out_free_remote_memory:
    krdma_free_remote_memory(conn, kmr);
out:
    return ret;
}


int dvs_test_io(void)
{
    int ret = 0, i, n;
    struct dvs_region *region;
    void *buf = NULL;
    dma_addr_t dst;

    region = dvs_alloc_region(1024, 1);
    if (region == NULL) {
        pr_err("error on dvs_alloc_region\n");
        ret = -EINVAL;
        goto out;
    }

    buf = vzalloc(1ULL * MB);
    if (buf == NULL) {
        pr_err("error on vzalloc\n");
        goto out_free_region;
    }

    dst = page_to_phys(vmalloc_to_page(buf));

    n = (1024 * MB) / 4096;
    for (i = 0; i < n; i++) {
        ret = dvs_read(region, dst, i * 4096, 4096);
        if (ret) {
            pr_err("error on dvs_read\n");
            goto out_vfree;
        }
    }
    for (i = 0; i < n; i++) {
        ret = dvs_write(region, dst, i * 4096, 4096);
        if (ret) {
            pr_err("error on dvs_write\n");
            goto out_vfree;
        }
    }

    vfree(buf);
    dvs_free_region(region);

    return 0;

out_vfree:
    vfree(buf);
out_free_region:
    dvs_free_region(region);
out:
    return ret;
}