#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/timekeeping.h>
#include <linux/spinlock.h>
#include <rack_dvs.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem distributed virtual storage");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

#define DEBUG_LOG if (g_debug) pr_info

static LIST_HEAD(dvs_node_list);
static DEFINE_SPINLOCK(dvs_node_list_lock);

static LIST_HEAD(dvs_region_list);
static DEFINE_SPINLOCK(dvs_region_list_lock);

/**
 * dvs_get_node_rr - Select a node using Round Robin policy.
 */
static struct dvs_node *dvs_get_node_rr(void)
{
    struct dvs_node *node = NULL;

    spin_lock(&dvs_node_list_lock);
    if (list_empty(&dvs_node_list)) {
        pr_err("failed to get a node from the list\n");
        goto out;
    }
    node = list_first_entry(&dvs_node_list, struct dvs_node, head);
    list_rotate_left(&dvs_node_list);
    spin_unlock(&dvs_node_list_lock);

    return node;

out:
    spin_unlock(&dvs_node_list_lock);

    return NULL;
}

int dvs_io(struct dvs_region *dvsr, dma_addr_t dst, u64 offset, u32 size,
           int dir)
{
    int ret = 0;
    u64 slab_size_bytes, slab_index, slab_offset;
    struct dvs_slab *slab;
    struct dvs_node *node;

    slab_size_bytes = dvsr->slab_size_mb * MB;
    slab_index = offset / slab_size_bytes;
    slab_offset = offset % slab_size_bytes;

    slab = &dvsr->slabs[slab_index];
    spin_lock(&slab->lock);
    if ((slab->conn == NULL) && (slab->kmr == NULL)) {
        /* allocate remote memory for this slab */
        node = dvs_get_node_rr();
        if (node == NULL) {
            pr_err("error on dvs_get_node_rr\n");
            spin_unlock(&slab->lock);
            goto out;
        }
        slab->conn = node->conn;
        if (slab->conn == NULL) {
            pr_err("conn pointer in dvs_node is NULL\n");
            spin_unlock(&slab->lock);
            goto out;
        }
        slab->kmr = krdma_alloc_remote_memory(slab->conn, slab_size_bytes);
        if (slab->kmr == NULL) {
            pr_err("error on krdma_alloc_remote_memory\n");
            slab->conn = NULL;
            spin_unlock(&slab->lock);
            goto out;
        }
    }
    spin_unlock(&slab->lock);

    ret = krdma_io(slab->conn, slab->kmr, dst, slab_offset, size, dir);
    if (ret) {
        pr_err("error on krdma_io\n");
        goto out;
    }

    return 0;

out:
    return ret;
}
EXPORT_SYMBOL(dvs_io);

struct dvs_region *dvs_alloc_region(u64 size_mb, u64 slab_size_mb)
{
    u64 i, nr_slabs;
    struct dvs_region *dvsr = NULL;

    if (size_mb % slab_size_mb) {
        pr_err("the region size required to be multiple of the slab size\n");
        goto out;
    }

    nr_slabs = size_mb / slab_size_mb;

    dvsr = kzalloc(sizeof(*dvsr), GFP_KERNEL);
    if (dvsr == NULL) {
        pr_err("failed to allocate memory for dvsr\n");
        goto out;
    }

    INIT_LIST_HEAD(&dvsr->head);
    dvsr->size_mb = size_mb;
    dvsr->slab_size_mb = slab_size_mb;
    dvsr->nr_slabs = nr_slabs;
    spin_lock_init(&dvsr->lock);

    dvsr->slabs = kzalloc(nr_slabs * sizeof(*dvsr->slabs), GFP_KERNEL);
    if (dvsr->slabs == NULL) {
        pr_err("failed to allocated memory for dvsr->slabs\n");
        goto out_free_dvsr;
    }

    for (i = 0; i < nr_slabs; i++)
        spin_lock_init(&dvsr->slabs[i].lock);

    spin_lock(&dvs_region_list_lock);
    list_add_tail(&dvsr->head, &dvs_region_list);
    spin_unlock(&dvs_region_list_lock);

    DEBUG_LOG("dvs_alloc_region size_mb: %llu, slab_size_mb: %llu, dvsr: %p\n",
              size_mb, slab_size_mb, dvsr);

    return dvsr;

out_free_dvsr:
    kfree(dvsr);
out:
    return NULL;
}
EXPORT_SYMBOL(dvs_alloc_region);

void dvs_free_region(struct dvs_region *dvsr)
{
    u64 i;
    struct dvs_slab *slab;

    spin_lock(&dvs_region_list_lock);
    list_del_init(&dvsr->head);
    spin_unlock(&dvs_region_list_lock);

    for (i = 0; i < dvsr->nr_slabs; i++) {
        slab = &dvsr->slabs[i];
        spin_lock(&slab->lock);
        if (slab->conn && slab->kmr)
            krdma_free_remote_memory(slab->conn, slab->kmr);
        spin_unlock(&slab->lock);
    }

    kfree(dvsr->slabs);
    kfree(dvsr);

    return;
}
EXPORT_SYMBOL(dvs_free_region);

static int dvs_setup(void)
{
    int i, n, ret = 0;
    struct krdma_conn *nodes[DVS_MAX_NODES];
    struct dvs_node *node, *next;

    n = krdma_get_all_nodes(nodes, DVS_MAX_NODES);
    pr_info("available nodes: %d\n", n);
    for (i = 0; i < n; i++)
        pr_info("node: %s (%p)\n", nodes[i]->nodename, nodes[i]);

    spin_lock(&dvs_node_list_lock);
    for (i = 0; i < n; i++) {
        node = kzalloc(sizeof(*node), GFP_KERNEL);
        if (node == NULL) {
            pr_err("failed to allocate memory for dvs_node\n");
            ret = -ENOMEM;
            goto out;
        }
        INIT_LIST_HEAD(&node->head);
        node->conn = nodes[i];
        list_add_tail(&node->head, &dvs_node_list);
    }
    spin_unlock(&dvs_node_list_lock);

    return 0;

out:
    list_for_each_entry_safe(node, next, &dvs_node_list, head) {
        list_del_init(&node->head);
        kfree(node);
    }

    spin_unlock(&dvs_node_list_lock);

    return ret;
}

static void dvs_cleanup(void)
{
    struct dvs_node *node, *next;

    spin_lock(&dvs_node_list_lock);

    list_for_each_entry_safe(node, next, &dvs_node_list, head) {
        list_del_init(&node->head);
        kfree(node);
    }

    spin_unlock(&dvs_node_list_lock);
}

static int dvs_test(void)
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

static int __init rack_dvs_init(void)
{
    int ret = 0;

    if (dvs_test()) {
        pr_err("error on dvs_test\n");
    }

    ret = dvs_setup();
    if (ret) {
        pr_err("error on dvs_setup\n");
        goto out;
    }

    pr_info("rack_dvs: module loaded\n");

    return 0;

out:
    return ret;
}

static void __exit rack_dvs_exit(void)
{
    dvs_cleanup();
    pr_info("rack_dvs: module unloaded\n");
}

module_init(rack_dvs_init);
module_exit(rack_dvs_exit);
