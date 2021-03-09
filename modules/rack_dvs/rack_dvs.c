#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/timekeeping.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/dma-mapping.h>
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

int dvs_io(struct dvs_region *dvsr, dma_addr_t addr, u64 offset, u32 size,
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

    ret = krdma_io(slab->conn, slab->kmr, addr, slab_offset, size, dir);
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

static int dvs_test_correctness(void)
{
    int ret = 0;
    u64 size = 4096;
    struct dvs_region *region;
    void *buf = NULL, *tmp = NULL;
    dma_addr_t addr;

    region = dvs_alloc_region(1, 1);
    if (region == NULL) {
        pr_err("error on dvs_alloc_region\n");
        ret = -EINVAL;
        goto out;
    }

    buf = vzalloc(size);
    if (buf == NULL) {
        pr_err("error on vzalloc\n");
        goto out_free_region;
    }
    get_random_bytes(buf, size);

    tmp = vzalloc(size);
    if (tmp == NULL) {
        pr_err("error on vzalloc\n");
        goto out_vfree;
    }
    memcpy(tmp, buf, size);

    ret = memcmp(buf, tmp, size);
    if (ret == 0) {
        pr_info("[0] memcmp successful! (%llu,%d)\n", *((u64 *) buf), ret);
    } else {
        pr_info("[0] memcmp failed! (%llu,%d)\n", *((u64 *) buf), ret);
    }

    addr = page_to_phys(vmalloc_to_page(buf));
    dvs_write(region, addr, 0, size);
    memset(buf, 0, size);
    dvs_read(region, addr, 0, size);
    ret = memcmp(buf, tmp, 4096);
    if (ret == 0) {
        pr_info("[1] memcmp successful! (%llu,%d)\n", *((u64 *) buf), ret);
    } else {
        pr_info("[1] memcmp failed! (%llu,%d)\n", *((u64 *) buf), ret);
    }

    vfree(buf);
    dvs_free_region(region);

    return 0;

out_vfree:
    vfree(tmp);
out_free_region:
    dvs_free_region(region);
out:
    return ret;
}

static int __init rack_dvs_init(void)
{
    int ret = 0;

    ret = dvs_setup();
    if (ret) {
        pr_err("error on dvs_setup\n");
        goto out;
    }

    ret = dvs_test_correctness();
    if (ret) {
        pr_err("error on dvs_test_io\n");
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
