#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/delay.h>
#include <krdma.h>
#include <rack_dvs.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RDMA backend for RackMem Distributed Virtual Storage");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

int g_backup = 0;
module_param_named(backup, g_backup, int, 0);
MODULE_PARM_DESC(backup, "enable local storage backup");

int g_backup_storage_delay = 10;
module_param_named(backup_storage_delay, g_backup_storage_delay, int, 0);
MODULE_PARM_DESC(backup_storage, "microsecond delay for the emulated storage");

#define DEBUG_LOG if (g_debug) pr_info

struct rdma_node {
    struct list_head head;
    struct krdma_conn *conn;
};

struct rdma_slab {
    bool backup;
    void *local_storage;
    struct krdma_mr *kmr;
};

static LIST_HEAD(rdma_node_list);
static DEFINE_SPINLOCK(rdma_node_list_lock);

static struct dvs_slab *rdma_alloc(u64 size);
static void rdma_free(struct dvs_slab *slab);
static int rdma_read(struct dvs_slab *slab, u64 offset, u64 size, void *dst);
static int rdma_write(struct dvs_slab *slab, u64 offset, u64 size, void *src);

static struct rack_dvs_ops rdma_ops = {
    .alloc  = rdma_alloc,
    .free   = rdma_free,
    .read   = rdma_read,
    .write  = rdma_write
};

static struct rack_dvs_dev rdma_dev = {
    .dvs_ops = &rdma_ops
};

static struct rdma_node *rdma_get_node(void)
{
    struct rdma_node *node = NULL;

    spin_lock(&rdma_node_list_lock);
    if (list_empty(&rdma_node_list)) {
        pr_err("failed to get a rdma node from the list\n");
        spin_unlock(&rdma_node_list_lock);
        goto out;
    }
    node = list_first_entry(&rdma_node_list, struct rdma_node, head);
    list_rotate_left(&rdma_node_list);
    spin_unlock(&rdma_node_list_lock);

    return node;

out:
    return NULL;
}

static struct dvs_slab *rdma_alloc(u64 size)
{
    int ret = 0;
    struct dvs_slab *dvs_slab;
    struct rdma_node *node;
    struct rdma_slab *rdma_slab;

    DEBUG_LOG("rdma_alloc size: %llu\n", size);

    node = rdma_get_node();
    if (node == NULL) {
        pr_err("no available rdma node\n");
        ret = -ENOMEM;
        goto out;
    }

    dvs_slab = kzalloc(sizeof(*dvs_slab), GFP_KERNEL);
    if (dvs_slab == NULL) {
        pr_err("failed to allocate memory for dvs_slab\n");
        goto out;
    }

    rdma_slab = kzalloc(sizeof(*rdma_slab), GFP_KERNEL);
    if (rdma_slab == NULL) {
       pr_err("failed to allocate memory for rdma_slab\n");
       ret = -ENOMEM;
       goto out_kfree_dvs_slab;
    }

    rdma_slab->backup = g_backup;

    if (rdma_slab->backup) {
        rdma_slab->local_storage = vzalloc(size);
        if (rdma_slab->local_storage == NULL) {
            pr_err("failed to allocate emulated storage for the slab\n");
            goto out_kfree_rdma_slab;
        }
    }

    rdma_slab->kmr = krdma_alloc_remote_memory(node->conn, size);
    if (rdma_slab->kmr == NULL) {
        pr_err("error on krdma_alloc_remote_memory\n");
        ret = -ENOMEM;
        goto out_free_local_storage;
    }

    INIT_LIST_HEAD(&dvs_slab->lh);
    dvs_slab->dev = &rdma_dev;
    dvs_slab->private = (void *) rdma_slab;

    return dvs_slab;

out_free_local_storage:
    if (rdma_slab->local_storage)
        vfree(rdma_slab->local_storage);
out_kfree_rdma_slab:
    kfree(rdma_slab);
out_kfree_dvs_slab:
    kfree(dvs_slab);
out:
    return NULL;
}

static void rdma_free(struct dvs_slab *slab)
{
    struct rdma_slab *rdma_slab;

    DEBUG_LOG("rdma_free slab: %p\n", slab);

    rdma_slab = (struct rdma_slab *) slab->private;
    krdma_free_remote_memory(rdma_slab->kmr->conn, rdma_slab->kmr);
    if (rdma_slab->backup)
        vfree(rdma_slab->local_storage);
    kfree(rdma_slab);
}

static int rdma_read(struct dvs_slab *slab, u64 offset, u64 size, void *dst)
{
    int ret = 0;
    struct rdma_slab *rdma_slab;
    struct krdma_conn *conn;
    struct krdma_mr *kmr;
    dma_addr_t addr;

    DEBUG_LOG("rdma_read slab: %p, offset: %llu, size: %llu, dst: %p\n",
              slab, offset, size, dst);

    rdma_slab = (struct rdma_slab *) slab->private;
    conn = rdma_slab->kmr->conn;
    kmr = rdma_slab->kmr;

    if (dst >= high_memory)
        addr = page_to_phys(vmalloc_to_page(dst));
    else
        addr = virt_to_phys(dst);

    ret = krdma_io(conn, kmr, addr, offset, size, READ);
    if (ret) {
        pr_err("error on krdma_io\n");
        goto out;
    }

    return 0;

out:
    return ret;
}

static int rdma_write(struct dvs_slab *slab, u64 offset, u64 size, void *src)
{
    int ret = 0;
    struct rdma_slab *rdma_slab;
    struct krdma_conn *conn;
    struct krdma_mr *kmr;
    struct ib_rdma_wr wr;
    struct ib_sge sgl;
    dma_addr_t addr;
    u64 completion;

    DEBUG_LOG("rdma_write slab: %p, offset: %llu, size: %llu, dst: %p\n",
              slab, offset, size, src);

    rdma_slab = (struct rdma_slab *) slab->private;
    conn = rdma_slab->kmr->conn;
    kmr = rdma_slab->kmr;

    if (src >= high_memory)
        addr = page_to_phys(vmalloc_to_page(src));
    else
        addr = virt_to_phys(src);

    /* Do async write here */
    ret = krdma_io_async(conn, kmr, &wr, &sgl, addr, offset, size, WRITE,
                         &completion);
    if (ret) {
        pr_err("error on krdma_io\n");
        goto out;
    }

    /* make a backup if the flag is on */
    if (rdma_slab->backup) {
        memcpy((void *) (rdma_slab->local_storage + offset), src, size);
        if (g_backup_storage_delay > 0)
            udelay(g_backup_storage_delay);
    }

    /* check the I/O completion */
    ret = krdma_poll_completion(conn->rdma_qp.cq, &completion);
    if (ret) {
        pr_err("error on krdma_poll_cq\n");
        goto out;
    }


    return 0;

out:
    return ret;
}

static int __init rack_dvs_rdma_init(void)
{
    int i, n, ret = 0;
    struct krdma_conn *nodes[32];
    struct rdma_node *node, *next;
    u64 size_mb, slab_mb;

    n = krdma_get_all_nodes(nodes, 32);
    if (n == 0) {
        pr_err("no available nodes for rdma backend\n");
        ret = -EINVAL;
        goto out;
    }

    pr_info("available nodes: %d\n", n);
    for (i = 0; i < n; i++)
        pr_info("node: %s (%p)\n", nodes[i]->nodename, nodes[i]);

    spin_lock(&rdma_node_list_lock);

    for (i = 0; i < n; i++) {
        node = kzalloc(sizeof(*node), GFP_KERNEL);
        if (node == NULL) {
            pr_err("failed to allocate memory for rdma_node\n");
            ret = -ENOMEM;
            goto out_free_nodes;
        }
        INIT_LIST_HEAD(&node->head);
        node->conn = nodes[i];
        list_add_tail(&node->head, &rdma_node_list);
    }

    spin_unlock(&rdma_node_list_lock);

    ret = rack_dvs_register_dev(&rdma_dev);
    if (ret) {
        pr_err("failed to register rdma backend for RackDVS\n");
        goto out_free_nodes;
    }

    size_mb = 256;
    slab_mb = 64;
    /*
     *ret = dvs_test_single_thread_correctness(size_mb, slab_mb);
     *if (ret)
     *    pr_info("dvs_test_single_thread_correctness (%llu, %llu): FAIL\n",
     *            size_mb, slab_mb);
     *else
     *    pr_info("dvs_test_single_thread_correctness (%llu, %llu): SUCCESS\n",
     *            size_mb, slab_mb);
     */

    pr_info("rack_dvs_rdma: module loaded\n");

    return 0;

 out_free_nodes:
    list_for_each_entry_safe(node, next, &rdma_node_list, head) {
        list_del_init(&node->head);
        kfree(node);
    }

    spin_unlock(&rdma_node_list_lock);

out:
    return ret;
}

static void __exit rack_dvs_rdma_exit(void)
{
    struct rdma_node *node, *next;

    spin_lock(&rdma_node_list_lock);
    list_for_each_entry_safe(node, next, &rdma_node_list, head) {
        list_del_init(&node->head);
        kfree(node);
    }

    spin_unlock(&rdma_node_list_lock);

    rack_dvs_unregister_dev(&rdma_dev);

    pr_info("rack_dvs_rdma: module unloaded\n");
}

module_init(rack_dvs_rdma_init);
module_exit(rack_dvs_rdma_exit);
