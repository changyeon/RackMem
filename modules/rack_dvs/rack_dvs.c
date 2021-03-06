#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
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

    DEBUG_LOG("krdma read start\n");
    ret = krdma_read(conn, kmr, paddr, 0, kmr->size);
    if (ret) {
        pr_err("error on krdma_read\n");
        goto out_dma_free;
    }
    DEBUG_LOG("krdma read finished\n");

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
