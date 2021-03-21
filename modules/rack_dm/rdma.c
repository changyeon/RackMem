#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <rack_dm.h>

struct rdma_node {
    struct list_head head;
    struct krdma_conn *conn;
};

static LIST_HEAD(rdma_node_list);
static DEFINE_SPINLOCK(rdma_node_list_lock);

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

int alloc_remote_page(u64 size, struct krdma_mr **kmr)
{
    int ret = 0;
    struct rdma_node *node;

    node = rdma_get_node();
    if (node == NULL) {
        pr_err("no available rdma node\n");
        ret = -ENOMEM;
        goto out;
    }

    *kmr = krdma_alloc_remote_memory(node->conn, size);
    if (*kmr == NULL) {
        pr_err("error on krdma_alloc_remote_memory\n");
        ret = -ENOMEM;
        goto out;
    }

    return 0;

out:
    return ret;
}

void free_remote_page(struct krdma_mr *kmr)
{
    krdma_free_remote_memory(kmr->conn, kmr);
    kfree(kmr);
}

int read_remote_page(struct krdma_mr *kmr, void *dst)
{
    int ret = 0;
    dma_addr_t addr;

    if (dst >= high_memory)
        addr = page_to_phys(vmalloc_to_page(dst));
    else
        addr = virt_to_phys(dst);

    ret = krdma_io(kmr->conn, kmr, addr, 0, kmr->size, READ);
    if (ret) {
        pr_err("error on krdma_io\n");
        goto out;
    }

    return 0;

out:
    return ret;
}

int write_remote_page(struct krdma_mr *kmr, void *src)
{
    int ret = 0;
    dma_addr_t addr;

    if (src >= high_memory)
        addr = page_to_phys(vmalloc_to_page(src));
    else
        addr = virt_to_phys(src);

    ret = krdma_io(kmr->conn, kmr, addr, 0, kmr->size, WRITE);
    if (ret) {
        pr_err("error on krdma_io\n");
        goto out;
    }

    return 0;

out:
    return ret;
}

int update_rdma_node_list(void)
{
    int i, n, ret = 0;
    struct krdma_conn *nodes[32];
    struct rdma_node *node, *next;

    n = krdma_get_all_nodes(nodes, 32);
    if (n == 0) {
        pr_err("no available nodes\n");
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

void free_rdma_node_list(void)
{
    struct rdma_node *node, *next;

    spin_lock(&rdma_node_list_lock);
    list_for_each_entry_safe(node, next, &rdma_node_list, head) {
        list_del_init(&node->head);
        kfree(node);
    }

    spin_unlock(&rdma_node_list_lock);
}
