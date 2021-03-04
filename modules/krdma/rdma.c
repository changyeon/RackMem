#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "rdma.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

struct krdma_mr *krdma_alloc_mr(struct krdma_conn *conn, u32 size)
{
    struct krdma_mr *kmr = NULL;

    kmr = kzalloc(sizeof(*kmr), GFP_KERNEL);
    if (kmr == NULL) {
        pr_err("failed to allocate memory for kmr\n");
        goto out;
    }

    kmr->conn = conn;
    kmr->size = size;

    kmr->vaddr = ib_dma_alloc_coherent(
            conn->pd->device, size, &kmr->paddr, GFP_KERNEL);
    if (kmr->vaddr == NULL) {
        pr_err("failed to allocate memory for kmr buffer\n");
        goto out_kfree;
    }

    return kmr;

out_kfree:
    kfree(kmr);
out:
    return NULL;
}

void krdma_free_mr(struct krdma_conn *conn, struct krdma_mr *kmr)
{
    ib_dma_free_coherent(conn->pd->device, kmr->size, kmr->vaddr, kmr->paddr);
    kfree(kmr);
}
