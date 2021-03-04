#ifndef _KRDMA_RDMA_H_
#define _KRDMA_RDMA_H_

#include "cm.h"

struct krdma_mr {
    struct krdma_conn *conn;
    u32 size;
    u64 vaddr;
    dma_addr_t paddr;
    u32 rkey;
};

int krdma_poll_completion(struct ib_cq *cq, u64 *completion);
int krdma_poll_cq_one(struct ib_cq *cq);
int krdma_read(struct krdma_conn *conn, struct krdma_mr *kmr, u64 dst, u64 offset, u32 length);
int krdma_write(struct krdma_conn *conn, struct krdma_mr *kmr, u64 dst, u64 offset, u32 length);

#endif /* _KRDMA_RDMA_H_ */
