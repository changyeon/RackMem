#ifndef _KRDMA_RDMA_H_
#define _KRDMA_RDMA_H_

#include "cm.h"

struct krdma_mr_t *krdma_alloc_mr(struct krdma_conn *conn, u32 size);
void krdma_free_mr(struct krdma_conn *conn, struct krdma_mr_t *kmr);

#endif /* _KRDMA_RDMA_H_ */
