#ifndef _KRDMA_RPC_H_
#define _KRDMA_RPC_H_

#include <rdma/ib_verbs.h>
#include <krdma.h>

void krdma_cq_comp_handler(struct ib_cq *cq, void *ctx);
void krdma_cq_event_handler(struct ib_event *event, void *ctx);
struct krdma_msg *krdma_msg_alloc(struct krdma_conn *conn, unsigned long size);
void krdma_msg_free(struct krdma_msg *msg);
int krdma_rpc_setup(struct ib_device *ib_dev, struct ib_pd *pd, struct ib_cq *cq);
void krdma_rpc_cleanup(void);

#endif /* _KRDMA_RPC_H_ */

