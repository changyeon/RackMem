#ifndef _KRDMA_RPC_H_
#define _KRDMA_RPC_H_

#include <rdma/ib_verbs.h>

int krdma_rpc_setup(struct ib_device *ib_dev, struct ib_pd *pd, struct ib_cq *cq);
void krdma_rpc_cleanup(void);

#endif /* _KRDMA_RPC_H_ */

