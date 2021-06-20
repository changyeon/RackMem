#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

#include <rdma/rdma_cm.h>

#define KRDMA_MAX_SEND_WR       128UL
#define KRDMA_MAX_RECV_WR       128UL
#define KRDMA_MAX_SEND_SGE      16UL
#define KRDMA_MAX_RECV_SGE      16UL

#define KRDMA_RETRY_COUNT       128UL
#define KRDMA_RNR_RETRY_COUNT   128UL

#define KRDMA_MAX_CQE           256UL

#define KRDMA_SEND_MSG_SIZE          4096UL
#define KRDMA_RECV_MSG_SIZE          4096UL
#define KRDMA_SEND_MSG_POOL_SIZE     128UL
#define KRDMA_RECV_MSG_POOL_SIZE     128UL

struct krdma_msg {
    struct list_head lh;
    struct completion done;
    u64 size;
    struct ib_device *ib_dev;
    void *buf;
    dma_addr_t dma_addr;
    struct ib_sge sge;
    struct ib_send_wr send_wr;
    struct ib_recv_wr recv_wr;
};

struct krdma_msg_pool {
    struct list_head lh;
    unsigned long size;
    spinlock_t lock;
};

struct krdma_conn {
    struct rdma_cm_id *cm_id;
    struct ib_pd *pd;
    struct ib_cq *cq;
    struct ib_qp *qp;

    struct list_head lh;
    int cm_error;
    struct completion cm_done;
    struct work_struct cleanup_connection_work;

    /* RPC related */
    struct krdma_msg_pool *send_msg_pool;
    struct krdma_msg_pool *recv_msg_pool;
};

struct krdma_msg_pool *krdma_msg_pool_create(struct krdma_conn *conn, unsigned long n, unsigned long size);
void krdma_msg_pool_destroy(struct krdma_msg_pool *pool);
struct krdma_msg *krdma_msg_pool_get(struct krdma_msg_pool *pool);
void krdma_msg_pool_put(struct krdma_msg_pool *pool, struct krdma_msg *msg);

#endif /* _INCLUDE_KRDMA_H_ */
