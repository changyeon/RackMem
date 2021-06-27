#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

#include <rdma/rdma_cm.h>
#include <linux/utsname.h>

#define KRDMA_MAX_SEND_WR           128UL
#define KRDMA_MAX_RECV_WR           128UL
#define KRDMA_MAX_SEND_SGE          16UL
#define KRDMA_MAX_RECV_SGE          16UL

#define KRDMA_RETRY_COUNT           128UL
#define KRDMA_RNR_RETRY_COUNT       128UL

#define KRDMA_MAX_CQE               256UL

#define KRDMA_SEND_MSG_SIZE         4096UL
#define KRDMA_RECV_MSG_SIZE         4096UL
#define KRDMA_SEND_MSG_POOL_SIZE    128UL
#define KRDMA_RECV_MSG_POOL_SIZE    128UL

static const char * const wc_opcodes[] = {
    [IB_WC_SEND]                    = "SEND",
    [IB_WC_RDMA_WRITE]              = "RDMA_WRITE",
    [IB_WC_RDMA_READ]               = "RDMA_READ",
    [IB_WC_COMP_SWAP]               = "COMP_SWAP",
    [IB_WC_FETCH_ADD]               = "FETCH_ADD",
    [IB_WC_LSO]                     = "LSO",
    [IB_WC_LOCAL_INV]               = "LOCAL_INV",
    [IB_WC_REG_MR]                  = "REG_MR",
    [IB_WC_MASKED_COMP_SWAP]        = "MASKED_COMP_SWAP",
    [IB_WC_MASKED_FETCH_ADD]        = "MASKED_FETCH_ADD",
    [IB_WC_RECV]                    = "RECV",
    [IB_WC_RECV_RDMA_WITH_IMM]      = "RECV_RDMA_WITH_IMM",
};

enum krdma_recv_type {
    KRDMA_RPC_REQUEST,
    KRDMA_RPC_RESPONSE
};

struct krdma_rpc {
    u32 id;
    u32 type;
    u32 send_completion;
    u32 recv_completion;
    u64 send_ptr;
    u64 recv_ptr;
    u64 payload;
};

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

struct krdma_qp {
    struct ib_qp *qp;
    struct ib_cq *cq;
};

struct krdma_conn {
    struct hlist_node hn;
    char nodename[__NEW_UTS_LEN + 1];
    u32 nodehash;

    struct rdma_cm_id *cm_id;
    struct ib_pd *pd;

    int cm_error;
    struct completion cm_done;
    struct work_struct cleanup_connection_work;

    struct krdma_msg *send_msg;
    struct krdma_msg *recv_msg;

    struct krdma_qp rdma_qp;
    struct krdma_qp rpc_qp;

    struct krdma_msg_pool *send_msg_pool;
    struct krdma_msg_pool *recv_msg_pool;
};

struct krdma_msg_pool *krdma_msg_pool_create(struct krdma_conn *conn, unsigned long n, unsigned long size);
void krdma_msg_pool_destroy(struct krdma_msg_pool *pool);
struct krdma_msg *krdma_msg_pool_get(struct krdma_msg_pool *pool);
void krdma_msg_pool_put(struct krdma_msg_pool *pool, struct krdma_msg *msg);

#endif /* _INCLUDE_KRDMA_H_ */
