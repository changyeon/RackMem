#ifndef _KRDMA_CM_H_
#define _KRDMA_CM_H_

#include <rdma/rdma_cm.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>

#define KRDMA_CM_TIMEOUT           1000

#define KRDMA_CM_RETRY_COUNT        128
#define KRDMA_CM_RNR_RETRY_COUNT    128

#define KRDMA_CM_MAX_CQE            128
#define KRDMA_CM_MAX_SEND_WR        128
#define KRDMA_CM_MAX_RECV_WR        128
#define KRDMA_CM_MAX_SEND_SGE       16
#define KRDMA_CM_MAX_RECV_SGE       16

#define KRDMA_MSG_BUF_SIZE          4096
#define KRDMA_RECV_WR_POOL_SIZE     16
#define KRDMA_SEND_WR_POOL_SIZE     16

static const char * const wc_opcodes[] = {
    [IB_WC_SEND]                = "SEND",
    [IB_WC_RDMA_WRITE]          = "RDMA_WRITE",
    [IB_WC_RDMA_READ]           = "RDMA_READ",
    [IB_WC_COMP_SWAP]           = "COMP_SWAP",
    [IB_WC_FETCH_ADD]           = "FETCH_ADD",
    [IB_WC_LSO]                 = "LSO",
    [IB_WC_LOCAL_INV]           = "LOCAL_INV",
    [IB_WC_REG_MR]              = "REG_MR",
    [IB_WC_MASKED_COMP_SWAP]    = "MASKED_COMP_SWAP",
    [IB_WC_MASKED_FETCH_ADD]    = "MASKED_FETCH_ADD",
    [IB_WC_RECV]                = "RECV",
    [IB_WC_RECV_RDMA_WITH_IMM]  = "RECV_RDMA_WITH_IMM",
};

struct krdma_qp {
    struct ib_qp *qp;
    struct ib_cq *cq;

    u32 local_qpn;
    u32 local_psn;
    u32 local_lid;

    u32 remote_qpn;
    u32 remote_psn;
    u32 remote_lid;
};

struct krdma_conn {
    struct hlist_node hn;
    char nodename[__NEW_UTS_LEN + 1];

    /* cm related */
    int cm_error;
    struct rdma_cm_id *cm_id;
    struct completion cm_done;
    struct work_struct release_work;

    /* global pd */
    struct ib_pd *pd;
    u32 lkey;
    u32 rkey;

    /* message buffers */
    struct krdma_msg *send_msg;
    struct krdma_msg *recv_msg;

    /* krdma QPs */
    struct krdma_qp rdma_qp;
    struct krdma_qp rpc_qp;

    /* msg pool */
    struct krdma_msg_pool *send_msg_pool;
    struct krdma_msg_pool *recv_msg_pool;
};

int krdma_cm_setup(char *server, int port, void *context);
void krdma_cm_cleanup(void);

#endif /* _KRDMA_CM_H_ */
