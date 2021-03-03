#ifndef _KRDMA_CM_H_
#define _KRDMA_CM_H_

#include <rdma/rdma_cm.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>

#define KRDMA_CMD_TIMEOUT           1000

#define KRDMA_CM_RETRY_COUNT        128
#define KRDMA_CM_RNR_RETRY_COUNT    128

#define KRDMA_CM_MAX_CQE            128
#define KRDMA_CM_MAX_SEND_WR        128
#define KRDMA_CM_MAX_RECV_WR        128
#define KRDMA_CM_MAX_SEND_SGE       16
#define KRDMA_CM_MAX_RECV_SGE       16

#define KRDMA_NR_POST_RECV          16

enum krdma_cmd {
    KRDMA_CMD_HANDSHAKE_RDMA,
    KRDMA_CMD_HANDSHAKE_RPC_QP,
    KRDMA_CMD_REQUEST_NODE_NAME,
    KRDMA_CMD_RESPONSE_NODE_NAME
};

struct krdma_msg_fmt {
    u64 cmd;
    u64 arg1;
    u64 arg2;
    u64 arg3;
};

struct krdma_msg_pool {
    struct list_head head;
    u32 size;
    spinlock_t lock;
};

typedef struct krdma_mr_t {
    struct krdma_conn *conn;
    u32 size;
    void *vaddr;
    dma_addr_t paddr;
} krdma_mr_t;

struct krdma_msg {
    struct list_head head;
    u32 size;
    void *vaddr;
    dma_addr_t paddr;
    struct ib_sge sgl;
    struct ib_send_wr send_wr;
    struct ib_recv_wr recv_wr;
    struct completion done;
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
