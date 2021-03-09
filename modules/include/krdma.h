#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

#include <rdma/rdma_cm.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/dma-mapping.h>

static const char * const wc_opcodes[] = {
    [IB_WC_SEND]               = "SEND",
    [IB_WC_RDMA_WRITE]         = "RDMA_WRITE",
    [IB_WC_RDMA_READ]          = "RDMA_READ",
    [IB_WC_COMP_SWAP]          = "COMP_SWAP",
    [IB_WC_FETCH_ADD]          = "FETCH_ADD",
    [IB_WC_LSO]                = "LSO",
    [IB_WC_LOCAL_INV]          = "LOCAL_INV",
    [IB_WC_REG_MR]             = "REG_MR",
    [IB_WC_MASKED_COMP_SWAP]   = "MASKED_COMP_SWAP",
    [IB_WC_MASKED_FETCH_ADD]   = "MASKED_FETCH_ADD",
    [IB_WC_RECV]               = "RECV",
    [IB_WC_RECV_RDMA_WITH_IMM] = "RECV_RDMA_WITH_IMM",
};

/*
 * CM related
 */
#define KRDMA_CM_TIMEOUT            1000

#define KRDMA_CM_RETRY_COUNT        128
#define KRDMA_CM_RNR_RETRY_COUNT    128

#define KRDMA_CM_MAX_CQE            256
#define KRDMA_CM_MAX_SEND_WR        128
#define KRDMA_CM_MAX_RECV_WR        128

#define KRDMA_CM_MAX_SEND_SGE       16
#define KRDMA_CM_MAX_RECV_SGE       16

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
    struct work_struct poll_work;

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
int krdma_cm_connect(char *server, int port);

/*
 * RDMA related
 */
struct krdma_mr {
    struct krdma_conn *conn;
    u32 size;
    u64 vaddr;
    dma_addr_t paddr;
    u32 rkey;
};

int krdma_poll_completion(struct ib_cq *cq, u64 *completion);
int krdma_poll_cq_one(struct ib_cq *cq);

#define krdma_read(conn, kmr, addr, offset, length) \
    krdma_io(conn, kmr, addr, offset, length, READ)
#define krdma_write(conn, kmr, addr, offset, length) \
    krdma_io(conn, kmr, addr, offset, length, WRITE)
int krdma_io(struct krdma_conn *conn, struct krdma_mr *kmr, dma_addr_t addr, u64 offset, u32 length, int dir);

/*
 * RPC related
 */
#define KRDMA_MSG_BUF_SIZE          4096
#define KRDMA_RECV_WR_POOL_SIZE     16
#define KRDMA_SEND_WR_POOL_SIZE     16

enum krdma_cmd {
    KRDMA_CMD_HANDSHAKE_RDMA,
    KRDMA_CMD_HANDSHAKE_RPC_QP,
    KRDMA_CMD_REQUEST_NODE_NAME,
    KRDMA_CMD_RESPONSE_NODE_NAME,
    KRDMA_CMD_REQUEST_ALLOC_REMOTE_MEMORY,
    KRDMA_CMD_RESPONSE_ALLOC_REMOTE_MEMORY,
    KRDMA_CMD_REQUEST_FREE_REMOTE_MEMORY,
    KRDMA_CMD_RESPONSE_FREE_REMOTE_MEMORY,
    __NR_KRDMA_CMDS
};

static const char * const krdma_cmds[] = {
    [KRDMA_CMD_HANDSHAKE_RDMA]               = "HANDSHAKE_RDMA",
    [KRDMA_CMD_HANDSHAKE_RPC_QP]             = "HANDSHAKE_RPC_QP",
    [KRDMA_CMD_REQUEST_NODE_NAME]            = "REQUEST_NODE_NAME",
    [KRDMA_CMD_RESPONSE_NODE_NAME]           = "RESPONSE_NODE_NAME",
    [KRDMA_CMD_REQUEST_ALLOC_REMOTE_MEMORY]  = "REQUEST_ALLOC_REMOTE_MEMORY",
    [KRDMA_CMD_RESPONSE_ALLOC_REMOTE_MEMORY] = "RESPONSE_ALLOC_REMOTE_MEMORY",
    [KRDMA_CMD_REQUEST_FREE_REMOTE_MEMORY]   = "REQUEST_FREE_REMOTE_MEMORY",
    [KRDMA_CMD_RESPONSE_FREE_REMOTE_MEMORY]  = "RESPONSE_FREE_REMOTE_MEMORY"
};

struct krdma_msg_fmt {
    u64 cmd;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
    u64 arg6;
};

struct krdma_msg_pool {
    struct list_head head;
    u32 size;
    spinlock_t lock;
};

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

struct krdma_msg_pool *krdma_alloc_msg_pool(struct krdma_conn *conn, int n, u32 size);
void krdma_release_msg_pool(struct krdma_conn *conn, struct krdma_msg_pool *pool);
struct krdma_msg *krdma_get_msg(struct krdma_msg_pool *pool);
void krdma_put_msg(struct krdma_msg_pool *pool, struct krdma_msg *kmsg);
struct krdma_msg *krdma_alloc_msg(struct krdma_conn *conn, u32 size);
void krdma_free_msg(struct krdma_conn *conn, struct krdma_msg *kmsg);
int krdma_get_node_name(struct krdma_conn *conn, char *dst);
int krdma_rpc_execute(struct krdma_conn *conn, struct krdma_msg *recv_msg);
int handle_msg(struct krdma_conn *conn, struct ib_wc *wc);
void krdma_poll_work(struct work_struct *ws);

/*
 * Exported APIs
 */
void krdma_test(void);
int krdma_get_all_nodes(struct krdma_conn *nodes[], int n);
struct krdma_mr *krdma_alloc_remote_memory(struct krdma_conn *conn, u32 size);
int krdma_free_remote_memory(struct krdma_conn *conn, struct krdma_mr *kmr);

#endif /* _INCLUDE_KRDMA_H_ */
