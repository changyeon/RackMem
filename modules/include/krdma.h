#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

#include <rdma/rdma_cm.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/utsname.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/dma-mapping.h>

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

#define KRDMA_POLL_WORK_ARRAY_SIZE  8

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

struct krdma_poll_work {
    struct krdma_conn *conn;
    struct work_struct work;
};

struct krdma_conn {
    struct hlist_node hn;
    char nodename[__NEW_UTS_LEN + 1];
    u32 nodename_hash;

    /* cm related */
    int cm_error;
    struct rdma_cm_id *cm_id;
    struct completion cm_done;
    struct work_struct release_work;
    atomic64_t poll_work_index;
    struct krdma_poll_work poll_work_arr[KRDMA_POLL_WORK_ARRAY_SIZE];

    /* global pd */
    struct ib_pd *pd;
    u32 lkey;
    u32 rkey;
    u32 remote_rkey;

    /* message buffers */
    struct krdma_msg *send_msg;
    struct krdma_msg *recv_msg;

    /* krdma QPs */
    struct krdma_qp rdma_qp;
    struct krdma_qp rpc_qp;

    /* msg pool */
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
    u64 size;
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
int krdma_io(struct krdma_conn *conn, struct krdma_mr *kmr, dma_addr_t addr, u64 offset, u64 length, int dir);

/*
 * RPC related
 */
#define KRDMA_MSG_BUF_SIZE              4096
#define KRDMA_RECV_WR_POOL_SIZE         256
#define KRDMA_SEND_WR_POOL_SIZE         16

enum krdma_cmd {
    KRDMA_CMD_RKEY_REQUEST,
    KRDMA_CMD_RKEY_RESPONSE,
    KRDMA_CMD_GENERAL_RPC_REQUEST,
    KRDMA_CMD_GENERAL_RPC_RESPONSE,
    __NR_KRDMA_CMDS
};

static const char * const krdma_cmds[] = {
    [KRDMA_CMD_RKEY_REQUEST]            = "RKEY_REQUEST",
    [KRDMA_CMD_RKEY_RESPONSE]           = "RKEY_RESPONSE",
    [KRDMA_CMD_GENERAL_RPC_REQUEST]     = "GENERAL_RPC_REQUEST",
    [KRDMA_CMD_GENERAL_RPC_RESPONSE]    = "GENERAL_RPC_RESPONSE"
};

enum krdma_rpc {
    KRDMA_RPC_DUMMY                     = 0xAAAA0000,
    KRDMA_RPC_GET_NODE_NAME,
    KRDMA_RPC_ALLOC_REMOTE_MEMORY,
    KRDMA_RPC_FREE_REMOTE_MEMORY
};

struct krdma_msg_pool {
    struct list_head head;
    u64 size;
    spinlock_t lock;
};

struct krdma_msg {
    struct list_head head;
    u64 size;
    void *vaddr;
    dma_addr_t paddr;
    struct ib_sge sgl;
    struct ib_send_wr send_wr;
    struct ib_recv_wr recv_wr;
    struct completion done;
};

struct qp_msg_fmt {
    u32 qpn;
    u32 psn;
    u32 lid;
};

struct rpc_msg_fmt {
    u32 cmd;
    u32 rpc_id;
    u64 request_id;
    s32 ret;
    u32 size;
    u64 payload;
};

struct payload_fmt {
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
    u64 arg6;
};

struct krdma_rpc_func {
    struct hlist_node hn;
    u32 id;
    int (*func)(void *, void *, void *);
    void *ctx;
};

void krdma_free_rpc_table(void);
int krdma_register_rpc(u32 id, int (*func)(void *, void *, void *), void *ctx);
void krdma_unregister_rpc(u32 id);
struct krdma_msg_pool *krdma_alloc_msg_pool(struct krdma_conn *conn, int n, u64 size);
void krdma_free_msg_pool(struct krdma_conn *conn, struct krdma_msg_pool *pool);
struct krdma_msg *krdma_get_msg(struct krdma_msg_pool *pool);
void krdma_put_msg(struct krdma_msg_pool *pool, struct krdma_msg *kmsg);
struct krdma_msg *krdma_alloc_msg(struct krdma_conn *conn, u64 size);
void krdma_free_msg(struct krdma_conn *conn, struct krdma_msg *kmsg);
void krdma_poll_work(struct work_struct *ws);
int krdma_send_rpc_request(struct krdma_conn *conn, struct krdma_msg *msg);
int krdma_get_remote_rkey(struct krdma_conn *conn);
int krdma_dummy_rpc(struct krdma_conn *conn, u64 val);
int krdma_get_remote_node_name(struct krdma_conn *conn);
int krdma_rpc_execute(struct krdma_conn *conn, struct krdma_msg *recv_msg);
int handle_msg(struct krdma_conn *conn, struct ib_wc *wc);
int register_all_krdma_rpc(void);
void unregister_all_krdma_rpc(void);

/*
 * debugfs
 */
int krdma_debugfs_setup(void);
void krdma_debugfs_cleanup(void);

/*
 * Performance benchmark
 */
int krdma_test_rpc_performance(struct krdma_conn *conn, int nr_threads);


/*
 * Exported APIs
 */
void krdma_local_node_name(char *dst);
u32 krdma_local_node_hash(void);
int krdma_get_all_nodes(struct krdma_conn *nodes[], int n);
struct krdma_conn *krdma_get_node(void);
struct krdma_conn *krdma_get_node_by_name(char *nodename);
struct krdma_conn *krdma_get_node_by_key(u32 key);
struct krdma_mr *krdma_alloc_remote_memory(struct krdma_conn *conn, u64 size);
int krdma_free_remote_memory(struct krdma_conn *conn, struct krdma_mr *kmr);
int krdma_poll_completion(struct ib_cq *cq, u64 *completion);

#endif /* _INCLUDE_KRDMA_H_ */
