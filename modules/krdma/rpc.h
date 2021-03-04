#ifndef _KRDMA_RPC_H_
#define _KRDMA_RPC_H_

#include "cm.h"
#include "rdma.h"

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
struct krdma_mr *krdma_alloc_remote_memory(struct krdma_conn *conn, u32 size);
int krdma_free_remote_memory(struct krdma_conn *conn, struct krdma_mr *kmr);
int krdma_get_node_name(struct krdma_conn *conn, char *dst);
int krdma_rpc_execute(struct krdma_conn *conn, struct krdma_msg *recv_msg);
int handle_msg(struct krdma_conn *conn, struct ib_wc *wc);

#endif /* _KRDMA_RPC_H_ */
