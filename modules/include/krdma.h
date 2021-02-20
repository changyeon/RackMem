#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

#define DEBUG_LOG if (g_debug) pr_info

#include <rdma/rdma_cm.h>

enum cm_state {
    CM_STATE_IDLE,
    CM_STATE_CONNECT_REQUEST,
    CM_STATE_ADDR_RESOLVED,
    CM_STATE_ROUTE_RESOLVED,
    CM_STATE_CONNECTED,
    CM_STATE_DISCONNECTED,
    CM_STATE_ERROR
};

struct krdma_cb {
    int server;
    enum cm_state state;

    struct rdma_cm_id *cm_id;
    struct rdma_cm_id *cm_id_child;
    struct ib_cq *cq;
    struct ib_pd *pd;
    struct ib_qp *qp;
    struct ib_mr *mr;

    spinlock_t lock;
    wait_queue_head_t sem;

};

struct krdma_cb *krdma_accept(char *server, int port);
struct krdma_cb *krdma_connect(char *server, int port);
void krdma_disconnect(struct krdma_cb *cb);
void krdma_test(void);

// RDMA APIs
// krdma_join
// krdma_read
// krdma_write
// krdma_malloc
// krdma_free
// krdma_map

// RPC APIs
// krdma_rpc_register
// krmda_rpc_call
// krdma_rpc_recv
// krdma_rpc_reply
// krdma_send

// Synchronization APIs
// krdma_lock
// krdma_barrier
// krdma_fetch_and_add
// krdma_test_and_set

#endif /* _INCLUDE_KRDMA_H_ */
