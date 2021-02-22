#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

#include <rdma/rdma_cm.h>
#include <linux/ioctl.h>
#include <linux/completion.h>

enum krdma_conn_state {
    CONN_STATE_IDLE,
    CONN_STATE_CONNECTED
};

struct krdma_conn {
    int state;
    struct rdma_cm_id *cm_id;
    struct ib_pd *pd;
    struct ib_cq *cq;
    struct ib_qp *qp;
    int cm_error;
    struct completion cm_done;
};

int krdma_cm_connect(char *server, int port);
int krdma_cm_setup(char *server, int port, void *context);
void krdma_cm_cleanup(void);
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
