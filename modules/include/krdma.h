#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

#include <rdma/rdma_cm.h>
#include <linux/ioctl.h>
#include <linux/completion.h>
#include <linux/utsname.h>
#include <linux/types.h>
#include <linux/workqueue.h>

enum krdma_conn_state {
    CONN_STATE_IDLE,
    CONN_STATE_CONNECTED
};

struct krdma_msg {
    u64 cmd;
    u64 arg1;
    u64 arg2;
    u64 arg3;
};

struct krdma_conn {
    char nodename[__NEW_UTS_LEN + 1];
    int state;
    struct rdma_cm_id *cm_id;
    struct ib_pd *pd;
    struct ib_mr *mr;
    struct ib_cq *cq;
    struct ib_qp *qp;
    int cm_error;
    struct completion cm_done;
    struct work_struct release_work;

    u32 lkey;
    u32 rkey;

    /* message buffers */
    struct krdma_msg send_msg __aligned(32);
    struct krdma_msg recv_msg __aligned(32);

    u64 send_dma_addr;
    u64 recv_dma_addr;

    struct ib_sge send_sgl;
    struct ib_sge recv_sgl;

    struct ib_send_wr send_wr;
    struct ib_recv_wr recv_wr;

    /* RDMA buffers */
    void *rdma_buf;
    dma_addr_t rdma_dma_addr;

    struct ib_sge rdma_sgl;
    struct ib_rdma_wr rdma_wr;

    struct hlist_node hn;
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
