#ifndef _KRDMA_CM_H_
#define _KRDMA_CM_H_

#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <rdma/rdma_cm.h>

#define KRDMA_CM_RETRY_COUNT        128
#define KRDMA_CM_RNR_RETRY_COUNT    128

#define KRDMA_CM_MAX_CQE            128
#define KRDMA_CM_MAX_SEND_WR        128
#define KRDMA_CM_MAX_RECV_WR        128
#define KRDMA_CM_MAX_SEND_SGE       16
#define KRDMA_CM_MAX_RECV_SGE       16

enum krdma_cmd {
    KRDMA_CMD_HANDSHAKE_RDMA,
    KRDMA_CMD_HANDSHAKE_MSG_QP
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

    /* message QP */
    struct ib_qp *msg_qp;
    struct ib_cq *msg_cq;

    u32 msg_local_qpn;
    u32 msg_local_psn;
    u32 msg_local_lid;

    u32 msg_remote_qpn;
    u32 msg_remote_psn;
    u32 msg_remote_lid;
};

int krdma_cm_setup(char *server, int port, void *context);
void krdma_cm_cleanup(void);

#endif /* _KRDMA_CM_H_ */
