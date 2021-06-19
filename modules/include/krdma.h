#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

#include <rdma/rdma_cm.h>

struct krdma_conn {
    struct list_head lh;

    int cm_error;
    struct rdma_cm_id *cm_id;
    struct completion cm_done;
    struct work_struct cleanup_connection_work;

    struct ib_pd *pd;
    struct ib_cq *cq;

    /* RPC related */
    struct ib_send_wr send_wr;
    struct ib_sge send_sge;
    void *send_buf_local;
    dma_addr_t send_buf_dma;

    struct ib_recv_wr recv_wr;
    struct ib_sge recv_sge;
    void *recv_buf_local;
    dma_addr_t recv_buf_dma;
};

#endif /* _INCLUDE_KRDMA_H_ */
