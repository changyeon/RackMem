#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

#include <rdma/rdma_cm.h>

struct krdma_msg {
    struct list_head lh;
    struct completion done;
    u64 size;
    struct ib_device *ib_dev;
    void *buf;
    dma_addr_t dma_addr;
    struct ib_sge sge;
    struct ib_send_wr send_wr;
    struct ib_recv_wr recv_wr;
};

struct krdma_conn {
    struct list_head lh;

    int cm_error;
    struct rdma_cm_id *cm_id;
    struct completion cm_done;
    struct work_struct cleanup_connection_work;

    /* RPC related */
    struct krdma_msg *send_msg;
    struct krdma_msg *recv_msg;
};

struct krdma_msg *krdma_msg_cache_get(void);
void krdma_msg_cache_put(struct krdma_msg *msg);

#endif /* _INCLUDE_KRDMA_H_ */
