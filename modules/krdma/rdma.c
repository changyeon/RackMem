#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/completion.h>
#include <rdma/ib_verbs.h>

#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info


static inline int check_wc_status(struct ib_wc *wc)
{
    int ret = 0;

    DEBUG_LOG("check_wc_status: %s\n", ib_wc_status_msg(wc->status));

    switch (wc->status) {
    case IB_WC_SUCCESS:
        break;
    default:
        pr_err("oof bad wc status %s (%s)\n", ib_wc_status_msg(wc->status),
                wc_opcodes[wc->opcode]);
        ret = -EINVAL;
        goto out;
    };

    return 0;

out:
    return ret;
}

static inline int check_wc_opcode(struct ib_wc *wc)
{
    int ret = 0;
    u64 *completion = (u64 *) wc->wr_id;

    switch (wc->opcode) {
    case IB_WC_RDMA_WRITE:
    case IB_WC_RDMA_READ:
        if (completion)
            *completion = 1;
        break;
    case IB_WC_SEND:
    case IB_WC_COMP_SWAP:
    case IB_WC_FETCH_ADD:
    case IB_WC_LSO:
    case IB_WC_LOCAL_INV:
    case IB_WC_REG_MR:
    case IB_WC_MASKED_COMP_SWAP:
    case IB_WC_MASKED_FETCH_ADD:
    case IB_WC_RECV:
    case IB_WC_RECV_RDMA_WITH_IMM:
    default:
        pr_err("%s:%d Unexpected opcode %d\n", __func__, __LINE__, wc->opcode);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("check_wc_opcode: %s, wr_id: %llu\n", wc_opcodes[wc->opcode],
              (u64) wc->wr_id);

    return 0;

out:
    return ret;
}

int krdma_poll_completion(struct ib_cq *cq, u64 *completion)
{
    int ret = 0;
    struct ib_wc wc;

    while (true) {
        ret = ib_poll_cq(cq, 1, &wc);
        if (ret < 0 || ret > 1) {
            pr_err("error on ib_poll_cq: (%d, %d)\n", ret, wc.status);
            goto err;
        }
        if (wc.opcode < 0) {
            pr_err("bad opcode: %d\n", wc.opcode);
            ret = -EINVAL;
            goto err;
        }
        if (ret == 1) {
            if (check_wc_status(&wc))
                goto err;
            if (check_wc_opcode(&wc))
                goto err;
        }
        if (*completion)
            break;
    }

    return 0;

err:
    return ret;
}

int krdma_poll_cq_one(struct ib_cq *cq)
{
    int ret = 0;
    struct ib_wc wc;

    while (true) {
        ret = ib_poll_cq(cq, 1, &wc);
        if (ret < 0 || ret > 1) {
            pr_err("error on ib_poll_cq: (%d, %d)\n", ret, wc.status);
            goto err;
        }
        if (ret == 1)
            break;
    }

    return 0;

err:
    return ret;
}

int krdma_io(struct krdma_conn *conn, struct krdma_mr *kmr, dma_addr_t addr,
             u64 offset, u64 length, int dir)
{
    int ret = 0;
    u64 completion;
    struct ib_rdma_wr wr;
    struct ib_sge sgl;
    const struct ib_send_wr *bad_send_wr = NULL;

    memset(&wr, 0, sizeof(wr));
    memset(&sgl, 0, sizeof(sgl));

    sgl.addr = (u64) addr;
    sgl.lkey = conn->lkey;
    sgl.length = length;

    DEBUG_LOG("rdma_%s local_addr: %llu, remote_addr: %llu, length: %llu\n",
              (dir == READ) ? "read" : "write",
              (u64) addr, kmr->paddr + offset, length);

    wr.remote_addr = kmr->paddr + offset;
    wr.rkey = kmr->rkey;

    wr.wr.next = NULL;
    wr.wr.wr_id = (u64) &completion;
    wr.wr.sg_list = &sgl;
    wr.wr.num_sge = 1;
    wr.wr.opcode = (dir == WRITE) ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
    wr.wr.send_flags = IB_SEND_SIGNALED;

    completion = 0;
    ret = ib_post_send(conn->rdma_qp.qp, &wr.wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send\n");
        goto out;
    }

    ret = krdma_poll_completion(conn->rdma_qp.cq, &completion);
    if (ret) {
        pr_err("error on krdma_poll_cq\n");
        goto out;
    }

    return 0;

out:

    return ret;
}
EXPORT_SYMBOL(krdma_io);
