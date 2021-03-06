#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/dma-mapping.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/completion.h>
#include <linux/preempt.h>
#include <rdma/ib_verbs.h>

#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

extern char g_nodename[__NEW_UTS_LEN + 1];

struct krdma_msg *krdma_alloc_msg(struct krdma_conn *conn, u32 size)
{
    struct krdma_msg *kmsg = NULL;

    kmsg = kzalloc(sizeof(*kmsg), GFP_KERNEL);
    if (kmsg == NULL) {
        pr_err("failed to allocate memory for kmsg\n");
        goto out;
    }

    INIT_LIST_HEAD(&kmsg->head);
    kmsg->size = size;

    kmsg->vaddr = ib_dma_alloc_coherent(
            conn->pd->device, size, &kmsg->paddr, GFP_KERNEL);
    if (kmsg->vaddr == NULL) {
        pr_err("failed to allocate memory for kmsg buffer\n");
        goto out_kfree;
    }

    kmsg->sgl.addr = kmsg->paddr;
    kmsg->sgl.lkey = conn->lkey;
    kmsg->sgl.length = size;

    kmsg->send_wr.wr_id = (u64) kmsg;
    kmsg->send_wr.opcode = IB_WR_SEND;
    kmsg->send_wr.send_flags = IB_SEND_SIGNALED;
    kmsg->send_wr.sg_list = &kmsg->sgl;
    kmsg->send_wr.num_sge = 1;

    kmsg->recv_wr.wr_id = (u64) kmsg;
    kmsg->recv_wr.sg_list = &kmsg->sgl;
    kmsg->recv_wr.num_sge = 1;

    init_completion(&kmsg->done);

    return kmsg;

out_kfree:
    kfree(kmsg);
out:
    return NULL;
}

void krdma_free_msg(struct krdma_conn *conn, struct krdma_msg *kmsg)
{
    ib_dma_free_coherent(conn->pd->device, kmsg->size, kmsg->vaddr, kmsg->paddr);
    kfree(kmsg);
}

struct krdma_msg_pool *krdma_alloc_msg_pool(struct krdma_conn *conn, int n,
                                            u32 size)
{
    int i;
    struct krdma_msg_pool *pool;
    struct krdma_msg *kmsg, *tmp;

    pool = kzalloc(sizeof(*pool), GFP_KERNEL);
    if (pool == NULL) {
        pr_err("failed to allocate memory for msg pool\n");
        goto out;
    }

    INIT_LIST_HEAD(&pool->head);
    spin_lock_init(&pool->lock);
    pool->size = 0;

    for (i = 0; i < n; i++) {
        kmsg = krdma_alloc_msg(conn, size);
        if (kmsg == NULL) {
            pr_err("error on krdma_alloc_msg\n");
            goto out_free_list;
        }
        list_add_tail(&kmsg->head, &pool->head);
        pool->size++;
    }

    return pool;

out_free_list:
    list_for_each_entry_safe(kmsg, tmp, &pool->head, head) {
        list_del_init(&kmsg->head);
        krdma_free_msg(conn, kmsg);
    }
    kfree(pool);
out:
    return NULL;
}

void krdma_release_msg_pool(struct krdma_conn *conn,
                            struct krdma_msg_pool *pool)
{
    struct krdma_msg *kmsg, *tmp;

    list_for_each_entry_safe(kmsg, tmp, &pool->head, head) {
        list_del_init(&kmsg->head);
        krdma_free_msg(conn, kmsg);
    }

    kfree(pool);
}

struct krdma_msg *krdma_get_msg(struct krdma_msg_pool *pool)
{
    struct krdma_msg *kmsg;

    spin_lock(&pool->lock);
    if (list_empty(&pool->head)) {
        kmsg = NULL;
        goto err;
    }

    kmsg = list_first_entry(&pool->head, struct krdma_msg, head);
    list_del_init(&kmsg->head);
    pool->size--;
    spin_unlock(&pool->lock);

    return kmsg;

err:
    spin_unlock(&pool->lock);

    return NULL;
}

void krdma_put_msg(struct krdma_msg_pool *pool, struct krdma_msg *kmsg)
{
    spin_lock(&pool->lock);
    list_add_tail(&kmsg->head, &pool->head);
    pool->size++;
    spin_unlock(&pool->lock);
}

static int rpc_response_alloc_remote_memory(struct krdma_conn *conn,
                                            struct krdma_msg *recv_msg)
{
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *recv_buf;
    struct krdma_mr *kmr = NULL;

    recv_buf = (struct krdma_msg_fmt *) recv_msg->vaddr;

    send_msg = (struct krdma_msg *) recv_buf->arg1;
    kmr = (struct krdma_mr *) recv_buf->arg2;
    kmr->conn = conn;
    kmr->size = recv_buf->arg3;
    kmr->vaddr = recv_buf->arg4;
    kmr->paddr = (dma_addr_t) recv_buf->arg5;
    kmr->rkey = recv_buf->arg6;

    complete(&send_msg->done);

    return 0;
}

static int rpc_request_alloc_remote_memory(struct krdma_conn *conn,
                                           struct krdma_msg *recv_msg)
{
    int ret = 0;
    const struct ib_send_wr *bad_send_wr;
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *send_buf;
    struct krdma_msg_fmt *recv_buf;
    size_t size;
    dma_addr_t paddr;
    void *vaddr;

    recv_buf = (struct krdma_msg_fmt *) recv_msg->vaddr;
    size = (size_t) recv_buf->arg3;

    vaddr = ib_dma_alloc_coherent(
            conn->pd->device, size, &paddr, GFP_KERNEL);
    if (vaddr == NULL) {
        pr_err("failed to allocate memory for kmr buffer\n");
        ret = -ENOMEM;
        goto out;
    }

    send_msg = krdma_get_msg(conn->send_msg_pool);
    if (send_msg == NULL) {
        pr_err("error on krmda_get_msg\n");
        ret = -ENOMEM;
        goto out_dma_free;
    }

    send_buf = (struct krdma_msg_fmt *) send_msg->vaddr;
    send_buf->cmd = KRDMA_CMD_RESPONSE_ALLOC_REMOTE_MEMORY;
    send_buf->arg1 = recv_buf->arg1;
    send_buf->arg2 = recv_buf->arg2;
    send_buf->arg3 = recv_buf->arg3;
    send_buf->arg4 = (u64) vaddr;
    send_buf->arg5 = (u64) paddr;
    send_buf->arg6 = (u64) conn->rkey;

    send_msg->send_wr.wr_id = (u64) send_msg;
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out_put_msg;
    }

    return 0;

out_put_msg:
    krdma_put_msg(conn->send_msg_pool, send_msg);
out_dma_free:
    ib_dma_free_coherent(conn->pd->device, size, vaddr, paddr);
out:
    return ret;
}

/**
 * Allocate remote memory
 */
struct krdma_mr *krdma_alloc_remote_memory(struct krdma_conn *conn, u32 size)
{
    int ret;
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *send_buf;
    struct krdma_mr *kmr = NULL;
    const struct ib_send_wr *bad_send_wr;

    send_msg = krdma_get_msg(conn->send_msg_pool);
    if (send_msg == NULL) {
        pr_err("error on krmda_get_msg\n");
        goto out;
    }

    kmr = kzalloc(sizeof(*kmr), GFP_KERNEL);
    if (kmr == NULL) {
        pr_err("failed to allocate memory for kmr\n");
        goto out_put_msg;
    }

    send_buf = (struct krdma_msg_fmt *) send_msg->vaddr;
    send_buf->cmd = KRDMA_CMD_REQUEST_ALLOC_REMOTE_MEMORY;
    send_buf->arg1 = (u64) send_msg;
    send_buf->arg2 = (u64) kmr;
    send_buf->arg3 = (u64) size;

    init_completion(&send_msg->done);
    send_msg->send_wr.wr_id = 0ULL;

    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out_free_kmr;
    }

    ret = wait_for_completion_timeout(
            &send_msg->done, msecs_to_jiffies(KRDMA_CM_TIMEOUT) + 1);
    if (ret == 0) {
        pr_err("timeout in krdma_get_node_name\n");
        goto out_free_kmr;
    }

    krdma_put_msg(conn->send_msg_pool, send_msg);

    return kmr;

out_free_kmr:
    kfree(kmr);
out_put_msg:
    krdma_put_msg(conn->send_msg_pool, send_msg);
out:
    return NULL;
}
EXPORT_SYMBOL(krdma_alloc_remote_memory);

static int rpc_response_free_remote_memory(struct krdma_conn *conn,
                                            struct krdma_msg *recv_msg)
{
    int ret = 0;
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *recv_buf;

    recv_buf = (struct krdma_msg_fmt *) recv_msg->vaddr;

    send_msg = (struct krdma_msg *) recv_buf->arg1;
    ret = (int) recv_buf->arg2;
    if (ret) {
        pr_err("failed to free remote memory\n");
        goto out;
    }
    complete(&send_msg->done);

    return 0;

out:
    complete(&send_msg->done);

    return ret;
}


static int rpc_request_free_remote_memory(struct krdma_conn *conn,
                                          struct krdma_msg *recv_msg)
{
    int ret = 0;
    const struct ib_send_wr *bad_send_wr;
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *send_buf;
    struct krdma_msg_fmt *recv_buf;
    size_t size;
    dma_addr_t paddr;
    void *vaddr;

    recv_buf = (struct krdma_msg_fmt *) recv_msg->vaddr;

    size = recv_buf->arg2;
    vaddr = (void *) recv_buf->arg3;
    paddr = (dma_addr_t) recv_buf->arg4;

    ib_dma_free_coherent(conn->pd->device, size, vaddr, paddr);

    send_msg = krdma_get_msg(conn->send_msg_pool);
    if (send_msg == NULL) {
        pr_err("error on krmda_get_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    send_buf = (struct krdma_msg_fmt *) send_msg->vaddr;
    send_buf->cmd = KRDMA_CMD_RESPONSE_FREE_REMOTE_MEMORY;
    send_buf->arg1 = recv_buf->arg1;
    send_buf->arg2 = 0;

    send_msg->send_wr.wr_id = (u64) send_msg;
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out_put_msg;
    }

    return 0;

out_put_msg:
    krdma_put_msg(conn->send_msg_pool, send_msg);
out:
    return ret;
}

/**
 * Free remote memory
 */
int krdma_free_remote_memory(struct krdma_conn *conn, struct krdma_mr *kmr)
{
    int ret = 0;
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *send_buf;
    const struct ib_send_wr *bad_send_wr;

    send_msg = krdma_get_msg(conn->send_msg_pool);
    if (send_msg == NULL) {
        ret = -ENOMEM;
        pr_err("error on krmda_get_msg\n");
        goto out;
    }

    send_buf = (struct krdma_msg_fmt *) send_msg->vaddr;
    send_buf->cmd = KRDMA_CMD_REQUEST_FREE_REMOTE_MEMORY;
    send_buf->arg1 = (u64) send_msg;
    send_buf->arg2 = (u64) kmr->size;
    send_buf->arg3 = (u64) kmr->vaddr;
    send_buf->arg4 = (u64) kmr->paddr;

    init_completion(&send_msg->done);
    send_msg->send_wr.wr_id = 0ULL;

    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    ret = wait_for_completion_timeout(
            &send_msg->done, msecs_to_jiffies(KRDMA_CM_TIMEOUT) + 1);
    if (ret == 0) {
        pr_err("timeout in krdma_get_node_name: %d\n", ret);
        goto out;
    }

    krdma_put_msg(conn->send_msg_pool, send_msg);
    kfree(kmr);

    return 0;

out:
    krdma_put_msg(conn->send_msg_pool, send_msg);
    kfree(kmr);

    return ret;
}
EXPORT_SYMBOL(krdma_free_remote_memory);

static int rpc_request_node_name(struct krdma_conn *conn,
                                 struct krdma_msg *recv_msg)
{
    int ret = 0;
    const struct ib_send_wr *bad_send_wr;
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *send_buf;
    struct krdma_msg_fmt *recv_buf;
    char *src, *dst;

    send_msg = krdma_get_msg(conn->send_msg_pool);
    if (send_msg == NULL) {
        pr_err("error on krmda_get_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    send_buf = (struct krdma_msg_fmt *) send_msg->vaddr;
    recv_buf = (struct krdma_msg_fmt *) recv_msg->vaddr;

    send_buf->cmd = KRDMA_CMD_RESPONSE_NODE_NAME;
    send_buf->arg1 = recv_buf->arg1;
    send_buf->arg2 = recv_buf->arg2;

    src = g_nodename;
    dst = (char *) &send_buf->arg3;
    strncpy(dst, src, __NEW_UTS_LEN + 1);

    send_msg->send_wr.wr_id = (u64) send_msg;
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr,
                       &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    return 0;

out:
    return ret;
}

static int rpc_response_node_name(struct krdma_conn *conn,
                                  struct krdma_msg *recv_msg)
{
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *recv_buf;
    char *dst, *src;

    recv_buf = (struct krdma_msg_fmt *) recv_msg->vaddr;

    dst = (char *) recv_buf->arg1;
    src = (char *) &recv_buf->arg3;

    strncpy(dst, src, __NEW_UTS_LEN + 1);

    send_msg = (struct krdma_msg *) recv_buf->arg2;
    complete(&send_msg->done);

    return 0;
}

/**
 * Get remote side's node name of the connection.
 */
int krdma_get_node_name(struct krdma_conn *conn, char *dst)
{
    int ret = 0;
    const struct ib_send_wr *bad_send_wr;
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *msg;

    send_msg = krdma_get_msg(conn->send_msg_pool);
    if (send_msg == NULL) {
        pr_err("error on krdma_get_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    msg = (struct krdma_msg_fmt *) send_msg->vaddr;

    msg->cmd = KRDMA_CMD_REQUEST_NODE_NAME;
    msg->arg1 = (u64) dst;
    msg->arg2 = (u64) send_msg;
    msg->arg3 = 0ULL;

    init_completion(&send_msg->done);
    send_msg->send_wr.wr_id = 0ULL;

    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out_put_msg;
    }

    ret = wait_for_completion_timeout(
            &send_msg->done, msecs_to_jiffies(KRDMA_CM_TIMEOUT) + 1);
    if (ret == 0) {
        pr_err("timeout in krdma_get_node_name\n");
        goto out_put_msg;
    }

    krdma_put_msg(conn->send_msg_pool, send_msg);

    return 0;

out_put_msg:
    krdma_put_msg(conn->send_msg_pool, send_msg);
out:
    return ret;
}

static int krdma_rpc_handler(struct krdma_conn *conn, struct krdma_msg *recv_msg)
{
    int ret = 0;
    struct krdma_msg_fmt *msg = (struct krdma_msg_fmt *) recv_msg->vaddr;

    DEBUG_LOG("rpc_handler cmd: %s (%llu, %llu, %llu, %llu, %llu, %llu)\n",
              krdma_cmds[msg->cmd], msg->arg1, msg->arg2, msg->arg3, msg->arg4,
              msg->arg5, msg->arg6);

    switch (msg->cmd) {
        case KRDMA_CMD_REQUEST_NODE_NAME:
            ret = rpc_request_node_name(conn, recv_msg);
            break;
        case KRDMA_CMD_RESPONSE_NODE_NAME:
            ret = rpc_response_node_name(conn, recv_msg);
            break;
        case KRDMA_CMD_REQUEST_ALLOC_REMOTE_MEMORY:
            ret = rpc_request_alloc_remote_memory(conn, recv_msg);
            break;
        case KRDMA_CMD_RESPONSE_ALLOC_REMOTE_MEMORY:
            ret = rpc_response_alloc_remote_memory(conn, recv_msg);
            break;
        case KRDMA_CMD_REQUEST_FREE_REMOTE_MEMORY:
            ret = rpc_request_free_remote_memory(conn, recv_msg);
            break;
        case KRDMA_CMD_RESPONSE_FREE_REMOTE_MEMORY:
            ret = rpc_response_free_remote_memory(conn, recv_msg);
            break;
    }

    if (ret) {
        pr_err("error on rpc: %s\n", krdma_cmds[msg->cmd]);
        goto out;
    }

    return 0;

out:
    return ret;
}

static int process_completion(struct krdma_conn *conn, struct ib_wc *wc)
{
    int ret;
    bool post_recv = false;
    const struct ib_recv_wr *bad_recv_wr = NULL;
    struct krdma_msg *kmsg = (struct krdma_msg *) wc->wr_id;

    DEBUG_LOG("process_completion opcode: %s, status: %s (%p)\n",
              wc_opcodes[wc->opcode], ib_wc_status_msg(wc->status), kmsg);

    switch (wc->status) {
    case IB_WC_SUCCESS:
        break;
    default:
        pr_err("oof bad wc status %s (%s)\n", ib_wc_status_msg(wc->status),
                wc_opcodes[wc->opcode]);
        goto out;
    };

    switch (wc->opcode) {
    case IB_WC_SEND:
        if (kmsg)
            krdma_put_msg(conn->send_msg_pool, kmsg);
        break;
    case IB_WC_RDMA_WRITE:
    case IB_WC_RDMA_READ:
    case IB_WC_COMP_SWAP:
    case IB_WC_FETCH_ADD:
    case IB_WC_LSO:
    case IB_WC_LOCAL_INV:
    case IB_WC_REG_MR:
    case IB_WC_MASKED_COMP_SWAP:
    case IB_WC_MASKED_FETCH_ADD:
        break;
    case IB_WC_RECV:
        ret = krdma_rpc_handler(conn, kmsg);
        if (ret) {
            pr_err("error on krdma_rpc_handler\n");
            break;
        }
        post_recv = true;
        break;
    case IB_WC_RECV_RDMA_WITH_IMM:
        post_recv = true;
        break;
    default:
        pr_err("%s:%d Unexpected opcode %d\n", __func__, __LINE__, wc->opcode);
        goto out;
    }

    if (post_recv) {
        ret = ib_post_recv(conn->rpc_qp.qp, &kmsg->recv_wr, &bad_recv_wr);
        if (ret) {
            pr_err("error on ib_post_recv: %d\n", ret);
            goto out;
        }
    }

    return 0;

out:
    return -1;
}

void krdma_poll_work(struct work_struct *ws)
{
    int ret = 0;
    struct krdma_conn *conn;
    struct ib_cq *cq;
    struct ib_wc wc;

    conn = container_of(ws, struct krdma_conn, poll_work);
    cq = conn->rpc_qp.cq;

    DEBUG_LOG("krdma_poll_work cq: %p, conn: %p\n", cq, conn);

    while (true) {
        ret = ib_poll_cq(conn->rpc_qp.cq, 1, &wc);
        if (ret < 0) {
            pr_err("error on ib_poll_cq: %s (%s)\n",
                   ib_wc_status_msg(wc.status), wc_opcodes[wc.opcode]);
            break;
        }
        if (ret == 0) {
            break;
        } else if (ret == 1) {
            process_completion(conn, &wc);
            ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
            if (ret) {
                pr_err("error on ib_req_notify_cq: %d\n", ret);
                break;
            }
        } else {
            pr_err("Wrong number of CQ completions!\n");
            break;
        }
    }

}
