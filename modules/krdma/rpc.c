#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "cm.h"
#include "rpc.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

extern char g_nodename[__NEW_UTS_LEN + 1];

static int rpc_handler_request_node_name(struct krdma_conn *conn,
                                         struct krdma_msg *recv_msg)
{
    int ret = 0;
    const struct ib_send_wr *bad_send_wr;
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *recv_buf;
    struct krdma_msg_fmt *send_buf;
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

    DEBUG_LOG("write the node name to the buffer\n");
    src = g_nodename;
    dst = (char *) &send_buf->arg3;
    strncpy(dst, src, __NEW_UTS_LEN + 1);

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

static int rpc_handler_response_node_name(struct krdma_conn *conn,
                                          struct krdma_msg *recv_msg)
{
    struct krdma_msg *send_msg;
    struct krdma_msg_fmt *recv_buf;
    char *dst, *src;

    recv_buf = (struct krdma_msg_fmt *) recv_msg->vaddr;

    dst = (char *) recv_buf->arg1;
    src = (char *) &recv_buf->arg3;

    DEBUG_LOG("remote node name: dst: %s, src: %s\n", dst, src);
    strncpy(dst, src, __NEW_UTS_LEN + 1);

    send_msg = (struct krdma_msg *) recv_buf->arg2;
    DEBUG_LOG("comelete the waiter: %p\n", send_msg);
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

    DEBUG_LOG("krdma_get_node_name\n");

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

    DEBUG_LOG("krdma_get_node_name post send\n");
    send_msg->send_wr.wr_id = 0ULL;
    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out_free_kmsg;
    }

    DEBUG_LOG("krdma_get_node_name wait for completion\n");
    ret = wait_for_completion_timeout(
            &send_msg->done, msecs_to_jiffies(KRDMA_CMD_TIMEOUT) + 1);
    if (ret == 0) {
        pr_err("timeout in krdma_get_node_name\n");
        goto out_free_kmsg;
    }

    krdma_put_msg(conn->send_msg_pool, send_msg);
    DEBUG_LOG("krdma_get_node_name completed free the message\n");

    return 0;

out_free_kmsg:
    krdma_put_msg(conn->send_msg_pool, send_msg);
out:
    return ret;
}

int krdma_rpc_execute(struct krdma_conn *conn, struct krdma_msg *recv_msg)
{
    int ret = 0;
    struct krdma_msg_fmt *msg = (struct krdma_msg_fmt *) recv_msg->vaddr;

    DEBUG_LOG("rpc_execute (%s, %llu, %llu, %llu)\n",
            krdma_cmds[msg->cmd], msg->arg1, msg->arg2, msg->arg3);

    switch (msg->cmd) {
        case KRDMA_CMD_REQUEST_NODE_NAME:
            ret = rpc_handler_request_node_name(conn, recv_msg);
            break;
        case KRDMA_CMD_RESPONSE_NODE_NAME:
            ret = rpc_handler_response_node_name(conn, recv_msg);
            break;
    }

    if (ret) {
        pr_err("error on rpc_handler: %s\n", krdma_cmds[msg->cmd]);
        goto out;
    }

    return 0;

out:
    return ret;
}

int handle_msg(struct krdma_conn *conn, struct ib_wc *wc)
{
    int ret;
    bool post_recv = false;
    const struct ib_recv_wr *bad_recv_wr = NULL;
    struct krdma_msg *kmsg = (struct krdma_msg *) wc->wr_id;

    DEBUG_LOG("cq completion (%s, %s, %p)\n", wc_opcodes[wc->opcode],
              ib_wc_status_msg(wc->status), kmsg);

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
        ret = krdma_rpc_execute(conn, kmsg);
        if (ret) {
            pr_err("error on krdma_rpc_execute\n");
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
