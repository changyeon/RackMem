#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <rdma/ib_verbs.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/stringhash.h>
#include <linux/random.h>


#include "cm.h"
#include "rpc.h"
#include <krdma.h>

extern int g_debug;
extern char g_nodename[__NEW_UTS_LEN + 1];

#define DEBUG_LOG if (g_debug) pr_info

/* shared ib resources */
static struct ib_pd *global_pd;

static struct rdma_cm_id *server_cm_id;

/* conn hash table */
static DEFINE_SPINLOCK(conn_ht_lock);
static DEFINE_HASHTABLE(conn_ht, 10);

/* ib_device list */
static LIST_HEAD(ib_dev_list);
static DEFINE_SPINLOCK(ib_dev_list_lock);

struct krdma_ib_dev {
    struct list_head head;
    struct ib_device *ib_dev;
};

static int poll_cq_one(struct ib_cq *cq)
{
    int ret;
    struct ib_wc wc;

    while (true) {
        ret = ib_poll_cq(cq, 1, &wc);
        if (ret < 0 || ret > 1) {
            pr_err("error on ib_poll_cq: (%d, %d)\n", ret, wc.status);
            ret = -EINVAL;
            goto out;
        }
        if (ret == 1)
            break;
    }

    return 0;

out:
    return ret;
}

static int handshake_client(struct krdma_conn *conn)
{
    int ret;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;
    const struct ib_send_wr *send_wr = &conn->send_msg->send_wr;
    const struct ib_recv_wr *recv_wr = &conn->recv_msg->recv_wr;

    ret = ib_post_send(conn->rdma_qp.qp, send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* poll send */
    poll_cq_one(conn->rdma_qp.cq);

    /* poll recv */
    poll_cq_one(conn->rdma_qp.cq);

    ret = ib_post_recv(conn->rdma_qp.qp, recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

    return 0;

out:
    return ret;
}

static int handshake_server(struct krdma_conn *conn)
{
    int ret;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;
    const struct ib_send_wr *send_wr = &conn->send_msg->send_wr;
    const struct ib_recv_wr *recv_wr = &conn->recv_msg->recv_wr;

    /* poll recv */
    poll_cq_one(conn->rdma_qp.cq);

    ret = ib_post_recv(conn->rdma_qp.qp, recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

    ret = ib_post_send(conn->rdma_qp.qp, send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* poll send */
    poll_cq_one(conn->rdma_qp.cq);

    return 0;

out:
    return ret;
}


static void cleanup_connection(struct work_struct *ws)
{
    struct krdma_conn *conn;

    conn = container_of(ws, struct krdma_conn, cleanup_connection_work);

    ib_destroy_qp(conn->rpc_qp.qp);
    ib_destroy_cq(conn->rpc_qp.cq);

    krdma_msg_pool_destroy(conn->recv_msg_pool);
    krdma_msg_pool_destroy(conn->send_msg_pool);

    rdma_destroy_qp(conn->cm_id);
    ib_destroy_cq(conn->rdma_qp.cq);
    rdma_destroy_id(conn->cm_id);

    krdma_msg_free(conn->recv_msg);
    krdma_msg_free(conn->send_msg);

    spin_lock(&conn_ht_lock);
    hash_del(&conn->hn);
    spin_unlock(&conn_ht_lock);

    kfree(conn);
    DEBUG_LOG("cleanup_connection\n");
}

static int connect_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
                      u32 local_psn, u32 remote_qpn, u32 remote_psn)
{
    int ret, mask;
    struct ib_qp_attr new_qp_attr;

    /* transition to INIT */
    mask  = IB_QP_STATE;
    mask |= IB_QP_ACCESS_FLAGS;
    mask |= IB_QP_PKEY_INDEX;
    mask |= IB_QP_PORT;

    memset(&new_qp_attr, 0, sizeof(new_qp_attr));
    new_qp_attr.qp_state = IB_QPS_INIT;
    new_qp_attr.qp_access_flags = qp_attr->qp_access_flags;
    new_qp_attr.pkey_index = qp_attr->pkey_index;
    new_qp_attr.port_num = qp_attr->port_num;

    ret = ib_modify_qp(qp, &new_qp_attr, mask);
    if (ret) {
        pr_err("error on ib_modify_qp: %d\n", ret);
        goto out;
    }

    /* trasition to RTR */
    mask  = IB_QP_STATE;
    mask |= IB_QP_AV;
    mask |= IB_QP_PATH_MTU;
    mask |= IB_QP_DEST_QPN;
    mask |= IB_QP_RQ_PSN;
    mask |= IB_QP_MAX_DEST_RD_ATOMIC;
    mask |= IB_QP_MIN_RNR_TIMER;

    memset(&new_qp_attr, 0, sizeof(new_qp_attr));
    new_qp_attr.qp_state = IB_QPS_RTR;
    new_qp_attr.ah_attr = qp_attr->ah_attr;
    new_qp_attr.path_mtu = qp_attr->path_mtu;
    new_qp_attr.dest_qp_num = remote_qpn;
    new_qp_attr.rq_psn = remote_psn;
    new_qp_attr.max_dest_rd_atomic = qp_attr->max_dest_rd_atomic;
    new_qp_attr.min_rnr_timer = qp_attr->min_rnr_timer;

    ret = ib_modify_qp(qp, &new_qp_attr, mask);
    if (ret) {
        pr_err("error on ib_modify_qp: %d\n", ret);
        goto out;
    }

    /* trasition to RTS */
    mask  = IB_QP_STATE;
    mask |= IB_QP_SQ_PSN;
    mask |= IB_QP_RETRY_CNT;
    mask |= IB_QP_RNR_RETRY;
    mask |= IB_QP_MAX_QP_RD_ATOMIC;
    mask |= IB_QP_TIMEOUT;

    memset(&new_qp_attr, 0, sizeof(new_qp_attr));
    new_qp_attr.qp_state = IB_QPS_RTS;
    new_qp_attr.sq_psn = local_psn;
    new_qp_attr.retry_cnt = qp_attr->retry_cnt;
    new_qp_attr.rnr_retry = qp_attr->rnr_retry;
    new_qp_attr.max_rd_atomic = qp_attr->max_rd_atomic;
    new_qp_attr.timeout = qp_attr->timeout;

    ret = ib_modify_qp(qp, &new_qp_attr, mask);
    if (ret) {
        pr_err("error on ib_modify_qp: %d\n", ret);
        goto out;
    }

    return 0;

out:
    return ret;
}

static int allocate_rpc_qp(struct krdma_conn *conn)
{
    int ret;
    struct rdma_cm_id *cm_id = conn->cm_id;
    struct ib_cq_init_attr cq_attr;
    struct ib_qp_init_attr qp_attr;

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.cqe = KRDMA_MAX_CQE;
    cq_attr.comp_vector = 0;

    conn->rpc_qp.cq = ib_create_cq(cm_id->device, krdma_cq_comp_handler,
                                   krdma_cq_event_handler, conn, &cq_attr);
    if (IS_ERR(conn->rpc_qp.cq)) {
        ret = PTR_ERR(conn->rpc_qp.cq);
        pr_err("error on ib_create_cq: %d\n", ret);
        goto out;
    }

    ret = ib_req_notify_cq(conn->rpc_qp.cq, IB_CQ_NEXT_COMP);
    if (ret) {
        pr_err("error on ib_req_notify_cq: %d\n", ret);
        goto out;
    }

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = (void *) conn;
    qp_attr.send_cq = conn->rpc_qp.cq;
    qp_attr.recv_cq = conn->rpc_qp.cq;
    qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
    qp_attr.qp_type = IB_QPT_RC;
    qp_attr.cap.max_send_wr = KRDMA_MAX_SEND_WR;
    qp_attr.cap.max_recv_wr = KRDMA_MAX_RECV_WR;
    qp_attr.cap.max_send_sge = KRDMA_MAX_SEND_SGE;
    qp_attr.cap.max_recv_sge = KRDMA_MAX_RECV_SGE;

    /* for flush_qp() ? */
    qp_attr.cap.max_send_wr++;
    qp_attr.cap.max_recv_wr++;

    conn->rpc_qp.qp = ib_create_qp(conn->pd, &qp_attr);
    if (IS_ERR(conn->rpc_qp.qp)) {
        ret = PTR_ERR(conn->rpc_qp.qp);
        pr_err("error on ib_create_qp: %d\n", ret);
        goto out_destroy_cq;
    }

    return 0;

out_destroy_cq:
    ib_destroy_cq(conn->rpc_qp.cq);
    conn->rpc_qp.cq = NULL;
out:
    return ret;
}

static int allocate_rdma_qp(struct krdma_conn *conn)
{
    int ret;
    struct ib_cq_init_attr cq_attr;
    struct ib_qp_init_attr qp_attr;
    struct krdma_qp *kqp = &conn->rdma_qp;

    /* Step 1: allocate CQ */
    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.cqe = KRDMA_MAX_CQE;
    cq_attr.comp_vector = 0;

    kqp->cq = ib_create_cq(
            conn->cm_id->device, NULL, NULL, conn, &cq_attr);
    if (IS_ERR(kqp->cq)) {
        ret = PTR_ERR(kqp->cq);
        pr_err("error on ib_create_cq: %d\n", ret);
        goto out;
    }

    /* Step 2: allocate QP */
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = (void *) conn;
    qp_attr.send_cq = kqp->cq;
    qp_attr.recv_cq = kqp->cq;
    qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
    qp_attr.qp_type = IB_QPT_RC;
    qp_attr.cap.max_send_wr = KRDMA_MAX_SEND_WR;
    qp_attr.cap.max_recv_wr = KRDMA_MAX_RECV_WR;
    qp_attr.cap.max_send_sge = KRDMA_MAX_SEND_SGE;
    qp_attr.cap.max_recv_sge = KRDMA_MAX_RECV_SGE;

    /* for flush_qp() */
    qp_attr.cap.max_send_wr++;
    qp_attr.cap.max_recv_wr++;

    ret = rdma_create_qp(conn->cm_id, conn->pd, &qp_attr);
    if (ret) {
        pr_err("error on rdma_create_qp: %d\n", ret);
        goto out;
    }
    kqp->qp = conn->cm_id->qp;

    return 0;

out:
    return ret;
}

static int addr_resolved(struct krdma_conn *conn)
{
    int ret;
    int timeout = 1000;

    conn->pd = global_pd;

    ret = allocate_rdma_qp(conn);
    if (ret) {
        pr_err("error on alocate_rdma_qp: %d\n", ret);
        goto out;
    }

    ret = rdma_resolve_route(conn->cm_id, timeout);
    if (ret) {
        pr_err("error on rdma_resolve_route: %d\n", ret);
        goto out_destroy_qp;
    }

    return 0;

out_destroy_qp:
    rdma_destroy_qp(conn->cm_id);
out:
    return ret;
}

static int route_resolved(struct krdma_conn *conn)
{
    int ret;
    const struct ib_recv_wr *bad_recv_wr;
    struct rdma_conn_param conn_param;

    conn->send_msg = krdma_msg_alloc(conn, 4096);
    if (conn->send_msg == NULL) {
        pr_err("error on krdma_msg_alloc\n");
        ret = -ENOMEM;
        goto out;
    }

    conn->recv_msg = krdma_msg_alloc(conn, 4096);
    if (conn->send_msg == NULL) {
        pr_err("error on krdma_msg_alloc\n");
        ret = -ENOMEM;
        goto out_free_send_msg;
    }

    ret = ib_post_recv(conn->rdma_qp.qp, &conn->recv_msg->recv_wr,
                       &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out_free_recv_msg;
    }

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.responder_resources = 1;
    conn_param.initiator_depth = 1;
    conn_param.retry_count = KRDMA_RETRY_COUNT;
    conn_param.rnr_retry_count = KRDMA_RNR_RETRY_COUNT;

    ret = rdma_connect(conn->cm_id, &conn_param);
    if (ret) {
        pr_err("error on rdma_connect: %d\n", ret);
        goto out;
    }

    return 0;

out_free_recv_msg:
    krdma_msg_free(conn->recv_msg);
out_free_send_msg:
    krdma_msg_free(conn->send_msg);
out:
    return ret;
}

static int established_client(struct krdma_conn *conn)
{
    int ret;
    struct krdma_msg *msg;
    const struct ib_recv_wr *bad_recv_wr;
    struct ib_qp_attr qp_attr;
    struct ib_qp_init_attr qp_init_attr;
    u32 local_qpn, local_psn, remote_qpn, remote_psn;

    DEBUG_LOG("established client: %p\n", conn->cm_id->device);

    /* Step 1: exchange the node name */
    strcpy((char *) conn->send_msg->buf, g_nodename);

    ret = handshake_client(conn);
    if (ret) {
        pr_err("error on handshake_client\n");
        goto out;
    }

    strcpy(conn->nodename, (char *) conn->recv_msg->buf);
    conn->nodehash = hashlen_hash(hashlen_string(NULL, conn->nodename));
    DEBUG_LOG("established client: handshake nodename: %s, nodehash: %u\n",
              conn->nodename, conn->nodehash);

    /* Step 2: allocate rpc_qp */
    ret = allocate_rpc_qp(conn);
    if (ret) {
        pr_err("error on allocate_rpc_qp: %d\n", ret);
        goto out;
    }

    /* Step 3: allocate a RPC message pool */
    conn->send_msg_pool = krdma_msg_pool_create(
            conn, KRDMA_SEND_MSG_POOL_SIZE, KRDMA_SEND_MSG_SIZE);
    if (conn->send_msg_pool == NULL) {
        pr_err("failed to allocate send message pool\n");
        ret = -ENOMEM;
        goto out_destroy_rpc_qp;
    }

    conn->recv_msg_pool = krdma_msg_pool_create(
            conn, KRDMA_RECV_MSG_POOL_SIZE, KRDMA_RECV_MSG_SIZE);
    if (conn->recv_msg_pool == NULL) {
        pr_err("failed to allocate recv message pool\n");
        ret = -ENOMEM;
        goto out_destroy_send_msg_pool;
    }

    /* Step 4: post the RPC message pool */
    spin_lock(&conn->recv_msg_pool->lock);
    list_for_each_entry(msg, &conn->recv_msg_pool->lh, lh) {
        ret = ib_post_recv(conn->rpc_qp.qp, &msg->recv_wr, &bad_recv_wr);
        if (ret) {
            pr_err("error on ib_post_recv: %d\n", ret);
            goto out_destroy_recv_msg_pool;
        }
    }
    spin_unlock(&conn->recv_msg_pool->lock);

    /* Step 5: exchange the QP data */
    local_qpn = conn->rpc_qp.qp->qp_num;
    local_psn = get_random_int() & 0xFFFFFF;

    ((u32 *) conn->send_msg->buf)[0] = local_qpn;
    ((u32 *) conn->send_msg->buf)[1] = local_psn;

    ret = handshake_client(conn);
    if (ret) {
        pr_err("error on handshake_client\n");
        goto out;
    }

    remote_qpn = ((u32 *) conn->recv_msg->buf)[0];
    remote_psn = ((u32 *) conn->recv_msg->buf)[1];

    DEBUG_LOG("established_client: handshake QP data: (%u, %u)\n",
              remote_qpn, remote_psn);

    /* Step 6: connect the QP, reuse the rdma_qp data */
    memset(&qp_attr, 0, sizeof(qp_attr));
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    ret = ib_query_qp(conn->rdma_qp.qp, &qp_attr, 0, &qp_init_attr);
    if (ret) {
        pr_err("error on ib_query_qp: %d\n", ret);
        goto out;
    }

    ret = connect_qp(conn->rpc_qp.qp, &qp_attr, local_psn, remote_qpn,
                     remote_psn);
    if (ret) {
        pr_err("failed to connect the rpc_qp\n");
        goto out_destroy_recv_msg_pool;
    }

    /* Step 7: add the connection to the hash table */
    spin_lock(&conn_ht_lock);
    hash_add(conn_ht, &conn->hn, conn->nodehash);
    spin_unlock(&conn_ht_lock);

    return 0;

out_destroy_recv_msg_pool:
    krdma_msg_pool_destroy(conn->recv_msg_pool);
    conn->recv_msg_pool = NULL;
out_destroy_send_msg_pool:
    krdma_msg_pool_destroy(conn->send_msg_pool);
    conn->send_msg_pool = NULL;
out_destroy_rpc_qp:
    ib_destroy_qp(conn->rpc_qp.qp);
    conn->rpc_qp.qp = NULL;
out:
    return ret;
}

static int krdma_cm_event_handler_client(struct rdma_cm_id *cm_id,
                                         struct rdma_cm_event *ev)
{
    int ret;
    struct krdma_conn *conn = cm_id->context;

    DEBUG_LOG("[client_handler] cm_event: %s (%d), status: %d, id: %p\n",
              rdma_event_msg(ev->event), ev->event, ev->status, cm_id);

    switch (ev->event) {
    case RDMA_CM_EVENT_ADDR_RESOLVED:
        ret = addr_resolved(conn);
        break;
    case RDMA_CM_EVENT_ROUTE_RESOLVED:
        ret = route_resolved(conn);
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        /* complete cm_done regardless of sucess or failure */
        ret = established_client(conn);
        conn->cm_error = ret;
        complete(&conn->cm_done);
        return 0;
    case RDMA_CM_EVENT_REJECTED:
    case RDMA_CM_EVENT_ROUTE_ERROR:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    case RDMA_CM_EVENT_UNREACHABLE:
    case RDMA_CM_EVENT_ADDR_ERROR:
        pr_err("CM error event: %s (%d)\n", rdma_event_msg(ev->event),
               ev->event);
        ret = -ECONNRESET;
        break;
    case RDMA_CM_EVENT_DISCONNECTED:
        ret = rdma_disconnect(conn->cm_id);
        schedule_work(&conn->cleanup_connection_work);
        break;
    case RDMA_CM_EVENT_ADDR_CHANGE:
    case RDMA_CM_EVENT_TIMEWAIT_EXIT:
    case RDMA_CM_EVENT_DEVICE_REMOVAL:
    default:
        pr_err("unexpected cm event (client): %s (%d)\n",
               rdma_event_msg(ev->event), ev->event);
        ret = -EINVAL;
        break;
    }

    if (ret) {
        conn->cm_error = ret;
        complete(&conn->cm_done);
    }

    /* Return zero here to make the client destroy the cm_id on error. */
    return 0;
}

static int connect_request(struct rdma_cm_id *cm_id)
{
    int ret;
    struct krdma_conn *conn;
    struct rdma_conn_param conn_param;
    const struct ib_recv_wr *bad_recv_wr;

    conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (conn == NULL) {
        pr_err("failed to allocate memory for krdma_conn\n");
        ret = -ENOMEM;
        goto out;
    }

    conn->cm_id = cm_id;
    conn->pd = global_pd;

    init_completion(&conn->cm_done);
    INIT_WORK(&conn->cleanup_connection_work, cleanup_connection);

    ret = allocate_rdma_qp(conn);
    if (ret) {
        pr_err("error on alocate_rdma_qp: %d\n", ret);
        goto out_kfree_conn;
    }

    /* allocate send message */
    conn->send_msg = krdma_msg_alloc(conn, 4096);
    if (conn->send_msg == NULL) {
        pr_err("error on krdma_msg_alloc\n");
        ret = -ENOMEM;
        goto out_destroy_qp;
    }
    /* allocate recv message */
    conn->recv_msg = krdma_msg_alloc(conn, 4096);
    if (conn->send_msg == NULL) {
        pr_err("error on krdma_msg_alloc\n");
        ret = -ENOMEM;
        goto out_free_send_msg;
    }

    ret = ib_post_recv(conn->rdma_qp.qp, &conn->recv_msg->recv_wr,
                       &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out_free_recv_msg;
    }

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.responder_resources = 1;
    conn_param.initiator_depth = 1;

    ret = rdma_accept(cm_id, &conn_param);
    if (ret) {
        pr_err("error on rdma_accept: %d\n", ret);
        goto out_free_recv_msg;
    }

    return 0;

out_free_recv_msg:
    krdma_msg_free(conn->recv_msg);
out_free_send_msg:
    krdma_msg_free(conn->send_msg);
out_destroy_qp:
    rdma_destroy_qp(conn->cm_id);
out_kfree_conn:
    kfree(conn);
out:
    return ret;
}

static int established_server(struct krdma_conn *conn)
{
    int ret;
    struct krdma_msg *msg;
    const struct ib_recv_wr *bad_recv_wr;
    struct ib_qp_attr qp_attr;
    struct ib_qp_init_attr qp_init_attr;
    u32 local_qpn, local_psn, remote_qpn, remote_psn;

    DEBUG_LOG("established server: %p\n", conn->cm_id->device);

    /* Step 1: exchange the node name */
    strcpy((char *) conn->send_msg->buf, g_nodename);

    ret = handshake_server(conn);
    if (ret) {
        pr_err("error on handshake_server\n");
        goto out;
    }

    strcpy(conn->nodename, (char *) conn->recv_msg->buf);
    conn->nodehash = hashlen_hash(hashlen_string(NULL, conn->nodename));
    DEBUG_LOG("established server: handshake nodename: %s, nodehash: %u\n",
              conn->nodename, conn->nodehash);

    /* Step 2: allocate rpc_qp */
    ret = allocate_rpc_qp(conn);
    if (ret) {
        pr_err("error on allocate_rpc_qp: %d\n", ret);
        goto out;
    }

    /* Step 3: allocate a RPC message pool */
    conn->send_msg_pool = krdma_msg_pool_create(
            conn, KRDMA_SEND_MSG_POOL_SIZE, KRDMA_SEND_MSG_SIZE);
    if (conn->send_msg_pool == NULL) {
        pr_err("failed to allocate send message pool\n");
        ret = -ENOMEM;
        goto out_destroy_rpc_qp;
    }

    conn->recv_msg_pool = krdma_msg_pool_create(
            conn, KRDMA_RECV_MSG_POOL_SIZE, KRDMA_RECV_MSG_SIZE);
    if (conn->recv_msg_pool == NULL) {
        pr_err("failed to allocate recv message pool\n");
        ret = -ENOMEM;
        goto out_destroy_send_msg_pool;
    }

    /* Step 4: post the RPC message pool */
    spin_lock(&conn->recv_msg_pool->lock);
    list_for_each_entry(msg, &conn->recv_msg_pool->lh, lh) {
        ret = ib_post_recv(conn->rpc_qp.qp, &msg->recv_wr, &bad_recv_wr);
        if (ret) {
            pr_err("error on ib_post_recv: %d\n", ret);
            goto out_destroy_recv_msg_pool;
        }
    }
    spin_unlock(&conn->recv_msg_pool->lock);

    /* Step 5: exchange the QP data */
    local_qpn = conn->rpc_qp.qp->qp_num;
    local_psn = get_random_int() & 0xFFFFFF;

    ((u32 *) conn->send_msg->buf)[0] = local_qpn;
    ((u32 *) conn->send_msg->buf)[1] = local_psn;

    ret = handshake_server(conn);
    if (ret) {
        pr_err("error on handshake_server\n");
        goto out;
    }

    remote_qpn = ((u32 *) conn->recv_msg->buf)[0];
    remote_psn = ((u32 *) conn->recv_msg->buf)[1];

    DEBUG_LOG("established_server: handshake QP data: (%u, %u)\n",
              remote_qpn, remote_psn);

    /* Step 6: connect the QP, reuse the rdma_qp data */
    memset(&qp_attr, 0, sizeof(qp_attr));
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    ret = ib_query_qp(conn->rdma_qp.qp, &qp_attr, 0, &qp_init_attr);
    if (ret) {
        pr_err("error on ib_query_qp: %d\n", ret);
        goto out;
    }

    ret = connect_qp(conn->rpc_qp.qp, &qp_attr, local_psn, remote_qpn,
                     remote_psn);
    if (ret) {
        pr_err("failed to connect the rpc_qp\n");
        goto out_destroy_recv_msg_pool;
    }

    /* Step 7: add the connection to the hash table */
    spin_lock(&conn_ht_lock);
    hash_add(conn_ht, &conn->hn, conn->nodehash);
    spin_unlock(&conn_ht_lock);

    return 0;

out_destroy_recv_msg_pool:
    krdma_msg_pool_destroy(conn->recv_msg_pool);
    conn->recv_msg_pool = NULL;
out_destroy_send_msg_pool:
    krdma_msg_pool_destroy(conn->send_msg_pool);
    conn->send_msg_pool = NULL;
out_destroy_rpc_qp:
    ib_destroy_qp(conn->rpc_qp.qp);
    conn->rpc_qp.qp = NULL;
out:
    return ret;
}

static int krdma_cm_event_handler_server(struct rdma_cm_id *cm_id,
                                         struct rdma_cm_event *ev)
{
    int ret;
    struct krdma_conn *conn = NULL;

    DEBUG_LOG("[server_handler] cm_event: %s (%d), status: %d, id: %p\n",
              rdma_event_msg(ev->event), ev->event, ev->status, cm_id);

    if (cm_id->qp)
        conn = cm_id->qp->qp_context;

    switch (ev->event) {
    case RDMA_CM_EVENT_CONNECT_REQUEST:
        ret = connect_request(cm_id);
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        ret = established_server(conn);
        break;
    case RDMA_CM_EVENT_ADDR_CHANGE:
    case RDMA_CM_EVENT_DISCONNECTED:
    case RDMA_CM_EVENT_TIMEWAIT_EXIT:
        ret = rdma_disconnect(conn->cm_id);
        schedule_work(&conn->cleanup_connection_work);
        break;
    case RDMA_CM_EVENT_REJECTED:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    default:
        pr_err("unexpected cm event (server): %s (%d)\n",
               rdma_event_msg(ev->event), ev->event);
        ret = -EINVAL;
    }

    if (ret) {
        pr_err("got an error while handling cm_event: %s\n",
               rdma_event_msg(ev->event));
    }

    return ret;
}

static int fill_sockaddr(struct sockaddr_storage *sin, uint8_t addr_type,
                         char *server, int port)
{
    int ret;
    u8 addr[16];

    memset(addr, 0, 16);
    memset(sin, 0, sizeof(*sin));

    if (addr_type == AF_INET) {
        struct sockaddr_in *sin4 = (struct sockaddr_in *) sin;
        sin4->sin_family = AF_INET;
        sin4->sin_port = htons(port);
        if (!in4_pton(server, -1, addr, -1, NULL)) {
            pr_err("error on in4_pton\n");
            ret = -EINVAL;
            goto out;
        }
        memcpy((void *) &sin4->sin_addr.s_addr, addr, 4);
    } else if (addr_type == AF_INET6) {
        /* TODO */
        ret = -EINVAL;
        goto out;
    } else {
        /* wrong address type! */
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    return ret;
}

static void krdma_add_ib_device(struct ib_device *ib_dev)
{
    struct krdma_ib_dev *krdma_ib_dev;

    DEBUG_LOG("add a ib_device to the list: %p\n", ib_dev);

    krdma_ib_dev = kzalloc(sizeof(struct krdma_ib_dev), GFP_KERNEL);
    if (krdma_ib_dev == NULL) {
        pr_err("failed to allocate memory for krdma_ib_dev\n");
        return;
    }

    krdma_ib_dev->ib_dev = ib_dev;
    INIT_LIST_HEAD(&krdma_ib_dev->head);

    spin_lock(&ib_dev_list_lock);
    list_add_tail(&krdma_ib_dev->head, &ib_dev_list);
    spin_unlock(&ib_dev_list_lock);
}

static void krdma_remove_ib_device(struct ib_device *ib_dev, void *client_data)
{
    struct krdma_ib_dev *krdma_ib_dev;
    struct krdma_ib_dev *target = NULL;

    DEBUG_LOG("remove a ib_device from the list: %p\n", ib_dev);

    spin_lock(&ib_dev_list_lock);
    list_for_each_entry(krdma_ib_dev, &ib_dev_list, head) {
        if (krdma_ib_dev->ib_dev == ib_dev) {
            target = krdma_ib_dev;
            break;
        }
    }
    if (target) {
        list_del_init(&target->head);
        kfree(target);
    }
    spin_unlock(&ib_dev_list_lock);
}

static struct ib_client krdma_ib_client = {
    .name       = "krdma",
    .add        = krdma_add_ib_device,
    .remove     = krdma_remove_ib_device
};


int krdma_setup(char *server, int port)
{
    int ret;
    int backlog = 128;
    struct sockaddr_storage sin;
    struct krdma_ib_dev *dev;

    ret = ib_register_client(&krdma_ib_client);
    if (ret) {
        pr_err("failed to register a ib_client\n");
        goto out;
    }

    dev = list_first_entry(&ib_dev_list, struct krdma_ib_dev, head);
    if (dev == NULL) {
        pr_err("failed to get a krdma_ib_dev from the list\n");
        goto out_unregister_ib_client;
    }

    global_pd = ib_alloc_pd(dev->ib_dev, IB_PD_UNSAFE_GLOBAL_RKEY);
    if (IS_ERR(global_pd)) {
        ret = PTR_ERR(global_pd);
        pr_err("failed to allocate global pd: %d\n", ret);
        goto out_unregister_ib_client;
    }

    server_cm_id = rdma_create_id(&init_net, krdma_cm_event_handler_server,
                                  NULL, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(server_cm_id)) {
        ret = PTR_ERR(server_cm_id);
        pr_err("error on rdma_create_id: %d\n", ret);
        goto out_dealloc_pd;
    }

    ret = fill_sockaddr(&sin, AF_INET, server, port);
    if (ret) {
        pr_err("error on fill_sockaddr\n");
        goto out_destroy_cm_id;
    }

    ret = rdma_bind_addr(server_cm_id, (struct sockaddr *) &sin);
    if (ret) {
        pr_err("error on rdma_bind_addr: %d\n", ret);
        goto out_destroy_cm_id;
    }

    ret = rdma_listen(server_cm_id, backlog);
    if (ret) {
        pr_err("error on rdma_listen: %d\n", ret);
        goto out_destroy_cm_id;
    }

    DEBUG_LOG("krdma_setup, server_cm_id: %p\n", server_cm_id);

    return 0;

out_destroy_cm_id:
    rdma_destroy_id(server_cm_id);
out_dealloc_pd:
    ib_dealloc_pd(global_pd);
    global_pd = NULL;
out_unregister_ib_client:
    ib_unregister_client(&krdma_ib_client);
out:
    return ret;
}

static int live_connections(void)
{
    int i = 0, n = 0;
    struct krdma_conn *conn;

    spin_lock(&conn_ht_lock);
    hash_for_each(conn_ht, i, conn, hn)
        n++;
    spin_unlock(&conn_ht_lock);

    return n;
}

void krdma_cleanup(void)
{
    int i = 0;
    struct krdma_conn *conn;

    spin_lock(&conn_ht_lock);
    hash_for_each(conn_ht, i, conn, hn)
        rdma_disconnect(conn->cm_id);
    spin_unlock(&conn_ht_lock);

    /* wait until all connections are cleaned up */
    while (live_connections() > 0)
        udelay(1000);

    rdma_destroy_id(server_cm_id);
    ib_dealloc_pd(global_pd);
    ib_unregister_client(&krdma_ib_client);

    server_cm_id = NULL;
    global_pd = NULL;

    DEBUG_LOG("krdma_cleanup, server_cm_id: %p\n", server_cm_id);
}

int krdma_connect(char *server, int port)
{
    int ret;
    int timeout = 100;
    struct krdma_conn *conn;
    struct sockaddr_storage dst_addr;

    conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (conn == NULL) {
        pr_err("failed to allocate memory for krdma_conn\n");
        ret = -ENOMEM;
        goto out;
    }

    init_completion(&conn->cm_done);
    INIT_WORK(&conn->cleanup_connection_work, cleanup_connection);

    conn->cm_id = rdma_create_id(&init_net, krdma_cm_event_handler_client,
                                 (void *) conn, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(conn->cm_id)) {
        ret = PTR_ERR(conn->cm_id);
        pr_err("failed to create a client cm_id: %d\n", ret);
        goto out_free_conn;
    }

    ret = fill_sockaddr(&dst_addr, AF_INET, server, port);
    if (ret) {
        pr_err("error on fill_sockaddr\n");
        goto out_destroy_cm_id;
    }

    ret = rdma_resolve_addr(conn->cm_id, NULL, (struct sockaddr *) &dst_addr,
                            timeout);
    if (ret) {
        pr_err("error on rdma_resolve_addr: %d", ret);
        goto out_destroy_cm_id;
    }

    ret = wait_for_completion_timeout(
            &conn->cm_done, msecs_to_jiffies(timeout));
    if (ret == 0) {
        pr_err("krdma_connect timeout\n");
        ret = -ETIMEDOUT;
        goto out_destroy_cm_id;
    }

    if (conn->cm_error) {
        pr_err("krdma_connect error: %d\n", conn->cm_error);
        ret = -ETIMEDOUT;
        goto out_destroy_cm_id;
    }

    return 0;

out_destroy_cm_id:
    rdma_destroy_id(conn->cm_id);
out_free_conn:
    kfree(conn);
out:
    return ret;
}
