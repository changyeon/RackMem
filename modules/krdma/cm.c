#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/dma-mapping.h>
#include <linux/utsname.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/stringhash.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <rdma/ib_verbs.h>

#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

static DEFINE_SPINLOCK(ht_lock);
static DEFINE_HASHTABLE(ht_krdma_node, 10);

extern char g_nodename[__NEW_UTS_LEN + 1];

struct rdma_cm_id *cm_id_server;

static void print_device_attr(struct ib_device_attr *dev_attr)
{
    u64 flags;
    flags = dev_attr->device_cap_flags;

    pr_info("fw_ver: %llu\n", dev_attr->fw_ver);
    pr_info("max_mr_size: %llu\n", dev_attr->max_mr_size);
    pr_info("page_size_cap: %llu\n", dev_attr->page_size_cap);
    pr_info("vendor_id: %u\n", dev_attr->vendor_id);
    pr_info("hw_ver: %u\n", dev_attr->hw_ver);
    pr_info("max_qp: %u\n", dev_attr->max_qp);
    pr_info("max_qp_wr: %u\n", dev_attr->max_qp_wr);
    pr_info("device_cap_flags: 0x%llx\n", dev_attr->device_cap_flags);
    pr_info("IB_DEV_MEM_MGT_EXTENSIONS: %llu\n",
            (flags & IB_DEVICE_MEM_MGT_EXTENSIONS) ? 1ULL : 0ULL);
    pr_info("max_send_sge: %d\n", dev_attr->max_send_sge);
    pr_info("max_recv_sge: %d\n", dev_attr->max_recv_sge);
    pr_info("max_cq: %d\n", dev_attr->max_cq);
    pr_info("max_cqe: %d\n", dev_attr->max_cqe);
    pr_info("max_mr: %d\n", dev_attr->max_mr);
    pr_info("max_pd: %d\n", dev_attr->max_pd);
    pr_info("max_ah: %d\n", dev_attr->max_ah);
    pr_info("max_srq: %d\n", dev_attr->max_srq);
    pr_info("max_srq_wr: %d\n", dev_attr->max_srq_wr);
    pr_info("max_srq_sge: %d\n", dev_attr->max_srq_sge);
    pr_info("max_fmr_pglist: %u\n", dev_attr->max_fast_reg_page_list_len);
    pr_info("max_pkeys: %u\n", dev_attr->max_pkeys);
}

static void print_port_attr(struct ib_device *dev)
{
    int i, ret;
    struct ib_port_attr port_attr;

    for (i = 0; i < dev->phys_port_cnt; i++) {
        memset(&port_attr, 0, sizeof(port_attr));
        ret = ib_query_port(dev, (u8) (i + 1), &port_attr);
        if (ret) {
            pr_err("error on ib_query_port: %d\n", ret);
            break;
        }
        pr_info("port_num: %d\n", i + 1);
        pr_info("max_mtu: %u\n", port_attr.max_mtu);
        pr_info("active_mtu: %u\n", port_attr.active_mtu);
        pr_info("port_cap_flags: %u\n", port_attr.port_cap_flags);
        pr_info("max_msg_sz: %u\n", port_attr.max_msg_sz);
        pr_info("sm_lid: %u\n", port_attr.sm_lid);
        pr_info("lid: %u\n", port_attr.lid);
        pr_info("active_width: %u\n", port_attr.active_width);
        pr_info("active_speed: %u\n", port_attr.active_speed);
        pr_info("===============================================\n");
    }
}

void static print_qp_attr(struct ib_qp *qp)
{
    int ret;
    struct ib_qp_attr qp_attr;
    struct ib_qp_init_attr qp_init_attr;

    ret = ib_query_qp(qp, &qp_attr, 0, &qp_init_attr);
    if (ret) {
        pr_err("error on ib_query_qp: %d\n", ret);
        return;
    }
    pr_info("qp_state: %d\n", qp_attr.qp_state);
    pr_info("cur_qp_state: %d\n", qp_attr.cur_qp_state);
    pr_info("path_mtu: %d\n", qp_attr.path_mtu);
    pr_info("qkey: %u\n", qp_attr.qkey);
    pr_info("rq_psn: %u\n", qp_attr.rq_psn);
    pr_info("sq_psn: %u\n", qp_attr.sq_psn);
    pr_info("dest_qp_num: %u\n", qp_attr.dest_qp_num);
    pr_info("qp_access_flags: %u\n", qp_attr.qp_access_flags);
    pr_info("pkey_index: %u\n", qp_attr.pkey_index);
    pr_info("min_rnr_timer: %u\n", qp_attr.min_rnr_timer);
    pr_info("qp_attr_port_num: %u\n", qp_attr.port_num);
    pr_info("timeout: %u\n", qp_attr.timeout);
    pr_info("retry_cnt: %u\n", qp_attr.retry_cnt);
    pr_info("rnr_retry: %u\n", qp_attr.rnr_retry);
    pr_info("rate_limit: %u\n", qp_attr.rate_limit);
    pr_info("max_send_wr: %u\n", qp_attr.cap.max_send_wr);
    pr_info("max_recv_wr: %u\n", qp_attr.cap.max_recv_wr);
    pr_info("max_send_sge: %u\n", qp_attr.cap.max_send_sge);
    pr_info("max_recv_sge: %u\n", qp_attr.cap.max_recv_sge);
    pr_info("max_inline_data: %u\n", qp_attr.cap.max_inline_data);
    pr_info("event_handler: %p\n", qp_init_attr.event_handler);
    pr_info("qp_context: %p\n", qp_init_attr.qp_context);
    pr_info("send_cq: %p\n", qp_init_attr.send_cq);
    pr_info("recv_cq: %p\n", qp_init_attr.recv_cq);
    pr_info("sq_sig_type: %d\n", qp_init_attr.sq_sig_type);
    pr_info("qp_type: %d\n", qp_init_attr.qp_type);
    pr_info("create_flags: %u\n", qp_init_attr.create_flags);
    pr_info("qp_init_attr_port_num: %u\n", qp_init_attr.port_num);
    pr_info("qp_num: %u\n", qp->qp_num);
    pr_info("qp_port: %u\n", qp->port);
    pr_info("source_qpn: %u\n", qp_init_attr.source_qpn);
}

/**
 * print the connection information
 */
static void print_conn(struct krdma_conn *conn)
{
    struct ib_device *dev;
    struct ib_device_attr *dev_attr;

    dev = conn->cm_id->device;
    dev_attr = &dev->attrs;

    pr_info("============ print connection info ============\n");
    pr_info("nodename: %s\n", conn->nodename);
    pr_info("cm_id: %p\n", conn->cm_id);
    pr_info("pd: %p, lkey: %u, rkey: %d, remote_rkey: %u\n",
            conn->pd, conn->lkey, conn->rkey, conn->remote_rkey);
    pr_info("rdma_qp: %p, rpc_qp: %p\n", conn->rdma_qp.qp, conn->rpc_qp.qp);

    pr_info("=========== print device attributes ===========\n");
    pr_info("name: %s\n", dev->name);
    pr_info("phys_port_cnt: %u\n", dev->phys_port_cnt);
    print_device_attr(dev_attr);

    pr_info("============ print port attributes ============\n");
    print_port_attr(dev);

    pr_info("========== print rdma qp attributes ===========\n");
    print_qp_attr(conn->rdma_qp.qp);

    pr_info("========= print rpc qp attributes =========\n");
    print_qp_attr(conn->rpc_qp.qp);

    pr_info("===============================================\n");
}

static void krdma_release_work(struct work_struct *ws)
{
    struct krdma_conn *conn;

    conn = container_of(ws, struct krdma_conn, release_work);
    DEBUG_LOG("start release work (%s)\n", conn->nodename);

    /* destroy rdma qp */
    rdma_destroy_qp(conn->cm_id);

    /* destroy rpc qp */
    ib_destroy_qp(conn->rpc_qp.qp);

    rdma_destroy_id(conn->cm_id);

    ib_destroy_cq(conn->rdma_qp.cq);
    ib_destroy_cq(conn->rpc_qp.cq);

    krdma_free_msg(conn, conn->send_msg);
    krdma_free_msg(conn, conn->recv_msg);
    krdma_free_msg_pool(conn, conn->recv_msg_pool);

    ib_dealloc_pd(conn->pd);

    spin_lock(&ht_lock);
    hash_del(&conn->hn);
    spin_unlock(&ht_lock);

    kfree(conn);
}

/**
 * Add the connection to the hashtable.
 */
static void add_krdma_node(struct krdma_conn *conn)
{
    unsigned int key;

    key = hashlen_hash(hashlen_string(ht_krdma_node, conn->nodename));
    spin_lock(&ht_lock);
    hash_add(ht_krdma_node, &conn->hn, key);
    spin_unlock(&ht_lock);
}

static void krdma_cq_comp_handler(struct ib_cq *cq, void *ctx)
{
    s64 poll_work_index;
    struct krdma_conn *conn = (struct krdma_conn *) ctx;

    poll_work_index = atomic64_fetch_add(1, &conn->poll_work_index);
    poll_work_index %= KRDMA_POLL_WORK_ARRAY_SIZE;
    schedule_work(&conn->poll_work_arr[poll_work_index].work);
}

static void krdma_cq_event_handler(struct ib_event *event, void *ctx)
{
    pr_info("cq_event_handler: (%s, %p)\n", ib_event_msg(event->event), ctx);
}

static int allocate_global_pd(struct krdma_conn *conn)
{
    int ret = 0;
    struct rdma_cm_id *cm_id = conn->cm_id;

    conn->pd = ib_alloc_pd(cm_id->device, IB_PD_UNSAFE_GLOBAL_RKEY);
    if (IS_ERR(conn->pd)) {
        ret = PTR_ERR(conn->pd);
        pr_err("error on ib_alloc_pd: %d\n", ret);
        goto out;
    }

    conn->lkey = conn->pd->local_dma_lkey;
    conn->rkey = conn->pd->unsafe_global_rkey;

    DEBUG_LOG("unsafe global pd lkey: %u, rkey: %u\n", conn->lkey, conn->rkey);

    return 0;

out:
    return ret;
}

static int connect_rpc_qp(struct krdma_conn *conn)
{
    int ret, mask;
    struct ib_device *dev = conn->cm_id->device;
    struct ib_qp_attr qp_attr;
    struct ib_qp_attr rpc_qp_attr;
    struct ib_qp_init_attr qp_init_attr;
    struct ib_port_attr port_attr;

    memset(&port_attr, 0, sizeof(port_attr));
    ret = ib_query_port(dev, (u8) 1, &port_attr);
    if (ret) {
        pr_err("error on ib_query_port: %d\n", ret);
        goto out;
    }

    memset(&qp_attr, 0, sizeof(qp_attr));
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    ret = ib_query_qp(conn->rdma_qp.qp, &qp_attr, 0, &qp_init_attr);
    if (ret) {
        pr_err("error on ib_query_qp: %d\n", ret);
        goto out;
    }

    /* transition to INIT */
    mask  = IB_QP_STATE;
    mask |= IB_QP_ACCESS_FLAGS;
    mask |= IB_QP_PKEY_INDEX;
    mask |= IB_QP_PORT;

    memset(&rpc_qp_attr, 0, sizeof(rpc_qp_attr));
    rpc_qp_attr.qp_state = IB_QPS_INIT;
    rpc_qp_attr.qp_access_flags = qp_attr.qp_access_flags;
    rpc_qp_attr.pkey_index = qp_attr.pkey_index;
    rpc_qp_attr.port_num = qp_attr.port_num;

    ret = ib_modify_qp(conn->rpc_qp.qp, &rpc_qp_attr, mask);
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

    memset(&rpc_qp_attr, 0, sizeof(rpc_qp_attr));
    rpc_qp_attr.qp_state = IB_QPS_RTR;
    rpc_qp_attr.ah_attr = qp_attr.ah_attr;
    rpc_qp_attr.path_mtu = qp_attr.path_mtu;
    rpc_qp_attr.dest_qp_num = conn->rpc_qp.remote_qpn;
    rpc_qp_attr.rq_psn = conn->rpc_qp.remote_psn;
    rpc_qp_attr.max_dest_rd_atomic = qp_attr.max_dest_rd_atomic;
    rpc_qp_attr.min_rnr_timer = qp_attr.min_rnr_timer;

    ret = ib_modify_qp(conn->rpc_qp.qp, &rpc_qp_attr, mask);
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

    memset(&rpc_qp_attr, 0, sizeof(rpc_qp_attr));
    rpc_qp_attr.qp_state = IB_QPS_RTS;
    rpc_qp_attr.sq_psn = conn->rpc_qp.local_psn;
    rpc_qp_attr.retry_cnt = qp_attr.retry_cnt;
    rpc_qp_attr.rnr_retry = qp_attr.rnr_retry;
    rpc_qp_attr.max_rd_atomic = qp_attr.max_rd_atomic;
    rpc_qp_attr.timeout = qp_attr.timeout;

    ret = ib_modify_qp(conn->rpc_qp.qp, &rpc_qp_attr, mask);
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
    cq_attr.cqe = KRDMA_CM_MAX_CQE;
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
    qp_attr.cap.max_send_wr = KRDMA_CM_MAX_SEND_WR;
    qp_attr.cap.max_recv_wr = KRDMA_CM_MAX_RECV_WR;
    qp_attr.cap.max_send_sge = KRDMA_CM_MAX_SEND_SGE;
    qp_attr.cap.max_recv_sge = KRDMA_CM_MAX_RECV_SGE;

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
    int ret = 0;
    struct rdma_cm_id *cm_id = conn->cm_id;
    struct krdma_qp *kqp = &conn->rdma_qp;
    struct ib_cq_init_attr cq_attr;
    struct ib_qp_init_attr qp_attr;

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.cqe = KRDMA_CM_MAX_CQE;
    cq_attr.comp_vector = 0;

    kqp->cq = ib_create_cq(cm_id->device, NULL, NULL, conn, &cq_attr);
    if (IS_ERR(kqp->cq)) {
        ret = PTR_ERR(kqp->cq);
        pr_err("error on ib_create_cq: %d\n", ret);
        goto out;
    }

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = (void *) conn;
    qp_attr.send_cq = kqp->cq;
    qp_attr.recv_cq = kqp->cq;
    qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
    qp_attr.qp_type = IB_QPT_RC;
    qp_attr.cap.max_send_wr = KRDMA_CM_MAX_SEND_WR;
    qp_attr.cap.max_recv_wr = KRDMA_CM_MAX_RECV_WR;
    qp_attr.cap.max_send_sge = KRDMA_CM_MAX_SEND_SGE;
    qp_attr.cap.max_recv_sge = KRDMA_CM_MAX_RECV_SGE;

    /* for flush_qp() ? */
    qp_attr.cap.max_send_wr++;
    qp_attr.cap.max_recv_wr++;

    ret = rdma_create_qp(cm_id, conn->pd, &qp_attr);
    if (ret) {
        pr_err("error on rdma_create_qp: %d\n", ret);
        goto out_destroy_cq;
    }

    kqp->qp = cm_id->qp;

    return 0;

out_destroy_cq:
    ib_destroy_cq(kqp->cq);
    kqp->cq = NULL;
out:
    return ret;
}

/**
 * server side connection request handling
 */
static int krdma_cm_connect_request(struct rdma_cm_id *cm_id)
{
    int i, ret;
    struct krdma_conn *conn;
    struct rdma_conn_param param;
    const struct ib_recv_wr *bad_recv_wr;

    conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (conn == NULL) {
        pr_err("failed to allocate memory for cm connection\n");
        ret = -ENOMEM;
        goto out;
    }

    init_completion(&conn->cm_done);
    INIT_WORK(&conn->release_work, krdma_release_work);

    atomic64_set(&conn->poll_work_index, 0);
    for (i = 0; i < KRDMA_POLL_WORK_ARRAY_SIZE; i++) {
        INIT_WORK(&conn->poll_work_arr[i].work, krdma_poll_work);
        conn->poll_work_arr[i].conn = conn;
    }

    conn->cm_id = cm_id;

    ret = allocate_global_pd(conn);
    if (ret) {
        pr_err("error on allocate_global_pd: %d\n", ret);
        goto out_kfree;
    }

    ret = allocate_rdma_qp(conn);
    if (ret) {
        pr_err("error on allocate_rdma_qp: %d\n", ret);
        goto out_dealloc_pd;
    }

    /* setup a message buffer for send */
    conn->send_msg = krdma_alloc_msg(conn, PAGE_SIZE);
    if (conn->send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        goto out_destroy_qp;
    }

    /* setup a message buffer for recv */
    conn->recv_msg = krdma_alloc_msg(conn, PAGE_SIZE);
    if (conn->recv_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        goto out_free_send_msg;
    }

    ret = ib_post_recv(conn->rdma_qp.qp, &conn->recv_msg->recv_wr,
                       &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out_free_recv_msg;
    }

    memset(&param, 0, sizeof(param));
    param.responder_resources = 1;
    param.initiator_depth = 1;

    ret = rdma_accept(cm_id, &param);
    if (ret) {
        pr_err("error on rdma_accept: %d\n", ret);
        goto out_free_recv_msg;
    }

    return 0;

out_free_recv_msg:
    krdma_free_msg(conn, conn->recv_msg);
out_free_send_msg:
    krdma_free_msg(conn, conn->send_msg);
out_destroy_qp:
    rdma_destroy_qp(conn->cm_id);
    ib_destroy_cq(conn->rdma_qp.cq);
out_dealloc_pd:
    ib_dealloc_pd(conn->pd);
out_kfree:
    kfree(conn);
out:
    return ret;
}

static int krdma_post_wr(struct krdma_conn *conn, int n)
{
    int ret;
    struct krdma_msg *recv_msg = NULL;
    const struct ib_recv_wr *bad_recv_wr;
    struct krdma_msg_pool *pool;

    pool = krdma_alloc_msg_pool(conn, n, KRDMA_MSG_BUF_SIZE);
    if (pool == NULL) {
        pr_err("error on krdma_alloc_msg_pool\n");
        ret = -ENOMEM;
        goto out;
    }

    list_for_each_entry(recv_msg, &pool->head, head) {
        ret = ib_post_recv(conn->rpc_qp.qp, &recv_msg->recv_wr, &bad_recv_wr);
        if (ret) {
            pr_err("error on ib_post_recv: %d\n", ret);
            goto out_free_msg_pool;
        }
    }

    conn->recv_msg_pool = pool;

    return 0;

out_free_msg_pool:
    krdma_free_msg_pool(conn, pool);
out:
    return ret;
}

static void handshake_server(struct krdma_conn *conn)
{
    int ret;
    const struct ib_send_wr *bad_send_wr;
    const struct ib_recv_wr *bad_recv_wr;
    const struct ib_send_wr *send_wr = &conn->send_msg->send_wr;
    const struct ib_recv_wr *recv_wr = &conn->recv_msg->recv_wr;

    /* poll recv */
    krdma_poll_cq_one(conn->rdma_qp.cq);

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
    krdma_poll_cq_one(conn->rdma_qp.cq);

out:
    return;
}

static void handshake_client(struct krdma_conn *conn)
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
    krdma_poll_cq_one(conn->rdma_qp.cq);

    /* poll recv */
    krdma_poll_cq_one(conn->rdma_qp.cq);

    ret = ib_post_recv(conn->rdma_qp.qp, recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

out:
    return;
}

static int krdma_cm_established_server(struct krdma_conn *conn)
{
    int ret = 0;
    struct qp_msg_fmt *fmt;

    /* create an additional QP for rpc */
    ret = allocate_rpc_qp(conn);
    if (ret) {
        pr_err("error on allocate_rpc_qp: %d\n", ret);
        goto out;
    }

    ret = krdma_post_wr(conn, KRDMA_RECV_WR_POOL_SIZE);
    if (ret) {
        pr_err("error on krdma_post_wr\n");
        goto out;
    }

    conn->rpc_qp.local_qpn = conn->rpc_qp.qp->qp_num;
    conn->rpc_qp.local_psn = get_random_int() & 0xFFFFFF;
    conn->rpc_qp.local_lid = conn->rpc_qp.qp->port;

    DEBUG_LOG("local_qpn: %u, local_psn: %u, local_lid: %u\n",
              conn->rpc_qp.local_qpn, conn->rpc_qp.local_psn,
              conn->rpc_qp.local_lid);

    fmt = (struct qp_msg_fmt *) conn->send_msg->vaddr;
    fmt->qpn = conn->rpc_qp.local_qpn;
    fmt->psn = conn->rpc_qp.local_psn;
    fmt->lid = conn->rpc_qp.local_lid;

    handshake_server(conn);

    fmt = (struct qp_msg_fmt *) conn->recv_msg->vaddr;
    conn->rpc_qp.remote_qpn = fmt->qpn;
    conn->rpc_qp.remote_psn = fmt->psn;
    conn->rpc_qp.remote_lid = fmt->lid;

    DEBUG_LOG("remote_qpn: %u, remote_psn: %u, remote_lid: %u\n",
              conn->rpc_qp.remote_qpn, conn->rpc_qp.remote_psn,
              conn->rpc_qp.remote_lid);

    /* connect the rpc QP */
    ret = connect_rpc_qp(conn);
    if (ret) {
        pr_err("error on connect_rpc_qp: %d\n", ret);
        goto out;
    }
    handshake_server(conn);

    /* register krdma rpc functions */
    ret = register_all_krdma_rpc();
    if (ret) {
        pr_err("error on register_all_krdma_rpc\n");
        goto out;
    }
    handshake_server(conn);

    /* get remote_rkey */
    ret = krdma_get_remote_rkey(conn);
    if (ret < 0) {
        pr_err("error on krdma_get_remote_rkey\n");
        goto out;
    }
    conn->remote_rkey = ret;

    /* update the remote node name and add it to the node hash table */
    ret = krdma_get_node_name(conn, conn->nodename);
    if (ret) {
        pr_err("error on krdma_get_node_name\n");
        goto out;
    }
    add_krdma_node(conn);

    if (g_debug)
        print_conn(conn);

    pr_info("connection established with %s\n", conn->nodename);

    return 0;

out:
    pr_err("failed to establish the connection: %p\n", conn);

    /*
     * add this connection to the hash table to prevent the release worker
     * try to delete the dangling conn from the hash table.
     */
    add_krdma_node(conn);
    rdma_disconnect(conn->cm_id);

    return ret;
}

static int krdma_cm_established_client(struct krdma_conn *conn)
{
    int ret = 0;
    struct qp_msg_fmt *fmt;

    /* create an additional QP for rpc */
    ret = allocate_rpc_qp(conn);
    if (ret) {
        pr_err("error on allocate_rpc_qp: %d\n", ret);
        goto out;
    }

    ret = krdma_post_wr(conn, KRDMA_RECV_WR_POOL_SIZE);
    if (ret) {
        pr_err("error on krdma_post_wr\n");
        goto out;
    }

    conn->rpc_qp.local_qpn = conn->rpc_qp.qp->qp_num;
    conn->rpc_qp.local_psn = get_random_int() & 0xFFFFFF;
    conn->rpc_qp.local_lid = conn->rpc_qp.qp->port;

    DEBUG_LOG("local_qpn: %u, local_psn: %u, local_lid: %u\n",
              conn->rpc_qp.local_qpn, conn->rpc_qp.local_psn,
              conn->rpc_qp.local_lid);

    fmt = (struct qp_msg_fmt *) conn->send_msg->vaddr;
    fmt->qpn = conn->rpc_qp.local_qpn;
    fmt->psn = conn->rpc_qp.local_psn;
    fmt->lid = conn->rpc_qp.local_lid;

    handshake_client(conn);

    fmt = (struct qp_msg_fmt *) conn->recv_msg->vaddr;
    conn->rpc_qp.remote_qpn = fmt->qpn;
    conn->rpc_qp.remote_psn = fmt->psn;
    conn->rpc_qp.remote_lid = fmt->lid;

    DEBUG_LOG("remote_qpn: %u, remote_psn: %u, remote_lid: %u\n",
              conn->rpc_qp.remote_qpn, conn->rpc_qp.remote_psn,
              conn->rpc_qp.remote_lid);

    /* connect the rpc QP */
    ret = connect_rpc_qp(conn);
    if (ret) {
        pr_err("error on connect_rpc_qp: %d\n", ret);
        goto out;
    }
    handshake_client(conn);

    /* register krdma rpc functions */
    ret = register_all_krdma_rpc();
    if (ret) {
        pr_err("error on register_all_krdma_rpc\n");
        goto out;
    }
    handshake_client(conn);

    /* get remote_rkey */
    ret = krdma_get_remote_rkey(conn);
    if (ret < 0) {
        pr_err("error on krdma_get_remote_rkey\n");
        goto out;
    }
    conn->remote_rkey = ret;

    /* update the remote node name and add it to the node hash table */
    ret = krdma_get_node_name(conn, conn->nodename);
    if (ret) {
        pr_err("error on krdma_get_node_name\n");
        goto out;
    }
    add_krdma_node(conn);

    if (g_debug)
        print_conn(conn);

    pr_info("connection established with %s\n", conn->nodename);

    return 0;

out:
    pr_err("failed to establish the connection: %p\n", conn);

    /*
     * add this connection to the hash table to prevent the release worker
     * try to delete the dangling conn from the hash table.
     */
    add_krdma_node(conn);
    rdma_disconnect(conn->cm_id);

    return ret;
}

static int krdma_cm_handler_server(struct rdma_cm_id *cm_id,
                                   struct rdma_cm_event *ev)
{
    int ret = 0;
    struct krdma_conn *conn = NULL;

    if (cm_id->qp)
        conn = cm_id->qp->qp_context;

    DEBUG_LOG("cm_event: %s (%d), status: %d, id: %p\n",
              rdma_event_msg(ev->event), ev->event, ev->status, cm_id);

    switch (ev->event) {
    case RDMA_CM_EVENT_CONNECT_REQUEST:
        ret = krdma_cm_connect_request(cm_id);
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        ret = krdma_cm_established_server(conn);
        break;
    case RDMA_CM_EVENT_ADDR_CHANGE:
    case RDMA_CM_EVENT_DISCONNECTED:
    case RDMA_CM_EVENT_TIMEWAIT_EXIT:
        rdma_disconnect(conn->cm_id);
        schedule_work(&conn->release_work);
        break;
    case RDMA_CM_EVENT_REJECTED:
        break;
    case RDMA_CM_EVENT_CONNECT_ERROR:
        break;
    default:
        pr_err("unexpected cm event (server): %s (%d)\n",
               rdma_event_msg(ev->event), ev->event);
        break;
    }

    return 0;
}

static int krdma_cm_addr_resolved(struct krdma_conn *conn)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    int ret = 0;

    ret = allocate_global_pd(conn);
    if (ret) {
        pr_err("error on allocate_global_pd: %d\n", ret);
        goto out;
    }

    ret = allocate_rdma_qp(conn);
    if (ret) {
        pr_err("error on allocate_rdma_qp: %d\n", ret);
        goto out_dealloc_pd;
    }

    ret = rdma_resolve_route(cm_id, KRDMA_CM_TIMEOUT);
    if (ret) {
        pr_err("error on rdma_resolve_route: %d\n", ret);
        goto out_release_qp;
    }

    return 0;

out_release_qp:
    rdma_destroy_qp(conn->cm_id);
    ib_destroy_cq(conn->rdma_qp.cq);
out_dealloc_pd:
    ib_dealloc_pd(conn->pd);
out:
    return ret;
}

static int krdma_cm_route_resolved(struct krdma_conn *conn)
{
    int ret = 0;
    struct rdma_conn_param param;
    const struct ib_recv_wr *bad_recv_wr;

    /* setup a message buffer for send */
    conn->send_msg = krdma_alloc_msg(conn, PAGE_SIZE);
    if (conn->send_msg == NULL) {
        ret = -ENOMEM;
        pr_err("error on krdma_alloc_msg\n");
        goto out_destroy_qp;
    }

    /* setup a message buffer for recv */
    conn->recv_msg = krdma_alloc_msg(conn, PAGE_SIZE);
    if (conn->recv_msg == NULL) {
        ret = -ENOMEM;
        pr_err("error on krdma_alloc_msg\n");
        goto out_free_send_msg;
    }

    ret = ib_post_recv(conn->rdma_qp.qp, &conn->recv_msg->recv_wr,
                       &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out_free_recv_msg;
    }

    memset(&param, 0, sizeof(param));
    param.responder_resources = 1;
    param.initiator_depth = 1;
    param.retry_count = KRDMA_CM_RETRY_COUNT;
    param.rnr_retry_count = KRDMA_CM_RNR_RETRY_COUNT;

    ret = rdma_connect(conn->cm_id, &param);
    if (ret) {
        pr_err("error on rdma_connect: %d\n", ret);
        goto out_free_recv_msg;
    }

    return 0;

out_free_recv_msg:
    krdma_free_msg(conn, conn->recv_msg);
out_free_send_msg:
    krdma_free_msg(conn, conn->send_msg);
out_destroy_qp:
    rdma_destroy_qp(conn->cm_id);
    ib_destroy_cq(conn->rdma_qp.cq);
    ib_dealloc_pd(conn->pd);

    return ret;
}

static int krdma_cm_conn_rejected(struct krdma_conn *conn,
                                  struct rdma_cm_event *ev)
{
    pr_err("connect rejected: %s (%d)\n",
           rdma_reject_msg(conn->cm_id, ev->status), ev->status);

    return -ECONNRESET;
}

static int krdma_cm_handler_client(struct rdma_cm_id *cm_id,
                                   struct rdma_cm_event *ev)
{
    int cm_error = 0;
    struct krdma_conn *conn = cm_id->context;

    DEBUG_LOG("cm_event: %s (%d), status: %d, id: %p\n",
              rdma_event_msg(ev->event), ev->event, ev->status, cm_id);

    switch(ev->event) {
    case RDMA_CM_EVENT_ADDR_RESOLVED:
        cm_error = krdma_cm_addr_resolved(conn);
        break;
    case RDMA_CM_EVENT_ROUTE_RESOLVED:
        cm_error = krdma_cm_route_resolved(conn);
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        conn->cm_error = krdma_cm_established_client(conn);
        /* complete cm_done regardless of sucess/failure */
        complete(&conn->cm_done);
        return 0;
    case RDMA_CM_EVENT_REJECTED:
        pr_err("connection rejected!: %s (%d)\n", rdma_event_msg(ev->event),
               ev->event);
        cm_error = krdma_cm_conn_rejected(conn, ev);
        break;
    case RDMA_CM_EVENT_ROUTE_ERROR:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    case RDMA_CM_EVENT_UNREACHABLE:
    case RDMA_CM_EVENT_ADDR_ERROR:
        pr_err("CM error event: %s (%d)\n", rdma_event_msg(ev->event),
               ev->event);
        cm_error = -ECONNRESET;
        break;
    case RDMA_CM_EVENT_DISCONNECTED:
        rdma_disconnect(conn->cm_id);
        schedule_work(&conn->release_work);
        break;
    case RDMA_CM_EVENT_ADDR_CHANGE:
    case RDMA_CM_EVENT_TIMEWAIT_EXIT:
    case RDMA_CM_EVENT_DEVICE_REMOVAL:
    default:
        pr_err("unexpected cm event (client): %s (%d)\n",
               rdma_event_msg(ev->event), ev->event);
        break;
    }

    if (cm_error) {
        conn->cm_error = cm_error;
        complete(&conn->cm_done);
    }

    return 0;
}

static int fill_sockaddr(struct sockaddr_storage *sin, uint8_t addr_type,
                         char *server, int port)
{
    int ret = 0;
    u8 addr[16];

    memset(addr, 0, 16);
    memset(sin, 0, sizeof(*sin));

    if (addr_type == AF_INET) {
        struct sockaddr_in *sin4 = (struct sockaddr_in *) sin;
        sin4->sin_family = AF_INET;
        sin4->sin_port = htons(port);
        if (!in4_pton(server, -1, addr, -1, NULL)) {
            pr_err("error on in4_pton\n");
            ret = 1;
            goto out;
        }
        memcpy((void *) &sin4->sin_addr.s_addr, addr, 4);
    } else if (addr_type == AF_INET6) {
        /* TODO */
        ret = 1;
    } else {
        /* wrong address type! */
        ret = 1;
    }

out:
    return ret;
}

int krdma_cm_connect(char *server, int port)
{
    int i, ret = 0;
    struct krdma_conn *conn;
    struct sockaddr_storage sin;
    unsigned long jiffies;

    conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (conn == NULL) {
        pr_err("failed to allocate memory for cm connection\n");
        goto out;
    }

    init_completion(&conn->cm_done);
    INIT_WORK(&conn->release_work, krdma_release_work);

    atomic64_set(&conn->poll_work_index, 0);
    for (i = 0; i < KRDMA_POLL_WORK_ARRAY_SIZE; i++) {
        INIT_WORK(&conn->poll_work_arr[i].work, krdma_poll_work);
        conn->poll_work_arr[i].conn = conn;
    }

    conn->cm_id = rdma_create_id(&init_net, krdma_cm_handler_client,
                                 (void *) conn, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(conn->cm_id)) {
        ret = PTR_ERR(conn->cm_id);
        pr_err("error on rdma_create_id: %d\n", ret);
        goto out_free_conn;
    }

    if (fill_sockaddr(&sin, AF_INET, server, port)) {
        pr_err("error on fill_sockaddr\n");
        ret = -EINVAL;
        goto out_destroy_cm_id;
    }

    ret = rdma_resolve_addr(conn->cm_id, NULL, (struct sockaddr *) &sin,
                            KRDMA_CM_TIMEOUT);
    if (ret) {
        pr_err("error on rdma_resolve_addr: %d", ret);
        goto out_destroy_cm_id;
    }

    jiffies = msecs_to_jiffies(KRDMA_CM_TIMEOUT) + 1;
    ret = wait_for_completion_timeout(&conn->cm_done, jiffies);
    if (ret == 0) {
        pr_err("krdma_cm_connect timeout\n");
        ret = -ETIMEDOUT;
        goto out_destroy_cm_id;
    }

    if (conn->cm_error) {
        pr_err("krdma_cm_connect error: %d\n", conn->cm_error);
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

int krdma_cm_setup(char *server, int port, void *context)
{
    int ret;
    int backlog = 128;
    struct rdma_cm_id *cm_id;
    struct sockaddr_storage sin;

     /* NOTE: returning non-zero value from the handler will destroy cm_id. */
    cm_id = rdma_create_id(&init_net, krdma_cm_handler_server, context,
                           RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(cm_id)) {
        ret = PTR_ERR(cm_id);
        pr_err("error on rdma_create_id: %d\n", ret);
        goto out;
    }

    if (fill_sockaddr(&sin, AF_INET, server, port)) {
        pr_err("error on fill_sockaddr\n");
        goto out_destroy_cm_id;
    }

    ret = rdma_bind_addr(cm_id, (struct sockaddr *) &sin);
    if (ret) {
        pr_err("error on rdma_bind_addr: %d\n", ret);
        goto out_destroy_cm_id;
    }

    ret = rdma_listen(cm_id, backlog);
    if (ret) {
        pr_err("error on rdma_listen: %d\n", ret);
        goto out_destroy_cm_id;
    }

    cm_id_server = cm_id;

    return 0;

out_destroy_cm_id:
    rdma_destroy_id(cm_id);
out:
    return -1;
}

/**
 * Returns the number of live connections.
 */
static int get_nr_live_conn(void)
{
    int i = 0, n = 0;
    struct krdma_conn *curr;

    spin_lock(&ht_lock);
    hash_for_each(ht_krdma_node, i, curr, hn) {
        n++;
    }
    spin_unlock(&ht_lock);

    return n;
}

void krdma_cm_cleanup(void)
{
    int i = 0;
    struct krdma_conn *curr;

    spin_lock(&ht_lock);
    hash_for_each(ht_krdma_node, i, curr, hn) {
        rdma_disconnect(curr->cm_id);
    }
    spin_unlock(&ht_lock);

    while (get_nr_live_conn() > 0)
        msleep(100);

    rdma_destroy_id(cm_id_server);
}

int krdma_get_all_nodes(struct krdma_conn *nodes[], int n)
{
    int i = 0, size = 0;
    struct krdma_conn *curr;

    spin_lock(&ht_lock);
    hash_for_each(ht_krdma_node, i, curr, hn) {
        if (size >= n)
            break;
        nodes[size++] = curr;
    }
    spin_unlock(&ht_lock);

    return size;
}
EXPORT_SYMBOL(krdma_get_all_nodes);


/**
 * krdma_get_node - Returns the node associated with the given name.
 * If a name is not given, it returns the first node in the list.
 */
struct krdma_conn *krdma_get_node(char *nodename)
{
    int bkt;
    bool success = false;
    unsigned int key;
    struct krdma_conn *conn = NULL;

    if (hash_empty(ht_krdma_node)) {
        pr_err("the node hash table is null\n");
        goto out;
    }

    if (nodename == NULL) {
        hash_for_each(ht_krdma_node, bkt, conn, hn) {
            /* break here to return the first node in the hash table */
            goto success;
        }
    }

    key = hashlen_hash(hashlen_string(ht_krdma_node, nodename));
    hash_for_each_possible(ht_krdma_node, conn, hn, key) {
        if (strcmp(conn->nodename, nodename) == 0) {
            success = true;
            break;
        }
    }

    if (!success) {
        pr_err("the node %s does not exists in the table\n", nodename);
        goto out;
    }

success:
    return conn;
out:
    return NULL;
}
EXPORT_SYMBOL(krdma_get_node);
