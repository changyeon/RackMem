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

#include "cm.h"
#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

static DEFINE_SPINLOCK(ht_lock);
static DEFINE_HASHTABLE(ht_krdma_node, 10);

extern char g_nodename[__NEW_UTS_LEN + 1];

static struct krdma_cm_context {
    struct rdma_cm_id *cm_id_server;
} krdma_cm_context;

static const char * const wc_opcodes[] = {
    [IB_WC_SEND]                = "SEND",
    [IB_WC_RDMA_WRITE]          = "RDMA_WRITE",
    [IB_WC_RDMA_READ]           = "RDMA_READ",
    [IB_WC_COMP_SWAP]           = "COMP_SWAP",
    [IB_WC_FETCH_ADD]           = "FETCH_ADD",
    [IB_WC_LSO]                 = "LSO",
    [IB_WC_LOCAL_INV]           = "LOCAL_INV",
    [IB_WC_REG_MR]              = "REG_MR",
    [IB_WC_MASKED_COMP_SWAP]    = "MASKED_COMP_SWAP",
    [IB_WC_MASKED_FETCH_ADD]    = "MASKED_FETCH_ADD",
    [IB_WC_RECV]                = "RECV",
    [IB_WC_RECV_RDMA_WITH_IMM]  = "RECV_RDMA_WITH_IMM",
};

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
    pr_info("max_fmr: %d\n", dev_attr->max_fmr);
    pr_info("max_srq: %d\n", dev_attr->max_fmr);
    pr_info("max_srq_wr: %d\n", dev_attr->max_fmr);
    pr_info("max_srq_sge: %d\n", dev_attr->max_fmr);
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
    pr_info("pd: %p, cq: %p, qp: %p\n", conn->pd, conn->cq, conn->qp);
    pr_info("lkey: %u, rkey: %u\n", conn->lkey, conn->rkey);
    pr_info("send_dma_addr: %llu, recv_dma_addr: %llu\n", conn->send_dma_addr,
            conn->recv_dma_addr);
    pr_info("rdma_buf: %p, rdma_dma_addr: %llu\n", conn->rdma_buf,
            conn->rdma_dma_addr);

    pr_info("=========== print device attributes ===========\n");
    pr_info("name: %s\n", dev->name);
    pr_info("phys_port_cnt: %u\n", dev->phys_port_cnt);
    print_device_attr(dev_attr);

    pr_info("============ print port attributes ============\n");
    print_port_attr(dev);

    pr_info("========== print rdma qp attributes ===========\n");
    print_qp_attr(conn->qp);

    pr_info("========= print message qp attributes =========\n");
    print_qp_attr(conn->msg_qp);

    pr_info("===============================================\n");
}

static void release_qp(struct krdma_conn *conn)
{
    rdma_destroy_qp(conn->cm_id);
    ib_destroy_cq(conn->cq);
    ib_dealloc_pd(conn->pd);
    conn->cq = NULL;
    conn->pd = NULL;
}

static void krdma_release_work(struct work_struct *ws)
{
    struct krdma_conn *conn;

    conn = container_of(ws, struct krdma_conn, release_work);

    ib_drain_qp(conn->qp);
    rdma_destroy_qp(conn->cm_id);
    ib_destroy_qp(conn->msg_qp);
    rdma_destroy_id(conn->cm_id);
    ib_free_cq(conn->cq);
    ib_dealloc_pd(conn->pd);

    ib_dma_free_coherent(conn->pd->device, PAGE_SIZE, conn->rdma_buf,
                         conn->rdma_dma_addr);
    ib_dma_unmap_single(conn->pd->device, conn->send_dma_addr,
                        sizeof(conn->send_msg) , DMA_BIDIRECTIONAL);
    ib_dma_unmap_single(conn->pd->device, conn->recv_dma_addr,
                        sizeof(conn->recv_msg) , DMA_BIDIRECTIONAL);

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
    DEBUG_LOG("cq_comp_handler: (%p, %p)\n", cq, ctx);
}

static void krdma_cq_event_handler(struct ib_event *event, void *ctx)
{
    DEBUG_LOG("cq_event_handler: (%s, %p)\n", ib_event_msg(event->event), ctx);
}

static int krdma_poll_cq_one(struct krdma_conn *conn)
{
    int ret = 0;
    struct ib_wc wc;

    while (true) {
        ret = ib_poll_cq(conn->cq, 1, &wc);
        if (ret < 0)
            pr_err("error on ib_poll_cq: (%d, %d)\n", ret, wc.status);
        if (ret == 1) {
            DEBUG_LOG("poll cq successful: (%s, %d)\n", wc_opcodes[wc.opcode],
                      wc.opcode);
            break;
        }
    }

    return 0;
}

static int connect_msg_qp(struct krdma_conn *conn)
{
    int ret, mask;
    struct ib_device *dev = conn->cm_id->device;
    struct ib_qp_attr qp_attr;
    struct ib_qp_attr msg_qp_attr;
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
    ret = ib_query_qp(conn->qp, &qp_attr, 0, &qp_init_attr);
    if (ret) {
        pr_err("error on ib_query_qp: %d\n", ret);
        goto out;
    }

    /* transition to INIT */
    mask  = IB_QP_STATE;
    mask |= IB_QP_ACCESS_FLAGS;
    mask |= IB_QP_PKEY_INDEX;
    mask |= IB_QP_PORT;

    memset(&msg_qp_attr, 0, sizeof(msg_qp_attr));
    msg_qp_attr.qp_state = IB_QPS_INIT;
    msg_qp_attr.qp_access_flags = qp_attr.qp_access_flags;
    msg_qp_attr.pkey_index = qp_attr.pkey_index;
    msg_qp_attr.port_num = qp_attr.port_num;

    DEBUG_LOG("modify_qp: NONE -> INIT\n");
    ret = ib_modify_qp(conn->msg_qp, &msg_qp_attr, mask);
    if (ret) {
        pr_err("error on ib_modify_qp: %d\n", ret);
        goto out;
    }
    DEBUG_LOG("modify_qp: NONE -> INIT successful!\n");

    /* trasition to RTR */
    mask  = IB_QP_STATE;
    mask |= IB_QP_AV;
    mask |= IB_QP_PATH_MTU;
    mask |= IB_QP_DEST_QPN;
    mask |= IB_QP_RQ_PSN;
    mask |= IB_QP_MAX_DEST_RD_ATOMIC;
    mask |= IB_QP_MIN_RNR_TIMER;

    memset(&msg_qp_attr, 0, sizeof(msg_qp_attr));
    msg_qp_attr.qp_state = IB_QPS_RTR;
    msg_qp_attr.ah_attr = qp_attr.ah_attr;
    msg_qp_attr.path_mtu = qp_attr.path_mtu;
    msg_qp_attr.dest_qp_num = conn->msg_remote_qpn;
    msg_qp_attr.rq_psn = conn->msg_remote_psn;
    msg_qp_attr.max_dest_rd_atomic = qp_attr.max_dest_rd_atomic;
    msg_qp_attr.min_rnr_timer = qp_attr.min_rnr_timer;

    DEBUG_LOG("modify_qp: INIT -> RTR\n");
    ret = ib_modify_qp(conn->msg_qp, &msg_qp_attr, mask);
    if (ret) {
        pr_err("error on ib_modify_qp: %d\n", ret);
        goto out;
    }
    DEBUG_LOG("modify_qp: INIT -> RTR successful!\n");

    /* trasition to RTS */
    mask  = IB_QP_STATE;
    mask |= IB_QP_SQ_PSN;
    mask |= IB_QP_RETRY_CNT;
    mask |= IB_QP_RNR_RETRY;
    mask |= IB_QP_MAX_QP_RD_ATOMIC;
    mask |= IB_QP_TIMEOUT;

    memset(&msg_qp_attr, 0, sizeof(msg_qp_attr));
    msg_qp_attr.qp_state = IB_QPS_RTS;
    msg_qp_attr.sq_psn = conn->msg_local_psn;
    msg_qp_attr.retry_cnt = qp_attr.retry_cnt;
    msg_qp_attr.rnr_retry = qp_attr.rnr_retry;
    msg_qp_attr.max_rd_atomic = qp_attr.max_rd_atomic;
    msg_qp_attr.timeout = qp_attr.timeout;

    DEBUG_LOG("modify_qp: RTR -> RTS\n");
    ret = ib_modify_qp(conn->msg_qp, &msg_qp_attr, mask);
    if (ret) {
        pr_err("error on ib_modify_qp: %d\n", ret);
        goto out;
    }
    DEBUG_LOG("modify_qp: RTR -> RTS successful!\n");

    return 0;

out:
    return ret;
}

static int allocate_msg_qp(struct krdma_conn *conn)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    int ret;
    struct ib_cq_init_attr cq_attr;
    struct ib_qp_init_attr qp_attr;

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.cqe = KRDMA_CM_MAX_CQE;
    cq_attr.comp_vector = 0;

    conn->msg_cq = ib_create_cq(cm_id->device, krdma_cq_comp_handler,
                                krdma_cq_event_handler, conn, &cq_attr);
    if (IS_ERR(conn->msg_cq)) {
        ret = PTR_ERR(conn->msg_cq);
        pr_err("error on ib_create_cq: %d\n", ret);
        goto out;
    }

    ret = ib_req_notify_cq(conn->msg_cq, IB_CQ_NEXT_COMP);
    if (ret) {
        pr_err("error on ib_req_notify_cq: %d\n", ret);
        goto out;
    }

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = (void *) conn;
    qp_attr.send_cq = conn->msg_cq;
    qp_attr.recv_cq = conn->msg_cq;
    qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
    qp_attr.qp_type = IB_QPT_RC;
    qp_attr.cap.max_send_wr = KRDMA_CM_MAX_SEND_WR;
    qp_attr.cap.max_recv_wr = KRDMA_CM_MAX_RECV_WR;
    qp_attr.cap.max_send_sge = KRDMA_CM_MAX_SEND_SGE;
    qp_attr.cap.max_recv_sge = KRDMA_CM_MAX_RECV_SGE;

    /* for flush_qp() ? */
    qp_attr.cap.max_send_wr++;
    qp_attr.cap.max_recv_wr++;

    conn->msg_qp = ib_create_qp(conn->pd, &qp_attr);
    if (IS_ERR(conn->msg_qp)) {
        ret = PTR_ERR(conn->msg_qp);
        pr_err("error on ib_create_qp: %d\n", ret);
        goto out_destroy_cq;
    }

    return 0;

out_destroy_cq:
    ib_destroy_cq(conn->msg_cq);
    conn->msg_cq = NULL;
out:
    return ret;
}

static int allocate_qp(struct krdma_conn *conn)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    int ret = 0;
    struct ib_cq_init_attr cq_attr;
    struct ib_qp_init_attr qp_attr;

    conn->pd = ib_alloc_pd(cm_id->device, IB_PD_UNSAFE_GLOBAL_RKEY);
    if (IS_ERR(conn->pd)) {
        ret = PTR_ERR(conn->pd);
        pr_err("error on ib_alloc_pd: %d\n", ret);
        goto out;
    }

    DEBUG_LOG("local_dma_lkey: %u, unsafe_global_rkey: %u\n",
              conn->pd->local_dma_lkey, conn->pd->unsafe_global_rkey);

    conn->lkey = conn->pd->local_dma_lkey;
    conn->rkey = conn->pd->unsafe_global_rkey;

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.cqe = KRDMA_CM_MAX_CQE;
    cq_attr.comp_vector = 0;

    conn->cq = ib_create_cq(cm_id->device, NULL, NULL, conn, &cq_attr);
    if (IS_ERR(conn->cq)) {
        ret = PTR_ERR(conn->cq);
        pr_err("error on ib_create_cq: %d\n", ret);
        goto out_dealloc_pd;
    }

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = (void *) conn;
    qp_attr.send_cq = conn->cq;
    qp_attr.recv_cq = conn->cq;
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

    conn->qp = cm_id->qp;

    return 0;

out_destroy_cq:
    ib_destroy_cq(conn->cq);
    conn->cq = NULL;
out_dealloc_pd:
    ib_dealloc_pd(conn->pd);
    conn->pd = NULL;
out:
    return ret;
}

static int setup_message_buffer(struct krdma_conn *conn)
{
    int ret = 0;
    struct krdma_msg *msg;

    /* setup message buffers */
    msg = &conn->send_msg;
    conn->send_dma_addr = ib_dma_map_single(
            conn->pd->device, (void *) msg, sizeof(*msg), DMA_BIDIRECTIONAL);

    msg = &conn->recv_msg;
    conn->recv_dma_addr = ib_dma_map_single(
            conn->pd->device, (void *) msg, sizeof(*msg), DMA_BIDIRECTIONAL);

    DEBUG_LOG("send_dma_addr: %llu, recv_dma_addr: %llu\n",
              conn->send_dma_addr, conn->recv_dma_addr);

    conn->send_sgl.addr = conn->send_dma_addr;
    conn->send_sgl.length = sizeof(conn->send_msg);
    conn->send_sgl.lkey = conn->lkey;

    conn->send_wr.opcode = IB_WR_SEND;
    conn->send_wr.send_flags = IB_SEND_SIGNALED;
    conn->send_wr.sg_list = &conn->send_sgl;
    conn->send_wr.num_sge = 1;

    conn->recv_sgl.addr = conn->recv_dma_addr;
    conn->recv_sgl.length = sizeof(conn->recv_msg);
    conn->recv_sgl.lkey = conn->lkey;

    conn->recv_wr.sg_list = &conn->recv_sgl;
    conn->recv_wr.num_sge = 1;

    /* setup RDMA buffer */
    conn->rdma_buf = ib_dma_alloc_coherent(
            conn->pd->device, PAGE_SIZE, &conn->rdma_dma_addr, GFP_KERNEL);
    if (conn->rdma_buf == NULL) {
        ret = -ENOMEM;
        pr_err("failed to allocate memory for rdma_buf\n");
        goto out_nomem;
    }

    conn->rdma_sgl.addr = conn->rdma_dma_addr;
    conn->rdma_sgl.lkey = conn->lkey;
    conn->rdma_sgl.length = PAGE_SIZE;

    conn->rdma_wr.wr.next = NULL;
    conn->rdma_wr.wr.wr_id = 0;
    conn->rdma_wr.wr.sg_list = &conn->rdma_sgl;
    conn->rdma_wr.wr.num_sge = 1;
    conn->rdma_wr.wr.send_flags = IB_SEND_SIGNALED;

    return 0;

out_nomem:
    ib_dma_unmap_single(conn->pd->device, conn->send_dma_addr,
                        sizeof(conn->send_msg) , DMA_BIDIRECTIONAL);
    ib_dma_unmap_single(conn->pd->device, conn->recv_dma_addr,
                        sizeof(conn->recv_msg) , DMA_BIDIRECTIONAL);
    return ret;
}

/**
 * server side connection request handling
 */
static int krdma_cm_connect_request(struct rdma_cm_id *cm_id)
{
    int ret;
    struct krdma_conn *conn;
    struct rdma_conn_param param;
    const struct ib_recv_wr *bad_wr;

    conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (conn == NULL) {
        pr_err("failed to allocate memory for cm connection\n");
        ret = -ENOMEM;
        goto out;
    }

    init_completion(&conn->cm_done);
    INIT_WORK(&conn->release_work, krdma_release_work);
    conn->cm_id = cm_id;

    ret = allocate_qp(conn);
    if (ret) {
        pr_err("error on allocate_qp: %d\n", ret);
        goto out;
    }

    /* setup message buffer */
    setup_message_buffer(conn);

    ret = ib_post_recv(conn->qp, &conn->recv_wr, &bad_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out_release_qp;
    }
    DEBUG_LOG("post recv on the server side\n");

    memset(&param, 0, sizeof(param));
    param.responder_resources = 1;
    param.initiator_depth = 1;

    ret = rdma_accept(cm_id, &param);
    if (ret) {
        pr_err("error on rdma_accept: %d\n", ret);
        goto out_release_qp;
    }

    return 0;

out_release_qp:
    release_qp(conn);
out:
    return ret;
}

static int krdma_cm_established_server(struct krdma_conn *conn)
{
    int ret = 0;
    const struct ib_recv_wr *bad_recv_wr;
    const struct ib_send_wr *bad_send_wr;

    /* create an additional QP for message exchange */
    ret = allocate_msg_qp(conn);
    if (ret) {
        pr_err("error on allocate_msg_qp: %d\n", ret);
        goto out_disconnect;
    }

    conn->msg_local_qpn = conn->msg_qp->qp_num;
    conn->msg_local_psn = get_random_int() & 0xFFFFFF;
    conn->msg_local_lid = conn->qp->port;

    DEBUG_LOG("local_qpn: %u, local_psn: %u, local_lid: %u\n",
              conn->msg_local_qpn, conn->msg_local_psn, conn->msg_local_lid);

    /* fill the message buffer with the message QP info */
    conn->send_msg.cmd = KRDMA_CMD_HANDSHAKE_MSG_QP;
    conn->send_msg.arg1 = conn->msg_local_qpn;
    conn->send_msg.arg2 = conn->msg_local_psn;
    conn->send_msg.arg3 = conn->msg_local_lid;

    /* receive the QP information from the client */
    krdma_poll_cq_one(conn);

    ret = ib_post_recv(conn->qp, &conn->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

    conn->msg_remote_qpn = conn->recv_msg.arg1;
    conn->msg_remote_psn = conn->recv_msg.arg2;
    conn->msg_remote_lid = conn->recv_msg.arg3;

    DEBUG_LOG("remote_qpn: %u, remote_psn: %u, remote_lid: %u\n",
              conn->msg_remote_qpn, conn->msg_remote_psn, conn->msg_remote_lid);

    /* send the QP information to the client */
    ret = ib_post_send(conn->qp, &conn->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* poll send completion */
    krdma_poll_cq_one(conn);

    /* connect the message QP */
    ret = connect_msg_qp(conn);
    if (ret) {
        pr_err("error on connect_msg_qp: %d\n", ret);
        goto out_disconnect;
    }

    /*
     * preparation for the node name exchange with RDMA.
     * write the local node name to the last half of the buffer.
     * the remote node name will be written to the first half of the buffer.
     */
    strncpy(conn->rdma_buf + (PAGE_SIZE / 2), g_nodename, __NEW_UTS_LEN + 1);

    /* fill the message buffer with RDMA region info and message QP info */
    conn->send_msg.cmd = KRDMA_CMD_HANDSHAKE_RDMA;
    conn->send_msg.arg1 = conn->rkey;
    conn->send_msg.arg2 = conn->rdma_dma_addr;
    conn->send_msg.arg3 = PAGE_SIZE;

    /* receive the RDMA buffer information from the client */
    krdma_poll_cq_one(conn);

    /* send the RDMA buffer information to the client */
    ret = ib_post_send(conn->qp, &conn->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* poll send completion */
    krdma_poll_cq_one(conn);

    /* read the remote node name with RDMA READ */
    conn->rdma_wr.remote_addr = conn->recv_msg.arg2 + (PAGE_SIZE / 2);
    conn->rdma_wr.rkey = conn->recv_msg.arg1;
    conn->rdma_wr.wr.opcode = IB_WR_RDMA_READ;
    conn->rdma_sgl.length = (PAGE_SIZE / 2);

    ret = ib_post_send(conn->qp, &conn->rdma_wr.wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* poll RDMA read completion */
    krdma_poll_cq_one(conn);

    /* update the remote node name and add it to the node hash table */
    strncpy(conn->nodename, conn->rdma_buf, __NEW_UTS_LEN + 1);
    add_krdma_node(conn);

    if (g_debug)
        print_conn(conn);

    DEBUG_LOG("connection established with %s\n", conn->nodename);

    return 0;

out_disconnect:
    pr_err("failed to establish the connection: %p\n", conn);

    /*
     * add this connection to the hash table to prevent the release worker
     * try to delete the dangling conn from the hash table.
     */
    add_krdma_node(conn);
    rdma_disconnect(conn->cm_id);
out:
    return ret;
}

static int krdma_cm_established_client(struct krdma_conn *conn)
{
    int ret = 0;
    const struct ib_recv_wr *bad_recv_wr;
    const struct ib_send_wr *bad_send_wr;

    /* create an additional QP for message exchange */
    ret = allocate_msg_qp(conn);
    if (ret) {
        pr_err("error on allocate_msg_qp: %d\n", ret);
        goto out_disconnect;
    }

    conn->msg_local_qpn = conn->msg_qp->qp_num;
    conn->msg_local_psn = get_random_int() & 0xFFFFFF;
    conn->msg_local_lid = conn->qp->port;

    DEBUG_LOG("local_qpn: %u, local_psn: %u, local_lid: %u\n",
              conn->msg_local_qpn, conn->msg_local_psn, conn->msg_local_lid);

    /* fill the message buffer with the message QP info */
    conn->send_msg.cmd = KRDMA_CMD_HANDSHAKE_MSG_QP;
    conn->send_msg.arg1 = conn->msg_local_qpn;
    conn->send_msg.arg2 = conn->msg_local_psn;
    conn->send_msg.arg3 = conn->msg_local_lid;

    /* client sends the QP information first */
    ret = ib_post_send(conn->qp, &conn->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* poll send completion */
    krdma_poll_cq_one(conn);

    /* poll recv completion */
    krdma_poll_cq_one(conn);

    ret = ib_post_recv(conn->qp, &conn->recv_wr, &bad_recv_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out;
    }

    conn->msg_remote_qpn = conn->recv_msg.arg1;
    conn->msg_remote_psn = conn->recv_msg.arg2;
    conn->msg_remote_lid = conn->recv_msg.arg3;

    DEBUG_LOG("remote_qpn: %u, remote_psn: %u, remote_lid: %u\n",
              conn->msg_remote_qpn, conn->msg_remote_psn, conn->msg_remote_lid);

    /* connect the message QP */
    ret = connect_msg_qp(conn);
    if (ret) {
        pr_err("error on connect_msg_qp: %d\n", ret);
        goto out_disconnect;
    }

    /*
     * preparation for the node name exchange with RDMA.
     * write the local node name to the last half of the buffer.
     * the remote node name will be written to the first half of the buffer.
     */
    strncpy(conn->rdma_buf + (PAGE_SIZE / 2), g_nodename, __NEW_UTS_LEN + 1);

    /* fill the message buffer with RDMA region info and message QP info */
    conn->send_msg.cmd = KRDMA_CMD_HANDSHAKE_RDMA;
    conn->send_msg.arg1 = conn->rkey;
    conn->send_msg.arg2 = conn->rdma_dma_addr;
    conn->send_msg.arg3 = PAGE_SIZE;

    /* client sends the RDMA information first */
    ret = ib_post_send(conn->qp, &conn->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* poll send completion */
    krdma_poll_cq_one(conn);

    /* poll recv completion */
    krdma_poll_cq_one(conn);

    /* read the remote node name with RDMA READ */
    conn->rdma_wr.remote_addr = conn->recv_msg.arg2 + (PAGE_SIZE / 2);
    conn->rdma_wr.rkey = conn->recv_msg.arg1;
    conn->rdma_wr.wr.opcode = IB_WR_RDMA_READ;
    conn->rdma_sgl.length = (PAGE_SIZE / 2);

    ret = ib_post_send(conn->qp, &conn->rdma_wr.wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    /* poll RDMA read completion */
    krdma_poll_cq_one(conn);

    /* update the remote node name and add it to the node hash table */
    strncpy(conn->nodename, conn->rdma_buf, __NEW_UTS_LEN + 1);
    add_krdma_node(conn);

    if (g_debug)
        print_conn(conn);

    DEBUG_LOG("connection established with %s\n", conn->nodename);

    return 0;

out_disconnect:
    pr_err("failed to establish the connection: %p\n", conn);

    /*
     * add this connection to the hash table to prevent the release worker
     * try to delete the dangling conn from the hash table.
     */
    add_krdma_node(conn);
    rdma_disconnect(conn->cm_id);
out:
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

    DEBUG_LOG("cm_handler_server finished\n");

    return 0;
}

static int krdma_cm_addr_resolved(struct krdma_conn *conn)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    int ret = 0;
    unsigned long timeout_ms = 2000;

    ret = allocate_qp(conn);
    if (ret) {
        pr_err("error on allocate_qp: %d\n", ret);
        goto out;
    }

    ret = rdma_resolve_route(cm_id, timeout_ms);
    if (ret) {
        pr_err("error on rdma_resolve_route: %d\n", ret);
        goto out_release_qp;
    }

    return 0;

out_release_qp:
    release_qp(conn);
out:
    return ret;
}

static int krdma_cm_route_resolved(struct krdma_conn *conn)
{
    int ret;
    struct rdma_conn_param param;
    const struct ib_recv_wr *bad_wr;

    /* setup message buffer */
    setup_message_buffer(conn);

    ret = ib_post_recv(conn->qp, &conn->recv_wr, &bad_wr);
    if (ret) {
        pr_err("error on ib_post_recv: %d\n", ret);
        goto out_destroy_qp;
    }
    DEBUG_LOG("post recv on the client side\n");

    memset(&param, 0, sizeof(param));
    param.responder_resources = 1;
    param.initiator_depth = 1;
    param.retry_count = KRDMA_CM_RETRY_COUNT;
    param.rnr_retry_count = KRDMA_CM_RNR_RETRY_COUNT;

    ret = rdma_connect(conn->cm_id, &param);
    if (ret) {
        pr_err("error on rdma_connect: %d\n", ret);
        goto out_destroy_qp;
    }

    return 0;

out_destroy_qp:
    rdma_destroy_qp(conn->cm_id);

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

    DEBUG_LOG("cm_handler_client finished\n");

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
    int ret = 0;
    struct krdma_conn *conn;
    struct sockaddr_storage sin;
    unsigned long jiffies, timeout_ms = 2000;

    conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (conn == NULL) {
        pr_err("failed to allocate memory for cm connection\n");
        goto out;
    }

    init_completion(&conn->cm_done);
    INIT_WORK(&conn->release_work, krdma_release_work);

    conn->cm_id = rdma_create_id(&init_net, krdma_cm_handler_client,
                                 (void *) conn, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(conn->cm_id)) {
        ret = PTR_ERR(conn->cm_id);
        pr_err("error on rdma_create_id: %d\n", ret);
        goto out_free_conn;
    }

    if (fill_sockaddr(&sin, AF_INET, server, port)) {
        pr_err("error on fill_sockaddr\n");
        goto out_destroy_cm_id;
    }

    ret = rdma_resolve_addr(conn->cm_id, NULL, (struct sockaddr *) &sin,
                            timeout_ms);
    if (ret) {
        pr_err("error on rdma_resolve_addr: %d", ret);
        goto out_destroy_cm_id;
    }

    jiffies = msecs_to_jiffies(timeout_ms) + 1;
    ret = wait_for_completion_timeout(&conn->cm_done, jiffies);
    if (ret == 0) {
        pr_err("krdma_cm_connect timeout\n");
        goto out_destroy_cm_id;
    }

    if (conn->cm_error) {
        pr_err("krdma_cm_connect error: %d\n", conn->cm_error);
        goto out_destroy_cm_id;
    }

    return 0;

out_destroy_cm_id:
    rdma_destroy_id(conn->cm_id);
out_free_conn:
    kfree(conn);
out:
    return -1;
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

    krdma_cm_context.cm_id_server = cm_id;

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

    rdma_destroy_id(krdma_cm_context.cm_id_server);
}

void krdma_test(void)
{
    pr_info("hello world\n");
}
EXPORT_SYMBOL(krdma_test);
