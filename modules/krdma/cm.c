#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/dma-mapping.h>
#include <linux/utsname.h>

#include <krdma.h>

extern char g_nodename[__NEW_UTS_LEN + 1];

static struct krdma_cm_context {
    struct rdma_cm_id *cm_id_server;
} krdma_cm_context;

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
            DEBUG_LOG("poll cq successful\n");
            break;
        }
    }

    return 0;
}

static int allocate_qp(struct krdma_conn *conn)
{
    struct rdma_cm_id *cm_id = conn->cm_id;
    int ret = 0;
    struct ib_cq_init_attr cq_attr;
    struct ib_qp_init_attr qp_attr;
    struct ib_device_attr *dev_attr;

    conn->pd = ib_alloc_pd(cm_id->device, IB_PD_UNSAFE_GLOBAL_RKEY);
    if (IS_ERR(conn->pd)) {
        ret = PTR_ERR(conn->pd);
        pr_err("error on ib_alloc_pd\n");
        goto out;
    }

    DEBUG_LOG("local_dma_lkey: %u, unsafe_global_rkey: %u\n",
              conn->pd->local_dma_lkey, conn->pd->unsafe_global_rkey);

    conn->mr = conn->pd->__internal_mr;
    conn->lkey = conn->pd->local_dma_lkey;
    conn->rkey = conn->pd->unsafe_global_rkey;

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.cqe = 128;
    cq_attr.comp_vector = 0;

    conn->cq = ib_create_cq(cm_id->device, krdma_cq_comp_handler,
                            krdma_cq_event_handler, conn, &cq_attr);
    if (IS_ERR(conn->cq)) {
        ret = PTR_ERR(conn->cq);
        pr_err("error on ib_create_cq\n");
        goto out_dealloc_pd;
    }

    ret = ib_req_notify_cq(conn->cq, IB_CQ_NEXT_COMP);
    if (ret) {
        pr_err("error on ib_req_notify_cq\n");
        goto out_destroy_cq;
    }

    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = (void *) conn;
    qp_attr.send_cq = conn->cq;
    qp_attr.recv_cq = conn->cq;
    qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
    qp_attr.qp_type = IB_QPT_RC;
    qp_attr.cap.max_send_wr = 64;
    qp_attr.cap.max_recv_wr = 64;

    /* for flush_qp() ? */
    qp_attr.cap.max_send_wr++;
    qp_attr.cap.max_recv_wr++;

    dev_attr = &cm_id->device->attrs;
    qp_attr.cap.max_recv_sge = 1;
    qp_attr.cap.max_send_sge = 1;

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

static void release_qp(struct krdma_conn *conn)
{
    rdma_destroy_qp(conn->cm_id);
    ib_destroy_cq(conn->cq);
    ib_dealloc_pd(conn->pd);
    conn->cq = NULL;
    conn->pd = NULL;
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
    conn->cm_id = cm_id;

    ret = allocate_qp(conn);
    if (ret) {
        pr_err("error on allocate_qp\n");
        goto out;
    }

    /* setup message buffer */
    setup_message_buffer(conn);

    ret = ib_post_recv(conn->qp, &conn->recv_wr, &bad_wr);
    if (ret) {
        pr_err("error on ib_post_recv\n");
        goto out_release_qp;
    }
    DEBUG_LOG("post recv on the server side\n");

    memset(&param, 0, sizeof(param));
    param.responder_resources = 1;
    param.initiator_depth = 1;

    ret = rdma_accept(cm_id, &param);
    if (ret) {
        pr_err("error on rdma_accept\n");
        goto out_release_qp;
    }

    return 0;

out_release_qp:
    release_qp(conn);
out:
    return ret;
}

static int krdma_cm_established(struct krdma_conn *conn)
{
    int ret = 0;
    const struct ib_send_wr *bad_wr;

    /* fill message buffer with RDMA region info */
    conn->send_msg.cmd = conn->rkey;
    conn->send_msg.arg1 = conn->rdma_dma_addr;
    conn->send_msg.arg2 = PAGE_SIZE;
    conn->send_msg.arg3 = 0;

    /* use the later half of rdma_buf to store the node name */
    strncpy(conn->rdma_buf + (PAGE_SIZE / 2), g_nodename, __NEW_UTS_LEN + 1);

    ret = ib_post_send(conn->qp, &conn->send_wr, &bad_wr);
    if (ret) {
        pr_err("error on ib_post_send\n");
        goto out;
    }

    /* for send and receive completion */
    krdma_poll_cq_one(conn);
    krdma_poll_cq_one(conn);

    DEBUG_LOG("rdma_buf rkey: %llu, remote_addr: %llu\n", conn->recv_msg.cmd,
              conn->recv_msg.arg1);

    /* read the node name of the remote node */
    conn->rdma_wr.remote_addr = conn->recv_msg.arg1 + (PAGE_SIZE / 2);
    conn->rdma_wr.rkey = conn->recv_msg.cmd;
    conn->rdma_wr.wr.opcode = IB_WR_RDMA_READ;
    conn->rdma_sgl.length = (PAGE_SIZE / 2);

    ret = ib_post_send(conn->qp, &conn->rdma_wr.wr, &bad_wr);
    if (ret) {
        pr_err("error on ib_post_send\n");
        goto out;
    }

    /* for rdma read completion */
    krdma_poll_cq_one(conn);

    strncpy(conn->nodename, conn->rdma_buf, __NEW_UTS_LEN + 1);

    DEBUG_LOG("connection established with %s\n", conn->nodename);

    return 0;

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
        ret = krdma_cm_established(conn);
        break;
    case RDMA_CM_EVENT_ADDR_CHANGE:
    case RDMA_CM_EVENT_DISCONNECTED:
    case RDMA_CM_EVENT_TIMEWAIT_EXIT:
        /* TODO: implement disconnect event handler */
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
    unsigned long timeout_ms = 2000;

    ret = allocate_qp(conn);
    if (ret) {
        pr_err("error on allocate_qp\n");
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
        pr_err("error on ib_post_recv\n");
        goto out_destroy_qp;
    }
    DEBUG_LOG("post recv on the client side\n");

    memset(&param, 0, sizeof(param));
    param.responder_resources = 1;
    param.initiator_depth = 1;
    param.retry_count = 7;
    param.rnr_retry_count = 7;

    ret = rdma_connect(conn->cm_id, &param);
    if (ret) {
        pr_err("error on rdma_connect\n");
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
        conn->cm_error = krdma_cm_established(conn);
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
        pr_info("CM got a disconnect event\n");
        /* TODO: implement disconnect handling function */
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
        pr_err("error on rdma_resolve_addr");
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


void krdma_cm_cleanup(void)
{
    rdma_destroy_id(krdma_cm_context.cm_id_server);
}


void krdma_test(void)
{
    pr_info("hello world\n");
}
EXPORT_SYMBOL(krdma_test);
