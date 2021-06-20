#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <rdma/ib_verbs.h>
#include <linux/inet.h>
#include <linux/socket.h>

#include "cm.h"
#include "rpc.h"
#include <krdma.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

/* shared ib resources */
static struct ib_pd *global_pd;
static struct ib_cq *global_cq;

static struct rdma_cm_id *server_cm_id;

/* a list for the connected nodes */
static LIST_HEAD(conn_list);
static DEFINE_SPINLOCK(conn_list_lock);

/* ib_device list */
static LIST_HEAD(ib_dev_list);
static DEFINE_SPINLOCK(ib_dev_list_lock);

struct krdma_ib_dev {
    struct list_head head;
    struct ib_device *ib_dev;
};

static void cleanup_connection(struct work_struct *ws)
{
    struct krdma_conn *conn;

    conn = container_of(ws, struct krdma_conn, cleanup_connection_work);

    rdma_destroy_qp(conn->cm_id);
    rdma_destroy_id(conn->cm_id);

    krdma_msg_pool_destroy(conn->send_msg_pool);
    krdma_msg_pool_destroy(conn->recv_msg_pool);

    spin_lock(&conn_list_lock);
    list_del_init(&conn->lh);
    spin_unlock(&conn_list_lock);

    kfree(conn);
    DEBUG_LOG("cleanup_connection\n");
}

static int addr_resolved(struct krdma_conn *conn)
{
    int ret;
    int timeout = 1000;
    struct ib_qp_init_attr qp_attr;

    conn->pd = global_pd;
    conn->cq = global_cq;

    /* create ib_qp */
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = (void *) conn;
    qp_attr.send_cq = conn->cq;
    qp_attr.recv_cq = conn->cq;
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
    conn->qp = conn->cm_id->qp;

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
    struct krdma_msg *msg;
    const struct ib_recv_wr *bad_recv_wr;
    struct rdma_conn_param conn_param;

    /* allocate message pool */
    conn->send_msg_pool = krdma_msg_pool_create(
            conn, KRDMA_SEND_MSG_POOL_SIZE, KRDMA_SEND_MSG_SIZE);
    if (conn->send_msg_pool == NULL) {
        pr_err("failed to allocate send message pool\n");
        ret = -ENOMEM;
        goto out;
    }

    conn->recv_msg_pool = krdma_msg_pool_create(
            conn, KRDMA_RECV_MSG_POOL_SIZE, KRDMA_RECV_MSG_SIZE);
    if (conn->recv_msg_pool == NULL) {
        pr_err("failed to allocate recv message pool\n");
        ret = -ENOMEM;
        goto out_destroy_send_msg_pool;
    }

    spin_lock(&conn->recv_msg_pool->lock);
    list_for_each_entry(msg, &conn->recv_msg_pool->lh, lh) {
        ret = ib_post_recv(conn->qp, &msg->recv_wr, &bad_recv_wr);
        if (ret) {
            pr_err("error on ib_post_recv: %d\n", ret);
            goto out_destroy_recv_msg_pool;
        }
    }
    spin_unlock(&conn->recv_msg_pool->lock);

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

out_destroy_recv_msg_pool:
    krdma_msg_pool_destroy(conn->recv_msg_pool);
out_destroy_send_msg_pool:
    krdma_msg_pool_destroy(conn->send_msg_pool);
out:
    return ret;
}

static int established_client(struct krdma_conn *conn)
{
    DEBUG_LOG("established client: %p\n", conn->cm_id->device);

    spin_lock(&conn_list_lock);
    list_add_tail(&conn->lh, &conn_list);
    spin_unlock(&conn_list_lock);

    return 0;
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
    struct krdma_msg *msg;
    struct ib_qp_init_attr qp_attr;
    const struct ib_recv_wr *bad_recv_wr;
    struct rdma_conn_param conn_param;

    conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (conn == NULL) {
        pr_err("failed to allocate memory for krdma_conn\n");
        ret = -ENOMEM;
        goto out;
    }

    conn->cm_id = cm_id;
    conn->pd = global_pd;
    conn->cq = global_cq;

    INIT_LIST_HEAD(&conn->lh);
    init_completion(&conn->cm_done);
    INIT_WORK(&conn->cleanup_connection_work, cleanup_connection);

    /* create ib_qp */
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.qp_context = (void *) conn;
    qp_attr.send_cq = conn->cq;
    qp_attr.recv_cq = conn->cq;
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
        goto out_kfree_conn;
    }
    conn->qp = conn->cm_id->qp;

    /* allocate message pool */
    conn->send_msg_pool = krdma_msg_pool_create(
            conn, KRDMA_SEND_MSG_POOL_SIZE, KRDMA_SEND_MSG_SIZE);
    if (conn->send_msg_pool == NULL) {
        pr_err("failed to allocate send message pool\n");
        ret = -ENOMEM;
        goto out_destroy_qp;
    }

    conn->recv_msg_pool = krdma_msg_pool_create(
            conn, KRDMA_RECV_MSG_POOL_SIZE, KRDMA_RECV_MSG_SIZE);
    if (conn->recv_msg_pool == NULL) {
        pr_err("failed to allocate recv message pool\n");
        ret = -ENOMEM;
        goto out_destroy_send_msg_pool;
    }

    spin_lock(&conn->recv_msg_pool->lock);
    list_for_each_entry(msg, &conn->recv_msg_pool->lh, lh) {
        ret = ib_post_recv(conn->qp, &msg->recv_wr, &bad_recv_wr);
        if (ret) {
            pr_err("error on ib_post_recv: %d\n", ret);
            goto out_destroy_recv_msg_pool;
        }
    }
    spin_unlock(&conn->recv_msg_pool->lock);

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.responder_resources = 1;
    conn_param.initiator_depth = 1;

    ret = rdma_accept(cm_id, &conn_param);
    if (ret) {
        pr_err("error on rdma_accept: %d\n", ret);
        goto out_destroy_recv_msg_pool;
    }

    return 0;

out_destroy_recv_msg_pool:
    krdma_msg_pool_destroy(conn->recv_msg_pool);
out_destroy_send_msg_pool:
    krdma_msg_pool_destroy(conn->send_msg_pool);
out_destroy_qp:
    rdma_destroy_qp(conn->cm_id);
out_kfree_conn:
    kfree(conn);
out:
    return ret;
}

static int established_server(struct krdma_conn *conn)
{
    DEBUG_LOG("established server: %p\n", conn->cm_id->device);

    spin_lock(&conn_list_lock);
    list_add_tail(&conn->lh, &conn_list);
    spin_unlock(&conn_list_lock);

    return 0;
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


static void cq_comp_handler(struct ib_cq *cq, void *ctx)
{
    DEBUG_LOG("cq_comp_handler: (%p, %p)\n", cq, ctx);
    /* TODO: add implementation */
}

static void cq_event_handler(struct ib_event *event, void *ctx)
{
    DEBUG_LOG("cq_event_handler: (%s, %p)\n", ib_event_msg(event->event), ctx);
    /* TODO: add implementation */
}

int krdma_setup(char *server, int port)
{
    int ret;
    int backlog = 128;
    struct sockaddr_storage sin;
    struct krdma_ib_dev *dev;
    struct ib_cq_init_attr cq_attr;

    /* Step 1: register a ib_client */
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

    /* Step 2: allocate global ib_pd */
    global_pd = ib_alloc_pd(dev->ib_dev, IB_PD_UNSAFE_GLOBAL_RKEY);
    if (IS_ERR(global_pd)) {
        ret = PTR_ERR(global_pd);
        pr_err("failed to allocate global pd: %d\n", ret);
        goto out_unregister_ib_client;
    }

    memset(&cq_attr, 0, sizeof(cq_attr));
    cq_attr.cqe = KRDMA_MAX_CQE;
    cq_attr.comp_vector = 0;

    /* Step 3: allocate global ib_cq */
    global_cq = ib_create_cq(dev->ib_dev, cq_comp_handler, cq_event_handler,
                             NULL, &cq_attr);
    if (IS_ERR(global_cq)) {
        ret = PTR_ERR(global_cq);
        pr_err("failed to create global cq: %d\n", ret);
        goto out_dealloc_pd;
    }

    /* Step 4: setup RPC processing threads */
    ret = krdma_rpc_setup(dev->ib_dev, global_pd, global_cq);
    if (ret) {
        pr_err("failed to setup krdma RPC\n");
        goto out_destroy_cq;
    }

    /* Step 5: create a rdma_cm_id for the server */
    server_cm_id = rdma_create_id(&init_net, krdma_cm_event_handler_server,
                                  NULL, RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(server_cm_id)) {
        ret = PTR_ERR(server_cm_id);
        pr_err("error on rdma_create_id: %d\n", ret);
        goto out_rpc_cleanup;
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
out_rpc_cleanup:
    krdma_rpc_cleanup();
out_destroy_cq:
    ib_destroy_cq(global_cq);
    global_cq = NULL;
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
    int n = 0;
    struct krdma_conn *conn;

    spin_lock(&conn_list_lock);
    list_for_each_entry(conn, &conn_list, lh)
        n++;
    spin_unlock(&conn_list_lock);

    return n;
}

void krdma_cleanup(void)
{
    struct krdma_conn *conn;

    spin_lock(&conn_list_lock);
    list_for_each_entry(conn, &conn_list, lh)
        rdma_disconnect(conn->cm_id);
    spin_unlock(&conn_list_lock);

    /* wait until all connections are cleaned up */
    while (live_connections() > 0)
        udelay(1000);

    rdma_destroy_id(server_cm_id);
    krdma_rpc_cleanup();
    ib_destroy_cq(global_cq);
    ib_dealloc_pd(global_pd);
    ib_unregister_client(&krdma_ib_client);

    server_cm_id = NULL;
    global_cq = NULL;
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

    INIT_LIST_HEAD(&conn->lh);
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
