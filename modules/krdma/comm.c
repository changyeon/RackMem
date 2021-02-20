#include <linux/module.h>
#include <linux/wait.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <krdma.h>

extern int g_debug;

static int krdma_cm_event_handler(struct rdma_cm_id *id,
                                  struct rdma_cm_event *event)
{
    struct krdma_cb *cb = id->context;

    DEBUG_LOG("krdma: cm_event: %s, id: %p", rdma_event_msg(event->event), id);

    switch (event->event) {
    case RDMA_CM_EVENT_ADDR_RESOLVED:
        cb->state = CM_STATE_ADDR_RESOLVED;
        wake_up_interruptible(&cb->sem);
        break;
    case RDMA_CM_EVENT_ROUTE_RESOLVED:
        cb->state = CM_STATE_ROUTE_RESOLVED;
        wake_up_interruptible(&cb->sem);
        break;
    case RDMA_CM_EVENT_CONNECT_REQUEST:
        cb->state = CM_STATE_CONNECT_REQUEST;
        cb->cm_id_child = id;
        DEBUG_LOG("krdma: cm_id_child: %p\n", cb->cm_id_child);
        wake_up_interruptible(&cb->sem);
        break;
    case RDMA_CM_EVENT_CONNECT_RESPONSE:
        wake_up_interruptible(&cb->sem);
        break;
    case RDMA_CM_EVENT_ESTABLISHED:
        if (cb->server)
            pr_info("[!!!] krdma: established event on server cm\n");
        else
            pr_info("[!!!] krdma: established event on client cm\n");
        cb->state = CM_STATE_CONNECTED;
        wake_up_interruptible(&cb->sem);
        break;
    case RDMA_CM_EVENT_DISCONNECTED:
        cb->state = CM_STATE_DISCONNECTED;
        wake_up_interruptible(&cb->sem);
        break;
    /* not defined */
    case RDMA_CM_EVENT_DEVICE_REMOVAL:
    case RDMA_CM_EVENT_MULTICAST_JOIN:
    case RDMA_CM_EVENT_MULTICAST_ERROR:
    case RDMA_CM_EVENT_ADDR_CHANGE:
        break;
    /* erorr */
    case RDMA_CM_EVENT_ADDR_ERROR:
    case RDMA_CM_EVENT_ROUTE_ERROR:
    case RDMA_CM_EVENT_CONNECT_ERROR:
    case RDMA_CM_EVENT_UNREACHABLE:
    case RDMA_CM_EVENT_REJECTED:
    case RDMA_CM_EVENT_TIMEWAIT_EXIT:
        cb->state = CM_STATE_ERROR;
        wake_up_interruptible(&cb->sem);
        break;
    default:
        pr_err("krmda: bad event type: %s\n", rdma_event_msg(event->event));
        cb->state = CM_STATE_ERROR;
        wake_up_interruptible(&cb->sem);
        break;
    }

    return 0;
}

static void krdma_cq_comp_handler(struct ib_cq *cq, void *ctx)
{
    pr_info("krdma: cq_comp_handler: cq: %p, ctx: %p\n", cq, ctx);
}

static void krdma_cq_event_handler(struct ib_event *event, void *ctx)
{
    pr_info("krdma: cq_event_handler: %s, ctx: %p\n",
            ib_event_msg(event->event), ctx);
}

static void init_krdma_cb(struct krdma_cb *cb)
{
    memset(cb, 0, sizeof(*cb));
    cb->state = CM_STATE_IDLE;
    init_waitqueue_head(&cb->sem);
    spin_lock_init(&cb->lock);
}

static int allocate_qp(struct krdma_cb *cb)
{
    int ret = 0;
    int tx_depth = 1024;
    unsigned int flags = 0;
    struct ib_cq_init_attr cq_init_attr;
    struct ib_qp_init_attr qp_init_attr;
    struct ib_device_attr *dev_attr;
    struct rdma_cm_id *cm_id;

    if (cb->server)
        cm_id = cb->cm_id_child;
    else
        cm_id = cb->cm_id;

    cb->pd = ib_alloc_pd(cm_id->device, flags);
    if (IS_ERR(cb->pd)) {
        pr_err("krdma: error on ib_alloc_pd\n");
        goto out;
    }

    memset(&cq_init_attr, 0, sizeof(cq_init_attr));
    cq_init_attr.cqe = tx_depth * 2;
    cq_init_attr.comp_vector = 0;

    cb->cq = ib_create_cq(cm_id->device, krdma_cq_comp_handler,
                          krdma_cq_event_handler, cb, &cq_init_attr);
    if (IS_ERR(cb->cq)) {
        pr_err("krdma: error on ib_create_cq\n");
        goto out_dealloc_pd;
    }

    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.cap.max_send_wr = tx_depth;
    qp_init_attr.cap.max_recv_wr = 2;

    /* for flush_qp() ? */
    qp_init_attr.cap.max_send_wr++;
    qp_init_attr.cap.max_recv_wr++;

    dev_attr = &cm_id->device->attrs;
    qp_init_attr.cap.max_recv_sge = dev_attr->max_recv_sge;
    qp_init_attr.cap.max_send_sge = dev_attr->max_send_sge;
    qp_init_attr.qp_type = IB_QPT_RC;
    qp_init_attr.send_cq = cb->cq;
    qp_init_attr.recv_cq = cb->cq;
    qp_init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;

    pr_info("[!!!] cm_id->device: %p, pd->device: %p\n",
            cm_id->device, cb->pd->device);

    ret = rdma_create_qp(cm_id, cb->pd, &qp_init_attr);
    if (ret) {
        pr_err("krdma: error on rdma_create_qp: %d\n", ret);
        goto out_destroy_cq;
    }
    cb->qp = cm_id->qp;

    return 0;

out_destroy_cq:
    ib_destroy_cq(cb->cq);
out_dealloc_pd:
    ib_dealloc_pd(cb->pd);
out:
    return 1;
}

static void release_qp(struct krdma_cb *cb)
{
    ib_destroy_qp(cb->qp);
    ib_destroy_cq(cb->cq);
    ib_dealloc_pd(cb->pd);
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
            pr_err("krdma: error on in4_pton\n");
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

/**
 * krdma_accept - Accept a connection request.
 * @server: accept address
 * @port: accept port
 */
struct krdma_cb *krdma_accept(char *server, int port)
{
    int ret = 0;
    int backlog = 128;
    struct krdma_cb *cb;
    struct sockaddr_storage sin;
    struct rdma_conn_param conn_param;

    cb = vmalloc(sizeof(*cb));
    if (!cb) {
        pr_err("krdma: failed to allocate memory for cb\n");
        goto out;
    }

    init_krdma_cb(cb);
    cb->server = 1;
    cb->cm_id = rdma_create_id(&init_net, krdma_cm_event_handler, cb,
                               RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(cb->cm_id)) {
        ret = PTR_ERR(cb->cm_id);
        pr_err("krdma: error on rdma_create_id %d\n", ret);
        goto out_free_cb;
    }
    DEBUG_LOG("krdma: created a cm_id: %p\n", cb->cm_id);

    if (fill_sockaddr(&sin, AF_INET, server, port)) {
        pr_err("krdma: error on fill_sockaddr\n");
        goto out_destroy_cm_id;
    }

    ret = rdma_bind_addr(cb->cm_id, (struct sockaddr *) &sin);
    if (ret) {
        pr_err("krdma: error on rdma_bind_addr: %d\n", ret);
        goto out_destroy_cm_id;
    }

    ret = rdma_listen(cb->cm_id, backlog);
    if (ret) {
        pr_err("krdma: error on rdma_listen: %d\n", ret);
        goto out_destroy_cm_id;
    }

    wait_event_interruptible(cb->sem,
                             cb->state >= CM_STATE_CONNECT_REQUEST);
    if (cb->state != CM_STATE_CONNECT_REQUEST) {
        pr_err("krdma: error on handling CM_STATE_CONNECT_REQUEST\n");
        goto out_destroy_cm_id_child;
    }
    DEBUG_LOG("krdma: got a connection request (%p:%p)\n",
              cb->cm_id, cb->cm_id_child);

    if (allocate_qp(cb)) {
        pr_err("krdma: error on allocate_qp\n");
        goto out_destroy_cm_id_child;
    }
    DEBUG_LOG("krdma: qp allocated successfully\n");

    /* allocate buffers */

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.responder_resources = 1;
    conn_param.initiator_depth = 1;

    ret = rdma_accept(cb->cm_id_child, &conn_param);
    if (ret) {
        pr_err("krdma: error on rdma_accept\n");
        goto out_release_qp;
    }

    wait_event_interruptible(cb->sem, cb->state >= CM_STATE_CONNECTED);
    if (cb->state == CM_STATE_ERROR) {
        pr_err("krdma: failed to connect the server\n");
        goto out_release_qp;
    }

    return cb;

out_release_qp:
    release_qp(cb);
out_destroy_cm_id_child:
    rdma_destroy_id(cb->cm_id_child);
out_destroy_cm_id:
    rdma_destroy_id(cb->cm_id);
out_free_cb:
    vfree(cb);
out:
    return NULL;
}
EXPORT_SYMBOL(krdma_accept);

struct krdma_cb *krdma_connect(char *server, int port)
{
    int ret = 0;
    unsigned long timeout_ms = 2000;
    struct krdma_cb *cb;
    struct sockaddr_storage sin;
    struct rdma_conn_param conn_param;

    cb = vmalloc(sizeof(*cb));
    if (!cb) {
        pr_err("krdma: failed to allocate memory for cb\n");
        goto out;
    }

    init_krdma_cb(cb);

    cb->cm_id = rdma_create_id(&init_net, krdma_cm_event_handler, cb,
                               RDMA_PS_TCP, IB_QPT_RC);
    if (IS_ERR(cb->cm_id)) {
        ret = PTR_ERR(cb->cm_id);
        pr_err("krdma: error on rdma_create_id %d\n", ret);
        goto out_free_cb;
    }

    if (fill_sockaddr(&sin, AF_INET, server, port)) {
        pr_err("krdma: error on fill_sockaddr\n");
        goto out_destroy_cm_id;
    }

    ret = rdma_resolve_addr(cb->cm_id, NULL, (struct sockaddr *) &sin,
                            timeout_ms);
    if (ret) {
        pr_err("krdma: error on rdma_resolve_addr\n");
        goto out_destroy_cm_id;
    }
    wait_event_interruptible(cb->sem, cb->state >= CM_STATE_ADDR_RESOLVED);

    if (cb->state != CM_STATE_ADDR_RESOLVED) {
        pr_err("krdma: failed to resolve the server address\n");
        goto out_destroy_cm_id;
    }

    ret = rdma_resolve_route(cb->cm_id, timeout_ms);
    if (ret) {
        pr_err("krdma: error on rdma_resolve_route\n");
        goto out_destroy_cm_id;
    }

    wait_event_interruptible(cb->sem, cb->state >= CM_STATE_ROUTE_RESOLVED);
    if (cb->state != CM_STATE_ROUTE_RESOLVED) {
        pr_err("krdma: failed to resolve route\n");
        goto out_destroy_cm_id;
    }

    if (allocate_qp(cb)) {
        pr_err("krdma: error on allocate_qp\n");
        goto out_destroy_cm_id;
    }
    DEBUG_LOG("krdma: qp allocated successfully\n");

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.responder_resources = 1;
    conn_param.initiator_depth = 1;
    conn_param.retry_count = 10;

    DEBUG_LOG("krdma: send connection request to the server\n");
    ret = rdma_connect(cb->cm_id, &conn_param);
    if (ret) {
        pr_err("krdma: error on rdma_connect\n");
        goto out_release_qp;
    }

    wait_event_interruptible(cb->sem, cb->state >= CM_STATE_CONNECTED);
    if (cb->state == CM_STATE_ERROR) {
        pr_err("krdma: failed to connect the server\n");
        goto out_release_qp;
    }
    DEBUG_LOG("krdma: connection established successfully\n");

    return cb;

out_release_qp:
    release_qp(cb);
out_destroy_cm_id:
    rdma_destroy_id(cb->cm_id);
out_free_cb:
    vfree(cb);
out:
    return NULL;
}
EXPORT_SYMBOL(krdma_connect);

void krdma_disconnect(struct krdma_cb *cb)
{
    int ret = 0;
    struct rdma_cm_id *cm_id;

    DEBUG_LOG("krdma: disconnect the connection: id: %p\n", cb->cm_id);

    if (cb->server)
        cm_id = cb->cm_id_child;
    else
        cm_id = cb->cm_id;

    ret = rdma_disconnect(cm_id);
    if (ret) {
        pr_err("krdma: error on rdma_disconnect\n");
        goto out;
    }

    DEBUG_LOG("krdma: waiting the disconnection event: id: %p\n", cm_id);
    wait_event_interruptible(cb->sem, cb->state >= CM_STATE_DISCONNECTED);
    if (cb->state >= CM_STATE_ERROR) {
        pr_err("krdma: failed to disconnect the server\n");
        goto out;
    }

out:
    release_qp(cb);
    if (cb->server)
        rdma_destroy_id(cb->cm_id_child);
    rdma_destroy_id(cb->cm_id);
    vfree(cb);
}
EXPORT_SYMBOL(krdma_disconnect);

void krdma_test(void)
{
    pr_info("krdma: hello world\n");
}
EXPORT_SYMBOL(krdma_test);
