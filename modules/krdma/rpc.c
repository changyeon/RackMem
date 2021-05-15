#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/dma-mapping.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/completion.h>
#include <linux/preempt.h>
#include <rdma/ib_verbs.h>

#include <krdma.h>

extern int g_debug;
extern struct rdma_cm_id *cm_id_server;

#define DEBUG_LOG if (g_debug) pr_info

extern char g_nodename[__NEW_UTS_LEN + 1];

static DEFINE_SPINLOCK(ht_lock);
static DEFINE_HASHTABLE(ht_rpc, 10);

static int krdma_rpc_execute_function(u32 id, void *input, void *output)
{
    int ret = 1;
    struct krdma_rpc_func *curr;

    hash_for_each_possible(ht_rpc, curr, hn, id) {
        if (curr->id == id) {
            ret = curr->func(input, output, curr->ctx);
            break;
        }
    }

    if (ret == 1) {
        ret = -EINVAL;
        pr_err("rpc id (%u) does not exist in the table\n", id);
        goto out;
    }

    if (ret < 0) {
        pr_err("error on the rpc call id: %u\n", id);
        goto out;
    }

    return ret;

out:
    return ret;
}

int krdma_register_rpc(u32 id, int (*func)(void *, void *, void *), void *ctx)
{
    int ret;
    struct krdma_rpc_func *rpc;

    DEBUG_LOG("krdma_register_rpc id: %u, func: %p\n", id, func);

    rpc = kzalloc(sizeof(*rpc), GFP_KERNEL);
    if (rpc == NULL) {
        pr_err("failed to allocate memory for krdma_rpc_func\n");
        ret = -ENOMEM;
        goto out;
    }

    rpc->id = id;
    rpc->func = func;
    rpc->ctx = ctx;

    spin_lock(&ht_lock);
    hash_add(ht_rpc, &rpc->hn, rpc->id);
    spin_unlock(&ht_lock);

    return 0;

out:
    return ret;
}
EXPORT_SYMBOL(krdma_register_rpc);

void krdma_unregister_rpc(u32 id)
{
    struct krdma_rpc_func *curr;

    DEBUG_LOG("krdma_unregister_rpc id: %u\n", id);

    hash_for_each_possible(ht_rpc, curr, hn, id) {
        if (curr->id == id) {
            hash_del(&curr->hn);
            kfree(curr);
            break;
        }
    }
}
EXPORT_SYMBOL(krdma_unregister_rpc);

void krdma_free_rpc_table(void)
{
    int i = 0;
    struct hlist_node *tmp;
    struct krdma_rpc_func *curr;

    spin_lock(&ht_lock);
    hash_for_each_safe(ht_rpc, i, tmp, curr, hn) {
        hash_del(&curr->hn);
        kfree(curr);
    }
    spin_unlock(&ht_lock);
}

struct krdma_msg *krdma_alloc_msg(struct krdma_conn *conn, u64 size)
{
    struct krdma_msg *kmsg = NULL;

    kmsg = kzalloc(sizeof(*kmsg), GFP_KERNEL);
    if (kmsg == NULL) {
        pr_err("failed to allocate memory for kmsg\n");
        goto out;
    }

    INIT_LIST_HEAD(&kmsg->head);
    kmsg->size = size;

    kmsg->vaddr = dma_alloc_coherent(
            conn->pd->device->dma_device, size, &kmsg->paddr, GFP_KERNEL);
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
EXPORT_SYMBOL(krdma_alloc_msg);

void krdma_free_msg(struct krdma_conn *conn, struct krdma_msg *kmsg)
{
    dma_free_coherent(conn->pd->device->dma_device, kmsg->size, kmsg->vaddr,
                      kmsg->paddr);
    kfree(kmsg);
}
EXPORT_SYMBOL(krdma_free_msg);

struct krdma_msg_pool *krdma_alloc_msg_pool(struct krdma_conn *conn, int n,
                                            u64 size)
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

void krdma_free_msg_pool(struct krdma_conn *conn, struct krdma_msg_pool *pool)
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

static int rkey_request_handler(struct krdma_conn *conn,
                                struct krdma_msg *recv_msg)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *send_buf;
    struct rpc_msg_fmt *recv_buf;
    const struct ib_send_wr *bad_send_wr;

    DEBUG_LOG("rkey_request_handler rkey: %u\n", conn->rkey);

    recv_buf = (struct rpc_msg_fmt *) recv_msg->vaddr;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -ENOMEM;
        goto out;
    }
    send_buf = (struct rpc_msg_fmt *) send_msg->vaddr;

    send_buf->cmd = KRDMA_CMD_RKEY_RESPONSE;
    send_buf->request_id = recv_buf->request_id;
    send_buf->payload = conn->rkey;

    send_msg->send_wr.wr_id = (u64) send_msg;

    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out_free_msg;
    }

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int rkey_response_handler(struct krdma_conn *conn,
                                 struct krdma_msg *recv_msg)
{
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *recv_buf;
    struct rpc_msg_fmt *send_buf;

    recv_buf = (struct rpc_msg_fmt *) recv_msg->vaddr;
    send_msg = (struct krdma_msg *) recv_buf->request_id;
    send_buf = (struct rpc_msg_fmt *) send_msg->vaddr;

    DEBUG_LOG("rkey_response_handler rkey: %llu\n", recv_buf->payload);

    send_buf->payload = recv_buf->payload;

    complete(&send_msg->done);

    return 0;
}

static int general_rpc_request_handler(struct krdma_conn *conn,
                                       struct krdma_msg *recv_msg)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *send_buf;
    struct rpc_msg_fmt *recv_buf;
    const struct ib_send_wr *bad_send_wr;

    recv_buf = (struct rpc_msg_fmt *) recv_msg->vaddr;

    DEBUG_LOG("rpc_request_general_rpc id: %u, request_id: %llu, size: %u\n",
              recv_buf->rpc_id, recv_buf->request_id, recv_buf->size);

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -ENOMEM;
        goto out;
    }
    send_buf = (struct rpc_msg_fmt *) send_msg->vaddr;

    send_buf->cmd = KRDMA_CMD_GENERAL_RPC_RESPONSE;
    send_buf->rpc_id = recv_buf->rpc_id;
    send_buf->request_id = recv_buf->request_id;

    send_buf->ret = krdma_rpc_execute_function(
            recv_buf->rpc_id,
            (void *) &recv_buf->payload,
            (void *) &send_buf->payload);

    if (send_buf->ret >= 0)
        send_buf->size = send_buf->ret;

    DEBUG_LOG("rpc_request_general_rpc id: %u send_buf ret: %d, size: %u\n",
              recv_buf->rpc_id, send_buf->ret, send_buf->size);

    send_msg->send_wr.wr_id = (u64) send_msg;

    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out_free_msg;
    }

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int general_rpc_response_handler(struct krdma_conn *conn,
                                        struct krdma_msg *recv_msg)
{
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *recv_buf;
    struct rpc_msg_fmt *send_buf;

    recv_buf = (struct rpc_msg_fmt *) recv_msg->vaddr;
    send_msg = (struct krdma_msg *) recv_buf->request_id;
    send_buf = (struct rpc_msg_fmt *) send_msg->vaddr;

    DEBUG_LOG("rpc_response_general_rpc id: %u, request_id: %llu, size: %u\n",
              recv_buf->rpc_id, recv_buf->request_id, recv_buf->size);

    if (recv_buf->size > 0) {
        send_buf->size = recv_buf->size;
        memcpy(&send_buf->payload, &recv_buf->payload, recv_buf->size);
    }

    complete(&send_msg->done);

    return 0;
}

static int krdma_rpc_handler(struct krdma_conn *conn,
                             struct krdma_msg *recv_msg)
{
    int ret = 0;
    struct rpc_msg_fmt *fmt = (struct rpc_msg_fmt *) recv_msg->vaddr;

    switch (fmt->cmd) {
        case KRDMA_CMD_RKEY_REQUEST:
            ret = rkey_request_handler(conn, recv_msg);
            break;
        case KRDMA_CMD_RKEY_RESPONSE:
            ret = rkey_response_handler(conn, recv_msg);
            break;
        case KRDMA_CMD_GENERAL_RPC_REQUEST:
            ret = general_rpc_request_handler(conn, recv_msg);
            break;
        case KRDMA_CMD_GENERAL_RPC_RESPONSE:
            ret = general_rpc_response_handler(conn, recv_msg);
            break;
        default:
            pr_err("unexpected rpc command %u\n", fmt->cmd);
            ret = -EINVAL;
            break;
    }

    if (ret) {
        pr_err("error on rpc: %s\n", krdma_cmds[fmt->cmd]);
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
            krdma_free_msg(conn, kmsg);
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
    bool to_stop = false;
    struct krdma_poll_work *poll_work;
    struct krdma_conn *conn;
    struct ib_cq *cq;
    struct ib_wc wc;

    poll_work = container_of(ws, struct krdma_poll_work, work);
    conn = poll_work->conn;
    cq = conn->rpc_qp.cq;

    DEBUG_LOG("krdma_poll_work cq: %p, conn: %p\n", cq, conn);

    while (true) {
        ret = ib_poll_cq(conn->rpc_qp.cq, 1, &wc);
        if (ret < 0 || ret > 1) {
            pr_err("error on ib_poll_cq: ret: %d (%s, %s)\n",
                   ret, ib_wc_status_msg(wc.status), wc_opcodes[wc.opcode]);
            break;
        }

        if (ret == 0 && to_stop)
            break;

        if (ret == 0) {
            ret = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
            if (ret) {
                pr_err("error on ib_req_notify_cq: %d\n", ret);
                break;
            }
            to_stop = true;
            continue;
        }

        if (ret == 1) {
            process_completion(conn, &wc);
            to_stop = false;
            continue;
        }
    }
}

int krdma_send_rpc_request(struct krdma_conn *conn, struct krdma_msg *msg)
{
    int ret;
    struct rpc_msg_fmt *fmt;
    const struct ib_send_wr *bad_send_wr;

    fmt = (struct rpc_msg_fmt *) msg->vaddr;
    fmt->request_id = (u64) msg;
    fmt->ret = 0;

    init_completion(&msg->done);
    msg->send_wr.wr_id = 0;

    ret = ib_post_send(conn->rpc_qp.qp, &msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out;
    }

    ret = wait_for_completion_timeout(
            &msg->done, msecs_to_jiffies(10000) + 1);
    if (ret == 0) {
        pr_err("timeout in krdma_send_rpc_request id: %u\n", fmt->rpc_id);
        ret = -ETIMEDOUT;
        goto out;
    }

    return 0;

out:
    return ret;
}
EXPORT_SYMBOL(krdma_send_rpc_request);

int krdma_get_remote_rkey(struct krdma_conn *conn)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;

    DEBUG_LOG("krdma_get_remote_rkey\n");

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_RKEY_REQUEST;
    fmt->size = 0;

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        ret = -EINVAL;
        goto out_free_msg;
    }

    ret = (int) fmt->payload;

    krdma_free_msg(conn, send_msg);

    return ret;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int dummy_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    u64 val;

    val = *((u64 *) input);
    *((u64 *) output) = val + 1;

    ret += sizeof(u64);

    return ret;
}

int krdma_dummy_rpc(struct krdma_conn *conn, u64 val)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = KRDMA_RPC_DUMMY;

    fmt->payload = val;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        ret = -EINVAL;
        goto out_free_msg;
    }

    DEBUG_LOG("val: %llu, result: %llu\n", val, fmt->payload);

    val = fmt->payload;

    krdma_free_msg(conn, send_msg);

    return val;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int get_node_name_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;

    strcpy(output, g_nodename);
    ret = strlen(g_nodename) + 1;

    DEBUG_LOG("get_node_name_rpc_handler %s, %d\n", g_nodename, ret);

    return ret;
}

int krdma_get_remote_node_name(struct krdma_conn *conn)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;

    DEBUG_LOG("krdma_get_node_name\n");

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = KRDMA_RPC_GET_NODE_NAME;
    fmt->size = 0;

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        ret = -EINVAL;
        goto out_free_msg;
    }

    strcpy(conn->nodename, (void *) &fmt->payload);
    conn->nodename_hash = hashlen_hash(hashlen_string(NULL, conn->nodename));

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

static int alloc_remote_memory_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    void *vaddr;
    u64 size, paddr;
    struct ib_device *ib_dev = cm_id_server->device;
    struct payload_fmt *payload;

    size = *((u64 *) input);

    vaddr = dma_alloc_coherent(ib_dev->dma_device, size, &paddr, GFP_KERNEL);
    if (vaddr == NULL) {
        pr_err("failed to allocate memory for kmr buffer\n");
        ret = -ENOMEM;
        goto out;
    }

    payload = (struct payload_fmt *) output;
    payload->arg1 = (u64) vaddr;
    payload->arg2 = (u64) paddr;

    ret = 2UL * sizeof(u64);

    return ret;

out:
    return ret;
}

struct krdma_mr *krdma_alloc_remote_memory(struct krdma_conn *conn, u64 size)
{
    int ret;
    struct krdma_mr *kmr = NULL;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;

    kmr = kzalloc(sizeof(*kmr), GFP_KERNEL);
    if (kmr == NULL) {
        pr_err("failed to allocate memory for kmr\n");
        goto out;
    }

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        goto out_free_kmr;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = KRDMA_RPC_ALLOC_REMOTE_MEMORY;

    fmt->payload = size;
    fmt->size = sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        goto out_free_msg;
    }

    payload = (struct payload_fmt *) &fmt->payload;

    kmr->conn  = conn;
    kmr->size  = size;
    kmr->vaddr = payload->arg1;
    kmr->paddr = payload->arg2;
    kmr->rkey  = conn->remote_rkey;

    krdma_free_msg(conn, send_msg);

    return kmr;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out_free_kmr:
    kfree(kmr);
out:
    return NULL;
}
EXPORT_SYMBOL(krdma_alloc_remote_memory);

static int free_remote_memory_rpc_handler(void *input, void *output, void *ctx)
{
    int ret = 0;
    u64 size, vaddr, paddr;
    struct ib_device *ib_dev = cm_id_server->device;
    struct payload_fmt *payload;

    payload = (struct payload_fmt *) input;
    size  = payload->arg1;
    vaddr = payload->arg2;
    paddr = payload->arg3;

    dma_free_coherent(ib_dev->dma_device, size, (void *) vaddr, paddr);

    return ret;
}

int krdma_free_remote_memory(struct krdma_conn *conn, struct krdma_mr *kmr)
{
    int ret;
    struct krdma_msg *send_msg;
    struct rpc_msg_fmt *fmt;
    struct payload_fmt *payload;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_free_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    fmt = (struct rpc_msg_fmt *) send_msg->vaddr;
    fmt->cmd = KRDMA_CMD_GENERAL_RPC_REQUEST;
    fmt->rpc_id = KRDMA_RPC_FREE_REMOTE_MEMORY;

    payload = (struct payload_fmt *) &fmt->payload;
    payload->arg1 = kmr->size;
    payload->arg2 = kmr->vaddr;
    payload->arg3 = kmr->paddr;

    fmt->size = 3UL * sizeof(u64);

    ret = krdma_send_rpc_request(conn, send_msg);
    if (ret) {
        pr_err("error on krdma_send_rpc_request\n");
        goto out_free_msg;
    }

    if (fmt->ret < 0) {
        pr_err("failed rpc request %d\n", fmt->rpc_id);
        ret = -EINVAL;
        goto out_free_msg;
    }

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}
EXPORT_SYMBOL(krdma_free_remote_memory);

int register_all_krdma_rpc(void)
{
    int ret;
    u32 rpc_id;

    DEBUG_LOG("register_all_krdma_rpc\n");

    rpc_id = KRDMA_RPC_DUMMY;
    ret = krdma_register_rpc(rpc_id, dummy_rpc_handler, NULL);
    if (ret) {
        pr_err("failed to register krdma_rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out;
    }

    rpc_id = KRDMA_RPC_GET_NODE_NAME;
    krdma_register_rpc(rpc_id, get_node_name_rpc_handler, NULL);
    if (ret) {
        pr_err("failed to register krdma_rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_dummy;
    }

    rpc_id = KRDMA_RPC_ALLOC_REMOTE_MEMORY;
    krdma_register_rpc(rpc_id, alloc_remote_memory_rpc_handler, NULL);
    if (ret) {
        pr_err("failed to register krdma_rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_get_node_name;
    }

    rpc_id = KRDMA_RPC_FREE_REMOTE_MEMORY;
    krdma_register_rpc(rpc_id, free_remote_memory_rpc_handler, NULL);
    if (ret) {
        pr_err("failed to register krdma_rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out_unregister_alloc_remote_memory;
    }

    return 0;

out_unregister_alloc_remote_memory:
    krdma_unregister_rpc(KRDMA_RPC_ALLOC_REMOTE_MEMORY);
out_unregister_get_node_name:
    krdma_unregister_rpc(KRDMA_RPC_GET_NODE_NAME);
out_unregister_dummy:
    krdma_unregister_rpc(KRDMA_RPC_DUMMY);
out:
    return ret;
}

void unregister_all_krdma_rpc(void)
{
    DEBUG_LOG("unregister_all_krdma_rpc\n");

    krdma_unregister_rpc(KRDMA_RPC_FREE_REMOTE_MEMORY);
    krdma_unregister_rpc(KRDMA_RPC_ALLOC_REMOTE_MEMORY);
    krdma_unregister_rpc(KRDMA_RPC_GET_NODE_NAME);
    krdma_unregister_rpc(KRDMA_RPC_DUMMY);
}
