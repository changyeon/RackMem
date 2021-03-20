#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <rack_dm.h>
#include <krdma.h>
#include "rpc.h"

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

int get_region_metadata_rpc_handler(void *input, void *output)
{
    u64 *ptr;

    ptr = (u64 *) input;
    pr_info("metadata_rpc_handler: region_id: %llu\n", *ptr);
    ptr = (u64 *) output;
    *ptr = 22419;

    return 0;
}

int get_region_metadata(struct krdma_conn *conn, u64 region_id)
{
    int ret;
    const struct ib_send_wr *bad_send_wr;
    struct krdma_msg *send_msg;
    struct krdma_rpc_fmt *fmt;

    send_msg = krdma_alloc_msg(conn, 4096);
    if (send_msg == NULL) {
        pr_err("error on krdma_alloc_msg\n");
        ret = -ENOMEM;
        goto out;
    }

    fmt = (struct krdma_rpc_fmt *) send_msg->vaddr;
    fmt->cmd = (u64) KRDMA_CMD_REQUEST_GENERAL_RPC;
    fmt->send_ptr = (u64) send_msg;
    fmt->rpc_id = (u64) RACK_DM_RPC_GET_REGION_METADATA;
    fmt->size = sizeof(u64);
    fmt->payload = (u64) region_id;

    init_completion(&send_msg->done);
    send_msg->send_wr.wr_id = 0;

    ret = ib_post_send(conn->rpc_qp.qp, &send_msg->send_wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send: %d\n", ret);
        goto out_free_msg;
    }

    ret = wait_for_completion_timeout(
            &send_msg->done, msecs_to_jiffies(100) + 1);

    if (ret == 0) {
        pr_err("timeout in krdma_get_node_name\n");
        goto out_free_msg;
    }

    pr_info("get_region_metadata received msg: %llu\n", fmt->payload);

    krdma_free_msg(conn, send_msg);

    return 0;

out_free_msg:
    krdma_free_msg(conn, send_msg);
out:
    return ret;
}

int register_rack_dm_rpc(void)
{
    int ret;
    u32 rpc_id;

    rpc_id = RACK_DM_RPC_GET_REGION_METADATA;
    ret = krdma_register_rpc(rpc_id, get_region_metadata_rpc_handler);
    if (ret) {
        pr_err("failed to register rack_dm rpc %d\n", rpc_id);
        ret = -EINVAL;
        goto out;
    }

    return 0;

out:
    return ret;
}

void unregister_rack_dm_rpc(void)
{
    krdma_unregister_rpc(RACK_DM_RPC_GET_REGION_METADATA);
}
