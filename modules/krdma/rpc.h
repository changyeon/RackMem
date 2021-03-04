#ifndef _KRDMA_RPC_H_
#define _KRDMA_RPC_H_

#include "cm.h"

static const char * const krdma_cmds[] = {
    [KRDMA_CMD_HANDSHAKE_RDMA]      = "HANDSHAKE_RDMA",
    [KRDMA_CMD_HANDSHAKE_RPC_QP]    = "HANDSHAKE_RPC_QP",
    [KRDMA_CMD_REQUEST_NODE_NAME]   = "REQUEST_NODE_NAME",
    [KRDMA_CMD_RESPONSE_NODE_NAME]  = "RESPONSE_NODE_NAME",
};

int krdma_rpc_execute(struct krdma_conn *conn, struct krdma_msg *recv_msg);
int krdma_get_node_name(struct krdma_conn *conn, char *dst);
int handle_msg(struct krdma_conn *conn, struct ib_wc *wc);

#endif /* _KRDMA_RPC_H_ */
