#ifndef _INCLUDE_KRDMA_H_
#define _INCLUDE_KRDMA_H_

int krdma_cm_connect(char *server, int port);
void krdma_test(void);

// RDMA APIs
// krdma_join
// krdma_read
// krdma_write
// krdma_malloc
// krdma_free
// krdma_map

// RPC APIs
// krdma_rpc_register
// krmda_rpc_call
// krdma_rpc_recv
// krdma_rpc_reply
// krdma_send

// Synchronization APIs
// krdma_lock
// krdma_barrier
// krdma_fetch_and_add
// krdma_test_and_set

#endif /* _INCLUDE_KRDMA_H_ */
