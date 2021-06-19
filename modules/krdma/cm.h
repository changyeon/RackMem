#ifndef _KRDMA_CM_H_
#define _KRDMA_CM_H_

#define KRDMA_MAX_SEND_WR       128
#define KRDMA_MAX_RECV_WR       128
#define KRDMA_MAX_SEND_SGE      16
#define KRDMA_MAX_RECV_SGE      16

#define KRDMA_RETRY_COUNT       128
#define KRDMA_RNR_RETRY_COUNT   128

int krdma_listen(char *server, int port);
void krdma_close(void);
int krdma_connect(char *server, int port);

#endif /* _KRDMA_CM_H_ */
