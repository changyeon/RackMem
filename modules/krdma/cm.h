#ifndef _KRDMA_CM_H_
#define _KRDMA_CM_H_

int krdma_setup(char *server, int port);
void krdma_cleanup(void);
int krdma_connect(char *server, int port);

#endif /* _KRDMA_CM_H_ */
