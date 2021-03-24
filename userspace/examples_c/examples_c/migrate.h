#ifndef _EXAMPLES_C_MIGRATE_H_
#define _EXAMPLES_C_MIGRATE_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <librackdm/rackdm.h>

#define GET_DIFF_NS(t0, t1) \
    (10e9 * t1.tv_sec + t1.tv_nsec) - (10e9 * t0.tv_sec + t0.tv_nsec)

#define REGION_SIZE 1073741824UL

struct migrate_msg {
    char node[64];
    uint64_t region_id;
    uint64_t region_size;
};

#endif /* _EXAMPLES_C_MIGRATE_H */
