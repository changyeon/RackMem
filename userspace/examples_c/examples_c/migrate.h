#ifndef _EXAMPLES_C_MIGRATE_H_
#define _EXAMPLES_C_MIGRATE_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <librackdm/rackdm.h>

struct migrate_msg {
    char node[64];
    uint64_t region_id;
    uint64_t region_size;
};

#endif /* _EXAMPLES_C_MIGRATE_H */
