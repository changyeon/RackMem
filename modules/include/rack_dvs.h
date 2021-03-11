#ifndef _INCLUDE_RACK_DVS_H_
#define _INCLUDE_RACK_DVS_H_

#define DVS_MAX_NODES       16
#define DVS_SLAB_SIZE_MB    64UL

#define MB                  (1UL << 20UL)
#define GB                  (1UL << 30UL)

#include <krdma.h>
#include <linux/list.h>
#include <linux/dma-mapping.h>

struct dvs_slab{
    struct krdma_conn *conn;
    struct krdma_mr *kmr;
    spinlock_t lock;
};

struct dvs_region {
    struct list_head head;
    u64 size_mb;
    u64 slab_size_mb;
    u64 nr_slabs;
    struct dvs_slab *slabs;
    spinlock_t lock;
};

struct dvs_node {
    struct list_head head;
    struct krdma_conn *conn;
};

#define dvs_read(dvsr, addr, offset, size) \
    dvs_io(dvsr, addr, offset, size, READ)
#define dvs_write(dvsr, addr, offset, size) \
    dvs_io(dvsr, addr, offset, size, WRITE)

int dvs_io(struct dvs_region *dvsr, dma_addr_t addr, u64 offset, u64 size, int dir);
struct dvs_region *dvs_alloc_region(u64 size_mb, u64 slab_size_mb);
void dvs_free_region(struct dvs_region *dvsr);

#endif /* _INCLUDE_RACK_DVS_H_ */
