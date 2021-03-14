#ifndef _INCLUDE_RACK_DVS_H_
#define _INCLUDE_RACK_DVS_H_

#define DVS_SLAB_SIZE_MB    64UL

#define MB                  (1UL << 20UL)
#define GB                  (1UL << 30UL)

#include <linux/list.h>

struct rack_dvs_dev {
    struct list_head head;
    struct rack_dvs_ops *dvs_ops;
};

struct dvs_slab {
    struct rack_dvs_dev *dev;
    void *private;
    spinlock_t lock;
};

struct rack_dvs_ops {
    int (*alloc)(struct dvs_slab *slab, u64 size);
    void (*free)(struct dvs_slab *slab);
    int (*read)(struct dvs_slab *slab, u64 offset, u64 size, void *dst);
    int (*write)(struct dvs_slab *slab, u64 offset, u64 size, void *src);
};

struct rack_dvs_region {
    u64 size_mb;
    u64 slab_size_mb;
    u64 nr_slabs;
    struct dvs_slab *slabs;
};

#define rack_dvs_read(region, offset, size, dst) \
    rack_dvs_io(region, offset, size, dst, READ)
#define rack_dvs_write(region, offset, size, dst) \
    rack_dvs_io(region, offset, size, dst, WRITE)

int rack_dvs_io(struct rack_dvs_region *region, u64 offset, u64 size,
                void *buf, int dir);
struct rack_dvs_region *rack_dvs_alloc_region(u64 size_mb, u64 slab_size_mb);
void rack_dvs_free_region(struct rack_dvs_region *region);
int rack_dvs_register_dev(struct rack_dvs_dev *dev);
void rack_dvs_unregister_dev(struct rack_dvs_dev *dev);

#endif /* _INCLUDE_RACK_DVS_H_ */
