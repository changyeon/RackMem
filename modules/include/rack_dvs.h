#ifndef _INCLUDE_RACK_DVS_H_
#define _INCLUDE_RACK_DVS_H_

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/completion.h>

#define MB                  (1UL << 20UL)
#define GB                  (1UL << 30UL)

#define count_event(region, event) \
    this_cpu_inc(region->stat->count[event])

enum rack_dvs_event {
    RACK_DVS_EVENT_SLAB_ALLOC,
    RACK_DVS_EVENT_SLAB_FREE,
    RACK_DVS_EVENT_GET_SLAB_FAST,
    RACK_DVS_EVENT_GET_SLAB_SLOW,
    RACK_DVS_EVENT_UPDATE_SLAB_POOL,
    RACK_DVS_EVENT_RECLAIM_SLAB,
    RACK_DVS_EVENT_SLAB_READ,
    RACK_DVS_EVENT_SLAB_WRITE,
    __NR_RACK_DVS_EVENTS
};

struct rack_dvs_event_count {
    u64 count[__NR_RACK_DVS_EVENTS];
};

static const char * const rack_dvs_events[] = {
    [RACK_DVS_EVENT_SLAB_ALLOC]                 = "slab_alloc",
    [RACK_DVS_EVENT_SLAB_FREE]                  = "slab_free",
    [RACK_DVS_EVENT_GET_SLAB_FAST]              = "get_slab_fast",
    [RACK_DVS_EVENT_GET_SLAB_SLOW]              = "get_slab_slow",
    [RACK_DVS_EVENT_UPDATE_SLAB_POOL]           = "update_slab_pool",
    [RACK_DVS_EVENT_RECLAIM_SLAB]               = "reclaim_slab",
    [RACK_DVS_EVENT_SLAB_READ]                  = "slab_read",
    [RACK_DVS_EVENT_SLAB_WRITE]                 = "slab_write",
};

struct rack_dvs_dev {
    struct list_head lh;
    struct rack_dvs_ops *dvs_ops;
};

struct dvs_slab {
    struct list_head lh;
    struct rack_dvs_dev *dev;
    void *private;
    int ref;
};

struct dvs_slab_pool {
    struct list_head lh;
    unsigned long size;
    unsigned long slab_size_bytes;
    spinlock_t lock;
};

struct dvs_slot {
    struct dvs_slab *slab;
    spinlock_t lock;
};

struct rack_dvs_ops {
    struct dvs_slab *(*alloc)(u64 size);
    void (*free)(struct dvs_slab *slab);
    int (*read)(struct dvs_slab *slab, u64 offset, u64 size, void *dst);
    int (*write)(struct dvs_slab *slab, u64 offset, u64 size, void *src);
};

struct rack_dvs_region {
    u64 size_bytes;
    u64 slab_size_bytes;
    u64 nr_slots;
    struct dvs_slot *slots;
    struct rack_dvs_event_count __percpu *stat;

    struct dvs_slab_pool slab_pool;
    struct work_struct update_slab_pool_work;
};

#define rack_dvs_read(region, offset, size, dst) \
    rack_dvs_io(region, offset, size, dst, READ)
#define rack_dvs_write(region, offset, size, dst) \
    rack_dvs_io(region, offset, size, dst, WRITE)

/*
 * Test functions
 */
int dvs_test_single_thread_correctness(u64 size_mb, u64 slab_mb);

/*
 * Exported APIs
 */
int rack_dvs_io(struct rack_dvs_region *region, u64 offset, u64 size,
                void *buf, int dir);
struct rack_dvs_region *rack_dvs_alloc_region(u64 size_bytes, u64 slab_size_bytes);
void rack_dvs_free_region(struct rack_dvs_region *region);
int rack_dvs_register_dev(struct rack_dvs_dev *dev);
void rack_dvs_unregister_dev(struct rack_dvs_dev *dev);

#endif /* _INCLUDE_RACK_DVS_H_ */
