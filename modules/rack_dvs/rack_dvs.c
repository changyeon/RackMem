#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <rack_dvs.h>
#include <rack_dvs.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem distributed virtual storage");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

#define DEBUG_LOG if (g_debug) pr_info

static LIST_HEAD(dvs_dev_list);
static DEFINE_SPINLOCK(dvs_dev_list_lock);

void update_slab_pool(struct work_struct *ws)
{
    struct rack_dvs_region *region;
    struct dvs_slab_pool *slab_pool;
    struct rack_dvs_dev *dev;
    struct dvs_slab *slab;
    unsigned long i, n = 8192UL;

    region = container_of(ws, struct rack_dvs_region, update_slab_pool_work);
    slab_pool = &region->slab_pool;

    spin_lock(&dvs_dev_list_lock);
    if (list_empty(&dvs_dev_list)) {
        spin_unlock(&dvs_dev_list_lock);
        pr_err("no available device\n");
        return;
    }
    dev = list_first_entry(&dvs_dev_list, struct rack_dvs_dev, lh);
    spin_unlock(&dvs_dev_list_lock);

    spin_lock(&slab_pool->lock);
    for (i = 0; i < n; i++) {
        slab = dev->dvs_ops->alloc(slab_pool->slab_size_bytes);
        if (slab == NULL) {
            pr_err("failed to allocate a slab from dev: %p\n", dev);
            break;
        }
        list_add_tail(&slab->lh, &slab_pool->lh);
        slab_pool->size++;
        count_event(region, RACK_DVS_EVENT_SLAB_ALLOC);
    }
    spin_unlock(&slab_pool->lock);

    count_event(region, RACK_DVS_EVENT_UPDATE_SLAB_POOL);
}

static struct dvs_slab *get_slab_fast(struct rack_dvs_region *region)
{
    struct dvs_slab *slab;

    spin_lock(&region->slab_pool.lock);
    if (list_empty(&region->slab_pool.lh)) {
        spin_unlock(&region->slab_pool.lock);
        goto out;
    }
    slab = list_first_entry(&region->slab_pool.lh, struct dvs_slab, lh);
    list_del_init(&slab->lh);
    region->slab_pool.size--;
    spin_unlock(&region->slab_pool.lock);

    return slab;

out:
    return NULL;
}

static struct dvs_slab *get_slab_slow(struct rack_dvs_region *region)
{
    struct rack_dvs_dev *dev;
    struct dvs_slab *slab;

    spin_lock(&dvs_dev_list_lock);
    if (list_empty(&dvs_dev_list)) {
        spin_unlock(&dvs_dev_list_lock);
        pr_err("no available device\n");
        goto out;
    }
    dev = list_first_entry(&dvs_dev_list, struct rack_dvs_dev, lh);
    spin_unlock(&dvs_dev_list_lock);

    slab = dev->dvs_ops->alloc(region->slab_size_bytes);
    if (slab == NULL) {
        pr_err("failed to allocate a slab from dev: %p\n", dev);
        goto out;
    }
    count_event(region, RACK_DVS_EVENT_SLAB_ALLOC);

    return slab;

out:
    return NULL;
}

static void check_and_update_slab_pool(struct rack_dvs_region *region)
{
    spin_lock(&region->slab_pool.lock);
    if (region->slab_pool.size < 4096)
        schedule_work(&region->update_slab_pool_work);
    spin_unlock(&region->slab_pool.lock);
}

/**
 * rack_dvs_io - handle I/O request on the region
 */
int rack_dvs_io(struct rack_dvs_region *region, u64 region_offset, u64 size,
                void *buf, int dir)
{
    int ret = 0;
    u64 slab_index, slab_offset;
    struct dvs_slot *slot;
    struct dvs_slab *slab;

    DEBUG_LOG("rack_dvs_io region: %p, offset: %llu, size: %llu, buf: %p, "
              "dir: %d\n", region, region_offset, size, buf, dir);

    slab_index = region_offset / region->slab_size_bytes;
    slab_offset = region_offset % region->slab_size_bytes;

    slot = &region->slots[slab_index];

    spin_lock(&slot->lock);
    if (slot->slab)
        goto success;

    slot->slab = get_slab_fast(region);
    if (slot->slab) {
        count_event(region, RACK_DVS_EVENT_GET_SLAB_FAST);
        goto success;
    }

    slot->slab = get_slab_slow(region);
    if (slot->slab == NULL) {
        spin_unlock(&slot->lock);
        pr_err("failed to allocate a slab (%p)\n", region);
        ret = -ENOMEM;
        goto out;
    }
    count_event(region, RACK_DVS_EVENT_GET_SLAB_SLOW);

success:
    spin_unlock(&slot->lock);

    check_and_update_slab_pool(region);

    slab = slot->slab;
    if (dir == READ) {
        ret = slab->dev->dvs_ops->read(slab, slab_offset, size, buf);
        count_event(region, RACK_DVS_EVENT_SLAB_READ);
    } else {
        ret = slab->dev->dvs_ops->write(slab, slab_offset, size, buf);
        count_event(region, RACK_DVS_EVENT_SLAB_WRITE);
    }

    if (ret) {
        pr_err("error on dvs_io: %d\n", ret);
        goto out;
    }

    return 0;

out:
    return ret;
}
EXPORT_SYMBOL(rack_dvs_io);

/**
 * rack_dvs_alloc_region - allocate a region from the registered devices
 */
struct rack_dvs_region *rack_dvs_alloc_region(u64 size_bytes,
                                              u64 slab_size_bytes)
{
    u64 i, nr_slots;
    struct rack_dvs_region *region;
    struct dvs_slot *slot;

    nr_slots = size_bytes / slab_size_bytes;

    DEBUG_LOG("rack_dvs_alloc_region size_bytes: %llu, slab_size_bytes: %llu, "
              "nr_slots: %llu\n", size_bytes, slab_size_bytes, nr_slots);

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (region == NULL) {
        pr_err("failed to allocate memory for struct rack_dvs_region\n");
        goto out;
    }

    region->size_bytes = size_bytes;
    region->slab_size_bytes = slab_size_bytes;
    region->nr_slots = nr_slots;

    region->slots = vzalloc(nr_slots * sizeof(*region->slots));
    if (region->slots == NULL) {
        pr_err("failed to allocate memory for region->slots\n");
        goto out_kfree_region;
    }

    for (i = 0; i < nr_slots; i++) {
        region->slots[i].slab = NULL;
        spin_lock_init(&region->slots[i].lock);
    }

    region->stat = alloc_percpu(struct rack_dvs_event_count);
    if (region->stat == NULL) {
        pr_err("failed to allocate percpu event array\n");
        goto out_free_slabs;
    }

    INIT_LIST_HEAD(&region->slab_pool.lh);
    region->slab_pool.size = 0;
    region->slab_pool.slab_size_bytes = slab_size_bytes;
    spin_lock_init(&region->slab_pool.lock);
    INIT_WORK(&region->update_slab_pool_work, update_slab_pool);

    return region;

out_free_slabs:
    for (i = 0; i < region->nr_slots; i++) {
        slot = &region->slots[i];
        spin_lock(&slot->lock);
        if (slot->slab) {
            slot->slab->dev->dvs_ops->free(slot->slab);
            count_event(region, RACK_DVS_EVENT_SLAB_FREE);
        }
        spin_unlock(&slot->lock);
    }
    vfree(region->slots);
out_kfree_region:
    kfree(region);
out:
    return NULL;
}
EXPORT_SYMBOL(rack_dvs_alloc_region);

static void print_statistics(struct rack_dvs_region *region)
{
    int i, cpu;
    u64 sum[__NR_RACK_DVS_EVENTS];

    memset(sum, 0, sizeof(sum));

    for_each_online_cpu(cpu)
        for (i = 0; i < __NR_RACK_DVS_EVENTS; i++)
            sum[i] += per_cpu(region->stat->count[i], cpu);

    for (i = 0; i < __NR_RACK_DVS_EVENTS; i++)
        pr_info("event_count (%p) %s: %llu\n", region, rack_dvs_events[i],
                sum[i]);
}

/**
 * rack_dvs_free_region - free dvs_region
 */
void rack_dvs_free_region(struct rack_dvs_region *region)
{
    u64 i;
    struct dvs_slab *slab, *next;
    struct dvs_slot *slot;

    DEBUG_LOG("rack_dvs_free_region region: %p\n", region);

    spin_lock(&region->slab_pool.lock);
    list_for_each_entry_safe(slab, next, &region->slab_pool.lh, lh) {
        list_del_init(&slab->lh);
        slab->dev->dvs_ops->free(slab);
        count_event(region, RACK_DVS_EVENT_SLAB_FREE);
    };
    spin_unlock(&region->slab_pool.lock);

    for (i = 0; i < region->nr_slots; i++) {
        slot = &region->slots[i];
        spin_lock(&slot->lock);
        if (slot->slab) {
            slot->slab->dev->dvs_ops->free(slot->slab);
            count_event(region, RACK_DVS_EVENT_SLAB_FREE);
        }
        spin_unlock(&slot->lock);
    }

    print_statistics(region);
    free_percpu(region->stat);

    vfree(region->slots);
    kfree(region);
}
EXPORT_SYMBOL(rack_dvs_free_region);

/**
 * rack_dvs_register_dev - register rack_dvs device
 */
int rack_dvs_register_dev(struct rack_dvs_dev *dev)
{
    DEBUG_LOG("rack_dvs_register_dev: %p\n", dev);

    spin_lock(&dvs_dev_list_lock);
    list_add_tail(&dev->lh, &dvs_dev_list);
    spin_unlock(&dvs_dev_list_lock);

    return 0;
}
EXPORT_SYMBOL(rack_dvs_register_dev);

/**
 * rack_dvs_unregister_dev - unregister rack_dvs device
 */
void rack_dvs_unregister_dev(struct rack_dvs_dev *dev)
{
    DEBUG_LOG("rack_dvs_unregister_dev: %p\n", dev);

    spin_lock(&dvs_dev_list_lock);
    list_del_init(&dev->lh);
    spin_unlock(&dvs_dev_list_lock);
}
EXPORT_SYMBOL(rack_dvs_unregister_dev);

static int __init rack_dvs_init(void)
{
    pr_info("rack_dvs: module loaded\n");

    return 0;
}

static void __exit rack_dvs_exit(void)
{
    pr_info("rack_dvs: module unloaded\n");
}

module_init(rack_dvs_init);
module_exit(rack_dvs_exit);
