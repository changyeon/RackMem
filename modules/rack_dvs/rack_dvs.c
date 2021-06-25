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
    struct rack_dvs_dev *dev;

    DEBUG_LOG("rack_dvs_io region: %p, offset: %llu, size: %llu, buf: %p, "
              "dir: %d\n", region, region_offset, size, buf, dir);

    slab_index = region_offset / region->slab_size_bytes;
    slab_offset = region_offset % region->slab_size_bytes;

    slot = &region->slots[slab_index];
    spin_lock(&slot->lock);
    slab = slot->slab;
    if (slab == NULL) {
        /* allocate a new slab for this slot */
        if (list_empty(&dvs_dev_list)) {
            pr_err("no available device\n");
            spin_unlock(&slot->lock);
            ret = -EINVAL;
            goto out;
        }

        /* FIXME: we only use the first device! */
        dev = list_first_entry(&dvs_dev_list, struct rack_dvs_dev, head);
        slab = dev->dvs_ops->alloc(region->slab_size_bytes);
        if (slab == NULL) {
            pr_err("failed to allocate a slab from dev: %p\n", dev);
            spin_unlock(&slot->lock);
            ret = -ENOMEM;
            goto out;
        }
        slot->slab = slab;
        count_event(region, RACK_DVS_EVENT_SLAB_ALLOC);
    }
    spin_unlock(&slot->lock);

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
    struct dvs_slot *slot;

    DEBUG_LOG("rack_dvs_free_region region: %p\n", region);

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
    list_add_tail(&dev->head, &dvs_dev_list);
    spin_unlock(&dvs_dev_list_lock);

    return 0;
}
EXPORT_SYMBOL(rack_dvs_register_dev);

/**
 * rack_dvs_unregister_dev - unregister rack_dvs device
 */
void rack_dvs_unregister_dev(struct rack_dvs_dev *dev)
{
    struct rack_dvs_dev *node, *next;

    DEBUG_LOG("rack_dvs_unregister_dev: %p\n", dev);

    spin_lock(&dvs_dev_list_lock);
    list_for_each_entry_safe(node, next, &dvs_dev_list, head) {
        list_del_init(&node->head);
    }

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
