#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
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
int rack_dvs_io(struct rack_dvs_region *region, u64 offset, u64 size,
                void *buf, int dir)
{
    int ret = 0;
    u64 slab_size_bytes, slab_index, slab_offset;
    struct dvs_slab *slab;

    DEBUG_LOG("rack_dvs_io region: %p, offset: %llu, size: %llu, buf: %p, "
              "dir: %d\n", region, offset, size, buf, dir);

    slab_size_bytes = region->slab_size_bytes;
    slab_index = offset / slab_size_bytes;
    slab_offset = offset % slab_size_bytes;

    slab = &region->slabs[slab_index];
    spin_lock(&slab->lock);
    if (slab->dev == NULL) {
        if (list_empty(&dvs_dev_list)) {
            pr_err("no available device\n");
            ret = -ENOMEM;
            spin_unlock(&slab->lock);
            goto out;
        }
        slab->dev = list_first_entry(&dvs_dev_list, struct rack_dvs_dev, head);
        ret = slab->dev->dvs_ops->alloc(slab, slab_size_bytes);
        if (ret) {
            pr_err("error on dvs_ops->alloc: %d\n", ret);
            spin_unlock(&slab->lock);
            goto out;
        }
    }
    spin_unlock(&slab->lock);

    if (dir == READ)
        ret = slab->dev->dvs_ops->read(slab, slab_offset, size, buf);
    else
        ret = slab->dev->dvs_ops->write(slab, slab_offset, size, buf);

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
    u64 i, nr_slabs;
    struct rack_dvs_region *region;

    nr_slabs = size_bytes / slab_size_bytes;

    DEBUG_LOG("rack_dvs_alloc_region size_bytes: %llu, slab_size_bytes: %llu, "
              "nr_slabs: %llu\n", size_bytes, slab_size_bytes, nr_slabs);

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (region == NULL) {
        pr_err("failed to allocate memory for struct rack_dvs_region\n");
        goto out;
    }

    region->size_bytes = size_bytes;
    region->slab_size_bytes = slab_size_bytes;
    region->nr_slabs = nr_slabs;

    region->slabs = vzalloc(nr_slabs * sizeof(struct dvs_slab));
    if (region->slabs == NULL) {
        pr_err("failed to allocate memory for region->slabs\n");
        goto out_kfree_region;
    }

    for (i = 0; i < nr_slabs; i++)
        spin_lock_init(&region->slabs[i].lock);

    DEBUG_LOG("rack_dvs_alloc_region size: %llumb, slab_size: %llumb (%p)\n",
              region->size_bytes, region->slab_size_bytes, region);

    return region;

out_kfree_region:
    kfree(region);
out:
    return NULL;
}
EXPORT_SYMBOL(rack_dvs_alloc_region);

/**
 * rack_dvs_free_region - free dvs_region
 */
void rack_dvs_free_region(struct rack_dvs_region *region)
{
    u64 i;
    struct dvs_slab *slab;

    DEBUG_LOG("rack_dvs_free_region region: %p\n", region);

    for (i = 0; i < region->nr_slabs; i++) {
        slab = &region->slabs[i];
        spin_lock(&slab->lock);
        if (slab->private)
            slab->dev->dvs_ops->free(slab);
        spin_unlock(&slab->lock);
    }

    vfree(region->slabs);
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
