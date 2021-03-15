#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <rack_dvs.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DRAM backend for RackMem Distributed Virtual Storage");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

int g_debug = 0;
module_param_named(debug, g_debug, int, 0);
MODULE_PARM_DESC(debug, "enable debug mode");

#define DEBUG_LOG if (g_debug) pr_info

struct dram_slab {
    void *buf;
};

static int dram_alloc(struct dvs_slab *slab, u64 size);
static void dram_free(struct dvs_slab *slab);
static int dram_read(struct dvs_slab *slab, u64 offset, u64 size, void *dst);
static int dram_write(struct dvs_slab *slab, u64 offset, u64 size, void *src);

static struct rack_dvs_ops dram_ops = {
    .alloc  = dram_alloc,
    .free   = dram_free,
    .read   = dram_read,
    .write  = dram_write
};

static struct rack_dvs_dev dram_dev = {
    .dvs_ops = &dram_ops
};

static int dram_alloc(struct dvs_slab *slab, u64 size)
{
    int ret = 0;
    struct dram_slab *dram_slab;

    DEBUG_LOG("dram_alloc slab: %p, size: %llu\n", slab, size);

    dram_slab = kzalloc(sizeof(*slab), GFP_KERNEL);
    if (dram_slab == NULL) {
       pr_err("failed to allocate memory for dram_slab\n");
       ret = -ENOMEM;
       goto out;
    }

    dram_slab->buf = vzalloc(size);
    if (dram_slab->buf == NULL) {
        pr_err("failed to allocate memory for dram_slab->buf\n");
       ret = -ENOMEM;
        goto out_kfree_slab;
    }

    slab->private = (void *) dram_slab;

    return 0;

out_kfree_slab:
    kfree(dram_slab);
out:
    return ret;
}

static void dram_free(struct dvs_slab *slab)
{
    struct dram_slab *dram_slab;

    DEBUG_LOG("dram_free slab: %p\n", slab);

    dram_slab = (struct dram_slab *) slab->private;
    vfree(dram_slab->buf);
    kfree(dram_slab);
}

/**
 * dram_read - read data from the slab
 */
static int dram_read(struct dvs_slab *slab, u64 offset, u64 size, void *dst)
{
    struct dram_slab *dram_slab;

    DEBUG_LOG("dram_read slab: %p, offset: %llu, size: %llu, dst: %p\n",
              slab, offset, size, dst);

    dram_slab = (struct dram_slab *) slab->private;
    memcpy(dst, dram_slab->buf + offset, size);

    return 0;
}

/**
 * dram_write - write data to the slab
 */
static int dram_write(struct dvs_slab *slab, u64 offset, u64 size, void *src)
{
    struct dram_slab *dram_slab;

    DEBUG_LOG("dram_write slab: %p, offset: %llu, size: %llu, src: %p\n",
              slab, offset, size, src);

    dram_slab = (struct dram_slab *) slab->private;
    memcpy(dram_slab->buf + offset, src, size);

    return 0;
}

static int __init rack_dvs_dram_init(void)
{
    int ret = 0;
    ret = rack_dvs_register_dev(&dram_dev);
    if (ret) {
        pr_err("failed to register dram backend for RackDVS\n");
        goto out;
    }

    ret = dvs_test_single_thread_correctness();
    if (ret)
        pr_info("dvs_test_single_thread_correctness: FAIL\n");
    else
        pr_info("dvs_test_single_thread_correctness: SUCCESS\n");

    pr_info("rack_dvs_dram: module loaded\n");

    return 0;

out:
    return ret;
}

static void __exit rack_dvs_dram_exit(void)
{
    rack_dvs_unregister_dev(&dram_dev);

    pr_info("rack_dvs_dram: module unloaded\n");
}

module_init(rack_dvs_dram_init);
module_exit(rack_dvs_dram_exit);
