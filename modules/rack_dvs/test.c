#include <rack_dvs.h>
#include <uapi/asm-generic/errno.h>
#include <linux/vmalloc.h>
#include <linux/random.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

int dvs_test_single_thread_correctness(u64 size_mb, u64 slab_mb)
{
    u64 size_bytes = size_mb * MB, slab_size_bytes = slab_mb * MB;
    u64 i, n, offset;
    int ret = 0;
    struct rack_dvs_region *region;
    void *buf, *tmp;

    region = rack_dvs_alloc_region(size_bytes, slab_size_bytes);
    if (region == NULL) {
        pr_err("error on rack_dvs_alloc_region\n");
        ret = -ENOMEM;
        goto out;
    }

    buf = vzalloc(size_bytes);
    if (buf == NULL) {
        pr_err("failed to allocate memory for buf\n");
        ret = -ENOMEM;
        goto out_free_region;
    }

    tmp = vzalloc(size_bytes);
    if (buf == NULL) {
        pr_err("failed to allocate memory for tmp\n");
        ret = -ENOMEM;
        goto out_free_buf;
    }

    get_random_bytes(buf, size_bytes);
    memcpy(tmp, buf, size_bytes);

    ret = memcmp(buf, tmp, size_bytes);
    if (ret != 0) {
        pr_err("memcmp failed - #1\n");
        goto out_free_tmp;
    }

    n = (size_bytes) / PAGE_SIZE;
    for (i = 0; i < n; i++) {
        offset = i * PAGE_SIZE;
        ret = rack_dvs_write(region, offset, PAGE_SIZE, buf + offset);
        if (ret) {
            pr_err("error on rack_dvs_write\n");
            goto out_free_tmp;
        }
    }
    memset(buf, 0, size_bytes);

    ret = memcmp(buf, tmp, size_bytes);
    if (ret == 0) {
        pr_err("memcmp failed - #2\n");
        goto out_free_tmp;
    }

    n = (size_bytes) / PAGE_SIZE;
    for (i = 0; i < n; i++) {
        offset = i * PAGE_SIZE;
        ret = rack_dvs_read(region, offset, PAGE_SIZE, buf + offset);
        if (ret) {
            pr_err("error on rack_dvs_read\n");
            goto out_free_tmp;
        }
    }


    n = (size_bytes) / PAGE_SIZE;
    for (i = 0; i < n; i++) {
        offset = i * PAGE_SIZE;
        ret = memcmp(buf + offset, tmp + offset, PAGE_SIZE);
        if (ret != 0)
            pr_err("memcmp fail:    %llu/%llu\n", i, n);
    }

    rack_dvs_free_region(region);

    return 0;

out_free_tmp:
    vfree(tmp);
out_free_buf:
    vfree(buf);
out_free_region:
    rack_dvs_free_region(region);
out:
    return ret;
}
