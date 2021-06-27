#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/percpu-defs.h>

#include <rack_dvs.h>
#include <rack_vm.h>
#include "debugfs.h"

extern int g_debug;
extern int g_page_size;
extern int g_slab_size_bytes;

#define DEBUG_LOG if (g_debug) pr_info

void rack_vm_close(struct vm_area_struct *vma);
vm_fault_t rack_vm_fault(struct vm_fault *vmf);

static struct vm_operations_struct rack_vm_ops = {
        .close = rack_vm_close,
        .fault = rack_vm_fault,
};

int rack_vm_mmap(struct file *fp, struct vm_area_struct *vma)
{
    int ret;
    u64 size_bytes, page_size, slab_size_bytes;
    struct rack_vm_region *region;

    size_bytes = vma->vm_end - vma->vm_start;
    page_size = g_page_size;
    slab_size_bytes = g_slab_size_bytes;

    if (slab_size_bytes < page_size) {
        pr_err("the slab size is smaller than the page size "
               "(%llu, %llu)\n", slab_size_bytes, page_size);
        ret = -EINVAL;
        goto out;
    }

    if (slab_size_bytes % page_size) {
        pr_err("the slab size is not a multiple of the page size "
               "(%llu, %llu)\n", slab_size_bytes, page_size);
        ret = -EINVAL;
        goto out;
    }

    DEBUG_LOG("rack_vm_mmap size: %llu, page_size: %llu, "
              "slab_size_bytes: %llu, vma: %p\n", size_bytes, page_size,
              slab_size_bytes, vma);

    region = rack_vm_alloc_region(size_bytes, page_size, slab_size_bytes);
    if (region == NULL) {
        pr_err("error on rack_vm_alloc_region\n");
        ret = -EINVAL;
        goto out;
    }

    ret = rack_vm_map_region(region, vma, &rack_vm_ops);
    if (ret) {
        pr_err("error on rack_vm_map_region\n");
        goto out_free_region;
    }

    ret = rack_vm_debugfs_add_region(region);
    if (ret) {
        pr_err("error on rack_vm_debugfs_add_region\n");
        goto out_free_region;
    }

    return 0;

out_free_region:
    rack_vm_free_region(region);
out:
    return -EINVAL;
}

void rack_vm_close(struct vm_area_struct *vma)
{
    struct rack_vm_region *region;

    DEBUG_LOG("rack_vm_close vma: %p\n", vma);

    region = (struct rack_vm_region *) vma->vm_private_data;

    rack_vm_debugfs_del_region(region);
    rack_vm_free_region(region);
    vma->vm_private_data = NULL;

}

static inline void background_reclaim(struct rack_vm_region *region)
{
    /* threshold == 0.25% */
    s64 threshold = atomic64_read(&region->page_count_limit) / 400;

    if (region->full)
        if (rack_vm_page_list_size(&region->inactive_list) < threshold)
            schedule_work(&region->reclaim_work.ws);
}

vm_fault_t rack_vm_fault(struct vm_fault *vmf)
{
    int ret = 0;
    struct rack_vm_region *region;
    struct vm_area_struct *vma = vmf->vma;
    u64 fault_address, page_index;
    struct rack_vm_page *rpage = NULL;

    region = (struct rack_vm_region *) vma->vm_private_data;
    if (region == NULL) {
        pr_err("vm_private_data is NULL\n");
        goto out;
    }

    count_event(region, RACK_VM_EVENT_PGFAULT);
    if (vmf->flags & FAULT_FLAG_WRITE)
        count_event(region, RACK_VM_EVENT_PGFAULT_WRITE);
    else
        count_event(region, RACK_VM_EVENT_PGFAULT_READ);

    vma = vmf->vma;
    fault_address = (vmf->address / region->page_size) * region->page_size;
    page_index = (fault_address - vma->vm_start) / region->page_size;

    DEBUG_LOG("rack_vm_fault vma: %p, fault_address: %llu, pg_index: %llu\n",
              vma, fault_address, page_index);

    /* Step 1: Lock the rack_vm_page of the fault address */
    rpage = &region->pages[page_index];
    spin_lock(&rpage->lock);

    /* Step 2: Return here if the page has been resolved by another handler */
    if (unlikely(rpage->flags & RACK_VM_PAGE_ACTIVE)) {
        count_event(region, RACK_VM_EVENT_PGFAULT_COLLISION);
        goto success;
    }

    /* Step 3: Pagefault on an inactive page, just restore the mapping */
    if (unlikely(rpage->flags & RACK_VM_PAGE_INACTIVE)) {
        count_event(region, RACK_VM_EVENT_PGFAULT_INACTIVE);
        rack_vm_page_list_del(&region->inactive_list, rpage);
        goto success_remap;
    }

    /* Step 4: Allocate a new page if the current page count is below than
     * the threshold */
    rpage->buf = rack_vm_alloc_buf(region);
    if (rpage->buf)
        goto success_reclaim;

    /* Step 5: Try to reclaim a page from the inactive list */
    rpage->buf = rack_vm_reclaim_inactive(region);
    if (rpage->buf) {
        count_event(region, RACK_VM_EVENT_RECLAIM_FAST);
        goto success_reclaim;
    }

    /* Step 6: Reclaim a page from the active list */
    rpage->buf = rack_vm_reclaim_active(region);
    if (unlikely(rpage->buf == NULL) ) {
        pr_err("failed to reclaim a page\n");
        goto out_unlock;
    }
    count_event(region, RACK_VM_EVENT_RECLAIM_SLOW);

success_reclaim:
    if (rpage->flags == RACK_VM_PAGE_IDLE) {
        /* this is the first access on this page! */
        count_event(region, RACK_VM_EVENT_ACCSSED);
        goto success_remap;
    }

    /* Step 7: Restore the page */
    ret = rack_vm_restore(region, rpage);
    if (unlikely(ret)) {
        pr_err("failed to restore the page\n");
        goto out_unlock;
    }

success_remap:
    /* Step 8: Remap the page */
    ret = rack_vm_remap(region, rpage, fault_address, region->page_size);
    if (unlikely(ret)) {
        pr_err("failed to remap the page\n");
        goto out_unlock;
    }

success:
    spin_unlock(&rpage->lock);

    background_reclaim(region);

    return VM_FAULT_NOPAGE;

out_unlock:
    rpage->flags = RACK_VM_PAGE_ERROR;
    spin_unlock(&rpage->lock);
out:

    return VM_FAULT_ERROR;
}
