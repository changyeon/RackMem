#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mm_types.h>

#include <rack_dvs.h>
#include <rack_vm.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

void rack_vm_close(struct vm_area_struct *vma);
vm_fault_t rack_vm_fault(struct vm_fault *vmf);

static struct vm_operations_struct rack_vm_ops = {
        .close = rack_vm_close,
        .fault = rack_vm_fault,
};

int rack_vm_mmap(struct file *fp, struct vm_area_struct *vma)
{
    u64 size_bytes, page_size, slab_size_bytes;
    struct rack_vm_region *region;

    size_bytes = vma->vm_end - vma->vm_start;
    page_size = PAGE_SIZE;
    slab_size_bytes = 64ULL * MB;

    region = rack_vm_alloc_region(size_bytes, PAGE_SIZE, 64 * MB);
    if (region == NULL) {
        pr_err("error on rack_vm_alloc_region\n");
        goto out;
    }

    region->vma = vma;
    vma->vm_private_data = (void *) region;
    vma->vm_ops = &rack_vm_ops;
    vma->vm_flags |= VM_MIXEDMAP;

    return 0;

out:
    return -EINVAL;
}

void rack_vm_close(struct vm_area_struct *vma)
{
    struct rack_vm_region *region;

    region = (struct rack_vm_region *) vma->vm_private_data;
    rack_vm_free_region(region);
    vma->vm_private_data = NULL;

}

int rack_vm_remap(struct rack_vm_region *region, struct rack_vm_page *rpage,
                  u64 fault_address, u64 page_size)
{
    int ret;

    ret = remap_vmalloc_range_partial(region->vma, fault_address, rpage->buf,
                                      0ULL, page_size);
    if (ret) {
        pr_err("error on remap_vmalloc_range_partial: %d\n", ret);
        goto out;
    }

    rpage->flags = RACK_VM_PAGE_ACTIVE;
    rack_vm_page_list_add(&region->active_list, rpage);

    return 0;

out:
    rpage->flags = RACK_VM_PAGE_ERROR;

    return ret;
}

void rack_vm_unmap(struct rack_vm_region *region, struct rack_vm_page *rpage)
{
    zap_page_range(region->vma,
                   region->vma->vm_start + rpage->index * region->page_size,
                   region->page_size);
    rpage->flags = RACK_VM_PAGE_INACTIVE;
}

void *rack_vm_reclaim(struct rack_vm_region *region)
{
    void *buf;

    buf = vmalloc_user(region->page_size);
    if (buf == NULL) {
        pr_err("error on vmalloc_user\n");
        goto out;
    }

    return buf;

out:
    return NULL;
}

int rack_vm_restore(struct rack_vm_region *region, struct rack_vm_page *rpage)
{
    int ret;
    dma_addr_t dst = page_to_phys(vmalloc_to_page(rpage->buf));

    ret = dvs_read(region->dvsr, dst, rpage->index * region->page_size,
                   region->page_size);
    if (ret) {
        pr_err("error on dvs_read: %d\n", ret);
        goto out;
    }

    return 0;

out:
    return ret;
}

int rack_vm_writeback(struct rack_vm_region *region,
                      struct rack_vm_page *rpage)
{
    int ret;
    dma_addr_t dst = page_to_phys(vmalloc_to_page(rpage->buf));

    ret = dvs_write(region->dvsr, dst, rpage->index * region->page_size,
                    region->page_size);
    if (ret) {
        pr_err("error on dvs_write: %d\n", ret);
        goto out;
    }

    return 0;

out:
    return ret;
}

vm_fault_t rack_vm_fault(struct vm_fault *vmf)
{
    int ret = 0;
    struct rack_vm_region *region;
    struct vm_area_struct *vma = vmf->vma;
    u64 fault_address, vma_size, vma_offset, page_index;
    struct rack_vm_page *rpage = NULL;

    region = (struct rack_vm_region *) vma->vm_private_data;
    if (region == NULL) {
        pr_err("vm_private_data is NULL\n");
        goto out;
    }

    vma = vmf->vma;
    fault_address = vmf->address & ~((1 << PAGE_SHIFT) - 1);
    vma_size = vma->vm_end - vma->vm_start;
    vma_offset = fault_address - vma->vm_start;
    page_index = vma_offset / region->page_size;

    /* Step 1: Lock the rack_vm_page of the fault address */
    rpage = &region->pages[page_index];
    spin_lock(&rpage->lock);

    /* Step 2: Return here if the page has been resolved by another handler */
    if (unlikely(rpage->flags & RACK_VM_PAGE_ACTIVE)) {
        goto success;
    }

    /* Step 3: Pagefault on an inactive page, just restore the mapping */
    if (unlikely(rpage->flags & RACK_VM_PAGE_INACTIVE)) {
        rack_vm_page_list_del(&region->inactive_list, rpage);
        ret = rack_vm_remap(region, rpage, fault_address, region->page_size);
        if (ret) {
            pr_err("error on rack_vm_remap\n");
            goto out_unlock;
        }
        goto success;
    }

    /* Step 4: Reclaim a page to handle this page fault */
    rpage->buf = rack_vm_reclaim(region);
    if (unlikely(rpage->buf == NULL) ) {
        pr_err("failed to reclaim a page\n");
        goto out_unlock;
    }

    /* Step 5: Restore the page */
    if (rpage->flags & RACK_VM_PAGE_REMOTE) {
        ret = rack_vm_restore(region, rpage);
        if (ret) {
            pr_err("failed to restore the page\n");
            goto out_unlock;
        }
    }

    /* Step 6: Remap the page */
    ret = rack_vm_remap(region, rpage, fault_address, region->page_size);
    if (ret) {
        pr_err("failed to remap the page\n");
        goto out_unlock;
    }

success:
    spin_unlock(&rpage->lock);

    return VM_FAULT_NOPAGE;

out_unlock:
    spin_unlock(&rpage->lock);
out:

    return VM_FAULT_ERROR;
}
