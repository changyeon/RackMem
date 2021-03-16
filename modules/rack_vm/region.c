#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <rack_vm.h>

extern int g_debug;

#define DEBUG_LOG if (g_debug) pr_info

static void rack_vm_page_list_init(struct rack_vm_page_list *page_list)
{
    INIT_LIST_HEAD(&page_list->head);
    page_list->size = 0;
    spin_lock_init(&page_list->lock);
}

void rack_vm_page_list_add(struct rack_vm_page_list *page_list,
                                  struct rack_vm_page *rpage)
{
    spin_lock(&page_list->lock);
    list_add_tail(&rpage->head, &page_list->head);
    page_list->size++;
    DEBUG_LOG("page_list_add %p %d\n", page_list, page_list->size);
    spin_unlock(&page_list->lock);
}

void rack_vm_page_list_del(struct rack_vm_page_list *page_list,
                                  struct rack_vm_page *rpage)
{
    spin_lock(&page_list->lock);
    list_del_init(&rpage->head);
    page_list->size--;
    DEBUG_LOG("page_list_del %p %d\n", page_list, page_list->size);
    spin_unlock(&page_list->lock);
}

struct rack_vm_page *rack_vm_page_list_pop(struct rack_vm_page_list *page_list)
{
    struct rack_vm_page *rpage;

    spin_lock(&page_list->lock);
    if (list_empty(&page_list->head)) {
        spin_unlock(&page_list->lock);
        goto out;
    }
    rpage = list_first_entry(&page_list->head, struct rack_vm_page, head);
    list_del_init(&rpage->head);
    page_list->size--;

    spin_unlock(&page_list->lock);

    return rpage;

out:
    return NULL;
}

int rack_vm_page_list_size(struct rack_vm_page_list *page_list)
{
    int size;

    spin_lock(&page_list->lock);
    size = page_list->size;
    spin_unlock(&page_list->lock);

    return size;
}

int rack_vm_remap(struct rack_vm_region *region, struct rack_vm_page *rpage,
                  u64 fault_address, u64 page_size)
{
    int ret;

    DEBUG_LOG("rack_vm_remap region: %p, pg_index: %llu\n", region,
              rpage->index);

    ret = remap_vmalloc_range_partial(
            region->vma, fault_address, rpage->buf, page_size);
    if (ret) {
        pr_err("error on remap_vmalloc_range_partial: %d\n", ret);
        goto out;
    }

    rpage->flags = RACK_VM_PAGE_ACTIVE;
    rack_vm_page_list_add(&region->active_list, rpage);

    return 0;

out:
    return ret;
}

int rack_vm_restore(struct rack_vm_region *region, struct rack_vm_page *rpage)
{
    int ret;

    DEBUG_LOG("rack_vm_restore region: %p, pg_index: %llu\n", region,
              rpage->index);

    ret = rack_dvs_read(region->dvsr, rpage->index * region->page_size,
                        region->page_size, rpage->buf);
    if (ret) {
        pr_err("error on rack_dvs_read: %d\n", ret);
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

    DEBUG_LOG("rack_vm_writeback region: %p, pg_index: %llu\n", region,
              rpage->index);

    ret = rack_dvs_write(region->dvsr, rpage->index * region->page_size,
                         region->page_size, rpage->buf);
    if (ret) {
        pr_err("error on rack_dvs_write: %d\n", ret);
        goto out;
    }

    return 0;

out:
    return ret;
}

void rack_vm_unmap(struct rack_vm_region *region, struct rack_vm_page *rpage)
{
    DEBUG_LOG("rack_vm_unmap region: %p, pg_index: %llu\n", region,
              rpage->index);

    zap_page_range(region->vma,
                   region->vma->vm_start + rpage->index * region->page_size,
                   region->page_size);
    rpage->flags = RACK_VM_PAGE_INACTIVE;
}

void *rack_vm_reclaim_active(struct rack_vm_region *region)
{
    int ret;
    void *buf = NULL;
    struct rack_vm_page *rpage;

    rpage = rack_vm_page_list_pop(&region->active_list);

    if (rpage == NULL) {
        pr_err("failed to reclaim a page from active_list\n");
        rpage->flags = RACK_VM_PAGE_ERROR;
        goto out;
    }

    spin_lock(&rpage->lock);
    rack_vm_unmap(region, rpage);

    ret = rack_vm_writeback(region, rpage);
    if (ret) {
        pr_err("error on rack_vm_writeback: %p\n", rpage);
        rpage->flags = RACK_VM_PAGE_ERROR;
        spin_unlock(&rpage->lock);
        goto out;
    }
    buf = rpage->buf;
    rpage->buf = NULL;
    rpage->flags = RACK_VM_PAGE_NOT_PRESENT;
    spin_unlock(&rpage->lock);

    return buf;

out:
    return NULL;
}

void *rack_vm_reclaim_inactive(struct rack_vm_region *region)
{
    int ret;
    void *buf = NULL;
    struct rack_vm_page *rpage;

    rpage = rack_vm_page_list_pop(&region->inactive_list);

    if (rpage) {
        spin_lock(&rpage->lock);
        if (likely(rpage->flags & RACK_VM_PAGE_INACTIVE)) {
            ret = rack_vm_writeback(region, rpage);
            if (ret) {
                pr_err("error on rack_vm_writeback: %p\n", rpage);
                rpage->flags = RACK_VM_PAGE_ERROR;
                goto out;
            }
            buf = rpage->buf;
            rpage->buf = NULL;
            rpage->flags = RACK_VM_PAGE_NOT_PRESENT;
        } else {
            /* this page may be in ACTIVE state if this page is touched
             * by another thread before we get the lock */
        }
        spin_unlock(&rpage->lock);
    }

out:
    return buf;
}

void *rack_vm_alloc_buf(struct rack_vm_region *region)
{
    void *buf = NULL;
    s64 page_count_limit = atomic64_read(&region->page_count_limit);
    s64 page_count = atomic64_fetch_add(1, &region->page_count);

    if (page_count >= page_count_limit) {
        atomic64_dec(&region->page_count);
        goto out;
    }

    buf = vmalloc_user(region->page_size);
    if (buf == NULL) {
        pr_err("error on vmalloc_user\n");
        goto out;
    }

    return buf;

out:
    return NULL;
}

struct rack_vm_region *rack_vm_alloc_region(u64 size_bytes, u64 page_size,
                                            u64 slab_size_bytes)
{
    u64 i, total_size_bytes;
    struct rack_vm_region *region = NULL;
    struct rack_dvs_region *dvsr;

    DEBUG_LOG("rack_vm_alloc_region size_bytes: %llu, page_size: %llu "
              "slab_size_bytes: %llu\n", size_bytes, page_size,
              slab_size_bytes);

    total_size_bytes = (size_bytes / slab_size_bytes) * slab_size_bytes;
    if (size_bytes % slab_size_bytes) {
        total_size_bytes += slab_size_bytes;
        pr_info("round up the region size %llu -> %llu\n", size_bytes,
                total_size_bytes);
    }

    if (total_size_bytes % page_size) {
        pr_err("the total_size_bytes is not multiple of page_size (%llu,%llu)\n",
               total_size_bytes, page_size);
        goto out;
    }

    if (slab_size_bytes % MB) {
        pr_err("the slab size is not multiple of MB: %llu\n", slab_size_bytes);
        goto out;
    }

    dvsr = rack_dvs_alloc_region(total_size_bytes / MB, slab_size_bytes / MB);
    if (dvsr == NULL) {
        pr_err("error on dvs_alloc_region\n");
        goto out;
    }

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (region == NULL) {
        pr_err("failed to allocate memory for struct rack_vm_region\n");
        goto out_rack_dvs_free_region;
    }

    region->size = total_size_bytes;
    region->page_size = page_size;
    region->max_pages = total_size_bytes / page_size;

    /* FIXME */
    atomic64_set(&region->page_count_limit, 65536);
    atomic64_set(&region->page_count, 0);

    region->pages = vzalloc(region->max_pages * sizeof(struct rack_vm_page));
    if (region->pages == NULL) {
        pr_err("failed to allocate memory for region->pages\n");
        goto out_kfree_region;
    }
    for (i = 0; i < region->max_pages; i++) {
        region->pages[i].index = i;
        spin_lock_init(&region->pages[i].lock);
    }
    rack_vm_page_list_init(&region->active_list);
    rack_vm_page_list_init(&region->inactive_list);
    region->dvsr = dvsr;
    spin_lock_init(&region->lock);

    return region;

out_kfree_region:
    kfree(region);
out_rack_dvs_free_region:
    rack_dvs_free_region(dvsr);
out:
    return NULL;
}

void rack_vm_free_region(struct rack_vm_region *region)
{
    DEBUG_LOG("rack_vm_free_region %p\n", region);

    if (region->dvsr)
        rack_dvs_free_region(region->dvsr);
    vfree(region->pages);
    kfree(region);
};
