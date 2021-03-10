#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
    spin_unlock(&page_list->lock);
}

void rack_vm_page_list_del(struct rack_vm_page_list *page_list,
                                  struct rack_vm_page *rpage)
{
    spin_lock(&page_list->lock);
    list_del_init(&rpage->head);
    page_list->size--;
    spin_unlock(&page_list->lock);
}

struct rack_vm_page *rack_vm_page_list_pop(struct rack_vm_page_list *page_list)
{
    struct rack_vm_page *rpage;

    spin_lock(&page_list->lock);
    if (list_empty(&page_list->head)) {
        pr_err("rack_vm_page_list is empty: %p\n", page_list);
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

struct rack_vm_region *rack_vm_alloc_region(u64 size_bytes, u64 page_size,
                                            u64 slab_size_bytes)
{
    u64 total_size_bytes;
    struct rack_vm_region *region = NULL;
    struct dvs_region *dvsr;

    DEBUG_LOG("rack_vm_alloc_region size_bytes: %llu, page_size: %llu "
              "slab_size_bytes: %llu\n", size_bytes, page_size,
              slab_size_bytes);

    total_size_bytes = (size_bytes / slab_size_bytes) * slab_size_bytes;
    if (size_bytes % slab_size_bytes) {
        total_size_bytes += total_size_bytes;
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

    dvsr = dvs_alloc_region(total_size_bytes / MB, slab_size_bytes / MB);
    if (dvsr == NULL) {
        pr_err("error on dvs_alloc_region\n");
        goto out;
    }

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (region == NULL) {
        pr_err("failed to allocate memory for struct rack_vm_region\n");
        goto out_dvs_free_region;
    }

    region->size = total_size_bytes;
    region->page_size = page_size;
    region->total_pages = total_size_bytes / page_size;
    region->active_pages = 0;
    region->local_pages_limit = 65536; /* FIXME */
    region->local_pages = 0;

    region->pages = vzalloc(region->total_pages * sizeof(struct rack_vm_page));
    if (region->pages == NULL) {
        pr_err("failed to allocate memory for region->pages\n");
        goto out_kfree_region;
    }
    rack_vm_page_list_init(&region->active_list);
    rack_vm_page_list_init(&region->inactive_list);
    region->dvsr = dvsr;
    spin_lock_init(&region->lock);

    return region;

out_kfree_region:
    kfree(region);
out_dvs_free_region:
    dvs_free_region(dvsr);
out:
    return NULL;
}

void rack_vm_free_region(struct rack_vm_region *region)
{
    DEBUG_LOG("rack_vm_free_region %p\n", region);

    if (region->dvsr)
        dvs_free_region(region->dvsr);
    vfree(region->pages);
    kfree(region);
};
