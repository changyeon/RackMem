#ifndef _INCLUDE_RACK_VM_H_
#define _INCLUDE_RACK_VM_H_

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <linux/atomic.h>
#include <rack_dvs.h>

enum rack_vm_page_state {
    RACK_VM_PAGE_IDLE           = 0x000001,
    RACK_VM_PAGE_ACTIVE         = 0x000002,
    RACK_VM_PAGE_INACTIVE       = 0x000004,
    RACK_VM_PAGE_NOT_PRESENT    = 0x000008,
    RACK_VM_PAGE_PREFETCH       = 0x000010,
    RACK_VM_PAGE_EARLY_FREE     = 0x000020,
    RACK_VM_PAGE_ERROR          = 0x000040
};

struct rack_vm_page_list {
    struct list_head head;
    int size;
    spinlock_t lock;
};

struct rack_vm_page {
    int flags;
    struct list_head head;
    u64 index;
    u32 hotness;
    u32 prefetch_hint;
    u64 active;
    void *buf;
    spinlock_t lock;
};

struct rack_vm_region {
    u64 size;
    u64 page_size;
    u64 max_pages;
    atomic64_t page_count_limit;
    atomic64_t page_count;

    struct rack_vm_page *pages;
    struct rack_vm_page_list active_list;
    struct rack_vm_page_list inactive_list;

    struct dvs_region *dvsr;
    struct vm_area_struct *vma;
    spinlock_t lock;
};

int rack_vm_mmap(struct file *fp, struct vm_area_struct *vma);

/* virtual memory */
void rack_vm_page_list_add(struct rack_vm_page_list *page_list, struct rack_vm_page *rpage);
void rack_vm_page_list_del(struct rack_vm_page_list *page_list, struct rack_vm_page *rpage);
struct rack_vm_page *rack_vm_page_list_pop(struct rack_vm_page_list *page_list);
int rack_vm_page_list_size(struct rack_vm_page_list *page_list);
int rack_vm_remap(struct rack_vm_region *region, struct rack_vm_page *rpage, u64 fault_address, u64 page_size);
int rack_vm_restore(struct rack_vm_region *region, struct rack_vm_page *rpage);
int rack_vm_writeback(struct rack_vm_region *region, struct rack_vm_page *rpage);
void rack_vm_unmap(struct rack_vm_region *region, struct rack_vm_page *rpage);
void *rack_vm_reclaim_active(struct rack_vm_region *region);
void *rack_vm_reclaim_inactive(struct rack_vm_region *region);
void *rack_vm_alloc_buf(struct rack_vm_region *region);
struct rack_vm_region *rack_vm_alloc_region(u64 size_bytes, u64 page_size, u64 slab_size_bytes);
void rack_vm_free_region(struct rack_vm_region *region);

#endif /* _INCLUDE_RACK_VM_H_ */
