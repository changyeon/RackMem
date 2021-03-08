#ifndef _INCLUDE_RACK_VM_H_
#define _INCLUDE_RACK_VM_H_

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <rack_dvs.h>

enum rack_vm_page_state {
    RACK_VM_PAGE_IDLE           = 0x000001,
    RACK_VM_PAGE_ACTIVE         = 0x000002,
    RACK_VM_PAGE_INACTIVE       = 0x000004,
    RACK_VM_PAGE_PREFETCH       = 0x000008,
    RACK_VM_PAGE_EARLY_FREE     = 0x000010,
    RACK_VM_PAGE_REMOTE         = 0x000020,
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
    u64 total_pages;
    u64 active_pages;
    u64 local_pages_limit;
    u64 local_pages;

    struct rack_vm_page *pages;
    struct rack_vm_page_list active_list;
    struct rack_vm_page_list inactive_list;

    struct dvs_region *dvsr;
    struct vm_area_struct *vma;
    spinlock_t lock;
};

int rack_vm_mmap(struct file *fp, struct vm_area_struct *vma);
void rack_vm_page_list_add(struct rack_vm_page_list *page_list, struct rack_vm_page *rpage);
void rack_vm_page_list_del(struct rack_vm_page_list *page_list, struct rack_vm_page *rpage);
struct rack_vm_page *rack_vm_page_list_pop(struct rack_vm_page_list *page_list);
int rack_vm_page_list_size(struct rack_vm_page_list *page_list);
struct rack_vm_region *rack_vm_alloc_region(u64 size_bytes, u64 page_size, u64 slab_size_bytes);
void rack_vm_free_region(struct rack_vm_region *region);

#endif /* _INCLUDE_RACK_VM_H_ */
