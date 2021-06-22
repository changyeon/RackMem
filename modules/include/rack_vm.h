#ifndef _INCLUDE_RACK_VM_H_
#define _INCLUDE_RACK_VM_H_

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <linux/atomic.h>
#include <linux/percpu-defs.h>
#include <linux/dcache.h>
#include <linux/workqueue.h>
#include <rack_dvs.h>

#define count_event(region, event) \
    this_cpu_inc(region->stat->count[event])

enum rack_vm_event {
    RACK_VM_EVENT_PGFAULT,
    RACK_VM_EVENT_PGFAULT_READ,
    RACK_VM_EVENT_PGFAULT_WRITE,
    RACK_VM_EVENT_PGFAULT_COLLISION,
    RACK_VM_EVENT_PGFAULT_INACTIVE,
    RACK_VM_EVENT_RECLAIM_FAST,
    RACK_VM_EVENT_RECLAIM_SLOW,
    RACK_VM_EVENT_BG_RECLAIM_TASK,
    RACK_VM_EVENT_BG_RECLAIM,
    RACK_VM_EVENT_IO_READ,
    RACK_VM_EVENT_IO_WRITE,
    RACK_VM_EVENT_ALLOC_LOCAL_PAGE,
    RACK_VM_EVENT_FREE_LOCAL_PAGE,
    RACK_VM_EVENT_RECLAIM_INACTIVE,
    RACK_VM_EVENT_RECLAIM_INACTIVE_MISS,
    RACK_VM_EVENT_RECLAIM_ACTIVE,
    RACK_VM_EVENT_REMAP,
    RACK_VM_EVENT_UNMAP,
    __NR_RACK_VM_EVENTS
};

struct rack_vm_event_count {
    u64 count[__NR_RACK_VM_EVENTS];
};

static const char * const rack_vm_events[] = {
    [RACK_VM_EVENT_PGFAULT]                 = "pgfault",
    [RACK_VM_EVENT_PGFAULT_READ]            = "pgfault_read",
    [RACK_VM_EVENT_PGFAULT_WRITE]           = "pgfualt_write",
    [RACK_VM_EVENT_PGFAULT_COLLISION]       = "pgfault_collision",
    [RACK_VM_EVENT_PGFAULT_INACTIVE]        = "pgfault_inactive",
    [RACK_VM_EVENT_RECLAIM_FAST]            = "reclaim_fast",
    [RACK_VM_EVENT_RECLAIM_SLOW]            = "reclaim_slow",
    [RACK_VM_EVENT_BG_RECLAIM_TASK]         = "background_reclaim_task",
    [RACK_VM_EVENT_BG_RECLAIM]              = "background_reclaim",
    [RACK_VM_EVENT_IO_READ]                 = "io_read",
    [RACK_VM_EVENT_IO_WRITE]                = "io_write",
    [RACK_VM_EVENT_ALLOC_LOCAL_PAGE]        = "alloc_local_page",
    [RACK_VM_EVENT_FREE_LOCAL_PAGE]         = "free_local_page",
    [RACK_VM_EVENT_RECLAIM_INACTIVE]        = "reclaim_inactive",
    [RACK_VM_EVENT_RECLAIM_INACTIVE_MISS]   = "reclaim_inactive_miss",
    [RACK_VM_EVENT_RECLAIM_ACTIVE]          = "reclaim_active",
    [RACK_VM_EVENT_REMAP]                   = "remap",
    [RACK_VM_EVENT_UNMAP]                   = "unmap",
};

enum rack_vm_page_state {
    RACK_VM_PAGE_IDLE                       = 0x000001,
    RACK_VM_PAGE_ACTIVE                     = 0x000002,
    RACK_VM_PAGE_INACTIVE                   = 0x000004,
    RACK_VM_PAGE_NOT_PRESENT                = 0x000008,
    RACK_VM_PAGE_PREFETCH                   = 0x000010,
    RACK_VM_PAGE_EARLY_FREE                 = 0x000020,
    RACK_VM_PAGE_ERROR                      = 0x000040
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

struct rack_vm_work {
    struct work_struct ws;
    struct rack_vm_region *region;
};

struct rack_vm_region {
    u64 pid;
    u64 size;
    u64 page_size;
    u64 max_pages;
    atomic64_t page_count_limit;
    atomic64_t page_count;
    bool full;

    struct rack_vm_page *pages;
    struct rack_vm_page_list active_list;
    struct rack_vm_page_list inactive_list;

    struct rack_dvs_region *dvsr;

    struct rack_vm_work reclaim_work;

    struct vm_area_struct *vma;
    struct rack_vm_event_count __percpu *stat;

    struct dentry *dbgfs_root;
    struct dentry *dbgfs_stat;
    struct dentry *dbgfs_mem_limit;

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
int rack_vm_map_region(struct rack_vm_region *region, struct vm_area_struct *vma, struct vm_operations_struct *vm_ops);
struct rack_vm_region *rack_vm_alloc_region(u64 size_bytes, u64 page_size, u64 slab_size_bytes);
void rack_vm_free_region(struct rack_vm_region *region);

#endif /* _INCLUDE_RACK_VM_H_ */
