#ifndef _INCLUDE_RACK_DM_H_
#define _INCLUDE_RACK_DM_H_

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <linux/atomic.h>
#include <linux/percpu-defs.h>
#include <linux/debugfs.h>
#include <krdma.h>

#define count_event(region, event) \
    this_cpu_inc(region->stat->count[event])

enum rack_dm_event {
    RACK_DM_EVENT_PGFAULT,
    RACK_DM_EVENT_PGFAULT_READ,
    RACK_DM_EVENT_PGFAULT_WRITE,
    RACK_DM_EVENT_PGFAULT_COLLISION,
    RACK_DM_EVENT_PGFAULT_INACTIVE,
    RACK_DM_EVENT_RDMA_READ,
    RACK_DM_EVENT_RDMA_WRITE,
    RACK_DM_EVENT_ALLOC_LOCAL_PAGE,
    RACK_DM_EVENT_FREE_LOCAL_PAGE,
    RACK_DM_EVENT_ALLOC_REMOTE_PAGE,
    RACK_DM_EVENT_FREE_REMOTE_PAGE,
    RACK_DM_EVENT_RECLAIM_INACTIVE,
    RACK_DM_EVENT_RECLAIM_INACTIVE_MISS,
    RACK_DM_EVENT_RECLAIM_ACTIVE,
    RACK_DM_EVENT_REMAP,
    RACK_DM_EVENT_UNMAP,
    __NR_RACK_DM_EVENTS
};

struct rack_dm_event_count {
    u64 count[__NR_RACK_DM_EVENTS];
};

static const char * const rack_dm_events[] = {
    [RACK_DM_EVENT_PGFAULT]                 = "pgfault",
    [RACK_DM_EVENT_PGFAULT_READ]            = "pgfault_read",
    [RACK_DM_EVENT_PGFAULT_WRITE]           = "pgfualt_write",
    [RACK_DM_EVENT_PGFAULT_COLLISION]       = "pgfault_collision",
    [RACK_DM_EVENT_PGFAULT_INACTIVE]        = "pgfault_inactive",
    [RACK_DM_EVENT_RDMA_READ]               = "rdma_read",
    [RACK_DM_EVENT_RDMA_WRITE]              = "rdma_write",
    [RACK_DM_EVENT_ALLOC_LOCAL_PAGE]        = "alloc_local_page",
    [RACK_DM_EVENT_FREE_LOCAL_PAGE]         = "free_local_page",
    [RACK_DM_EVENT_ALLOC_REMOTE_PAGE]       = "alloc_remote_page",
    [RACK_DM_EVENT_FREE_REMOTE_PAGE]        = "free_remote_page",
    [RACK_DM_EVENT_RECLAIM_INACTIVE]        = "reclaim_inactive",
    [RACK_DM_EVENT_RECLAIM_INACTIVE_MISS]   = "reclaim_inactive_miss",
    [RACK_DM_EVENT_RECLAIM_ACTIVE]          = "reclaim_active",
    [RACK_DM_EVENT_REMAP]                   = "remap",
    [RACK_DM_EVENT_UNMAP]                   = "unmap",
};

enum rack_dm_page_state {
    RACK_DM_PAGE_IDLE                       = 0x000001,
    RACK_DM_PAGE_ACTIVE                     = 0x000002,
    RACK_DM_PAGE_INACTIVE                   = 0x000004,
    RACK_DM_PAGE_NOT_PRESENT                = 0x000008,
    RACK_DM_PAGE_PREFETCH                   = 0x000010,
    RACK_DM_PAGE_EARLY_FREE                 = 0x000020,
    RACK_DM_PAGE_ERROR                      = 0x000040
};

struct rack_dm_page_list {
    int size;
    struct list_head head;
    spinlock_t lock;
};

struct remote_page {
    struct krdma_conn *conn;
    u64 remote_paddr;
    u64 remote_vaddr;
};

struct rack_dm_page {
    int flags;
    u64 index;
    void *buf;
    struct remote_page *remote_page;
    struct list_head head;
    spinlock_t lock;
};

struct rack_dm_region {
    bool persistent;
    u64 rid;
    u64 pid;
    u64 size;
    u64 page_size;
    u64 max_pages;
    atomic64_t page_count_limit;
    atomic64_t page_count;

    struct rack_dm_page *pages;
    struct rack_dm_page_list active_list;
    struct rack_dm_page_list inactive_list;

    struct vm_area_struct *vma;
    struct rack_dm_event_count __percpu *stat;

    struct dentry *dbgfs_root;
    struct dentry *dbgfs_stat;

    spinlock_t lock;
};

int rack_dm_mmap(struct file *fp, struct vm_area_struct *vma);

/* virtual memory */
void rack_dm_page_list_add(struct rack_dm_page_list *page_list, struct rack_dm_page *rpage);
void rack_dm_page_list_del(struct rack_dm_page_list *page_list, struct rack_dm_page *rpage);
struct rack_dm_page *rack_dm_page_list_pop(struct rack_dm_page_list *page_list);
int rack_dm_page_list_size(struct rack_dm_page_list *page_list);
int rack_dm_remap(struct rack_dm_region *region, struct rack_dm_page *rpage, u64 fault_address, u64 page_size);
int rack_dm_restore(struct rack_dm_region *region, struct rack_dm_page *rpage);
int rack_dm_writeback(struct rack_dm_region *region, struct rack_dm_page *rpage);
void rack_dm_unmap(struct rack_dm_region *region, struct rack_dm_page *rpage);
void *rack_dm_reclaim_active(struct rack_dm_region *region);
void *rack_dm_reclaim_inactive(struct rack_dm_region *region);
void *rack_dm_alloc_buf(struct rack_dm_region *region);
int rack_dm_map_region(struct rack_dm_region *region, struct vm_area_struct *vma, struct vm_operations_struct *vm_ops);
struct rack_dm_region *rack_dm_alloc_region(u64 size_bytes, u64 page_size);
void rack_dm_free_region(struct rack_dm_region *region);
void rack_dm_migrate_clean_up_region(struct rack_dm_region *region);
int rack_dm_rdma(struct krdma_conn *conn, u64 local_dma_addr, u64 remote_dma_addr, u64 size, int dir);

/* remote memory */
int alloc_remote_user_page(struct rack_dm_page *rpage, u64 page_size);
int free_remote_user_page(struct krdma_conn *conn, u64 size, u64 remote_vaddr, u64 remote_paddr);
int update_rdma_node_list(void);
void free_rdma_node_list(void);

/* rpc */
int rack_dm_setup_rpc(void);
void rack_dm_cleanup_rpc(void);
int get_region_metadata(struct krdma_conn *conn, struct rack_dm_region *region, u64 remote_region_id);
int migrate_clean_up(struct krdma_conn *conn, u64 remote_region_id);

#endif /* _INCLUDE_RACK_DM_H_ */
