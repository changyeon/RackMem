#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <rack_dm.h>

extern int g_debug;
extern int g_local_pages;

#define DEBUG_LOG if (g_debug) pr_info

static void rack_dm_page_list_init(struct rack_dm_page_list *page_list)
{
    INIT_LIST_HEAD(&page_list->head);
    page_list->size = 0;
    spin_lock_init(&page_list->lock);
}

void rack_dm_page_list_add(struct rack_dm_page_list *page_list,
                           struct rack_dm_page *rpage)
{
    spin_lock(&page_list->lock);
    list_add_tail(&rpage->head, &page_list->head);
    page_list->size++;
    DEBUG_LOG("page_list_add %p %d\n", page_list, page_list->size);
    spin_unlock(&page_list->lock);
}

void rack_dm_page_list_del(struct rack_dm_page_list *page_list,
                           struct rack_dm_page *rpage)
{
    spin_lock(&page_list->lock);
    list_del_init(&rpage->head);
    page_list->size--;
    DEBUG_LOG("page_list_del %p %d\n", page_list, page_list->size);
    spin_unlock(&page_list->lock);
}

struct rack_dm_page *rack_dm_page_list_pop(struct rack_dm_page_list *page_list)
{
    struct rack_dm_page *rpage;

    spin_lock(&page_list->lock);
    if (list_empty(&page_list->head)) {
        spin_unlock(&page_list->lock);
        goto out;
    }
    rpage = list_first_entry(&page_list->head, struct rack_dm_page, head);
    list_del_init(&rpage->head);
    page_list->size--;
    spin_unlock(&page_list->lock);

    return rpage;

out:
    return NULL;
}

int rack_dm_page_list_size(struct rack_dm_page_list *page_list)
{
    int size;

    spin_lock(&page_list->lock);
    size = page_list->size;
    spin_unlock(&page_list->lock);

    return size;
}

static void rack_dm_print_statistics(struct rack_dm_region *region)
{
    int i, cpu;
    u64 sum[__NR_RACK_DM_EVENTS];

    memset(sum, 0, sizeof(sum));
    for_each_online_cpu(cpu)
        for (i = 0; i < __NR_RACK_DM_EVENTS; i++)
            sum[i] += per_cpu(region->stat->count[i], cpu);

    for (i = 0; i < __NR_RACK_DM_EVENTS; i++)
        pr_info("statistics (%p) %s: %llu\n", region, rack_dm_events[i],
                sum[i]);
}

int rack_dm_remap(struct rack_dm_region *region, struct rack_dm_page *rpage,
                  u64 fault_address, u64 page_size)
{
    int ret;

    DEBUG_LOG("rack_dm_remap region: %p, pg_index: %llu\n", region,
              rpage->index);

    ret = remap_vmalloc_range_partial(
            region->vma, fault_address, rpage->buf, page_size);
    if (ret) {
        pr_err("error on remap_vmalloc_range_partial: %d\n", ret);
        goto out;
    }

    rpage->flags = RACK_DM_PAGE_ACTIVE;
    rack_dm_page_list_add(&region->active_list, rpage);

    count_event(region, RACK_DM_EVENT_REMAP);

    return 0;

out:
    return ret;
}

int rack_dm_rdma(struct krdma_conn *conn, u64 local_dma_addr,
                 u64 remote_dma_addr, u64 size, int dir)
{
    int ret = 0;
    u64 completion;
    struct ib_rdma_wr wr;
    struct ib_sge sgl;
    const struct ib_send_wr *bad_send_wr = NULL;

    memset(&wr, 0, sizeof(wr));
    memset(&sgl, 0, sizeof(sgl));

    sgl.addr = local_dma_addr;
    sgl.lkey = conn->lkey;
    sgl.length = size;

    wr.remote_addr = remote_dma_addr;
    wr.rkey = conn->remote_rkey;

    wr.wr.next = NULL;
    wr.wr.wr_id = (u64) &completion;
    wr.wr.sg_list = &sgl;
    wr.wr.num_sge = 1;
    wr.wr.opcode = dir == WRITE ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
    wr.wr.send_flags = IB_SEND_SIGNALED;

    completion = 0;
    ret = ib_post_send(conn->rdma_qp.qp, &wr.wr, &bad_send_wr);
    if (ret) {
        pr_err("error on ib_post_send\n");
        goto out;
    }

    ret = krdma_poll_completion(conn->rdma_qp.cq, &completion);
    if (ret) {
        pr_err("error on krdma_poll_cq\n");
        goto out;
    }

    return 0;

out:
    return ret;
}

int rack_dm_restore(struct rack_dm_region *region, struct rack_dm_page *rpage)
{
    int ret;
    u64 local_dma_addr;

    DEBUG_LOG("rack_dm_restore region: %p, pg_index: %llu\n", region,
              rpage->index);

    if (rpage->remote_page == NULL) {
        pr_err("Weird! This message should not be printed!");
        ret = -EINVAL;
        goto out;
    }

    local_dma_addr = ib_dma_map_page(
            rpage->remote_page->conn->cm_id->device,
            vmalloc_to_page(rpage->buf), 0, region->page_size,
            DMA_BIDIRECTIONAL);

    ret = rack_dm_rdma(
            rpage->remote_page->conn, local_dma_addr,
            rpage->remote_page->remote_paddr, region->page_size, READ);
    if (ret) {
        pr_err("error on read_remote_page\n");
        goto out;
    }

    ib_dma_unmap_page(
            rpage->remote_page->conn->cm_id->device,
            local_dma_addr, region->page_size, DMA_BIDIRECTIONAL);

    count_event(region, RACK_DM_EVENT_RDMA_READ);

    return 0;

out:
    return ret;
}

int rack_dm_writeback(struct rack_dm_region *region, struct rack_dm_page *rpage)
{
    int ret;
    u64 local_dma_addr;

    DEBUG_LOG("rack_dm_writeback region: %p, pg_index: %llu\n", region,
              rpage->index);

    if (rpage->remote_page == NULL) {
        ret = alloc_remote_user_page(region, rpage, NULL);
        if (ret) {
            pr_err("error on alloc_remote_page\n");
            goto out;
        }
    }

    if (rpage->remote_page == NULL) {
        pr_err("failed to allocate a remote_page\n");
        ret = -ENOMEM;
        goto out;
    }

    local_dma_addr = ib_dma_map_page(
            rpage->remote_page->conn->cm_id->device,
            vmalloc_to_page(rpage->buf), 0, region->page_size,
            DMA_BIDIRECTIONAL);

    ret = rack_dm_rdma(
            rpage->remote_page->conn, local_dma_addr,
            rpage->remote_page->remote_paddr, region->page_size, WRITE);
    if (ret) {
        pr_err("error on write_remote_page\n");
        goto out;
    }

    ib_dma_unmap_page(
            rpage->remote_page->conn->cm_id->device,
            local_dma_addr, region->page_size, DMA_BIDIRECTIONAL);

    count_event(region, RACK_DM_EVENT_RDMA_WRITE);

    return 0;

out:
    return ret;
}

void rack_dm_unmap(struct rack_dm_region *region, struct rack_dm_page *rpage)
{
    DEBUG_LOG("rack_dm_unmap region: %p, pg_index: %llu\n", region,
              rpage->index);

    zap_page_range(region->vma,
                   region->vma->vm_start + rpage->index * region->page_size,
                   region->page_size);
    rpage->flags = RACK_DM_PAGE_INACTIVE;

    count_event(region, RACK_DM_EVENT_UNMAP);
}

void *rack_dm_reclaim_active(struct rack_dm_region *region)
{
    int ret;
    void *buf = NULL;
    struct rack_dm_page *rpage;

    rpage = rack_dm_page_list_pop(&region->active_list);

    if (rpage == NULL) {
        pr_err("failed to reclaim a page from active_list\n");
        goto out;
    }

    spin_lock(&rpage->lock);
    rack_dm_unmap(region, rpage);

    ret = rack_dm_writeback(region, rpage);
    if (ret) {
        pr_err("error on rack_dm_writeback: %p\n", rpage);
        rpage->flags = RACK_DM_PAGE_ERROR;
        spin_unlock(&rpage->lock);
        goto out;
    }
    buf = rpage->buf;
    rpage->buf = NULL;
    rpage->flags = RACK_DM_PAGE_NOT_PRESENT;
    spin_unlock(&rpage->lock);

    count_event(region, RACK_DM_EVENT_RECLAIM_ACTIVE);

    return buf;

out:
    return NULL;
}

void *rack_dm_reclaim_inactive(struct rack_dm_region *region)
{
    void *buf = NULL;
    struct rack_dm_page *rpage;

    rpage = rack_dm_page_list_pop(&region->inactive_list);

    if (rpage) {
        spin_lock(&rpage->lock);
        if (likely(rpage->flags & RACK_DM_PAGE_INACTIVE)) {
            count_event(region, RACK_DM_EVENT_RECLAIM_INACTIVE);
            buf = rpage->buf;
            rpage->buf = NULL;
            rpage->flags = RACK_DM_PAGE_NOT_PRESENT;
        } else {
            /*
             * This page may be in ACTIVE state if the page is touched by
             * another thread before we get the lock.
             * In this case, the inactive_list size is decreased twice by this
             * function and the pagefault handler.
             * To make the size correct, we increment size by 1 here.
             */
            spin_lock(&region->inactive_list.lock);
            region->inactive_list.size++;
            spin_unlock(&region->inactive_list.lock);
            count_event(region, RACK_DM_EVENT_RECLAIM_INACTIVE_MISS);
        }
        spin_unlock(&rpage->lock);
    }

    return buf;
}

void *rack_dm_alloc_buf(struct rack_dm_region *region)
{
    void *buf = NULL;
    s64 page_count_limit = atomic64_read(&region->page_count_limit);
    s64 page_count = atomic64_fetch_add(1, &region->page_count);

    if (page_count >= page_count_limit) {
        atomic64_dec(&region->page_count);
        region->full = true;
        goto out;
    }

    buf = vmalloc_user(region->page_size);
    if (buf == NULL) {
        pr_err("error on vmalloc_user\n");
        goto out;
    }
    count_event(region, RACK_DM_EVENT_ALLOC_LOCAL_PAGE);

    return buf;

out:
    return NULL;
}

static int write_region_id(struct rack_dm_region *region)
{
    int ret;
    struct rack_dm_page *rpage = NULL;
    void *buf = NULL;

    rpage = &region->pages[0];

    rpage->buf = rack_dm_alloc_buf(region);
    if (rpage->buf == NULL) {
        pr_err("error on rack_dm_alloc_buf\n");
        ret = -ENOMEM;
        goto out;
    }

    *((u64 *) rpage->buf) = region->rid;
    krdma_local_node_name((char *) ((u64) rpage->buf + sizeof(u64)));

    DEBUG_LOG("write_region_id id: %llu, node_name: %s\n",
              *((u64 *) rpage->buf),
              (char *) ((u64) rpage->buf + sizeof(u64)));

    ret = rack_dm_remap(region, rpage, region->vma->vm_start,
                        region->page_size);
    if (ret) {
        pr_err("failed to remap the page\n");
        goto out_free_buf;
    }

    return 0;

out_free_buf:
    atomic64_dec(&region->page_count);
    vfree(buf);
out:
    return ret;
}

int rack_dm_map_region(struct rack_dm_region *region,
                       struct vm_area_struct *vma,
                       struct vm_operations_struct *vm_ops)
{
    int ret;

    region->vma = vma;
    region->pid = (u64) region->vma->vm_mm->owner->pid;

    vma->vm_private_data = (void *) region;
    vma->vm_ops = vm_ops;
    vma->vm_flags |= VM_MIXEDMAP;

    ret = write_region_id(region);
    if (ret) {
        pr_err("error on write_region_id\n");
        goto out;
    }

    return 0;

out:
    return ret;
}

static void reclaim_active_pages(struct work_struct *ws)
{
    struct rack_dm_work *work;
    struct rack_dm_region *region;
    int i, ret;
    struct rack_dm_page *rpage;

    work = container_of(ws, struct rack_dm_work, ws);
    region = work->region;

    count_event(region, RACK_DM_EVENT_BG_RECLAIM_TASK);

    for (i = 0; i < 16384; i++) {
        rpage = rack_dm_page_list_pop(&region->active_list);
        if (rpage == NULL) {
            pr_err("failed to reclaim a page from active_list\n");
            break;
        }
        spin_lock(&rpage->lock);
        rack_dm_unmap(region, rpage);
        ret = rack_dm_writeback(region, rpage);
        if (ret) {
            pr_err("error on rack_dm_writeback: %p\n", rpage);
            rpage->flags = RACK_DM_PAGE_ERROR;
            spin_unlock(&rpage->lock);
            break;
        }
        rack_dm_page_list_add(&region->inactive_list, rpage);
        spin_unlock(&rpage->lock);

        count_event(region, RACK_DM_EVENT_BG_RECLAIM);
    }
}

static void precopy_active_pages(struct work_struct *ws)
{
    int ret;
    struct rack_dm_work *work;
    struct rack_dm_region *region;
    char *target_node;
    unsigned long nr_pages, i;
    struct rack_dm_page *rpage;

    work = container_of(ws, struct rack_dm_work, ws);
    region = work->region;
    target_node = work->target_node;
    nr_pages = work->nr_pages;

    for (i = 0; i < nr_pages; i++) {
        rpage = rack_dm_page_list_pop(&region->active_list);
        if (rpage == NULL) {
            pr_err("failed to reclaim a page from active_list\n");
            break;
        }
        spin_lock(&rpage->lock);
        rack_dm_unmap(region, rpage);
        ret = rack_dm_writeback(region, rpage);
        if (ret) {
            pr_err("error on rack_dm_writeback: %p\n", rpage);
            rpage->flags = RACK_DM_PAGE_ERROR;
            spin_unlock(&rpage->lock);
            break;
        }
        rack_dm_page_list_add(&region->inactive_list, rpage);
        spin_unlock(&rpage->lock);

        count_event(region, RACK_DM_EVENT_BG_RECLAIM_PRECOPY);
    }

    pr_info("precopy_active_pages target_node: %s, nr_pages: %lu\n",
            target_node, nr_pages);

    count_event(region, RACK_DM_EVENT_PRECOPY_TASK);
    complete(&region->precopy_work.done);
}

static void prefetch_active_pages(struct work_struct *ws)
{
    int ret;
    struct rack_dm_work *work;
    struct rack_dm_region *region;
    unsigned long i, nr_pages, fault_address, cnt;
    u64 *prefetch_pages;
    struct rack_dm_page *rpage;

    work = container_of(ws, struct rack_dm_work, ws);
    region = work->region;
    nr_pages = work->nr_pages;
    prefetch_pages = work->arr;

    pr_info("prefetch_active_pages nr_pages: %lu, arr: %p\n",
            nr_pages, prefetch_pages);

    cnt = 0;
    for (i = 0; i < nr_pages; i++) {
        rpage = &region->pages[prefetch_pages[nr_pages - (i + 1)]];
        spin_lock(&rpage->lock);
        if (rpage->flags != RACK_DM_PAGE_NOT_PRESENT) {
            spin_unlock(&rpage->lock);
            continue;
        }
        rpage->buf = rack_dm_alloc_buf(region);
        if (rpage->buf == NULL) {
            spin_unlock(&rpage->lock);
            break;
        }

        ret = rack_dm_restore(region, rpage);
        if (unlikely(ret)) {
            pr_err("failed to restore the page\n");
            spin_unlock(&rpage->lock);
            break;
        }

        fault_address  = region->vma->vm_start;
        fault_address += rpage->index * region->page_size;
        ret = rack_dm_remap(region, rpage, fault_address, region->page_size);
        if (unlikely(ret)) {
            pr_err("failed to remap the page\n");
            spin_unlock(&rpage->lock);
            break;
        }
        spin_unlock(&rpage->lock);
        count_event(region, RACK_DM_EVENT_PREFETCH_MIGRATION);
        cnt++;
    }

    vfree(prefetch_pages);
    count_event(region, RACK_DM_EVENT_PREFETCH_TASK);
    pr_info("prefetch_active_pages finished: %lu\n", cnt);
}

static void migrate_clean_up_task(struct work_struct *ws)
{
    struct rack_dm_work *work;
    struct rack_dm_region *region;
    struct rack_dm_page *rpage;
    u64 i;

    work = container_of(ws, struct rack_dm_work, ws);
    region = work->region;

    pr_info("rack_dm_migrate_clean_up_region %p\n", region);

    for (i = 0; i < region->max_pages; i++) {
        rpage = &region->pages[i];
        if ((rpage->flags == RACK_DM_PAGE_ACTIVE) && (rpage->remote_page)) {
            /*
             *ret = free_remote_user_page(
             *        rpage->remote_page->conn, region->page_size,
             *        rpage->remote_page->remote_vaddr,
             *        rpage->remote_page->remote_paddr);
             *if (ret) {
             *    pr_err("error on free_remote_user_page\n");
             *    break;
             *}
             */
        }
        if (rpage->remote_page) {
            kfree(rpage->remote_page);
        }
    }

    free_remote_page_list(region);
    rack_dm_print_statistics(region);
    free_percpu(region->stat);
    vfree(region->pages);
    kfree(region);
}

struct rack_dm_region *rack_dm_alloc_region(u64 size_bytes, u64 page_size)
{
    u64 i, total_size_bytes;
    struct rack_dm_region *region = NULL;

    DEBUG_LOG("rack_dm_alloc_region size_bytes: %llu, page_size: %llu\n",
              size_bytes, page_size);

    total_size_bytes = (size_bytes / PAGE_SIZE) * PAGE_SIZE;
    if (size_bytes % PAGE_SIZE) {
        total_size_bytes += PAGE_SIZE;
        pr_info("round up the region size %llu -> %llu\n", size_bytes,
                total_size_bytes);
    }

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (region == NULL) {
        pr_err("failed to allocate memory for struct rack_dm_region\n");
        goto out;
    }

    region->rid = (u64) region;
    region->size = total_size_bytes;
    region->page_size = page_size;
    region->max_pages = total_size_bytes / page_size;

    atomic64_set(&region->page_count_limit, g_local_pages);
    atomic64_set(&region->page_count, 0);
    region->full = false;

    region->pages = vzalloc(region->max_pages * sizeof(struct rack_dm_page));
    if (region->pages == NULL) {
        pr_err("failed to allocate memory for region->pages\n");
        goto out_kfree_region;
    }
    for (i = 0; i < region->max_pages; i++) {
        region->pages[i].index = i;
        region->pages[i].flags = RACK_DM_PAGE_IDLE;
        spin_lock_init(&region->pages[i].lock);
    }
    rack_dm_page_list_init(&region->active_list);
    rack_dm_page_list_init(&region->inactive_list);
    rack_dm_page_list_init(&region->remote_page_list);

    region->remote_page_work.region = region;
    INIT_WORK(&region->remote_page_work.ws, refill_remote_page_list_bulk);

    region->reclaim_work.region = region;
    INIT_WORK(&region->reclaim_work.ws, reclaim_active_pages);

    region->precopy_work.region = region;
    INIT_WORK(&region->precopy_work.ws, precopy_active_pages);

    region->prefetch_work.region = region;
    INIT_WORK(&region->prefetch_work.ws, prefetch_active_pages);

    region->migrate_clean_up_work.region = region;
    INIT_WORK(&region->migrate_clean_up_work.ws, migrate_clean_up_task);

    region->stat = alloc_percpu(struct rack_dm_event_count);
    if (region->stat == NULL) {
        pr_err("error on alloc_percpu (region->stat)\n");
        goto out_vfree_pages;
    }
    spin_lock_init(&region->lock);

    schedule_work(&region->remote_page_work.ws);

    return region;

out_vfree_pages:
    vfree(region->pages);
out_kfree_region:
    kfree(region);
out:
    return NULL;
}

void free_remote_page_list(struct rack_dm_region *region)
{
    struct rack_dm_page_list *remote_page_list = &region->remote_page_list;
    struct remote_page *remote_page;

    spin_lock(&remote_page_list->lock);
    list_for_each_entry(remote_page, &remote_page_list->head, head) {
        free_remote_user_page(
                remote_page->conn, region->page_size,
                remote_page->remote_vaddr, remote_page->remote_paddr);
        count_event(region, RACK_DM_EVENT_FREE_REMOTE_PAGE);
    }
    spin_unlock(&remote_page_list->lock);
}

void rack_dm_free_region(struct rack_dm_region *region)
{
    int ret;
    u64 i;
    struct rack_dm_page *rpage;

    DEBUG_LOG("rack_dm_free_region %p\n", region);

    for (i = 0; i < region->max_pages; i++) {
        rpage = &region->pages[i];
        if (rpage->buf) {
            vfree(rpage->buf);
            count_event(region, RACK_DM_EVENT_FREE_LOCAL_PAGE);
        }
        if (rpage->remote_page) {
            ret = free_remote_user_page(
                    rpage->remote_page->conn, region->page_size,
                    rpage->remote_page->remote_vaddr,
                    rpage->remote_page->remote_paddr);
            if (ret) {
                pr_err("error on free_remote_page %llu\n", i);
                break;
            }
            kfree(rpage->remote_page);
            rpage->remote_page = NULL;
            count_event(region, RACK_DM_EVENT_FREE_REMOTE_PAGE);
        }
    }

    free_remote_page_list(region);
    rack_dm_print_statistics(region);
    free_percpu(region->stat);
    vfree(region->pages);
    kfree(region);
}

void rack_dm_migrate_clean_up_region(struct rack_dm_region *region)
{
    schedule_work(&region->migrate_clean_up_work.ws);
}
