#ifndef _LIBRACKDM_RACKDM_H_
#define _LIBRACKDM_RACKDM_H_

#include <stdint.h>
#include <sys/ioctl.h>

#define RACK_DM_DEV_PATH                "/dev/rack_vm"

#define RACK_DM_IOCTL_OPEN              _IOW(0xF8, 1, struct rack_dm_ioctl_msg)
#define RACK_DM_IOCTL_CLOSE             _IOW(0xF8, 2, struct rack_dm_ioctl_msg)
#define RACK_DM_IOCTL_MMAP              _IOW(0xF8, 3, struct rack_dm_ioctl_msg)
#define RACK_DM_IOCTL_PAGE_INIT         _IOW(0xF8, 4, struct rack_dm_ioctl_msg)
#define RACK_DM_IOCTL_SET_PERSISTENT    _IOW(0xF8, 5, struct rack_dm_ioctl_msg)
#define RACK_DM_IOCTL_MIGRATE_CLEAN_UP  _IOW(0xF8, 6, struct rack_dm_ioctl_msg)

struct rack_dm_ioctl_msg {
    char buf[128];
};

struct rack_dm_region {
    char node[64];
    uint64_t id;
    uint64_t size;
    void *buf;
};

struct rack_dm_region *rack_dm_open(uint64_t size);
struct rack_dm_region *rack_dm_mmap(const char *node, uint64_t remote_region_id, uint64_t size);
int rack_dm_close(struct rack_dm_region *region);
int rack_dm_page_init(struct rack_dm_region *region, uint64_t pg_index);
int rack_dm_set_persistent(struct rack_dm_region *region, uint64_t val);
int rack_dm_migrate_clean_up(const char *node, uint64_t remote_region_id);

#endif /* _LIBRACKDM_RACKDM_H */
