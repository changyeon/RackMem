#ifndef _RACK_DM_DEBUGFS_H_
#define _RACK_DM_DEBUGFS_H_

#include <rack_dm.h>

#define RACK_DM_DEBUGFS_ROOT    "rack_vm"

int rack_dm_debugfs_setup(void);
void rack_dm_debugfs_cleanup(void);
int rack_dm_debugfs_add_region(struct rack_dm_region *region);
void rack_dm_debugfs_del_region(struct rack_dm_region *region);

#endif /* _RACK_DM_DEBUGFS_H_ */
