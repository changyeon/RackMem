#ifndef _RACK_VM_DEBUGFS_H_
#define _RACK_VM_DEBUGFS_H_

#include <rack_vm.h>

#define RACK_VM_DEBUGFS_ROOT    "rack_vm"

int rack_vm_debugfs_setup(void);
void rack_vm_debugfs_cleanup(void);
int rack_vm_debugfs_add_region(struct rack_vm_region *region);
void rack_vm_debugfs_del_region(struct rack_vm_region *region);

#endif /* _RACK_VM_DEBUGFS_H_ */

