#ifndef _RACK_DM_IOCTL_H_
#define _RACK_DM_IOCTL_H_

#include <linux/ioctl.h>
#include <linux/fs.h>

#define RACK_DM_IOCTL_OPEN              _IOW(0xF8, 1, struct rack_dm_ioctl_msg)
#define RACK_DM_IOCTL_CLOSE             _IOW(0xF8, 2, struct rack_dm_ioctl_msg)
#define RACK_DM_IOCTL_MMAP              _IOW(0xF8, 3, struct rack_dm_ioctl_msg)

struct rack_dm_ioctl_msg {
    char buf[128];
};

long rack_dm_ioctl(struct file *fp, unsigned int cmd, unsigned long arg);

#endif /* _RACK_DM_IOCTL_H_ */
