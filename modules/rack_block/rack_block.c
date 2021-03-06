#include <linux/module.h>
#include <krdma.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem RDMA block device");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

static int __init rack_block_init(void)
{
    int ret = 0;

    pr_info("rack_block: module loaded\n");

    return ret;
}

static void __exit rack_block_exit(void)
{
    pr_info("rack_block: module unloaded\n");
}

module_init(rack_block_init);
module_exit(rack_block_exit);
