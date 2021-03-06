#include <linux/module.h>
#include <krdma.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem virtual memory");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

static int __init rack_vm_init(void)
{
    int ret = 0;

    pr_info("rack_vm: module loaded\n");

    return ret;
}

static void __exit rack_vm_exit(void)
{
    pr_info("rack_vm: module unloaded\n");
}

module_init(rack_vm_init);
module_exit(rack_vm_exit);
