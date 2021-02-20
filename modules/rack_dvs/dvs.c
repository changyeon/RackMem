#include <linux/module.h>
#include <krdma.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RackMem distributed virtual storage");
MODULE_AUTHOR("Changyeon Jo <changyeon@csap.snu.ac.kr>");

static int __init rack_dvs_init(void)
{
    int ret = 0;

    pr_info("rack_dvs: module loaded\n");
    krdma_test();

    return ret;
}

static void __exit rack_dvs_exit(void)
{
    pr_info("rack_dvs: module unloaded\n");
}

module_init(rack_dvs_init);
module_exit(rack_dvs_exit);
