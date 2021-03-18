#include <stdio.h>
#include <librackdm/rackdm.h>

static void run_test(void)
{
    struct rack_dm_region *region;

    region = rack_dm_open(1048576);
    if (region == NULL) {
        perror("error on rack_dm_open");
        goto out;
    }

    printf("region id: %lu\n", region->id);

    return;

out:
    return;
}

int main(void)
{
    printf("RackDM Test\n");
    run_test();

    return 0;
}
