#ifndef _RACK_DM_RPC_H_
#define _RACK_DM_RPC_H_

enum rack_dm_rpc {
    RACK_DM_RPC_ALLOC_REMOTE_USER_PAGE          = 0xBBBB0000,
    RACK_DM_RPC_FREE_REMOTE_USER_PAGE,
    RACK_DM_RPC_ALLOC_REMOTE_MEMORY,
    RACK_DM_RPC_FREE_REMOTE_MEMORY,
    RACK_DM_RPC_GET_REGION_METADATA,
    RACK_DM_RPC_MIGRATE_CLEAN_UP
};

#endif /* _RACK_DM_RPC_H_ */

