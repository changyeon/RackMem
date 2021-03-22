#ifndef _RACK_DM_RPC_H_
#define _RACK_DM_RPC_H_

enum rack_dm_rpc {
    RACK_DM_RPC_ALLOC_REMOTE_PAGE           = 0xBBBB0000,
    RACK_DM_RPC_FREE_REMOTE_PAGE,
    RACK_DM_RPC_GET_REGION_METADATA
};

#endif /* _RACK_DM_RPC_H_ */

