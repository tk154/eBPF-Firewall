#ifndef BPFW_COMMON_USER_H
#define BPFW_COMMON_USER_H


#include <stdbool.h>

#include "../../common.h"
#include "logging/logging.h"


struct flow_key_value {
    struct flow_key key;
    struct flow_value value;
};


enum bpfw_hook {
    BPFW_HOOK_TC          = (1U << 0),

    BPFW_HOOK_XDP_GENERIC = (1U << 1),
    BPFW_HOOK_XDP_DRIVER  = (1U << 2),
    BPFW_HOOK_XDP_OFFLOAD = (1U << 3),

    BPFW_HOOK_XDP         = ( BPFW_HOOK_XDP_GENERIC | BPFW_HOOK_XDP_DRIVER | BPFW_HOOK_XDP_OFFLOAD )
};

struct cmd_args {
    char* obj_path;
    enum bpfw_hook hook;

    char** if_names;
    unsigned int if_count;

    bool dsa;

    __u32 map_poll_sec;
    __u32 map_max_entries;

    __u32 tcp_flow_timeout;
    __u32 udp_flow_timeout;
};


#endif
