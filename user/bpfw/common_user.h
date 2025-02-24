#ifndef BPFW_COMMON_USER_H
#define BPFW_COMMON_USER_H

#include <stdbool.h>
#include "../../common.h"


enum {
    BPFW_RC_ERROR = -1,
    BPFW_RC_OK    =  0
};

enum bpfw_hook {
    BPFW_HOOK_TC          = (1U << 0),

    BPFW_HOOK_XDP_GENERIC = (1U << 1),
    BPFW_HOOK_XDP_NATIVE  = (1U << 2),
    BPFW_HOOK_XDP_OFFLOAD = (1U << 3),

    BPFW_HOOK_XDP         = ( BPFW_HOOK_XDP_GENERIC |
                              BPFW_HOOK_XDP_NATIVE  |
                              BPFW_HOOK_XDP_OFFLOAD )
};


struct flow_key_value {
    struct flow_key key;
    struct flow_value value;
};

struct flow_timeout {
    __u32 tcp, udp;
};


static bool ipeq(const __be32 *ip1, const __be32 *ip2, __u8 family) {
	switch (family) {
        case AF_INET:
            return ip1[0] == ip2[0];
        case AF_INET6:
            return ip1[0] == ip2[0] && ip1[1] == ip2[1] &&
                   ip1[2] == ip2[2] && ip1[3] == ip2[3];
		default:
			return false;
	}
}


#endif
