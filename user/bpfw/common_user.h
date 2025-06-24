#ifndef BPFW_COMMON_USER_H
#define BPFW_COMMON_USER_H

#include "../../common.h"

#include <stdbool.h>
#include <net/if.h>


#define DEFAULT_RSS_PROG_PATH       "./rss.o"

enum {
    BPFW_RC_ERROR = -1,
    BPFW_RC_OK    =  0
};

enum bpf_hook {
    BPF_HOOK_AUTO        = (1U << 0),
    BPF_HOOK_TC          = (1U << 1),

    BPF_HOOK_XDP_GENERIC = (1U << 2),
    BPF_HOOK_XDP_NATIVE  = (1U << 3),
    BPF_HOOK_XDP_OFFLOAD = (1U << 4),

    BPF_HOOK_XDP         = ( BPF_HOOK_XDP_GENERIC |
                             BPF_HOOK_XDP_NATIVE  |
                             BPF_HOOK_XDP_OFFLOAD )
};


struct flow {
    struct flow_key key;
    struct flow_value value;
};

struct flow_timeout {
    __u32 tcp, udp;
};

struct map_settings {
    __u32 max_entries;
    __u32 poll_sec;
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
