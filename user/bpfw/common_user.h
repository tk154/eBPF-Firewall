#ifndef BPFW_COMMON_USER_H
#define BPFW_COMMON_USER_H

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

    BPFW_HOOK_XDP         = ( BPFW_HOOK_XDP_GENERIC | BPFW_HOOK_XDP_NATIVE | BPFW_HOOK_XDP_OFFLOAD )
};


struct flow_key_value {
    struct flow_key key;
    struct flow_value value;
};

struct flow_timeout {
    __u32 tcp, udp;
};


#define bpf_flow_map_for_each_entry(fd, flow, block) \
    int rc = bpf_map_get_next_key(fd, NULL, &flow.key); \
    while (rc == 0) { \
        if (bpf_map_lookup_elem(fd, &flow.key, &flow.value) != 0) { \
            bpfw_error("Error looking up flow entry: %s (-%d).\n", strerror(errno), errno); \
            return BPFW_RC_ERROR; \
        } \
        block; \
        rc = bpf_map_get_next_key(fd, &flow.key, &flow.key); \
    } \
    if (rc != -ENOENT) { \
        bpfw_error("Error retrieving flow key: %s (-%d).\n", strerror(errno), errno); \
        return BPFW_RC_ERROR; \
    }

static bool ipeq(const void *ip1, const void *ip2, __u8 family) {
	switch (family) {
        case AF_INET:
            return memcmp(ip1, ip2, IPV4_ALEN) == 0;
        case AF_INET6:
            return memcmp(ip1, ip2, IPV6_ALEN) == 0;
		default:
			return false;
	}
}


#endif
