#ifndef BPFW_CT_COMMON_H
#define BPFW_CT_COMMON_H

#include "conntrack.h"


struct conntrack_handle {
    // Store the nf_conntrack handle pointer
    struct nfct_handle *ct_handle;
    struct nf_conntrack *ct;

    // Timeouts from /proc/sys/net/netfilter
    // Note: There are more, for now just basic ones
    __u32 tcp_timeout, udp_timeout, udp_stream_timeout;
};

enum ct_ip_attr {
    ATTR_IP_SRC,
    ATTR_IP_DST,
    ATTR_ORIG_IP_SRC,
    ATTR_ORIG_IP_DST,
    ATTR_REPL_IP_SRC,
    ATTR_REPL_IP_DST
};


const void* nfct_get_attr_ip(struct nf_conntrack *ct, const enum ct_ip_attr type, __u8 family);
//void nfct_set_attr_ip(struct nf_conntrack *ct, const enum ct_ip_attr type, const void* ip, __u8 family);


#endif
