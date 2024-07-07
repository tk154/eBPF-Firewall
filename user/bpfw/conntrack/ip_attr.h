#ifndef BPFW_CONNTRACK_IP_ATTR_H
#define BPFW_CONNTRACK_IP_ATTR_H

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>


enum conntrack_ip_attr {
    ATTR_IP_SRC,
    ATTR_IP_DST,
    ATTR_ORIG_IP_SRC,
    ATTR_ORIG_IP_DST,
    ATTR_REPL_IP_SRC,
    ATTR_REPL_IP_DST
};

static enum nf_conntrack_attr ipv4_attr[] = {
    ATTR_IPV4_SRC,
    ATTR_IPV4_DST,
    ATTR_ORIG_IPV4_SRC,
    ATTR_ORIG_IPV4_DST,
    ATTR_REPL_IPV4_SRC,
    ATTR_REPL_IPV4_DST
};

static enum nf_conntrack_attr ipv6_attr[] = {
    ATTR_IPV6_SRC,
    ATTR_IPV6_DST,
    ATTR_ORIG_IPV6_SRC,
    ATTR_ORIG_IPV6_DST,
    ATTR_REPL_IPV6_SRC,
    ATTR_REPL_IPV6_DST
};


static const void* nfct_get_attr_ip(struct nf_conntrack *ct, const enum conntrack_ip_attr type, __u8 family) {
    switch (family) {
        case AF_INET:
            return nfct_get_attr(ct, ipv4_attr[type]);
        case AF_INET6:
            return nfct_get_attr(ct, ipv6_attr[type]);
        default:
            return NULL;
    }
}

static void nfct_set_attr_ip(struct nf_conntrack *ct, const enum conntrack_ip_attr type, void* ip, __u8 family) {
    switch (family) {
        case AF_INET:
            return nfct_set_attr(ct, ipv4_attr[type], ip);
        case AF_INET6:
            return nfct_set_attr(ct, ipv6_attr[type], ip);
    }
}


#endif
