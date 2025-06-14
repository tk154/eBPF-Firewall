#include "ct_common.h"

#include <string.h>
#include <arpa/inet.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "../log/log.h"


/* Modified versions originally from include/net/checksum.h */

static __sum16 csum_add(__sum16 csum, const __be16 *add, size_t len) {
	__u16 res = (__u16)csum;

	for (size_t i = 0; i < len; i++) {
		res += (__u16)add[i];
		res += res < (__u16)add[i];
	}

	return (__sum16)res;
}

static __sum16 csum_sub(__sum16 csum, const __be16 *sub, size_t len) {
	__be16 sub_neg[len];
	
	for (size_t i = 0; i < len; i++)
		sub_neg[i] = ~sub[i];

	return csum_add(csum, sub_neg, len);
}

static void csum_replace(__sum16 *csum, const __be16 *old, const __be16 *new, size_t len) {
	*csum = ~csum_add(csum_sub(~(*csum), old, len), new, len);
}


static bool ct_flow_is_reverse(struct nf_conntrack *ct, struct flow_key *f_key) {
    __be32 *dest_ip = flow_ip_get_dest(&f_key->ip, f_key->family);
    __be32 *src_ip = flow_ip_get_src(&f_key->ip, f_key->family);
    __u8 family = f_key->family;

    return !(
        ipeq(src_ip,  nfct_get_attr_ip(ct, ATTR_ORIG_IP_SRC, family), family) &&
        ipeq(dest_ip, nfct_get_attr_ip(ct, ATTR_ORIG_IP_DST, family), family) &&
        f_key->src_port  == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) &&
        f_key->dest_port == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)
    );
}


void conntrack_check_nat(struct conntrack_handle *conntrack_h, struct flow *flow) {
    struct nf_conntrack *ct = conntrack_h->ct;

    // Check if reverse
    bool is_reverse = ct_flow_is_reverse(ct, &flow->key);

    // SNAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
        const void *old_ip, *new_ip;
        
        // Check if reverse
        if (!is_reverse) {
            old_ip = nfct_get_attr_ip(ct, ATTR_ORIG_IP_SRC, flow->key.family);
            new_ip = nfct_get_attr_ip(ct, ATTR_REPL_IP_DST, flow->key.family);

            ipcpy(flow->value.next.nat.src_ip, new_ip, flow->key.family);
            flow->value.next.nat.rewrite_flag |= REWRITE_SRC_IP;
        }
        else {
            // Reverse (DNAT)
            old_ip = nfct_get_attr_ip(ct, ATTR_REPL_IP_DST, flow->key.family);
            new_ip = nfct_get_attr_ip(ct, ATTR_ORIG_IP_SRC, flow->key.family);

            ipcpy(flow->value.next.nat.dest_ip, new_ip, flow->key.family);
            flow->value.next.nat.rewrite_flag |= REWRITE_DEST_IP;
        }

        // Calculate the L3 and L4 checksum diffs
        if (flow->key.family == AF_INET) {
            csum_replace(&flow->value.next.ipv4_cksum_diff, old_ip, new_ip, 2);
            csum_replace(&flow->value.next.nat.l4_cksum_diff, old_ip, new_ip, 2);
        }
        else
            csum_replace(&flow->value.next.nat.l4_cksum_diff, old_ip, new_ip, 8);
    }

    // DNAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)) {
        const void *old_ip, *new_ip;

        // Check if reverse
        if (!is_reverse) {
            old_ip = nfct_get_attr_ip(ct, ATTR_ORIG_IP_DST, flow->key.family);
            new_ip = nfct_get_attr_ip(ct, ATTR_REPL_IP_SRC, flow->key.family);

            ipcpy(flow->value.next.nat.dest_ip, new_ip, flow->key.family);
            flow->value.next.nat.rewrite_flag |= REWRITE_DEST_IP;
        }
        else {
            // Reverse (SNAT)
            old_ip = nfct_get_attr_ip(ct, ATTR_REPL_IP_SRC, flow->key.family);
            new_ip = nfct_get_attr_ip(ct, ATTR_ORIG_IP_DST, flow->key.family);

            ipcpy(flow->value.next.nat.src_ip, new_ip, flow->key.family);
            flow->value.next.nat.rewrite_flag |= REWRITE_SRC_IP;
        }

        // Calculate the L3 and L4 checksum diffs
        if (flow->key.family == AF_INET) {
            csum_replace(&flow->value.next.ipv4_cksum_diff, old_ip, new_ip, 2);
            csum_replace(&flow->value.next.nat.l4_cksum_diff, old_ip, new_ip, 2);
        }
        else
            csum_replace(&flow->value.next.nat.l4_cksum_diff, old_ip, new_ip, 8);
    }

    // SPAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT)) {
        __be16 old_port, new_port;

        // Check if reverse
        if (!is_reverse) {
            old_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
            new_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);

            flow->value.next.nat.src_port      = new_port;
            flow->value.next.nat.rewrite_flag |= REWRITE_SRC_PORT;
        }
        else {
            // Reverse (DPAT)
            old_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);
            new_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);

            flow->value.next.nat.dest_port     = new_port;
            flow->value.next.nat.rewrite_flag |= REWRITE_DEST_PORT;
        }

        // Calculate the L4 checksum diff
        csum_replace(&flow->value.next.nat.l4_cksum_diff, &old_port, &new_port, 1);
    }

    // DPAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_DPAT)) {
        __be16 old_port, new_port;

        // Check if reverse
        if (!is_reverse) {
            old_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
            new_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);

            flow->value.next.nat.dest_port     = new_port;
            flow->value.next.nat.rewrite_flag |= REWRITE_DEST_PORT;
        }
        else {
            // Reverse (SPAT)
            old_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
            new_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

            flow->value.next.nat.src_port      = new_port;
            flow->value.next.nat.rewrite_flag |= REWRITE_SRC_PORT;
        }

        // Calculate the L4 checksum diff
        csum_replace(&flow->value.next.nat.l4_cksum_diff, &old_port, &new_port, 1);
    }

    bpfw_verbose_nat("Nat: ", &flow->value.next.nat, flow->key.family);
}
