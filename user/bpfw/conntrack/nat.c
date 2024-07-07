#include "nat.h"

#include "checksum.h"
#include "ip_attr.h"

#include <string.h>
#include <arpa/inet.h>


void check_nat(struct nf_conntrack *ct, struct flow_key_value *flow) {
    __u8 family = flow->key.family;
    size_t ip_len = family == AF_INET ? 4 : 16;

    // SNAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
        const void *old_ip, *new_ip;
        
        // Check if reverse
        if (memcmp(flow->key.src_ip, nfct_get_attr_ip(ct, ATTR_ORIG_IP_SRC, family), ip_len) == 0) {
            old_ip = nfct_get_attr_ip(ct, ATTR_ORIG_IP_SRC, family);
            new_ip = nfct_get_attr_ip(ct, ATTR_REPL_IP_DST, family);

            ipcpy(flow->value.n_entry.src_ip, new_ip, family);
            flow->value.n_entry.rewrite_flag |= REWRITE_SRC_IP;
        }
        else {
            // Reverse (DNAT)
            old_ip = nfct_get_attr_ip(ct, ATTR_REPL_IP_DST, family);
            new_ip = nfct_get_attr_ip(ct, ATTR_ORIG_IP_SRC, family);

            ipcpy(flow->value.n_entry.dest_ip, new_ip, family);
            flow->value.n_entry.rewrite_flag |= REWRITE_DEST_IP;
        }

        // Calculate the L3 and L4 checksum diffs
        if (family == AF_INET) {
            csum_replace(&flow->value.ipv4_cksum_diff, old_ip, new_ip, 2);
            csum_replace(&flow->value.n_entry.l4_cksum_diff, old_ip, new_ip, 2);
        }
        else
            csum_replace(&flow->value.n_entry.l4_cksum_diff, old_ip, new_ip, 8);
    }

    // DNAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)) {
        const void *old_ip, *new_ip;

        // Check if reverse
        if (memcmp(flow->key.dest_ip, nfct_get_attr_ip(ct, ATTR_ORIG_IP_DST, family), ip_len) == 0) {
            old_ip = nfct_get_attr_ip(ct, ATTR_ORIG_IP_DST, family);
            new_ip = nfct_get_attr_ip(ct, ATTR_REPL_IP_SRC, family);

            ipcpy(flow->value.n_entry.dest_ip, new_ip, family);
            flow->value.n_entry.rewrite_flag |= REWRITE_DEST_IP;
        }
        else {
            // Reverse (SNAT)
            old_ip = nfct_get_attr_ip(ct, ATTR_REPL_IP_SRC, family);
            new_ip = nfct_get_attr_ip(ct, ATTR_ORIG_IP_DST, family);

            ipcpy(flow->value.n_entry.src_ip, new_ip, family);
            flow->value.n_entry.rewrite_flag |= REWRITE_SRC_IP;
        }

        // Calculate the L3 and L4 checksum diffs
        if (family == AF_INET) {
            csum_replace(&flow->value.ipv4_cksum_diff, old_ip, new_ip, 2);
            csum_replace(&flow->value.n_entry.l4_cksum_diff, old_ip, new_ip, 2);
        }
        else
            csum_replace(&flow->value.n_entry.l4_cksum_diff, old_ip, new_ip, 8);
    }

    // SPAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT)) {
        __be16 old_port, new_port;

        // Check if reverse
        if (flow->key.src_port == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) {
            old_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
            new_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);

            flow->value.n_entry.src_port      = new_port;
            flow->value.n_entry.rewrite_flag |= REWRITE_SRC_PORT;
        }
        else {
            // Reverse (DPAT)
            old_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);
            new_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);

            flow->value.n_entry.dest_port     = new_port;
            flow->value.n_entry.rewrite_flag |= REWRITE_DEST_PORT;
        }

        // Calculate the L4 checksum diff
        csum_replace(&flow->value.n_entry.l4_cksum_diff, &old_port, &new_port, 1);
    }

    // DPAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_DPAT)) {
        __be16 old_port, new_port;

        // Check if reverse
        if (flow->key.dest_port == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) {
            old_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
            new_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);

            flow->value.n_entry.dest_port     = new_port;
            flow->value.n_entry.rewrite_flag |= REWRITE_DEST_PORT;
        }
        else {
            // Reverse (SPAT)
            old_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
            new_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

            flow->value.n_entry.src_port      = new_port;
            flow->value.n_entry.rewrite_flag |= REWRITE_SRC_PORT;
        }

        // Calculate the L4 checksum diff
        csum_replace(&flow->value.n_entry.l4_cksum_diff, &old_port, &new_port, 1);
    }

    bpfw_verbose_nat("Nat:", &flow->value.n_entry, family);
}
