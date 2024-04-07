#include "nat.h"
#include "checksum.h"

#include <arpa/inet.h>


static void log_nat(struct nat_entry *n_entry) {
    if (fw_log_level >= FW_LOG_LEVEL_VERBOSE) {
        if (!n_entry->rewrite_flag)
            return;

        FW_VERBOSE("Nat:");

        if (n_entry->rewrite_flag & REWRITE_SRC_IP) {
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &n_entry->src_ip, src_ip, sizeof(src_ip));
            FW_VERBOSE(" %s", src_ip);
        }
        else
            FW_VERBOSE(" -");

        if (n_entry->rewrite_flag & REWRITE_SRC_PORT)
            FW_VERBOSE(" %hu", ntohs(n_entry->src_port));
        else
            FW_VERBOSE(" -");

        if (n_entry->rewrite_flag & REWRITE_DEST_IP) {
            char dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &n_entry->dest_ip, dest_ip, sizeof(dest_ip));
            FW_VERBOSE(" %s", dest_ip);
        }
        else
            FW_VERBOSE(" -");

        if (n_entry->rewrite_flag & REWRITE_DEST_PORT)
            FW_VERBOSE(" %hu", ntohs(n_entry->dest_port));
        else
            FW_VERBOSE(" -");

        FW_VERBOSE("\n");
    }
}

void check_nat(struct nf_conntrack *ct, struct flow_key_value *flow) {
    // SNAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
        __be32 old_ip, new_ip;
        
        // Check if reverse
        if (flow->key.src_ip == nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC)) {
            old_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
            new_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);

            flow->value.n_entry.src_ip        = new_ip;
            flow->value.n_entry.rewrite_flag |= REWRITE_SRC_IP;
        }
        else {
            // Reverse (DNAT)
            old_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);
            new_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);

            flow->value.n_entry.dest_ip       = new_ip;
            flow->value.n_entry.rewrite_flag |= REWRITE_DEST_IP;
        }

        // Calculate the L3 and L4 checksum diffs
        csum_replace4(&flow->value.l3_cksum_diff, old_ip, new_ip);
        csum_replace4(&flow->value.n_entry.l4_cksum_diff, old_ip, new_ip);
    }

    // DNAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)) {
        __be32 old_ip, new_ip;

        // Check if reverse
        if (flow->key.dest_ip == nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST)) {
            old_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
            new_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);

            flow->value.n_entry.dest_ip       = new_ip;
            flow->value.n_entry.rewrite_flag |= REWRITE_DEST_IP;
        }
        else {
            // Reverse (SNAT)
            old_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
            new_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);

            flow->value.n_entry.src_ip        = new_ip;
            flow->value.n_entry.rewrite_flag |= REWRITE_SRC_IP;
        }

        // Calculate the L3 and L4 checksum diffs
        csum_replace4(&flow->value.l3_cksum_diff, old_ip, new_ip);
        csum_replace4(&flow->value.n_entry.l4_cksum_diff, old_ip, new_ip);
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
        csum_replace2(&flow->value.n_entry.l4_cksum_diff, old_port, new_port);
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
        csum_replace2(&flow->value.n_entry.l4_cksum_diff, old_port, new_port);
    }

    log_nat(&flow->value.n_entry);
}
