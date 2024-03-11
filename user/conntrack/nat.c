#include "nat.h"
#include "checksum.h"


void check_nat(struct nf_conntrack *ct, struct flow_key *f_key, struct flow_value *f_value) {
    // SNAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_SNAT)) {
        __be32 old_ip, new_ip;
        
        // Check if reverse
        if (f_key->src_ip == nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC)) {
            old_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
            new_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);

            f_value->n_entry.src_ip        = new_ip;
            f_value->n_entry.rewrite_flag |= REWRITE_SRC_IP;
        }
        else {
            // Reverse (DNAT)
            old_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);
            new_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);

            f_value->n_entry.dest_ip       = new_ip;
            f_value->n_entry.rewrite_flag |= REWRITE_DEST_IP;
        }

        // Calculate the L3 and L4 checksum diffs
        csum_replace4(&f_value->l3_cksum_diff, old_ip, new_ip);
        csum_replace4(&f_value->n_entry.l4_cksum_diff, old_ip, new_ip);
    }

    // DNAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_DNAT)) {
        __be32 old_ip, new_ip;

        // Check if reverse
        if (f_key->dest_ip == nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST)) {
            old_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
            new_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);

            f_value->n_entry.dest_ip       = new_ip;
            f_value->n_entry.rewrite_flag |= REWRITE_DEST_IP;
        }
        else {
            // Reverse (SNAT)
            old_ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
            new_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);

            f_value->n_entry.src_ip        = new_ip;
            f_value->n_entry.rewrite_flag |= REWRITE_SRC_IP;
        }

        // Calculate the L3 and L4 checksum diffs
        csum_replace4(&f_value->l3_cksum_diff, old_ip, new_ip);
        csum_replace4(&f_value->n_entry.l4_cksum_diff, old_ip, new_ip);
    }

    // SPAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_SPAT)) {
        __be16 old_port, new_port;

        // Check if reverse
        if (f_key->src_port == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)) {
            old_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
            new_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);

            f_value->n_entry.src_port      = new_port;
            f_value->n_entry.rewrite_flag |= REWRITE_SRC_PORT;
        }
        else {
            // Reverse (DPAT)
            old_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);
            new_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);

            f_value->n_entry.dest_port     = new_port;
            f_value->n_entry.rewrite_flag |= REWRITE_DEST_PORT;
        }

        // Calculate the L4 checksum diff
        csum_replace2(&f_value->n_entry.l4_cksum_diff, old_port, new_port);
    }

    // DPAT
    if (nfct_getobjopt(ct, NFCT_GOPT_IS_DPAT)) {
        __be16 old_port, new_port;

        // Check if reverse
        if (f_key->dest_port == nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)) {
            old_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
            new_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);

            f_value->n_entry.dest_port     = new_port;
            f_value->n_entry.rewrite_flag |= REWRITE_DEST_PORT;
        }
        else {
            // Reverse (SPAT)
            old_port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
            new_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

            f_value->n_entry.src_port      = new_port;
            f_value->n_entry.rewrite_flag |= REWRITE_SRC_PORT;
        }

        // Calculate the L4 checksum diff
        csum_replace2(&f_value->n_entry.l4_cksum_diff, old_port, new_port);
    }
}
