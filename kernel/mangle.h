#ifndef BPFW_MANGLE_H
#define BPFW_MANGLE_H

#include "common_kern.h"


/* From include/net/checksum.h */
/**
 * Handle overflow while adding the addend to the checksum
 * @param cksum Pointer to the checksum
 * @param addend The addend
 * **/
__always_inline static void cksum_add(__sum16 *cksum, __sum16 addend) {
	__u16 res = (__u16)*cksum + (__u16)addend;
	*cksum = (__sum16)(res + (res < (__u16)addend));
}

/**
 * Check if NAT must be applied and adjust the addresses and L4 checksum
 * @param n_entry Pointer to the NAT entry
 * @param iph Pointer to the IPv4 header
 * @param sport Pointer to the source port
 * @param dport Pointer to the destination port
 * @param cksum Pointer to the L4 checksum
 * **/
__always_inline static void apply_nat(struct l3_header* l3, struct l4_header* l4, struct nat_entry *n_entry) {
	// Check if NAT must be applied
	if (!n_entry->rewrite_flag)
		return;

	// Rewrite the source IP
	if (n_entry->rewrite_flag & REWRITE_SRC_IP)
		ipcpy(l3->src_ip, n_entry->src_ip, l3->family);

	// Rewrite the destination IP
	if (n_entry->rewrite_flag & REWRITE_DEST_IP)
		ipcpy(l3->dest_ip, n_entry->dest_ip, l3->family);

	// Rewrite the source port
	if (n_entry->rewrite_flag & REWRITE_SRC_PORT)
		*l4->src_port = n_entry->src_port;

	// Rewrite the destination port
	if (n_entry->rewrite_flag & REWRITE_DEST_PORT)
		*l4->dest_port = n_entry->dest_port;

	if (l3->proto == IPPROTO_TCP || *l4->cksum)
		// Adjust the L4 checksum
		cksum_add(l4->cksum, n_entry->l4_cksum_diff);
}

__always_inline static void mangle_packet(struct l3_header* l3, struct l4_header* l4, struct next_entry* next) {
    // Decrement the TTL, adjust the checksum
    (*l3->ttl)--;

    if (l3->family == AF_INET)
        cksum_add(l3->cksum, next->ipv4_cksum_diff);

    // Apply NAT
    apply_nat(l3, l4, &next->nat);
}


#endif
