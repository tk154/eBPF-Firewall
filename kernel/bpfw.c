#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define BPF_LOG_LEVEL BPF_LOG_LEVEL_INFO
#include "common_kern.h"
#include "../common.h"


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
	__uint(max_entries, 1024);
	//__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} FLOW_MAP SEC(".maps");


// Declare the VLAN header struct because it's only included in the kernel source header <linux/if_vlan.h>
struct vlan_hdr {
	__be16 h_vlan_TCI;					// priority and VLAN ID
	__be16 h_vlan_encapsulated_proto;	// packet type ID or len
};

// tcphdr from <linux/tcp.h> uses the host endianness, instead of the compiler endianness
struct tcp_flags {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	__u8 cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#endif
};
#define TCP_FLAGS_OFFSET 13


/**
 * Helper to swap the src and dest IP and the src and dest port of a flow key
 * @param f_key Pointer to the flow key
 * @param f_value Pointer to the flow value
 * **/
__always_inline void reverse_flow_key(struct flow_key *f_key, struct flow_value *f_value) {
	__be32 src_ip    = f_value->n_entry.rewrite_flag & REWRITE_SRC_IP ?
					   f_value->n_entry.src_ip : f_key->src_ip;

	f_key->src_ip    = f_value->n_entry.rewrite_flag & REWRITE_DEST_IP ?
					   f_value->n_entry.dest_ip : f_key->dest_ip;

	f_key->dest_ip   = src_ip;

	__be16 src_port  = f_value->n_entry.rewrite_flag & REWRITE_SRC_PORT ?
					   f_value->n_entry.src_port : f_key->src_port;

	f_key->src_port  = f_value->n_entry.rewrite_flag & REWRITE_DEST_PORT ?
					   f_value->n_entry.dest_port : f_key->dest_port;

	f_key->dest_port = src_port;

	f_key->ifindex   = f_value->next_h.ifindex;
	f_key->vlan_id   = f_value->next_h.vlan_id;
}

__always_inline bool tcp_finished(struct flow_key *f_key, struct flow_value *f_value, struct tcp_flags flags) {
	if (!flags.fin && !flags.rst)
		return false;

	// Mark the flow as finished
	f_value->action = ACTION_NONE;

	// Also mark the flow as finished for the reverse direction, if there is one
	reverse_flow_key(f_key, f_value);

	f_value = bpf_map_lookup_elem(&FLOW_MAP, f_key);
	if (f_value)
		f_value->action = ACTION_NONE;

	#if BPF_LOG_LEVEL >= BPF_LOG_LEVEL_INFO
		if (flags.fin) BPF_INFO("FIN");
		if (flags.rst) BPF_INFO("RST");
	#endif

	return true;
}

/* From include/net/checksum.h */
/**
 * Handle overflow while adding the addend to the checksum
 * @param cksum Pointer to the checksum
 * @param addend The addend
 * **/
__always_inline void cksum_add(__sum16 *cksum, __sum16 addend) {
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
__always_inline void apply_nat(struct nat_entry *n_entry, struct iphdr *iph, __be16 *sport, __be16 *dport, __sum16 *cksum) {
	// Check if NAT must be applied
	if (!n_entry->rewrite_flag)
		return;

	// Rewrite the source IP
	if (n_entry->rewrite_flag & REWRITE_SRC_IP)
		iph->saddr = n_entry->src_ip;

	// Rewrite the destination IP
	if (n_entry->rewrite_flag & REWRITE_DEST_IP)
		iph->daddr = n_entry->dest_ip;

	// Rewrite the source port
	if (n_entry->rewrite_flag & REWRITE_SRC_PORT)
		*sport = n_entry->src_port;

	// Rewrite the destination port
	if (n_entry->rewrite_flag & REWRITE_DEST_PORT)
		*dport = n_entry->dest_port;

	// Adjust the L4 checksum
	cksum_add(cksum, n_entry->l4_cksum_diff);
}

__always_inline int check_vlan(struct BPFW_CTX *ctx, struct ethhdr **ethh, __be16 h_proto, __u16 packet_vlan, __u16 next_hop_vlan) {
	if (!packet_vlan && next_hop_vlan) {
		BPF_DEBUG("Add VLAN Tag %u", next_hop_vlan);

#if defined(XDP_PROGRAM)
		if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)) != 0)
			return -1;

		if (ctx->data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > ctx->data_end)
			return -1;

		*ethh = (void*)(long)ctx->data;
		(*ethh)->h_proto = bpf_htons(ETH_P_8021Q);

		struct vlan_hdr *vlan_h = (struct vlan_hdr*)(*ethh + 1);
		vlan_h->h_vlan_TCI = bpf_htons(next_hop_vlan);
		vlan_h->h_vlan_encapsulated_proto = h_proto;
		
#elif defined(TC_PROGRAM)
		if (bpf_skb_vlan_push(ctx, ETH_P_8021Q, next_hop_vlan) != 0)
			return -1;

		if (ctx->data + sizeof(struct ethhdr) > ctx->data_end)
			return -1;

		*ethh = (void*)(long)ctx->data;
#endif
	}
	else if (packet_vlan && !next_hop_vlan) {
		BPF_DEBUG("Remove VLAN Tag");

#if defined(XDP_PROGRAM)
		if (bpf_xdp_adjust_head(ctx, sizeof(struct vlan_hdr)) != 0)
			return -1;

		if (ctx->data + sizeof(struct ethhdr) > ctx->data_end)
			return -1;

		*ethh = (void*)(long)ctx->data;
		(*ethh)->h_proto = h_proto;
		
#elif defined(TC_PROGRAM)
		if (bpf_skb_vlan_pop(ctx) != 0)
			return -1;

		if (ctx->data + sizeof(struct ethhdr) > ctx->data_end)
			return -1;

		*ethh = (void*)(long)ctx->data;
#endif
	}

	return 0;
}

/**
 * Rewrite the Ethernet header and redirect the package to the next hop
 * @param ethh The Ethernet header to rewrite
 * @param next_h The source and destination MAC and ifindex for the next hop
 * @returns BPF_REDIRECT on success, BPF_DROP otherwise
 * **/
__always_inline long redirect_package(struct ethhdr *ethh, struct next_hop *next_h) {
	// Adjust the MAC addresses
	memcpy(ethh->h_source, next_h->src_mac,  sizeof(ethh->h_source));
	memcpy(ethh->h_dest,   next_h->dest_mac, sizeof(ethh->h_dest));

	BPF_DEBUG("Redirect package to ifindex %u", next_h->ifindex);
	BPF_DEBUG_MAC("Dst MAC: ", next_h->dest_mac);

	// Redirect the package
	return bpf_redirect(next_h->ifindex, 0);
}


SEC("bpfw")
/**
 * Entry point of the BPF program executed when a new package is received on the hook
 * @param ctx The package contents and some metadata. Type is xdp_md for XDP and __sk_buff for TC programs.
 * @returns The action to be executed on the received package
**/
int fw_func(struct BPFW_CTX *ctx) {
	BPF_DEBUG("---------- New Package ----------");
	BPF_DEBUG("ifindex: %u", ctx->ingress_ifindex);

	// Save pointer to the first and last Byte of the received package
	void* data 	   = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	// Parse the Ethernet header, will drop the package if out-of-bounds
	parse_header(struct ethhdr, *ethh, data, data_end);

    BPF_DEBUG_MAC("Src MAC: ", ethh->h_source);
	BPF_DEBUG_MAC("Dst MAC: ", ethh->h_dest);

    __be16 h_proto = ethh->h_proto;
	__u16 vlan_id = 0;

	// Check if there is a VLAN header
#if defined(XDP_PROGRAM)
    if (h_proto == bpf_htons(ETH_P_8021Q)) {
		// Parse the VLAN header, will drop the package if out-of-bounds
		parse_header(struct vlan_hdr, *vlan_h, data, data_end);

		// Save the VLAN ID (last 12 Byte)
        vlan_id = bpf_htons(vlan_h->h_vlan_TCI) & 0x0FFF;

		BPF_DEBUG("VLAN ID: %u", vlan_id);

		// Save the packet type ID of the next header
		h_proto = vlan_h->h_vlan_encapsulated_proto;
    }
#elif defined(TC_PROGRAM)
	if (ctx->vlan_present && ctx->vlan_proto == bpf_htons(ETH_P_8021Q)) {
		// Save the VLAN ID (last 12 Byte)
        vlan_id = ctx->vlan_tci & 0x0FFF;

		BPF_DEBUG("VLAN ID: %u", vlan_id);
	}
#endif

	if (h_proto != bpf_htons(ETH_P_IP)) {
		BPF_DEBUG("h_proto: 0x%04x", h_proto);
		return BPFW_PASS;
	}

	// Parse the IPv4 header, will drop the package if out-of-bounds
	parse_header(struct iphdr, *iph, data, data_end);

	BPF_DEBUG_IP("Src IP: ", iph->saddr);
	BPF_DEBUG_IP("Dst IP: ", iph->daddr);

	// Pointers for possible NAT adjustments
	__be16  *sport, *dport;
	__sum16 *cksum;

	// TCP Flags
	struct tcp_flags flags = {};

	switch (iph->protocol) {
		case IPPROTO_TCP:;
			// Parse the TCP header, will drop the package if out-of-bounds
			parse_header(struct tcphdr, *tcph, data, data_end);

			BPF_DEBUG("TCP Src Port: %u", bpf_ntohs(tcph->source));
			BPF_DEBUG("TCP Dst Port: %u", bpf_ntohs(tcph->dest));

			// For possible NAT adjustmenets
			sport = &tcph->source;
			dport = &tcph->dest;
			cksum = &tcph->check;

			// Save the TCP Flags
			flags = *(struct tcp_flags*)((void*)tcph + TCP_FLAGS_OFFSET);
		break;

		case IPPROTO_UDP:;
			// Parse the UDP header, will drop the package if out-of-bounds
			parse_header(struct udphdr, *udph, data, data_end);

			BPF_DEBUG("UDP Src Port: %u", bpf_ntohs(udph->source));
			BPF_DEBUG("UDP Dst Port: %u", bpf_ntohs(udph->dest));

			// For possible NAT adjustmenets
			sport = &udph->source;
			dport = &udph->dest;
			cksum = &udph->check;
		break;

		default:
			BPF_DEBUG("IP Protocol: %u", iph->protocol);
			return BPFW_PASS;
	}

	// Fill the flow key
	struct flow_key f_key = {};
	f_key.ifindex = ctx->ingress_ifindex;
	f_key.vlan_id = vlan_id;
	f_key.src_ip = iph->saddr;
	f_key.dest_ip = iph->daddr;
	f_key.src_port = *sport;
	f_key.dest_port = *dport;
	f_key.l4_proto = iph->protocol;

	// Check if a conntrack entry exists
	struct flow_value* f_value = bpf_map_lookup_elem(&FLOW_MAP, &f_key);
	if (!f_value) {
		// If there is none, create a new one
		struct flow_value f_value = {};
		bpf_map_update_elem(&FLOW_MAP, &f_key, &f_value, BPF_NOEXIST);

		return BPFW_PASS;
	}

	// Reset the timeout
	f_value->idle = 0;

	switch (f_value->action) {
		case ACTION_REDIRECT:
			// Pass the package to the network stack if 
			// there is a FIN or RST or the TTL expired
			if (tcp_finished(&f_key, f_value, flags) || iph->ttl <= 1)
				return BPFW_PASS;

			// Decrement the TTL, adjust the checksum
			iph->ttl--;
			cksum_add(&iph->check, f_value->l3_cksum_diff);

			// Apply NAT
			apply_nat(&f_value->n_entry, iph, sport, dport, cksum);

			if (check_vlan(ctx, &ethh, h_proto, vlan_id, f_value->next_h.vlan_id) != 0)
				return BPFW_DROP;

			// Redirect the package
			return redirect_package(ethh, &f_value->next_h);

		case ACTION_DROP:
			BPF_DEBUG("Drop package");
			return BPFW_DROP;

		case ACTION_PASS:
		default:
			BPF_DEBUG("Pass package to network stack");
			return BPFW_PASS;
	}
}

char _license[] SEC("license") = "GPL";
