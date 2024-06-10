#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define BPF_LOG_LEVEL BPF_LOG_LEVEL_WARN
#include "common_kern.h"


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
	__uint(max_entries, 1024);
	//__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} FLOW_MAP SEC(".maps");


/**
 * Helper to swap the src and dest IP and the src and dest port of a flow key
 * @param f_key Pointer to the flow key
 * @param f_value Pointer to the flow value
 * **/
__always_inline void reverse_flow_key(struct flow_key *f_key, struct flow_value *f_value) {
	__u8 src_ip[16];

	ipcpy(src_ip, f_value->n_entry.rewrite_flag & REWRITE_SRC_IP ?
		f_value->n_entry.src_ip : f_key->src_ip, f_key->family);

	ipcpy(f_key->src_ip, f_value->n_entry.rewrite_flag & REWRITE_DEST_IP ?
		f_value->n_entry.dest_ip : f_key->dest_ip, f_key->family);

	ipcpy(f_key->dest_ip, src_ip, f_key->family);

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

	BPF_LOG_KEY(flags.fin ? "FIN" : "RST", f_key);

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
__always_inline void apply_nat(struct nat_entry *n_entry, __u8 family, void *src_ip, void *dest_ip,
								__be16 *sport, __be16 *dport, __sum16 *l4_cksum) {
	// Check if NAT must be applied
	if (!n_entry->rewrite_flag)
		return;

	// Rewrite the source IP
	if (n_entry->rewrite_flag & REWRITE_SRC_IP)
		ipcpy(src_ip, n_entry->src_ip, family);

	// Rewrite the destination IP
	if (n_entry->rewrite_flag & REWRITE_DEST_IP)
		ipcpy(dest_ip, n_entry->dest_ip, family);

	// Rewrite the source port
	if (n_entry->rewrite_flag & REWRITE_SRC_PORT)
		*sport = n_entry->src_port;

	// Rewrite the destination port
	if (n_entry->rewrite_flag & REWRITE_DEST_PORT)
		*dport = n_entry->dest_port;

	// Adjust the L4 checksum
	cksum_add(l4_cksum, n_entry->l4_cksum_diff);
}

__always_inline void* check_vlan(struct BPFW_CTX *ctx, __be16 h_proto, __u16 packet_vlan, __u16 next_hop_vlan) {
	if (!packet_vlan && next_hop_vlan) {
		BPF_DEBUG("Add VLAN Tag %u", next_hop_vlan);

#if defined(XDP_PROGRAM)
		int rc = bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr));
		if (rc != 0) {
			BPF_ERROR("bpf_xdp_adjust_head error: %d", rc);
			return NULL;
		}

		void* data 	   = (void*)(long)ctx->data;
		void* data_end = (void*)(long)ctx->data_end;

		if (data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr) > data_end)
			return NULL;

		struct ethhdr *ethh = data;
		ethh->h_proto = bpf_htons(ETH_P_8021Q);
		data += sizeof(struct ethhdr);

		struct vlan_hdr *vlan_h = data;
		vlan_h->h_vlan_TCI = bpf_htons(next_hop_vlan);
		vlan_h->h_vlan_encapsulated_proto = h_proto;
		
#elif defined(TC_PROGRAM)
		int rc = bpf_skb_vlan_push(ctx, ETH_P_8021Q, next_hop_vlan);
		if (rc != 0) {
			BPF_ERROR("bpf_skb_vlan_push error: %d", rc);
			return NULL;
		}

		void* data 	   = (void*)(long)ctx->data;
		void* data_end = (void*)(long)ctx->data_end;

		if (data + sizeof(struct ethhdr) > data_end)
			return NULL;
#endif
		return data;
	}

	if (packet_vlan && !next_hop_vlan) {
		BPF_DEBUG("Remove VLAN Tag");

#if defined(XDP_PROGRAM)
		int rc = bpf_xdp_adjust_head(ctx, sizeof(struct vlan_hdr));
		if (rc != 0) {
			BPF_ERROR("bpf_xdp_adjust_head error: %d", rc);
			return NULL;
		}

		void* data 	   = (void*)(long)ctx->data;
		void* data_end = (void*)(long)ctx->data_end;

		if (data + sizeof(struct ethhdr) > data_end)
			return NULL;

		struct ethhdr *ethh = data;
		ethh->h_proto = h_proto;
		
#elif defined(TC_PROGRAM)
		int rc = bpf_skb_vlan_pop(ctx);
		if (rc != 0) {
			BPF_ERROR("bpf_skb_vlan_pop error: %d", rc);
			return NULL;
		}

		void* data 	   = (void*)(long)ctx->data;
		void* data_end = (void*)(long)ctx->data_end;

		if (data + sizeof(struct ethhdr) > data_end)
			return NULL;
#endif
		return data;
	}

	return (void*)(long)ctx->data;
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
        vlan_id = bpf_ntohs(vlan_h->h_vlan_TCI) & 0x0FFF;

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

	void *src_ip, *dest_ip;
	__u8 family, proto, *ttl;
	__sum16 *l3_cksum;

	switch (h_proto) {
		case bpf_ntohs(ETH_P_IP):;
			// Parse the IPv4 header, will drop the package if out-of-bounds
			parse_header(struct iphdr, *iph, data, data_end);

			BPF_DEBUG_IPV4("Src IPv4: ", &iph->saddr);
			BPF_DEBUG_IPV4("Dst IPv4: ", &iph->daddr);

			family	= AF_INET;
			src_ip 	= &iph->saddr;
			dest_ip = &iph->daddr;

			proto    =  iph->protocol;
			ttl 	 = &iph->ttl;
			l3_cksum = &iph->check;
		break;

		case bpf_ntohs(ETH_P_IPV6):;
			// Parse the IPv4 header, will drop the package if out-of-bounds
			parse_header(struct ipv6hdr, *ipv6h, data, data_end);

			BPF_DEBUG_IPV6("Src IPv6: ", &ipv6h->saddr);
			BPF_DEBUG_IPV6("Dst IPv6: ", &ipv6h->daddr);

			family	= AF_INET6;
			src_ip  = &ipv6h->saddr;
			dest_ip = &ipv6h->daddr;

			proto =  ipv6h->nexthdr;
			ttl   = &ipv6h->hop_limit;
		break;

		default:
			BPF_DEBUG("h_proto: 0x%04x", h_proto);
			return BPFW_PASS;
	}

	// Pointers for possible NAT adjustments
	__be16  *sport, *dport;
	__sum16 *l4_cksum;

	// TCP Flags
	struct tcp_flags flags = {};

	switch (proto) {
		case IPPROTO_TCP:;
			// Parse the TCP header, will drop the package if out-of-bounds
			parse_header(struct tcphdr, *tcph, data, data_end);

			BPF_DEBUG("TCP Src Port: %u", bpf_ntohs(tcph->source));
			BPF_DEBUG("TCP Dst Port: %u", bpf_ntohs(tcph->dest));

			// For possible NAT adjustmenets
			sport 	 = &tcph->source;
			dport 	 = &tcph->dest;
			l4_cksum = &tcph->check;

			// Save the TCP Flags
			flags = *(struct tcp_flags*)((void*)tcph + TCP_FLAGS_OFFSET);
		break;

		case IPPROTO_UDP:;
			// Parse the UDP header, will drop the package if out-of-bounds
			parse_header(struct udphdr, *udph, data, data_end);

			BPF_DEBUG("UDP Src Port: %u", bpf_ntohs(udph->source));
			BPF_DEBUG("UDP Dst Port: %u", bpf_ntohs(udph->dest));

			// For possible NAT adjustmenets
			sport 	 = &udph->source;
			dport 	 = &udph->dest;
			l4_cksum = &udph->check;
		break;

		default:
			BPF_DEBUG("IP Protocol: %u", proto);
			return BPFW_PASS;
	}

	// Fill the flow key
	struct flow_key f_key = {};
	f_key.ifindex = ctx->ingress_ifindex;
	f_key.vlan_id = vlan_id;
	f_key.src_port = *sport;
	f_key.dest_port = *dport;
	f_key.family = family;
	f_key.proto = proto;

	ipcpy(f_key.src_ip, src_ip, family);
	ipcpy(f_key.dest_ip, dest_ip, family);

	// Check if a conntrack entry exists
	struct flow_value* f_value = bpf_map_lookup_elem(&FLOW_MAP, &f_key);
	if (!f_value) {
		BPF_LOG_KEY("NEW", &f_key);

		// If there is none, create a new one
		struct flow_value f_value = {};
		if (bpf_map_update_elem(&FLOW_MAP, &f_key, &f_value, BPF_NOEXIST) != 0)
			BPF_WARN("bpf_map_update_elem error");

		return BPFW_PASS;
	}

	// Reset the timeout
	f_value->idle = 0;

	switch (f_value->action) {
		case ACTION_REDIRECT:
			// Pass the package to the network stack if 
			// there is a FIN or RST or the TTL expired
			if (tcp_finished(&f_key, f_value, flags) || *ttl <= 1)
				return BPFW_PASS;

			// Decrement the TTL, adjust the checksum
			(*ttl)--;

			if (family == AF_INET)
				cksum_add(l3_cksum, f_value->ipv4_cksum_diff);

			// Apply NAT
			apply_nat(&f_value->n_entry, family, src_ip, dest_ip, sport, dport, l4_cksum);

			ethh = check_vlan(ctx, h_proto, vlan_id, f_value->next_h.vlan_id);
			if (!ethh)
				return BPFW_DROP;

			// Redirect the package
			return redirect_package(ethh, &f_value->next_h);

		case ACTION_DROP:
			BPF_DEBUG("Drop package");
			return BPFW_DROP;

		case ACTION_PASS:
		default:
			BPF_DEBUG("Pass package");
			return BPFW_PASS;
	}
}

char _license[] SEC("license") = "GPL";
