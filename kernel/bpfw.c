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
	__type(key, struct conn_key);
	__type(value, struct conn_value);
	__uint(max_entries, 1024);
	//__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} CONN_MAP SEC(".maps");


// Declare the VLAN header struct because it's only included in the kernel source header <linux/if_vlan.h>
struct vlan_hdr {
	__be16 h_vlan_TCI;					// priority and VLAN ID
	__be16 h_vlan_encapsulated_proto;	// packet type ID or len
};


/**
 * Helper to swap the src and dest IP and the src and dest port of a connection key
 * @param c_key Pointer to the connection key
 * **/
__always_inline void reverse_conn_key(struct conn_key *c_key) {
	__be32 tmp_ip    = c_key->src_ip;
	c_key->src_ip    = c_key->dest_ip;
	c_key->dest_ip   = tmp_ip;

	__be16 tmp_port  = c_key->src_port;
	c_key->src_port  = c_key->dest_port;
	c_key->dest_port = tmp_port;
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

/**
 * Use bpf_fib_lookup to decide wether to route the package and where to
 * @param ctx xdp_md for XDP and __sk_buff for TC programs
 * @param iph The IPv4 Header of the package
 * @param c_key Pointer to the connection key
 * @param c_value Where to store the result, ifindex and MAC addresses
 * **/
__always_inline void make_routing_decision(struct BPF_CTX *ctx, struct iphdr *iph, struct conn_key *c_key, struct conn_value *c_value) {
	// Fill the lookup key
	struct bpf_fib_lookup fib_params = {};
	fib_params.family = AF_INET;
	fib_params.l4_protocol = iph->protocol;
	fib_params.sport = c_key->src_port;
	fib_params.dport = c_value->n_entry.dest_port ? c_value->n_entry.dest_port : c_key->dest_port;
	fib_params.tot_len = bpf_ntohs(iph->tot_len);
	fib_params.tos = iph->tos;
	fib_params.ipv4_src = iph->saddr;
	fib_params.ipv4_dst = c_value->n_entry.dest_ip ? c_value->n_entry.dest_ip : iph->daddr;
	fib_params.ifindex = ctx->ingress_ifindex;

	// Do a loopkup in the kernel routing table
	long rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	BPF_INFO("bpf_fib_lookup: %d", rc);

	switch (rc) { 
		case BPF_FIB_LKUP_RET_SUCCESS:
			BPF_INFO("ifindex: %d", fib_params.ifindex);

			// Copy the MAC addresses
			memcpy(c_value->next_h.src_mac,  fib_params.smac, ETH_ALEN);
			memcpy(c_value->next_h.dest_mac, fib_params.dmac, ETH_ALEN);

			c_value->next_h.ifindex = fib_params.ifindex;
			c_value->action = ACTION_REDIRECT;
		break;

		case BPF_FIB_LKUP_RET_BLACKHOLE:  
		case BPF_FIB_LKUP_RET_UNREACHABLE: 
		case BPF_FIB_LKUP_RET_PROHIBIT:   
			c_value->action = ACTION_DROP;
		break;

		case BPF_FIB_LKUP_RET_FRAG_NEEDED:  // fragmentation required to fwd
			BPF_INFO("tot_len: %u, mtu_result: %u",
				bpf_ntohs(iph->tot_len), fib_params.mtu_result);
		break;

		case BPF_FIB_LKUP_RET_NOT_FWDED:   
		case BPF_FIB_LKUP_RET_FWD_DISABLED:
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:  
		case BPF_FIB_LKUP_RET_NO_NEIGH:    
		default:
			c_value->action = ACTION_PASS;
	}
}

__always_inline long redirect_package(struct ethhdr *ethh, struct next_hop *next_h) {
	// Adjust the MAC addresses
	memcpy(ethh->h_source, next_h->src_mac,  sizeof(ethh->h_source));
	memcpy(ethh->h_dest,   next_h->dest_mac, sizeof(ethh->h_dest));

	BPF_DEBUG("Redirect package to if%u", next_h->ifindex);

	// Redirect the package
	return bpf_redirect(next_h->ifindex, 0);
}


SEC("fw")
/**
 * Entry point of the BPF program executed when a new package is received on the hook
 * @param ctx The package contents and some metadata. Type is xdp_md for XDP and __sk_buff for TC programs.
 * @returns The action to be executed on the received package
**/
int fw_func(struct BPF_CTX *ctx) {
	BPF_DEBUG("---------- New Package ----------");

	// Save the first and last Byte of the received package
	void* data 	   = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	// A pointer to save the cuurent position inside the package
	void* p = data;

	// Parse the Ethernet header, will drop the package if out-of-bounds
	parse_header(struct ethhdr, *ethh, p, data_end);

	// Initialize the connection key
	struct conn_key c_key = {};
    __be16 h_proto = ethh->h_proto;

	// Check if there is a VLAN header
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
		// Parse the VLAN header, will drop the package if out-of-bounds
		parse_header(struct vlan_hdr, *vlan_h, p, data_end);

		// Save the VLAN ID (last 12 Byte)
        c_key.vlan_id = bpf_htons(vlan_h->h_vlan_TCI) & 0x0FFF;

		BPF_DEBUG("VLAN ID: %u", c_key.vlan_id);

		// Save the packet type ID of the next header
		h_proto = vlan_h->h_vlan_encapsulated_proto;
    }

	if (h_proto == bpf_htons(ETH_P_IP)) {
		// Parse the IPv4 header, will drop the package if out-of-bounds
		parse_header(struct iphdr, *iph, p, data_end);

		BPF_DEBUG_IP("Source IP: ", iph->saddr);
		BPF_DEBUG_IP("Destination IP: ", iph->daddr);
		BPF_DEBUG("Protocol: %u", iph->protocol);

		c_key.src_ip   = iph->saddr;
		c_key.dest_ip  = iph->daddr;
		c_key.l4_proto = iph->protocol;

		// Pointers for possible NAT adjustments
		__be16  *sport, *dport;
		__sum16 *cksum;

		// TCP FIN and RST
		__u8 fin = 0, rst = 0;

		switch (iph->protocol) {
			case IPPROTO_TCP:;
				// Parse the TCP header, will drop the package if out-of-bounds
				parse_header(struct tcphdr, *tcph, p, data_end);

				BPF_DEBUG("TCP Source Port: %u", bpf_ntohs(tcph->source));
				BPF_DEBUG("TCP Destination Port: %u", bpf_ntohs(tcph->dest));

				c_key.src_port  = tcph->source;
				c_key.dest_port = tcph->dest;

				// For possible NAT adjustmenets
				sport = &tcph->source;
				dport = &tcph->dest;
				cksum = &tcph->check;

				// Save if connection is closed or reset
				fin = tcph->fin;
				rst = tcph->rst;
			break;

			case IPPROTO_UDP:;
				// Parse the UDP header, will drop the package if out-of-bounds
				parse_header(struct udphdr, *udph, p, data_end);

				BPF_DEBUG("UDP Source Port: %u", bpf_ntohs(udph->source));
				BPF_DEBUG("UDP Destination Port: %u", bpf_ntohs(udph->dest));

				c_key.src_port  = udph->source;
				c_key.dest_port = udph->dest;

				// For possible NAT adjustmenets
				sport = &udph->source;
				dport = &udph->dest;
				cksum = &udph->check;
			break;

			default:
				return BPF_PASS;
		}

		// Check if a conntrack entry exists
		struct conn_value* c_value = bpf_map_lookup_elem(&CONN_MAP, &c_key);
		if (!c_value) {
			// If there is none, create a new one
			struct conn_value c_value = {};
			bpf_map_update_elem(&CONN_MAP, &c_key, &c_value, BPF_NOEXIST);

			return BPF_PASS;
		}

		// Pass the package to the network stack if the connection is not yet or anymore established
		if (c_value->state != CONN_ESTABLISHED)
			return BPF_PASS;

		if (fin) {
			// Mark the connection as finished
			c_value->state  = CONN_FIN;
			c_value->update = 1;

			BPF_INFO("Connection will be closed");

			return BPF_PASS;
		}

		if (rst) {
			// Mark the connection as finished
			c_value->state  = CONN_FIN;
			c_value->update = 1;

			// Also mark the connection as finished for the reverse direction, if there is one
			reverse_conn_key(&c_key);

			c_value = bpf_map_lookup_elem(&CONN_MAP, &c_key);
			if (c_value) {
				c_value->state  = CONN_FIN;
				c_value->update = 1;
			}

			BPF_INFO("Connection was reset");

			return BPF_PASS;
		}

		BPF_DEBUG("Connection is established");

		// If a routing decision hasn't been made yet (first package), do it now
		if (!c_value->action)
			make_routing_decision(ctx, iph, &c_key, c_value);

		switch (c_value->action) {
			case ACTION_REDIRECT:
				// Pass the package to the network stack if the TTL expired
				if (iph->ttl <= 1)
					return BPF_PASS;

				// Decrement the TTL, adjust the checksum
				iph->ttl--;
				cksum_add(&iph->check, c_value->l3_cksum_diff);

				// Apply NAT
				apply_nat(&c_value->n_entry, iph, sport, dport, cksum);

				// Tell the user-space program to update the conntrack timeout
				c_value->update = 1;

				// Redirect the package
				return redirect_package(ethh, &c_value->next_h);

			case ACTION_DROP:
				return BPF_DROP;

			case ACTION_PASS:
			default:
				return BPF_PASS;
		}
	}

    return BPF_PASS;
}

char _license[] SEC("license") = "GPL";
