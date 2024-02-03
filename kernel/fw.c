#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define BPF_LOG_LEVEL BPF_LOG_LEVEL_INFO
#include "common_xdp_tc.h"
#include "../common.h"


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conn_key);
	__type(value, struct conn_value);
	__uint(max_entries, 1024);
	//__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} CONN_MAP SEC(".maps");


// Declare the VLAN header struct manually since it is not included in my <linux/if_vlan.h>
struct vlan_hdr {
	__be16 h_vlan_TCI;					// priority and VLAN ID
	__be16 h_vlan_encapsulated_proto;	// packet type ID or len
};


/**
 * Helper to swap the src and dest IP and the src and dest port of a connection key
 * @param c_key Pointer to the original connection key
 * @param rev_c_key Pointer where to store the reversed key
 * **/
void reverse_conn_key(struct conn_key *c_key, struct conn_key *rev_c_key) {
	rev_c_key->src_ip    = c_key->dest_ip;
	rev_c_key->dest_ip   = c_key->src_ip;
	rev_c_key->src_port  = c_key->dest_port;
	rev_c_key->dest_port = c_key->src_port;
	rev_c_key->protocol  = c_key->protocol;
}

/**
 * Use bpf_fib_lookup to decide wether to route the package and where to
 * @param ctx xdp_md for XDP and __sk_buff for TC programs
 * @param iph The IPv4 Header of the package
 * @param next_h Where to store the result, ifindex and MAC addresses
 * **/
__always_inline void make_routing_decision(struct BPF_CTX *ctx, struct iphdr* iph, struct next_hop* next_h) {
	// Fill the lookup key
	struct bpf_fib_lookup fib_params = {};
	fib_params.family = AF_INET;
	fib_params.l4_protocol = iph->protocol;
	fib_params.sport = 0;
	fib_params.dport = 0;
	fib_params.tot_len = bpf_ntohs(iph->tot_len);
	fib_params.tos = iph->tos;
	fib_params.ipv4_src = iph->saddr;
	fib_params.ipv4_dst = iph->daddr;
	fib_params.ifindex = ctx->ingress_ifindex;

	// Do a loopkup in the kernel routing table
	long rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	BPF_DEBUG("bpf_fib_lookup: %d", rc);
	BPF_DEBUG("ifindex: %d", fib_params.ifindex);

	switch (rc) { 
		case BPF_FIB_LKUP_RET_SUCCESS:      // lookup successful
			// Adjust the MAC addresses
			memcpy(next_h->smac, fib_params.smac, ETH_ALEN);
			memcpy(next_h->dmac, fib_params.dmac, ETH_ALEN);

			next_h->ifindex = fib_params.ifindex;
			next_h->action = ACTION_REDIRECT;
		break;

		case BPF_FIB_LKUP_RET_BLACKHOLE:    // dest is blackholed; can be dropped 
		case BPF_FIB_LKUP_RET_UNREACHABLE:  // dest is unreachable; can be dropped 
		case BPF_FIB_LKUP_RET_PROHIBIT:     // dest not allowed; can be dropped 
			next_h->action = ACTION_DROP;
		break;

		case BPF_FIB_LKUP_RET_NOT_FWDED:    // packet is not forwarded 
		case BPF_FIB_LKUP_RET_FWD_DISABLED: // fwding is not enabled on ingress 
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:   // fwd requires encapsulation 
		case BPF_FIB_LKUP_RET_NO_NEIGH:     // no neighbor entry for nh
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:  // fragmentation required to fwd
			next_h->action = ACTION_PASS;
		break;
	}
}

/**
 * Forwards the data package to the next hop
 * @param ethh The Ethernet Header of the package
 * @param iph The IPv4 Header of the package
 * @param next_h Contains the ifindex and MAC addresses
 * @returns BPF_REDIRECT on success, BPF_DROP (XDP_ABORTED) if there was a error
 * **/
long redirect_package(struct ethhdr* ethh, struct iphdr* iph, struct next_hop* next_h) {
	// Decrement the TTL, adjust the checksum
	iph->ttl--;
	iph->check += 0x01;

	// Adjust the MAC addresses
	memcpy(ethh->h_source, next_h->smac, ETH_ALEN);
	memcpy(ethh->h_dest,   next_h->dmac, ETH_ALEN);

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
	// Save the first and last Byte of the received package
	void* data 	   = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;

	// A pointer to save the cuurent position inside the package
	void* p = data;

	// Parse the Ethernet header, will drop the package if out-of-bounds
	parse_header(struct ethhdr, *ethh, p, data_end);

	// Save the packet type ID, default to no VLAN ID
    __be16 h_proto = ethh->h_proto;
    __u16 vlan_id = 0;

	// Check if there is a VLAN header
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
		// Parse the VLAN header, will drop the package if out-of-bounds
		parse_header(struct vlan_hdr, *vlan_h, p, data_end);

		// Save the VLAN ID (last 12 Byte)
        vlan_id = bpf_htons(vlan_h->h_vlan_TCI) & 0x0FFF;

		// Save the packet type ID of the next header
		h_proto = vlan_h->h_vlan_encapsulated_proto;
    }

	if (h_proto == bpf_htons(ETH_P_IP)) {
		// Parse the IPv4 header, will drop the package if out-of-bounds
		parse_header(struct iphdr, *iph, p, data_end);

		// Save the source and destination port if there is a TCP or UDP header
		__be16 sport = 0, dport = 0;
		__u8 fin = 0, rst = 0;

		switch (iph->protocol) {
			case IPPROTO_TCP:;
				// Parse the TCP header, will drop the package if out-of-bounds
				parse_header(struct tcphdr, *tcph, p, data_end);

				sport = tcph->source;
				dport = tcph->dest;

				fin = tcph->fin;
				rst = tcph->rst;
			break;

			case IPPROTO_UDP:;
				// Parse the UDP header, will drop the package if out-of-bounds
				parse_header(struct udphdr, *udph, p, data_end);

				sport = udph->source;
				dport = udph->dest;
			break;

			case IPPROTO_ICMP:;
				// Parse the ICMP header, will drop the package if out-of-bounds
				parse_header(struct icmphdr, *icmph, p, data_end);

				/* Nothing to do here yet */
				BPF_UNUSED(icmph);
			break;

			default:
				BPF_DEBUG("Protocol %u not implemented yet.", iph->protocol);
				return BPF_PASS;
		}

		// Print some package information
		BPF_DEBUG("---------- New Package ----------");
		BPF_DEBUG("VLAN ID: %u", vlan_id);
		BPF_DEBUG_IP("Source IP: ", iph->saddr);
		BPF_DEBUG_IP("Destination IP: ", iph->daddr);
		BPF_DEBUG("Source Port: %u", bpf_htons(sport));
		BPF_DEBUG("Destination Port: %u", bpf_htons(dport));

		// Fill the conntrack key
		struct conn_key c_key = {};
		c_key.src_ip    = iph->saddr;
		c_key.dest_ip   = iph->daddr;
		c_key.src_port  = sport;
		c_key.dest_port = dport;
		c_key.protocol  = iph->protocol;

		// Check if a conntrack entry exists
		struct conn_value* c_value = bpf_map_lookup_elem(&CONN_MAP, &c_key);
		if (!c_value) {
			// If there is none, create a new one
			struct conn_value c_value = {};
			bpf_map_update_elem(&CONN_MAP, &c_key, &c_value, BPF_NOEXIST);

			return BPF_PASS;
		}

		if (fin) {
			// Mark the connection as finished
			c_value->ct_entry.state = CONN_FIN;
			BPF_DEBUG("Connection will be closed");

			return BPF_PASS;
		}

		if (rst) {
			// Mark the connection as finished
			c_value->ct_entry.state = CONN_FIN;

			// Also mark the connection as finished for the reverse direction, if there is one
			struct conn_key rev_c_key = {};
			reverse_conn_key(&c_key, &rev_c_key);

			struct conn_value* rev_c_value = bpf_map_lookup_elem(&CONN_MAP, &rev_c_key);
			if (rev_c_value)
				rev_c_value->ct_entry.state = CONN_FIN;

			BPF_DEBUG("Connection was reset");

			return BPF_PASS;
		}

		// Pass the package to the network stack if the connection is not yet or anymore established
		if (c_value->ct_entry.state != CONN_ESTABLISHED)
			return BPF_PASS;

		BPF_DEBUG("Connection is established");

		if (!c_value->next_h.action)
			make_routing_decision(ctx, iph, &c_value->next_h);

		switch (c_value->next_h.action) {
			case ACTION_REDIRECT:
				// Pass the package to the network stack if the TTL expired
				if (iph->ttl <= 1)
					return BPF_PASS;

				// Adjust the packet counter
				c_value->ct_entry.packets++;
				c_value->ct_entry.bytes += data_end - data;

				BPF_DEBUG("Redirect package");

				return redirect_package(ethh, iph, &c_value->next_h);

			case ACTION_DROP:
				return BPF_DROP;

			case ACTION_PASS:
				// BPF_PASS
				break;
		}
	}

    return BPF_PASS;
}

char _license[] SEC("license") = "GPL";
