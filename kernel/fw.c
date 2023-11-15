#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DEBUG 1
#include "common_xdp_tc.h"
#include "../common.h"


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conntrack_key);
	__type(value, conntrack_state);
	__uint(max_entries, 1024);
	//__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} CONNTRACK_MAP SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct nat_key);
	__type(value, struct nat_value);
	__uint(max_entries, 128);
	//__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} NAT_MAP SEC(".maps");


// Declare the VLAN header struct manually since it is not included in my <linux/if_vlan.h>
struct vlan_hdr {
	__be16 h_vlan_TCI;					// priority and VLAN ID
	__be16 h_vlan_encapsulated_proto;	// packet type ID or len
};


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

		switch (iph->protocol) {
			case IPPROTO_TCP:;
				// Parse the TCP header, will drop the package if out-of-bounds
				parse_header(struct tcphdr, *tcph, p, data_end);

				sport = tcph->source;
				dport = tcph->dest;
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
		}

		// Print some package information
		BPF_DEBUG("---------- New Package ----------");
		BPF_DEBUG("VLAN ID: %u", vlan_id);
		BPF_DEBUG_IP("Source IP: ", iph->saddr);
		BPF_DEBUG_IP("Destination IP: ", iph->daddr);
		BPF_DEBUG("Source Port: %u", bpf_htons(sport));
		BPF_DEBUG("Destination Port: %u", bpf_htons(dport));

		// Fill the conntrack key
		struct conntrack_key ct_key = {};
		ct_key.src_ip    = iph->saddr;
		ct_key.dest_ip   = iph->daddr;
		ct_key.src_port  = sport;
		ct_key.dest_port = dport;
		ct_key.protocol  = iph->protocol;

		// Check if a conntrack entry exists
		conntrack_state* state = bpf_map_lookup_elem(&CONNTRACK_MAP, &ct_key);
		if (state) {
			BPF_DEBUG("Connection entry exists");
			if (iph->protocol == IPPROTO_TCP)
				BPF_DEBUG("TCP connection state is: %u", *state);
		}


		// Fill the NAT key
		struct nat_key n_key = {};
		n_key.ifindex   = ctx->ingress_ifindex;
		n_key.src_ip    = iph->saddr;
		n_key.dest_ip   = iph->daddr;
		n_key.src_port  = sport;
		n_key.dest_port = dport;
		n_key.vlan_id   = vlan_id;
		n_key.protocol  = iph->protocol;
		memcpy(n_key.src_mac, ethh->h_source, sizeof(n_key.src_mac));
		memcpy(n_key.dest_mac, ethh->h_dest, sizeof(n_key.dest_mac));

		// Check if a NAT entry exists
		struct nat_value* nat_entry = bpf_map_lookup_elem(&NAT_MAP, &n_key);
		if (nat_entry) {
			BPF_DEBUG("NAT entry exists");
			BPF_DEBUG_IP("Source IP: ", nat_entry->src_ip);
			BPF_DEBUG_IP("Destination IP: ", nat_entry->dest_ip);
			BPF_DEBUG("Source Port: %u", bpf_htons(nat_entry->src_port));
			BPF_DEBUG("Destination Port: %u", bpf_htons(nat_entry->dest_port));
		}
	}

    return BPF_PASS;
}

char _license[] SEC("license") = "GPL";
