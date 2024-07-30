#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define BPF_LOG_LEVEL BPF_LOG_LEVEL_WARN
#include "common_kern.h"

#include "dsa.h"
#include "parse_header.h"
#include "push_header.h"
#include "mangle.h"

#ifndef FLOW_MAP_MAX_ENTRIES
#define FLOW_MAP_MAX_ENTRIES 1024
#endif


struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
	__uint(max_entries, FLOW_MAP_MAX_ENTRIES);
	//__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} FLOW_MAP SEC(".maps");


/**
 * Helper to swap the src and dest IP and the src and dest port of a flow key
 * @param f_key Pointer to the flow key
 * @param f_value Pointer to the flow value
 * **/
__always_inline static void reverse_flow_key(struct flow_key *f_key, struct flow_value *f_value) {
	__u8 src_ip[IPV6_ALEN];

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
	f_key->pppoe_id  = f_value->next_h.pppoe_id;

	memcpy(f_key->src_mac, f_value->next_h.dest_mac, ETH_ALEN);
}

__always_inline static bool tcp_finished(struct flow_key *f_key, struct flow_value *f_value, struct tcp_flags flags) {
	if (f_key->proto != IPPROTO_TCP || (!flags.fin && !flags.rst))
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


SEC("bpfw")
/**
 * Entry point of the BPF program executed when a new package is received on the hook
 * @param ctx The package contents and some metadata. Type is xdp_md for XDP and __sk_buff for TC programs.
 * @returns The action to be executed on the received package
**/
int fw_func(struct BPFW_CTX *ctx) {
	BPF_DEBUG("---------- New Package ----------");

	// Save pointer to the first and last Byte of the received package
	struct packet_data pkt = {
		.data 	  = (void*)(long)ctx->data,
		.data_end = (void*)(long)ctx->data_end,
		.p 		  = (void*)(long)ctx->data
	};

	struct l2_header l2;
	if (!parse_l2_header(ctx, &pkt, &l2))
		return BPFW_PASS;

	struct l3_header l3;
	if (!parse_l3_header(&pkt, l2.proto, &l3))
		return BPFW_PASS;

	struct l4_header l4;
	if (!parse_l4_header(&pkt, l3.proto, &l4))
		return BPFW_PASS;

	// Fill the flow key
	struct flow_key f_key = {};
	f_key.ifindex = ctx->ingress_ifindex;
	f_key.vlan_id = l2.vlan_id;
	f_key.pppoe_id = l2.pppoe_id;
	f_key.src_port = *l4.sport;
	f_key.dest_port = *l4.dport;
	f_key.dsa_port = l2.dsa_port;
	f_key.family = l3.family;
	f_key.proto = l3.proto;

	ipcpy(f_key.src_ip, l3.src_ip, l3.family);
	ipcpy(f_key.dest_ip, l3.dest_ip, l3.family);
	memcpy(f_key.src_mac, l2.src_mac, ETH_ALEN);

	// Check if a conntrack entry exists
	struct flow_value* f_value = bpf_map_lookup_elem(&FLOW_MAP, &f_key);
	if (!f_value) {
		BPF_LOG_KEY("NEW", &f_key);

		// If there is none, create a new one
		struct flow_value f_value = {};

		int rc = bpf_map_update_elem(&FLOW_MAP, &f_key, &f_value, BPF_NOEXIST);
		if (rc != 0)
			BPF_WARN("bpf_map_update_elem error: %d", rc);

		return BPFW_PASS;
	}

	// Reset the timeout
	f_value->idle = 0;

	switch (f_value->action) {
		case ACTION_REDIRECT:
			// Pass the package to the network stack if 
			// there is a FIN or RST or the TTL expired
			if (tcp_finished(&f_key, f_value, l4.tcp_flags) || *l3.ttl <= 1)
				return BPFW_PASS;

			mangle_packet(&l3, &l4, f_value);

			if (!push_l2_header(ctx, &pkt, &l2, &f_value->next_h))
				return BPFW_DROP;

			BPF_DEBUG("Redirect to ifindex %u", f_value->next_h.ifindex);

#ifdef XDP_PROGRAM
			if (ctx->ingress_ifindex == f_value->next_h.ifindex)
				return XDP_TX;
#endif
			// Redirect the package
			return bpf_redirect(f_value->next_h.ifindex, 0);

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
