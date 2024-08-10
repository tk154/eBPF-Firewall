#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define BPFW_LOG_LEVEL BPFW_LOG_LEVEL_WARN
#include "common_kern.h"

#include "dsa.h"
#include "parse_header.h"
#include "push_header.h"
#include "mangle.h"


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} FLOW_MAP SEC(".maps");


/**
 * Helper to swap the src and dest IP and the src and dest port of a flow key
 * @param f_key Pointer to the flow key
 * @param f_value Pointer to the flow value
 * **/
__always_inline static void reverse_flow_key(struct flow_key *f_key, struct flow_value *f_value) {
	__u8 temp_ip[IPV6_ALEN];

	ipcpy(temp_ip, f_value->next.nat.rewrite_flag & REWRITE_SRC_IP ?
		f_value->next.nat.src_ip : f_key->src_ip, f_key->family);

	ipcpy(f_key->src_ip, f_value->next.nat.rewrite_flag & REWRITE_DEST_IP ?
		f_value->next.nat.dest_ip : f_key->dest_ip, f_key->family);

	ipcpy(f_key->dest_ip, temp_ip, f_key->family);

	__be16 temp_port  = f_value->next.nat.rewrite_flag & REWRITE_SRC_PORT ?
					   f_value->next.nat.src_port : f_key->src_port;

	f_key->src_port  = f_value->next.nat.rewrite_flag & REWRITE_DEST_PORT ?
					   f_value->next.nat.dest_port : f_key->dest_port;

	f_key->dest_port = temp_port;

	f_key->ifindex  = f_value->next.hop.ifindex;
	f_key->dsa_port = f_value->next.hop.dsa_port;
	f_key->vlan_id  = f_value->next.hop.vlan_id;
	f_key->pppoe_id = f_value->next.hop.pppoe_id;
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

	bpfw_info_key(flags.fin ? "FIN" : "RST", f_key);

	return true;
}


/**
 * Entry point of the BPF program executed when a new package is received on the hook
 * @param ctx The package contents and some metadata. Type is xdp_md for XDP and __sk_buff for TC programs.
 * @returns The action to be executed on the received package
**/
__always_inline static __u8 bpfw_func(void *ctx, bool xdp, struct packet_data *pkt, __u32 *out_ifindex) {
	bpfw_debug("---------- New Package ----------");

	struct l2_header l2;
	if (!parse_l2_header(ctx, xdp, pkt, &l2))
		return ACTION_PASS;

	struct l3_header l3;
	if (!parse_l3_header(pkt, l2.proto, &l3))
		return ACTION_PASS;

	struct l4_header l4;
	if (!parse_l4_header(pkt, l3.proto, &l4))
		return ACTION_PASS;

	// Fill the flow key
	struct flow_key f_key = {};
	f_key.ifindex = pkt->ifindex;
	f_key.vlan_id = l2.vlan_id;
	f_key.pppoe_id = l2.pppoe_id;
	f_key.src_port = *l4.sport;
	f_key.dest_port = *l4.dport;
	f_key.dsa_port = l2.dsa_port;
	f_key.family = l3.family;
	f_key.proto = l3.proto;

	ipcpy(f_key.src_ip, l3.src_ip, l3.family);
	ipcpy(f_key.dest_ip, l3.dest_ip, l3.family);

	// Check if a conntrack entry exists
	struct flow_value* f_value = bpf_map_lookup_elem(&FLOW_MAP, &f_key);
	if (!f_value) {
		bpfw_info_key("NEW", &f_key);

		// If there is none, create a new one
		struct flow_value f_value = {};
		memcpy(f_value.src_mac, l2.src_mac, ETH_ALEN);

		long rc = bpf_map_update_elem(&FLOW_MAP, &f_key, &f_value, BPF_NOEXIST);
		if (rc != 0)
			bpfw_warn("bpf_map_update_elem error: %d", rc);

		return ACTION_PASS;
	}

	// Reset the timeout
	f_value->idle = 0;

	switch (f_value->action) {
		case ACTION_REDIRECT:
			// Pass the package to the network stack if 
			// there is a FIN or RST or the TTL expired
			if (tcp_finished(&f_key, f_value, l4.tcp_flags) || *l3.ttl <= 1)
				return ACTION_PASS;

			mangle_packet(&l3, &l4, &f_value->next);

			if (!push_l2_header(ctx, xdp, pkt, &l2, &f_value->next.hop))
				return ACTION_DROP;

			bpfw_debug("Redirect to ifindex %u", f_value->next.hop.ifindex);
			*out_ifindex = f_value->next.hop.ifindex;

			break;

		case ACTION_DROP:
			bpfw_debug("Drop package");
			break;

		case ACTION_PASS:
		default:
			bpfw_debug("Pass package");
	}

	return f_value->action;
}


SEC("xdp")
int bpfw_xdp(struct xdp_md *xdp_md) {
	// Save pointer to the first and last Byte of the received package
	struct packet_data pkt = {
		.ifindex  = xdp_md->ingress_ifindex,
		.data 	  = (void*)(long)xdp_md->data,
		.data_end = (void*)(long)xdp_md->data_end,
		.p 		  = (void*)(long)xdp_md->data
	};

	__u32 out_ifindex;
	__u8 action = bpfw_func(xdp_md, true, &pkt, &out_ifindex);

	switch (action) {
		case ACTION_REDIRECT:
			if (pkt.ifindex == out_ifindex)
				return XDP_TX;

			return bpf_redirect(out_ifindex, 0);

		case ACTION_DROP:
			return XDP_DROP;

		case ACTION_PASS:
		default:
			return XDP_PASS;
	}
}

SEC("tc")
int bpfw_tc(struct __sk_buff *skb) {
	// Save pointer to the first and last Byte of the received package
	struct packet_data pkt = {
		.ifindex  = skb->ingress_ifindex,
		.data 	  = (void*)(long)skb->data,
		.data_end = (void*)(long)skb->data_end,
		.p 		  = (void*)(long)skb->data
	};

	__u32 out_ifindex;
	__u8 action = bpfw_func(skb, false, &pkt, &out_ifindex);

	switch (action) {
		case ACTION_REDIRECT:
			return bpf_redirect(out_ifindex, 0);

		case ACTION_DROP:
			return TC_ACT_SHOT;

		case ACTION_PASS:
		default:
			return TC_ACT_UNSPEC;
	}
}

char _license[] SEC("license") = "GPL";
