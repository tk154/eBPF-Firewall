#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define BPFW_LOG_LEVEL BPFW_LOG_LEVEL_WARN
#include "common_kern.h"

#include "dsa/dsa.h"
#include "parse_header.h"
#include "push_header.h"
#include "mangle.h"


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
	__uint(max_entries, FLOW_MAP_DEFAULT_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} BPFW_FLOW_MAP SEC(".maps");

SEC(USERSPACE_TIME_SECTION)
struct user_time user;


__always_inline static void *ipcpy_fill_zeros(void *dest, const void* src, __u8 family) {
    switch (family) {
        case AF_INET:
			memset(dest + IPV4_ALEN, 0, IPV6_ALEN - IPV4_ALEN);
            return memcpy(dest, src, IPV4_ALEN);

        case AF_INET6:
            return memcpy(dest, src, IPV6_ALEN);

		default:
			return NULL;
    }
}

/**
 * Helper to swap the src and dest IP and the src and dest port of a flow key
 * @param f_key Pointer to the flow key
 * @param f_value Pointer to the flow value
 * **/
__always_inline static void reverse_flow_key(struct flow_key *f_key, struct next_entry *next) {
	f_key->ifindex  = next->hop.ifindex;
	f_key->dsa_port = next->hop.dsa_port;
	f_key->vlan_id  = next->hop.vlan_id;
	f_key->pppoe_id = next->hop.pppoe_id;

	ipcpy(f_key->src_ip, next->nat.rewrite_flag & REWRITE_DEST_IP ?
		next->nat.dest_ip : f_key->dest_ip, f_key->family);
	ipcpy(f_key->dest_ip, next->nat.rewrite_flag & REWRITE_SRC_IP ?
		next->nat.src_ip : f_key->src_ip, f_key->family);
	
	f_key->src_port  = next->nat.rewrite_flag & REWRITE_DEST_PORT ?
					   next->nat.dest_port : f_key->dest_port;
	f_key->dest_port = next->nat.rewrite_flag & REWRITE_SRC_PORT ?
					   next->nat.src_port : f_key->src_port;
}

__always_inline static bool tcp_finished(struct flow_key *f_key, struct flow_value *f_value, struct tcphdr_flags tcp_flags) {
	if (f_key->proto != IPPROTO_TCP)
		return false;

	if (tcp_flags.fin) {
		// Mark the flow as finished
		f_value->state = STATE_NONE;
		bpfw_info_key("FIN", f_key);

		return true;
	}

	if (tcp_flags.rst) {
		// Mark the flow as finished
		f_value->state = STATE_NONE;

		// Also mark the flow as finished for the reverse direction, if there is one
		reverse_flow_key(f_key, &f_value->next);

		f_value = bpf_map_lookup_elem(&BPFW_FLOW_MAP, f_key);
		if (f_value)
			f_value->state = STATE_NONE;

		bpfw_info_key("RST", f_key);

		return true;
	}

	return false;
}

__always_inline static void fill_flow_key(struct flow_key *f_key, __u32 ifindex, struct packet_header *header) {
	f_key->ifindex = ifindex;

	f_key->dsa_port = header->l2.dsa_port;
	f_key->vlan_id  = header->l2.vlan_id;
	f_key->pppoe_id = header->l2.pppoe_id;
	
	f_key->family = header->l3.family;
	ipcpy_fill_zeros(f_key->src_ip, header->l3.src_ip, header->l3.family);
	ipcpy_fill_zeros(f_key->dest_ip, header->l3.dest_ip, header->l3.family);

	f_key->proto = header->l3.proto;
	f_key->src_port = *header->l4.src_port;
	f_key->dest_port = *header->l4.dest_port;

	f_key->__pad = 0;
}

__always_inline static long create_new_flow_entry(struct flow_key *f_key, __u64 curr_time, void *src_mac) {
	bpfw_info_key("NEW", f_key);

	struct flow_value f_value;
	f_value.state = STATE_NEW_FLOW;
	f_value.time = curr_time;

	memcpy(f_value.src_mac, src_mac, ETH_ALEN);
	memset(&f_value.next, 0, sizeof(f_value.next));

	long rc = bpf_map_update_elem(&BPFW_FLOW_MAP, f_key, &f_value, BPF_NOEXIST);
	if (rc != 0)
		bpfw_warn("bpf_map_update_elem error: %d", rc);

	return rc;
}


/**
 * Entry point of the BPF program executed when a new package is received on the hook
 * @param ctx The package contents and some metadata. Type is xdp_md for XDP and __sk_buff for TC programs.
 * @returns The action to be executed on the received package
**/
__always_inline static __u8 bpfw_func(void *ctx, bool xdp, struct packet_data *pkt) {
	__u64 curr_time = bpf_ktime_get_coarse_ns();
	if (curr_time - user.last_time >= user.timeout) {
		bpfw_warn("Userspace program doesn't respond anymore.");
		return ACTION_PASS;
	}

	bpfw_debug("---------- New Package ----------");

	struct packet_header header;
	if (!parse_l2_header(ctx, xdp, pkt, &header.l2))
		return ACTION_PASS;

	if (!parse_l3_header(pkt, header.l2.proto, &header.l3))
		return ACTION_PASS;

	if (!parse_l4_header(pkt, header.l3.proto, &header.l4))
		return ACTION_PASS;

	// Fill the flow key
	struct flow_key f_key;
	fill_flow_key(&f_key, pkt->in_ifindex, &header);

	// Check if a flowtrack entry exists
	struct flow_value* f_value = bpf_map_lookup_elem(&BPFW_FLOW_MAP, &f_key);
	if (!f_value) {
		// If there is none, create a new one
		create_new_flow_entry(&f_key, curr_time, header.l2.src_mac);
		return ACTION_PASS;
	}

	// Reset the timeout
	f_value->time = curr_time;

	switch (f_value->state) {
		case STATE_FORWARD:
			// Pass the package to the network stack if 
			// there is a FIN or RST or the TTL expired
			if (tcp_finished(&f_key, f_value, header.l4.tcp_flags))
				return ACTION_PASS;

			mangle_packet(&header.l3, &header.l4, &f_value->next);

			if (!push_l2_header(ctx, xdp, pkt, &header.l2, &f_value->next.hop))
				return ACTION_DROP;

			pkt->out_ifindex = f_value->next.hop.ifindex;
			bpfw_debug("Redirect to ifindex %u", pkt->out_ifindex);

			break;

		case STATE_DROP:
			bpfw_debug("Drop package");
			break;

		case STATE_PASS:
		default:
			bpfw_debug("Pass package");
	}

	return f_value->state;
}


#ifndef BPFW_NO_XDP
SEC("xdp")
int BPFW_XDP_PROG(struct xdp_md *xdp_md) {
	// Save pointer to the first and last Byte of the received package
	struct packet_data pkt = {
		.in_ifindex = xdp_md->ingress_ifindex,
		.data 	  	= (void*)(long)xdp_md->data,
		.data_end 	= (void*)(long)xdp_md->data_end,
		.p 		  	= (void*)(long)xdp_md->data
	};

	__u8 action = bpfw_func(xdp_md, true, &pkt);
	switch (action) {
		case ACTION_FORWARD:
			if (pkt.in_ifindex == pkt.out_ifindex)
				return XDP_TX;

			return bpf_redirect(pkt.out_ifindex, 0);

		case ACTION_DROP:
			return XDP_DROP;

		case ACTION_PASS:
		default:
			return XDP_PASS;
	}
}
#endif

#ifndef BPFW_NO_TC
SEC("tc")
int BPFW_TC_PROG(struct __sk_buff *skb) {
	// Save pointer to the first and last Byte of the received package
	struct packet_data pkt = {
		.in_ifindex = skb->ingress_ifindex,
		.data 	  	= (void*)(long)skb->data,
		.data_end 	= (void*)(long)skb->data_end,
		.p 		  	= (void*)(long)skb->data
	};

	__u8 action = bpfw_func(skb, false, &pkt);
	switch (action) {
		case ACTION_FORWARD:
			return bpf_redirect(pkt.out_ifindex, 0);

		case ACTION_DROP:
			return TC_ACT_SHOT;

		case ACTION_PASS:
		default:
			return TC_ACT_UNSPEC;
	}
}
#endif

char _license[] SEC("license") = "GPL";
