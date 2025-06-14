#ifndef BPFW_PUSH_HEADER_H
#define BPFW_PUSH_HEADER_H

#include "common_kern.h"


#define prev_proto(data) (*((__be16 *)(data) - 1))

__always_inline static __be16 proto_eth2ppp(__be16 eth_proto) {
	switch (eth_proto) {
		case bpf_htons(ETH_P_IP):
			return bpf_htons(PPP_IP);
		case bpf_htons(ETH_P_IPV6):
			return bpf_htons(PPP_IPV6);
		default:
			return 0;
	}
}

__always_inline static bool tc_vlan_recheck_pointer(struct __sk_buff *skb, struct packet_data *pkt) {
	pkt->data     = (void*)(long)skb->data;
	pkt->data_end = (void*)(long)skb->data_end;
	pkt->p		  = pkt->data + sizeof(struct ethhdr);

	return pkt->p <= pkt->data_end;
}

__always_inline static bool pkt_vlan_push(struct packet_data *pkt, __u16 vlan_id, __be16 proto) {
	struct vlanhdr *vlan_h;
	check_header(vlan_h, pkt);

	vlan_h->tci = bpf_htons(vlan_id);
	vlan_h->proto = proto;

	prev_proto(vlan_h) = bpf_htons(ETH_P_8021Q);

	return true;
}

__always_inline static bool pkt_vlan_pop(struct packet_data *pkt, __be16 proto) {
	prev_proto(pkt->p) = proto;

	return true;
}

__always_inline static bool skb_vlan_push(struct __sk_buff *skb, struct packet_data *pkt, __u16 vlan_id) {
	long rc = bpf_skb_vlan_push(skb, ETH_P_8021Q, vlan_id);
	if (rc != 0) {
		bpfw_error("bpf_skb_vlan_push error: %d", rc);
		return false;
	}

	return tc_vlan_recheck_pointer(skb, pkt);
}

__always_inline static bool skb_vlan_pop(struct __sk_buff *skb, struct packet_data *pkt) {
	long rc = bpf_skb_vlan_pop(skb);
	if (rc != 0) {
		bpfw_error("bpf_skb_vlan_pop error: %d", rc);
		return false;
	}

	return tc_vlan_recheck_pointer(skb, pkt);
}

__always_inline static bool adjust_l2_size(void *ctx, bool xdp, struct packet_data *pkt, __s8 diff) {
	if (!diff)
		return true;

	if (xdp) {
		struct xdp_md *xdp_md = ctx;

		long rc = bpf_xdp_adjust_head(xdp_md, -diff);
		if (rc != 0) {
			bpfw_error("bpf_xdp_adjust_head error: %d", rc);
			return false;
		}

		pkt->data 	  = (void*)(long)xdp_md->data;
		pkt->data_end = (void*)(long)xdp_md->data_end;
	}
	else {
		struct __sk_buff *skb = ctx;

		long rc = bpf_skb_change_head(skb, diff, 0);
		if (rc != 0) {
			bpfw_error("bpf_skb_change_head error: %d", rc);
			return false;
		}

		pkt->data 	  = (void*)(long)skb->data;
		pkt->data_end = (void*)(long)skb->data_end;
	}

	return true;
}

/**
 * Rewrite the Ethernet header and redirect the package to the next hop
 * @param ethh The Ethernet header to rewrite
 * @param next_h The source and destination MAC and ifindex for the next hop
 * @returns BPF_REDIRECT on success, BPF_DROP otherwise
 * **/
__always_inline static bool set_eth_header(struct packet_data *pkt, struct next_hop *next_h) {
	struct ethhdr *ethh;

	if (next_h->dsa_port) {
		if (!push_dsa_header(pkt, next_h))
			return false;

		bpfw_debug("DSA Port: %u", next_h->dsa_port & ~DSA_PORT_SET);
	}
	else
		push_ethhdr(ethh, pkt, next_h);

	bpfw_debug_mac("Dst MAC: ", next_h->dest_mac);

	return true;
}

__always_inline static bool check_vlan_header(void *ctx, bool xdp, struct packet_data *pkt, struct l2_header *l2, struct next_hop *next_h) {
	if (!l2->vlan_id && !next_h->vlan_id)
		return true;

	if (l2->vlan_id && !next_h->vlan_id) {
		bpfw_debug("Remove VLAN Tag");

		if (xdp || l2->dsa_port)
			return pkt_vlan_pop(pkt, l2->proto);

		return skb_vlan_pop(ctx, pkt);
	}
	else if (!l2->vlan_id && next_h->vlan_id) {
		bpfw_debug("Add VLAN Tag %u", next_h->vlan_id);

		if (xdp || next_h->dsa_port)
			return pkt_vlan_push(pkt, next_h->vlan_id, l2->proto);

		return skb_vlan_push(ctx, pkt, next_h->vlan_id);
	}
	else if (l2->vlan_id != next_h->vlan_id) {
		bpfw_debug("Add VLAN Tag %u", next_h->vlan_id);

		if (xdp || l2->dsa_port) {
			if (!pkt_vlan_pop(pkt, l2->proto))
				return false;
		}
		else {
			if (!skb_vlan_pop(ctx, pkt))
				return false;
		}

		if (xdp || next_h->dsa_port) {
			if (!pkt_vlan_push(pkt, next_h->vlan_id, l2->proto))
				return false;
		}
		else {
			if (!skb_vlan_push(ctx, pkt, next_h->vlan_id))
				return false;
		}
	}
	else if (!xdp) {
		if (!l2->dsa_port && next_h->dsa_port) {
			if (!skb_vlan_pop(ctx, pkt))
				return false;

			return pkt_vlan_push(pkt, next_h->vlan_id, l2->proto);
		}
		else if (l2->dsa_port && !next_h->dsa_port) {
			if (!pkt_vlan_pop(pkt, l2->proto))
				return false;

			return skb_vlan_push(ctx, pkt, next_h->vlan_id);
		}
	}

	return true;
}

__always_inline static bool check_pppoe_header(struct packet_data *pkt, struct l2_header *l2, __be16 next_hop_pppoe) {
	struct pppoehdr *pppoe_h;

    if (l2->pppoe_id && !next_hop_pppoe) {
		bpfw_debug("Remove PPPoE Header");

		prev_proto(pkt->p) = l2->proto;
    }
    else if (l2->pppoe_id != next_hop_pppoe) {
		check_header(pppoe_h, pkt);

		if (!l2->pppoe_id && next_hop_pppoe) {
			pppoe_h->vertype = 0x11;
			pppoe_h->code = 0x00;
			pppoe_h->length = bpf_htons(l2->payload_len + sizeof(pppoe_h->proto));
			pppoe_h->proto = proto_eth2ppp(l2->proto);

			prev_proto(pppoe_h) = bpf_htons(ETH_P_PPP_SES);
		}

		bpfw_debug("Add PPPoE ID 0x%x", next_hop_pppoe);
		pppoe_h->sid = next_hop_pppoe;
    }

    return true;
}

__always_inline static bool push_l2_header(void *ctx, bool xdp, struct packet_data *pkt, struct l2_header* l2, struct next_hop *next_h) {
    if (!adjust_l2_size(ctx, xdp, pkt, next_h->l2_diff))
        return false;
		
    pkt->p = pkt->data;

    if (!set_eth_header(pkt, next_h))
		return false;

    if (!check_vlan_header(ctx, xdp, pkt, l2, next_h))
        return false;

    if (!check_pppoe_header(pkt, l2, next_h->pppoe_id))
        return false;

    return true;
}


#endif
