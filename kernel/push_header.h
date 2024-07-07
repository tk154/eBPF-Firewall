#ifndef BPFW_PUSH_HEADER_H
#define BPFW_PUSH_HEADER_H

#include "common_kern.h"


#define prev_proto(data) *(__be16*)(data - sizeof(__be16))

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

__always_inline static bool adjust_l2_size(struct BPFW_CTX *ctx, struct packet_data *pkt, __s8 diff) {
	if (!diff)
		return true;

#if defined(XDP_PROGRAM)
	long rc = bpf_xdp_adjust_head(ctx, -diff);
	if (rc != 0) {
		BPF_ERROR("bpf_xdp_adjust_head error: %d", rc);
		return false;
	}

#elif defined(TC_PROGRAM)
	long rc = bpf_skb_change_head(ctx, diff, 0);
	if (rc != 0) {
		BPF_ERROR("bpf_skb_change_head error: %d", rc);
		return false;
	}
#endif

	pkt->data 	   = (void*)(long)ctx->data;
	pkt->data_end  = (void*)(long)ctx->data_end;

#ifndef BPFW_DSA
	if (pkt->data + sizeof(struct ethhdr) > pkt->data_end)
		return false;
#endif

	return true;
}

/**
 * Rewrite the Ethernet header and redirect the package to the next hop
 * @param ethh The Ethernet header to rewrite
 * @param next_h The source and destination MAC and ifindex for the next hop
 * @returns BPF_REDIRECT on success, BPF_DROP otherwise
 * **/
__always_inline static bool set_eth_header(struct packet_data *pkt, struct next_hop *next_h) {
#ifdef BPFW_DSA
	if (next_h->dsa_port) {
		if (pkt->p + sizeof(struct ethhdr_dsa_tx) > pkt->data_end)
			return false;

		struct ethhdr_dsa_tx *ethh = pkt->p;

		__u8 dsa_port = next_h->dsa_port & ~DSA_PORT_SET;
		ethh->dsa_tag = dsa_get_tag(dsa_port);

		// Adjust the MAC addresses
		memcpy(ethh->h_source, next_h->src_mac,  ETH_ALEN);
		memcpy(ethh->h_dest,   next_h->dest_mac, ETH_ALEN);

		BPF_DEBUG("DSA Port: %u", dsa_port);
		BPF_DEBUG_MAC("Dst MAC: ", next_h->dest_mac);

		pkt->p += sizeof(struct ethhdr_dsa_tx);
		return true;
	}

	if (pkt->p + sizeof(struct ethhdr) > pkt->data_end)
		return false;
#endif

	struct ethhdr *ethh = pkt->p;

	// Adjust the MAC addresses
	memcpy(ethh->h_source, next_h->src_mac,  ETH_ALEN);
	memcpy(ethh->h_dest,   next_h->dest_mac, ETH_ALEN);

	BPF_DEBUG_MAC("Dst MAC: ", next_h->dest_mac);

	pkt->p += sizeof(struct ethhdr);
	return true;
}

__always_inline static bool tc_vlan_recheck_pointer(struct BPFW_CTX *ctx, struct packet_data *pkt) {
	pkt->data     = (void*)(long)ctx->data;
	pkt->data_end = (void*)(long)ctx->data_end;
	pkt->p		  = pkt->data + sizeof(struct ethhdr);

	return pkt->p <= pkt->data_end;
}

__always_inline static bool check_vlan_header(struct BPFW_CTX *ctx, struct packet_data *pkt, struct l2_header *l2, struct next_hop *next_h) {
	if (!l2->vlan_id && next_h->vlan_id) {
		BPF_DEBUG("Add VLAN Tag %u", next_h->vlan_id);

#ifdef TC_PROGRAM
#ifdef BPFW_DSA
		if (next_h->ifindex != dsa_switch)
#endif
		{
			int rc = bpf_skb_vlan_push(ctx, ETH_P_8021Q, next_h->vlan_id);
			if (rc != 0) {
				BPF_ERROR("bpf_skb_vlan_push error: %d", rc);
				return false;
			}

			if (!tc_vlan_recheck_pointer(ctx, pkt))
				return false;

			return true;
		}
#endif
#if defined(XDP_PROGRAM) || defined(BPFW_DSA)
		if (pkt->p + sizeof(struct vlanhdr) > pkt->data_end)
			return false;

		struct vlanhdr *vlan_h = pkt->p;
		vlan_h->tci = bpf_htons(next_h->vlan_id);
		vlan_h->proto = l2->proto;

		prev_proto(pkt->p) = bpf_htons(ETH_P_8021Q);
		pkt->p += sizeof(struct vlanhdr);
#endif
	}

	else if (l2->vlan_id && !next_h->vlan_id) {
		BPF_DEBUG("Remove VLAN Tag");

#ifdef TC_PROGRAM
#ifdef BPFW_DSA
		if (ctx->ingress_ifindex != dsa_switch)
#endif
		{
			int rc = bpf_skb_vlan_pop(ctx);
			if (rc != 0) {
				BPF_ERROR("bpf_skb_vlan_pop error: %d", rc);
				return false;
			}

			if (!tc_vlan_recheck_pointer(ctx, pkt))
				return false;

			return true;
		}
#endif
#if defined(XDP_PROGRAM) || defined(BPFW_DSA)
		prev_proto(pkt->p) = l2->proto;
#endif
	}

	return true;
}

__always_inline static bool check_pppoe_header(struct packet_data *pkt, struct l2_header *l2, __be16 next_hop_pppoe) {
    if (l2->pppoe_id && !next_hop_pppoe) {
		BPF_DEBUG("Remove PPPoE Header");

		prev_proto(pkt->p) = l2->proto;
    }
    else if (l2->pppoe_id != next_hop_pppoe) {
		BPF_DEBUG("Add PPPoE ID 0x%x", next_hop_pppoe);

		if (pkt->p + sizeof(struct pppoehdr) > pkt->data_end)
			return false;

        struct pppoehdr *pppoe_h = pkt->p;
        pppoe_h->vertype = 0x11;
		pppoe_h->code = 0x00;
		pppoe_h->sid = next_hop_pppoe;
		pppoe_h->length = bpf_htons(l2->payload_len + sizeof(pppoe_h->proto));
		pppoe_h->proto = proto_eth2ppp(l2->proto);

		prev_proto(pkt->p) = bpf_htons(ETH_P_PPP_SES);
		pkt->p += sizeof(struct pppoehdr);
    }

    return true;
}

__always_inline static bool push_l2_header(struct BPFW_CTX *ctx, struct packet_data *pkt, struct l2_header* l2, struct next_hop *next_h) {
    if (!adjust_l2_size(ctx, pkt, next_h->l2_diff))
        return false;
		
    pkt->p = pkt->data;

    if (!set_eth_header(pkt, next_h))
		return false;

    if (!check_vlan_header(ctx, pkt, l2, next_h))
        return false;

    if (!check_pppoe_header(pkt, l2, next_h->pppoe_id))
        return false;

    return true;
}


#endif
