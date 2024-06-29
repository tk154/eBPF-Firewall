#ifndef BPFW_PUSH_HEADER_H
#define BPFW_PUSH_HEADER_H

#include "common_kern.h"


#define prev_proto(data) *(__be16*)(data - sizeof(__be16))

__always_inline static __s8 calc_l2_diff(struct flow_key *f_key, struct next_hop *next_h) {
	__s8 diff = 0;

#ifdef BPFW_DSA
	if (next_h->dsa_port & DSA_PORT_SET)
		diff += sizeof(struct ethhdr_dsa_tx) - sizeof(struct ethhdr_dsa_rx);
	else
		diff += sizeof(struct ethhdr) - sizeof(struct ethhdr_dsa_rx);
#endif

#ifdef XDP_PROGRAM
	if (!f_key->vlan_id && next_h->vlan_id)
		diff += sizeof(struct vlanhdr);
	else if (f_key->vlan_id && !next_h->vlan_id)
		diff -= sizeof(struct vlanhdr);
#endif

	if (!f_key->pppoe_id && next_h->pppoe_id)
		diff += sizeof(struct pppoehdr);
	else if (f_key->pppoe_id && !next_h->pppoe_id)
		diff -= sizeof(struct pppoehdr);

	return diff;
}

__always_inline static bool adjust_l2_size(struct BPFW_CTX *ctx, __s8 diff, struct packet_data *pkt) {
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

/**
 * Rewrite the Ethernet header and redirect the package to the next hop
 * @param ethh The Ethernet header to rewrite
 * @param next_h The source and destination MAC and ifindex for the next hop
 * @returns BPF_REDIRECT on success, BPF_DROP otherwise
 * **/
__always_inline static bool set_ethhdr(struct packet_data *pkt, struct next_hop *next_h) {
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

__always_inline static bool check_vlan(struct BPFW_CTX *ctx, struct packet_data *pkt, __be16 proto, __u16 packet_vlan, __u16 next_hop_vlan) {
#if defined(XDP_PROGRAM)
    if (!packet_vlan && next_hop_vlan) {
        BPF_DEBUG("Add VLAN Tag %u", next_hop_vlan);

		if (pkt->p + sizeof(struct vlanhdr) > pkt->data_end)
			return false;

        struct vlanhdr *vlan_h = pkt->p;
        vlan_h->h_vlan_TCI = bpf_htons(next_hop_vlan);
        vlan_h->h_vlan_encapsulated_proto = proto;

		prev_proto(pkt->p) = bpf_htons(ETH_P_8021Q);
		pkt->p += sizeof(struct vlanhdr);
    }
    else if (packet_vlan && !next_hop_vlan) {
        BPF_DEBUG("Remove VLAN Tag");

		prev_proto(pkt->p) = proto;
    }

#elif defined(TC_PROGRAM)
    if (!packet_vlan && next_hop_vlan) {
        BPF_DEBUG("Add VLAN Tag %u", next_hop_vlan);

        int rc = bpf_skb_vlan_push(ctx, ETH_P_8021Q, next_hop_vlan);
        if (rc != 0) {
            BPF_ERROR("bpf_skb_vlan_push error: %d", rc);
			return false;
        }

		pkt->data     = (void*)(long)ctx->data;
        pkt->data_end = (void*)(long)ctx->data_end;
		pkt->p		  = pkt->data + sizeof(struct ethhdr);

		if (pkt->p > pkt->data_end)
			return false;
    } 
    else if (packet_vlan && !next_hop_vlan) {
        BPF_DEBUG("Remove VLAN Tag");

        int rc = bpf_skb_vlan_pop(ctx);
        if (rc != 0) {
            BPF_ERROR("bpf_skb_vlan_pop error: %d", rc);
			return false;
        }

		pkt->data     = (void*)(long)ctx->data;
        pkt->data_end = (void*)(long)ctx->data_end;
		pkt->p		  = pkt->data + sizeof(struct ethhdr);

		if (pkt->p > pkt->data_end)
			return false;
    }
#endif

	return true;
}

__always_inline static bool check_pppoe(struct packet_data *pkt, __be16 proto, __u16 pppoe_len, __be16 packet_pppoe, __be16 next_hop_pppoe) {
    if (!packet_pppoe && next_hop_pppoe) {
		BPF_DEBUG("Add PPPoE ID 0x%x", next_hop_pppoe);

		if (pkt->p + sizeof(struct pppoehdr) > pkt->data_end)
			return false;

        struct pppoehdr *pppoe_h = pkt->p;
        pppoe_h->vertype = 0x11;
		pppoe_h->code = 0x00;
		pppoe_h->sid = next_hop_pppoe;
		pppoe_h->length = bpf_htons(pppoe_len);
		pppoe_h->proto = proto_eth2ppp(proto);

		prev_proto(pkt->p) = bpf_htons(ETH_P_PPP_SES);
		pkt->p += sizeof(struct pppoehdr);
    }
    else if (packet_pppoe && !next_hop_pppoe) {
		BPF_DEBUG("Remove PPPoE Header");

		prev_proto(pkt->p) = proto;
    }

    return true;
}

__always_inline static bool push_l2_header(struct BPFW_CTX *ctx, struct packet_data *pkt, __s8 l2_diff, struct l2_header* l2, struct next_hop *next_h) {
    if (l2_diff && !adjust_l2_size(ctx, l2_diff, pkt))
        return false;
		
    pkt->p = pkt->data;

    if (!set_ethhdr(pkt, next_h))
		return false;

    if (!check_vlan(ctx, pkt, l2->proto, l2->vlan_id, next_h->vlan_id))
        return false;

    if (!check_pppoe(pkt, l2->proto, l2->pppoe_len, l2->pppoe_id, next_h->pppoe_id))
        return false;

    return true;
}


#endif
