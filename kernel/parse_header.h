#ifndef BPFW_PARSE_HEADER_H
#define BPFW_PARSE_HEADER_H

#include <linux/if_ether.h>
#include <linux/ppp_defs.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <stdbool.h>
#include "common_kern.h"

#ifdef BPFW_DSA
#include "dsa.h"
#endif


// Helper macro to make the out-of-bounds check on a packet header and drop the package on failure
#define parse_header(header_type, header_ptr, pkt) \
    header_type header_ptr = pkt->p; \
	pkt->p += sizeof(header_type); \
    if (pkt->p > pkt->data_end) { \
        BPF_WARN(#header_type" > data_end"); \
        return false; \
    }


__always_inline static __be16 proto_ppp2eth(__be16 ppp_proto) {
	switch (ppp_proto) {
		case bpf_htons(PPP_IP):
			return bpf_htons(ETH_P_IP);
		case bpf_htons(PPP_IPV6):
			return bpf_htons(ETH_P_IPV6);
		default:
			return 0;
	}
}

__always_inline static bool parse_l2_header(struct BPFW_CTX *ctx, struct packet_data *pkt, struct l2_header *l2) {
	// Parse the Ethernet header, will drop the package if out-of-bounds
#ifdef BPFW_DSA
	if (ctx->ingress_ifindex == dsa_switch) {
		parse_header(struct ethhdr_dsa_rx, *ethh, pkt);

		l2->src_mac = ethh->h_source;
    	l2->proto = ethh->h_proto;
		l2->dsa_port = dsa_get_port(ethh->dsa_tag) | DSA_PORT_SET;
	}
	else
#endif
	{
		parse_header(struct ethhdr, *ethh, pkt);

		l2->src_mac = ethh->h_source;
		l2->proto = ethh->h_proto;
		l2->dsa_port = 0;
	}

    BPF_DEBUG_MAC("Src MAC: ", l2->src_mac);

	// Check if there is a VLAN header
#if defined(XDP_PROGRAM)
    if (l2->proto == bpf_htons(ETH_P_8021Q)) {
		// Parse the VLAN header, will drop the package if out-of-bounds
		parse_header(struct vlanhdr, *vlan_h, pkt);

		// Save the VLAN ID (last 12 Byte)
        l2->vlan_id = bpf_ntohs(vlan_h->h_vlan_TCI) & 0x0FFF;

		BPF_DEBUG("VLAN ID: %u", vlan_id);

		// Save the packet type ID of the next header
		l2->proto = vlan_h->h_vlan_encapsulated_proto;
    }
#elif defined(TC_PROGRAM)
	if (ctx->vlan_present && ctx->vlan_proto == bpf_htons(ETH_P_8021Q)) {
		// Save the VLAN ID (last 12 Byte)
        l2->vlan_id = ctx->vlan_tci & 0x0FFF;

		BPF_DEBUG("VLAN ID: %u", vlan_id);
	}
#endif
	else
		l2->vlan_id = 0;

	if (l2->proto == bpf_ntohs(ETH_P_PPP_SES)) {
		// Parse the PPPoE header, will drop the package if out-of-bounds
		parse_header(struct pppoehdr, *pppoe_h, pkt);

		l2->pppoe_id = pppoe_h->sid;

		BPF_DEBUG("PPPoE Session ID: 0x%x", l2->pppoe_id);

		l2->proto = proto_ppp2eth(pppoe_h->proto);
		if (!l2->proto) {
			BPF_DEBUG("PPPoE Protocol: 0x%04x", pppoe_h->proto);
			return false;
		}
	}
	else
		l2->pppoe_id = 0;

	l2->pppoe_len = pkt->data_end - pkt->p + sizeof(((struct pppoehdr*)0)->proto);

    return true;
}

__always_inline static bool parse_l3_header(struct packet_data *pkt, __be16 proto, struct l3_header *l3) {
	switch (proto) {
		case bpf_ntohs(ETH_P_IP):;
			// Parse the IPv4 header, will drop the package if out-of-bounds
			parse_header(struct iphdr, *iph, pkt);

			BPF_DEBUG_IPV4("Src IPv4: ", &iph->saddr);
			BPF_DEBUG_IPV4("Dst IPv4: ", &iph->daddr);

			l3->family	= AF_INET;
			l3->src_ip 	= &iph->saddr;
			l3->dest_ip = &iph->daddr;

			l3->proto   = iph->protocol;
			l3->ttl 	= &iph->ttl;
			l3->cksum   = &iph->check;
		break;

		case bpf_ntohs(ETH_P_IPV6):;
			// Parse the IPv4 header, will drop the package if out-of-bounds
			parse_header(struct ipv6hdr, *ipv6h, pkt);

			BPF_DEBUG_IPV6("Src IPv6: ", &ipv6h->saddr);
			BPF_DEBUG_IPV6("Dst IPv6: ", &ipv6h->daddr);

			l3->family	= AF_INET6;
			l3->src_ip  = &ipv6h->saddr;
			l3->dest_ip = &ipv6h->daddr;

			l3->proto   =  ipv6h->nexthdr;
			l3->ttl     = &ipv6h->hop_limit;
		break;

		default:
			BPF_DEBUG("Ethernet Protocol: 0x%04x", proto);
			return false;
	}

    return true;
}

__always_inline static bool parse_l4_header(struct packet_data *pkt, __be16 proto, struct l4_header *l4) {
	switch (proto) {
		case IPPROTO_TCP:;
			// Parse the TCP header, will drop the package if out-of-bounds
			parse_header(struct tcphdr, *tcph, pkt);

			BPF_DEBUG("TCP Src Port: %u", bpf_ntohs(tcph->source));
			BPF_DEBUG("TCP Dst Port: %u", bpf_ntohs(tcph->dest));

			// For possible NAT adjustmenets
			l4->sport = &tcph->source;
			l4->dport = &tcph->dest;
			l4->cksum = &tcph->check;

			// Save the TCP Flags
			l4->tcp = *(struct tcp_flags*)((void*)tcph + TCP_FLAGS_OFFSET);
		break;

		case IPPROTO_UDP:;
			// Parse the UDP header, will drop the package if out-of-bounds
			parse_header(struct udphdr, *udph, pkt);

			BPF_DEBUG("UDP Src Port: %u", bpf_ntohs(udph->source));
			BPF_DEBUG("UDP Dst Port: %u", bpf_ntohs(udph->dest));

			// For possible NAT adjustmenets
			l4->sport = &udph->source;
			l4->dport = &udph->dest;
			l4->cksum = &udph->check;
		break;

		default:
			BPF_DEBUG("IP Protocol: %u", proto);
			return false;
	}

    return true;
}


#endif
