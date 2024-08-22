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

#define IP_MF		0x2000	/* "More Fragments" */
#define IP_OFFSET	0x1fff	/* "Fragment Offset" */


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

__always_inline static bool parse_eth_header(void *ctx, struct packet_data *pkt, struct l2_header *l2) {
	// Parse the Ethernet header, will drop the package if out-of-bounds
	if (pkt->ifindex.in == dsa_switch.ifindex) {
		if (!parse_dsa_header(pkt, l2))
			return false;

		bpfw_debug("Interface: %u@p%u", pkt->ifindex.in, l2->dsa_port & ~DSA_PORT_SET);
	}
	else {
		check_header(struct ethhdr, *ethh, pkt);

		l2->src_mac = ethh->h_source;
		l2->proto = ethh->h_proto;
		l2->dsa_port = 0;

		bpfw_debug("Interface: %u", pkt->ifindex.in);
	}

	bpfw_debug_mac("Src MAC: ", l2->src_mac);

	return true;
}

__always_inline static bool parse_vlan_header(void *ctx, bool xdp, struct packet_data *pkt, struct l2_header *l2) {
	if (xdp || pkt->ifindex.in == dsa_switch.ifindex) {
		// Check if there is a VLAN header
		if (l2->proto == bpf_htons(ETH_P_8021Q)) {
			// Parse the VLAN header, will drop the package if out-of-bounds
			check_header(struct vlanhdr, *vlan_h, pkt);

			// Save the VLAN ID (last 12 Byte)
			l2->vlan_id = bpf_ntohs(vlan_h->tci) & 0x0FFF;

			bpfw_debug("VLAN ID: %u", l2->vlan_id);

			// Save the packet type ID of the next header
			l2->proto = vlan_h->proto;

			return true;
		}
	}
	else {
		struct __sk_buff *skb = ctx;

		if (skb->vlan_present && skb->vlan_proto == bpf_htons(ETH_P_8021Q)) {
			// Save the VLAN ID (last 12 Byte)
			l2->vlan_id = skb->vlan_tci & 0x0FFF;

			bpfw_debug("VLAN ID: %u", l2->vlan_id);

			return true;
		}
	}

	l2->vlan_id = 0;

	return true;
}

__always_inline static bool parse_pppoe_header(struct packet_data *pkt, struct l2_header *l2) {
	if (l2->proto == bpf_ntohs(ETH_P_PPP_SES)) {
		// Parse the PPPoE header, will drop the package if out-of-bounds
		check_header(struct pppoehdr, *pppoe_h, pkt);

		l2->pppoe_id = pppoe_h->sid;

		bpfw_debug("PPPoE Session ID: 0x%x", l2->pppoe_id);

		l2->proto = proto_ppp2eth(pppoe_h->proto);
		if (!l2->proto) {
			bpfw_debug("PPPoE Protocol: 0x%04x", pppoe_h->proto);
			return false;
		}
	}
	else
		l2->pppoe_id = 0;

	return true;
}

__always_inline static bool parse_l2_header(void *ctx, bool xdp, struct packet_data *pkt, struct l2_header *l2) {
	// Parse the Ethernet header, will drop the package if out-of-bounds
	if (!parse_eth_header(ctx, pkt, l2))
		return false;

	// Check if there is a VLAN header
	if (!parse_vlan_header(ctx, xdp, pkt, l2))
		return false;

	if (!parse_pppoe_header(pkt, l2))
		return false;

	l2->payload_len = pkt->data_end - pkt->p;

    return true;
}

__always_inline static bool parse_ipv4_header(struct packet_data *pkt, struct l3_header *l3) {
	// Parse the IPv4 header, will drop the package if out-of-bounds
	check_header(struct iphdr, *iph, pkt);

	bpfw_debug_ipv4("Src IPv4: ", &iph->saddr);
	bpfw_debug_ipv4("Dst IPv4: ", &iph->daddr);

	__u8 ihl = ((struct iphdr_ver_ihl*)iph)->ihl;

	/* ip options */
	if (ihl * 4 != sizeof(*iph)) {
		bpfw_debug("IHL words (%u) doesn't equal IPv4 Header size.", ihl);
		return false;
	}

	/* ip fragmented traffic */
	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
		bpfw_debug("IPv4 Packet is fragmented.");
		return false;
	}

	l3->family	= AF_INET;
	l3->src_ip 	= &iph->saddr;
	l3->dest_ip = &iph->daddr;

	l3->proto   =  iph->protocol;
	l3->ttl 	= &iph->ttl;
	l3->cksum   = &iph->check;

	return true;
}

__always_inline static bool parse_ipv6_header(struct packet_data *pkt, struct l3_header *l3) {
	// Parse the IPv6 header, will drop the package if out-of-bounds
	check_header(struct ipv6hdr, *ipv6h, pkt);

	bpfw_debug_ipv6("Src IPv6: ", &ipv6h->saddr);
	bpfw_debug_ipv6("Dst IPv6: ", &ipv6h->daddr);

	l3->family	= AF_INET6;
	l3->src_ip  = &ipv6h->saddr;
	l3->dest_ip = &ipv6h->daddr;

	l3->proto   =  ipv6h->nexthdr;
	l3->ttl     = &ipv6h->hop_limit;

	return true;
}

__always_inline static bool parse_l3_header(struct packet_data *pkt, __be16 proto, struct l3_header *l3) {
	bool success;

	switch (proto) {
		case bpf_ntohs(ETH_P_IP):
			success = parse_ipv4_header(pkt, l3);
			break;

		case bpf_ntohs(ETH_P_IPV6):
			success = parse_ipv6_header(pkt, l3);
			break;

		default:
			bpfw_debug("Ethernet Protocol: 0x%04x", proto);
			return false;
	}

	if (!success)
		return false;

	if (*l3->ttl <= 1) {
		bpfw_debug("TTL expired.");
		return false;
	}

	return true;
}

__always_inline static bool parse_tcp_header(struct packet_data *pkt, struct l4_header *l4) {
	// Parse the TCP header, will drop the package if out-of-bounds
	check_header(struct tcphdr, *tcph, pkt);

	bpfw_debug("TCP Src Port: %u", bpf_ntohs(tcph->source));
	bpfw_debug("TCP Dst Port: %u", bpf_ntohs(tcph->dest));

	// For possible NAT adjustmenets
	l4->src_port  = &tcph->source;
	l4->dest_port = &tcph->dest;
	l4->cksum 	  = &tcph->check;

	// Save the TCP Flags
	l4->tcp_flags = *(struct tcphdr_flags*)((void*)tcph + TCP_HEADER_FLAGS_OFFSET);

	return true;
}

__always_inline static bool parse_udp_header(struct packet_data *pkt, struct l4_header *l4) {
	// Parse the UDP header, will drop the package if out-of-bounds
	check_header(struct udphdr, *udph, pkt);

	bpfw_debug("UDP Src Port: %u", bpf_ntohs(udph->source));
	bpfw_debug("UDP Dst Port: %u", bpf_ntohs(udph->dest));

	// For possible NAT adjustmenets
	l4->src_port  = &udph->source;
	l4->dest_port = &udph->dest;
	l4->cksum 	  = &udph->check;

	return true;
}

__always_inline static bool parse_l4_header(struct packet_data *pkt, __be16 proto, struct l4_header *l4) {
	switch (proto) {
		case IPPROTO_TCP:
			return parse_tcp_header(pkt, l4);

		case IPPROTO_UDP:
			return parse_udp_header(pkt, l4);

		default:
			bpfw_debug("IP Protocol: %u", proto);
			return false;
	}
}


#endif
