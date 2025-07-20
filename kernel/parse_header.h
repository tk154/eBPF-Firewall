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

#ifndef NO_DSA
#include "dsa/dsa.h"
#endif

#define IP_MF			0x2000	/* "More Fragments" */
#define IP_OFFSET		0x1FFF	/* "Fragment Offset" */
#define IP_VERSION(ip)	(*(__u8 *)(ip) >> 4)
#define IP_IHL(ip)		(*(__u8 *)(ip) & 0xF)

// tcphdr from <linux/tcp.h> uses the host endianness, instead of the compiler endianness
#define TCP_FLAGS(tcp)	(*((__u8 *)(tcp) + 13))
#define TCP_FIN(flags)	((flags) & BIT(0))
#define TCP_RST(flags)	((flags) & BIT(2))


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
#ifndef NO_DSA
	if (pkt->in_ifindex == dsa_switch.ifindex) {
		if (!parse_dsa_header(pkt, l2))
			return false;

		bpfw_debug("Interface: %u@p%u", pkt->in_ifindex, l2->dsa_port & ~DSA_PORT_SET);
	}
	else
#endif
	{
		struct ethhdr *ethh;
		parse_ethhdr(ethh, pkt, l2);

		l2->dsa_port = 0;

		bpfw_debug("Interface: %u", pkt->in_ifindex);
	}

	bpfw_debug_mac("Src MAC: ", l2->src_mac);

	return true;
}

__always_inline static bool parse_vlan_header(void *ctx, bool xdp, struct packet_data *pkt, struct l2_header *l2) {
	struct vlanhdr *vlan_h;

	if (xdp || l2->dsa_port) {
		// Check if there is a VLAN header
		if (l2->proto == bpf_htons(ETH_P_8021Q)) {
			// Parse the VLAN header, will drop the package if out-of-bounds
			check_header(vlan_h, pkt);

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
	struct pppoehdr *pppoe_h;

	if (l2->proto == bpf_ntohs(ETH_P_PPP_SES)) {
		// Parse the PPPoE header, will drop the package if out-of-bounds
		check_header(pppoe_h, pkt);

		l2->pppoe_id = pppoe_h->sid;
		l2->proto = proto_ppp2eth(pppoe_h->proto);

		bpfw_debug("PPPoE Session ID: 0x%x", l2->pppoe_id);

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
	struct iphdr *iph;
	__u8 ver, ihl;

	check_header(iph, pkt);

	bpfw_debug_ipv4("Src IPv4: ", &iph->saddr);
	bpfw_debug_ipv4("Dst IPv4: ", &iph->daddr);

	ver = IP_VERSION(iph);
	ihl = IP_IHL(iph);

	if (ver != IPVERSION) {
		bpfw_debug("Invalid IPv4 version %u", ver);
		return false;
	}

	// IP options
	if (ihl != sizeof(*iph) >> 2) {
		bpfw_debug("IHL words (%u) doesn't equal IPv4 Header size.", ihl);
		return false;
	}

	/* IP fragmented traffic */
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

	l3->tot_len = bpf_ntohs(iph->tot_len);

	return true;
}

__always_inline static bool parse_ipv6_header(struct packet_data *pkt, struct l3_header *l3) {
	// Parse the IPv6 header, will drop the package if out-of-bounds
	struct ipv6hdr *ipv6h;
	check_header(ipv6h, pkt);

	bpfw_debug_ipv6("Src IPv6: ", &ipv6h->saddr);
	bpfw_debug_ipv6("Dst IPv6: ", &ipv6h->daddr);

	l3->family	= AF_INET6;
	l3->src_ip  = ipv6h->saddr.s6_addr32;
	l3->dest_ip = ipv6h->daddr.s6_addr32;

	l3->proto   =  ipv6h->nexthdr;
	l3->ttl     = &ipv6h->hop_limit;

	l3->tot_len = bpf_ntohs(ipv6h->payload_len) + sizeof(*ipv6h);

	return true;
}

__always_inline static bool parse_l3_header(struct packet_data *pkt, __be16 proto, struct l3_header *l3) {
	bool success;
	
	l3->offset = pkt->p - pkt->data;

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
	struct tcphdr *tcph;
	check_header(tcph, pkt);

	bpfw_debug("TCP Src Port: %u", bpf_ntohs(tcph->source));
	bpfw_debug("TCP Dst Port: %u", bpf_ntohs(tcph->dest));

	// For possible NAT adjustmenets
	l4->src_port  = &tcph->source;
	l4->dest_port = &tcph->dest;
	l4->cksum 	  = &tcph->check;

	// Save the TCP Flags
	l4->tcp_flags = TCP_FLAGS(tcph);

	return true;
}

__always_inline static bool parse_udp_header(struct packet_data *pkt, struct l4_header *l4) {
	// Parse the UDP header, will drop the package if out-of-bounds
	struct udphdr *udph;
	check_header(udph, pkt);

	bpfw_debug("UDP Src Port: %u", bpf_ntohs(udph->source));
	bpfw_debug("UDP Dst Port: %u", bpf_ntohs(udph->dest));

	// For possible NAT adjustmenets
	l4->src_port  = &udph->source;
	l4->dest_port = &udph->dest;
	l4->cksum 	  = &udph->check;

	l4->payload_len = bpf_ntohs(udph->len) - sizeof(*udph);

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

__always_inline static bool parse_header(void *ctx, bool xdp, struct packet_data *pkt, struct packet_header *header) {
	return parse_l2_header(ctx, xdp, pkt, &header->l2) &&
		parse_l3_header(pkt, header->l2.proto, &header->l3) &&
		parse_l4_header(pkt, header->l3.proto, &header->l4);
}


#endif
