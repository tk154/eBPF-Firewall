#ifndef BPFW_DSA_GSWIP
#define BPFW_DSA_GSWIP

#include "../common_kern.h"


#define GSWIP_TX_HEADER_LEN		4

#define GSWIP_TX_SLPID_CPU		2
#define GSWIP_TX_DPID_ELAN		0

#define GSWIP_TX_PORT_MAP_EN	BIT(7)
#define GSWIP_TX_PORT_MAP_SEL	BIT(6)

#define GSWIP_TX_DPID_EN        BIT(0)
#define GSWIP_TX_PORT_MAP_SHIFT	1
#define GSWIP_TX_PORT_MAP_MASK	GENMASK(6, 1)

#define GSWIP_RX_HEADER_LEN	    8

#define GSWIP_RX_SPPID_SHIFT	4
#define GSWIP_RX_SPPID_MASK     GENMASK(6, 4)


struct gswip_tag_rcv {
	__u8   h_tag[GSWIP_RX_HEADER_LEN];
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__be16 h_proto;
} __packed;

struct gswip_tag_xmit {
	__u8   h_tag[GSWIP_TX_HEADER_LEN];
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__be16 h_proto;
} __packed;


__always_inline static bool gswip_tag_rcv(struct packet_data *pkt, struct l2_header *l2) {
    parse_ethhdr(struct gswip_tag_rcv, hdr, pkt, l2);
    l2->dsa_port = (hdr->h_tag[7] & GSWIP_RX_SPPID_MASK) >> GSWIP_RX_SPPID_SHIFT;

    return true;
}

__always_inline static bool gswip_tag_xmit(struct packet_data *pkt, struct next_hop *next_h, __u8 dsa_port) {
    push_ethhdr(struct gswip_tag_xmit, hdr, pkt, next_h);

	hdr->h_tag[0] = GSWIP_TX_SLPID_CPU;
	hdr->h_tag[1] = GSWIP_TX_DPID_ELAN;
	hdr->h_tag[2] = GSWIP_TX_PORT_MAP_EN | GSWIP_TX_PORT_MAP_SEL;
	hdr->h_tag[3] = BIT(dsa_port + GSWIP_TX_PORT_MAP_SHIFT) & GSWIP_TX_PORT_MAP_MASK;
	hdr->h_tag[3] |= GSWIP_TX_DPID_EN;

    return true;
}


#endif
