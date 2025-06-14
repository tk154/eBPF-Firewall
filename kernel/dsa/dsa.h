#ifndef BPFW_DSA
#define BPFW_DSA

#include <stdbool.h>

#include "../common_kern.h"

#include "gswip.h"
#include "mtk.h"
#include "qca.h"


#define DSA_TAG(tag) { \
		.proto = STRINGIFY(tag), \
		.rx_size = sizeof(((struct tag##_tag_rcv*)0)->h_tag), \
		.tx_size = sizeof(((struct tag##_tag_xmit*)0)->h_tag) \
	}


SEC(DSA_TAG_SECTION)
const struct dsa_tag dsa_tag[] = { DSA_TAG(gswip), DSA_TAG(mtk), DSA_TAG(qca) };

SEC(DSA_SWITCH_SECTION)
struct dsa_switch dsa_switch = {};


enum {
	DSA_PROTO_NONE = 0,
	DSA_PROTO_GSWIP,
	DSA_PROTO_MTK,
	DSA_PROTO_QCA
};

__always_inline static bool parse_dsa_header(struct packet_data *pkt, struct l2_header *l2) {
	bool rc;

	switch (dsa_switch.proto) {
		case DSA_PROTO_GSWIP:
			rc = gswip_tag_rcv(pkt, l2);
			break;
		case DSA_PROTO_MTK:
			rc = mtk_tag_rcv(pkt, l2);
			break;
		case DSA_PROTO_QCA:
			rc = qca_tag_rcv(pkt, l2);
			break;
		default:
			return false;
	}

	l2->dsa_port |= DSA_PORT_SET;
	return rc;
}

__always_inline static bool push_dsa_header(struct packet_data *pkt, struct next_hop *next_h) {
	__u8 dsa_port = next_h->dsa_port & ~DSA_PORT_SET;

	switch (dsa_switch.proto) {
		case DSA_PROTO_GSWIP:
			return gswip_tag_xmit(pkt, next_h, dsa_port);
		case DSA_PROTO_MTK:
			return mtk_tag_xmit(pkt, next_h, dsa_port);
		case DSA_PROTO_QCA:
			return qca_tag_xmit(pkt, next_h, dsa_port);
		default:
			return false;
	}
}


#endif
