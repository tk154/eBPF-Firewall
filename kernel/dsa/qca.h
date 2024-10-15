#ifndef BPFW_DSA_QCA
#define BPFW_DSA_QCA

#include "../common_kern.h"


#define QCA_HDR_LEN 				2
#define QCA_HDR_VERSION				0x2

#define QCA_HDR_RECV_SOURCE_PORT	GENMASK(2, 0)

#define QCA_HDR_XMIT_VERSION 		GENMASK(7, 6)
#define QCA_HDR_XMIT_FROM_CPU		BIT(7)
#define QCA_HDR_XMIT_DP_BIT			GENMASK(6, 0)


struct qca_tag_rcv {
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__u8   h_tag[QCA_HDR_LEN];
	__be16 h_proto;
} __packed;

struct qca_tag_xmit {
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__u8   h_tag[QCA_HDR_LEN];
	__be16 h_proto;
} __packed;


__always_inline static bool qca_tag_rcv(struct packet_data *pkt, struct l2_header *l2) {
    parse_ethhdr(struct qca_tag_rcv, hdr, pkt, l2);
    l2->dsa_port = FIELD_GET(QCA_HDR_RECV_SOURCE_PORT, hdr->h_tag[1]);

    return true;
}

__always_inline static bool qca_tag_xmit(struct packet_data *pkt, struct next_hop *next_h, __u8 dsa_port) {
    push_ethhdr(struct qca_tag_xmit, hdr, pkt, next_h);

	hdr->h_tag[0] = FIELD_PREP(QCA_HDR_XMIT_VERSION, QCA_HDR_VERSION);
	hdr->h_tag[1] = QCA_HDR_XMIT_FROM_CPU;
	hdr->h_tag[1] |= FIELD_PREP(QCA_HDR_XMIT_DP_BIT, BIT(dsa_port));

    return true;
}


#endif
