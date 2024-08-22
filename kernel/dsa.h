#include <stdbool.h>

#include <linux/types.h>
#include "common_kern.h"


#define __packed __attribute__((packed))

#define parse_dsa_tag(tag, get_port) \
	__always_inline static bool tag(struct packet_data *pkt, struct l2_header *l2) { \
		check_header(struct tag, *tag, pkt) \
		l2->src_mac = tag->h_source; \
		l2->proto = tag->h_proto; \
		l2->dsa_port = (get_port) | DSA_PORT_SET; \
		return true; \
	}

#define push_dsa_tag(tag, get_tag) \
	__always_inline static bool tag(struct packet_data *pkt, struct next_hop *next_hop) { \
		check_header(struct tag, *tag, pkt) \
		memcpy(tag->h_source, next_hop->src_mac,  ETH_ALEN); \
		memcpy(tag->h_dest,   next_hop->dest_mac, ETH_ALEN); \
		tag->h_tag = (get_tag) & ~DSA_PORT_SET; \
		return true; \
	}

#define DSA_TAG(tag) { \
		.proto = STRINGIFY(tag), \
		.rx_size = sizeof(((struct tag##_tag_rcv*)0)->h_tag), \
		.tx_size = sizeof(((struct tag##_tag_xmit*)0)->h_tag) \
	}


struct gswip_tag_rcv {
	__u64  h_tag;
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__be16 h_proto;
} __packed;

struct gswip_tag_xmit {
	__u32  h_tag;
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__be16 h_proto;
} __packed;

parse_dsa_tag(gswip_tag_rcv, (gswip_tag_rcv->h_tag >> 4) & 0x07)
push_dsa_tag(gswip_tag_xmit, 0x0200c001 | (1 << (next_hop->dsa_port + 1)))


struct mtk_tag_rcv {
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__u32  h_tag;
	__be16 h_proto;
} __packed;

struct mtk_tag_xmit {
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__u32  h_tag;
	__be16 h_proto;
} __packed;

parse_dsa_tag(mtk_tag_rcv, (mtk_tag_rcv->h_tag >> 8) & 0x07)
push_dsa_tag(mtk_tag_xmit, (1 << next_hop->dsa_port) << 8)


struct qca_tag_rcv {
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__u16  h_tag;
	__be16 h_proto;
} __packed;

struct qca_tag_xmit {
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__u16  h_tag;
	__be16 h_proto;
} __packed;

parse_dsa_tag(qca_tag_rcv, qca_tag_rcv->h_tag & 0x07)
push_dsa_tag(qca_tag_xmit, 0x8080 | (1 << next_hop->dsa_port))


SEC(DSA_TAG_SECTION)
const struct dsa_tag dsa_tag[] = { DSA_TAG(gswip), DSA_TAG(mtk), DSA_TAG(qca) };

SEC(DSA_SWITCH_SECTION)
struct dsa_switch dsa_switch;


enum {
	DSA_PROTO_GSWIP = 1,
	DSA_PROTO_MTK,
	DSA_PROTO_QCA
};

__always_inline static bool parse_dsa_header(struct packet_data *pkt, struct l2_header *l2) {
	switch (dsa_switch.proto) {
		case DSA_PROTO_GSWIP:
			return gswip_tag_rcv(pkt, l2);
		case DSA_PROTO_MTK:
			return mtk_tag_rcv(pkt, l2);
		case DSA_PROTO_QCA:
			return qca_tag_rcv(pkt, l2);
		default:
			return false;
	}
}

__always_inline static bool push_dsa_header(struct packet_data *pkt, struct next_hop *next_hop) {
	switch (dsa_switch.proto) {
		case DSA_PROTO_GSWIP:
			return gswip_tag_xmit(pkt, next_hop);
		case DSA_PROTO_MTK:
			return mtk_tag_xmit(pkt, next_hop);
		case DSA_PROTO_QCA:
			return qca_tag_xmit(pkt, next_hop);
		default:
			return false;
	}
}
