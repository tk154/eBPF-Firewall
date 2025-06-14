#ifndef BPFW_DSA_MTK
#define BPFW_DSA_MTK

#include "../common_kern.h"


#define MTK_HDR_LEN		                4
#define MTK_HDR_XMIT_UNTAGGED		    0
#define MTK_HDR_XMIT_TAGGED_TPID_8100	1
#define MTK_HDR_RECV_SOURCE_PORT_MASK	GENMASK(2, 0)
#define MTK_HDR_XMIT_DP_BIT_MASK	    GENMASK(5, 0)


struct mtk_tag_rcv {
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__u8   h_tag[MTK_HDR_LEN];
	__be16 h_proto;
} __packed;

struct mtk_tag_xmit {
	__u8   h_dest[ETH_ALEN];
	__u8   h_source[ETH_ALEN];
	__u8   h_tag[MTK_HDR_LEN];
	__be16 h_proto;
} __packed;


__always_inline static bool mtk_tag_rcv(struct packet_data *pkt, struct l2_header *l2) {
	struct mtk_tag_rcv *mtk;
    parse_ethhdr(mtk, pkt, l2);

    l2->dsa_port = mtk->h_tag[1] & MTK_HDR_RECV_SOURCE_PORT_MASK;

    return true;
}

__always_inline static bool mtk_tag_xmit(struct packet_data *pkt, struct next_hop *next_h, __u8 dsa_port) {
	struct mtk_tag_xmit *mtk;
    push_ethhdr(mtk, pkt, next_h);

	mtk->h_tag[1] = (1 << dsa_port) & MTK_HDR_XMIT_DP_BIT_MASK;

	if (!next_h->vlan_id) {
		mtk->h_tag[0] = MTK_HDR_XMIT_UNTAGGED;
		mtk->h_tag[2] = 0;
		mtk->h_tag[3] = 0;
	}
	else
		mtk->h_tag[0] = MTK_HDR_XMIT_TAGGED_TPID_8100;

    return true;
}


#endif
