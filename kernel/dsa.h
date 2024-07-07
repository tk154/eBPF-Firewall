#include <linux/types.h>
#include "common_kern.h"


#if defined(DSA_GSWIP)
	#define dsa_tag_proto "gswip"

	struct ethhdr_dsa_rx {
		__u64  dsa_tag;
		__u8   h_dest[6];
		__u8   h_source[6];
		__be16 h_proto;
	} __attribute__((packed));

	struct ethhdr_dsa_tx {
		__u32  dsa_tag;
		__u8   h_dest[6];
		__u8   h_source[6];
		__be16 h_proto;
	} __attribute__((packed));

	#define dsa_get_port(dsa_tag) ((dsa_tag >> 4) & 0x07)
	#define dsa_get_tag(dsa_port) (0x0200c001 | (1 << (dsa_port + 1)))
#elif defined(DSA_MTK)
	#define dsa_tag_proto ""

	struct ethhdr_dsa_rx {
		__u8   h_dest[6];
		__u8   h_source[6];
		__u32  dsa_tag;
		__be16 h_proto;
	} __attribute__((packed));

	struct ethhdr_dsa_tx {
		__u8   h_dest[6];
		__u8   h_source[6];
		__u32  dsa_tag;
		__be16 h_proto;
	} __attribute__((packed));

	#define dsa_get_port(dsa_tag) ((dsa_tag >> 8) & 0x07)
	#define dsa_get_tag(dsa_port) ((1 << dsa_port) << 8)
#elif defined(DSA_QCA)
	#define dsa_tag_proto ""

	struct ethhdr_dsa_rx {
		__u8   h_dest[6];
		__u8   h_source[6];
		__u16  dsa_tag;
		__be16 h_proto;
	} __attribute__((packed));

	struct ethhdr_dsa_tx {
		__u8   h_dest[6];
		__u8   h_source[6];
		__u16  dsa_tag;
		__be16 h_proto;
	} __attribute__((packed));

	#define dsa_get_port(dsa_tag) (dsa_tag & 0x07)
	#define dsa_get_tag(dsa_port) (0x8080 | (1 << dsa_port))
#endif

SEC(DSA_PROTO_SECTION)
char proto[DSA_PROTO_MAX_LEN] = dsa_tag_proto;

SEC(DSA_TAG_SECTION)
const struct dsa_tag tag = {
	.rx_size = sizeof(struct ethhdr_dsa_rx),
	.tx_size = sizeof(struct ethhdr_dsa_tx)
};

SEC(DSA_SWITCH_SECTION)
__u32 dsa_switch;
