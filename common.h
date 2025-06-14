#ifndef BPFW_COMMON_H
#define BPFW_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <linux/types.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>


#define STRINGIFY(x) 				 	#x
#define BPFW_NAME(x) 				 	STRINGIFY(x)  // Used to get the prog/map name as a string (used for user space programs)

#define BPFW_XDP_PROG				 	bpfw_xdp
#define BPFW_TC_PROG				 	bpfw_tc

#define XDP_PROG_NAME				 	BPFW_NAME(BPFW_XDP_PROG)
#define TC_PROG_NAME				 	BPFW_NAME(BPFW_TC_PROG)

#define BPFW_IPV4_FLOW_MAP      	 	bpfw_ipv4_flows
#define BPFW_IPV6_FLOW_MAP      	 	bpfw_ipv6_flows
#define IPV4_FLOW_MAP_NAME 		  	 	BPFW_NAME(BPFW_IPV4_FLOW_MAP)
#define IPV6_FLOW_MAP_NAME 		  	 	BPFW_NAME(BPFW_IPV6_FLOW_MAP)

#define FLOW_MAP_DEFAULT_MAX_ENTRIES	1024

#define USERSPACE_TIME_SECTION 		 	".bss.time"

#define DSA_TAG_SECTION			  	 	".rodata.dsa.tag"
#define DSA_SWITCH_SECTION		  	 	".rodata.dsa.switch"

#define DSA_PROTO_MAX_LEN				8
#define DSA_PORT_SET					(1U << 7)


enum {
	STATE_NEW_FLOW,

	STATE_NONE,
	ACTION_NONE = STATE_NONE,

	STATE_PASS,
	ACTION_PASS = STATE_PASS,

	STATE_DROP,
	ACTION_DROP = STATE_DROP,

	STATE_FORWARD,
	ACTION_FORWARD = STATE_FORWARD,
};

enum {
	REWRITE_SRC_IP    = 1U << 0,
	REWRITE_DEST_IP   = 1U << 1,
	REWRITE_SRC_PORT  = 1U << 2,
	REWRITE_DEST_PORT = 1U << 3
};


#define FLOW_KEY_COMMON \
	__u32  ifindex;		\
	__le16 vlan_id;		\
	__be16 pppoe_id;	\
	__be16 src_port;	\
	__be16 dest_port;	\
	__u8   dsa_port;	\
	__u8   family;		\
	__u8   proto;		\
	__u8   __pad;

struct flow4_ip {
	__be32 src[1], dest[1];
};

struct flow6_ip {
	__be32 src[4], dest[4];
};

union flow_ip {
	struct flow4_ip v4;
	struct flow6_ip v6;
};

struct flow_key {
	FLOW_KEY_COMMON
	union flow_ip ip;
};


struct next_hop {
	__u32  ifindex;

	__u8   src_mac [ETH_ALEN];
	__u8   dest_mac[ETH_ALEN];

	__le16 vlan_id;
	__be16 pppoe_id;
	__u16  mtu;

	__u8   dsa_port;
	__s8   l2_diff;
};

struct nat_entry {
	__be32  src_ip[4];
	__be32  dest_ip[4];

	__be16  src_port;
	__be16  dest_port;

	__sum16 l4_cksum_diff;
	__u8    rewrite_flag;
};

struct next_entry {
	struct next_hop hop;
	struct nat_entry nat;

	__sum16 ipv4_cksum_diff;
};

struct flow_value {
	__u64 time;
	__u8  src_mac[ETH_ALEN];

	union {
		__u8 action, state;
	};

	struct next_entry next;
};


struct user_time {
	__u64 timeout;
	__u64 last_time;
	bool warned_about_timeout;
};

struct dsa_switch {
	__u32 ifindex;
	__u8  proto;
};

struct dsa_tag {
	char proto[DSA_PROTO_MAX_LEN];
	__u8 rx_size, tx_size;
};


struct vlanhdr {
	__be16 tci;
	__be16 proto;
};

struct pppoehdr {
	__u8   vertype;
	__u8   code;
	__be16 sid;
	__be16 length;
    __be16 proto;
};


__always_inline static void ipcpy(__be32 *dest, const __be32 *src, __u8 family) {
    /*switch (family) {
        case AF_INET6:
            dest[3] = src[3];
			dest[2] = src[2];
			dest[1] = src[1];
        case AF_INET:
            dest[0] = src[0];
    }*/

	dest[0] = src[0];

	if (family == AF_INET6) {
		dest[1] = src[1];
		dest[2] = src[2];
		dest[3] = src[3];
	}
}

__always_inline static __be32 *flow_ip_get_src(union flow_ip *flow_ip, __u8 family) {
	return family == AF_INET ? flow_ip->v4.src : flow_ip->v6.src;
	/*switch (family) {
		case AF_INET:
			return flow_ip->v4.src;
		case AF_INET6:
			return flow_ip->v6.src;
		default:
			return NULL;
	}*/
}

__always_inline static __be32 *flow_ip_get_dest(union flow_ip *flow_ip, __u8 family) {
	return family == AF_INET ? flow_ip->v4.dest : flow_ip->v6.dest;
}


#endif
